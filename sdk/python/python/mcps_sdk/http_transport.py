"""MCP-S request/response transport — one signed POST per ``ClientSession`` request.

This is step (ii): a dedicated transport that maps ``mcp.ClientSession``'s
persistent-stream model onto the production ``mcps-proxy``'s wire, which is **one
HTTP/1.1 POST per (mTLS) connection, ``Connection: close``** — a pure
request/response channel with NO server push (``mcps-proxy/src/tls.rs::serve_once``).

The byte-level security is the SAME audited pipeline the stdio
:class:`~mcps_sdk.transport.McpsTransport` uses — :func:`sign_outbound` (sign +
register correlation) and :func:`verify_inbound` (correlate + verify + strip). What
differs is the *shape*: instead of pumping a persistent byte stream, every outbound
``ClientSession`` **request** becomes exactly one ``post(request_bytes) ->
response_bytes`` round trip, and that response is the only inbound message for it.

Lifecycle over a no-server-push request/response transport (the questions step ii
exists to answer):

* ``initialize`` is an ordinary request (it has an ``id``): it is signed, POSTed,
  the server-signed ``InitializeResult`` is verified + stripped, and delivered to
  ``ClientSession`` — which negotiates the protocol version normally.
* ``notifications/initialized`` (and every other client→server **notification**) is
  fire-and-forget: it has no ``id`` and expects no response. This transport has no
  channel to deliver a fire-and-forget message — the proxy treats every POST as a
  signed request that MUST verify and MUST get a response — so notifications are
  **dropped** (the minimal proxy + stateless fileserver do not consume them). A
  stricter inner server that required ``initialized`` would need a tunnelling
  convention; that is out of scope for this transport.
* A **fail-closed** verification cannot be surfaced as a read-stream ``Exception``
  here the way the stdio adapter does: ``ClientSession``'s receive loop routes a
  stream ``Exception`` to ``_handle_incoming`` (it does NOT fail the awaiting call),
  so the in-flight request would hang. Instead a rejected response is delivered as a
  **JSON-RPC error correlated to the request id**, carrying the frozen ``mcps.*``
  reason — so the awaiting ``ClientSession`` call raises cleanly.

The TLS/socket specifics live OUTSIDE this module: the caller supplies a synchronous
``post(request_bytes: bytes) -> response_bytes: bytes`` (mirroring how
:class:`McpsTransport` takes ``byte_send`` / ``byte_lines``). The blocking POST is
run off the event loop with ``anyio.to_thread``. See
:func:`mcps_sdk.client.connect_mtls_http` for the production mTLS wiring.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Callable, Optional

import mcps_sdk

from .transport import (
    McpsConfig,
    _request_fields,
    sign_outbound,
)

# A synchronous request/response round trip: signed request bytes in, the response
# ``(content_type, body)`` out. One call == one mTLS connection + POST in the
# production wiring. The content type lets the multi-path decoder distinguish a
# direct-JSON response from a (single) SSE-framed one.
PostSync = Callable[[bytes], "tuple[str, bytes]"]

# JSON-RPC server-error code carrying a fail-closed MCP-S rejection back to the
# awaiting ClientSession call (reserved server-error range, -32000..-32099).
MCPS_REJECTED_CODE = -32099


class McpsHttpTransport:
    """Maps a ``ClientSession`` stream pair onto one signed POST per request.

    ``post`` is a *synchronous* ``request_bytes -> response_bytes`` callable (the
    production wiring opens one mTLS connection and POSTs); it is run off the event
    loop via ``anyio.to_thread``. Outbound notifications are dropped (no
    fire-and-forget channel); a rejected response is delivered as a JSON-RPC error
    correlated to the request id so the awaiting call raises.
    """

    def __init__(
        self,
        post: PostSync,
        config: McpsConfig,
        correlation: Any = None,
        *,
        clock: Optional[Callable[[], int]] = None,
        nonce_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        self._post = post
        self._config = config
        self._correlation = correlation or mcps_sdk.CorrelationStore()
        self._clock = clock or (lambda: int(time.time()))
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(16))
        self._tg = None
        self._app_read_send = None
        self._app_write_recv = None

    async def __aenter__(self):
        import anyio

        # we -> ClientSession (verified responses); ClientSession -> we (requests).
        self._app_read_send, app_read_recv = anyio.create_memory_object_stream(0)
        app_write_send, self._app_write_recv = anyio.create_memory_object_stream(0)
        self._tg = anyio.create_task_group()
        await self._tg.__aenter__()
        self._tg.start_soon(self._writer_loop)
        return app_read_recv, app_write_send

    async def __aexit__(self, *exc):
        if self._tg is not None:
            self._tg.cancel_scope.cancel()
            await self._tg.__aexit__(*exc)

    async def _writer_loop(self) -> None:
        async for session_message in self._app_write_recv:
            is_request, rid, _method, _params = _request_fields(session_message)
            if not is_request:
                # A notification (or a response to a server-initiated request).
                # The request/response transport has no fire-and-forget channel and
                # the minimal proxy never pushes, so there is nowhere to send it —
                # drop it. `initialize` already negotiated; the stateless fileserver
                # does not consume `notifications/initialized`.
                continue
            # One independent POST per request, off the event loop. start_soon so a
            # slow round trip does not head-of-line block concurrent app calls; each
            # request owns its own correlation entry (distinct JSON-RPC ids).
            self._tg.start_soon(self._round_trip, session_message, rid)

    async def _round_trip(self, session_message: Any, rid: Any) -> None:
        import anyio

        from .streamable import verify_inbound_messages

        now = self._clock()
        wire = sign_outbound(
            session_message,
            self._config,
            self._correlation,
            now_unix=now,
            nonce=self._nonce_factory(),
            expires_unix=now + self._config.ttl_seconds,
        )
        content_type, body = await anyio.to_thread.run_sync(self._post, wire)
        # Route the response through the multi-path decoder so a direct-JSON OR a
        # (single) SSE-framed response is verified the same way; every decoded
        # message gets the correlated-response verification or the server-initiated
        # inbound policy. The one-POST-per-request proxy contract yields exactly one
        # response, so a reject binds to this request's id (so the awaiting call
        # raises, not hangs); an accepted/passed-through message is delivered as-is.
        for outcome in verify_inbound_messages(
            content_type, body, self._config, self._correlation, now_unix=self._clock()
        ):
            if outcome.kind in ("accept", "passthrough"):
                await self._app_read_send.send(outcome.message)
            else:
                await self._app_read_send.send(self._reject_message(rid, outcome.reason))

    @staticmethod
    def _reject_message(rid: Any, reason: Optional[str]) -> Any:
        from mcp.shared.message import SessionMessage
        from mcp.types import ErrorData, JSONRPCError, JSONRPCMessage

        error = JSONRPCError(
            jsonrpc="2.0",
            id=rid,
            error=ErrorData(code=MCPS_REJECTED_CODE, message=reason or "mcps.verification_failed"),
        )
        return SessionMessage(JSONRPCMessage(error))
