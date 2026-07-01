"""MCP-S transport adapter — signs outbound / verifies inbound at the byte boundary.

The MCP Python SDK serializes JSON-RPC *inside* each transport (the anyio stream
between ``ClientSession`` and the transport carries pydantic ``SessionMessage``
objects, not bytes), so the only seam with exact-byte control is the transport
itself (spike #199). This adapter therefore OWNS the wire: ``ClientSession`` talks
plain MCP over in-memory streams, and the adapter signs every outbound request and
verifies every inbound response against the audited ``mcps-client-core`` bindings.

The security core is two sync, deterministic functions — :func:`sign_outbound`
(steps 1-4 of the proxy pipeline: sign + register correlation) and
:func:`verify_inbound` (steps 5-9: correlate + verify + strip envelope). The
:class:`McpsTransport` class is thin async glue that pumps those over a byte
channel and a pair of memory streams. ``mcp`` is imported lazily so the rest of the
SDK loads without it.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import mcps_sdk


class McpsVerificationError(Exception):
    """Raised/surfaced when an inbound response fails closed. Carries the frozen
    ``mcps.*`` wire reason. Delivered to ``ClientSession`` via the read stream
    (which accepts ``SessionMessage | Exception``) so the failed call raises."""

    def __init__(self, reason: Optional[str]):
        super().__init__(f"MCP-S response rejected: {reason}")
        self.reason = reason


@dataclass
class McpsConfig:
    """Per-connection MCP-S policy + identity the adapter signs/verifies under."""

    signer: Any  # mcps_sdk.Signer
    policy: Any  # mcps_sdk.SignerPolicy
    resolver: Any  # mcps_sdk.TrustResolver
    audience: str
    on_behalf_of: str
    # Authorization-evidence binding. PREFER a provider: set ``authorization`` to an
    # ``AuthorizationBindingProvider`` (e.g. ``OpaqueBytesProvider``) or a prebuilt
    # ``mcps_sdk.AuthorizationBinding`` — the digest is then computed in the audited
    # core from the real artifact bytes, not supplied as a constant.
    # ``authorization_policy`` (an ``mcps_sdk.AuthorizationBindingPolicy``) fails a
    # route closed to its permitted binding types. The raw ``binding_digest_*``
    # shortcut below is the dev/test fallback used only when ``authorization`` is None.
    authorization: Any = None
    authorization_policy: Any = None
    binding_digest_alg: str = "sha256"
    binding_digest_value: str = ""
    expected_server_signer: Optional[str] = None
    enforcement_mode: str = "require_mcps"
    legacy_allowed: bool = False
    ttl_seconds: int = 300
    route_id: str = "default"
    # Inbound policy for SERVER-INITIATED messages (a server->client request or
    # notification — NOT a response to one of our signed requests). The MCP-S
    # evidence model binds a server's signature to the client's `request_hash`; a
    # server-initiated message has none, so `mcps-client-core` cannot verify it.
    # STRICT MCP-S is the client-initiated request/response subset (to be extended
    # to signed multi-round-trip continuation by a future v0.8 profile; ARBITRARY
    # server push stays out of scope): the safe default FAILS CLOSED (in-taxonomy).
    #
    # `True` is a DEGRADED / MIGRATION policy ONLY — it is an explicit operator
    # opt-OUT of the guarantee for the server-initiated channel, to run legacy
    # servers during migration. The message is then delivered but audited as
    # NO-EVIDENCE. It is NOT strict enterprise MCP-S and must never be presented as
    # such. Leave it off for strict deployments.
    allow_unverified_server_initiated: bool = False


def _rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request_fields(session_message: Any):
    """Return (is_request, id, method, params) from a SessionMessage's root."""
    root = session_message.message.root
    rid = getattr(root, "id", None)
    method = getattr(root, "method", None)
    return (rid is not None and method is not None), rid, method, getattr(root, "params", None)


def _binding_kwargs(config: McpsConfig, method: str, params: Any, deadline_unix: int) -> dict:
    """Resolve the authorization-binding signing kwargs for this request.

    With ``config.authorization`` set, call the provider (or accept a prebuilt
    binding) under a real :class:`~mcps_sdk.authorization.BindingRequestContext`, so
    the digest is computed by the audited core from the actual artifact — then
    enforce the optional route policy (fails closed on a disallowed type). With no
    provider, fall back to the raw ``binding_digest_*`` opaque shortcut (dev/test).
    """
    if config.authorization is None:
        return {
            "binding_digest_alg": config.binding_digest_alg,
            "binding_digest_value": config.binding_digest_value,
        }
    provider = config.authorization
    if hasattr(provider, "provide"):
        from .authorization import BindingRequestContext

        tool_id = params.get("name") if (method == "tools/call" and isinstance(params, dict)) else None
        binding = provider.provide(
            BindingRequestContext(
                audience=config.audience,
                route_id=config.route_id,
                method=method,
                tool_id=tool_id,
                deadline_unix=deadline_unix,
            )
        )
    else:
        binding = provider  # a prebuilt mcps_sdk.AuthorizationBinding
    if config.authorization_policy is not None:
        config.authorization_policy.enforce(binding)  # raises on a disallowed type
    return {"authorization_binding": binding}


def sign_outbound(
    session_message: Any,
    config: McpsConfig,
    correlation: Any,
    *,
    now_unix: int,
    nonce: str,
    expires_unix: int,
) -> bytes:
    """Sign an outbound request and register it for correlation; return wire bytes.

    A non-request (notification / a response to a server-initiated request) is
    passed through plain for now — signing those is a later slice (#199 gap).
    """
    is_request, rid, method, params = _request_fields(session_message)
    if not is_request:
        return session_message.message.model_dump_json(by_alias=True, exclude_none=True).encode()

    signed = mcps_sdk.sign_request_with_signer(
        json.dumps(rid),
        method,
        json.dumps(params or {}),
        on_behalf_of=config.on_behalf_of,
        audience=config.audience,
        nonce=nonce,
        issued_at=_rfc3339(now_unix),
        expires_at=_rfc3339(expires_unix),
        signer=config.signer,
        policy=config.policy,
        **_binding_kwargs(config, method, params, expires_unix),
    )
    correlation.register(
        correlation_id=str(rid),
        request_hash=signed.request_hash,
        nonce=nonce,
        deadline_unix=expires_unix,
        now_unix=now_unix,
        audience=config.audience,
        route_id=config.route_id,
        expected_server_signers=[config.expected_server_signer]
        if config.expected_server_signer
        else [],
    )
    return signed.wire_bytes


@dataclass
class InboundOutcome:
    """Result of verifying one inbound line. ``kind`` is accept / reject / passthrough."""

    kind: str
    message: Any = None  # a plain SessionMessage on accept/passthrough
    reason: Optional[str] = None  # the mcps.* wire reason on reject


def _strip_envelope(obj: dict) -> dict:
    """Remove the MCP-S response envelope from ``result._meta`` so the app sees plain MCP."""
    result = obj.get("result")
    meta = result.get("_meta") if isinstance(result, dict) else None
    if isinstance(meta, dict):
        meta.pop(mcps_sdk.response_meta_key(), None)
        if not meta:
            result.pop("_meta", None)
    return obj


def _session_message(obj_or_bytes: Any) -> Any:
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage

    raw = obj_or_bytes if isinstance(obj_or_bytes, (bytes, bytearray, str)) else json.dumps(obj_or_bytes)
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


def verify_inbound(
    line: bytes,
    config: McpsConfig,
    correlation: Any,
    *,
    now_unix: int,
) -> InboundOutcome:
    """Correlate + verify one inbound line.

    A response to one of our requests (has ``id``, no ``method``) is correlated and
    verified; on accept the MCP-S envelope is stripped and a plain SessionMessage is
    returned. A late/uncorrelatable/expired correlation or a failed verification is
    a fail-closed reject.

    A SERVER-INITIATED message (it carries a ``method`` — a server->client request if
    id-bearing, a notification if not) is NOT a response to one of our requests, so
    there is no ``request_hash`` to bind it and the core cannot verify it. The
    ``allow_unverified_server_initiated`` policy decides: fail closed under the safe
    default (``mcps.missing_envelope`` for an id-bearing server request,
    ``mcps.notification_forbidden`` for a notification — both in the frozen
    taxonomy), or pass it through unverified (audited as no-evidence) when allowed.
    """
    obj = json.loads(line)
    has_method = "method" in obj
    rid = obj.get("id")

    if has_method:
        # Server-initiated request/notification — no request_hash binding exists, so
        # the core cannot verify it. Apply the inbound policy.
        if config.allow_unverified_server_initiated:
            return InboundOutcome("passthrough", message=_session_message(obj))
        reason = "mcps.missing_envelope" if rid is not None else "mcps.notification_forbidden"
        return InboundOutcome("reject", reason=reason)

    if rid is None:
        # Neither a method nor an id: not a correlatable JSON-RPC response. Fail
        # closed rather than deliver an uncorrelatable, unverifiable message.
        return InboundOutcome("reject", reason="mcps.missing_envelope")

    # A response to one of our outstanding requests.
    try:
        entry = correlation.take_for_response(str(rid), now_unix)
    except ValueError as exc:
        # late / uncorrelatable / expired -> fail closed. Normalize to the bare
        # mcps.* wire code so reject reasons are consistent with the verify path.
        return InboundOutcome("reject", reason=str(exc).rsplit(": ", 1)[-1])

    result = mcps_sdk.verify_response(
        line,
        resolver=config.resolver,
        expected_request_hash=entry.request_hash,
        expected_server_signer=config.expected_server_signer,
        enforcement_mode=config.enforcement_mode,
        legacy_allowed=config.legacy_allowed,
    )
    if result.accepted:
        return InboundOutcome("accept", message=_session_message(_strip_envelope(obj)))
    if result.decision == "fallback":
        # Config-permitted legacy/plaintext pass-through (audited as no-evidence).
        return InboundOutcome("accept", message=_session_message(obj))
    return InboundOutcome("reject", reason=result.reason)


# Byte-channel callables the async transport pumps over.
ByteSend = Callable[[bytes], Awaitable[None]]  # write framed bytes to the wire


class McpsTransport:
    """Thin async glue: pumps :func:`sign_outbound` / :func:`verify_inbound` between
    a byte channel (the real wire) and the in-memory streams ``ClientSession`` uses.

    ``byte_send`` writes framed bytes to the wire; ``byte_lines`` is an async
    iterator of inbound raw lines (newline-delimited JSON, the MCP stdio framing).
    Inject these from a subprocess (stdio) — or, in tests, from in-memory pipes.
    """

    def __init__(
        self,
        byte_send: ByteSend,
        byte_lines: Any,  # async iterator of bytes lines
        config: McpsConfig,
        correlation: Any = None,
        *,
        clock: Optional[Callable[[], int]] = None,
        nonce_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        self._byte_send = byte_send
        self._byte_lines = byte_lines
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
        self._tg.start_soon(self._reader_loop)
        return app_read_recv, app_write_send

    async def __aexit__(self, *exc):
        if self._tg is not None:
            self._tg.cancel_scope.cancel()
            await self._tg.__aexit__(*exc)

    async def _writer_loop(self):
        async for session_message in self._app_write_recv:
            now = self._clock()
            wire = sign_outbound(
                session_message,
                self._config,
                self._correlation,
                now_unix=now,
                nonce=self._nonce_factory(),
                expires_unix=now + self._config.ttl_seconds,
            )
            await self._byte_send(wire + b"\n")

    async def _reader_loop(self):
        async for line in self._byte_lines:
            if not line:
                continue
            outcome = verify_inbound(line, self._config, self._correlation, now_unix=self._clock())
            if outcome.kind in ("accept", "passthrough"):
                await self._app_read_send.send(outcome.message)
            else:
                # Fail closed: surface to ClientSession via the read stream.
                await self._app_read_send.send(McpsVerificationError(outcome.reason))
