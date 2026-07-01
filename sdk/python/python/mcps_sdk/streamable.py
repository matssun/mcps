"""Streamable-HTTP multi-path inbound decode — every decode site routes through MCP-S.

The MCP streamable-HTTP transport admits JSON-RPC messages at THREE inbound decode
sites, and a secure adapter must run EVERY one through the same verification +
server-initiated policy (the spike's open item, README "three inbound decode
sites"):

1. **direct JSON** — a ``POST`` answered with ``Content-Type: application/json``
   carrying one JSON-RPC response (the correlated, ``request_hash``-bound case).
2. **POST-SSE** — a ``POST`` answered with ``Content-Type: text/event-stream``: the
   correlated response, possibly interleaved with server-initiated messages, each
   delivered as one SSE ``data`` event.
3. **standalone GET-SSE** — a separate ``GET`` opening a ``text/event-stream`` of
   purely server-initiated messages (no correlated responses).

This module is the single decode choke point: :func:`decode_inbound` turns a
``(content_type, body)`` pair from ANY of those sites into a list of raw JSON-RPC
payloads, and :func:`verify_inbound_messages` runs each payload through
:func:`~mcps_sdk.transport.verify_inbound` — so the correlated-response verification
AND the server-initiated inbound policy (fail-closed by default; see
``McpsConfig.allow_unverified_server_initiated``) apply uniformly at all three sites.

The SSE parser operates on a fully-read body (the bytes already buffered). True
incremental SSE streaming — consuming events as they arrive on a long-lived
connection — belongs to a dedicated streaming transport; this layer is the
verification-correct decoder that such a transport plugs into.
"""

from __future__ import annotations

from typing import Any, List

from .transport import InboundOutcome, McpsConfig, verify_inbound


def sse_data_events(raw: bytes) -> List[bytes]:
    """Parse a ``text/event-stream`` body into the ``data`` payload of each event.

    Implements the W3C SSE framing the MCP transport relies on: events are separated
    by a blank line; ``data:`` field lines accumulate and are joined with ``\\n``;
    comment lines (leading ``:``) and non-``data`` fields (``event`` / ``id`` /
    ``retry``) are ignored; a single leading space after the field colon is stripped.
    Accepts CRLF, LF, or bare-CR terminators. Each returned payload is one JSON-RPC
    message (MCP emits one message per event). An event with no ``data`` field
    yields nothing.
    """
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    events: List[bytes] = []
    data_lines: List[str] = []

    def dispatch() -> None:
        if data_lines:
            payload = "\n".join(data_lines)
            if payload:
                events.append(payload.encode("utf-8"))
            data_lines.clear()

    for line in text.split("\n"):
        if line == "":
            dispatch()
            continue
        if line.startswith(":"):
            continue  # comment
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
        # event / id / retry (and unknown fields) are not security-relevant here.
    dispatch()  # a final event need not be followed by a blank line
    return events


def decode_inbound(content_type: str, body: bytes) -> List[bytes]:
    """Decode one inbound HTTP body into its JSON-RPC payload(s), by content type.

    ``text/event-stream`` is parsed into one payload per SSE ``data`` event;
    anything else (``application/json`` or unspecified) is treated as a single
    direct JSON-RPC message. An empty body yields no payloads.
    """
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type == "text/event-stream":
        return sse_data_events(body)
    trimmed = body.strip()
    return [trimmed] if trimmed else []


def verify_inbound_messages(
    content_type: str,
    body: bytes,
    config: McpsConfig,
    correlation: Any,
    *,
    now_unix: int,
) -> List[InboundOutcome]:
    """Decode an inbound body (any of the three sites) and verify EVERY message.

    Each decoded JSON-RPC payload is run through
    :func:`~mcps_sdk.transport.verify_inbound`, so a correlated response is
    ``request_hash``-verified and a server-initiated message is subjected to the
    fail-closed inbound policy — uniformly, whichever decode site the body came from.
    """
    outcomes: List[InboundOutcome] = []
    for payload in decode_inbound(content_type, body):
        if not payload:
            continue
        try:
            outcomes.append(verify_inbound(payload, config, correlation, now_unix=now_unix))
        except ValueError:
            outcomes.append(InboundOutcome("reject", reason="mcps.missing_envelope"))
    return outcomes
