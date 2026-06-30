"""Streamable-HTTP multi-path inbound decode + uniform verification.

Covers the SSE framing parser, the content-type-aware `decode_inbound`, and that
EVERY decode site (direct JSON and SSE) routes through the same MCP-S verification
and server-initiated policy. The production `mcps-proxy` is JSON-only, so these are
unit tests over golden response vectors (the same fixtures the transport uses) plus
synthesized SSE framing — the decoder is the verification-correct layer a future
streaming transport plugs into.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import mcps_sdk
from mcps_sdk.streamable import decode_inbound, sse_data_events, verify_inbound_messages

FIX = Path(__file__).parent / "fixtures"
REQ = json.loads((FIX / "sign_request_vector.json").read_text())["inputs"]
RESP = json.loads((FIX / "verify_response_vectors.json").read_text())
SERVER = RESP["server"]
NOW = int(datetime(2026, 6, 30, 20, 0, 0, tzinfo=timezone.utc).timestamp())
TTL = 300


def _config(**kw):
    resolver = mcps_sdk.TrustResolver()
    resolver.insert_public_key(
        SERVER["signer_id"], SERVER["key_id"], bytes.fromhex(SERVER["public_key_hex"])
    )
    base = dict(
        signer=mcps_sdk.Signer.software(
            bytes.fromhex(REQ["seed_hex"]), signer_id=REQ["signer"], key_id=REQ["key_id"]
        ),
        policy=mcps_sdk.SignerPolicy(REQ["signer"], environment="dev-test", require_mcps=True),
        resolver=resolver,
        audience=REQ["audience"],
        on_behalf_of=REQ["on_behalf_of"],
        binding_digest_alg=REQ["binding_digest_alg"],
        binding_digest_value=REQ["binding_digest_value"],
        expected_server_signer=SERVER["signer_id"],
        ttl_seconds=TTL,
    )
    base.update(kw)
    return mcps_sdk.McpsConfig(**base)


def _valid_response() -> str:
    return next(s for s in RESP["scenarios"] if s["name"] == "valid")["response_bytes"]


def _registered():
    corr = mcps_sdk.CorrelationStore()
    corr.register(
        correlation_id="req-1",
        request_hash=RESP["client_request_hash"],
        nonce="n1",
        deadline_unix=NOW + TTL,
        now_unix=NOW,
    )
    return corr


def _sse(*payloads: str) -> bytes:
    """Frame each JSON payload as one SSE `data` event (multi-line safe)."""
    out = ""
    for payload in payloads:
        out += "".join(f"data: {line}\n" for line in payload.split("\n")) + "\n"
    return out.encode()


# --- SSE framing parser ----------------------------------------------------

def test_sse_single_event():
    assert sse_data_events(b"data: hello\n\n") == [b"hello"]


def test_sse_multiple_events():
    assert sse_data_events(b"data: a\n\ndata: b\n\n") == [b"a", b"b"]


def test_sse_multiline_data_joined_with_newline():
    assert sse_data_events(b"data: line1\ndata: line2\n\n") == [b"line1\nline2"]


def test_sse_ignores_comments_and_other_fields():
    raw = b": keep-alive\nevent: message\nid: 7\ndata: payload\nretry: 1000\n\n"
    assert sse_data_events(raw) == [b"payload"]


def test_sse_crlf_terminators():
    assert sse_data_events(b"data: x\r\n\r\ndata: y\r\n\r\n") == [b"x", b"y"]


def test_sse_trailing_event_without_blank_line():
    assert sse_data_events(b"data: tail") == [b"tail"]


def test_sse_event_without_data_yields_nothing():
    assert sse_data_events(b"event: ping\n\n") == []


def test_sse_strips_only_one_leading_space():
    assert sse_data_events(b"data:  two-spaces\n\n") == [b" two-spaces"]


# --- content-type dispatch -------------------------------------------------

def test_decode_direct_json():
    assert decode_inbound("application/json", b'{"a":1}') == [b'{"a":1}']


def test_decode_unspecified_content_type_is_direct_json():
    assert decode_inbound("", b'{"a":1}') == [b'{"a":1}']


def test_decode_event_stream_with_charset_param():
    assert decode_inbound("text/event-stream; charset=utf-8", b"data: {}\n\n") == [b"{}"]


def test_decode_empty_body_yields_nothing():
    assert decode_inbound("application/json", b"   ") == []


# --- uniform verification across decode sites ------------------------------

def test_direct_json_response_verifies_and_strips():
    outcomes = verify_inbound_messages(
        "application/json", _valid_response().encode(), _config(), _registered(), now_unix=NOW + 1
    )
    assert [o.kind for o in outcomes] == ["accept"]
    dumped = json.loads(outcomes[0].message.message.model_dump_json(by_alias=True, exclude_none=True))
    assert "_meta" not in dumped.get("result", {})


def test_sse_framed_response_verifies_identically():
    """The SAME signed response delivered as an SSE event verifies exactly as the
    direct-JSON path — proving the SSE decode site routes through verification."""
    outcomes = verify_inbound_messages(
        "text/event-stream", _sse(_valid_response()), _config(), _registered(), now_unix=NOW + 1
    )
    assert [o.kind for o in outcomes] == ["accept"]


def test_sse_server_initiated_notification_fails_closed():
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    outcomes = verify_inbound_messages(
        "text/event-stream", _sse(notif), _config(), mcps_sdk.CorrelationStore(), now_unix=NOW
    )
    assert outcomes[0].kind == "reject"
    assert outcomes[0].reason == "mcps.notification_forbidden"


def test_sse_interleaved_response_and_server_message():
    """A POST-SSE stream carrying the correlated response AND a server-initiated
    notification: the response is accepted, the unverifiable notification is rejected
    by policy — each decoded message independently runs the inbound pipeline."""
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    outcomes = verify_inbound_messages(
        "text/event-stream", _sse(_valid_response(), notif), _config(), _registered(), now_unix=NOW + 1
    )
    assert [o.kind for o in outcomes] == ["accept", "reject"]
    assert outcomes[1].reason == "mcps.notification_forbidden"


def test_sse_server_initiated_passthrough_when_allowed():
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    outcomes = verify_inbound_messages(
        "text/event-stream", _sse(notif),
        _config(allow_unverified_server_initiated=True), mcps_sdk.CorrelationStore(), now_unix=NOW,
    )
    assert outcomes[0].kind == "passthrough"
