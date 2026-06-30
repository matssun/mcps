"""Transport-adapter tests (#199, transport slice).

The adapter's security core is two sync functions: sign_outbound (sign + register)
and verify_inbound (correlate + verify + strip). These are tested against the same
golden vectors as the bindings, proving the adapter writes byte-identical signed
requests and verifies responses exactly. Two async tests drive the McpsTransport
pumps over in-memory byte channels via anyio.run (no live subprocess needed).

Requires `mcp` installed (Python >= 3.10).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import mcps_sdk
from mcps_sdk.transport import (
    McpsConfig,
    McpsTransport,
    McpsVerificationError,
    sign_outbound,
    verify_inbound,
)

# These tests exercise the real mcp ClientSession message types; skip cleanly where
# mcp/anyio are not installed (e.g. a core-only Python < 3.10 env).
anyio = pytest.importorskip("anyio")
pytest.importorskip("mcp.types")
from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
REQ_VEC = json.loads((FIX / "sign_request_vector.json").read_text())
REQ = REQ_VEC["inputs"]
REQ_EXPECTED_WIRE = REQ_VEC["expected_wire_bytes"]
RESP = json.loads((FIX / "verify_response_vectors.json").read_text())
SERVER = RESP["server"]

# The request fixture was signed with issued_at=20:00:00Z, expires=20:05:00Z.
NOW = int(datetime(2026, 6, 30, 20, 0, 0, tzinfo=timezone.utc).timestamp())
TTL = 300


def _config(**kw):
    signer = mcps_sdk.Signer.software(
        bytes.fromhex(REQ["seed_hex"]), signer_id=REQ["signer"], key_id=REQ["key_id"]
    )
    policy = mcps_sdk.SignerPolicy(REQ["signer"], environment="dev-test", require_mcps=True)
    resolver = mcps_sdk.TrustResolver()
    resolver.insert_public_key(
        SERVER["signer_id"], SERVER["key_id"], bytes.fromhex(SERVER["public_key_hex"])
    )
    base = dict(
        signer=signer,
        policy=policy,
        resolver=resolver,
        audience=REQ["audience"],
        on_behalf_of=REQ["on_behalf_of"],
        binding_digest_alg=REQ["binding_digest_alg"],
        binding_digest_value=REQ["binding_digest_value"],
        expected_server_signer=SERVER["signer_id"],
        ttl_seconds=TTL,
    )
    base.update(kw)
    return McpsConfig(**base)


def _sm_request(rid, method, params):
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


def _valid_response_bytes():
    return next(s for s in RESP["scenarios"] if s["name"] == "valid")["response_bytes"].encode()


# --- sync security core ----------------------------------------------------

def test_sign_outbound_matches_request_vector():
    """The adapter's writer produces byte-identical signed bytes to the golden
    request vector, and registers the request for correlation."""
    corr = mcps_sdk.CorrelationStore()
    sm = _sm_request("req-1", "tools/call", {"name": "echo", "arguments": {"text": "hello"}})
    wire = sign_outbound(sm, _config(), corr, now_unix=NOW, nonce=REQ["nonce"], expires_unix=NOW + TTL)
    assert wire.decode() == REQ_EXPECTED_WIRE
    assert corr.outstanding == 1


def test_sign_outbound_passes_through_notification():
    corr = mcps_sdk.CorrelationStore()
    notif = SessionMessage(
        JSONRPCMessage.model_validate_json('{"jsonrpc":"2.0","method":"notifications/cancelled"}')
    )
    wire = sign_outbound(notif, _config(), corr, now_unix=NOW, nonce="n", expires_unix=NOW + TTL)
    assert b"notifications/cancelled" in wire
    assert corr.outstanding == 0  # not a request -> not correlated


def _register_for_valid(corr):
    corr.register(
        correlation_id="req-1",
        request_hash=RESP["client_request_hash"],
        nonce="n1",
        deadline_unix=NOW + TTL,
        now_unix=NOW,
    )


def test_verify_inbound_accepts_and_strips_envelope():
    corr = mcps_sdk.CorrelationStore()
    _register_for_valid(corr)
    out = verify_inbound(_valid_response_bytes(), _config(), corr, now_unix=NOW + 1)
    assert out.kind == "accept"
    dumped = json.loads(out.message.message.model_dump_json(by_alias=True, exclude_none=True))
    assert "_meta" not in dumped.get("result", {}), "MCP-S envelope must be stripped"
    assert corr.outstanding == 0  # correlation consumed


def test_verify_inbound_rejects_tampered():
    corr = mcps_sdk.CorrelationStore()
    _register_for_valid(corr)
    tampered = next(s for s in RESP["scenarios"] if s["name"] == "tampered_signature")
    out = verify_inbound(tampered["response_bytes"].encode(), _config(), corr, now_unix=NOW + 1)
    assert out.kind == "reject"
    assert out.reason == "mcps.response_sig_invalid"


def test_verify_inbound_uncorrelatable_without_pending():
    """A response with no registered request fails closed (uncorrelatable)."""
    out = verify_inbound(_valid_response_bytes(), _config(), mcps_sdk.CorrelationStore(), now_unix=NOW + 1)
    assert out.kind == "reject"
    assert out.reason == "mcps.response_hash_mismatch"


def test_verify_inbound_passes_through_server_notification():
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"x": 1}}).encode()
    out = verify_inbound(notif, _config(), mcps_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "passthrough"
    assert out.message.message.root.method == "notifications/message"


# --- async pump wiring (anyio.run, no subprocess) --------------------------

def test_transport_writer_pump_signs_to_wire():
    async def scenario():
        sent = []

        async def byte_send(b):
            sent.append(b)

        _send_lines, recv_lines = anyio.create_memory_object_stream(0)
        corr = mcps_sdk.CorrelationStore()
        transport = McpsTransport(
            byte_send, recv_lines, _config(), corr,
            clock=lambda: NOW, nonce_factory=lambda: REQ["nonce"],
        )
        async with transport as (_read_stream, write_stream):
            await write_stream.send(
                _sm_request("req-1", "tools/call", {"name": "echo", "arguments": {"text": "hello"}})
            )
            await anyio.sleep(0.05)
        return sent, corr.outstanding

    sent, outstanding = anyio.run(scenario)
    assert sent and sent[0].rstrip(b"\n").decode() == REQ_EXPECTED_WIRE
    assert outstanding == 1


def test_transport_reader_pump_verifies_and_delivers():
    async def scenario():
        send_lines, recv_lines = anyio.create_memory_object_stream(10)

        async def byte_send(_b):
            pass

        corr = mcps_sdk.CorrelationStore()
        _register_for_valid(corr)
        transport = McpsTransport(byte_send, recv_lines, _config(), corr, clock=lambda: NOW + 1)
        async with transport as (read_stream, _write_stream):
            await send_lines.send(_valid_response_bytes())
            return await read_stream.receive()

    msg = anyio.run(scenario)
    assert not isinstance(msg, Exception)
    assert str(msg.message.root.id) == "req-1"


def test_transport_reader_pump_surfaces_rejection_as_exception():
    async def scenario():
        send_lines, recv_lines = anyio.create_memory_object_stream(10)

        async def byte_send(_b):
            pass

        corr = mcps_sdk.CorrelationStore()
        _register_for_valid(corr)
        tampered = next(s for s in RESP["scenarios"] if s["name"] == "tampered_signature")
        transport = McpsTransport(byte_send, recv_lines, _config(), corr, clock=lambda: NOW + 1)
        async with transport as (read_stream, _write_stream):
            await send_lines.send(tampered["response_bytes"].encode())
            return await read_stream.receive()

    msg = anyio.run(scenario)
    assert isinstance(msg, McpsVerificationError)
    assert msg.reason == "mcps.response_sig_invalid"
