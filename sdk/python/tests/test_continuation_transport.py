"""ADR-MCPS-047 multi-round-trip driving through the async SDK transport (v0.8).

The primitives (sign_request continuation kwargs, verify classification,
record_input_required) are covered by test_continuation.py. THIS file proves the
transport GLUE a real ``mcp.ClientSession`` uses actually drives the elicitation
round trip end to end, and that the server-initiated boundary stays fail-closed:

  1. a verified InputRequiredResult is delivered to the session as plain MCP;
  2. it is retained (associate-without-consume), not consumed as terminal;
  3. the answer leg is signed WITH the continuation binding;
  4. a terminal response bound to the FIRST-round hash (not the continuation hash)
     fails closed;
  5. a tampered/mismatched requestState on the answer leg fails closed;
  6. an answer with no recorded MRT state fails closed;
  7. a replayed continuation fails closed (single-use);
  8. arbitrary server push (a method-bearing elicitation REQUEST) still fails closed.

Requires `mcp` (Python >= 3.10).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import mcps_sdk
from mcps_sdk.transport import McpsConfig, McpsTransport, sign_outbound, verify_inbound

anyio = pytest.importorskip("anyio")
pytest.importorskip("mcp.types")
from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage  # noqa: E402

REQUEST_META_KEY = "se.syncom/mcps.request"
FIX = Path(__file__).parent / "fixtures"
REQ = json.loads((FIX / "sign_request_vector.json").read_text())["inputs"]
RESP = json.loads((FIX / "verify_response_vectors.json").read_text())
SERVER = RESP["server"]
H1 = RESP["client_request_hash"]  # the first-round request hash the IRR binds

NOW = int(datetime(2026, 6, 30, 20, 0, 0, tzinfo=timezone.utc).timestamp())
TTL = 300
# The requestState the generator's InputRequiredResult carries.
STATE = "eyJzdGVwIjoxfQ"


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


def _scenario(name):
    return next(s for s in RESP["scenarios"] if s["name"] == name)


def _input_required_bytes():
    return _scenario("input_required")["response_bytes"].encode()


def _irr_response_hash():
    return _scenario("input_required")["expected"]["response_hash"]


def _sm(rid, method, params):
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


def _answer(rid="req-2", request_state=STATE):
    return _sm(
        rid,
        "tools/call",
        {
            "name": "delete_files",
            "arguments": {"paths": ["a", "b", "c"]},
            "inputResponses": {"confirm": True},
            "requestState": request_state,
        },
    )


def _register_first(corr):
    corr.register(
        correlation_id="req-1",
        request_hash=H1,
        nonce="n1",
        deadline_unix=NOW + TTL,
        now_unix=NOW,
    )


def _receive_elicitation(corr, mrt):
    """Verify the InputRequiredResult through the inbound path; return the outcome."""
    _register_first(corr)
    return verify_inbound(_input_required_bytes(), _config(), corr, now_unix=NOW + 1, mrt=mrt)


# --- 1 + 2: delivered as plain MCP, retained not consumed -------------------


def test_input_required_delivered_plain_and_retained():
    corr = mcps_sdk.CorrelationStore()
    mrt = {}
    out = _receive_elicitation(corr, mrt)
    assert out.kind == "accept"
    dumped = json.loads(out.message.message.model_dump_json(by_alias=True, exclude_none=True))
    assert dumped["result"]["resultType"] == "inputRequired"
    assert "_meta" not in dumped["result"], "MCP-S envelope must be stripped"
    # Retained as non-terminal (D7), NOT consumed as a terminal response.
    assert corr.outstanding == 0
    assert corr.non_terminal_outstanding == 1
    # MRT state stashed under the opaque requestState handle.
    assert STATE in mrt


# --- 3: the answer leg is signed with the continuation binding --------------


def test_answer_leg_signed_with_continuation_binding():
    corr = mcps_sdk.CorrelationStore()
    mrt = {}
    _receive_elicitation(corr, mrt)
    wire = sign_outbound(
        _answer(), _config(), corr, now_unix=NOW + 2, nonce="answernoncefresh1", expires_unix=NOW + 2 + TTL, mrt=mrt
    )
    env = json.loads(wire)["params"]["_meta"][REQUEST_META_KEY]
    assert env["continuation"]["type"] == "mcp-mrt"
    assert env["continuation"]["previous_request_hash"] == H1
    assert env["continuation"]["input_required_response_hash"] == _irr_response_hash()
    # Single-use: the handle is consumed.
    assert STATE not in mrt
    # The continuation is a fresh outstanding request.
    assert corr.outstanding == 1


# --- 4: the first-round leg is spent — its response can't complete the exchange -


def test_first_round_response_cannot_be_replayed_after_input_required():
    """The terminal must bind the CONTINUATION's request_hash, not the first round's.
    After the InputRequiredResult, the first-round slot (req-1) is consumed into the
    non-terminal record, so replaying a first-round-bound response — the valid
    terminal, correctly signed, still id=req-1 (the whole object incl. id is signed,
    so it cannot be retargeted to the continuation id) — cannot correlate. It fails
    closed, so a first-round response can never be spliced in as the continuation's
    terminal."""
    corr = mcps_sdk.CorrelationStore()
    mrt = {}
    _receive_elicitation(corr, mrt)
    assert corr.non_terminal_outstanding == 1 and corr.outstanding == 0
    out = verify_inbound(_scenario("valid")["response_bytes"].encode(), _config(), corr, now_unix=NOW + 2)
    assert out.kind == "reject"
    assert out.reason == "mcps.response_hash_mismatch"


# --- 5: tampered / mismatched requestState fails closed ---------------------


def test_tampered_request_state_fails_closed():
    corr = mcps_sdk.CorrelationStore()
    mrt = {}
    _receive_elicitation(corr, mrt)
    # The client echoes a DIFFERENT requestState than the one bound to the exchange.
    with pytest.raises(ValueError, match="continuation_malformed"):
        sign_outbound(
            _answer(request_state="dGFtcGVyZWQ"),
            _config(),
            corr,
            now_unix=NOW + 2,
            nonce="answernoncefresh1",
            expires_unix=NOW + 2 + TTL,
            mrt=mrt,
        )


# --- 6: no recorded MRT state fails closed ----------------------------------


def test_answer_without_recorded_state_fails_closed():
    corr = mcps_sdk.CorrelationStore()
    with pytest.raises(ValueError, match="no recorded multi-round-trip state"):
        sign_outbound(
            _answer(), _config(), corr, now_unix=NOW + 2, nonce="answernoncefresh1", expires_unix=NOW + 2 + TTL, mrt={}
        )


# --- 7: replayed continuation fails closed (single-use) ---------------------


def test_replayed_continuation_fails_closed():
    corr = mcps_sdk.CorrelationStore()
    mrt = {}
    _receive_elicitation(corr, mrt)
    sign_outbound(
        _answer(), _config(), corr, now_unix=NOW + 2, nonce="answernoncefresh1", expires_unix=NOW + 2 + TTL, mrt=mrt
    )
    # Replaying the same answer (fresh nonce) finds no MRT state -> fail closed.
    with pytest.raises(ValueError, match="no recorded multi-round-trip state"):
        sign_outbound(
            _answer(rid="req-3"),
            _config(),
            corr,
            now_unix=NOW + 3,
            nonce="answernoncefresh2",
            expires_unix=NOW + 3 + TTL,
            mrt=mrt,
        )


# --- 8: arbitrary server push still fails closed ----------------------------


def test_server_initiated_elicitation_request_still_fails_closed():
    """A legitimate elicitation arrives as a RESPONSE (InputRequiredResult). A
    server that PUSHES an elicitation as a method-bearing request is arbitrary push
    (D9) — no request_hash binding — and fails closed under require_mcps."""
    push = json.dumps(
        {"jsonrpc": "2.0", "id": "s-1", "method": "elicitation/create", "params": {"message": "hi"}}
    ).encode()
    out = verify_inbound(push, _config(), mcps_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "reject"
    assert out.reason == "mcps.missing_envelope"


# --- async end to end: reader records, writer binds (shared self._mrt) -------


def test_async_transport_drives_elicitation_round_trip():
    async def scenario():
        sent = []

        async def byte_send(b):
            sent.append(b)

        send_lines, recv_lines = anyio.create_memory_object_stream(10)
        corr = mcps_sdk.CorrelationStore()
        _register_first(corr)
        transport = McpsTransport(
            byte_send, recv_lines, _config(), corr,
            clock=lambda: NOW + 1, nonce_factory=lambda: "asyncanswernonce1",
        )
        async with transport as (read_stream, write_stream):
            # Server elicits.
            await send_lines.send(_input_required_bytes())
            elicit = await read_stream.receive()
            # Client answers; the writer must pick up the recorded MRT state.
            await write_stream.send(_answer())
            await anyio.sleep(0.05)
        return elicit, sent

    elicit, sent = anyio.run(scenario)
    # `elicit` is the SessionMessage the reader delivered; `.message` is its JSONRPCMessage.
    dumped = json.loads(elicit.message.model_dump_json(by_alias=True, exclude_none=True))
    assert dumped["result"]["resultType"] == "inputRequired"
    assert sent, "the answer leg must have been signed to the wire"
    env = json.loads(sent[-1].rstrip(b"\n"))["params"]["_meta"][REQUEST_META_KEY]
    assert env["continuation"]["previous_request_hash"] == H1
    assert env["continuation"]["input_required_response_hash"] == _irr_response_hash()


# --- request/response (mTLS/HTTP) transport: same MRT threading, one POST per leg -


def test_http_transport_drives_elicitation_round_trip():
    """ADR-047 continuation through :class:`McpsHttpTransport` — the one-POST-per-request
    wire the production ``connect_mtls_http`` uses. Proves the transport's own MRT
    threading (``self._mrt`` recorded on the InputRequiredResult leg, bound on the answer
    leg): without it the answer POST would fail closed as ``mcps.continuation_malformed``.

    The stdio async test above injects the server IRR into a passive byte pump; the HTTP
    transport has no such channel — every inbound message is the response to a POST — so a
    fake ``post`` returns the (pre-signed) IRR for the first leg and captures the answer
    leg's wire. As in that test, the first-round hash is stood in for by the pre-registered
    ``H1`` (the fixture IRR binds it); the first leg carries a DISTINCT id so its own
    correlation entry does not clobber that pre-registration."""
    from mcps_sdk.http_transport import McpsHttpTransport

    posted: list = []

    def fake_post(wire: bytes):
        posted.append(wire)
        # Leg 1 (the elicit): reply with the server-signed InputRequiredResult (bound to
        # H1). Leg 2 (the answer): we assert on the captured wire, so any well-formed body
        # that fails closed is fine — it is delivered as a correlated reject we drain.
        return ("application/json", _input_required_bytes() if len(posted) == 1 else b"{}")

    nonces = iter([f"httpnonce{i}" for i in range(8)])

    async def scenario():
        corr = mcps_sdk.CorrelationStore()
        _register_first(corr)  # the pre-registered first-round (H1) the fixture IRR binds
        transport = McpsHttpTransport(
            fake_post,
            _config(),
            corr,
            clock=lambda: NOW + 1,
            nonce_factory=lambda: next(nonces),  # distinct per leg (both legs sign here)
        )
        async with transport as (read_stream, write_stream):
            # A DISTINCT id (not req-1) so this leg's own entry can't overwrite H1's.
            await write_stream.send(
                _sm("req-0", "tools/call", {"name": "delete_files", "arguments": {"paths": ["a", "b", "c"]}})
            )
            elicit = await read_stream.receive()
            # The answer: the writer must pick up the recorded MRT state and bind it.
            await write_stream.send(_answer())
            await read_stream.receive()  # drain the answer leg's (fail-closed) delivery
        return elicit

    elicit = anyio.run(scenario)
    dumped = json.loads(elicit.message.model_dump_json(by_alias=True, exclude_none=True))
    assert dumped["result"]["resultType"] == "inputRequired"
    assert len(posted) == 2, "both the elicit leg and the answer leg must POST"
    env = json.loads(posted[-1])["params"]["_meta"][REQUEST_META_KEY]
    assert env["continuation"]["type"] == "mcp-mrt"
    assert env["continuation"]["previous_request_hash"] == H1
    assert env["continuation"]["input_required_response_hash"] == _irr_response_hash()
