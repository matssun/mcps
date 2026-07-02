"""ADR-MCPS-047 continuation-binding tests for the Python SDK (v0.8).

Covers the three SDK surfaces the multi-round-trip flow needs:
  1. `sign_request(..., continuation_*)` embeds the signed `continuation` binding;
  2. `verify_response` classifies a signed `InputRequiredResult` (`input_required`,
     `response_hash`) — read only from verified bytes;
  3. `CorrelationStore.record_input_required` associates-without-consuming and returns
     the `(previous_request_hash, input_required_response_hash)` binding to sign the
     answer leg.

The signed InputRequiredResult response comes from the independent Rust oracle
(`cargo run --example gen_response_vector`), so classification is checked against a
real verified response, not a hand-built one.
"""

import json
from pathlib import Path

import pytest

import mcps_sdk

# Frozen wire constant (the request envelope key under params._meta).
REQUEST_META_KEY = "se.syncom/mcps.request"
SEED = bytes(range(32))
DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"

FIXTURE = Path(__file__).parent / "fixtures" / "verify_response_vectors.json"
VEC = json.loads(FIXTURE.read_text())
SERVER = VEC["server"]
CLIENT_RH = VEC["client_request_hash"]


def _sign(**continuation):
    return mcps_sdk.sign_request(
        '"req-1"',
        "tools/call",
        '{"name":"echo","arguments":{}}',
        signer="did:example:client",
        key_id="k1",
        on_behalf_of="user:alice",
        audience="did:example:server",
        nonce="Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        issued_at="2026-06-30T20:00:00Z",
        expires_at="2026-06-30T20:05:00Z",
        seed=SEED,
        binding_digest_alg="sha256",
        binding_digest_value=DIGEST,
        **continuation,
    )


def _envelope(signed):
    obj = json.loads(signed.wire_bytes)
    return obj["params"]["_meta"][REQUEST_META_KEY]


def _resolver():
    r = mcps_sdk.TrustResolver()
    r.insert_public_key(
        SERVER["signer_id"], SERVER["key_id"], bytes.fromhex(SERVER["public_key_hex"])
    )
    return r


def _input_required_scenario():
    return next(s for s in VEC["scenarios"] if s["name"] == "input_required")


# --- 1. signing the continuation binding -----------------------------------


def test_ordinary_request_omits_continuation():
    assert "continuation" not in _envelope(_sign())


def test_continuation_request_binds_both_hashes():
    signed = _sign(
        continuation_previous_request_hash=CLIENT_RH,
        continuation_input_required_response_hash="sha256:" + DIGEST,
    )
    cont = _envelope(signed)["continuation"]
    assert cont["type"] == "mcp-mrt"
    assert cont["previous_request_hash"] == CLIENT_RH
    assert cont["input_required_response_hash"] == "sha256:" + DIGEST


def test_one_sided_continuation_is_rejected():
    with pytest.raises(ValueError, match="continuation requires BOTH"):
        _sign(continuation_previous_request_hash=CLIENT_RH)


# --- 2. classifying a verified InputRequiredResult --------------------------


def test_verify_classifies_input_required():
    s = _input_required_scenario()
    res = mcps_sdk.verify_response(
        s["response_bytes"].encode(),
        resolver=_resolver(),
        expected_request_hash=s["params"]["expected_request_hash"],
        expected_server_signer=s["params"]["expected_server_signer"],
    )
    assert res.accepted
    assert res.input_required
    assert res.result_class == "input_required"
    assert res.response_hash == s["expected"]["response_hash"]


def test_terminal_response_is_not_input_required():
    valid = next(s for s in VEC["scenarios"] if s["name"] == "valid")
    res = mcps_sdk.verify_response(
        valid["response_bytes"].encode(),
        resolver=_resolver(),
        expected_request_hash=valid["params"]["expected_request_hash"],
        expected_server_signer=valid["params"]["expected_server_signer"],
    )
    assert res.accepted
    assert not res.input_required
    assert res.result_class == "terminal"


# --- 3. correlation store: associate-without-consume ------------------------


def test_record_input_required_retains_and_returns_binding():
    store = mcps_sdk.CorrelationStore()
    store.register(
        correlation_id="c1",
        request_hash=CLIENT_RH,
        nonce="n1",
        deadline_unix=2000,
        now_unix=1000,
    )
    prev, resp = store.record_input_required("c1", "sha256:" + DIGEST, 1500)
    assert prev == CLIENT_RH
    assert resp == "sha256:" + DIGEST
    # The original response slot is consumed; the exchange stays associated.
    assert store.outstanding == 0
    assert store.non_terminal_outstanding == 1


# --- end to end: verify -> record -> sign the continuation ------------------


def test_end_to_end_continuation_round_trip():
    s = _input_required_scenario()
    res = mcps_sdk.verify_response(
        s["response_bytes"].encode(),
        resolver=_resolver(),
        expected_request_hash=CLIENT_RH,
        expected_server_signer=SERVER["signer_id"],
    )
    assert res.input_required

    store = mcps_sdk.CorrelationStore()
    store.register(
        correlation_id="c1",
        request_hash=CLIENT_RH,
        nonce="n1",
        deadline_unix=2000,
        now_unix=1000,
    )
    prev, resp = store.record_input_required("c1", res.response_hash, 1500)

    signed = _sign(
        continuation_previous_request_hash=prev,
        continuation_input_required_response_hash=resp,
    )
    cont = _envelope(signed)["continuation"]
    assert cont["previous_request_hash"] == CLIENT_RH
    assert cont["input_required_response_hash"] == res.response_hash
