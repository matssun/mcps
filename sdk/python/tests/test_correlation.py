"""In-flight correlation tests (Commit B of the response side, #199).

CorrelationStore binds an outgoing signed request to exactly ONE acceptable
returning response, and rejects late, replayed, uncorrelatable, nonce-reused, or
expired responses — fail-closed with the frozen mcps.* wire code (no parallel
taxonomy). The clock is the caller's: every method takes now_unix.

Wire codes are taken from the oracle (`cargo run --example gen_correlation_vectors`)
so they are never hard-coded here.
"""

import json
from pathlib import Path

import pytest

import mcps_sdk

CODES = json.loads(
    (Path(__file__).parent / "fixtures" / "correlation_wire_codes.json").read_text()
)

RH = "sha256:AAAA"


def _register(store, *, cid="c1", nonce="n1", deadline=2000, now=1000, **kw):
    store.register(
        correlation_id=cid,
        request_hash=kw.get("request_hash", RH),
        nonce=nonce,
        deadline_unix=deadline,
        now_unix=now,
        **{k: v for k, v in kw.items() if k != "request_hash"},
    )


def test_register_and_correlate_round_trip():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1", deadline=2000, now=1000)
    assert store.outstanding == 1
    entry = store.take_for_response("c1", 1500)
    assert entry.request_hash == RH
    assert entry.nonce == "n1"
    assert entry.version == "draft-02"
    assert store.outstanding == 0


def test_duplicate_correlation_id_fails_closed():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1")
    with pytest.raises(ValueError, match=CODES["duplicate_correlation_id"]):
        _register(store, cid="c1", nonce="n2")


def test_nonce_reuse_within_window_fails_closed():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="shared", deadline=2000, now=1000)
    with pytest.raises(ValueError, match=CODES["nonce_reuse"]):
        _register(store, cid="c2", nonce="shared", deadline=2000, now=1500)


def test_nonce_reusable_after_window_closes():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="shared", deadline=2000, now=1000)
    store.take_for_response("c1", 1500)
    store.sweep_expired(2001)  # evict the closed nonce window
    _register(store, cid="c2", nonce="shared", deadline=3000, now=2001)
    assert store.outstanding == 1


def test_late_response_after_cleanup_is_uncorrelatable():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1", deadline=2000, now=1000)
    assert store.sweep_expired(2001) == 1
    with pytest.raises(ValueError, match=CODES["uncorrelatable"]):
        store.take_for_response("c1", 2002)


def test_response_past_deadline_is_expired():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1", deadline=2000, now=1000)
    with pytest.raises(ValueError, match=CODES["expired"]):
        store.take_for_response("c1", 2001)
    assert store.outstanding == 0  # removed by the attempt


def test_unknown_correlation_id_is_uncorrelatable():
    store = mcps_sdk.CorrelationStore()
    with pytest.raises(ValueError, match=CODES["uncorrelatable"]):
        store.take_for_response("nope", 1000)


def test_cancel_removes_entry():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1")
    assert store.cancel("c1") is True
    assert store.cancel("c1") is False
    assert store.outstanding == 0
    with pytest.raises(ValueError, match=CODES["uncorrelatable"]):
        store.take_for_response("c1", 1500)


def test_sweep_removes_only_expired():
    store = mcps_sdk.CorrelationStore()
    _register(store, cid="c1", nonce="n1", deadline=1500, now=1000)
    _register(store, cid="c2", nonce="n2", deadline=3000, now=1000)
    assert store.sweep_expired(2000) == 1
    assert store.outstanding == 1
    assert store.take_for_response("c2", 2000).request_hash == RH


def test_pending_entry_carries_metadata():
    store = mcps_sdk.CorrelationStore()
    store.register(
        correlation_id="c1",
        request_hash=RH,
        nonce="n1",
        deadline_unix=2000,
        now_unix=1000,
        route_id="route-a",
        audience="did:example:server",
        expected_server_signers=["did:example:server"],
        authz_digest="digest123",
    )
    e = store.take_for_response("c1", 1500)
    assert e.route_id == "route-a"
    assert e.audience == "did:example:server"
    assert e.expected_server_signers == ["did:example:server"]
    assert e.authz_digest == "digest123"
