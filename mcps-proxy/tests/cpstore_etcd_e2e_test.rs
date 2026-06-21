//! Issue #69 (epic #68 v0.4 Axis 1) — live cross-node replay proof against a REAL
//! etcd (the CP / LINEARIZABLE backend).
//!
//! This whole file is compiled ONLY under the `cpstore_etcd` feature (the same
//! feature that compiles the [`EtcdAtomicReplayStore`]). It is a BLACK-BOX
//! exercise of the public `mcps_core::ReplayCache` API over two
//! [`SharedReplayCache`] instances backed by two independent connections to the
//! SAME etcd cluster — modelling two proxy nodes sharing one CP store.
//!
//! etcd is not installed in every environment, so the test is gated on the
//! `MCPS_TEST_ETCD_URL` env var (the etcd v3 JSON gateway, e.g.
//! `http://127.0.0.1:2379`): when it is unset the test prints a skip notice and
//! returns successfully (it does NOT fail — a self-skip is NOT counted as a pass
//! of the live assertion). When it is set (e.g. a CI job that brings up etcd) it
//! runs the load-bearing assertions: a nonce accepted on node A is rejected as a
//! replay on node B, and the inserted key carries a BOUNDED lease TTL (not the
//! now=0 absolute-epoch TTL).
#![cfg(feature = "cpstore_etcd")]

use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use serde_json::Value;

use mcps_core::ReplayCache;
use mcps_core::ReplayDecision;
use mcps_proxy::EtcdAtomicReplayStore;
use mcps_proxy::SharedReplayCache;

const AUD: &str = "did:example:verifier";
const SKEW: i64 = 30;

/// Read the etcd v3 gateway URL the test should run against, or `None` to skip.
/// A real CP store is not present in every environment. Hard-fails under
/// `MCPS_REQUIRE_LIVE_INFRA` so CI cannot score an unavailable backend as a green
/// skip.
fn etcd_url() -> Option<String> {
    let url = std::env::var("MCPS_TEST_ETCD_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!(
            "MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_ETCD_URL is unavailable \
             — this live e2e MUST run under CI, not skip"
        );
    }
    url
}

/// CI opt-in: when `MCPS_REQUIRE_LIVE_INFRA` is set to any non-empty value, a
/// missing-infra SKIP must HARD-FAIL instead of passing, so CI cannot score an
/// unavailable backend as a green test. Unset (local dev) leaves skip behavior
/// unchanged.
fn require_live_infra() -> bool {
    std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

/// Build a `SharedReplayCache` over a fresh etcd connection to `url`. Each call is
/// an independent "node" (its own agent) sharing the one etcd cluster.
fn node(url: &str) -> SharedReplayCache {
    SharedReplayCache::new(Box::new(EtcdAtomicReplayStore::connect(url)), SKEW)
}

/// The composite key `SharedReplayCache` derives, recomputed here so the TTL probe
/// can read the SAME etcd key the cache inserts. Mirrors
/// `SharedReplayCache::composite_key`: length-prefixed `(signer, audience, nonce)`
/// then `sha256_hash_id` (lowercase hex).
fn composite_key(signer: &str, audience: &str, nonce: &str) -> String {
    let preimage = format!(
        "{}:{}|{}:{}|{}:{}",
        signer.len(),
        signer,
        audience.len(),
        audience,
        nonce.len(),
        nonce,
    );
    mcps_core::sha256_hash_id(preimage.as_bytes())
}

/// The load-bearing cross-node proof: a nonce accepted on node A is rejected as a
/// replay on node B, where A and B are two separate `SharedReplayCache` instances
/// over two separate connections to the SAME etcd. This is the LINEARIZABLE
/// horizontal replay-safety property the single-node file cache cannot provide.
#[test]
fn cross_node_insert_via_a_is_replay_via_b() {
    let Some(url) = etcd_url() else {
        eprintln!(
            "SKIP cross_node_insert_via_a_is_replay_via_b: MCPS_TEST_ETCD_URL unset \
             (no etcd available in this environment) — NOT a pass of the live assertion"
        );
        return;
    };

    // A future expiry so the inserted key carries a real multi-second lease window
    // and persists across the two node calls. Test-name-derived signer/nonce so
    // reruns target a distinct key space and never collide with a prior run's
    // still-live entry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64;
    let expires_at = now + 600;
    let signer = "did:example:host#cpstore_cross_node_insert_via_a_is_replay_via_b";
    let nonce = "nonce-69-cpstore-cross-node-insert-via-a-is-replay-via-b";

    let mut node_a = node(&url);
    let mut node_b = node(&url);

    assert_eq!(
        node_a.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Fresh),
        "first sight on node A must be Fresh"
    );
    assert_eq!(
        node_b.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Replay),
        "node B must reject a nonce first seen on node A — shared etcd CP replay state"
    );
}

/// Single-node fresh-then-replay over the real etcd: the same node sees a nonce
/// once as Fresh and again as Replay.
#[test]
fn single_node_fresh_then_replay() {
    let Some(url) = etcd_url() else {
        eprintln!(
            "SKIP single_node_fresh_then_replay: MCPS_TEST_ETCD_URL unset \
             (no etcd available) — NOT a pass of the live assertion"
        );
        return;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64;
    let expires_at = now + 600;
    let signer = "did:example:host#cpstore_single_node_fresh_then_replay";
    let nonce = "nonce-69-cpstore-single-node-fresh-then-replay";

    let mut cache = node(&url);
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Replay),
        "second sight on the same node is a Replay"
    );
}

/// MCPS-090 — live confirmation that the inserted key gets a BOUNDED
/// `retain_until - now` lease window, NOT the `now = 0` absolute-epoch TTL (~56
/// years) that would let the keyspace grow without bound.
///
/// We insert with `expires_at = now + window`, then read the key's lease via the
/// etcd `kv/range` + `lease/timetolive` gateway calls and assert the granted TTL
/// is within a small band of `(window + skew)` and FAR below the absolute-epoch
/// range. Gated on `MCPS_TEST_ETCD_URL` exactly like the other live tests — SKIP
/// is printed and the test returns (never silently a pass of a real assertion)
/// when no etcd is present.
#[test]
fn live_lease_ttl_is_bounded_window_not_absolute_epoch() {
    let Some(url) = etcd_url() else {
        eprintln!(
            "SKIP live_lease_ttl_is_bounded_window_not_absolute_epoch: MCPS_TEST_ETCD_URL \
             unset (no etcd available) — NOT a pass of the live assertion"
        );
        return;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64;
    let window_secs: i64 = 600;
    let expires_at = now + window_secs;
    let signer = "did:example:host#cpstore_live_lease_ttl_bounded_window";
    let nonce = "nonce-69-cpstore-live-lease-ttl-bounded-window";

    let mut cache = node(&url);
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );

    // Read the key's lease id via kv/range, then its remaining TTL via
    // lease/timetolive — both over the same v3 JSON gateway.
    let key_b64 = STANDARD.encode(composite_key(signer, AUD, nonce).as_bytes());
    let range = post_json(&url, "v3/kv/txn", &json!({})); // ensure gateway reachable
    drop(range);
    let range_resp = post_json(
        &url,
        "v3/kv/range",
        &json!({ "key": key_b64 }),
    );
    let lease_str = range_resp["kvs"][0]["lease"]
        .as_str()
        .expect("the inserted key carries a lease (bounded TTL), not lease 0");
    let lease_id: i64 = lease_str.parse().expect("lease id is an integer string");
    assert_ne!(lease_id, 0, "an unleased key would never expire (the now=0 DoS)");

    let ttl_resp = post_json(
        &url,
        "v3/lease/timetolive",
        &json!({ "ID": lease_id }),
    );
    let granted_ttl: i64 = ttl_resp["grantedTTL"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| ttl_resp["grantedTTL"].as_i64())
        .expect("lease grantedTTL present");

    let expected = window_secs + SKEW;
    assert!(
        (granted_ttl - expected).abs() < 60,
        "lease grantedTTL ({granted_ttl}s) must be ≈ the (window + skew) = {expected}s window"
    );
    // The decisive anti-regression bound: the now=0 bug would grant a TTL on the
    // order of expires_at (~1.78e9 s ≈ 56 years). The window is a tiny fraction.
    assert!(
        granted_ttl < expires_at / 1000,
        "lease grantedTTL ({granted_ttl}s) must be vastly below the now=0 absolute-epoch \
         TTL (~{expires_at}s ≈ 56 years)"
    );
}

/// POST a JSON body to the etcd v3 gateway and parse the JSON reply. Used only by
/// the live tests (which already require a reachable etcd), so a transport error
/// here is a genuine test failure, not a fail-closed path under test.
fn post_json(base_url: &str, path: &str, body: &Value) -> Value {
    let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
    let bytes = serde_json::to_vec(body).expect("serialize etcd request");
    let resp = ureq::AgentBuilder::new()
        .build()
        .post(&url)
        .timeout(std::time::Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_bytes(&bytes)
        .unwrap_or_else(|e| panic!("etcd POST {path}: {e}"));
    // Bounded read, mirroring the production bounded-read idiom in
    // `aws_kms_keysource.rs` / `etcd_store.rs`: a misconfigured/hostile
    // `MCPS_TEST_ETCD_URL` could otherwise stream an arbitrarily large body and OOM
    // the test runner. lease/grant and txn replies are tiny — cap at 256 KiB (cap+1
    // so a body whose length is EXACTLY the cap is accepted; only a strictly larger
    // body is rejected). Behavior is otherwise identical to the prior
    // `into_string()` read.
    const MAX_TEST_RESPONSE_BYTES: u64 = 256 * 1024;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_TEST_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("etcd {path} read response: {e}"));
    if buf.len() as u64 > MAX_TEST_RESPONSE_BYTES {
        panic!("etcd {path} response body exceeds {MAX_TEST_RESPONSE_BYTES}-byte cap");
    }
    serde_json::from_slice(&buf).unwrap_or_else(|e| panic!("etcd {path} reply not JSON: {e}"))
}
