//! etcd-backed [`AtomicReplayStore`] — the #69 (epic #68 v0.4 Axis 1) CP /
//! LINEARIZABLE shared replay backend that makes
//! `--replay-durability-tier linearizable` declarable with a real
//! durable-linearizable store behind it (ADR-MCPS-020, resolving that ADR's
//! open question YES).
//!
//! The shared-cache SEMANTICS already live in
//! [`SharedReplayCache`](crate::shared_replay::SharedReplayCache); this module
//! supplies the missing CP backend: a concrete [`AtomicReplayStore`] whose
//! insert-if-absent is enforced by an etcd v3 transaction. Each op is a single
//! atomic mini-transaction over etcd's JSON/HTTP gateway:
//!   * `POST /v3/lease/grant` mints a lease with a BOUNDED TTL (so a recorded
//!     nonce self-evicts after its freshness window — no client-side prune);
//!   * `POST /v3/kv/txn` with `compare { key, target: CREATE, create_revision: 0 }`
//!     makes the absent-check + put one indivisible, linearizable step:
//!       - `succeeded == true`  ⇒ the key was absent and we put it ⇒ `Fresh`;
//!       - `succeeded == false` ⇒ the key already exists ⇒ `Replay`.
//!     Two proxy nodes racing on the same nonce against the same etcd cluster
//!     therefore cannot both observe it absent — etcd linearizes the txn.
//! Multi-node replay safety holds ONLY when every proxy node points at the SAME
//! etcd cluster (a single logical CP store); separate clusters are separate
//! replay universes.
//!
//! ## ADR-MCPS-018 lean-sync firewall
//!
//! The transport is SYNCHRONOUS blocking `ureq` (already a workspace dep) over
//! etcd's v3 JSON gateway — deliberately NOT `etcd-client`/tonic/tokio. Mirrors
//! the `aws_kms_keysource` / `gcp_kms_keysource` hand-audited sync-HTTP style: a
//! bounded per-request timeout so a stalled etcd fails closed within the bound
//! rather than wedging the single-threaded serve loop.
//!
//! This entire module is compiled ONLY under the non-default `cpstore_etcd`
//! cargo feature, so a default build is byte-for-byte unchanged and gains zero
//! dependencies (it reuses `ureq` / `serde_json` / `base64`, already in tree).

use std::io::Read;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use serde_json::Value;

use crate::shared_replay::AtomicReplayStore;
use crate::shared_replay::ReplayStoreError;
use mcps_core::ReplayDecision;

/// A source of the CURRENT Unix time (seconds) for deriving the lease TTL. The
/// proxy's IMPURE edge: `mcps-core` carries no clock (the pure `ReplayCache`
/// trait passes `now_unix = 0`), so the *store* owns its clock here. Production
/// injects [`system_clock`]; tests inject a fixed clock so the TTL arithmetic is
/// deterministic. Mirrors `redis_store::UnixClock`.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Default per-request network timeout when the caller does not thread the
/// configured socket timeouts. Bounded so a sinkholed/half-open etcd cannot wedge
/// the single-threaded serve loop: the replay check runs BEFORE dispatch, so a
/// blocking op with no timeout would stall the whole proxy. Mirrors the
/// `DEFAULT_REDIS_TIMEOUT` / KMS `NETWORK_TIMEOUT` bound.
const DEFAULT_ETCD_TIMEOUT: Duration = Duration::from_secs(30);

/// The production [`UnixClock`]: reads the system clock. A clock that predates the
/// Unix epoch (impossible on a sane host) clamps to 0 rather than panicking.
pub fn system_clock() -> UnixClock {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// Compute the etcd lease TTL (SECONDS) from the already-skew-folded retain-until
/// instant and the CURRENT Unix time.
///
/// Factored out as a PURE function (no clock, no I/O) so the TTL arithmetic is
/// unit-testable everywhere without a live etcd: it is the load-bearing proof
/// that the MCPS-090 `now = 0` bug is gone — with a real `now`, the TTL is the
/// intended `retain_until - now` WINDOW (seconds), not the absolute Unix epoch
/// (~1.78e9 s ≈ 56 years, which would make leases never expire → unbounded
/// keyspace growth / DoS).
///
/// Clamps to a non-negative duration with a minimum of 1 second (etcd rejects a
/// non-positive lease TTL): if the retain-until has already passed, a minimal 1s
/// TTL records the sighting just long enough to answer a same-instant racing
/// replay, matching the in-memory / Redis stores retaining the entry at its
/// retain-until boundary.
pub(crate) fn compute_ttl_secs(expires_at_unix: i64, now_unix: i64) -> i64 {
    expires_at_unix.saturating_sub(now_unix).max(1)
}

/// The etcd lease-grant request body for `POST /v3/lease/grant`: a `TTL` in
/// seconds and `ID: 0` (let etcd assign the lease id). Pure, so the wire shape is
/// unit-testable without a live etcd.
pub(crate) fn build_lease_grant_body(ttl_secs: i64) -> Value {
    json!({ "TTL": ttl_secs, "ID": 0 })
}

/// The etcd put-if-absent transaction body for `POST /v3/kv/txn`.
///
/// `compare`: the key's `CREATE` revision equals `0` — true IFF the key does not
/// yet exist (a never-created key has create_revision 0). On success
/// (`succeeded`) the key is absent, so `success` PUTs it under the granted lease;
/// `failure` is empty (the key already exists ⇒ Replay). etcd v3 JSON encodes
/// keys/values as STANDARD base64. The lease is passed as a STRING (etcd's JSON
/// gateway encodes 64-bit ints as strings to survive JS number precision).
pub(crate) fn build_txn_body(key_b64: &str, value_b64: &str, lease_id: i64) -> Value {
    json!({
        "compare": [{
            "key": key_b64,
            "target": "CREATE",
            "result": "EQUAL",
            "create_revision": "0"
        }],
        "success": [{
            "request_put": {
                "key": key_b64,
                "value": value_b64,
                "lease": lease_id.to_string()
            }
        }],
        "failure": []
    })
}

/// Parse the lease id from an etcd `lease/grant` response. The JSON gateway
/// returns `{ "ID": "<int-as-string>", "TTL": "<int-as-string>", ... }` (64-bit
/// ints as strings). A missing/zero/unparseable id is an operational failure →
/// fail closed (an unleased put would never expire — the very DoS we guard).
pub(crate) fn parse_lease_id(resp: &Value) -> Result<i64, ReplayStoreError> {
    let raw = resp.get("ID").ok_or_else(|| ReplayStoreError::Unavailable {
        details: "etcd lease/grant response missing ID".to_string(),
    })?;
    // The gateway encodes the id as a string; tolerate a raw number too.
    let id = match raw {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
    .ok_or_else(|| ReplayStoreError::Unavailable {
        details: format!("etcd lease/grant ID not an integer: {raw}"),
    })?;
    if id == 0 {
        return Err(ReplayStoreError::Unavailable {
            details: "etcd lease/grant returned lease id 0 (unleased put would never expire)"
                .to_string(),
        });
    }
    Ok(id)
}

/// Map an etcd txn response to a [`ReplayDecision`]. etcd sets `succeeded: true`
/// when the compare held — i.e. the key was absent and the put landed ⇒ `Fresh`.
/// `succeeded: false` (or absent, which etcd uses for a false compare) means the
/// key already existed ⇒ `Replay`. Pure, so the decision mapping is unit-testable
/// without a live etcd.
pub(crate) fn decision_from_txn(resp: &Value) -> ReplayDecision {
    // etcd omits `succeeded` (defaults false) when the compare fails.
    let succeeded = resp.get("succeeded").and_then(Value::as_bool).unwrap_or(false);
    if succeeded {
        ReplayDecision::Fresh
    } else {
        ReplayDecision::Replay
    }
}

/// The HTTP seam between [`EtcdAtomicReplayStore`]'s decision logic and the etcd v3
/// JSON gateway: a single blocking `POST <base>/<path>` that returns the parsed JSON
/// reply or [`ReplayStoreError::Unavailable`] (fail closed). Production is
/// [`UreqEtcdTransport`] (blocking `ureq`); deterministic unit tests inject a
/// scripted double so the lease-grant / txn / lease-revoke call sequence is asserted
/// WITHOUT a live etcd. A trait, not a free function, ONLY to make that seam
/// testable — it adds no async and no new dependency (ADR-MCPS-018 sync firewall).
pub(crate) trait EtcdTransport: Send + Sync {
    fn post(&self, path: &str, body: &Value) -> Result<Value, ReplayStoreError>;
}

/// The production [`EtcdTransport`]: a blocking `ureq` agent over etcd's v3 JSON
/// gateway with a bounded per-request timeout.
struct UreqEtcdTransport {
    agent: ureq::Agent,
    /// The etcd v3 gateway base URL, e.g. `http://127.0.0.1:2379`, with any
    /// trailing slash trimmed so endpoint paths join cleanly.
    base_url: String,
    /// Bounds EACH blocking HTTP op so a stalled etcd fails closed within the
    /// bound instead of wedging the single-threaded serve loop.
    timeout: Duration,
}

impl EtcdTransport for UreqEtcdTransport {
    /// POST `body` to `<base>/<path>` and return the parsed JSON response, or
    /// [`ReplayStoreError::Unavailable`] on any transport / non-2xx status /
    /// JSON-parse failure (fail closed). The bounded `timeout` is applied to the
    /// blocking call. The body is serialized and sent with `send_bytes` (the
    /// `ureq` JSON helpers need an extra cargo feature; this reuses the same
    /// bounded-read idiom as the KMS signers).
    fn post(&self, path: &str, body: &Value) -> Result<Value, ReplayStoreError> {
        let url = format!("{}/{}", self.base_url, path);
        let bytes = serde_json::to_vec(body).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("etcd POST {path} request serialize failed: {e}"),
        })?;
        // A non-2xx status surfaces as `ureq::Error::Status` (also fail closed) —
        // both arms map to Unavailable so an outage / etcd error never serves
        // through as a fresh nonce.
        let response = self
            .agent
            .post(&url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_bytes(&bytes)
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("etcd POST {path} failed: {e}"),
            })?;
        // Bounded read: an overridden/hostile endpoint could otherwise return an
        // arbitrarily large body.
        let mut buf = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("etcd POST {path} read response failed: {e}"),
            })?;
        serde_json::from_slice::<Value>(&buf).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("etcd POST {path} response not JSON: {e}"),
        })
    }
}

/// A SHARED, CP / LINEARIZABLE [`AtomicReplayStore`] backed by etcd v3 over its
/// JSON/HTTP gateway (#69).
///
/// Holds an [`EtcdTransport`] (production: a blocking `ureq` agent over the gateway
/// base URL with a bounded per-request timeout) and the store's own clock (read per
/// op to derive the lease TTL — the pure `ReplayCache` trait passes `now_unix = 0`).
/// Any transport / HTTP-status / JSON-parse failure surfaces as
/// [`ReplayStoreError::Unavailable`] (fail closed — an outage is NEVER silently
/// treated as a fresh nonce, and the proxy never serves through).
pub struct EtcdAtomicReplayStore {
    /// The HTTP seam to etcd's JSON gateway (production `ureq`; scripted in tests).
    transport: Box<dyn EtcdTransport>,
    /// The store's OWN clock (the proxy's impure edge). Read per op to derive the
    /// lease TTL window, since the pure `ReplayCache` trait passes `now_unix = 0`.
    clock: UnixClock,
}

impl EtcdAtomicReplayStore {
    /// Connect to the etcd v3 JSON gateway at `endpoint` (e.g.
    /// `http://127.0.0.1:2379`) with the bounded default timeout and the
    /// production system clock. Convenience over [`connect_with`](Self::connect_with);
    /// prefer that from the CLI so the configured socket timeouts bound the op.
    pub fn connect(endpoint: &str) -> Self {
        Self::connect_with(endpoint, DEFAULT_ETCD_TIMEOUT, system_clock())
    }

    /// Connect with an explicit bounded per-request `timeout` and injected
    /// `clock`. No network I/O happens here (etcd's gateway is stateless HTTP and
    /// `ureq` opens connections lazily per request); construction cannot fail. The
    /// FIRST `insert_if_absent` is what surfaces an unreachable endpoint as
    /// [`ReplayStoreError::Unavailable`] (fail closed) at runtime.
    pub fn connect_with(endpoint: &str, timeout: Duration, clock: UnixClock) -> Self {
        EtcdAtomicReplayStore {
            transport: Box::new(UreqEtcdTransport {
                agent: ureq::AgentBuilder::new().build(),
                base_url: endpoint.trim_end_matches('/').to_string(),
                timeout,
            }),
            clock,
        }
    }

    /// Construct over an injected [`EtcdTransport`] — the deterministic unit-test
    /// seam that drives the REAL `insert_if_absent` decision + lease-revoke logic
    /// against a scripted transport double, no live etcd. Production uses
    /// [`connect_with`](Self::connect_with).
    #[cfg(test)]
    pub(crate) fn with_transport(transport: Box<dyn EtcdTransport>, clock: UnixClock) -> Self {
        EtcdAtomicReplayStore { transport, clock }
    }

    /// The exact lease TTL (seconds) `insert_if_absent` will request for
    /// `expires_at_unix`, reading the store's OWN injected clock (NOT the trait's
    /// `now_unix = 0`). Factored out so the MCPS-090 clock WIRING — that the store
    /// derives the TTL from a real `now`, not 0 — is unit-testable deterministically
    /// (see `ttl_secs_via_clock`) with a fixed clock and no etcd.
    fn ttl_secs_for(&self, expires_at_unix: i64) -> i64 {
        ttl_secs_via_clock(&self.clock, expires_at_unix)
    }
}

/// The etcd `lease/revoke` request body for `POST /v3/lease/revoke`: the lease id as
/// a STRING (the v3 JSON gateway encodes 64-bit ints as strings). Pure, so the wire
/// shape is unit-testable without a live etcd.
pub(crate) fn build_lease_revoke_body(lease_id: i64) -> Value {
    json!({ "ID": lease_id.to_string() })
}

/// Upper bound on an etcd response body read (lease/grant and txn replies are
/// tiny); caps a hostile/misconfigured endpoint's body rather than reading
/// unbounded.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// The clock-WIRING path, isolated from any etcd connection: read `clock` for the
/// current Unix time and derive the lease TTL (seconds). This is the exact
/// computation [`EtcdAtomicReplayStore::insert_if_absent`] performs, so a unit
/// test that injects a fixed clock proves the store derives the TTL from a REAL
/// `now` (the MCPS-090 fix), not the trait's hard-wired `0`, with NO live etcd.
fn ttl_secs_via_clock(clock: &UnixClock, expires_at_unix: i64) -> i64 {
    compute_ttl_secs(expires_at_unix, clock())
}

impl AtomicReplayStore for EtcdAtomicReplayStore {
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
        _now_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        // Derive a server-side lease TTL from the (already skew-folded)
        // retain-until instant relative to the store's OWN clock — NOT the trait's
        // `now_unix`, which is 0 (the pure `ReplayCache` carries no clock).
        // Trusting that 0 was the MCPS-090 bug: it made the lease TTL ≈ the
        // absolute Unix epoch (~56 years), so keys ~never expired → unbounded
        // keyspace growth (DoS). Reading the real `now` here makes the TTL the
        // intended `retain_until - now` WINDOW (seconds), clamped to a positive
        // value etcd accepts.
        let ttl_secs = self.ttl_secs_for(expires_at_unix);

        // 1) Grant a lease bounded by that TTL, so the nonce self-evicts after its
        //    freshness window (no client-side prune).
        let lease_resp = self
            .transport
            .post("v3/lease/grant", &build_lease_grant_body(ttl_secs))?;
        let lease_id = parse_lease_id(&lease_resp)?;

        // etcd v3 JSON encodes keys/values as STANDARD base64. Value is a constant
        // marker (1) — only the key carries replay identity.
        let key_b64 = STANDARD.encode(key.as_bytes());
        let value_b64 = STANDARD.encode([1u8]);

        // 2) Linearizable put-if-absent: a txn whose compare holds IFF the key has
        //    create_revision 0 (i.e. never existed). `succeeded` ⇒ Fresh, else the
        //    key already existed ⇒ Replay.
        let txn_resp = self
            .transport
            .post("v3/kv/txn", &build_txn_body(&key_b64, &value_b64, lease_id))?;
        let decision = decision_from_txn(&txn_resp);

        // On the Replay branch the txn did NOT put anything, so the lease granted in
        // step 1 is attached to nothing and would sit idle until its TTL expires.
        // Under a replay storm that orphan-lease churn is avoidable etcd load, so
        // issue a BEST-EFFORT revoke to release it now. This is pure cleanup: it does
        // NOT change the decision (still `Replay`), and a revoke transport/HTTP
        // failure is intentionally swallowed — at worst the lease falls back to
        // expiring at its TTL (the prior behavior). Cleanup is fail-SAFE, never
        // fail-closed: a revoke error must never turn a Replay into a Fresh or an
        // error. The happy (Fresh) path keeps its lease and issues NO extra call.
        if matches!(decision, ReplayDecision::Replay) {
            let _ = self
                .transport
                .post("v3/lease/revoke", &build_lease_revoke_body(lease_id));
        }

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::build_lease_grant_body;
    use super::build_lease_revoke_body;
    use super::build_txn_body;
    use super::compute_ttl_secs;
    use super::decision_from_txn;
    use super::parse_lease_id;
    use super::ttl_secs_via_clock;
    use super::EtcdTransport;
    use super::ReplayDecision;
    use super::ReplayStoreError;
    use super::UnixClock;
    use super::Value;
    use serde_json::json;

    /// PURE, no-etcd proof that the MCPS-090 `now = 0` bug is gone: with a real
    /// `now`, the lease TTL is the intended `retain_until - now` WINDOW (seconds),
    /// NOT the absolute Unix epoch (~1.78e9 s ≈ 56 years). Deterministic.
    #[test]
    fn ttl_secs_is_window_not_absolute_epoch() {
        let retain_until: i64 = 1_779_998_730;
        let now: i64 = retain_until - 600;
        let ttl = compute_ttl_secs(retain_until, now);
        assert_eq!(ttl, 600, "TTL must be the (retain_until - now) window in seconds");
        // Nowhere near the absolute-epoch range the now=0 bug produced.
        let now_zero_bug = compute_ttl_secs(retain_until, 0);
        assert_eq!(now_zero_bug, retain_until, "the now=0 bug would make TTL the absolute epoch");
        assert!(ttl < now_zero_bug / 1000, "window TTL must be vastly smaller than the now=0 epoch TTL");
    }

    /// PURE proof of the MCPS-090 clock WIRING: the store derives the TTL from a
    /// REAL `now` read through its INJECTED clock, NOT the trait's hard-wired
    /// `now = 0`. A regression to `now = 0` would make the TTL the absolute epoch —
    /// caught here deterministically, everywhere, with no etcd.
    #[test]
    fn injected_clock_makes_ttl_the_window_not_the_now_zero_epoch() {
        let retain_until: i64 = 1_779_998_730;
        let fixed_now: i64 = retain_until - 600;
        let clock: UnixClock = Box::new(move || fixed_now);
        let ttl = ttl_secs_via_clock(&clock, retain_until);
        assert_eq!(ttl, 600, "TTL must be (retain_until - injected_now), proving the clock is read, not 0");
        assert_ne!(
            ttl,
            compute_ttl_secs(retain_until, 0),
            "the injected-clock TTL must differ from the now=0 absolute-epoch TTL"
        );
    }

    /// A retain-until at/before `now` clamps to a minimal positive TTL (never 0,
    /// never negative — etcd rejects a non-positive lease TTL).
    #[test]
    fn ttl_secs_clamps_to_minimal_when_already_expired() {
        assert_eq!(compute_ttl_secs(1_000, 1_000), 1, "exactly-now → 1s");
        assert_eq!(compute_ttl_secs(900, 1_000), 1, "already-past → 1s, not 0/neg");
    }

    /// The lease-grant body carries the bounded TTL and ID 0 (etcd assigns the id).
    #[test]
    fn lease_grant_body_carries_bounded_ttl() {
        let body = build_lease_grant_body(600);
        assert_eq!(body["TTL"], json!(600));
        assert_eq!(body["ID"], json!(0));
    }

    /// The txn body is a linearizable put-if-absent: compare CREATE == 0 (key
    /// absent), success PUTs the value under the lease, failure is empty.
    #[test]
    fn txn_body_is_put_if_absent_under_lease() {
        let body = build_txn_body("a2V5", "dmFs", 42);
        let cmp = &body["compare"][0];
        assert_eq!(cmp["target"], json!("CREATE"));
        assert_eq!(cmp["result"], json!("EQUAL"));
        assert_eq!(cmp["create_revision"], json!("0"), "absent <=> create_revision 0");
        assert_eq!(cmp["key"], json!("a2V5"));
        let put = &body["success"][0]["request_put"];
        assert_eq!(put["key"], json!("a2V5"));
        assert_eq!(put["value"], json!("dmFs"));
        assert_eq!(put["lease"], json!("42"), "lease id is a string (JSON gateway 64-bit encoding)");
        assert_eq!(body["failure"], json!([]), "key-present branch is a no-op (Replay)");
    }

    /// `succeeded: true` ⇒ the compare held (key absent, put landed) ⇒ Fresh.
    #[test]
    fn txn_succeeded_is_fresh() {
        assert_eq!(decision_from_txn(&json!({ "succeeded": true })), ReplayDecision::Fresh);
    }

    /// `succeeded: false` AND an omitted `succeeded` (etcd's false-compare shape)
    /// both mean the key already existed ⇒ Replay (fail-safe default).
    #[test]
    fn txn_not_succeeded_is_replay() {
        assert_eq!(decision_from_txn(&json!({ "succeeded": false })), ReplayDecision::Replay);
        assert_eq!(
            decision_from_txn(&json!({ "header": { "revision": "7" } })),
            ReplayDecision::Replay,
            "an omitted `succeeded` (false compare) must default to Replay, never Fresh"
        );
    }

    /// The lease id is parsed from the JSON gateway's STRING encoding (and a raw
    /// number is tolerated).
    #[test]
    fn parse_lease_id_accepts_string_and_number() {
        assert_eq!(parse_lease_id(&json!({ "ID": "7587880697336124931" })).unwrap(), 7587880697336124931);
        assert_eq!(parse_lease_id(&json!({ "ID": 1234 })).unwrap(), 1234);
    }

    /// A missing / zero / unparseable lease id is an operational failure → fail
    /// closed: an unleased put would never expire (the MCPS-090 DoS we guard).
    #[test]
    fn parse_lease_id_fails_closed_on_missing_zero_or_garbage() {
        assert!(matches!(
            parse_lease_id(&json!({ "TTL": "600" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert!(matches!(
            parse_lease_id(&json!({ "ID": "0" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert!(matches!(
            parse_lease_id(&json!({ "ID": "not-an-int" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Acceptance proofs over the AtomicReplayStore trait, modelling etcd's
    // linearizable put-if-absent semantics WITHOUT a live etcd — the analogue of
    // the Redis cross-node proof (`InMemoryAtomicReplayStore` over a cloned Arc).
    //
    // `decision_from_txn`/`build_txn_body` (proven above) capture the exact
    // semantics etcd enforces: a `compare CREATE == 0` (key absent) txn yields
    // `succeeded ⇒ Fresh`, else `Replay`. `SharedEtcdModelStore` is that contract
    // realized over a shared map — first put = Fresh, any later put of the same
    // key = Replay — so CLONING it shares the SAME backing state and models two
    // proxy nodes against one etcd cluster. This proves the load-bearing
    // cross-instance rejection deterministically (the real etcd path is proven
    // end-to-end by the gated cpstore_etcd_e2e_test).
    // -----------------------------------------------------------------------

    use super::AtomicReplayStore;
    use super::EtcdAtomicReplayStore;
    use crate::shared_replay::SharedReplayCache;
    use mcps_core::ReplayCache;
    use mcps_core::ReplayCacheError;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    const AUD: &str = "did:example:verifier";

    /// The `lease/revoke` body carries the lease id as a STRING (the v3 JSON gateway
    /// encodes 64-bit ints as strings), matching how the txn body passes the lease.
    #[test]
    fn lease_revoke_body_carries_string_lease_id() {
        let body = build_lease_revoke_body(7587880697336124931);
        assert_eq!(
            body["ID"],
            json!("7587880697336124931"),
            "lease id must be a string for the v3 JSON gateway 64-bit encoding"
        );
    }

    /// A scripted [`EtcdTransport`] double: it returns a fixed reply per etcd path
    /// (`v3/lease/grant`, `v3/kv/txn`, `v3/lease/revoke`) and RECORDS every
    /// `(path, body)` it was POSTed, so a test can assert the exact call sequence the
    /// REAL `insert_if_absent` drives — no live etcd. `revoke_fails` flips the
    /// revoke reply to a transport failure to prove the best-effort (fail-safe)
    /// guarantee. Mirrors the model-store test-double style above.
    struct ScriptedTransport {
        /// Mapping from etcd path to the JSON reply to return for a successful POST.
        replies: std::collections::HashMap<String, Value>,
        /// When true, `v3/lease/revoke` returns `Unavailable` instead of a reply,
        /// modelling a revoke transport/HTTP failure.
        revoke_fails: bool,
        /// The recorded `(path, body)` of every POST, in call order.
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl ScriptedTransport {
        fn new(txn_reply: Value, revoke_fails: bool) -> Self {
            let mut replies = std::collections::HashMap::new();
            // A lease-grant reply carrying a non-zero id (the JSON gateway's string
            // encoding) so `parse_lease_id` succeeds and the flow reaches the txn.
            replies.insert("v3/lease/grant".to_string(), json!({ "ID": "424242", "TTL": "600" }));
            replies.insert("v3/kv/txn".to_string(), txn_reply);
            replies.insert("v3/lease/revoke".to_string(), json!({ "header": { "revision": "9" } }));
            ScriptedTransport {
                replies,
                revoke_fails,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn paths(&self) -> Vec<String> {
            self.calls
                .lock()
                .expect("calls lock")
                .iter()
                .map(|(p, _)| p.clone())
                .collect()
        }
    }

    impl EtcdTransport for ScriptedTransport {
        fn post(&self, path: &str, body: &Value) -> Result<Value, ReplayStoreError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((path.to_string(), body.clone()));
            if self.revoke_fails && path == "v3/lease/revoke" {
                return Err(ReplayStoreError::Unavailable {
                    details: "scripted revoke failure".to_string(),
                });
            }
            Ok(self
                .replies
                .get(path)
                .cloned()
                .unwrap_or_else(|| panic!("scripted transport has no reply for path {path}")))
        }
    }

    /// Delegating impl so a test can hold an `Arc<ScriptedTransport>` (to inspect the
    /// recorded calls AFTER the store consumed its `Box<dyn EtcdTransport>`) while the
    /// store drives the SAME shared double.
    impl EtcdTransport for Arc<ScriptedTransport> {
        fn post(&self, path: &str, body: &Value) -> Result<Value, ReplayStoreError> {
            (**self).post(path, body)
        }
    }

    fn fixed_clock() -> UnixClock {
        Box::new(|| 1_779_998_100)
    }

    /// A Replay outcome (txn `succeeded: false`) triggers a best-effort
    /// `v3/lease/revoke` for the just-granted lease id — releasing the orphan lease
    /// the put-if-absent never attached, rather than letting it churn until TTL.
    /// The decision is unchanged (still `Replay`); the revoke is a side cleanup.
    #[test]
    fn replay_revokes_the_unused_lease() {
        let transport = Arc::new(ScriptedTransport::new(json!({ "succeeded": false }), false));
        let store = EtcdAtomicReplayStore::with_transport(
            Box::new(Arc::clone(&transport)),
            fixed_clock(),
        );
        let decision = store
            .insert_if_absent("did:example:host|aud|nonce", 1_779_998_700, 0)
            .expect("replay decision must not error");
        assert_eq!(decision, ReplayDecision::Replay, "key present ⇒ Replay");
        assert_eq!(
            transport.paths(),
            vec![
                "v3/lease/grant".to_string(),
                "v3/kv/txn".to_string(),
                "v3/lease/revoke".to_string(),
            ],
            "a Replay must follow grant+txn with a lease/revoke of the granted lease"
        );
        // The revoke targets the EXACT lease id the grant returned (424242), as a
        // string per the JSON gateway encoding.
        let revoke_body = transport
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .find(|(p, _)| p == "v3/lease/revoke")
            .map(|(_, b)| b.clone())
            .expect("a revoke call must have been recorded");
        assert_eq!(
            revoke_body["ID"],
            json!("424242"),
            "revoke must target the just-granted lease id"
        );
    }

    /// The Fresh (happy) path keeps its lease: grant + txn only, NO extra
    /// `lease/revoke` call — the put attached the lease, so there is nothing to
    /// release.
    #[test]
    fn fresh_does_not_revoke_the_lease() {
        let transport = Arc::new(ScriptedTransport::new(json!({ "succeeded": true }), false));
        let store = EtcdAtomicReplayStore::with_transport(
            Box::new(Arc::clone(&transport)),
            fixed_clock(),
        );
        let decision = store
            .insert_if_absent("did:example:host|aud|nonce", 1_779_998_700, 0)
            .expect("fresh decision must not error");
        assert_eq!(decision, ReplayDecision::Fresh, "key absent ⇒ Fresh");
        assert_eq!(
            transport.paths(),
            vec!["v3/lease/grant".to_string(), "v3/kv/txn".to_string()],
            "the Fresh path must NOT issue a lease/revoke — the lease is in use"
        );
    }

    /// The revoke is BEST-EFFORT / fail-SAFE: a revoke transport failure must NOT
    /// turn a Replay into an error or a Fresh — the decision stays `Replay` and the
    /// lease simply falls back to expiring at its TTL (the prior behavior).
    #[test]
    fn replay_revoke_failure_still_returns_replay_never_errors() {
        let transport = Arc::new(ScriptedTransport::new(json!({ "succeeded": false }), true));
        let store = EtcdAtomicReplayStore::with_transport(
            Box::new(Arc::clone(&transport)),
            fixed_clock(),
        );
        let result = store.insert_if_absent("did:example:host|aud|nonce", 1_779_998_700, 0);
        assert_eq!(
            result,
            Ok(ReplayDecision::Replay),
            "a revoke failure must NOT turn a Replay into an error or a Fresh"
        );
        // The revoke was still ATTEMPTED (best-effort), even though it failed.
        assert!(
            transport.paths().contains(&"v3/lease/revoke".to_string()),
            "the revoke must be attempted on Replay even when it then fails"
        );
    }
    const NONCE: &str = "nonce-69-cpstore-acceptance";
    const EXPIRES: i64 = 1_779_998_700;
    const SKEW: i64 = 30;

    /// A shared store whose `insert_if_absent` realizes etcd's linearizable
    /// put-if-absent over a cloned `Arc<Mutex<..>>` (the mutex linearizes the
    /// absent-check + insert exactly as etcd's txn linearizes it server-side).
    /// First sight of a key ⇒ Fresh, any later sight ⇒ Replay — `decision_from_txn`
    /// applied to the modelled compare outcome.
    #[derive(Clone, Default)]
    struct SharedEtcdModelStore {
        seen: Arc<Mutex<BTreeSet<String>>>,
    }

    impl AtomicReplayStore for SharedEtcdModelStore {
        fn insert_if_absent(
            &self,
            key: &str,
            _expires_at_unix: i64,
            _now_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            let mut set = self.seen.lock().map_err(|e| ReplayStoreError::Unavailable {
                details: format!("model store poisoned: {e}"),
            })?;
            // `compare CREATE == 0` succeeds IFF the key was absent ⇒ Fresh.
            let was_absent = set.insert(key.to_string());
            let txn = json!({ "succeeded": was_absent });
            Ok(decision_from_txn(&txn))
        }
    }

    /// A store whose every call is an operational failure — models any etcd
    /// transport/HTTP/parse failure, exercising the fail-closed mapping.
    struct AlwaysUnavailableEtcdStore;

    impl AtomicReplayStore for AlwaysUnavailableEtcdStore {
        fn insert_if_absent(
            &self,
            _key: &str,
            _expires_at_unix: i64,
            _now_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable {
                details: "etcd unreachable".to_string(),
            })
        }
    }

    /// Fresh-then-Replay on one instance over the etcd-semantics store.
    #[test]
    fn fresh_then_replay_single_instance() {
        let mut cache = SharedReplayCache::new(Box::new(SharedEtcdModelStore::default()), SKEW);
        assert_eq!(
            cache.check_and_insert("did:example:host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert("did:example:host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    /// The load-bearing cross-instance proof: two SEPARATE `SharedReplayCache`
    /// over the SAME etcd-semantics store (cloned `Arc`, modelling two proxy nodes
    /// against one etcd cluster). A nonce accepted on node A is rejected as a
    /// replay on node B — the LINEARIZABLE horizontal replay-safety property.
    #[test]
    fn cross_instance_insert_via_a_is_replay_via_b() {
        let store = SharedEtcdModelStore::default();
        let mut node_a = SharedReplayCache::new(Box::new(store.clone()), SKEW);
        let mut node_b = SharedReplayCache::new(Box::new(store.clone()), SKEW);
        assert_eq!(
            node_a.check_and_insert("did:example:host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "first sight on node A is fresh"
        );
        assert_eq!(
            node_b.check_and_insert("did:example:host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay),
            "node B must reject a nonce first seen on node A — shared CP replay state"
        );
    }

    /// Fail closed on store unavailable → `ReplayCacheError::Unavailable`, never a
    /// Fresh serve-through. Any etcd transport/HTTP/parse failure lands here.
    #[test]
    fn store_unavailable_fails_closed_never_fresh() {
        let mut cache = SharedReplayCache::new(Box::new(AlwaysUnavailableEtcdStore), SKEW);
        let result = cache.check_and_insert("did:example:host", AUD, NONCE, EXPIRES);
        assert!(
            matches!(result, Err(ReplayCacheError::Unavailable { .. })),
            "an unavailable CP store must surface Unavailable, never allow; got {result:?}"
        );
        assert_ne!(
            result,
            Ok(ReplayDecision::Fresh),
            "a CP-store outage must NEVER be reported as Fresh (no serve-through)"
        );
    }
}
