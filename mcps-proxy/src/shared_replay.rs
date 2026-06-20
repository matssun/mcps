//! SHARED, server-side-ATOMIC replay cache for HORIZONTALLY-SCALED replay safety
//! (issue #3837; complements the single-node [`DurableReplayCache`]).
//!
//! The file-backed [`DurableReplayCache`](crate::durable_replay::DurableReplayCache)
//! is single-node only: each proxy process sees only its own file, so running it
//! across several nodes does NOT prevent cross-node replays. This module adds a
//! shared cache behind the same `mcps_core::ReplayCache` trait so that multiple
//! proxy processes / hosts share one replay-state store and a nonce accepted on
//! one node is rejected as a replay on every other node.
//!
//! ## Layering — backend-agnostic core + opt-in backend adapter
//!
//! The shared-cache SEMANTICS are factored out of any specific backend:
//!   * [`AtomicReplayStore`] is the minimal shared primitive — a single
//!     server-side-atomic *insert-if-absent-with-TTL* op. Any shared store
//!     (Redis, a SQL row with a unique key, a consensus KV, …) can implement it.
//!   * [`SharedReplayCache`] holds a `Box<dyn AtomicReplayStore>` and impls
//!     `mcps_core::ReplayCache`. It builds a collision-safe composite key from
//!     `(signer, audience, nonce)`, applies the clock skew EXACTLY as
//!     `InMemoryReplayCache` does, delegates atomicity to the store, and FAILS
//!     CLOSED on any store error (→ `mcps.replay_cache_unavailable`).
//!   * [`InMemoryAtomicReplayStore`] is a REAL reference store (an
//!     `Arc<Mutex<…>>`) — like `InMemoryReplayCache`, not a test mock. Because it
//!     is shared by `Arc`, the SAME store can back two `SharedReplayCache`
//!     instances, modelling two proxy nodes against one shared backend; that is
//!     the default-build, Bazel-tested path that proves cross-node rejection.
//!
//! Backends in tree:
//!   * [`InMemoryAtomicReplayStore`] (THIS module) — the default-build reference
//!     store. It is a single-process store and does NOT, on its own, give
//!     horizontally-scaled replay safety across SEPARATE proxy processes/hosts;
//!     it proves the cross-instance property only within one process (two
//!     `SharedReplayCache` over one cloned `Arc`).
//!   * `RedisAtomicReplayStore`
//!     (in the `redis_store` module, compiled ONLY under the non-default
//!     `redis_replay` cargo feature — written as inline code, NOT an intra-doc
//!     link, since that module is absent from the default-feature doc build and
//!     a link would be an unresolved `broken_intra_doc_links`) — a REAL
//!     server-side-atomic
//!     shared backend (Redis `SET NX PX`) wired by `cli.rs` for
//!     `--replay-cache shared`, giving genuine cross-process/cross-node replay
//!     safety.
//!
//! The DEFAULT build (without `redis_replay`) ships ONLY the in-memory reference
//! store and gains ZERO new dependencies, so the default build does NOT provide
//! cross-process replay safety — that "MUST NOT be claimed" caveat is scoped to
//! the default build. Under `--features redis_replay` the Redis-backed shared
//! store IS available.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

use mcps_core::sha256_hash_id;
use mcps_core::ReplayCache;
use mcps_core::ReplayCacheError;
use mcps_core::ReplayDecision;

/// An operational failure of an [`AtomicReplayStore`] (the shared backend could
/// not be reached or did not answer).
///
/// Mapped to [`ReplayCacheError::Unavailable`] via the `From` impl below, which
/// in turn maps to `mcps.replay_cache_unavailable` — so a backend failure FAILS
/// CLOSED and never falls back to "allow".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayStoreError {
    /// The shared store could not be reached or otherwise failed the op.
    #[error("shared replay store unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl From<ReplayStoreError> for ReplayCacheError {
    fn from(err: ReplayStoreError) -> ReplayCacheError {
        match err {
            ReplayStoreError::Unavailable { details } => {
                ReplayCacheError::Unavailable { details }
            }
        }
    }
}

/// The minimal SHARED, server-side-ATOMIC primitive a [`SharedReplayCache`] needs
/// from any backing store.
///
/// A single op — *insert this key if absent, with a server-side TTL* — carries
/// all the atomicity the cache requires: the absent-check and the insert MUST
/// happen as one atomic step in the store (e.g. Redis `SET key v NX PX ttl`), so
/// two nodes racing on the same nonce cannot both observe it absent. The store
/// owns expiry via the TTL; there is no separate prune step (contrast the
/// in-process caches' explicit `prune`).
///
/// `&self` (not `&mut self`): a shared store is consulted concurrently by many
/// callers, so implementations use interior synchronization / a connection pool.
pub trait AtomicReplayStore {
    /// Atomically insert `key` iff it is absent, with a TTL derived from
    /// `expires_at_unix` (already the skew-folded `retain_until = expires_at +
    /// skew`, mirroring `InMemoryReplayCache`) relative to the CURRENT time.
    ///
    /// `now_unix` is a VESTIGIAL anchor the caller passes as `0` because the pure
    /// `ReplayCache` trait carries no clock; an implementor that derives a
    /// server-side TTL (e.g. Redis `PX`) MUST read its OWN clock for "now" and
    /// IGNORE this `0`. Trusting the `0` makes the TTL ≈ the absolute Unix epoch
    /// (~56 years) → unbounded keyspace growth (the H-8/H-9 / MCPS-090 bug). An
    /// implementor that has no TTL (e.g. the in-memory store, which evicts via an
    /// explicit `prune`) simply ignores it. Clamp any derived duration to
    /// non-negative.
    ///
    /// Returns [`ReplayDecision::Fresh`] if the key was absent and is now
    /// recorded, [`ReplayDecision::Replay`] if it was already present, or
    /// [`ReplayStoreError`] on an operational failure (→ fail closed).
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError>;
}

/// A [`ReplayCache`] backed by a shared [`AtomicReplayStore`], giving
/// horizontally-scaled replay safety: a nonce accepted on one node is rejected on
/// every node sharing the store.
///
/// `check_and_insert` folds the clock skew into `expires_at_unix` EXACTLY as
/// [`InMemoryReplayCache`](mcps_core::InMemoryReplayCache) does
/// (`retain_until = expires_at + max_clock_skew`), builds a collision-safe
/// composite key from `(signer, audience, nonce)`, and delegates the atomic
/// check-and-insert to the store. Any store error fails closed.
pub struct SharedReplayCache {
    store: Box<dyn AtomicReplayStore>,
    max_clock_skew_secs: i64,
}

impl SharedReplayCache {
    /// Build a shared cache over `store`, applying the symmetric
    /// `max_clock_skew_secs` to each entry's retain-until (folded into the TTL).
    pub fn new(store: Box<dyn AtomicReplayStore>, max_clock_skew_secs: i64) -> Self {
        SharedReplayCache {
            store,
            max_clock_skew_secs,
        }
    }

    /// Build a COLLISION-SAFE composite key for the `(signer, audience, nonce)`
    /// triple.
    ///
    /// Naive concatenation aliases distinct tuples (e.g. `("a", "bc", …)` and
    /// `("ab", "c", …)` would collide). We length-prefix each field
    /// (`<byte-len>:<field>`) so the parse is unambiguous regardless of any
    /// delimiter the fields themselves contain, then hash the result with
    /// `mcps_core::sha256_hash_id` to yield a fixed, opaque, store-safe key. The
    /// length-prefix guarantees injectivity of the preimage; the hash just makes
    /// the key compact and free of any character a backend might treat specially.
    fn composite_key(signer: &str, audience: &str, nonce: &str) -> String {
        // Length-prefixed (in BYTES) so no field content can forge a boundary.
        let preimage = format!(
            "{}:{}|{}:{}|{}:{}",
            signer.len(),
            signer,
            audience.len(),
            audience,
            nonce.len(),
            nonce,
        );
        sha256_hash_id(preimage.as_bytes())
    }
}

impl ReplayCache for SharedReplayCache {
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key = SharedReplayCache::composite_key(signer, audience, nonce);
        // Fold the skew into the retain-until instant exactly as
        // InMemoryReplayCache does, then hand that instant to the store as the
        // absolute retain-until. The pure ReplayCache trait carries NO clock, so
        // the `now_unix` parameter is passed as 0 and is a vestigial anchor the
        // store MUST IGNORE: each store derives its TTL from its OWN clock (the
        // proxy's impure edge), never from this 0. Trusting the 0 was the H-8/H-9
        // bug (MCPS-090) — it made the Redis `PX` ≈ the absolute Unix epoch
        // (~56 years), so keys ~never expired → unbounded keyspace growth (DoS).
        // The decision (Fresh/Replay) does NOT depend on the TTL value; only
        // eviction timing does.
        let retain_until = expires_at_unix.saturating_add(self.max_clock_skew_secs);
        Ok(self.store.insert_if_absent(&key, retain_until, 0)?)
    }
}

/// A REAL, shared in-memory [`AtomicReplayStore`] reference implementation (NOT a
/// test mock — the in-memory analogue of `InMemoryReplayCache`, usable wherever a
/// single multi-threaded process wants a shared store without an external
/// service).
///
/// State is an `Arc<Mutex<BTreeMap<key, retain_until>>>`, so CLONING the store
/// shares the SAME underlying map. That is what lets two [`SharedReplayCache`]
/// instances model two proxy nodes over one shared backend: insert via one,
/// replay-rejected via the other. The mutex makes the absent-check + insert
/// atomic, mirroring the server-side atomicity a real backend (Redis `SET NX`)
/// provides.
///
/// There is no background clock: an entry is a replay until [`prune`](InMemoryAtomicReplayStore::prune)
/// evicts it (the absolute `retain_until` carried per entry is the eviction
/// boundary).
#[derive(Clone, Default)]
pub struct InMemoryAtomicReplayStore {
    /// `composite_key -> retain_until` (absolute Unix seconds).
    seen: Arc<Mutex<BTreeMap<String, i64>>>,
}

impl InMemoryAtomicReplayStore {
    /// Construct an empty shared store. Clone it to share the SAME state.
    pub fn new() -> Self {
        InMemoryAtomicReplayStore {
            seen: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Evict every entry whose `retain_until < now_unix` (an explicit prune; this
    /// reference store has no background clock). After eviction the key is
    /// [`ReplayDecision::Fresh`] again — safe, because past its retain-until the
    /// nonce can no longer pass the freshness window.
    pub fn prune(&self, now_unix: i64) {
        if let Ok(mut map) = self.seen.lock() {
            map.retain(|_, &mut retain_until| retain_until >= now_unix);
        }
    }

    /// Number of live entries (test/inspection aid). A poisoned lock counts as 0.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AtomicReplayStore for InMemoryAtomicReplayStore {
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
        _now_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        // A poisoned mutex is an operational failure → fail closed (Unavailable),
        // never a silent "allow".
        let mut map = self.seen.lock().map_err(|e| ReplayStoreError::Unavailable {
            details: format!("shared store mutex poisoned: {e}"),
        })?;
        if map.contains_key(key) {
            return Ok(ReplayDecision::Replay);
        }
        // `expires_at_unix` is the already-skew-folded retain-until instant.
        map.insert(key.to_string(), expires_at_unix);
        Ok(ReplayDecision::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::AtomicReplayStore;
    use super::InMemoryAtomicReplayStore;
    use super::ReplayStoreError;
    use super::SharedReplayCache;
    use mcps_core::McpsError;
    use mcps_core::ReplayCache;
    use mcps_core::ReplayCacheError;
    use mcps_core::ReplayDecision;

    const SIGNER: &str = "did:example:host";
    const AUD: &str = "did:example:verifier";
    const NONCE: &str = "nonce-aaaaaaaaaaaaaaaaaaaaaa";
    const EXPIRES: i64 = 1_779_998_700;
    const SKEW: i64 = 30;

    /// A store whose every call is an operational failure — exercises the
    /// fail-closed mapping (the in-memory reference store has no failure path
    /// short of a poisoned mutex).
    struct AlwaysUnavailableStore;

    impl AtomicReplayStore for AlwaysUnavailableStore {
        fn insert_if_absent(
            &self,
            _key: &str,
            _expires_at_unix: i64,
            _now_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable {
                details: "shared backend unreachable".to_string(),
            })
        }
    }

    #[test]
    fn fresh_then_replay_single_instance() {
        let store = InMemoryAtomicReplayStore::new();
        let mut cache = SharedReplayCache::new(Box::new(store), SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    /// The load-bearing cross-node proof: two SEPARATE `SharedReplayCache`
    /// instances over the SAME shared store (cloned `Arc`, modelling two proxy
    /// nodes). A nonce inserted via node A is rejected as a replay via node B —
    /// the property the single-node file cache cannot provide.
    #[test]
    fn cross_instance_insert_via_a_is_replay_via_b() {
        let store = InMemoryAtomicReplayStore::new();
        // Clone shares the SAME underlying map (Arc<Mutex<..>>).
        let mut node_a = SharedReplayCache::new(Box::new(store.clone()), SKEW);
        let mut node_b = SharedReplayCache::new(Box::new(store.clone()), SKEW);

        assert_eq!(
            node_a.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "first sight on node A is fresh"
        );
        assert_eq!(
            node_b.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay),
            "node B must reject a nonce first seen on node A — shared replay state"
        );
        // The store really holds the single shared entry.
        assert_eq!(store.len(), 1);
    }

    /// Key-collision safety: changing ONLY the signer, ONLY the audience, or ONLY
    /// the nonce yields independent entries. The crafted inputs would ALIAS under
    /// naive concatenation (`signer + audience + nonce`): `("ab","c", n)` and
    /// `("a","bc", n)` both concatenate to `"abc" + n`. The length-prefixed key
    /// keeps them distinct.
    #[test]
    fn distinct_tuples_do_not_alias() {
        let store = InMemoryAtomicReplayStore::new();
        let mut cache = SharedReplayCache::new(Box::new(store), SKEW);

        // Would collide under naive concat: signer|audience boundary moved.
        assert_eq!(
            cache.check_and_insert("ab", "c", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert("a", "bc", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "moving the signer/audience boundary must NOT alias to a replay"
        );
        // Same nonce, different signer → independent.
        assert_eq!(
            cache.check_and_insert("other-host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // Same nonce, different audience → independent.
        assert_eq!(
            cache.check_and_insert(SIGNER, "other-aud", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // Same signer/audience, different nonce → independent.
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, "nonce-bbbbbbbbbbbbbbbbbbbbbb", EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // And each of the above is now a replay on a second sight.
        assert_eq!(
            cache.check_and_insert("ab", "c", NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
        assert_eq!(
            cache.check_and_insert("a", "bc", NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    /// Skew handling matches `InMemoryReplayCache` semantics: the stored
    /// retain-until is `expires_at + max_clock_skew`, and pruning strictly past it
    /// readmits the nonce while pruning AT it keeps it.
    #[test]
    fn skew_folded_into_retain_until_matches_in_memory_semantics() {
        let store = InMemoryAtomicReplayStore::new();
        let mut cache = SharedReplayCache::new(Box::new(store.clone()), SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        let retain_until = EXPIRES + SKEW;
        // Pruning AT retain_until keeps the entry (retain_until >= now).
        store.prune(retain_until);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay),
            "entry is live through its skew-extended retain-until"
        );
        // Pruning strictly past retain_until evicts → fresh again.
        store.prune(retain_until + 1);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "past retain-until the nonce is readmitted (it can no longer pass freshness)"
        );
    }

    /// A store error fails closed: `ReplayCacheError::Unavailable`, which maps to
    /// `McpsError::ReplayCacheUnavailable` — never "allow".
    #[test]
    fn store_error_fails_closed_as_unavailable() {
        let mut cache = SharedReplayCache::new(Box::new(AlwaysUnavailableStore), SKEW);
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
            .expect_err("an unavailable store must surface an error, never allow");
        assert!(matches!(err, ReplayCacheError::Unavailable { .. }));
        assert_eq!(err.to_mcps_error(), McpsError::ReplayCacheUnavailable);
        assert_eq!(McpsError::from(err), McpsError::ReplayCacheUnavailable);
    }

    /// The `From<ReplayStoreError>` bridge preserves the diagnostic and lands on
    /// the fail-closed `Unavailable` variant.
    #[test]
    fn store_error_converts_to_cache_unavailable() {
        let store_err = ReplayStoreError::Unavailable {
            details: "conn refused".to_string(),
        };
        let cache_err: ReplayCacheError = store_err.into();
        match cache_err {
            ReplayCacheError::Unavailable { details } => assert_eq!(details, "conn refused"),
        }
    }
}
