//! Replay detection (MCPS_SPEC §5 / ADR-006).
//!
//! Replay protection is a caller-injected [`ReplayCache`] keyed by the triple
//! `(signer, audience, nonce)`. In the `verify_request` pipeline it is invoked
//! **only after signature verification succeeds** (MCPS_SPEC §9 step 12), so
//! invalid-signature garbage can never burn a legitimate nonce.
//!
//! ## Decision vs. failure — fail closed
//!
//! The cache returns a [`ReplayDecision`] (`Fresh` | `Replay`) on success. It
//! deliberately does NOT bake the `mcps.replay_detected` verdict into itself:
//! the pipeline maps `Ok(ReplayDecision::Replay)` to
//! [`McpsError::ReplayDetected`]. An *operational* cache failure is a
//! [`ReplayCacheError`], which maps to [`McpsError::ReplayCacheUnavailable`]
//! (fail closed, distinct from a replay verdict — parallels
//! `trust_resolver_unavailable`). A cache failure NEVER falls back to "allow".
//!
//! ## Retention & distribution
//!
//! An entry must be retained until `expires_at + max_clock_skew`: once a
//! request can no longer pass the freshness window, its nonce can never be
//! validly replayed, so the entry may be pruned. The caller parses the
//! RFC 3339 `expires_at` into Unix seconds first and passes `expires_at_unix`
//! to [`ReplayCache::check_and_insert`]; the cache adds the skew to compute the
//! retain-until instant. In a distributed deployment the verifiers MUST share
//! replay state (a per-node in-memory cache does not prevent cross-node
//! replays); [`InMemoryReplayCache`] is a single-process reference only.
//!
//! ## Self-declared durability — machine-checkable, not just documented
//!
//! "Single-process reference only" is no longer prose alone: every
//! [`ReplayCache`] self-declares a [`ReplayDurabilityClass`] via
//! [`ReplayCache::durability_class`], defaulting (fail closed) to
//! [`ReplayDurabilityClass::SingleProcessReference`]. [`InMemoryReplayCache`]
//! honestly reports the single-process class, so the wiring layer can MACHINE-
//! CHECK the cache object it actually holds and refuse to run the volatile
//! reference cache on a production verify path — rather than relying on the
//! operator picking the right backend. This is a PURE, type-level capability;
//! `mcps-core` adds no clock, I/O, or networking (ADR-MCPS-011/012). Cross-node
//! strength beyond mere durability is still asserted by the proxy's
//! `ReplayDurabilityTier` (ADR-MCPS-020).

use std::collections::BTreeMap;

use crate::error::McpsError;

/// A [`ReplayCache`]'s self-declared durability posture (ADR-MCPS-020).
///
/// This is a PURE, type-level capability: `mcps-core` carries no clock, no I/O,
/// and no networking (ADR-MCPS-011/012), so this enum says nothing about *how* a
/// cache is durable — only whether the implementation asserts it survives the
/// volatility that makes the single-process reference cache unsafe in production.
///
/// It exists so the wiring layer can MACHINE-CHECK the cache it actually holds,
/// rather than inferring durability from which constructor the operator happened
/// to pick. The default ([`ReplayCache::durability_class`] returns
/// [`ReplayDurabilityClass::SingleProcessReference`]) is the conservative one: a
/// cache that does not explicitly declare itself durable is treated as the
/// non-durable reference, so an unknown or forgetful implementation can never
/// silently masquerade as a production replay store (fail closed).
///
/// `Durable` is a NECESSARY, not sufficient, condition for a production
/// horizontal deployment: cross-node strength is asserted separately by the
/// proxy's `ReplayDurabilityTier` (ADR-MCPS-020). A cache may be `Durable`
/// (survives restart) yet single-node; the tier check governs the horizontal
/// claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDurabilityClass {
    /// The cache keeps admitted `(signer, audience, nonce)` triples only in
    /// process memory. A process restart forgets every admitted nonce and a
    /// per-node instance is invisible to its peers — so it neither survives
    /// restart nor prevents cross-node replays. This is the
    /// [`InMemoryReplayCache`] reference posture: correct for tests, conformance
    /// vectors, and single-node dev, but NOT a production replay store.
    SingleProcessReference,
    /// The implementation asserts its admitted nonces outlive the process (a
    /// durable single-node store) and/or are shared across verifier instances.
    /// This is the minimum class a strict/production wiring layer accepts before
    /// it then applies the horizontal `ReplayDurabilityTier` check.
    Durable,
}

/// The outcome of a replay-cache lookup-and-insert.
///
/// The cache returns this on success; the pipeline maps
/// [`ReplayDecision::Replay`] to [`McpsError::ReplayDetected`] (MCPS_SPEC §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    /// The `(signer, audience, nonce)` triple was not previously seen; it has
    /// now been inserted. The request may proceed.
    Fresh,
    /// The triple was already present (and not pruned): a replay. The pipeline
    /// turns this into [`McpsError::ReplayDetected`].
    Replay,
}

/// An operational failure of a [`ReplayCache`] (distinct from a replay verdict).
///
/// Maps to [`McpsError::ReplayCacheUnavailable`] via
/// [`to_mcps_error`](ReplayCacheError::to_mcps_error) / the `From` impl. A
/// failure here fails closed and NEVER falls back to "allow".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayCacheError {
    /// The backing store could not be reached or otherwise failed to answer.
    /// → [`McpsError::ReplayCacheUnavailable`].
    #[error("replay cache unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl ReplayCacheError {
    /// Map this operational failure to its frozen [`McpsError`] (MCPS_SPEC §5/§8).
    ///
    /// Always [`McpsError::ReplayCacheUnavailable`] — fail closed, never "allow".
    pub fn to_mcps_error(&self) -> McpsError {
        match self {
            ReplayCacheError::Unavailable { .. } => McpsError::ReplayCacheUnavailable,
        }
    }
}

impl From<ReplayCacheError> for McpsError {
    fn from(err: ReplayCacheError) -> McpsError {
        err.to_mcps_error()
    }
}

/// The replay-detection injection point (MCPS_SPEC §5 / ADR-006).
///
/// Implementations are keyed by `(signer, audience, nonce)` and are consulted
/// only after signature verification. `expires_at_unix` is the request's
/// `expires_at` already parsed to Unix seconds; the implementation computes its
/// retain-until as `expires_at_unix + max_clock_skew`.
///
/// Returns `Ok(ReplayDecision::Fresh)` when the triple is newly recorded,
/// `Ok(ReplayDecision::Replay)` when it was already present, or
/// `Err(ReplayCacheError)` on an operational failure (→
/// [`McpsError::ReplayCacheUnavailable`], fail closed).
pub trait ReplayCache {
    /// Atomically check whether `(signer, audience, nonce)` was already seen and
    /// record it if not.
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError>;

    /// This cache's self-declared durability posture (ADR-MCPS-020).
    ///
    /// The wiring layer machine-checks THIS — the durability of the cache object
    /// it actually holds — instead of inferring production-readiness from which
    /// constructor was selected. The default is the conservative
    /// [`ReplayDurabilityClass::SingleProcessReference`]: a cache that does not
    /// explicitly override this is treated as non-durable, so a new or forgetful
    /// implementation can never silently pass a strict/production durability gate
    /// (fail closed). A durable implementation MUST override this to honestly
    /// return [`ReplayDurabilityClass::Durable`].
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }

    /// Whether this cache is the single-process, volatile reference posture
    /// ([`ReplayDurabilityClass::SingleProcessReference`]) — `true` for
    /// [`InMemoryReplayCache`] and for any implementation that has not declared
    /// itself durable. A strict/production wiring layer rejects a cache for which
    /// this is `true`.
    fn is_single_process_reference(&self) -> bool {
        self.durability_class() == ReplayDurabilityClass::SingleProcessReference
    }
}

/// Deterministic, [`BTreeMap`]-backed reference [`ReplayCache`] for tests and
/// conformance vectors (MCPS_SPEC §5).
///
/// Keyed by the `(signer, audience, nonce)` triple. Each recorded entry carries
/// a `retain_until = expires_at_unix + max_clock_skew_secs` instant; an entry
/// is considered live until that instant. Pruning is explicit (see
/// [`prune`](InMemoryReplayCache::prune)) — there is NO background clock, so the
/// cache stays pure and deterministic. This reference impl never returns
/// `Err`: in a single process the lookup always succeeds.
///
/// A distributed deployment MUST share replay state across verifiers; this
/// per-process cache does not prevent cross-node replays.
#[derive(Debug, Clone)]
pub struct InMemoryReplayCache {
    /// Symmetric clock skew added to `expires_at_unix` to compute retain-until.
    max_clock_skew_secs: i64,
    /// `(signer, audience, nonce)` -> retain-until Unix seconds.
    seen: BTreeMap<(String, String, String), i64>,
}

impl InMemoryReplayCache {
    /// Construct an empty cache with the symmetric `max_clock_skew_secs` used to
    /// compute each entry's retain-until.
    pub fn new(max_clock_skew_secs: i64) -> Self {
        InMemoryReplayCache {
            max_clock_skew_secs,
            seen: BTreeMap::new(),
        }
    }

    /// Evict every entry whose `retain_until < now_unix`.
    ///
    /// After eviction a previously-seen triple becomes [`ReplayDecision::Fresh`]
    /// again — by which point it can no longer pass the freshness window, so
    /// readmitting its nonce is safe. Pruning is explicit and side-effect free
    /// beyond the eviction itself, keeping the cache deterministic.
    pub fn prune(&mut self, now_unix: i64) {
        self.seen.retain(|_, &mut retain_until| retain_until >= now_unix);
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key = (
            signer.to_string(),
            audience.to_string(),
            nonce.to_string(),
        );
        if self.seen.contains_key(&key) {
            return Ok(ReplayDecision::Replay);
        }
        let retain_until = expires_at_unix.saturating_add(self.max_clock_skew_secs);
        self.seen.insert(key, retain_until);
        Ok(ReplayDecision::Fresh)
    }

    /// Honestly declares the single-process reference posture. Admitted nonces
    /// live only in this process's `BTreeMap`: a restart forgets them and a
    /// per-node instance is invisible to peers, so this cache neither survives
    /// restart nor prevents cross-node replays (ADR-MCPS-020). Declared
    /// explicitly (not left to the trait default) so the honesty is local to the
    /// reference impl and cannot drift if the default ever changes.
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryReplayCache;
    use super::ReplayCache;
    use super::ReplayCacheError;
    use super::ReplayDecision;
    use super::ReplayDurabilityClass;
    use crate::error::McpsError;

    const SIGNER: &str = "did:example:host";
    const AUD: &str = "did:example:verifier";
    const NONCE: &str = "nonce-aaaaaaaaaaaaaaaaaaaaaa";
    const EXPIRES: i64 = 1_779_998_700; // an arbitrary fixed epoch
    const SKEW: i64 = 30;

    /// A test-only cache whose every call is an operational failure. Exercises
    /// the [`McpsError::ReplayCacheUnavailable`] mapping (the in-memory
    /// reference cache has no failure path).
    struct AlwaysUnavailableReplayCache;

    impl ReplayCache for AlwaysUnavailableReplayCache {
        fn check_and_insert(
            &mut self,
            _signer: &str,
            _audience: &str,
            _nonce: &str,
            _expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayCacheError> {
            Err(ReplayCacheError::Unavailable {
                details: "backing store unreachable".to_string(),
            })
        }
    }

    #[test]
    fn first_insert_is_fresh() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn same_triple_again_is_replay() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    #[test]
    fn different_audience_same_nonce_is_fresh() {
        // Multi-tenant keying: the same nonce under a different audience is a
        // distinct key and must NOT be flagged as a replay.
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, "did:example:other-verifier", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn different_signer_same_nonce_is_fresh() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert("did:example:other-host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn prune_after_retain_until_readmits_triple() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // retain_until == EXPIRES + SKEW. Pruning strictly past it evicts.
        let retain_until = EXPIRES + SKEW;
        // Pruning AT retain_until keeps the entry (retain_until >= now).
        cache.prune(retain_until);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
        // Pruning strictly past retain_until evicts -> triple is Fresh again.
        cache.prune(retain_until + 1);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn in_memory_cache_never_errors() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        // Any number of distinct inserts succeed without an operational failure.
        for i in 0..5 {
            let nonce = format!("nonce-{i:022}");
            assert!(cache.check_and_insert(SIGNER, AUD, &nonce, EXPIRES).is_ok());
        }
    }

    #[test]
    fn in_memory_reference_declares_single_process_non_durable() {
        // ADR-MCPS-020 (#78): the reference cache must honestly self-declare the
        // single-process, volatile posture so a strict/production wiring layer can
        // machine-check the cache OBJECT it holds, rather than trusting the
        // operator to pick the right backend. A regression here (declaring itself
        // Durable) would silently re-open the cross-node / restart replay window
        // this marker exists to gate.
        let cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
        assert!(cache.is_single_process_reference());
    }

    #[test]
    fn durability_class_defaults_to_single_process_reference() {
        // A cache that implements ONLY check_and_insert (forgetting to declare a
        // durability posture) must be treated as the non-durable reference, NOT as
        // durable — fail closed. AlwaysUnavailableReplayCache exercises exactly the
        // default-only path.
        let cache = AlwaysUnavailableReplayCache;
        assert_eq!(
            cache.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
        assert!(cache.is_single_process_reference());
    }

    #[test]
    fn operational_failure_maps_to_replay_cache_unavailable() {
        let mut cache = AlwaysUnavailableReplayCache;
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
            .expect_err("always-unavailable cache must fail");
        assert_eq!(err.to_mcps_error(), McpsError::ReplayCacheUnavailable);
        // The `From` impl agrees.
        assert_eq!(McpsError::from(err), McpsError::ReplayCacheUnavailable);
    }
}
