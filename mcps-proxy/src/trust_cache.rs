//! Bounded trust-propagation cache (ADR-MCPS-021, Tier 1).
//!
//! `mcps-core` deliberately does NOT cache trust resolutions — its `resolver`
//! module states bounded-TTL caching is a *caller* concern, and the resolver
//! answer at verify time is final. In a multi-node fleet that caller concern
//! becomes a real one: revocation and key-status state must propagate across
//! nodes, and a verifier that re-hits the shared trust source on every request
//! pays latency and couples availability to it. ADR-MCPS-021 bounds the staleness
//! with a **trust-propagation window `T`**: a verifier MAY serve cached *active*
//! trust state for at most `T`, after which it MUST revalidate or fail closed.
//!
//! This module implements the **Tier 1** posture (bounded-cache eventual): a
//! [`TrustResolver`] wrapper that caches the inner resolver's answers under
//! ADR-MCPS-021's classification rules. It is pure (clock-injected, no I/O) so the
//! whole staleness/fail-closed contract is unit-testable without any external
//! store.
//!
//! ## Classification (ADR-MCPS-021)
//!
//! - **Active** key state is cached for at most `T` (the revocation exposure
//!   window). After `T` the entry is re-resolved; if the source is unavailable
//!   then, the request fails closed — a node never serves stale *active* trust
//!   beyond `T`, and a restart with an empty cache plus an unreachable source
//!   fails closed (no stale-trust resurrection).
//! - **`Revoked`** is a safe deny and is cached for `T` (caching a deny is never
//!   a security risk; serving it longer only delays re-admitting a key that was
//!   re-enabled, which the operator controls).
//! - **`NotFound`** uses a SHORT negative TTL so a freshly published rotation key
//!   is not suppressed (an availability hazard, not a security one).
//! - **`MalformedKey`** is a safe deny but, like `NotFound`, is correctable by
//!   republishing a valid key, so it uses the short negative TTL.
//! - **`Unavailable`** is an operational failure: it is NEVER cached as a trust
//!   decision and always fails closed.

use std::collections::HashMap;
use std::sync::Mutex;

use mcps_core::TrustResolver;
use mcps_core::TrustResolverError;
use mcps_core::VerificationKey;

/// The maximum recommended trust-propagation window (seconds). ADR-MCPS-021 warns
/// when a configured `T` exceeds 5 minutes (a long revocation exposure window);
/// strict/production mode MAY cap `T` at this value unless explicitly overridden.
pub const RECOMMENDED_MAX_T_SECS: i64 = 300;

/// The deployment-wide default trust-propagation window (seconds), ADR-MCPS-021.
pub const DEFAULT_T_SECS: i64 = 60;

/// The default short negative TTL (seconds) for `NotFound` / `MalformedKey`
/// outcomes, so a freshly published rotation key is not suppressed for the full
/// window `T` (an availability hazard, not a security one). Deliberately small and
/// `<= DEFAULT_T_SECS`; used when wiring the Tier-1 bounded cache (and the Tier-3
/// bounded fallback) from the CLI.
pub const DEFAULT_NEGATIVE_TTL_SECS: i64 = 5;

/// Whether a configured `T` exceeds the recommended maximum (→ the proxy warns;
/// strict mode MAY cap). A non-positive `T` (live-check / no caching) never warns.
pub fn t_exceeds_recommended_max(t_secs: i64) -> bool {
    t_secs > RECOMMENDED_MAX_T_SECS
}

/// Select the **strictest applicable** trust-propagation window (ADR-MCPS-021:
/// "a request MUST use the strictest applicable `T`").
///
/// Starts from the global `default_t_secs` and takes the minimum over any stricter
/// per-sensitivity-class windows that apply to the request (admin, financial
/// mutation, production infra, high-risk tools). Negative class windows are
/// ignored (malformed config never widens the window); the default is clamped to
/// non-negative. The result is the smallest — i.e. the tightest revocation
/// exposure — of the applicable windows.
pub fn strictest_applicable_t(default_t_secs: i64, class_windows: &[i64]) -> i64 {
    class_windows
        .iter()
        .copied()
        .filter(|t| *t >= 0)
        .fold(default_t_secs.max(0), |acc, t| acc.min(t))
}

/// A source of the CURRENT Unix time (seconds). The proxy's impure edge — the
/// pure `TrustResolver` trait carries no clock, so the cache owns one to bound the
/// propagation window `T`. Production injects [`system_clock`]; tests inject a
/// controllable clock so the window arithmetic is deterministic.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// The production [`UnixClock`]: reads the system clock, clamping a pre-epoch
/// reading (impossible on a sane host) to 0 rather than panicking.
pub fn system_clock() -> UnixClock {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// A cached resolution outcome. The full positive result (the key) is cached so a
/// key is NEVER cached independently of its active status (ADR-MCPS-021): a hit
/// reconstructs exactly the `resolve` answer that produced it.
#[derive(Clone)]
enum CachedOutcome {
    /// An active binding with its verification key.
    Active(VerificationKey),
    /// A safe-deny: the binding is revoked/disabled.
    Revoked,
    /// A definitive negative: no binding present.
    NotFound,
    /// The stored key material was malformed.
    Malformed,
}

impl CachedOutcome {
    /// Reconstruct the `resolve` result this cached outcome represents.
    fn to_result(&self) -> Result<VerificationKey, TrustResolverError> {
        match self {
            CachedOutcome::Active(key) => Ok(key.clone()),
            CachedOutcome::Revoked => Err(TrustResolverError::Revoked),
            CachedOutcome::NotFound => Err(TrustResolverError::NotFound),
            CachedOutcome::Malformed => Err(TrustResolverError::MalformedKey),
        }
    }
}

/// One cache entry: a classified outcome plus the absolute Unix instant at which
/// it expires (`resolved_at + ttl`).
struct CacheEntry {
    outcome: CachedOutcome,
    expires_at: i64,
}

/// A [`TrustResolver`] that wraps an inner resolver with ADR-MCPS-021 Tier-1
/// bounded-`T` caching.
///
/// `resolve` serves a cached entry while it is within its window; otherwise it
/// consults the inner resolver and caches the answer per the classification
/// rules. An [`TrustResolverError::Unavailable`] from the inner resolver is never
/// cached and fails closed — and because cached *active* state lives at most `T`,
/// a node cannot serve stale active trust beyond the window even while the source
/// is down (and a fresh process with an empty cache fails closed if the source is
/// unreachable).
pub struct BoundedTrustCache {
    inner: Box<dyn TrustResolver + Send + Sync>,
    /// The trust-propagation window `T` (seconds): the max age of cached *active*
    /// or *revoked* state.
    t_secs: i64,
    /// The short negative TTL (seconds) for `NotFound` / `MalformedKey`, so a
    /// freshly published key is not suppressed.
    negative_ttl_secs: i64,
    clock: UnixClock,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl BoundedTrustCache {
    /// Wrap `inner` with a propagation window of `t_secs` for active/revoked state
    /// and `negative_ttl_secs` for not-found/malformed negatives.
    ///
    /// `t_secs` is the documented revocation exposure window. `negative_ttl_secs`
    /// should be short (and `<= t_secs`) so rotation keys propagate promptly;
    /// values are clamped to non-negative.
    pub fn new(
        inner: Box<dyn TrustResolver + Send + Sync>,
        t_secs: i64,
        negative_ttl_secs: i64,
        clock: UnixClock,
    ) -> Self {
        BoundedTrustCache {
            inner,
            t_secs: t_secs.max(0),
            negative_ttl_secs: negative_ttl_secs.max(0),
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Compose a COLLISION-SAFE cache key for a `(signer, key_id)` pair.
    ///
    /// A naive `"{signer}#{key_id}"` join is NOT injective: a `signer` or `key_id`
    /// containing the `#` delimiter aliases distinct pairs (e.g. `("a#b", "c")` and
    /// `("a", "b#c")` both compose to `"a#b#c"`). Signer strings are DIDs/URIs that
    /// legitimately contain `#`, so two different bindings could collide — and now
    /// that [`evict`](BoundedTrustCache::evict) keys off this for Tier-3
    /// invalidation, a collision could evict the WRONG entry or fail to evict the
    /// intended one, and Tier 1/3 could serve the wrong cached key. We length-prefix
    /// each field (in BYTES) so the encoding is unambiguous regardless of any
    /// delimiter the fields contain, guaranteeing injectivity. This is the SAME
    /// hardening as `mcps_core::InMemoryTrustResolver::compose_key` (the #79 fix).
    /// Every cache op (resolve/cached/store/evict) routes through this one function,
    /// so fixing it here fixes all sites.
    fn compose_key(signer: &str, key_id: &str) -> String {
        format!("{}:{}|{}:{}", signer.len(), signer, key_id.len(), key_id)
    }

    /// Look up a still-live cache entry. Returns the reconstructed result on a hit
    /// within the window, or `None` if absent/expired. A poisoned cache mutex is an
    /// operational failure (fail closed): surfaced as `Some(Err(Unavailable))`.
    fn cached(
        &self,
        key: &str,
        now: i64,
    ) -> Option<Result<VerificationKey, TrustResolverError>> {
        let cache = match self.cache.lock() {
            Ok(c) => c,
            Err(e) => {
                return Some(Err(TrustResolverError::Unavailable {
                    details: format!("trust cache mutex poisoned: {e}"),
                }))
            }
        };
        let entry = cache.get(key)?;
        if now < entry.expires_at {
            Some(entry.outcome.to_result())
        } else {
            None
        }
    }

    /// Store `outcome` for `key` with `ttl` seconds from `now`. A poisoned mutex
    /// drops the write (the request still gets its answer; only caching is lost).
    fn store(&self, key: String, outcome: CachedOutcome, now: i64, ttl: i64) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                key,
                CacheEntry {
                    outcome,
                    expires_at: now.saturating_add(ttl),
                },
            );
        }
    }

    /// Evict every entry whose window has closed (`expires_at <= now`). Opportunistic
    /// housekeeping; correctness does not depend on it (an expired entry is ignored
    /// on read), but it bounds memory for churny key sets.
    pub fn prune(&self, now: i64) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|_, e| e.expires_at > now);
        }
    }

    /// Immediately drop any cached entry for `(signer, key_id)`, regardless of its
    /// remaining window. Returns `true` if an entry was present and removed.
    ///
    /// This is the hook the ADR-MCPS-021 **Tier 3** push-invalidation cache uses to
    /// honor a pushed revocation event BEFORE `T` elapses: the next `resolve`
    /// re-consults the inner store (picking up the revocation) instead of serving a
    /// stale-but-within-`T` active entry. A poisoned cache mutex is treated as
    /// "nothing to evict" (the entry, if any, is unreachable anyway and the next
    /// read fails closed via [`cached`](BoundedTrustCache::cached)).
    pub fn evict(&self, signer: &str, key_id: &str) -> bool {
        let key = Self::compose_key(signer, key_id);
        match self.cache.lock() {
            Ok(mut cache) => cache.remove(&key).is_some(),
            Err(_) => false,
        }
    }
}

impl TrustResolver for BoundedTrustCache {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        let now = (self.clock)();
        let key = Self::compose_key(signer, key_id);

        // 1. Serve a cached answer while it is within its window. Active/revoked
        //    entries live `T`; not-found/malformed live the short negative TTL.
        if let Some(hit) = self.cached(&key, now) {
            return hit;
        }

        // 2. Cache miss or expired window: consult the inner resolver. Past `T`
        //    there is no live cache to serve, so an Unavailable here fails closed —
        //    a node never serves stale active trust beyond `T`, and a fresh process
        //    (empty cache) with an unreachable source fails closed.
        let result = self.inner.resolve(signer, key_id);

        // 3. Cache the answer per ADR-MCPS-021 classification.
        match &result {
            Ok(verification_key) => {
                self.store(key, CachedOutcome::Active(verification_key.clone()), now, self.t_secs)
            }
            Err(TrustResolverError::Revoked) => {
                self.store(key, CachedOutcome::Revoked, now, self.t_secs)
            }
            Err(TrustResolverError::NotFound) => {
                self.store(key, CachedOutcome::NotFound, now, self.negative_ttl_secs)
            }
            Err(TrustResolverError::MalformedKey) => {
                self.store(key, CachedOutcome::Malformed, now, self.negative_ttl_secs)
            }
            // Unavailable is an operational failure: NEVER cached, always fail closed.
            Err(TrustResolverError::Unavailable { .. }) => {}
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedTrustCache;
    use super::UnixClock;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    use mcps_core::SigningKey;
    use mcps_core::TrustResolver;
    use mcps_core::TrustResolverError;
    use mcps_core::VerificationKey;

    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    /// A programmable inner resolver: returns whatever outcome is currently set and
    /// counts how many times the inner `resolve` actually ran (to prove cache hits
    /// do NOT consult it). Send+Sync via interior `Mutex`/atomics.
    struct ScriptedResolver {
        outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
        calls: AtomicUsize,
    }

    impl ScriptedResolver {
        fn new(initial: Result<VerificationKey, TrustResolverError>) -> Self {
            ScriptedResolver {
                outcome: Mutex::new(initial),
                calls: AtomicUsize::new(0),
            }
        }
        fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
            *self.outcome.lock().unwrap() = outcome;
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TrustResolver for ScriptedResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.lock().unwrap().clone()
        }
    }

    /// A clock whose "now" the test advances. Returned alongside a handle so the
    /// test can move time forward across the window boundary.
    fn controllable_clock(start: i64) -> (UnixClock, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(start));
        let handle = now.clone();
        let clock: UnixClock = Box::new(move || now.load(Ordering::SeqCst));
        (clock, handle)
    }

    const T: i64 = 60;
    const NEG_TTL: i64 = 5;

    /// A shared inner resolver wrapped so the cache owns one box while the test
    /// keeps a handle to drive/inspect it.
    fn cache_over(
        inner: Arc<ScriptedResolver>,
        clock: UnixClock,
    ) -> BoundedTrustCache {
        struct Shared(Arc<ScriptedResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        BoundedTrustCache::new(Box::new(Shared(inner)), T, NEG_TTL, clock)
    }

    #[test]
    fn active_hit_within_window_does_not_consult_inner() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        let first = cache.resolve("did:host", "key-1").expect("active resolves");
        assert_eq!(first.to_bytes(), key_from(&SEED_A).to_bytes());
        // A second call within T is served from cache: inner consulted only once.
        let second = cache.resolve("did:host", "key-1").expect("served from cache");
        assert_eq!(second.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(inner.calls(), 1, "within T the inner resolver is not re-consulted");
    }

    #[test]
    fn active_re_resolves_after_window() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("first resolve");
        // Past T the entry is stale: the inner resolver is consulted again, picking
        // up a rotated key.
        inner.set(Ok(key_from(&SEED_B)));
        now.store(1000 + T, Ordering::SeqCst); // exactly at expiry → no longer < expires_at
        let rotated = cache.resolve("did:host", "key-1").expect("re-resolves past T");
        assert_eq!(rotated.to_bytes(), key_from(&SEED_B).to_bytes());
        assert_eq!(inner.calls(), 2, "past T the inner resolver is consulted again");
    }

    #[test]
    fn revoked_is_cached_and_denies() {
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::Revoked)));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked
        );
        // Even if the inner flips to Active, the cached revoke denies within T.
        inner.set(Ok(key_from(&SEED_A)));
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "a cached safe-deny holds within T"
        );
        assert_eq!(inner.calls(), 1);
    }

    #[test]
    fn not_found_uses_short_ttl_so_a_new_key_propagates() {
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::NotFound)));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::NotFound
        );
        // A freshly published key must be picked up after the SHORT negative TTL,
        // well before the full T would elapse.
        inner.set(Ok(key_from(&SEED_A)));
        now.store(1000 + NEG_TTL, Ordering::SeqCst);
        let resolved = cache
            .resolve("did:host", "key-1")
            .expect("a published key resolves after the short negative TTL");
        assert_eq!(resolved.to_bytes(), key_from(&SEED_A).to_bytes());
        // And the short TTL is strictly less than the active window T.
        assert!(NEG_TTL < T);
    }

    #[test]
    fn unavailable_is_not_cached_and_fails_closed() {
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::Unavailable {
            details: "source down".to_string(),
        })));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert!(matches!(
            cache.resolve("did:host", "key-1"),
            Err(TrustResolverError::Unavailable { .. })
        ));
        // Not cached: the next call consults the inner resolver again (no stale
        // "unavailable" decision is served).
        inner.set(Ok(key_from(&SEED_A)));
        let resolved = cache.resolve("did:host", "key-1").expect("recovers when source returns");
        assert_eq!(resolved.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(inner.calls(), 2, "Unavailable is never cached");
    }

    #[test]
    fn active_then_source_down_within_window_still_serves_cached() {
        // ADR-MCPS-021: a node MAY serve cached active state obtained before an
        // outage while still within T.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "outage".to_string(),
        }));
        now.store(1000 + T - 1, Ordering::SeqCst); // still within the window
        let served = cache
            .resolve("did:host", "key-1")
            .expect("within T the cached active state is served despite the outage");
        assert_eq!(served.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(inner.calls(), 1, "within T the down source is not consulted");
    }

    #[test]
    fn no_indefinite_stale_active_past_window_fails_closed() {
        // The load-bearing safety property: past T with the source down, the cache
        // does NOT serve stale active trust — it fails closed.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "outage".to_string(),
        }));
        now.store(1000 + T, Ordering::SeqCst); // window closed
        assert!(
            matches!(
                cache.resolve("did:host", "key-1"),
                Err(TrustResolverError::Unavailable { .. })
            ),
            "past T the cache must NOT serve stale active trust; it fails closed"
        );
    }

    #[test]
    fn restart_empty_cache_with_source_down_fails_closed() {
        // A fresh process has an empty cache. With the source unreachable it cannot
        // resurrect any trust — it fails closed (no stale-trust resurrection).
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::Unavailable {
            details: "source down at startup".to_string(),
        })));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner, clock);

        assert!(matches!(
            cache.resolve("did:host", "key-1"),
            Err(TrustResolverError::Unavailable { .. })
        ));
    }

    #[test]
    fn strictest_applicable_t_picks_the_tightest_window() {
        use super::strictest_applicable_t;
        // No class overrides → the global default.
        assert_eq!(strictest_applicable_t(60, &[]), 60);
        // A stricter class window wins (smaller = tighter exposure).
        assert_eq!(strictest_applicable_t(60, &[10]), 10);
        // The strictest of several applicable classes wins.
        assert_eq!(strictest_applicable_t(60, &[30, 5, 45]), 5);
        // A looser class window never widens past the default.
        assert_eq!(strictest_applicable_t(60, &[120]), 60);
        // Negative (malformed) class windows are ignored, not treated as 0.
        assert_eq!(strictest_applicable_t(60, &[-1, 20]), 20);
    }

    #[test]
    fn t_exceeds_recommended_max_flags_long_windows() {
        use super::t_exceeds_recommended_max;
        use super::RECOMMENDED_MAX_T_SECS;
        assert!(!t_exceeds_recommended_max(RECOMMENDED_MAX_T_SECS));
        assert!(t_exceeds_recommended_max(RECOMMENDED_MAX_T_SECS + 1));
        assert!(!t_exceeds_recommended_max(0), "no caching never warns");
        assert!(!t_exceeds_recommended_max(super::DEFAULT_T_SECS));
    }

    #[test]
    fn evict_drops_an_in_window_entry_forcing_re_resolution() {
        // The Tier-3 hook: evict removes a still-in-window entry, so the next
        // resolve re-consults the inner store rather than serving the cached one.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        assert_eq!(inner.calls(), 1);
        // Evicting an unrelated key reports false (nothing removed).
        assert!(!cache.evict("did:host", "key-other"));
        // Evicting the cached entry reports true and forces a re-resolve.
        assert!(cache.evict("did:host", "key-1"));
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "after evict the next resolve re-consults the inner store"
        );
        assert_eq!(inner.calls(), 2);
    }

    #[test]
    fn compose_key_is_injective_across_delimiter_containing_pairs() {
        // Regression for the #79 collision class (mirrors mcps-core's
        // `composite_key_is_injective_across_delimiter_containing_pairs`).
        // `("a#b", "c")` and `("a", "b#c")` both collapse to `"a#b#c"` under a naive
        // `#` join. With the length-prefixed encoding they must NOT collide, so an
        // evict for one pair must not evict the other's cached entry.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        // Prime BOTH colliding-under-`#` pairs (the scripted inner returns the same
        // active key for either; what matters is that they occupy DISTINCT entries).
        cache.resolve("a#b", "c").expect("(\"a#b\",\"c\") active cached");
        cache.resolve("a", "b#c").expect("(\"a\",\"b#c\") active cached");
        assert_eq!(inner.calls(), 2, "two distinct pairs → two distinct misses");

        // Evicting one pair must report success and NOT touch the other.
        assert!(cache.evict("a#b", "c"), "the first pair's entry is present");
        // The other pair is still cached: a second resolve is a hit (no re-consult).
        cache.resolve("a", "b#c").expect("the other pair is still cached");
        assert_eq!(
            inner.calls(),
            2,
            "evicting (\"a#b\",\"c\") must NOT evict (\"a\",\"b#c\")"
        );
        // And the evicted pair really was dropped: it re-consults the inner store.
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            cache.resolve("a#b", "c").unwrap_err(),
            TrustResolverError::Revoked,
            "the evicted pair re-resolves (its entry was actually removed)"
        );
        assert_eq!(inner.calls(), 3);
    }

    #[test]
    fn prune_evicts_closed_windows() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner, clock);
        cache.resolve("did:host", "key-1").expect("cached");
        now.store(1000 + T + 1, Ordering::SeqCst);
        cache.prune(now.load(Ordering::SeqCst));
        // After prune the entry is gone; a fresh resolve re-consults the inner
        // resolver (proven indirectly: it still returns the active key).
        assert_eq!(
            cache.resolve("did:host", "key-1").expect("re-resolves").to_bytes(),
            key_from(&SEED_A).to_bytes()
        );
    }
}
