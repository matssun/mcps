//! Injected wall-clock abstraction for the host session (MCPS-033, ADR-MCPS-015).
//!
//! The host — unlike pure `mcps-core` — is allowed to read time, but it reads it
//! through an injected [`Clock`] so signing is deterministic under test. Core
//! itself never reads the clock (ADR-MCPS-006 "push timestamps to callers"); the
//! session is exactly such a caller, stamping `issued_at`/`expires_at` from the
//! injected clock and formatting them with `mcps_core::unix_to_rfc3339_utc`.

/// A source of the current time as Unix seconds (UTC).
///
/// Implemented in production by [`SystemClock`] (reads the OS clock) and in tests
/// by [`FixedClock`] (returns a frozen value), so session output is reproducible.
pub trait Clock {
    /// The current time as whole Unix seconds (UTC).
    fn now_unix(&self) -> i64;
}

/// Production clock: reads the OS wall clock via `std::time::SystemTime`.
///
/// A clock set before the Unix epoch yields a negative second count; this is the
/// faithful reading and is left to the freshness check at the verifier to reject.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Construct the production clock.
    pub fn new() -> Self {
        SystemClock
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(delta) => delta.as_secs() as i64,
            // Clock set before the epoch: report the (negative) offset faithfully
            // rather than fabricate a value. The verifier's freshness window then
            // rejects it — fail closed at the boundary, not by inventing time.
            Err(err) => -(err.duration().as_secs() as i64),
        }
    }
}

/// Deterministic test clock: always returns a fixed Unix-second value.
///
/// A TEST fixture, reused as an injectable clock by integration tests (and the
/// deterministic demo binaries) in this and dependent crates. It is compiled
/// only under `cfg(test)` or the explicit `test-fixtures` cargo feature — an
/// *enforced* boundary, so a default (production) build of `mcps-host` does not
/// compile or export `FixedClock` at all. That fixture therefore cannot be used
/// to pin a `HostSession` to a frozen clock unless `test-fixtures` is enabled.
/// (This scopes only this fixture; a consumer remains free to provide its own
/// [`Clock`] implementation.)
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now_unix: i64,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl FixedClock {
    /// Construct a clock frozen at `now_unix` (whole Unix seconds, UTC).
    pub fn new(now_unix: i64) -> Self {
        FixedClock { now_unix }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }
}
