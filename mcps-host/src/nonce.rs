//! Injected nonce-byte source for the host session (MCPS-033, ADR-MCPS-015).
//!
//! The session generates each request `nonce` from an injected [`NonceSource`]
//! and Base64URL-encodes it (MCPS_SPEC §2/§5: opaque, Base64URL-safe, ≥128 bits
//! of entropy). Injection keeps signing deterministic under test while the
//! production default draws from the OS CSPRNG.
//!
//! `getrandom` is the production entropy source: it is already in the mcps-host
//! dependency closure (transitively, via `ed25519-dalek`), is a thin wrapper over
//! the OS RNG, and pulls in NO networking/async runtime — so the crate stays
//! transport-free.

/// The number of random bytes drawn per nonce: 16 bytes = 128 bits, the spec's
/// minimum entropy. Encoded Base64URL-no-pad this is a 22-character opaque token.
pub const NONCE_BYTES: usize = 16;

/// A source of cryptographically opaque nonce bytes.
///
/// Implemented in production by [`SystemNonceSource`] (OS CSPRNG via `getrandom`)
/// and in tests by `SeededNonceSource` (a deterministic byte stream, available
/// only under `cfg(test)` or the `test-fixtures` feature), so the session's
/// signed output is reproducible under a fixed seed.
///
/// # Fail-closed contract (deliberate, security-critical)
///
/// `fill` is intentionally **infallible**: it has no `Result` return and an
/// implementation MUST NOT report a partial or degraded fill. The nonce is the
/// MCPS replay-freshness defense (MCPS-09 / MCPS_SPEC §2/§5) — a *predictable*
/// nonce is strictly worse than no nonce at all, so the only correct response to
/// an unavailable entropy source is to **fail loud** (panic / abort the signing
/// path), never to fall back to a weak or fixed value. The production
/// implementation upholds this by panicking if the OS CSPRNG is unavailable; see
/// [`SystemNonceSource::fill`]. The input is not attacker-controlled, so this
/// panic cannot be induced by a remote peer — it fires only on a genuinely
/// broken host. Keeping the signature infallible makes the no-weak-nonce
/// property unavoidable for every implementor rather than an opt-in.
pub trait NonceSource {
    /// Fill `out` with `out.len()` fresh nonce bytes.
    ///
    /// Infallible by contract: see the trait-level "Fail-closed contract" note.
    /// An implementation that cannot produce real entropy MUST fail loud (panic)
    /// rather than return predictable bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// Production nonce source: fills from the operating-system CSPRNG via
/// `getrandom`. No networking, no async runtime — OS entropy only.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNonceSource;

impl SystemNonceSource {
    /// Construct the production nonce source.
    pub fn new() -> Self {
        SystemNonceSource
    }
}

impl NonceSource for SystemNonceSource {
    fn fill(&mut self, out: &mut [u8]) {
        // DELIBERATE FAIL-CLOSED-BY-PANIC (see the `NonceSource` trait's
        // "Fail-closed contract"). `getrandom` reads OS entropy and only errors
        // when the OS CSPRNG is genuinely unavailable — a broken host, not an
        // attacker-controlled input. A host that cannot draw entropy MUST NOT
        // emit a predictable nonce (which would silently defeat MCPS replay
        // freshness), so we panic and abort the signing path rather than degrade.
        // The `NonceSource::fill` signature is infallible by design to make this
        // no-weak-nonce property unavoidable; converting it to `Result` was
        // considered and rejected (it would let a caller paper over the one
        // failure mode that must never be recovered from). Deterministic tests
        // inject the seeded source and never reach this path.
        getrandom::getrandom(out).expect("OS CSPRNG (getrandom) must be available to sign requests");
    }
}

/// Deterministic test nonce source: yields the seed bytes as a repeating stream,
/// advancing per byte so successive nonces differ while remaining reproducible.
///
/// It is a TEST provider with NO real entropy and must never reach a production
/// binary. Because it is reused as an injectable fixture by integration tests
/// (and the deterministic demo binaries) in this and dependent crates, it is
/// compiled only under `cfg(test)` or the explicit `test-fixtures` cargo feature
/// — an *enforced* boundary, not a doc-comment one. A default (production) build
/// of `mcps-host` does not compile this type at all, so a misconfigured
/// deployment cannot construct a `HostSession` with predictable nonces from it.
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone)]
pub struct SeededNonceSource {
    seed: Vec<u8>,
    offset: usize,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl SeededNonceSource {
    /// Construct a deterministic source over a non-empty `seed`.
    ///
    /// The first draw returns the leading `seed` bytes verbatim, so callers can
    /// pin exact nonce values in tests.
    pub fn new(seed: &[u8]) -> Self {
        SeededNonceSource {
            // A non-empty stream is required to fill any output; fall back to a
            // single zero byte for an empty seed so `fill` is always defined.
            seed: if seed.is_empty() { vec![0u8] } else { seed.to_vec() },
            offset: 0,
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl NonceSource for SeededNonceSource {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.seed[self.offset % self.seed.len()];
            self.offset += 1;
        }
    }
}
