//! MCP-S client-side ambassador (MCPS-014, ADR-MCPS-003).
//!
//! The host is the agent's local key/actor context. It injects and signs the
//! MCP-S request envelope ([`HostSigner`]) and verifies signed server responses
//! (re-exported [`verify_response`]). The language model never holds private
//! keys or constructs signatures: it can drive a [`HostSigner`] but cannot read
//! its key or forge a signature.
//!
//! The host produces and consumes raw JSON-RPC bytes; the transport (stdio /
//! Streamable HTTP) is the caller's concern, so this crate stays free of
//! networking/async and depends only on the pure `mcps-core` primitives.

pub mod clock;
pub mod nonce;
pub mod pending;
pub mod session;
pub mod signer;
pub mod verified_result;

pub use signer::HostSigner;

// MCPS-033 (ADR-MCPS-015): stateful client session over the unchanged signer,
// with injected clock + nonce providers (production defaults + deterministic
// test providers) and request_hash correlation by JSON-RPC id.
pub use clock::Clock;
pub use clock::SystemClock;
pub use nonce::NonceSource;
pub use nonce::SystemNonceSource;
// Deterministic TEST fixtures: re-exported ONLY when compiled under `cfg(test)`
// or the explicit `test-fixtures` feature, so they are absent from the default
// (production) public surface. A doc comment is not an enforced boundary; this
// `cfg` is (audit #81 MEDIUM).
#[cfg(any(test, feature = "test-fixtures"))]
pub use clock::FixedClock;
#[cfg(any(test, feature = "test-fixtures"))]
pub use nonce::SeededNonceSource;
pub use nonce::NONCE_BYTES;
pub use pending::PendingRequest;
pub use session::HostSession;
pub use session::DEFAULT_REQUEST_LIFETIME_SECS;
pub use verified_result::VerifiedResult;

// Response verification is exactly mcps-core's: the host re-exports it as the
// client-facing entry point (verify the server's signature + request binding).
// `unwrap_verified_result` / `UnwrappedResult` are re-exported alongside so a
// consumer can restore the original MCP shape after verification (issue #4077).
pub use mcps_core::unwrap_verified_result;
pub use mcps_core::verify_response;
pub use mcps_core::McpsError;
pub use mcps_core::TrustResolver;
pub use mcps_core::UnwrappedResult;
pub use mcps_core::VerifiedResponse;
