//! Pairing of a verified response's metadata with its unwrapped payload
//! (issue #4077 / MCPS-MED-4).

use mcps_core::UnwrappedResult;
use mcps_core::VerifiedResponse;

/// The full client-side outcome of verifying AND unwrapping a signed proxy
/// response: the cryptographic verdict ([`VerifiedResponse`] — signer/key/bound
/// request hash) plus the [`UnwrappedResult`] restoring the ORIGINAL MCP shape
/// the proxy reshaped before signing.
///
/// Returned by `HostSession::verify_and_unwrap_response`. Callers that only need
/// the verdict keep using `HostSession::verify_response`; callers that consume
/// the result payload use this so a scalar arrives as a scalar and an inner error
/// arrives as an error rather than a success.
///
/// Like [`VerifiedResponse`], this is a PROOF token (ADR-MCPS-003): the only
/// legitimate producer is `HostSession::verify_and_unwrap_response`, which builds
/// it from a `VerifiedResponse` that could itself only come from the verifier. To
/// keep it as evidence the fields are PRIVATE, the constructor is `pub(crate)`
/// (reachable only inside `mcps-host`), and `#[non_exhaustive]` blocks external
/// struct-literal construction. Downstream crates READ the verdict via the
/// accessors but can NOT fabricate one (issue #83).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VerifiedResult {
    /// The verification verdict: server signer, key id, and bound request hash.
    verified: VerifiedResponse,
    /// The original MCP `result` shape recovered after verification.
    unwrapped: UnwrappedResult,
}

impl VerifiedResult {
    /// Mint a verified+unwrapped outcome. `pub(crate)` ON PURPOSE: the ONLY
    /// legitimate producer is `HostSession::verify_and_unwrap_response`, so this
    /// proof token cannot be forged from outside `mcps-host` (issue #83).
    pub(crate) fn new(verified: VerifiedResponse, unwrapped: UnwrappedResult) -> Self {
        Self {
            verified,
            unwrapped,
        }
    }

    /// The verification verdict (server signer, key id, bound request hash).
    pub fn verified(&self) -> &VerifiedResponse {
        &self.verified
    }

    /// The original MCP `result` shape recovered after verification.
    pub fn unwrapped(&self) -> &UnwrappedResult {
        &self.unwrapped
    }

    /// Consume the outcome into its two parts (verdict, unwrapped payload) for
    /// callers that need to move both out by value.
    pub fn into_parts(self) -> (VerifiedResponse, UnwrappedResult) {
        (self.verified, self.unwrapped)
    }
}
