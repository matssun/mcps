//! Phase 5 authorization error taxonomy (ADR-MCPS-013).
//!
//! This is a SEPARATE taxonomy from the frozen Core `mcps_core::McpsError`. Core
//! proves a request is authentic, fresh, non-replayed, and audience-correct and
//! carries an opaque `authorization_hash`; the policy layer interprets the
//! authorization artifact behind that hash and renders an allow/deny decision.
//! The variants here supersede the planning brief's stale `mcps.capability_*`
//! names for the same reason Core renamed `capability_hash` -> `authorization_hash`:
//! the term "capability" was dropped from the MCP-S vocabulary.

/// The frozen Phase 5 authorization-error taxonomy (ADR-MCPS-013). One variant
/// per `mcps.authorization_*` wire token. `Display` (via `thiserror`) and
/// [`PolicyError::wire_code`] both render the bare token; any human-readable
/// context is kept out of the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The request verified at the Core layer but carries no
    /// `se.syncom/mcps.authorization` sibling block.
    #[error("mcps.authorization_block_missing")]
    AuthorizationBlockMissing,

    /// `sha256(decoded artifact bytes)` did not equal the verified
    /// `authorization_hash` — the artifact is not the one Core signed over.
    #[error("mcps.authorization_hash_mismatch")]
    AuthorizationHashMismatch,

    /// The `profile` identifier in the authorization block is not registered
    /// with this verifier.
    #[error("mcps.authorization_profile_unsupported")]
    AuthorizationProfileUnsupported,

    /// The artifact bytes do not parse into the profile's expected shape.
    #[error("mcps.authorization_malformed")]
    AuthorizationMalformed,

    /// The issuer signature (or delegation chain) over the artifact did not
    /// verify.
    #[error("mcps.authorization_signature_invalid")]
    AuthorizationSignatureInvalid,

    /// The artifact's grantee did not match the Core-verified request signer.
    #[error("mcps.authorization_signer_mismatch")]
    AuthorizationSignerMismatch,

    /// The artifact's subject did not match the verified `on_behalf_of`.
    #[error("mcps.authorization_subject_mismatch")]
    AuthorizationSubjectMismatch,

    /// The artifact's audience did not match the verified `audience`.
    #[error("mcps.authorization_audience_mismatch")]
    AuthorizationAudienceMismatch,

    /// `now` fell outside the artifact's `[not_before, expires_at]` window.
    #[error("mcps.authorization_expired")]
    AuthorizationExpired,

    /// The artifact's `revocation_id` was present in the revocation source.
    #[error("mcps.authorization_revoked")]
    AuthorizationRevoked,

    /// The revocation source could NOT determine the artifact's status (the
    /// backend was unavailable). M-10 (audit follow-up): this is DISTINCT from
    /// [`PolicyError::AuthorizationRevoked`] — both fail closed (deny), but an
    /// operational outage gets its own diagnosable token instead of being
    /// silently reported as a revocation. Mirrors Core's
    /// `trust_resolver_unavailable` / `replay_cache_unavailable` split.
    #[error("mcps.authorization_revocation_unavailable")]
    AuthorizationRevocationUnavailable,

    /// The requested method / tool-or-resource / arguments are not within the
    /// artifact's granted scope.
    #[error("mcps.authorization_scope_denied")]
    AuthorizationScopeDenied,
}

impl PolicyError {
    /// Returns the exact frozen wire token (`mcps.authorization_*`) for this error.
    /// The bare token only — never any human-readable context.
    pub fn wire_code(&self) -> &'static str {
        match self {
            PolicyError::AuthorizationBlockMissing => "mcps.authorization_block_missing",
            PolicyError::AuthorizationHashMismatch => "mcps.authorization_hash_mismatch",
            PolicyError::AuthorizationProfileUnsupported => {
                "mcps.authorization_profile_unsupported"
            }
            PolicyError::AuthorizationMalformed => "mcps.authorization_malformed",
            PolicyError::AuthorizationSignatureInvalid => "mcps.authorization_signature_invalid",
            PolicyError::AuthorizationSignerMismatch => "mcps.authorization_signer_mismatch",
            PolicyError::AuthorizationSubjectMismatch => "mcps.authorization_subject_mismatch",
            PolicyError::AuthorizationAudienceMismatch => "mcps.authorization_audience_mismatch",
            PolicyError::AuthorizationExpired => "mcps.authorization_expired",
            PolicyError::AuthorizationRevoked => "mcps.authorization_revoked",
            PolicyError::AuthorizationRevocationUnavailable => {
                "mcps.authorization_revocation_unavailable"
            }
            PolicyError::AuthorizationScopeDenied => "mcps.authorization_scope_denied",
        }
    }
}

/// Result alias over the Phase 5 authorization-error taxonomy.
pub type PolicyResult<T> = Result<T, PolicyError>;

#[cfg(test)]
mod tests {
    use super::PolicyError;

    fn check(err: PolicyError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcps.authorization_"));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn every_variant_renders_its_exact_wire_token() {
        check(
            PolicyError::AuthorizationBlockMissing,
            "mcps.authorization_block_missing",
        );
        check(
            PolicyError::AuthorizationHashMismatch,
            "mcps.authorization_hash_mismatch",
        );
        check(
            PolicyError::AuthorizationProfileUnsupported,
            "mcps.authorization_profile_unsupported",
        );
        check(
            PolicyError::AuthorizationMalformed,
            "mcps.authorization_malformed",
        );
        check(
            PolicyError::AuthorizationSignatureInvalid,
            "mcps.authorization_signature_invalid",
        );
        check(
            PolicyError::AuthorizationSignerMismatch,
            "mcps.authorization_signer_mismatch",
        );
        check(
            PolicyError::AuthorizationSubjectMismatch,
            "mcps.authorization_subject_mismatch",
        );
        check(
            PolicyError::AuthorizationAudienceMismatch,
            "mcps.authorization_audience_mismatch",
        );
        check(
            PolicyError::AuthorizationExpired,
            "mcps.authorization_expired",
        );
        check(
            PolicyError::AuthorizationRevoked,
            "mcps.authorization_revoked",
        );
        check(
            PolicyError::AuthorizationRevocationUnavailable,
            "mcps.authorization_revocation_unavailable",
        );
        check(
            PolicyError::AuthorizationScopeDenied,
            "mcps.authorization_scope_denied",
        );
    }

    /// M-10: the two revocation-denial tokens are DISTINCT (an outage is not a
    /// revocation), so a caller can tell them apart on the wire.
    #[test]
    fn revoked_and_unavailable_are_distinct_tokens() {
        assert_ne!(
            PolicyError::AuthorizationRevoked.wire_code(),
            PolicyError::AuthorizationRevocationUnavailable.wire_code()
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(
            PolicyError::AuthorizationRevoked,
            PolicyError::AuthorizationRevoked
        );
        assert_ne!(
            PolicyError::AuthorizationRevoked,
            PolicyError::AuthorizationExpired
        );
    }
}
