//! Frozen MCP-S error taxonomy (MCPS_SPEC §8 / ADR-002, ADR-007, ADR-009).
//!
//! Every `mcps.*` constant in the frozen oracle is represented by exactly one
//! variant. `Display` and [`McpsError::wire_code`] both render the bare
//! `mcps.<name>` token; any human-readable `details` payload is kept separate so
//! the wire token is never polluted.

/// The complete frozen MCP-S error taxonomy. One variant per `mcps.*` constant.
///
/// `Display` (via `thiserror`) and [`McpsError::wire_code`] both yield the exact
/// wire string (e.g. `mcps.invalid_signature`). Variants that can usefully carry
/// diagnostic context hold a `details: String`; the wire token NEVER includes it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpsError {
    /// No MCP-S envelope present under the expected `_meta` key.
    #[error("mcps.missing_envelope")]
    MissingEnvelope,

    /// Envelope `version` is not `draft-01`.
    #[error("mcps.unsupported_version")]
    UnsupportedVersion,

    /// Signature did not verify, or an unsupported algorithm was presented.
    #[error("mcps.invalid_signature")]
    InvalidSignature,

    /// The protected message violated the JCS-safe value domain (duplicate keys,
    /// unsafe integers, invalid UTF-8, non-integer numbers, ...).
    #[error("mcps.canonicalization_failed")]
    CanonicalizationFailed,

    /// The request fell outside its freshness window (stale or future-dated
    /// beyond the configured clock skew).
    #[error("mcps.expired_request")]
    ExpiredRequest,

    /// A previously seen `(signer, audience, nonce)` triple was replayed.
    #[error("mcps.replay_detected")]
    ReplayDetected,

    /// The envelope `audience` did not match the expected verifier identity.
    #[error("mcps.invalid_audience")]
    InvalidAudience,

    /// Trust resolution found no usable binding for `(signer, key_id)`
    /// (not-found / revoked / disabled / malformed key). Name kept verbatim per
    /// ADR-007 despite the field rename `actor` -> `signer`.
    #[error("mcps.actor_binding_failed")]
    ActorBindingFailed,

    /// Transport-level channel binding check failed.
    #[error("mcps.transport_binding_failed")]
    TransportBindingFailed,

    /// Required `authorization_hash` field absent. Renamed from the brief's
    /// `capability_hash_missing` (field renamed).
    #[error("mcps.authorization_hash_missing")]
    AuthorizationHashMissing,

    /// Required `on_behalf_of` field absent. Renamed from the brief's
    /// `missing_principal` ("principal" term rejected).
    #[error("mcps.on_behalf_of_missing")]
    OnBehalfOfMissing,

    /// `on_behalf_of` was present but malformed (e.g. empty). Renamed from the
    /// brief's `invalid_principal_format`.
    #[error("mcps.on_behalf_of_invalid_format")]
    OnBehalfOfInvalidFormat,

    /// Response signature did not verify, or an unsupported algorithm was used.
    #[error("mcps.response_sig_invalid")]
    ResponseSigInvalid,

    /// The response's `request_hash` did not match the locally verified request
    /// hash (binding mismatch).
    #[error("mcps.response_hash_mismatch")]
    ResponseHashMismatch,

    /// A security downgrade was attempted and refused.
    #[error("mcps.downgrade_forbidden")]
    DowngradeForbidden,

    /// A JSON-RPC batch (top-level array) was presented; forbidden in Core.
    #[error("mcps.batch_forbidden")]
    BatchForbidden,

    /// A security-consequential notification (no `id`) was presented; such
    /// operations must be id-bearing requests.
    #[error("mcps.notification_forbidden")]
    NotificationForbidden,

    /// An unknown field appeared inside an envelope (fail closed).
    #[error("mcps.unknown_envelope_field")]
    UnknownEnvelopeField,

    /// Operational/transient trust-resolver failure (distinct from a binding
    /// verdict). ADR-007 addition. Never falls back to allow.
    #[error("mcps.trust_resolver_unavailable")]
    TrustResolverUnavailable,

    /// Replay-cache failure (distinct from a replay verdict). Oracle addition
    /// (ADR-006: cache failure fails closed). Parallels
    /// `trust_resolver_unavailable`.
    #[error("mcps.replay_cache_unavailable")]
    ReplayCacheUnavailable,

    // ----- Draft-02 (v0.6) fail-closed codes (ADR-MCPS-040 / decision F.1) -----
    // Granular for protocol/profile-confusion failures; low-level JSON
    // value-domain failures stay coarse under `CanonicalizationFailed`. All nine
    // are draft-02-scoped: draft-01 verification never emits them (ADR-MCPS-041).
    /// Draft-02 envelope lacks the protected `canonicalization_id` member.
    #[error("mcps.canonicalization_id_missing")]
    CanonicalizationIdMissing,

    /// `canonicalization_id` names no canonicalization scheme the verifier knows
    /// (unrecognized token — an unknown-id probe).
    #[error("mcps.canonicalization_id_unknown")]
    CanonicalizationIdUnknown,

    /// `canonicalization_id` is a recognized scheme but is not in the active
    /// draft-02 profile allowlist (e.g. a future floats scheme presented under the
    /// int53-only v0.6 profile) — a disallowed-future-scheme probe.
    #[error("mcps.canonicalization_id_not_allowed")]
    CanonicalizationIdNotAllowed,

    /// The presented `canonicalization_id` does not match the value bound into the
    /// signed evidence (request/response disagreement or a signed-wrong-scheme
    /// presentation).
    #[error("mcps.canonicalization_id_mismatch")]
    CanonicalizationIdMismatch,

    /// Required draft-02 `authorization_binding` object absent. MINTED for
    /// draft-02 (ADR-MCPS-040): NOT a reuse of `authorization_hash_missing`, which
    /// names a draft-01 field that no longer exists on the draft-02 wire.
    #[error("mcps.authorization_binding_missing")]
    AuthorizationBindingMissing,

    /// `authorization_binding.binding_type` is not one of the base draft-02 forms
    /// (`opaque-bytes` / `authz-system-reference`).
    #[error("mcps.authorization_binding_type_unsupported")]
    AuthorizationBindingTypeUnsupported,

    /// `authorization_binding` is structurally invalid for its `binding_type`
    /// (missing mandatory field, malformed digest shape, ...).
    #[error("mcps.authorization_binding_malformed")]
    AuthorizationBindingMalformed,

    /// A structured authorization-object binding (case 3) was presented; the base
    /// draft-02 profile forbids it without an explicit authorization-binding
    /// profile defining artifact schema / canonicalization / hash / vectors.
    #[error("mcps.authorization_binding_profile_required")]
    AuthorizationBindingProfileRequired,

    /// The opaque-bytes binding cannot be reduced to one unambiguous byte string
    /// (e.g. both binding forms present, or an ambiguous artifact representation).
    #[error("mcps.authorization_binding_ambiguous_bytes")]
    AuthorizationBindingAmbiguousBytes,

    /// The optional draft-02 `continuation` object is present but `type` is not the
    /// supported multi-round-trip token (`mcp-mrt`) — ADR-MCPS-047 / D4. A future
    /// continuation profile would be a distinct token; anything unrecognized fails
    /// closed rather than being treated as a bare (unbound) request.
    #[error("mcps.continuation_type_unsupported")]
    ContinuationTypeUnsupported,

    /// The draft-02 `continuation` object is structurally invalid for its `type`
    /// (missing/extra field, empty value, or a hash that is not a well-formed
    /// `sha256:<base64url>` identifier) — ADR-MCPS-047 / D4. Core validates the
    /// binding SHAPE only; the policy/server layer checks the hashes against the
    /// verified `InputRequiredResult` it is answering.
    #[error("mcps.continuation_malformed")]
    ContinuationMalformed,
}

impl McpsError {
    /// Returns the exact frozen wire token (`mcps.<name>`) for this error.
    ///
    /// This is the bare token only — never any `details` payload.
    pub fn wire_code(&self) -> &'static str {
        match self {
            McpsError::MissingEnvelope => "mcps.missing_envelope",
            McpsError::UnsupportedVersion => "mcps.unsupported_version",
            McpsError::InvalidSignature => "mcps.invalid_signature",
            McpsError::CanonicalizationFailed => "mcps.canonicalization_failed",
            McpsError::ExpiredRequest => "mcps.expired_request",
            McpsError::ReplayDetected => "mcps.replay_detected",
            McpsError::InvalidAudience => "mcps.invalid_audience",
            McpsError::ActorBindingFailed => "mcps.actor_binding_failed",
            McpsError::TransportBindingFailed => "mcps.transport_binding_failed",
            McpsError::AuthorizationHashMissing => "mcps.authorization_hash_missing",
            McpsError::OnBehalfOfMissing => "mcps.on_behalf_of_missing",
            McpsError::OnBehalfOfInvalidFormat => "mcps.on_behalf_of_invalid_format",
            McpsError::ResponseSigInvalid => "mcps.response_sig_invalid",
            McpsError::ResponseHashMismatch => "mcps.response_hash_mismatch",
            McpsError::DowngradeForbidden => "mcps.downgrade_forbidden",
            McpsError::BatchForbidden => "mcps.batch_forbidden",
            McpsError::NotificationForbidden => "mcps.notification_forbidden",
            McpsError::UnknownEnvelopeField => "mcps.unknown_envelope_field",
            McpsError::TrustResolverUnavailable => "mcps.trust_resolver_unavailable",
            McpsError::ReplayCacheUnavailable => "mcps.replay_cache_unavailable",
            // Draft-02 (v0.6) — ADR-MCPS-040 / decision F.1.
            McpsError::CanonicalizationIdMissing => "mcps.canonicalization_id_missing",
            McpsError::CanonicalizationIdUnknown => "mcps.canonicalization_id_unknown",
            McpsError::CanonicalizationIdNotAllowed => "mcps.canonicalization_id_not_allowed",
            McpsError::CanonicalizationIdMismatch => "mcps.canonicalization_id_mismatch",
            McpsError::AuthorizationBindingMissing => "mcps.authorization_binding_missing",
            McpsError::AuthorizationBindingTypeUnsupported => {
                "mcps.authorization_binding_type_unsupported"
            }
            McpsError::AuthorizationBindingMalformed => "mcps.authorization_binding_malformed",
            McpsError::AuthorizationBindingProfileRequired => {
                "mcps.authorization_binding_profile_required"
            }
            McpsError::AuthorizationBindingAmbiguousBytes => {
                "mcps.authorization_binding_ambiguous_bytes"
            }
            McpsError::ContinuationTypeUnsupported => "mcps.continuation_type_unsupported",
            McpsError::ContinuationMalformed => "mcps.continuation_malformed",
        }
    }
}

/// Result alias over the frozen MCP-S error taxonomy.
pub type McpsResult<T> = Result<T, McpsError>;

#[cfg(test)]
mod tests {
    use super::McpsError;

    /// Every variant's `Display` output must equal its `wire_code`, and both
    /// must be a bare `mcps.*` token (no whitespace, no details).
    fn check(err: McpsError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcps."));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn renamed_and_kept_variants_render_exact_wire_strings() {
        check(
            McpsError::CanonicalizationFailed,
            "mcps.canonicalization_failed",
        );
        check(
            McpsError::AuthorizationHashMissing,
            "mcps.authorization_hash_missing",
        );
        check(McpsError::OnBehalfOfMissing, "mcps.on_behalf_of_missing");
        check(
            McpsError::OnBehalfOfInvalidFormat,
            "mcps.on_behalf_of_invalid_format",
        );
        check(
            McpsError::TrustResolverUnavailable,
            "mcps.trust_resolver_unavailable",
        );
        check(
            McpsError::ReplayCacheUnavailable,
            "mcps.replay_cache_unavailable",
        );
        // KEPT verbatim despite field rename actor -> signer (ADR-007).
        check(McpsError::ActorBindingFailed, "mcps.actor_binding_failed");
    }

    #[test]
    fn full_taxonomy_wire_strings() {
        check(McpsError::MissingEnvelope, "mcps.missing_envelope");
        check(McpsError::UnsupportedVersion, "mcps.unsupported_version");
        check(McpsError::InvalidSignature, "mcps.invalid_signature");
        check(McpsError::ExpiredRequest, "mcps.expired_request");
        check(McpsError::ReplayDetected, "mcps.replay_detected");
        check(McpsError::InvalidAudience, "mcps.invalid_audience");
        check(
            McpsError::TransportBindingFailed,
            "mcps.transport_binding_failed",
        );
        check(McpsError::ResponseSigInvalid, "mcps.response_sig_invalid");
        check(
            McpsError::ResponseHashMismatch,
            "mcps.response_hash_mismatch",
        );
        check(McpsError::DowngradeForbidden, "mcps.downgrade_forbidden");
        check(McpsError::BatchForbidden, "mcps.batch_forbidden");
        check(
            McpsError::NotificationForbidden,
            "mcps.notification_forbidden",
        );
        check(
            McpsError::UnknownEnvelopeField,
            "mcps.unknown_envelope_field",
        );
    }

    #[test]
    fn draft02_wire_strings() {
        // ADR-MCPS-040 / decision F.1 — the nine new draft-02 fail-closed codes.
        check(
            McpsError::CanonicalizationIdMissing,
            "mcps.canonicalization_id_missing",
        );
        check(
            McpsError::CanonicalizationIdUnknown,
            "mcps.canonicalization_id_unknown",
        );
        check(
            McpsError::CanonicalizationIdNotAllowed,
            "mcps.canonicalization_id_not_allowed",
        );
        check(
            McpsError::CanonicalizationIdMismatch,
            "mcps.canonicalization_id_mismatch",
        );
        check(
            McpsError::AuthorizationBindingMissing,
            "mcps.authorization_binding_missing",
        );
        check(
            McpsError::AuthorizationBindingTypeUnsupported,
            "mcps.authorization_binding_type_unsupported",
        );
        check(
            McpsError::AuthorizationBindingMalformed,
            "mcps.authorization_binding_malformed",
        );
        check(
            McpsError::AuthorizationBindingProfileRequired,
            "mcps.authorization_binding_profile_required",
        );
        check(
            McpsError::AuthorizationBindingAmbiguousBytes,
            "mcps.authorization_binding_ambiguous_bytes",
        );
    }

    /// `authorization_binding_missing` is MINTED for draft-02 and is distinct from
    /// the retained draft-01 `authorization_hash_missing` (ADR-MCPS-040).
    #[test]
    fn draft02_binding_missing_is_distinct_from_draft01_hash_missing() {
        assert_ne!(
            McpsError::AuthorizationBindingMissing.wire_code(),
            McpsError::AuthorizationHashMissing.wire_code(),
        );
        check(
            McpsError::AuthorizationHashMissing,
            "mcps.authorization_hash_missing",
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(McpsError::ReplayDetected, McpsError::ReplayDetected);
        assert_ne!(McpsError::ReplayDetected, McpsError::ExpiredRequest);
    }
}
