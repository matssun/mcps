//! MCP-S audit-evidence vocabulary (ADR-MCPS-035).
//!
//! The audit layer emits security evidence for the verdicts MCP-S Core reaches.
//! Its **rejection reasons are derived from the frozen `McpsError::wire_code()`
//! taxonomy** ([`crate::error`] is the sole authority): a rejection event carries
//! the EXACT `mcps.*` wire token as its `reason`, never a parallel sub-name. The
//! only net-new surface is the pair of success/lifecycle events the error enum
//! cannot express (`mcps.request.accepted`, `mcps.response.signed`).
//!
//! This keeps the audit layer inside the same bind-not-interpret boundary as the
//! rest of Core: there is no `authorization_hash_mismatch` audit reason, because
//! "mismatch" would imply Core semantically compared the authorization artifact —
//! which is the configured AuthorizationProfile's job (ADR-MCPS-013), not Core's.
//!
//! **Non-goal:** this vocabulary is NOT a full SIEM schema and does not replace
//! deployment audit policy. It fixes only the stable machine tokens; the optional
//! [`reason_label`](AuditEvent::reason_label) is non-normative display text.
//!
//! A CI drift guard (`//mcps-conformance:audit_vocabulary_guard_test`,
//! ADR-MCPS-035/036) asserts every rejection `reason` this module can emit is a
//! member of `McpsError::wire_code()`, and that the success set is exactly the
//! two-item allowlist below.

use crate::error::McpsError;

/// The fixed `event_type` of every MCP-S audit event. Rejections reuse two of
/// these; the two success events are the only net-new tokens (the error enum
/// cannot express a success/lifecycle outcome).
pub mod event_type {
    /// A request envelope passed verification (net-new success/lifecycle event).
    pub const REQUEST_ACCEPTED: &str = "mcps.request.accepted";
    /// A response was signed after the request verified (net-new success event).
    pub const RESPONSE_SIGNED: &str = "mcps.response.signed";
    /// A request was rejected; `reason` is the exact `McpsError::wire_code()`.
    pub const REQUEST_REJECTED: &str = "mcps.request.rejected";
    /// A response was rejected; `reason` is the exact `McpsError::wire_code()`.
    pub const RESPONSE_REJECTED: &str = "mcps.response.rejected";
}

/// The exact, exhaustive success/lifecycle allowlist (ADR-MCPS-035 §3). These
/// are the ONLY audit events the frozen error taxonomy cannot express; no third
/// success event may be minted without an ADR. The drift guard pins this set.
pub const SUCCESS_EVENT_TYPES: &[&str] =
    &[event_type::REQUEST_ACCEPTED, event_type::RESPONSE_SIGNED];

/// The rejection `event_type` allowlist. Both carry an `McpsError::wire_code()`
/// token in `reason`; neither mints a rejection sub-name (no
/// `mcps.request.rejected.bad_signature`, no `…authorization_hash_mismatch`).
pub const REJECTION_EVENT_TYPES: &[&str] =
    &[event_type::REQUEST_REJECTED, event_type::RESPONSE_REJECTED];

/// The frozen rejection reason for an `McpsError` — its EXACT `wire_code()`.
///
/// This is the single point that maps a Core verdict to an audit `reason`. It is
/// `wire_code()` verbatim: no rename, no sub-name, no interpretation. A new
/// rejection outcome therefore requires a new `McpsError` variant first (the
/// frozen-taxonomy process), which the audit layer then inherits automatically.
pub fn rejection_reason(error: &McpsError) -> &'static str {
    error.wire_code()
}

/// A non-normative, human-readable label for an `McpsError`, suitable for the
/// optional [`AuditEvent::reason_label`] display field. SIEM readability only —
/// the stable machine token is always [`rejection_reason`]; this MUST NOT be
/// parsed. Provided as a convenience so consumers need not maintain their own
/// map; absence of a label is always acceptable.
pub fn reason_label(error: &McpsError) -> &'static str {
    match error {
        McpsError::MissingEnvelope => "Missing MCP-S envelope",
        McpsError::UnsupportedVersion => "Unsupported envelope version",
        McpsError::InvalidSignature => "Invalid signature",
        McpsError::CanonicalizationFailed => "Canonicalization failed",
        McpsError::ExpiredRequest => "Expired request",
        McpsError::ReplayDetected => "Replay detected",
        McpsError::InvalidAudience => "Invalid audience",
        McpsError::ActorBindingFailed => "Signer trust binding failed",
        McpsError::TransportBindingFailed => "Transport binding failed",
        McpsError::AuthorizationHashMissing => "Authorization hash missing",
        McpsError::OnBehalfOfMissing => "on_behalf_of missing",
        McpsError::OnBehalfOfInvalidFormat => "on_behalf_of malformed",
        McpsError::ResponseSigInvalid => "Invalid response signature",
        McpsError::ResponseHashMismatch => "Response/request hash mismatch",
        McpsError::DowngradeForbidden => "Security downgrade forbidden",
        McpsError::BatchForbidden => "JSON-RPC batch forbidden",
        McpsError::NotificationForbidden => "Security notification forbidden",
        McpsError::UnknownEnvelopeField => "Unknown envelope field",
        McpsError::TrustResolverUnavailable => "Trust resolver unavailable",
        McpsError::ReplayCacheUnavailable => "Replay cache unavailable",
        // Draft-02 (v0.6) — ADR-MCPS-040 / decision F.1.
        McpsError::CanonicalizationIdMissing => "canonicalization_id missing",
        McpsError::CanonicalizationIdUnknown => "canonicalization_id unknown",
        McpsError::CanonicalizationIdNotAllowed => "canonicalization_id not allowed by profile",
        McpsError::CanonicalizationIdMismatch => "canonicalization_id mismatch",
        McpsError::AuthorizationBindingMissing => "authorization_binding missing",
        McpsError::AuthorizationBindingTypeUnsupported => "authorization_binding type unsupported",
        McpsError::AuthorizationBindingMalformed => "authorization_binding malformed",
        McpsError::AuthorizationBindingProfileRequired => "authorization_binding profile required",
        McpsError::AuthorizationBindingAmbiguousBytes => "authorization_binding ambiguous bytes",
    }
}

/// A minimal MCP-S audit event. The fields mirror ADR-MCPS-035 §6 (the kept seed
/// §5.8 fields). Only `event_type` and `decision` are always present; the rest are
/// optional context populated by the emit site. `reason` is set ONLY on rejection
/// events and is always an `McpsError::wire_code()` token.
///
/// This is a deliberately small value type, not a SIEM record: emit sites map it
/// to whatever sink they use. Core itself does not perform I/O (ADR-MCPS-011/012),
/// so this type only *describes* an event; transport/host layers serialize it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// One of [`SUCCESS_EVENT_TYPES`] or [`REJECTION_EVENT_TYPES`].
    pub event_type: &'static str,
    /// `accepted`/`signed` for success, `rejected` for rejection.
    pub decision: Decision,
    /// Frozen `McpsError::wire_code()` token; `None` for success events.
    pub reason: Option<&'static str>,
    /// Optional non-normative display label; never parsed.
    pub reason_label: Option<&'static str>,
}

/// The decision an audit event records. Success events are accept/sign; rejection
/// events are reject. There is no "mismatch" or other interpreted verdict here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Request passed verification (`mcps.request.accepted`).
    Accepted,
    /// Response was signed (`mcps.response.signed`).
    Signed,
    /// Request or response was rejected (`reason` carries the wire_code).
    Rejected,
}

impl AuditEvent {
    /// A `mcps.request.accepted` success event.
    pub fn request_accepted() -> Self {
        AuditEvent {
            event_type: event_type::REQUEST_ACCEPTED,
            decision: Decision::Accepted,
            reason: None,
            reason_label: None,
        }
    }

    /// A `mcps.response.signed` success event.
    pub fn response_signed() -> Self {
        AuditEvent {
            event_type: event_type::RESPONSE_SIGNED,
            decision: Decision::Signed,
            reason: None,
            reason_label: None,
        }
    }

    /// A `mcps.request.rejected` event whose `reason` is `error.wire_code()`.
    pub fn request_rejected(error: &McpsError) -> Self {
        AuditEvent {
            event_type: event_type::REQUEST_REJECTED,
            decision: Decision::Rejected,
            reason: Some(rejection_reason(error)),
            reason_label: Some(reason_label(error)),
        }
    }

    /// A `mcps.response.rejected` event whose `reason` is `error.wire_code()`.
    pub fn response_rejected(error: &McpsError) -> Self {
        AuditEvent {
            event_type: event_type::RESPONSE_REJECTED,
            decision: Decision::Rejected,
            reason: Some(rejection_reason(error)),
            reason_label: Some(reason_label(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rejection event's `reason` is the EXACT frozen wire token — never a
    /// minted sub-name and never an interpreted "mismatch".
    #[test]
    fn rejection_reason_is_exact_wire_code() {
        for err in [
            McpsError::InvalidSignature,
            McpsError::ExpiredRequest,
            McpsError::ReplayDetected,
            McpsError::ActorBindingFailed,
            McpsError::AuthorizationHashMissing,
        ] {
            let ev = AuditEvent::request_rejected(&err);
            assert_eq!(ev.reason, Some(err.wire_code()));
            assert_eq!(ev.event_type, "mcps.request.rejected");
            assert_eq!(ev.decision, Decision::Rejected);
            // No interpreted sub-name leaked into the token.
            assert!(!ev.reason.unwrap().contains("mismatch") || err == McpsError::ResponseHashMismatch);
        }
    }

    /// The success set is exactly the two-item allowlist; success events never
    /// carry a `reason`.
    #[test]
    fn success_events_are_the_two_item_allowlist() {
        assert_eq!(
            SUCCESS_EVENT_TYPES,
            &["mcps.request.accepted", "mcps.response.signed"]
        );
        assert_eq!(AuditEvent::request_accepted().reason, None);
        assert_eq!(AuditEvent::response_signed().reason, None);
    }

    /// There is no `authorization_hash_mismatch` audit reason: Core binds, never
    /// interprets the authorization artifact (ADR-MCPS-013).
    #[test]
    fn no_authorization_hash_mismatch_audit_reason() {
        for err in [
            McpsError::AuthorizationHashMissing,
            McpsError::ActorBindingFailed,
        ] {
            let reason = rejection_reason(&err);
            assert_ne!(reason, "mcps.authorization_hash_mismatch");
            assert_ne!(reason, "authorization_hash_mismatch");
        }
    }
}

