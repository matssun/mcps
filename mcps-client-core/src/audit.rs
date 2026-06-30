//! Client-side error taxonomy & audit events (MCPS-48, #195; ADR-MCPS-044 §Error
//! taxonomy; ADR-MCPS-035 audit vocabulary; CONTEXT.md §Client error taxonomy).
//!
//! Two rules:
//!
//! 1. **No parallel wire taxonomy.** Every client-side protocol/security failure
//!    maps to a frozen `mcps-core` [`McpsError`] (→ `wire_code()`). Local exception
//!    classes (e.g. [`crate::CorrelationError`]) and UX hints are allowed, but each
//!    maps to a stable wire token at this boundary — there is no client-only
//!    `mcps.*` reason. [`audit_for_decision`] and
//!    [`crate::CorrelationError::to_mcps_error`] are the only mapping points.
//! 2. **Verified vs legacy paths are distinguished.** A [`ClientAuditEvent`] records
//!    whether the outcome came from a verified MCP-S exchange ([`ClientPath::McpsVerified`])
//!    or an explicit legacy fallback ([`ClientPath::LegacyExplicit`]) — so an
//!    auditor can tell a cryptographically-verified call from a config-permitted
//!    plaintext one. The legacy fallback is NOT minted as an `mcps.*` success token
//!    (that frozen set is exactly `accepted`/`signed`); it is a local lifecycle
//!    marker carrying the [`AbsenceReason`] that made fallback eligible.
//!
//! The rejection `reason` is always an `McpsError::wire_code()` token, reusing
//! `mcps-core`'s [`mcps_core::audit`] vocabulary; the drift-guard test pins that
//! every client failure resolves to a member of that frozen set.

use crate::enforcement::AbsenceReason;
use crate::enforcement::EnforcementDecision;
use mcps_core::McpsError;

/// Which path produced an outcome — the verified-vs-legacy distinction the audit
/// trail must preserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPath {
    /// A verified MCP-S exchange (request signed, response verified).
    McpsVerified,
    /// An explicit, config-permitted legacy/plaintext fallback (no runtime evidence).
    LegacyExplicit,
}

/// The lifecycle outcome an audit event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOutcome {
    /// A verified MCP-S exchange was accepted.
    Accepted,
    /// The call fell back to legacy/plaintext (audited as no-runtime-evidence).
    FellBackToLegacy,
    /// The call was rejected (fail closed); `reason` carries the wire token.
    Rejected,
}

/// A client-side audit event. `reason` is set ONLY on [`ClientOutcome::Rejected`]
/// and is always a frozen `McpsError::wire_code()` token. `legacy_reason` is set
/// ONLY on [`ClientOutcome::FellBackToLegacy`] and is local, non-wire context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuditEvent {
    /// Verified MCP-S vs explicit legacy.
    pub path: ClientPath,
    /// Accepted / fell-back / rejected.
    pub outcome: ClientOutcome,
    /// Frozen `McpsError::wire_code()` token on rejection; `None` otherwise.
    pub reason: Option<&'static str>,
    /// The absence reason that made a legacy fallback eligible (local, non-wire).
    pub legacy_reason: Option<AbsenceReason>,
}

impl ClientAuditEvent {
    /// A verified MCP-S exchange was accepted.
    pub fn accepted_mcps() -> Self {
        ClientAuditEvent {
            path: ClientPath::McpsVerified,
            outcome: ClientOutcome::Accepted,
            reason: None,
            legacy_reason: None,
        }
    }

    /// An explicit legacy fallback occurred (marked no-runtime-evidence).
    pub fn fell_back_to_legacy(reason: AbsenceReason) -> Self {
        ClientAuditEvent {
            path: ClientPath::LegacyExplicit,
            outcome: ClientOutcome::FellBackToLegacy,
            reason: None,
            legacy_reason: Some(reason),
        }
    }

    /// A fail-closed rejection on the MCP-S path; `reason` is `error.wire_code()`.
    pub fn rejected(error: &McpsError) -> Self {
        ClientAuditEvent {
            path: ClientPath::McpsVerified,
            outcome: ClientOutcome::Rejected,
            reason: Some(error.wire_code()),
            legacy_reason: None,
        }
    }

    /// The non-normative human label for the rejection reason (display only; never
    /// parsed). Reuses `mcps-core`'s label map.
    pub fn reason_label(error: &McpsError) -> &'static str {
        mcps_core::audit::reason_label(error)
    }
}

/// Build the audit event for an [`EnforcementDecision`] (MCPS-42). This is the
/// single boundary translating a policy verdict into audit evidence, so the
/// verified/legacy distinction and the wire-token reason are always consistent.
pub fn audit_for_decision(decision: &EnforcementDecision) -> ClientAuditEvent {
    match decision {
        EnforcementDecision::AcceptMcps => ClientAuditEvent::accepted_mcps(),
        EnforcementDecision::FallBackToLegacy { reason } => {
            ClientAuditEvent::fell_back_to_legacy(*reason)
        }
        EnforcementDecision::FailClosed(error) => ClientAuditEvent::rejected(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::CorrelationError;

    /// Every CorrelationError maps to a frozen wire token (no parallel taxonomy).
    const ALL_CORRELATION_ERRORS: &[CorrelationError] = &[
        CorrelationError::DuplicateCorrelationId,
        CorrelationError::NonceReuse,
        CorrelationError::Uncorrelatable,
        CorrelationError::Expired,
    ];

    #[test]
    fn correlation_errors_map_to_frozen_wire_codes() {
        for err in ALL_CORRELATION_ERRORS {
            let wire = err.to_mcps_error().wire_code();
            assert!(
                wire.starts_with("mcps."),
                "{err:?} -> non-mcps reason {wire}"
            );
            // The mapped reason is a real audit rejection reason (round-trips through
            // mcps-core's vocabulary — proof it is a member of wire_code()).
            let mapped = err.to_mcps_error();
            assert_eq!(mcps_core::audit::rejection_reason(&mapped), wire);
        }
    }

    #[test]
    fn drift_guard_every_rejection_reason_is_a_wire_code() {
        // The audit layer can only produce a rejection reason via an McpsError, so a
        // rejection reason is structurally always a frozen wire_code. Pin it for a
        // representative spread, including the canon/authz draft-02 codes the client
        // can emit.
        for err in [
            McpsError::InvalidSignature,
            McpsError::ResponseSigInvalid,
            McpsError::ActorBindingFailed,
            McpsError::ResponseHashMismatch,
            McpsError::ReplayDetected,
            McpsError::ExpiredRequest,
            McpsError::DowngradeForbidden,
            McpsError::MissingEnvelope,
            McpsError::CanonicalizationIdNotAllowed,
            McpsError::AuthorizationBindingMissing,
        ] {
            let ev = ClientAuditEvent::rejected(&err);
            assert_eq!(ev.reason, Some(err.wire_code()));
            assert_eq!(ev.outcome, ClientOutcome::Rejected);
            assert_eq!(ev.path, ClientPath::McpsVerified);
            assert!(ev.reason.unwrap().starts_with("mcps."));
        }
    }

    #[test]
    fn decision_accept_audits_as_verified() {
        let ev = audit_for_decision(&EnforcementDecision::AcceptMcps);
        assert_eq!(ev.path, ClientPath::McpsVerified);
        assert_eq!(ev.outcome, ClientOutcome::Accepted);
        assert_eq!(ev.reason, None);
    }

    #[test]
    fn decision_fallback_audits_as_legacy_with_reason() {
        let ev = audit_for_decision(&EnforcementDecision::FallBackToLegacy {
            reason: AbsenceReason::PlainUnsigned,
        });
        assert_eq!(ev.path, ClientPath::LegacyExplicit);
        assert_eq!(ev.outcome, ClientOutcome::FellBackToLegacy);
        // The legacy path never claims an mcps.* success reason.
        assert_eq!(ev.reason, None);
        assert_eq!(ev.legacy_reason, Some(AbsenceReason::PlainUnsigned));
    }

    #[test]
    fn decision_fail_closed_audits_with_wire_reason() {
        let ev = audit_for_decision(&EnforcementDecision::FailClosed(
            McpsError::InvalidSignature,
        ));
        assert_eq!(ev.outcome, ClientOutcome::Rejected);
        assert_eq!(ev.reason, Some("mcps.invalid_signature"));
    }

    #[test]
    fn verified_and_legacy_paths_are_distinguishable() {
        let verified = ClientAuditEvent::accepted_mcps();
        let legacy =
            ClientAuditEvent::fell_back_to_legacy(AbsenceReason::TransportFailurePreEvidence);
        assert_ne!(verified.path, legacy.path);
    }
}
