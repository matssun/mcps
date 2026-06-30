//! Local enforcement-mode policy engine (MCPS-42, #189; ADR-MCPS-043
//! §Enforcement modes; CONTEXT.md §Fallback failure taxonomy).
//!
//! This is the bright line that decides — after an MCP-S exchange has been
//! attempted on the remote leg — whether the client/proxy ACCEPTS the verified
//! result, FALLS BACK to legacy/plain MCP, or FAILS CLOSED. It is pure policy: it
//! consults only the local mode, the per-route legacy allowlist, and a
//! classification of the exchange outcome. It never reads anything off the wire as
//! authority and never performs a silent downgrade.
//!
//! # Two normative modes (opportunistic is NOT here)
//! Production has exactly two modes — [`EnforcementMode::RequireMcps`] (strict,
//! fail-closed) and [`EnforcementMode::AllowLegacyExplicit`] (migration; legacy
//! only where config permits). `opportunistic_mcps` is deliberately EXCLUDED from
//! this normative matrix (CONTEXT.md §Two normative client modes); it survives
//! only as a non-normative dev/test probe (MCPS-53, #200) that never changes a
//! trust decision.
//!
//! # The bright line (CONTEXT.md §Fallback failure taxonomy)
//! - **Absence** of MCP-S evidence ([`EvidenceOutcome::Absent`]) — a connection
//!   failure before any evidence, a plain/unsigned response, or an unsigned
//!   "unsupported" hint — MAY fall back, but ONLY under `allow_legacy_explicit`
//!   AND an explicit per-route legacy allowlist entry.
//! - **Bad / inconsistent / downgrade-shaped** evidence
//!   ([`EvidenceOutcome::Invalid`]) — invalid request/response signature,
//!   unexpected `server_signer`, missing/mismatched `authorization_binding`,
//!   replay/freshness failure, `request_hash` mismatch, unsupported/mismatched
//!   `version` or `canonicalization_id` — MUST fail closed in EVERY mode. Bad
//!   evidence NEVER falls back: an attacker cannot strip a signature into a
//!   "downgrade" by corrupting it, because corruption is bad evidence, not absence.
//!
//! [`classify_response_result`] enforces that line in code: only a literal absent
//! envelope ([`McpsError::MissingEnvelope`]) becomes [`EvidenceOutcome::Absent`];
//! every other verification error is [`EvidenceOutcome::Invalid`].

use mcps_core::McpsError;
use mcps_core::VerifiedResponse;

/// The two normative client enforcement modes (CONTEXT.md §Two normative client
/// modes). Deliberately a closed two-variant set — `opportunistic_mcps` is not a
/// normative mode and is not representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Strict: every call MUST present a verified MCP-S exchange. Absence and bad
    /// evidence both fail closed; the per-route legacy allowlist is ignored.
    RequireMcps,
    /// Migration: a verified MCP-S exchange is accepted; ABSENCE of evidence may
    /// fall back to legacy ONLY for routes explicitly legacy-allowlisted. Bad
    /// evidence still fails closed.
    AllowLegacyExplicit,
}

/// Why MCP-S evidence was ABSENT for an exchange — the fallback-eligible set
/// (CONTEXT.md §Fallback failure taxonomy). Absence is the ONLY class eligible to
/// fall back, and only under `allow_legacy_explicit` + an allowlisted route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsenceReason {
    /// The connection/transport failed BEFORE any MCP-S evidence was produced.
    TransportFailurePreEvidence,
    /// A plain-MCP / unsigned response with no MCP-S envelope at all.
    PlainUnsigned,
    /// An unsigned "I only support legacy / version X" hint. NOT trusted evidence
    /// — it is recorded as absence, never as proof, and never triggers a silent
    /// downgrade on its own.
    ExplicitUnsupportedHint,
}

/// The classified outcome of one attempted MCP-S exchange. The engine decides
/// purely from this plus the mode and the route's legacy allowlist flag.
#[derive(Debug, Clone)]
pub enum EvidenceOutcome {
    /// A signed MCP-S response verified successfully (MCPS-41).
    Verified(VerifiedResponse),
    /// No MCP-S evidence was present (the fallback-eligible absence set).
    Absent(AbsenceReason),
    /// MCP-S evidence was present but failed verification (bad/downgrade-shaped).
    /// Carries the frozen [`McpsError`] so the fail-closed reason is exact.
    Invalid(McpsError),
}

/// The enforcement verdict for one exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementDecision {
    /// The verified MCP-S exchange satisfies policy — proceed with its result.
    AcceptMcps,
    /// Fall back to legacy/plain MCP for this route. The caller MUST audit this as
    /// a legacy / no-runtime-evidence path; `reason` records why fallback was
    /// eligible.
    FallBackToLegacy { reason: AbsenceReason },
    /// Fail closed with the exact frozen wire reason (→ `McpsError::wire_code()`).
    FailClosed(McpsError),
}

/// Map an [`AbsenceReason`] to the frozen wire reason used when absence fails
/// closed (strict mode, or migration mode without an allowlist entry). Plain
/// absence is [`McpsError::MissingEnvelope`]; a connection failure or an unsigned
/// downgrade hint is a refused downgrade ([`McpsError::DowngradeForbidden`]) —
/// strict mode will not proceed in plaintext.
fn absence_fail_closed_code(reason: AbsenceReason) -> McpsError {
    match reason {
        AbsenceReason::PlainUnsigned => McpsError::MissingEnvelope,
        AbsenceReason::TransportFailurePreEvidence | AbsenceReason::ExplicitUnsupportedHint => {
            McpsError::DowngradeForbidden
        }
    }
}

/// Classify the result of [`crate::verify_signed_response`] into an
/// [`EvidenceOutcome`]. This is the in-code bright line: ONLY a literal absent
/// envelope ([`McpsError::MissingEnvelope`]) is treated as absence (fallback-
/// eligible); EVERY other verification error — bad signature, unexpected signer,
/// replay, freshness, request_hash/version/canonicalization mismatch — is
/// [`EvidenceOutcome::Invalid`] and can never be reclassified into a silent
/// downgrade.
pub fn classify_response_result(result: Result<VerifiedResponse, McpsError>) -> EvidenceOutcome {
    match result {
        Ok(verified) => EvidenceOutcome::Verified(verified),
        Err(McpsError::MissingEnvelope) => EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned),
        Err(other) => EvidenceOutcome::Invalid(other),
    }
}

/// Decide the enforcement verdict for one exchange.
///
/// `route_legacy_allowed` is whether THIS route/audience has an explicit legacy
/// allowlist entry; it is consulted ONLY in [`EnforcementMode::AllowLegacyExplicit`]
/// and ONLY for absence. The decision table:
///
/// | outcome \ mode      | RequireMcps            | AllowLegacyExplicit                    |
/// |---------------------|------------------------|----------------------------------------|
/// | Verified            | AcceptMcps             | AcceptMcps                             |
/// | Absent + allowed    | FailClosed             | FallBackToLegacy                       |
/// | Absent + !allowed   | FailClosed             | FailClosed                             |
/// | Invalid             | FailClosed             | FailClosed (bad evidence never falls)  |
pub fn decide(
    mode: EnforcementMode,
    route_legacy_allowed: bool,
    outcome: &EvidenceOutcome,
) -> EnforcementDecision {
    match outcome {
        // A verified exchange always satisfies policy.
        EvidenceOutcome::Verified(_) => EnforcementDecision::AcceptMcps,

        // Bad / downgrade-shaped evidence fails closed in EVERY mode — this is the
        // downgrade-resistance core. The allowlist is irrelevant: a corrupted or
        // inconsistent response is never an eligible "absence".
        EvidenceOutcome::Invalid(err) => EnforcementDecision::FailClosed(err.clone()),

        // Absence: fallback only under migration mode AND an allowlisted route.
        EvidenceOutcome::Absent(reason) => match mode {
            EnforcementMode::RequireMcps => {
                EnforcementDecision::FailClosed(absence_fail_closed_code(*reason))
            }
            EnforcementMode::AllowLegacyExplicit => {
                if route_legacy_allowed {
                    EnforcementDecision::FallBackToLegacy { reason: *reason }
                } else {
                    EnforcementDecision::FailClosed(absence_fail_closed_code(*reason))
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stand-in for every bad-evidence (downgrade-shaped) class. Each MUST fail
    // closed in BOTH modes regardless of the allowlist.
    const BAD_EVIDENCE: &[McpsError] = &[
        McpsError::InvalidSignature,
        McpsError::ResponseSigInvalid,
        McpsError::ActorBindingFailed, // unexpected server_signer
        McpsError::AuthorizationBindingMissing,
        McpsError::ReplayDetected,
        McpsError::ExpiredRequest,
        McpsError::ResponseHashMismatch,
        McpsError::UnsupportedVersion,
        McpsError::CanonicalizationIdMismatch,
        McpsError::CanonicalizationIdNotAllowed,
        McpsError::CanonicalizationIdUnknown,
        McpsError::DowngradeForbidden,
    ];

    const ABSENCE: &[AbsenceReason] = &[
        AbsenceReason::TransportFailurePreEvidence,
        AbsenceReason::PlainUnsigned,
        AbsenceReason::ExplicitUnsupportedHint,
    ];

    #[test]
    fn classify_only_missing_envelope_is_absence() {
        assert!(matches!(
            classify_response_result(Err(McpsError::MissingEnvelope)),
            EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned)
        ));
        // Every other error is bad evidence, never absence.
        for err in BAD_EVIDENCE {
            assert!(
                matches!(
                    classify_response_result(Err(err.clone())),
                    EvidenceOutcome::Invalid(_)
                ),
                "{err:?} must classify as Invalid, not Absent"
            );
        }
    }

    #[test]
    fn bad_evidence_fails_closed_in_both_modes_even_when_allowlisted() {
        for err in BAD_EVIDENCE {
            let outcome = EvidenceOutcome::Invalid(err.clone());
            for mode in [
                EnforcementMode::RequireMcps,
                EnforcementMode::AllowLegacyExplicit,
            ] {
                // Even with the route legacy-allowlisted, bad evidence never falls back.
                assert_eq!(
                    decide(mode, true, &outcome),
                    EnforcementDecision::FailClosed(err.clone()),
                    "{err:?} under {mode:?} (allowlisted) must fail closed"
                );
            }
        }
    }

    #[test]
    fn absence_fails_closed_under_require_mcps_regardless_of_allowlist() {
        for reason in ABSENCE {
            let outcome = EvidenceOutcome::Absent(*reason);
            for allowed in [true, false] {
                assert_eq!(
                    decide(EnforcementMode::RequireMcps, allowed, &outcome),
                    EnforcementDecision::FailClosed(absence_fail_closed_code(*reason)),
                    "absence {reason:?} under require_mcps must fail closed"
                );
            }
        }
    }

    #[test]
    fn absence_falls_back_only_with_allowlist_under_legacy_mode() {
        for reason in ABSENCE {
            let outcome = EvidenceOutcome::Absent(*reason);
            // Allowlisted route → fall back (and the reason is preserved for audit).
            assert_eq!(
                decide(EnforcementMode::AllowLegacyExplicit, true, &outcome),
                EnforcementDecision::FallBackToLegacy { reason: *reason }
            );
            // Not allowlisted → fail closed even in migration mode.
            assert_eq!(
                decide(EnforcementMode::AllowLegacyExplicit, false, &outcome),
                EnforcementDecision::FailClosed(absence_fail_closed_code(*reason))
            );
        }
    }

    #[test]
    fn every_fail_closed_reason_is_a_frozen_wire_code() {
        // The decision's fail-closed reason must always be expressible as a frozen
        // wire_code (the audit reason vocabulary) — drift guard for #195.
        for reason in ABSENCE {
            let code = absence_fail_closed_code(*reason);
            assert!(code.wire_code().starts_with("mcps."));
        }
    }
}
