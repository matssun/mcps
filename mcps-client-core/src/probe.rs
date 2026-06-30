//! Dev/test-ONLY opportunistic MCP-S support probe (MCPS-53, #200; ADR-MCPS-043
//! §Enforcement modes — opportunistic cut to a dev probe; CONTEXT.md §Two normative
//! client modes).
//!
//! `opportunistic_mcps` was CUT from the normative enforcement matrix (only
//! [`crate::EnforcementMode::RequireMcps`] and
//! [`crate::EnforcementMode::AllowLegacyExplicit`] are normative). It survives only
//! as this NON-NORMATIVE diagnostic: it records which servers were observed to
//! support MCP-S, as telemetry. It MUST NEVER change a trust decision or production
//! routing — it produces no [`crate::EnforcementDecision`] and is not an
//! `EnforcementMode` variant.
//!
//! Enforced boundary: this module is compiled ONLY under `cfg(test)` or the
//! explicit, non-default `dev-probe` feature, so it cannot link into a default
//! production build (mirroring `mcps-host`'s dev-fixture gating).

use crate::enforcement::EvidenceOutcome;
use std::collections::HashMap;

/// A single per-server support observation (telemetry only — never a verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportObservation {
    /// A verified MCP-S exchange was observed for this server.
    SupportsMcps,
    /// No MCP-S evidence was observed (absent or invalid — telemetry does not
    /// distinguish; it is not making a trust decision).
    NoMcpsEvidence,
}

/// A dev/test diagnostic that records observed MCP-S support per server. It has no
/// method that yields a trust decision or a route — by construction it cannot
/// affect enforcement.
#[derive(Debug, Default)]
pub struct OpportunisticProbe {
    observations: HashMap<String, SupportObservation>,
}

impl OpportunisticProbe {
    /// A fresh probe with no observations.
    pub fn new() -> Self {
        OpportunisticProbe::default()
    }

    /// Record what was observed for `server` from an exchange outcome. Telemetry
    /// only — this does not, and cannot, feed any enforcement path.
    pub fn record(&mut self, server: impl Into<String>, outcome: &EvidenceOutcome) {
        let observation = match outcome {
            EvidenceOutcome::Verified(_) => SupportObservation::SupportsMcps,
            EvidenceOutcome::Absent(_) | EvidenceOutcome::Invalid(_) => {
                SupportObservation::NoMcpsEvidence
            }
        };
        self.observations.insert(server.into(), observation);
    }

    /// The recorded observation for `server`, if any (telemetry query).
    pub fn observation(&self, server: &str) -> Option<SupportObservation> {
        self.observations.get(server).copied()
    }

    /// Telemetry convenience: whether `server` was observed to support MCP-S.
    pub fn supports_mcps(&self, server: &str) -> bool {
        self.observation(server) == Some(SupportObservation::SupportsMcps)
    }

    /// The number of servers observed.
    pub fn observed_count(&self) -> usize {
        self.observations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::{decide, AbsenceReason, EnforcementDecision, EnforcementMode};
    use mcps_core::McpsError;

    #[test]
    fn records_support_per_server() {
        let mut probe = OpportunisticProbe::new();
        probe.record(
            "server-absent",
            &EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned),
        );
        probe.record(
            "server-bad",
            &EvidenceOutcome::Invalid(McpsError::InvalidSignature),
        );
        assert_eq!(
            probe.observation("server-absent"),
            Some(SupportObservation::NoMcpsEvidence)
        );
        assert!(!probe.supports_mcps("server-bad"));
        assert_eq!(probe.observed_count(), 2);
        // Unobserved server -> None.
        assert_eq!(probe.observation("unknown"), None);
    }

    #[test]
    fn probe_never_changes_an_enforcement_decision() {
        // The enforcement verdict for a given (mode, allowlist, outcome) is the same
        // whether or not a probe recorded anything — the probe is not an input to
        // `decide`, so it cannot create a side effect on a trust decision.
        let outcome = EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned);
        let baseline = decide(EnforcementMode::RequireMcps, true, &outcome);

        let mut probe = OpportunisticProbe::new();
        probe.record("server-x", &outcome);
        // Recording observations does not alter the verdict.
        let after = decide(EnforcementMode::RequireMcps, true, &outcome);
        assert_eq!(baseline, after);
        assert_eq!(
            after,
            EnforcementDecision::FailClosed(McpsError::MissingEnvelope)
        );
    }
}
