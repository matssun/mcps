//! Declared replay-store durability tier (ADR-MCPS-020).
//!
//! ADR-MCPS-020 specifies horizontal replay safety as a **durability contract on
//! the shared [`AtomicReplayStore`](crate::AtomicReplayStore) abstraction**, not
//! as a property of any one backend. The strength of the v0.3 replay claim is a
//! function of the **declared durability tier**, which is a *deployment
//! assertion*: the same backend implementation may be deployed at different tiers
//! depending on topology (a Redis adapter can run async, `WAIT`-quorum, or
//! single-store fail-closed).
//!
//! This module defines the tier as a first-class value with the **semantic
//! names** operators quote (never bare letters) and the **honest one-line
//! guarantee** each tier supports. The proxy surfaces the tier's own
//! [`guarantee`](ReplayDurabilityTier::guarantee) string; it MUST NOT emit a
//! claim stronger than its configured tier (the "tier-claim ceiling" — a proxy
//! that surfaces a tier's own guarantee, rather than a hardcoded stronger one,
//! cannot over-claim by construction).
//!
//! No total order is imposed across tiers: ADR-MCPS-020 deliberately names tiers
//! semantically so a reader does not misjudge which posture is stronger.
//! `SINGLE_STORE_FAIL_CLOSED` is "strong only under its fail-closed invariant",
//! which is a *different* failure profile from `REDIS_WAIT_QUORUM`, not a point on
//! one line. The only ordering this module asserts is the explicit, documented
//! **strict-production minimum** ([`meets_strict_production_minimum`]).
//!
//! [`meets_strict_production_minimum`]: ReplayDurabilityTier::meets_strict_production_minimum

/// The declared durability tier of a shared replay store (ADR-MCPS-020).
///
/// A **deployment assertion**: the proxy verifies the behavior it controls (e.g.
/// issuing `WAIT` and failing closed on insufficient acks) and surfaces the tier,
/// but it cannot independently prove every external store-topology property
/// (whether Sentinel/Cluster failover is enabled, whether ops fail closed after a
/// restart). The tier is verified as far as backend configuration allows and
/// asserted by the operator for the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDurabilityTier {
    /// Async Redis replication + failover (vanilla Sentinel/Cluster). Replay-safe
    /// in steady state; a failover or restart-with-state-loss may reopen a replay
    /// window bounded by the freshness window. Cheap, standard ops.
    RedisAsyncBounded,

    /// Redis `SET NX` + `WAIT <quorum> <timeout>`. Materially reduces failover
    /// replay risk; a `WAIT` timeout or insufficient acks fail closed. **Not**
    /// linearizable / not unconditional. Per-call latency cost.
    RedisWaitQuorum {
        /// Replica acknowledgements required before the insert is considered
        /// durable (the `numreplicas` argument to Redis `WAIT`).
        quorum: u32,
        /// Bound on how long the proxy waits for those acknowledgements before
        /// failing closed (the `timeout` argument to Redis `WAIT`, milliseconds).
        timeout_ms: u64,
    },

    /// A CP / linearizable store (etcd txn put-if-absent-under-lease, Consul, ZK,
    /// serializable SQL + unique key, FoundationDB). The strongest horizontal
    /// replay-safety claim, *conditional* on the store's documented durable
    /// linearizable write guarantee and correct MCP-S freshness enforcement.
    Linearizable,

    /// A single store with no failover. Strong **only** under the fail-closed
    /// invariant: all verifier instances reject protected requests whenever the
    /// store is unavailable or may have restarted from lost state, until the
    /// freshness window has elapsed since the last possible accepted write.
    SingleStoreFailClosed,
}

impl ReplayDurabilityTier {
    /// Parse an operator-supplied `--replay-durability-tier` value into a tier.
    ///
    /// Accepted forms (case-insensitive):
    /// - `redis-async`
    /// - `redis-wait-quorum:<quorum>:<timeout_ms>` (e.g. `redis-wait-quorum:2:500`)
    /// - `linearizable`
    /// - `single-store-fail-closed`
    ///
    /// Returns a human-readable error string (no panics) so the CLI can fail
    /// closed with a precise message.
    pub fn parse(value: &str) -> Result<ReplayDurabilityTier, String> {
        let lower = value.trim().to_lowercase();
        match lower.as_str() {
            "redis-async" => Ok(ReplayDurabilityTier::RedisAsyncBounded),
            "linearizable" => Ok(ReplayDurabilityTier::Linearizable),
            "single-store-fail-closed" => Ok(ReplayDurabilityTier::SingleStoreFailClosed),
            other => {
                let rest = other.strip_prefix("redis-wait-quorum").ok_or_else(|| {
                    format!(
                        "unknown replay durability tier '{value}' (expected redis-async | \
                         redis-wait-quorum:<quorum>:<timeout_ms> | linearizable | \
                         single-store-fail-closed)"
                    )
                })?;
                let mut parts = rest.split(':');
                // After the prefix the first split element is the empty string
                // before the first ':'.
                if parts.next() != Some("") {
                    return Err(format!(
                        "redis-wait-quorum requires ':<quorum>:<timeout_ms>' (got '{value}')"
                    ));
                }
                let quorum = parts
                    .next()
                    .and_then(|q| q.parse::<u32>().ok())
                    .filter(|q| *q >= 1)
                    .ok_or_else(|| {
                        format!("redis-wait-quorum quorum must be a positive integer (in '{value}')")
                    })?;
                let timeout_ms = parts
                    .next()
                    .and_then(|t| t.parse::<u64>().ok())
                    .filter(|t| *t >= 1)
                    .ok_or_else(|| {
                        format!(
                            "redis-wait-quorum timeout_ms must be a positive integer (in '{value}')"
                        )
                    })?;
                if parts.next().is_some() {
                    return Err(format!(
                        "redis-wait-quorum takes exactly ':<quorum>:<timeout_ms>' (got '{value}')"
                    ));
                }
                Ok(ReplayDurabilityTier::RedisWaitQuorum { quorum, timeout_ms })
            }
        }
    }

    /// The semantic wire name operators quote (ADR-MCPS-020). Stable, uppercase,
    /// backend-agnostic — used in config, startup logs, and audit records.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ReplayDurabilityTier::RedisAsyncBounded => "REDIS_ASYNC",
            ReplayDurabilityTier::RedisWaitQuorum { .. } => "REDIS_WAIT_QUORUM",
            ReplayDurabilityTier::Linearizable => "LINEARIZABLE",
            ReplayDurabilityTier::SingleStoreFailClosed => "SINGLE_STORE_FAIL_CLOSED",
        }
    }

    /// The honest one-line guarantee this tier supports (ADR-MCPS-020 table). The
    /// proxy surfaces THIS string as its replay claim; because it is the tier's
    /// own guarantee — never a hardcoded stronger one — the proxy cannot
    /// over-claim (the tier-claim ceiling). No tier's guarantee is described as
    /// "unconditional".
    pub fn guarantee(&self) -> &'static str {
        match self {
            ReplayDurabilityTier::RedisAsyncBounded => {
                "replay-safe in steady state; a failover or restart-with-state-loss \
                 may reopen a replay window bounded by the freshness window"
            }
            ReplayDurabilityTier::RedisWaitQuorum { .. } => {
                "materially reduced failover replay risk; WAIT timeout or insufficient \
                 acks fail closed; not linearizable / not unconditional"
            }
            ReplayDurabilityTier::Linearizable => {
                "strongest horizontal replay-safety claim, conditional on the store's \
                 durable linearizable write contract and correct freshness enforcement"
            }
            ReplayDurabilityTier::SingleStoreFailClosed => {
                "strong only under the fail-closed invariant: the fleet rejects \
                 protected requests on store unavailability or possible state loss \
                 until the freshness window elapses"
            }
        }
    }

    /// The structured startup/audit line ADR-MCPS-020 requires the proxy to log
    /// for the configured replay store: the backend label, the declared tier wire
    /// name, and the honest surfaced guarantee. Carries NO nonce material (nonces
    /// are sensitive correlation data); `backend` is an operator-facing label such
    /// as `"redis"`, `"etcd"`, or `"in-memory"`.
    pub fn startup_audit_line(&self, backend: &str) -> String {
        format!(
            "replay-store backend={backend} tier={} guarantee=\"{}\"",
            self.wire_name(),
            self.guarantee()
        )
    }

    /// Whether this tier meets the strict-production minimum of ADR-MCPS-020's
    /// second open question: a strict/production deployment refuses to start
    /// unless the declared tier is `REDIS_WAIT_QUORUM` or stronger.
    ///
    /// `REDIS_WAIT_QUORUM` and `LINEARIZABLE` meet it; `REDIS_ASYNC` (bounded
    /// failover caveat) and `SINGLE_STORE_FAIL_CLOSED` (single point of
    /// availability failure) do not. This is the ONLY ordering this type asserts,
    /// and it is an explicit deployment-policy threshold, not a general "tier X is
    /// stronger than tier Y" claim.
    pub fn meets_strict_production_minimum(&self) -> bool {
        matches!(
            self,
            ReplayDurabilityTier::RedisWaitQuorum { .. } | ReplayDurabilityTier::Linearizable
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayDurabilityTier;

    fn all_tiers() -> Vec<ReplayDurabilityTier> {
        vec![
            ReplayDurabilityTier::RedisAsyncBounded,
            ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 1,
                timeout_ms: 200,
            },
            ReplayDurabilityTier::Linearizable,
            ReplayDurabilityTier::SingleStoreFailClosed,
        ]
    }

    #[test]
    fn parse_round_trips_the_simple_tiers() {
        assert_eq!(
            ReplayDurabilityTier::parse("redis-async"),
            Ok(ReplayDurabilityTier::RedisAsyncBounded)
        );
        assert_eq!(
            ReplayDurabilityTier::parse("LINEARIZABLE"),
            Ok(ReplayDurabilityTier::Linearizable)
        );
        assert_eq!(
            ReplayDurabilityTier::parse("  single-store-fail-closed  "),
            Ok(ReplayDurabilityTier::SingleStoreFailClosed)
        );
    }

    #[test]
    fn parse_wait_quorum_extracts_quorum_and_timeout() {
        assert_eq!(
            ReplayDurabilityTier::parse("redis-wait-quorum:2:500"),
            Ok(ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 2,
                timeout_ms: 500
            })
        );
    }

    #[test]
    fn parse_rejects_unknown_and_malformed() {
        assert!(ReplayDurabilityTier::parse("cluster").is_err());
        assert!(ReplayDurabilityTier::parse("redis-wait-quorum").is_err());
        assert!(ReplayDurabilityTier::parse("redis-wait-quorum:0:500").is_err());
        assert!(ReplayDurabilityTier::parse("redis-wait-quorum:2:0").is_err());
        assert!(ReplayDurabilityTier::parse("redis-wait-quorum:2:500:9").is_err());
        assert!(ReplayDurabilityTier::parse("redis-wait-quorum:two:500").is_err());
    }

    #[test]
    fn wire_names_are_the_semantic_adr_names() {
        assert_eq!(
            ReplayDurabilityTier::RedisAsyncBounded.wire_name(),
            "REDIS_ASYNC"
        );
        assert_eq!(
            ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 2,
                timeout_ms: 500
            }
            .wire_name(),
            "REDIS_WAIT_QUORUM"
        );
        assert_eq!(
            ReplayDurabilityTier::Linearizable.wire_name(),
            "LINEARIZABLE"
        );
        assert_eq!(
            ReplayDurabilityTier::SingleStoreFailClosed.wire_name(),
            "SINGLE_STORE_FAIL_CLOSED"
        );
    }

    #[test]
    fn every_tier_has_a_nonempty_guarantee() {
        for tier in all_tiers() {
            assert!(
                !tier.guarantee().is_empty(),
                "{} must carry an honest guarantee string",
                tier.wire_name()
            );
        }
    }

    #[test]
    fn no_tier_claims_unconditional() {
        // ADR-MCPS-020: no tier's guarantee may be described as "unconditional".
        for tier in all_tiers() {
            assert!(
                !tier.guarantee().to_lowercase().contains("unconditional")
                    || tier.guarantee().contains("not unconditional"),
                "{} must not make an unconditional claim",
                tier.wire_name()
            );
        }
    }

    #[test]
    fn tier_claim_ceiling_async_is_not_linearizable() {
        // The tier-claim ceiling: a REDIS_ASYNC deployment's surfaced guarantee is
        // its own bounded-window claim, never the LINEARIZABLE one.
        assert_ne!(
            ReplayDurabilityTier::RedisAsyncBounded.guarantee(),
            ReplayDurabilityTier::Linearizable.guarantee()
        );
        assert!(ReplayDurabilityTier::RedisAsyncBounded
            .guarantee()
            .contains("bounded by the freshness window"));
    }

    #[test]
    fn startup_audit_line_carries_backend_tier_and_guarantee_no_nonce() {
        let line = ReplayDurabilityTier::RedisWaitQuorum {
            quorum: 2,
            timeout_ms: 500,
        }
        .startup_audit_line("redis");
        assert!(line.contains("backend=redis"));
        assert!(line.contains("tier=REDIS_WAIT_QUORUM"));
        assert!(line.contains("guarantee="));
        // No nonce/correlation material may leak into the startup line.
        assert!(!line.to_lowercase().contains("nonce"));
    }

    #[test]
    fn strict_production_minimum_is_wait_quorum_or_stronger() {
        assert!(ReplayDurabilityTier::RedisWaitQuorum {
            quorum: 1,
            timeout_ms: 100
        }
        .meets_strict_production_minimum());
        assert!(ReplayDurabilityTier::Linearizable.meets_strict_production_minimum());
        // Weaker tiers do NOT meet the strict-production minimum.
        assert!(!ReplayDurabilityTier::RedisAsyncBounded.meets_strict_production_minimum());
        assert!(!ReplayDurabilityTier::SingleStoreFailClosed.meets_strict_production_minimum());
    }
}
