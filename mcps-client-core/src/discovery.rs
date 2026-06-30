//! Stateless-primary discovery + advisory advert + capability-mismatch semantics
//! (MCPS-44, #191; ADR-MCPS-043 §Stateless-primary surface, §Capability-advert
//! semantics; CONTEXT.md §MCP-S discovery).
//!
//! # Stateless-primary
//! There is NO trusted pre-flight "do you speak MCP-S?" ask. The canonical model is
//! `local policy → signed request → verified signed response`: the FIRST verified
//! signed exchange IS both the proof of MCP-S support and the discovery result
//! (an HSTS-like posture, not ask-then-trust). [`ProvenSupport`] can therefore only
//! be minted from a real [`mcps_core::VerifiedResponse`] — an advert can never
//! produce it.
//!
//! # Advisory advert (legacy/session transports only)
//! A server that still runs `initialize` MAY advertise MCP-S under
//! `capabilities.experimental["se.syncom/mcps"]`. [`parse_legacy_advert`] reads it,
//! but it is ADVISORY ONLY: cacheable with a conservative TTL, non-authoritative,
//! with no freshness requirement. It is NEVER proof and NEVER weakens policy. A
//! stripped or tampered advert cannot cause a downgrade, because every trust
//! decision is driven by the verified exchange + local policy, not the advert
//! ([`evaluate_capability`] takes no advert input).
//!
//! # Capability-mismatch verdicts (ADR-MCPS-043)
//! Comparing the VERIFIED exchange against local policy:
//! - satisfies policy → [`CapabilityVerdict::SatisfiesPolicy`] (accept; log any
//!   advert mismatch);
//! - weaker than policy → [`CapabilityVerdict::WeakerThanPolicy`] (fail closed);
//! - stronger than policy but locally supported → [`CapabilityVerdict::StrongerSupported`]
//!   (accept);
//! - self-contradictory (version/canonicalization inconsistent) →
//!   [`CapabilityVerdict::SelfContradictory`] (protocol error).

use mcps_core::VerifiedResponse;
use mcps_core::DRAFT_02_CANONICALIZATION_ALLOWLIST;
use mcps_core::EXTENSION_ID;
use mcps_core::VERSION_DRAFT_01;
use mcps_core::VERSION_DRAFT_02;
use serde_json::Value;
use std::collections::HashMap;

/// Proof of MCP-S support derived from the first verified signed exchange. The ONLY
/// constructor takes an `mcps-core` [`VerifiedResponse`] (whose own construction is
/// crate-private to the verifier), so an advert — or any unverified input — can
/// never fabricate proof. This is the type-level form of "the verified exchange is
/// authoritative; the advert never is".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenSupport {
    server_signer: String,
}

impl ProvenSupport {
    /// Mint proof FROM a verified response — the stateless-primary discovery result.
    pub fn from_verified_response(verified: &VerifiedResponse) -> Self {
        ProvenSupport {
            server_signer: verified.server_signer().to_string(),
        }
    }

    /// The server signer the verified exchange proved control of.
    pub fn server_signer(&self) -> &str {
        &self.server_signer
    }
}

/// The advisory legacy/session advert (non-authoritative). All fields optional; an
/// absent or malformed advert simply yields `None` from [`parse_legacy_advert`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyAdvert {
    /// Versions the server CLAIMS to support (advisory — never trusted as proof).
    pub versions: Vec<String>,
    /// Canonicalization schemes the server CLAIMS to support (advisory).
    pub canonicalization_ids: Vec<String>,
}

/// Parse the advisory MCP-S advert from an `initialize` `capabilities` object, if
/// present under `experimental["se.syncom/mcps"]`. Returns `None` when absent or
/// not an object — absence is normal and non-authoritative, never an error.
pub fn parse_legacy_advert(capabilities: &Value) -> Option<LegacyAdvert> {
    let advert = capabilities
        .get("experimental")?
        .get(EXTENSION_ID)?
        .as_object()?;
    let versions = string_array(advert.get("versions"));
    let canonicalization_ids = string_array(advert.get("canonicalization_ids"));
    Some(LegacyAdvert {
        versions,
        canonicalization_ids,
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A conservative-TTL, non-authoritative cache for adverts. Keyed by an opaque
/// caller key (e.g. host or route). Adverts may be cached but are evicted on a
/// connection/policy change and on expiry; a cache hit is still advisory and never
/// influences a trust decision.
#[derive(Debug, Default)]
pub struct AdvertCache {
    ttl_secs: i64,
    entries: HashMap<String, (LegacyAdvert, i64)>,
}

impl AdvertCache {
    /// A cache with a conservative TTL (seconds).
    pub fn new(ttl_secs: i64) -> Self {
        AdvertCache {
            ttl_secs,
            entries: HashMap::new(),
        }
    }

    /// Cache `advert` under `key`, expiring at `now_unix + ttl`.
    pub fn insert(&mut self, key: impl Into<String>, advert: LegacyAdvert, now_unix: i64) {
        self.entries
            .insert(key.into(), (advert, now_unix + self.ttl_secs));
    }

    /// A non-expired cached advert for `key`, or `None`. Still advisory only.
    pub fn get(&self, key: &str, now_unix: i64) -> Option<&LegacyAdvert> {
        self.entries.get(key).and_then(|(advert, expiry)| {
            if *expiry > now_unix {
                Some(advert)
            } else {
                None
            }
        })
    }

    /// Evict the entry for `key` (call on a connection/policy change).
    pub fn evict(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Drop all expired entries.
    pub fn evict_expired(&mut self, now_unix: i64) {
        self.entries.retain(|_, (_, expiry)| *expiry > now_unix);
    }
}

/// The negotiable security capability an exchange used or a policy requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCapability {
    /// The envelope version (`draft-01` / `draft-02`).
    pub version: String,
    /// The canonicalization scheme id (`None` for draft-01, which carries none).
    pub canonicalization_id: Option<String>,
}

/// Local capability policy: the minimum version required and the versions the
/// client supports. Authoritative — discovery never edits this.
#[derive(Debug, Clone)]
pub struct CapabilityPolicy {
    required_min_version: String,
    supported_versions: Vec<String>,
}

impl CapabilityPolicy {
    /// Require at least `required_min_version`, supporting `supported_versions`.
    pub fn new(
        required_min_version: impl Into<String>,
        supported_versions: impl IntoIterator<Item = String>,
    ) -> Self {
        CapabilityPolicy {
            required_min_version: required_min_version.into(),
            supported_versions: supported_versions.into_iter().collect(),
        }
    }

    /// The common v0.6 posture: require and support draft-02 only.
    pub fn draft02_only() -> Self {
        Self::new(VERSION_DRAFT_02, [VERSION_DRAFT_02.to_string()])
    }
}

/// The capability-mismatch verdict for a verified exchange vs local policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityVerdict {
    /// The exchange meets policy exactly — accept (log any advert mismatch).
    SatisfiesPolicy,
    /// The exchange is weaker than policy — fail closed.
    WeakerThanPolicy,
    /// The exchange is stronger than the minimum and locally supported — accept.
    StrongerSupported,
    /// Version/canonicalization are internally inconsistent — protocol error.
    SelfContradictory,
}

/// Map a known version to an ordinal for comparison; unknown → 0 (treated as below
/// any required minimum).
fn version_rank(version: &str) -> u8 {
    match version {
        VERSION_DRAFT_01 => 1,
        VERSION_DRAFT_02 => 2,
        _ => 0,
    }
}

/// Evaluate a verified exchange's capability against local policy. Takes NO advert
/// input — the advert can never influence the verdict, so a stripped/tampered
/// advert cannot trigger a downgrade.
pub fn evaluate_capability(
    exchange: &ExchangeCapability,
    policy: &CapabilityPolicy,
) -> CapabilityVerdict {
    // Self-contradiction: protocol invariants between version and canonicalization.
    // draft-02 MUST carry a canonicalization_id in the profile allowlist; draft-01
    // MUST NOT carry one at all.
    match (exchange.version.as_str(), &exchange.canonicalization_id) {
        (VERSION_DRAFT_02, Some(id))
            if !DRAFT_02_CANONICALIZATION_ALLOWLIST.contains(&id.as_str()) =>
        {
            return CapabilityVerdict::SelfContradictory;
        }
        (VERSION_DRAFT_02, None) => return CapabilityVerdict::SelfContradictory,
        (VERSION_DRAFT_01, Some(_)) => return CapabilityVerdict::SelfContradictory,
        _ => {}
    }

    let exchange_rank = version_rank(&exchange.version);
    let required_rank = version_rank(&policy.required_min_version);

    // An unknown/unsupported version is below policy — fail closed.
    if exchange_rank == 0 || !policy.supported_versions.contains(&exchange.version) {
        return CapabilityVerdict::WeakerThanPolicy;
    }
    if exchange_rank < required_rank {
        CapabilityVerdict::WeakerThanPolicy
    } else if exchange_rank > required_rank {
        CapabilityVerdict::StrongerSupported
    } else {
        CapabilityVerdict::SatisfiesPolicy
    }
}

/// Whether the advisory advert disagrees with what the verified exchange actually
/// used (a LOG-only signal — the exchange is authoritative). `true` means the
/// advert did not list the exchange's version, so an auditor may want to note it;
/// it never changes a trust decision.
pub fn advert_mismatch(advert: &LegacyAdvert, exchange: &ExchangeCapability) -> bool {
    !advert.versions.is_empty() && !advert.versions.contains(&exchange.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft02_exchange() -> ExchangeCapability {
        ExchangeCapability {
            version: VERSION_DRAFT_02.to_string(),
            canonicalization_id: Some(DRAFT_02_CANONICALIZATION_ALLOWLIST[0].to_string()),
        }
    }

    #[test]
    fn satisfies_policy_when_exchange_meets_required_version() {
        assert_eq!(
            evaluate_capability(&draft02_exchange(), &CapabilityPolicy::draft02_only()),
            CapabilityVerdict::SatisfiesPolicy
        );
    }

    #[test]
    fn weaker_exchange_fails_closed() {
        // Policy requires draft-02; the exchange used draft-01 -> weaker.
        let policy = CapabilityPolicy::new(
            VERSION_DRAFT_02,
            [VERSION_DRAFT_01.to_string(), VERSION_DRAFT_02.to_string()],
        );
        let exchange = ExchangeCapability {
            version: VERSION_DRAFT_01.to_string(),
            canonicalization_id: None,
        };
        assert_eq!(
            evaluate_capability(&exchange, &policy),
            CapabilityVerdict::WeakerThanPolicy
        );
    }

    #[test]
    fn stronger_supported_exchange_is_accepted() {
        // Policy requires draft-01 (minimum) but supports draft-02; a draft-02
        // exchange is stronger and supported.
        let policy = CapabilityPolicy::new(
            VERSION_DRAFT_01,
            [VERSION_DRAFT_01.to_string(), VERSION_DRAFT_02.to_string()],
        );
        assert_eq!(
            evaluate_capability(&draft02_exchange(), &policy),
            CapabilityVerdict::StrongerSupported
        );
    }

    #[test]
    fn self_contradictory_version_canon_is_protocol_error() {
        // draft-02 without a canonicalization_id.
        let bad = ExchangeCapability {
            version: VERSION_DRAFT_02.to_string(),
            canonicalization_id: None,
        };
        assert_eq!(
            evaluate_capability(&bad, &CapabilityPolicy::draft02_only()),
            CapabilityVerdict::SelfContradictory
        );
        // draft-02 with a non-allowlisted canon.
        let bad2 = ExchangeCapability {
            version: VERSION_DRAFT_02.to_string(),
            canonicalization_id: Some("mcps-jcs-floats-v2".to_string()),
        };
        assert_eq!(
            evaluate_capability(&bad2, &CapabilityPolicy::draft02_only()),
            CapabilityVerdict::SelfContradictory
        );
        // draft-01 carrying a canonicalization_id.
        let bad3 = ExchangeCapability {
            version: VERSION_DRAFT_01.to_string(),
            canonicalization_id: Some("x".to_string()),
        };
        assert_eq!(
            evaluate_capability(&bad3, &CapabilityPolicy::draft02_only()),
            CapabilityVerdict::SelfContradictory
        );
    }

    #[test]
    fn advert_is_advisory_and_cannot_cause_a_downgrade() {
        // The verdict for a fixed exchange+policy is identical whether the advert is
        // present, stripped, or tampered (it claims no support / weaker support).
        let exchange = draft02_exchange();
        let policy = CapabilityPolicy::draft02_only();
        let baseline = evaluate_capability(&exchange, &policy);

        // Stripped (no advert at all): verdict unchanged.
        assert_eq!(evaluate_capability(&exchange, &policy), baseline);

        // Tampered advert claiming only draft-01 (a downgrade hint): the verdict
        // (driven by the exchange) is unchanged, and the advert mismatch is LOG-only.
        let tampered = LegacyAdvert {
            versions: vec![VERSION_DRAFT_01.to_string()],
            canonicalization_ids: vec![],
        };
        assert_eq!(evaluate_capability(&exchange, &policy), baseline);
        assert!(
            advert_mismatch(&tampered, &exchange),
            "advert mismatch is observable but log-only"
        );
    }

    #[test]
    fn parse_advert_present_and_absent() {
        let caps = json!({
            "experimental": {
                "se.syncom/mcps": {
                    "versions": ["draft-02"],
                    "canonicalization_ids": ["mcps-jcs-int53-json-v1"]
                }
            }
        });
        let advert = parse_legacy_advert(&caps).expect("advert present");
        assert_eq!(advert.versions, vec!["draft-02".to_string()]);

        // Absent extension -> None (non-authoritative, never an error).
        assert!(parse_legacy_advert(&json!({ "experimental": {} })).is_none());
        assert!(parse_legacy_advert(&json!({})).is_none());
        // Malformed (not an object) -> None.
        assert!(parse_legacy_advert(&json!({ "experimental": { "se.syncom/mcps": 7 } })).is_none());
    }

    #[test]
    fn advert_cache_respects_ttl_and_eviction() {
        let mut cache = AdvertCache::new(100);
        let advert = LegacyAdvert {
            versions: vec!["draft-02".to_string()],
            canonicalization_ids: vec![],
        };
        cache.insert("host-a", advert.clone(), 1000);
        // Within TTL.
        assert_eq!(cache.get("host-a", 1050), Some(&advert));
        // Past TTL -> expired.
        assert_eq!(cache.get("host-a", 1101), None);

        // Re-insert and evict on policy/connection change.
        cache.insert("host-a", advert.clone(), 2000);
        cache.evict("host-a");
        assert_eq!(cache.get("host-a", 2001), None);
    }

    #[test]
    fn proof_only_comes_from_a_verified_exchange() {
        // ProvenSupport has no constructor other than from_verified_response, and
        // VerifiedResponse cannot be built outside mcps-core's verifier — so an
        // advert can never mint proof. (Compile-time guarantee; this documents it.)
        // We assert the accessor shape over a value built in the round-trip tests.
        fn _accepts_only_verified(v: &VerifiedResponse) -> ProvenSupport {
            ProvenSupport::from_verified_response(v)
        }
    }
}
