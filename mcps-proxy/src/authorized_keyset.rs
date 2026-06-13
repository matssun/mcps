// SPDX-License-Identifier: Apache-2.0
//! Authorized server key set — the explicit admission anchor for response-signing
//! identity at fleet scale (ADR-MCPS-022).
//!
//! In a multi-node deployment every node must produce response signatures. The
//! naive "one shared identity" approach tempts copying one private key onto N
//! hosts; ADR-MCPS-022 forbids that and instead makes **per-node keys the v0.3
//! default**, anchored by an **explicit authorized key set / admission document**
//! rather than a loose flat list of discovered keys.
//!
//! This module supplies the verifier-side half of that decision:
//!
//! - [`AuthorizedKeyEntry`] / [`AuthorizedKeySet`] — the in-memory admission
//!   document. It binds each node `key_id` to the server `audience` it may
//!   represent, with the minimum governance fields ADR-MCPS-022 requires
//!   (issuer, node label, validity window, status, generation). The wire format
//!   of a *distributed signed manifest* is deliberately left to a later ADR; this
//!   type fixes the **minimum semantics**.
//! - [`ResponseSigningIdentityMode`] — the per-`audience` declaration
//!   (`per_node_keyset` | `shared_remote_signer`) operators MUST make. One mode
//!   per audience keeps client trust rules and audit interpretation unambiguous.
//! - [`KeySetTrustResolver`] — a [`TrustResolver`] that admits a response
//!   signature only when its `(server_signer, key_id)` resolves to an **active**
//!   entry in the authorized set for the configured audience, inside the entry's
//!   validity window. It reuses the frozen Core taxonomy: a key that is
//!   well-formed but not `active` in the set maps to
//!   [`TrustResolverError::Revoked`]/[`TrustResolverError::NotFound`] →
//!   [`McpsError::ActorBindingFailed`](mcps_core::error::McpsError::ActorBindingFailed).
//!   No new wire token and no new `_meta` key are introduced.
//!
//! Anchor *propagation and revocation* (the window `T`) are governed by
//! ADR-MCPS-021; wrap this resolver in
//! [`BoundedTrustCache`](crate::trust_cache::BoundedTrustCache) to obtain the
//! bounded revocation-exposure window. The node-key set **is** trust state, so
//! the two ADRs compose: 022 decides *what is admissible*, 021 decides *how long
//! a cached admission may be trusted*.

use std::collections::BTreeMap;

use mcps_core::TrustResolver;
use mcps_core::TrustResolverError;
use mcps_core::VerificationKey;

use crate::trust_cache::UnixClock;

/// The lifecycle status of an [`AuthorizedKeyEntry`].
///
/// Only [`Active`](KeyStatus::Active) keys may verify a signature. Both
/// [`Revoked`](KeyStatus::Revoked) and [`Disabled`](KeyStatus::Disabled) are
/// admission failures that surface as
/// [`McpsError::ActorBindingFailed`](mcps_core::error::McpsError::ActorBindingFailed)
/// via [`TrustResolverError::Revoked`] — modelled distinctly from a never-present
/// key so the not-found-vs-revoked paths stay exercisable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The key is currently authorized to sign for its audience.
    Active,
    /// The key was authorized but has been revoked (compromise / decommission).
    Revoked,
    /// The key is administratively disabled (not yet, or no longer, in service).
    Disabled,
}

/// One entry in the authorized server key set (ADR-MCPS-022 minimum semantics).
///
/// Binds a single node key to the server `audience` it may represent. The set of
/// active entries for an audience is exactly the fleet's response-signing
/// identity; there is no "trust any well-formed key that shows up" path.
#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    /// The wire `key_id` carried in the response signature block. Unique across
    /// the whole set (see [`AuthorizedKeySet::new`]); two different nodes MUST
    /// NOT present the same `key_id`.
    pub key_id: String,
    /// The Ed25519 verification key used to check the response signature.
    pub public_key: VerificationKey,
    /// The issuer / trust-root authority that admitted this key.
    pub issuer: String,
    /// The server identity (`server_signer`) this key is authorized to represent.
    pub audience: String,
    /// Operator-facing node identity / label (audit + diagnostics; never trusted
    /// for admission).
    pub node_label: String,
    /// Unix seconds before which the key is not yet valid. A node publishes its
    /// key and waits ≥ `T` (ADR-MCPS-021) before `valid_from`.
    pub valid_from: i64,
    /// Optional Unix-seconds expiry; `None` means "no scheduled expiry".
    pub valid_until: Option<i64>,
    /// Lifecycle status; only [`KeyStatus::Active`] admits a signature.
    pub status: KeyStatus,
    /// Monotonic generation / version for ADR-MCPS-021 propagation + revocation.
    pub generation: u64,
}

/// Why an [`AuthorizedKeySet`] or [`KeySetTrustResolver`] could not be
/// constructed. Construction fails closed so a malformed anchor can never be
/// silently trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeySetError {
    /// Two entries share a `key_id`. ADR-MCPS-022: two different nodes MUST NOT
    /// present the same `key_id` unless they are explicitly the same key entry.
    #[error("duplicate key_id in authorized key set: {0}")]
    DuplicateKeyId(String),

    /// `shared_remote_signer` mode was requested but the configured shared
    /// `key_id` is absent or not `active` for the audience.
    #[error("shared_remote_signer key_id is not an active entry for the audience: {0}")]
    SharedKeyNotActive(String),

    /// `shared_remote_signer` mode was requested but more than one entry is
    /// `active` for the audience. Shared mode means exactly one signing identity;
    /// multiple active keys is a per-node-keyset posture and is rejected so the
    /// mode cannot be silently mixed.
    #[error("shared_remote_signer requires exactly one active key for audience: {0}")]
    SharedModeMultipleActive(String),
}

/// The explicit authorized server key set — the admission document of
/// ADR-MCPS-022. Keyed by globally-unique `key_id`; each entry carries the
/// audience it is bound to.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeySet {
    by_key_id: BTreeMap<String, AuthorizedKeyEntry>,
}

impl AuthorizedKeySet {
    /// Build a set from explicit entries, rejecting duplicate `key_id`s.
    ///
    /// Rejecting collisions at construction is the "no key_id collision" rule of
    /// ADR-MCPS-022 — it makes "just a JSON array of public keys" unable to
    /// become the anchor by accident.
    pub fn new(entries: Vec<AuthorizedKeyEntry>) -> Result<AuthorizedKeySet, KeySetError> {
        let mut by_key_id: BTreeMap<String, AuthorizedKeyEntry> = BTreeMap::new();
        for entry in entries {
            if by_key_id.contains_key(&entry.key_id) {
                return Err(KeySetError::DuplicateKeyId(entry.key_id));
            }
            by_key_id.insert(entry.key_id.clone(), entry);
        }
        Ok(AuthorizedKeySet { by_key_id })
    }

    /// Look up the entry for `(audience, key_id)`. Returns `None` when the
    /// `key_id` is unknown or is bound to a different audience.
    pub fn lookup(&self, audience: &str, key_id: &str) -> Option<&AuthorizedKeyEntry> {
        self.by_key_id
            .get(key_id)
            .filter(|entry| entry.audience == audience)
    }

    /// Iterate over all entries (admission diagnostics / audit).
    pub fn entries(&self) -> impl Iterator<Item = &AuthorizedKeyEntry> {
        self.by_key_id.values()
    }

    /// Count the `active` entries bound to `audience`.
    fn active_count_for(&self, audience: &str) -> usize {
        self.by_key_id
            .values()
            .filter(|entry| entry.audience == audience && entry.status == KeyStatus::Active)
            .count()
    }
}

/// The response-signing identity mode an `audience` declares (ADR-MCPS-022).
///
/// A deployment MUST declare exactly one mode per audience; mixed steady-state
/// operation is rejected (allowed only inside an explicit migration window,
/// deferred to a future migration profile). The mode is a deployment assertion
/// surfaced in startup/audit output, mirroring
/// [`ReplayDurabilityTier`](crate::replay_tier::ReplayDurabilityTier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseSigningIdentityMode {
    /// Each node holds its own key; any `active` entry in the authorized set is
    /// admissible. The v0.3 default — tight per-node blast radius, no mandatory
    /// KMS, anchor managed through ADR-MCPS-021.
    PerNodeKeyset,
    /// All nodes sign through one non-exporting remote signer (KMS/HSM); only the
    /// single configured shared `key_id` is admissible. A higher key-custody
    /// tier, not necessarily a smaller blast radius.
    SharedRemoteSigner,
}

impl ResponseSigningIdentityMode {
    /// Parse an operator-supplied mode value (case-insensitive). Returns a
    /// human-readable error string (no panics) so the CLI fails closed.
    ///
    /// Accepted forms: `per-node-keyset`, `shared-remote-signer`.
    pub fn parse(value: &str) -> Result<ResponseSigningIdentityMode, String> {
        match value.trim().to_lowercase().as_str() {
            "per-node-keyset" => Ok(ResponseSigningIdentityMode::PerNodeKeyset),
            "shared-remote-signer" => Ok(ResponseSigningIdentityMode::SharedRemoteSigner),
            other => Err(format!(
                "unknown response-signing identity mode '{other}' (expected \
                 per-node-keyset | shared-remote-signer)"
            )),
        }
    }

    /// The stable, uppercase wire name operators quote — used in config, startup
    /// logs, and audit records.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ResponseSigningIdentityMode::PerNodeKeyset => "PER_NODE_KEYSET",
            ResponseSigningIdentityMode::SharedRemoteSigner => "SHARED_REMOTE_SIGNER",
        }
    }

    /// The honest one-line property this mode provides (ADR-MCPS-022). Surfaced
    /// directly so the deployment cannot over-claim.
    pub fn guarantee(&self) -> &'static str {
        match self {
            ResponseSigningIdentityMode::PerNodeKeyset => {
                "each node signs with its own key; compromise of one node revokes \
                 only that node's key (tight blast radius); no shared private key"
            }
            ResponseSigningIdentityMode::SharedRemoteSigner => {
                "one non-exporting remote signer for the whole audience; higher key \
                 custody, not necessarily smaller blast radius (a compromised node \
                 credential can sign as the shared identity until revoked)"
            }
        }
    }

    /// The structured startup/audit line ADR-MCPS-022 expects for the configured
    /// audience: the audience, the declared mode wire name, and the honest
    /// surfaced guarantee.
    pub fn startup_audit_line(&self, audience: &str) -> String {
        format!(
            "response-signing audience={audience} mode={} guarantee=\"{}\"",
            self.wire_name(),
            self.guarantee()
        )
    }
}

/// A [`TrustResolver`] that admits a response signature only against an explicit
/// [`AuthorizedKeySet`] for one configured audience (ADR-MCPS-022).
///
/// Resolution succeeds iff: the response's `server_signer` equals the configured
/// `audience`; the `key_id` is an entry bound to that audience; the declared mode
/// admits it (in `shared_remote_signer`, only the single configured shared key);
/// the entry status is [`KeyStatus::Active`]; and the current time is inside the
/// entry's validity window. Any other outcome fails closed onto the frozen Core
/// taxonomy — never "allow".
pub struct KeySetTrustResolver {
    key_set: AuthorizedKeySet,
    audience: String,
    mode: ResponseSigningIdentityMode,
    shared_key_id: Option<String>,
    clock: UnixClock,
}

impl KeySetTrustResolver {
    /// Construct a `per_node_keyset` resolver: any `active` entry bound to
    /// `audience` is admissible. `clock` supplies the verify-time Unix seconds for
    /// validity-window checks (inject [`system_clock`](crate::trust_cache::system_clock)
    /// in production).
    pub fn per_node_keyset(
        key_set: AuthorizedKeySet,
        audience: impl Into<String>,
        clock: UnixClock,
    ) -> KeySetTrustResolver {
        KeySetTrustResolver {
            key_set,
            audience: audience.into(),
            mode: ResponseSigningIdentityMode::PerNodeKeyset,
            shared_key_id: None,
            clock,
        }
    }

    /// Construct a `shared_remote_signer` resolver: only the single configured
    /// shared `key_id` is admissible. Fails closed if the shared key is not an
    /// active entry for the audience, or if more than one entry is active for the
    /// audience (which would be a per-node posture, not a shared one).
    pub fn shared_remote_signer(
        key_set: AuthorizedKeySet,
        audience: impl Into<String>,
        shared_key_id: impl Into<String>,
        clock: UnixClock,
    ) -> Result<KeySetTrustResolver, KeySetError> {
        let audience = audience.into();
        let shared_key_id = shared_key_id.into();

        let entry = key_set
            .lookup(&audience, &shared_key_id)
            .ok_or_else(|| KeySetError::SharedKeyNotActive(shared_key_id.clone()))?;
        if entry.status != KeyStatus::Active {
            return Err(KeySetError::SharedKeyNotActive(shared_key_id));
        }
        if key_set.active_count_for(&audience) > 1 {
            return Err(KeySetError::SharedModeMultipleActive(audience));
        }

        Ok(KeySetTrustResolver {
            key_set,
            audience,
            mode: ResponseSigningIdentityMode::SharedRemoteSigner,
            shared_key_id: Some(shared_key_id),
            clock,
        })
    }

    /// The declared mode (for audit / startup surfacing).
    pub fn mode(&self) -> ResponseSigningIdentityMode {
        self.mode
    }
}

impl std::fmt::Debug for KeySetTrustResolver {
    // Manual impl: the injected `clock` closure is not `Debug`. Omit it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySetTrustResolver")
            .field("audience", &self.audience)
            .field("mode", &self.mode)
            .field("shared_key_id", &self.shared_key_id)
            .field("key_set", &self.key_set)
            .finish_non_exhaustive()
    }
}

impl TrustResolver for KeySetTrustResolver {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        // The response must claim the server identity this resolver anchors. A
        // mismatch is a definitive negative (not our audience), not an outage.
        if signer != self.audience {
            return Err(TrustResolverError::NotFound);
        }

        // Non-flat trust: the key_id must be an entry bound to this audience.
        let entry = match self.key_set.lookup(&self.audience, key_id) {
            Some(entry) => entry,
            None => return Err(TrustResolverError::NotFound),
        };

        // Mode admission. In shared_remote_signer, only the one configured shared
        // key is admissible; a per-node key against a shared-only audience is the
        // "mixed-mode disabled" rejection.
        if self.mode == ResponseSigningIdentityMode::SharedRemoteSigner
            && self.shared_key_id.as_deref() != Some(key_id)
        {
            return Err(TrustResolverError::NotFound);
        }

        // Status: only active admits; revoked/disabled is a distinct binding
        // failure (still ActorBindingFailed on the wire).
        match entry.status {
            KeyStatus::Active => {}
            KeyStatus::Revoked | KeyStatus::Disabled => return Err(TrustResolverError::Revoked),
        }

        // Validity window. Outside the window is a definitive negative with the
        // not-found semantics so a freshly-valid key is not suppressed by a long
        // cache (ADR-MCPS-021 negative TTL).
        let now = (self.clock)();
        if now < entry.valid_from {
            return Err(TrustResolverError::NotFound);
        }
        if let Some(valid_until) = entry.valid_until {
            if now > valid_until {
                return Err(TrustResolverError::NotFound);
            }
        }

        Ok(entry.public_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizedKeyEntry;
    use super::AuthorizedKeySet;
    use super::KeySetError;
    use super::KeySetTrustResolver;
    use super::KeyStatus;
    use super::ResponseSigningIdentityMode;
    use mcps_core::error::McpsError;
    use mcps_core::SigningKey;
    use mcps_core::TrustResolver;
    use mcps_core::TrustResolverError;
    use mcps_core::VerificationKey;

    const AUDIENCE: &str = "did:example:server-1";
    const OTHER_AUDIENCE: &str = "did:example:server-2";

    // Fixed, documented seeds so keys are reproducible.
    const SEED_NODE_A: [u8; 32] = [10u8; 32];
    const SEED_NODE_B: [u8; 32] = [11u8; 32];
    const SEED_SHARED: [u8; 32] = [12u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    fn fixed_clock(now: i64) -> super::UnixClock {
        Box::new(move || now)
    }

    fn entry(
        key_id: &str,
        seed: &[u8; 32],
        audience: &str,
        status: KeyStatus,
    ) -> AuthorizedKeyEntry {
        AuthorizedKeyEntry {
            key_id: key_id.to_string(),
            public_key: key_from(seed),
            issuer: "did:example:root".to_string(),
            audience: audience.to_string(),
            node_label: format!("node-{key_id}"),
            valid_from: 0,
            valid_until: None,
            status,
            generation: 1,
        }
    }

    // ---- AuthorizedKeySet construction ----------------------------------------

    #[test]
    fn duplicate_key_id_is_rejected_at_construction() {
        let err = AuthorizedKeySet::new(vec![
            entry("dup", &SEED_NODE_A, AUDIENCE, KeyStatus::Active),
            entry("dup", &SEED_NODE_B, AUDIENCE, KeyStatus::Active),
        ])
        .expect_err("duplicate key_id must be rejected");
        assert_eq!(err, KeySetError::DuplicateKeyId("dup".to_string()));
    }

    // ---- per_node_keyset admission --------------------------------------------

    #[test]
    fn per_node_node_a_and_node_b_both_resolve() {
        let set = AuthorizedKeySet::new(vec![
            entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Active),
            entry("node-b", &SEED_NODE_B, AUDIENCE, KeyStatus::Active),
        ])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));

        let a = resolver.resolve(AUDIENCE, "node-a").expect("node-a admits");
        let b = resolver.resolve(AUDIENCE, "node-b").expect("node-b admits");
        assert_eq!(a.to_bytes(), key_from(&SEED_NODE_A).to_bytes());
        assert_eq!(b.to_bytes(), key_from(&SEED_NODE_B).to_bytes());
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn unknown_key_is_not_found_then_actor_binding_failed() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));

        let err = resolver
            .resolve(AUDIENCE, "node-unknown")
            .expect_err("unknown key rejected");
        assert_eq!(err, TrustResolverError::NotFound);
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);
    }

    #[test]
    fn well_formed_key_not_in_set_is_rejected_non_flat_trust() {
        // A key that is perfectly valid material but simply absent from the
        // authorized set must be rejected — no "trust any key that shows up".
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));
        // SEED_SHARED is a real key, but its key_id is not admitted.
        let err = resolver
            .resolve(AUDIENCE, "rogue-but-wellformed")
            .expect_err("absent key rejected");
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);
    }

    #[test]
    fn revoked_key_maps_to_revoked_then_actor_binding_failed() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Revoked,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));

        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("revoked rejected");
        assert_eq!(err, TrustResolverError::Revoked);
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);
    }

    #[test]
    fn disabled_key_is_rejected() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Disabled,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));
        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("disabled rejected");
        assert_eq!(err, TrustResolverError::Revoked);
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));
        // A response claiming a different server identity must not resolve here.
        let err = resolver
            .resolve(OTHER_AUDIENCE, "node-a")
            .expect_err("wrong audience rejected");
        assert_eq!(err, TrustResolverError::NotFound);
    }

    #[test]
    fn key_bound_to_other_audience_is_rejected() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            OTHER_AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(100));
        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("cross-audience key rejected");
        assert_eq!(err, TrustResolverError::NotFound);
    }

    // ---- validity window ------------------------------------------------------

    #[test]
    fn not_yet_valid_key_is_rejected() {
        let mut e = entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Active);
        e.valid_from = 1_000;
        let set = AuthorizedKeySet::new(vec![e]).expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(500));
        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("not yet valid rejected");
        assert_eq!(err, TrustResolverError::NotFound);
    }

    #[test]
    fn expired_key_is_rejected() {
        let mut e = entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Active);
        e.valid_from = 0;
        e.valid_until = Some(1_000);
        let set = AuthorizedKeySet::new(vec![e]).expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(2_000));
        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("expired rejected");
        assert_eq!(err, TrustResolverError::NotFound);
    }

    #[test]
    fn key_inside_validity_window_resolves() {
        let mut e = entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Active);
        e.valid_from = 1_000;
        e.valid_until = Some(2_000);
        let set = AuthorizedKeySet::new(vec![e]).expect("set");
        let resolver = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, fixed_clock(1_500));
        assert!(resolver.resolve(AUDIENCE, "node-a").is_ok());
    }

    // ---- shared_remote_signer mode --------------------------------------------

    #[test]
    fn shared_remote_signer_admits_only_the_shared_key() {
        let set = AuthorizedKeySet::new(vec![entry(
            "shared",
            &SEED_SHARED,
            AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let resolver =
            KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "shared", fixed_clock(100))
                .expect("shared resolver");
        assert!(resolver.resolve(AUDIENCE, "shared").is_ok());
        assert_eq!(
            resolver.mode(),
            ResponseSigningIdentityMode::SharedRemoteSigner
        );
    }

    #[test]
    fn shared_mode_rejects_a_per_node_key_mixed_mode_disabled() {
        // The set happens to also contain a per-node key as a non-active (e.g.
        // disabled) entry; presenting it against a shared-only audience must be
        // rejected — this is the "mixed-mode disabled" conformance vector.
        let set = AuthorizedKeySet::new(vec![
            entry("shared", &SEED_SHARED, AUDIENCE, KeyStatus::Active),
            entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Disabled),
        ])
        .expect("set");
        let resolver =
            KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "shared", fixed_clock(100))
                .expect("shared resolver");
        let err = resolver
            .resolve(AUDIENCE, "node-a")
            .expect_err("per-node key rejected under shared mode");
        assert_eq!(err, TrustResolverError::NotFound);
    }

    #[test]
    fn shared_mode_rejects_construction_with_two_active_keys() {
        let set = AuthorizedKeySet::new(vec![
            entry("shared", &SEED_SHARED, AUDIENCE, KeyStatus::Active),
            entry("node-a", &SEED_NODE_A, AUDIENCE, KeyStatus::Active),
        ])
        .expect("set");
        let err =
            KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "shared", fixed_clock(100))
                .expect_err("two active keys is not a shared posture");
        assert_eq!(
            err,
            KeySetError::SharedModeMultipleActive(AUDIENCE.to_string())
        );
    }

    #[test]
    fn shared_mode_rejects_construction_when_shared_key_absent() {
        let set = AuthorizedKeySet::new(vec![entry(
            "node-a",
            &SEED_NODE_A,
            AUDIENCE,
            KeyStatus::Active,
        )])
        .expect("set");
        let err =
            KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "absent", fixed_clock(100))
                .expect_err("absent shared key rejected");
        assert_eq!(err, KeySetError::SharedKeyNotActive("absent".to_string()));
    }

    // ---- mode enum ------------------------------------------------------------

    #[test]
    fn mode_parse_roundtrips_and_rejects_unknown() {
        assert_eq!(
            ResponseSigningIdentityMode::parse("per-node-keyset"),
            Ok(ResponseSigningIdentityMode::PerNodeKeyset)
        );
        assert_eq!(
            ResponseSigningIdentityMode::parse("  Shared-Remote-Signer  "),
            Ok(ResponseSigningIdentityMode::SharedRemoteSigner)
        );
        assert!(ResponseSigningIdentityMode::parse("copied-shared-key").is_err());
    }

    #[test]
    fn mode_wire_names_are_stable() {
        assert_eq!(
            ResponseSigningIdentityMode::PerNodeKeyset.wire_name(),
            "PER_NODE_KEYSET"
        );
        assert_eq!(
            ResponseSigningIdentityMode::SharedRemoteSigner.wire_name(),
            "SHARED_REMOTE_SIGNER"
        );
    }

    #[test]
    fn startup_audit_line_carries_audience_mode_and_guarantee() {
        let line = ResponseSigningIdentityMode::PerNodeKeyset.startup_audit_line(AUDIENCE);
        assert!(line.contains(AUDIENCE));
        assert!(line.contains("PER_NODE_KEYSET"));
        assert!(line.contains("own key"));
    }
}
