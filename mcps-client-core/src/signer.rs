//! Client signing-identity abstraction & custody policy (MCPS-46, #193;
//! ADR-MCPS-044 §Key custody; ADR-MCPS-028 KMS/mTLS signers; CONTEXT.md §Client
//! key custody).
//!
//! The ADR mandates custody **properties, not products**. This module is the
//! mechanism-neutral seam: a [`ClientSigner`] signs the canonical request preimage
//! and identifies itself in the evidence (`signer` + `key_id`), but never exposes
//! key material. Concrete backends — an OS keychain / Secure Enclave, an HSM, a
//! cloud KMS, a workload identity, an mTLS-bound identity, or a delegated signing
//! service (ADR-MCPS-028's `KeySource` seam) — implement [`ClientSigner`] in the
//! mode-specific layer above this pure crate. This crate ships only the trait, the
//! custody classification, the policy gate, and the in-process software /
//! dev-file signers used for tests and the dev bridge.
//!
//! # The custody properties enforced here
//! - **Identified in evidence**: every signer reports its `signer`/`key_id`, which
//!   the request envelope binds under signature.
//! - **Bound to policy**: [`authorize_signer`] checks the signer matches the
//!   identity policy binds to the route/audience; a missing / unknown / mismatched
//!   / revoked signer fails closed.
//! - **No unprotected file keys in production**: a [`CustodyClass::DevFileUnprotected`]
//!   signer is rejected under production `require_mcps`. Hardware/KMS-only is a
//!   HARDENING profile ([`SignerPolicy::require_non_exporting`]), never the base
//!   rule — a software key held private and scrubbed
//!   ([`CustodyClass::SoftwareHeldPrivate`]) is acceptable for the base posture.
//! - **Rotation/revocation by explicit config**: [`SignerPolicy`] carries a revoked
//!   key-id set; signing through a revoked key fails closed.
//!
//! All custody/policy failures map to [`McpsError::ActorBindingFailed`] — there is
//! no usable signing binding — keeping the client error vocabulary inside the
//! frozen `wire_code()` taxonomy (MCPS-48 reuse, not a parallel taxonomy).

use mcps_core::McpsError;
use mcps_core::SigningKey;
use std::collections::BTreeSet;

use crate::request::build_signed_request_with;
use crate::RequestSigningInputs;
use crate::SignedRequest;
use serde_json::Map;
use serde_json::Value;

/// The custody class of a signing identity — the property that policy reasons over
/// (NOT the product). Ordered from strongest to weakest posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyClass {
    /// Non-exporting or delegated: HSM, cloud KMS, OS keychain / Secure Enclave,
    /// workload identity, mTLS-bound identity, or a delegated signing service. The
    /// private material never leaves the device/service. Acceptable everywhere and
    /// the only class the hardening profile admits.
    NonExporting,
    /// In-process software key held private and scrubbed on drop (the seed-backed
    /// `mcps-core::SigningKey`, e.g. ADR-028's production-capable file `KeySource`).
    /// Acceptable for the base production posture; the hardening profile excludes it.
    SoftwareHeldPrivate,
    /// An UNPROTECTED dev/test file key. Permitted ONLY in explicitly-labelled
    /// dev/test; FORBIDDEN under production `require_mcps`.
    DevFileUnprotected,
}

impl CustodyClass {
    /// Whether this class is acceptable under production `require_mcps` WITHOUT the
    /// hardening profile: everything except an unprotected dev file key.
    fn acceptable_for_production(self) -> bool {
        !matches!(self, CustodyClass::DevFileUnprotected)
    }

    /// Whether this class satisfies the hardening (non-exporting-only) profile.
    fn is_non_exporting(self) -> bool {
        matches!(self, CustodyClass::NonExporting)
    }
}

/// A mechanism-neutral client signing identity. Implementors hold the key material
/// privately (or delegate to something that does) and expose only the identity +
/// the ability to sign a preimage.
pub trait ClientSigner {
    /// The signer identity bound into the request evidence (`signer`).
    fn signer_id(&self) -> &str;
    /// The key id naming the signing key in the evidence (`signature.key_id`).
    fn key_id(&self) -> &str;
    /// The custody class, for the policy gate.
    fn custody(&self) -> CustodyClass;
    /// Sign the canonical preimage, returning the Base64URL-no-pad signature, or a
    /// typed failure (e.g. a delegated signer that is unavailable). A signer that
    /// cannot sign fails closed — it never returns a placeholder.
    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError>;
}

/// The deployment environment label — explicit, because "dev/test" is the only
/// place an unprotected file key may be used (CONTEXT.md §Client key custody).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production: unprotected dev file keys are rejected under `require_mcps`.
    Production,
    /// Explicitly-labelled dev/test: dev file keys are permitted.
    DevTest,
}

/// The signer-custody policy for a route/client-identity. Resolved from explicit
/// config; never inferred. It pins the expected signer identity, the revoked
/// key-id set (rotation/revocation), the environment, whether `require_mcps` is in
/// force, and whether the hardening (non-exporting-only) profile is required.
#[derive(Debug, Clone)]
pub struct SignerPolicy {
    expected_signer: String,
    revoked_key_ids: BTreeSet<String>,
    environment: Environment,
    require_mcps: bool,
    require_non_exporting: bool,
}

impl SignerPolicy {
    /// A base policy binding `expected_signer` for the given environment and mode,
    /// with no revoked keys and no hardening profile.
    pub fn new(
        expected_signer: impl Into<String>,
        environment: Environment,
        require_mcps: bool,
    ) -> Self {
        SignerPolicy {
            expected_signer: expected_signer.into(),
            revoked_key_ids: BTreeSet::new(),
            environment,
            require_mcps,
            require_non_exporting: false,
        }
    }

    /// Mark `key_id` revoked (rotation/revocation by explicit config). Signing
    /// through a revoked key id fails closed.
    pub fn revoke_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.revoked_key_ids.insert(key_id.into());
        self
    }

    /// Require the hardening profile: only [`CustodyClass::NonExporting`] signers
    /// are accepted (hardware/KMS-only). This is opt-in, NOT the base rule.
    pub fn require_non_exporting(mut self) -> Self {
        self.require_non_exporting = true;
        self
    }
}

/// Authorize a signer against the policy, fail-closed. Checks, in order: identity
/// match (unknown/mismatched signer → fail), revocation (revoked key id → fail),
/// the hardening profile if required (non-exporting only), and the production
/// dev-file rule (`require_mcps` + production rejects an unprotected file key).
/// Every failure is [`McpsError::ActorBindingFailed`] — no usable signing binding.
pub fn authorize_signer(policy: &SignerPolicy, signer: &dyn ClientSigner) -> Result<(), McpsError> {
    // Identity: the signer must be exactly the one policy bound to this route.
    if signer.signer_id() != policy.expected_signer {
        return Err(McpsError::ActorBindingFailed);
    }
    // Revocation/rotation: a revoked key id is never usable.
    if policy.revoked_key_ids.contains(signer.key_id()) {
        return Err(McpsError::ActorBindingFailed);
    }
    // Hardening profile (opt-in): only non-exporting custody.
    if policy.require_non_exporting && !signer.custody().is_non_exporting() {
        return Err(McpsError::ActorBindingFailed);
    }
    // Production base rule: under require_mcps an unprotected dev file key is
    // forbidden outside an explicitly-labelled dev/test environment.
    if policy.require_mcps
        && policy.environment == Environment::Production
        && !signer.custody().acceptable_for_production()
    {
        return Err(McpsError::ActorBindingFailed);
    }
    Ok(())
}

/// Authorize the signer, then build & sign a draft-02 request through it.
///
/// The signer's `signer_id`/`key_id` OVERRIDE whatever identity `inputs` carried —
/// the evidence always names the actual signing identity. A custody/policy failure
/// (unknown/mismatched/revoked signer, dev key in production, hardening violation)
/// fails closed BEFORE any preimage is built; a signer that cannot sign fails
/// closed at signing time.
pub fn build_signed_request_with_signer(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    inputs: &RequestSigningInputs,
    signer: &dyn ClientSigner,
    policy: &SignerPolicy,
) -> Result<SignedRequest, McpsError> {
    authorize_signer(policy, signer)?;
    // Bind the evidence to the ACTUAL signer identity (defense against a caller
    // passing mismatched inputs).
    let mut bound = inputs.clone();
    bound.signer = signer.signer_id().to_string();
    bound.key_id = signer.key_id().to_string();
    build_signed_request_with(id, method, params, &bound, |preimage| {
        signer.sign_preimage(preimage)
    })
}

// ---------------------------------------------------------------------------
// Concrete signers shipped in the pure crate (software + dev-file). Hardware /
// KMS / delegated signers implement `ClientSigner` in the mode-specific layer.
// ---------------------------------------------------------------------------

/// In-process software signer over a seed-backed `mcps-core::SigningKey` (held
/// private, scrubbed on drop). Custody class [`CustodyClass::SoftwareHeldPrivate`]
/// — acceptable for the base production posture (ADR-028's production-capable file
/// `KeySource` is this class).
pub struct SoftwareSigner {
    key: SigningKey,
    signer_id: String,
    key_id: String,
}

impl SoftwareSigner {
    /// Construct from a held-private signing key and the evidence identity.
    pub fn new(key: SigningKey, signer_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        SoftwareSigner {
            key,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        }
    }
}

impl ClientSigner for SoftwareSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn custody(&self) -> CustodyClass {
        CustodyClass::SoftwareHeldPrivate
    }
    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
        Ok(self.key.sign(preimage))
    }
}

/// An UNPROTECTED dev/test file signer. Identical signing mechanism to
/// [`SoftwareSigner`] but classified [`CustodyClass::DevFileUnprotected`] so the
/// policy gate rejects it under production `require_mcps`. Use ONLY in
/// explicitly-labelled dev/test.
pub struct DevFileSigner {
    key: SigningKey,
    signer_id: String,
    key_id: String,
}

impl DevFileSigner {
    /// Construct a dev/test-only file signer.
    pub fn new(key: SigningKey, signer_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        DevFileSigner {
            key,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        }
    }
}

impl ClientSigner for DevFileSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn custody(&self) -> CustodyClass {
        CustodyClass::DevFileUnprotected
    }
    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
        Ok(self.key.sign(preimage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];
    const SIGNER: &str = "did:example:client";
    const KEY_ID: &str = "client-key-1";

    fn software() -> SoftwareSigner {
        SoftwareSigner::new(SigningKey::from_seed_bytes(&SEED), SIGNER, KEY_ID)
    }

    /// A mock non-exporting (delegated/KMS-like) signer for the hardening tests.
    struct DelegatedSigner {
        key: SigningKey,
    }
    impl ClientSigner for DelegatedSigner {
        fn signer_id(&self) -> &str {
            SIGNER
        }
        fn key_id(&self) -> &str {
            KEY_ID
        }
        fn custody(&self) -> CustodyClass {
            CustodyClass::NonExporting
        }
        fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
            Ok(self.key.sign(preimage))
        }
    }

    /// A signer that cannot sign (e.g. a delegated service that is unavailable).
    struct UnavailableSigner;
    impl ClientSigner for UnavailableSigner {
        fn signer_id(&self) -> &str {
            SIGNER
        }
        fn key_id(&self) -> &str {
            KEY_ID
        }
        fn custody(&self) -> CustodyClass {
            CustodyClass::NonExporting
        }
        fn sign_preimage(&self, _preimage: &[u8]) -> Result<String, McpsError> {
            Err(McpsError::ActorBindingFailed)
        }
    }

    #[test]
    fn matching_software_signer_authorizes_in_production_require_mcps() {
        let policy = SignerPolicy::new(SIGNER, Environment::Production, true);
        assert!(authorize_signer(&policy, &software()).is_ok());
    }

    #[test]
    fn unknown_or_mismatched_signer_fails_closed() {
        let policy = SignerPolicy::new("did:example:other", Environment::Production, true);
        assert_eq!(
            authorize_signer(&policy, &software()).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn revoked_key_id_fails_closed() {
        let policy = SignerPolicy::new(SIGNER, Environment::Production, true).revoke_key_id(KEY_ID);
        assert_eq!(
            authorize_signer(&policy, &software()).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn dev_file_key_rejected_under_production_require_mcps() {
        let policy = SignerPolicy::new(SIGNER, Environment::Production, true);
        let dev = DevFileSigner::new(SigningKey::from_seed_bytes(&SEED), SIGNER, KEY_ID);
        assert_eq!(
            authorize_signer(&policy, &dev).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn dev_file_key_allowed_in_dev_test() {
        let policy = SignerPolicy::new(SIGNER, Environment::DevTest, true);
        let dev = DevFileSigner::new(SigningKey::from_seed_bytes(&SEED), SIGNER, KEY_ID);
        assert!(authorize_signer(&policy, &dev).is_ok());
    }

    #[test]
    fn dev_file_key_allowed_in_production_when_not_require_mcps() {
        // allow_legacy_explicit (require_mcps = false): the strict dev-file rule
        // only bites under require_mcps.
        let policy = SignerPolicy::new(SIGNER, Environment::Production, false);
        let dev = DevFileSigner::new(SigningKey::from_seed_bytes(&SEED), SIGNER, KEY_ID);
        assert!(authorize_signer(&policy, &dev).is_ok());
    }

    #[test]
    fn hardening_profile_rejects_software_key_but_accepts_non_exporting() {
        let policy =
            SignerPolicy::new(SIGNER, Environment::Production, true).require_non_exporting();
        // Software-held-private is below the hardening bar.
        assert_eq!(
            authorize_signer(&policy, &software()).unwrap_err(),
            McpsError::ActorBindingFailed
        );
        // A non-exporting delegated/KMS signer passes.
        let delegated = DelegatedSigner {
            key: SigningKey::from_seed_bytes(&SEED),
        };
        assert!(authorize_signer(&policy, &delegated).is_ok());
    }

    #[test]
    fn unavailable_signer_fails_closed_at_signing_time() {
        // Authorization passes (identity/custody fine) but signing itself fails.
        let policy = SignerPolicy::new(SIGNER, Environment::Production, true);
        let inputs = RequestSigningInputs::with_default_canonicalization(
            SIGNER,
            KEY_ID,
            "user:alice",
            "did:example:server",
            mcps_core::AuthorizationBinding::OpaqueBytes {
                digest_alg: "sha256".to_string(),
                digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            },
            "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
            "2026-06-30T20:00:00Z",
            "2026-06-30T20:05:00Z",
        );
        let mut params = Map::new();
        params.insert("name".into(), Value::String("echo".into()));
        params.insert("arguments".into(), serde_json::json!({}));
        assert_eq!(
            build_signed_request_with_signer(
                &serde_json::json!("req-1"),
                "tools/call",
                params,
                &inputs,
                &UnavailableSigner,
                &policy,
            )
            .unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }
}
