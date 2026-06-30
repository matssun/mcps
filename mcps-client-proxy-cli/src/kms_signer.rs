//! Client-side GCP Cloud KMS object signer (ADR-MCPS-045 Phase 4 / Tier T4;
//! ADR-MCPS-028 §C key custody).
//!
//! This is the MODE-SPECIFIC adapter the pure `mcps-client-core` deliberately
//! leaves to its consumers: it binds the version-neutral [`ClientSigner`] trait to
//! a non-exporting Cloud KMS key. The Ed25519 private key lives in GCP Cloud KMS
//! (`EC_SIGN_ED25519`) and is NEVER exported — every signature is produced by the
//! cloud `asymmetricSign` op and (in the reused backend) re-verified locally
//! against the advertised public key before it is returned.
//!
//! It reuses the live-tested backend from `mcps-proxy`
//! (`GcpKmsEd25519Backend`, implementing the SDK-free [`KmsEd25519Backend`] seam)
//! rather than re-deriving the REST/`ureq` signing path. The only new logic here
//! is the thin trait bridge and the `KeyError → McpsError` mapping (a delegated
//! signer that cannot sign fails closed; it never returns a placeholder).
//!
//! Custody is reported as [`CustodyClass::NonExporting`], so this signer is the
//! only class that satisfies the hardening profile
//! (`SignerPolicy::require_non_exporting`) — exactly T4's "key custody in cloud
//! KMS" property.

use mcps_client_core::ClientSigner;
use mcps_client_core::CustodyClass;
use mcps_core::b64url_encode;
use mcps_core::McpsError;
use mcps_core::VerificationKey;
use mcps_proxy::kms_keysource::KmsEd25519Backend;
use mcps_proxy::GcpKmsConfig;
use mcps_proxy::GcpKmsEd25519Backend;

/// Raw Ed25519 public-key length, and the RFC 8410 Ed25519 SPKI length (a fixed
/// 12-byte prefix + the raw key), so the raw point is the trailing 32 bytes.
const ED25519_RAW_LEN: usize = 32;

/// A [`ClientSigner`] whose private key is held in GCP Cloud KMS (non-exporting).
pub struct KmsClientSigner {
    backend: GcpKmsEd25519Backend,
    signer_id: String,
    key_id: String,
}

impl KmsClientSigner {
    /// Build a production Cloud KMS client signer over the given key version.
    ///
    /// `use_metadata_server` selects the GCE/GKE workload-identity token source;
    /// otherwise an operator-supplied `MCPS_GCP_ACCESS_TOKEN` is used. Construction
    /// fetches and validates the public key once (Ed25519 SPKI + `EC_SIGN_ED25519`
    /// algorithm), failing closed on any non-Ed25519 key — so a misconfigured key
    /// version is rejected here, before a single request is signed.
    pub fn new(
        config: &GcpKmsConfig,
        use_metadata_server: bool,
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, String> {
        let backend = GcpKmsEd25519Backend::new(config, use_metadata_server)
            .map_err(|e| format!("gcp-kms client signer: {e}"))?;
        Ok(KmsClientSigner {
            backend,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        })
    }

    /// TEST-ONLY: build over an in-memory FAKE Cloud KMS transport backed by the
    /// local Ed25519 key with the given 32-byte seed — no network, no credentials.
    /// Used to prove the trait bridge end-to-end (a KMS-signed preimage verifies
    /// under the unmodified `mcps-core` verifier) offline.
    #[cfg(test)]
    fn for_test_with_local_seed(
        seed: &[u8; 32],
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        let backend = GcpKmsEd25519Backend::for_test_with_local_seed(seed)
            .expect("fake KMS backend builds");
        KmsClientSigner {
            backend,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        }
    }
}

impl KmsClientSigner {
    /// The signer's Ed25519 verification (public) key — exportable even from a
    /// non-exporting KMS. The remote PEP needs this in its trust store to verify
    /// the client's signed requests; the four-hop harness fetches it here.
    pub fn verification_key(&self) -> Result<VerificationKey, String> {
        let spki = self
            .backend
            .public_key_spki_der()
            .map_err(|e| format!("gcp-kms public key: {e}"))?;
        // RFC 8410 Ed25519 SPKI: the raw 32-byte point is the trailing bytes.
        let raw: [u8; ED25519_RAW_LEN] = spki
            .get(spki.len().saturating_sub(ED25519_RAW_LEN)..)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "gcp-kms public key SPKI too short".to_string())?;
        VerificationKey::from_bytes(&raw)
            .map_err(|e| format!("gcp-kms: invalid Ed25519 public key: {e}"))
    }
}

impl ClientSigner for KmsClientSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn custody(&self) -> CustodyClass {
        // The private key never leaves Cloud KMS — the only class the hardening
        // profile admits.
        CustodyClass::NonExporting
    }

    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
        // The backend returns the raw 64-byte Ed25519 signature (already
        // verify-before-return); the envelope wants Base64URL-no-pad. A KMS that
        // cannot sign (token expired, network down, key disabled) fails closed —
        // there is no usable signing binding — never a placeholder signature.
        self.backend
            .sign_raw_ed25519(preimage)
            .map(|raw| b64url_encode(&raw))
            .map_err(|_| McpsError::ActorBindingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcps_core::verify_ed25519;
    use mcps_core::VerificationKey;

    const SEED: [u8; 32] = [7u8; 32];
    const SIGNER: &str = "did:example:kms-client";
    const KEY_ID: &str = "kms-client-key-1";

    #[test]
    fn reports_non_exporting_custody_and_identity() {
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        assert_eq!(s.signer_id(), SIGNER);
        assert_eq!(s.key_id(), KEY_ID);
        assert_eq!(s.custody(), CustodyClass::NonExporting);
    }

    #[test]
    fn kms_signed_preimage_verifies_under_mcps_core() {
        // The whole point: a signature produced through the KMS client-signer
        // bridge verifies under the unmodified mcps-core Ed25519 verifier, with no
        // network. (Mirrors the server-side kms_signature_verifies_under_mcps_core
        // proof, now on the client seam.)
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        let preimage = b"the canonical draft-02 request preimage";
        let sig_b64url = s.sign_preimage(preimage).expect("kms sign");
        let pubkey = VerificationKey::from_bytes(
            &mcps_core::SigningKey::from_seed_bytes(&SEED).public_key().to_bytes(),
        )
        .expect("verify key");
        assert!(
            verify_ed25519(preimage, &sig_b64url, &pubkey).is_ok(),
            "a KMS-bridge signature must verify under mcps-core"
        );
    }

    #[test]
    fn passes_the_non_exporting_hardening_profile() {
        use mcps_client_core::authorize_signer;
        use mcps_client_core::Environment;
        use mcps_client_core::SignerPolicy;
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        let policy =
            SignerPolicy::new(SIGNER, Environment::Production, true).require_non_exporting();
        assert!(
            authorize_signer(&policy, &s).is_ok(),
            "a Cloud KMS signer must satisfy the hardening (non-exporting) profile"
        );
    }

    // ── Live lane (Tier T4) ────────────────────────────────────────────────
    // `#[ignore]` by default; runs against REAL GCP Cloud KMS from the cloud
    // script (scripts/test-gcp-cloud.sh.example):
    //   MCPS_GCP_KEY_VERSION=<client key version> MCPS_GCP_ACCESS_TOKEN=... \
    //     cargo test -p mcps-client-proxy-cli --features gcp_kms -- --ignored
    // FAILS LOUDLY if its config is absent — never a silent pass.

    fn require_env(name: &str) -> String {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => v,
            _ => panic!(
                "gcp-kms client lane: required env var {name} is not set — this lane runs \
                 against real Cloud KMS and does not pass without verifying"
            ),
        }
    }

    #[test]
    #[ignore = "requires a live GCP Cloud KMS client key (run with --ignored and MCPS_GCP_* set)"]
    fn gcp_kms_client_signs_a_draft02_request_that_verifies() {
        use mcps_core::request_signing_preimage;
        use mcps_core::verify_request_draft02;
        use mcps_core::InMemoryReplayCache;
        use mcps_core::InMemoryTrustResolver;
        use mcps_core::McpsError;
        use mcps_core::VerificationConfig;
        use mcps_core::REQUEST_META_KEY;
        use serde_json::json;

        const LIVE_SIGNER: &str = "did:example:gcp-kms-client";
        const LIVE_KEY_ID: &str = "gcp-kms-client-key-1";
        const SERVER: &str = "did:example:gcp-kms-server";
        const AUDIENCE: &str = "did:example:gcp-kms-server";
        const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
        const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
        const CANON_ID: &str = "mcps-jcs-int53-json-v1";
        const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
        const DIGEST: &str = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
        const SKEW: i64 = 30;

        let config = GcpKmsConfig {
            key_version_name: require_env("MCPS_GCP_KEY_VERSION"),
            endpoint: std::env::var("MCPS_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
        };
        let use_metadata = std::env::var("MCPS_GCP_USE_METADATA").is_ok_and(|v| v == "1");
        if !use_metadata {
            require_env("MCPS_GCP_ACCESS_TOKEN");
        }
        let signer = KmsClientSigner::new(&config, use_metadata, LIVE_SIGNER, LIVE_KEY_ID)
            .expect("construct live Cloud KMS client signer (key must be EC_SIGN_ED25519)");
        let pubkey = signer.verification_key().expect("Cloud KMS public key");

        // Build an unsigned draft-02 request, sign its preimage THROUGH the client
        // signer (i.e. via Cloud KMS asymmetricSign), and verify under the
        // unmodified draft-02 verifier.
        let mut request = json!({
            "jsonrpc": "2.0",
            "id": "req-kms-client-1",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello from a cloud-held client key" },
                "_meta": { REQUEST_META_KEY: {
                    "version": "draft-02",
                    "canonicalization_id": CANON_ID,
                    "signer": LIVE_SIGNER,
                    "on_behalf_of": "did:example:user-1",
                    "audience": AUDIENCE,
                    "authorization_binding": {
                        "binding_type": "opaque-bytes",
                        "digest_alg": "sha256",
                        "digest_value": DIGEST
                    },
                    "nonce": NONCE,
                    "issued_at": ISSUED_AT,
                    "expires_at": EXPIRES_AT,
                    "signature": { "alg": "Ed25519", "key_id": LIVE_KEY_ID, "value": null }
                }}
            }
        });
        let _ = SERVER; // documents the intended audience identity
        let preimage = request_signing_preimage(&request).expect("draft-02 request preimage");
        let sig = signer
            .sign_preimage(&preimage)
            .expect("Cloud KMS asymmetricSign over the draft-02 request preimage");
        request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!(sig);

        let raw = serde_json::to_vec(&request).expect("serialize");
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert(LIVE_SIGNER, LIVE_KEY_ID, pubkey.clone());
        let cfg = VerificationConfig {
            expected_audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        };
        let now = mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60;
        let mut replay = InMemoryReplayCache::new(SKEW);
        verify_request_draft02(&raw, &resolver, &mut replay, &cfg, now)
            .expect("a Cloud KMS client-signed draft-02 request MUST verify");

        // Negative — a post-signing tamper of the signed payload fails closed.
        let mut tampered = request.clone();
        tampered["params"]["arguments"]["text"] = json!("goodbye");
        let raw_t = serde_json::to_vec(&tampered).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw_t, &resolver, &mut replay, &cfg, now),
            Err(McpsError::InvalidSignature),
            "a post-signing tamper must fail closed"
        );
    }
}
