//! Provider-agnostic cloud-KMS response signer (ADR-MCPS-028).
//!
//! The real, non-exporting cloud-KMS backend behind the #3838 [`ResponseSigner`]
//! delegation seam: the Ed25519 response-signing key lives inside the KMS and is
//! NEVER exported — the only operation used is "sign these raw bytes". AWS KMS
//! (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType: RAW`) and GCP Cloud
//! KMS (`EC_SIGN_ED25519`) both expose exactly this and both return an RFC 8410
//! Ed25519 `SubjectPublicKeyInfo`, so the protocol mapping is IDENTICAL across
//! providers. This module is that shared mapping; a provider differs ONLY in the
//! [`KmsEd25519Backend`] network client (the `aws-sdk-kms` / GCP-REST adapters are
//! the feature-gated follow-ups — see ADR-MCPS-028 §B/§C).
//!
//! This core is deliberately DEPENDENCY-FREE (no cloud SDK), mirroring how the
//! #3838 seam landed: the security-critical logic — RAW-only PureEdDSA, raw
//! 64-byte signature, RFC 8410 public-key parsing, and fail-closed on every
//! deviation — is unit-tested with the REAL `mcps-core` verifier and no network.
//!
//! TLS material is delegated to an inner [`FileKeySource`]; delegated TLS signing
//! through the KMS (so the TLS private key also never leaves the device) is the
//! companion hardening item (ADR-MCPS-028 §G), not delivered here.

use std::sync::Arc;

use mcps_core::b64url_encode;
use mcps_core::verify_ed25519;
use mcps_core::VerificationKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;

use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::FileKeySource;
use crate::key_source::KeyError;
use crate::key_source::KeySource;
use crate::key_source::ResponseSigner;

/// Raw Ed25519 signature length (PureEdDSA, no pre-hash).
const ED25519_SIGNATURE_LEN: usize = 64;
/// Raw Ed25519 public-key length.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The fixed 12-byte DER prefix of an RFC 8410 Ed25519 `SubjectPublicKeyInfo`:
/// `SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 } BIT STRING(33) { 00 <32 raw> } }`.
/// AWS KMS `GetPublicKey` and GCP Cloud KMS both return the key in this exact form,
/// so the 32 raw bytes are the tail after this prefix. Anything else (a different
/// key type — RSA, NIST P-curve — or a malformed blob) is rejected.
pub(crate) const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Total length of an RFC 8410 Ed25519 SPKI (prefix + raw point).
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN;

/// The network-facing KMS operations an Ed25519 response signer needs. The
/// production implementations wrap a cloud SDK (`aws-sdk-kms` under feature
/// `aws_kms_keysource`; GCP Cloud KMS REST under `gcp_kms_keysource`); tests use a
/// local-key fake. Keeping this trait SDK-free is what lets the protocol mapping —
/// and its fail-closed checks — be proven against the real `mcps-core` verifier
/// with no network and no cloud credentials.
pub trait KmsEd25519Backend {
    /// PureEdDSA (Ed25519, **no pre-hash**) signature over the RAW `preimage`,
    /// returning the raw 64-byte signature. For AWS KMS this is `Sign` with
    /// `SigningAlgorithm = ED25519_SHA_512` and `MessageType = RAW`; the prehash
    /// variant (`ED25519_PH_SHA_512` / `MessageType: DIGEST`) is Ed25519ph and is
    /// FORBIDDEN — a backend that uses it produces a signature that will not verify
    /// over the raw preimage (proven caught in tests).
    fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// The DER `SubjectPublicKeyInfo` (RFC 8410) of the Ed25519 public key — what
    /// AWS KMS `GetPublicKey` returns directly and what a GCP public-key PEM decodes
    /// to. The verification (public) key IS exportable even from a non-exporting
    /// KMS; the private key is not, and this trait never asks for it.
    fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError>;
}

/// Extract the 32 raw Ed25519 public-key bytes from an RFC 8410 `SubjectPublicKeyInfo`.
///
/// Fail-closed: a blob of the wrong length, or one whose algorithm prefix is not
/// id-Ed25519 (`1.3.101.112`), is rejected — the KMS key MUST be an Ed25519 key.
/// This prevents silently treating an RSA / NIST-P-curve KMS key (a different,
/// MCP-S-incompatible algorithm) as if it were Ed25519.
pub(crate) fn ed25519_raw_point_from_spki(
    der: &[u8],
) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], KeyError> {
    if der.len() != ED25519_SPKI_LEN || der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(KeyError::Malformed(format!(
            "kms: public key is not an RFC 8410 Ed25519 SubjectPublicKeyInfo (got {} bytes); the \
             KMS key MUST be an Ed25519 key (AWS ECC_NIST_EDWARDS25519 / GCP EC_SIGN_ED25519)",
            der.len()
        )));
    }
    let mut raw = [0u8; ED25519_PUBLIC_KEY_LEN];
    raw.copy_from_slice(&der[ED25519_SPKI_PREFIX.len()..]);
    Ok(raw)
}

/// A non-exporting [`ResponseSigner`] that signs Ed25519 inside a cloud KMS.
///
/// Holds only a [`KmsEd25519Backend`]; it carries no TLS material, so its signing
/// behavior is testable in isolation. [`KmsKeySource`] composes it with a
/// [`FileKeySource`] for the (still-exported, by ADR-028 §G) TLS material.
pub struct KmsResponseSigner {
    backend: Box<dyn KmsEd25519Backend + Send + Sync>,
}

impl KmsResponseSigner {
    /// Build a signer over the given KMS backend.
    pub fn new(backend: Box<dyn KmsEd25519Backend + Send + Sync>) -> Self {
        KmsResponseSigner { backend }
    }
}

impl ResponseSigner for KmsResponseSigner {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        let signature = self.backend.sign_raw_ed25519(preimage)?;
        if signature.len() != ED25519_SIGNATURE_LEN {
            // A wrong-length signature is intrinsic (not a transient fault) — fail closed, never emit it.
            return Err(KeyError::Malformed(format!(
                "kms: backend returned a {}-byte signature; expected {ED25519_SIGNATURE_LEN} (expected a raw Ed25519 signature)",
                signature.len()
            )));
        }
        // Match SigningKey::sign EXACTLY: Base64URL-no-pad of the raw 64 bytes.
        let encoded = b64url_encode(&signature);
        // ADR-MCPS-028 §D, enforced AT THE SEAM (mirroring DelegatedResponseSigner):
        // re-verify the backend's signature against THIS signer's advertised public
        // key (`response_public_key`) before emitting. The concrete AWS/GCP backends
        // already self-verify (defense in depth, kept), but centralizing the check
        // here makes the "EVERY signature is verified locally before it is emitted"
        // property hold for ANY `KmsEd25519Backend` — including a future backend that
        // forgot to self-verify, or one wired to a mismatched key. Fail closed: never
        // emit a response signature the proxy's own advertised key cannot verify.
        // One verify per response sign — negligible.
        let public_key = self.response_public_key()?;
        verify_ed25519(preimage, &encoded, &public_key).map_err(|_| {
            KeyError::Malformed(
                "kms: backend produced a signature that does not verify as Ed25519 under its \
                 advertised public key (response_public_key)"
                    .to_string(),
            )
        })?;
        Ok(encoded)
    }

    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        let der = self.backend.public_key_spki_der()?;
        let raw = ed25519_raw_point_from_spki(&der)?;
        VerificationKey::from_bytes(&raw)
            .map_err(|e| KeyError::Malformed(format!("kms: invalid Ed25519 public key: {e}")))
    }
}

/// A cloud-KMS [`KeySource`]: response signing is delegated to the KMS (the
/// object-signing key never leaves it). TLS material comes from the inner
/// [`FileKeySource`] (cert chain + client-CA roots always; the exported TLS *key*
/// only on the non-delegated path).
///
/// Issue #60 (ADR-MCPS-028 §G): when `tls_signer` is `Some`, the TLS server key is
/// ALSO non-exporting — a SECOND, DISTINCT KMS key (a separate key id, and the
/// operator SHOULD scope it with a distinct authz policy) custodies it, and rustls
/// drives the handshake signature through that backend (a [`RawEd25519TlsSigner`])
/// so the TLS private key never leaves KMS. `None` keeps the file-backed TLS key.
/// The two KMS keys are independent: neither requires the other, and they are NOT
/// required to differ in code beyond being separate config fields.
pub struct KmsKeySource {
    signer: KmsResponseSigner,
    tls: FileKeySource,
    /// Optional DELEGATED TLS handshake signer (issue #60). `Some` when a distinct
    /// TLS KMS key id is configured; returned from [`KeySource::tls_delegated_signer`]
    /// so the #58 validated build path fails closed on a cert/key mismatch.
    tls_signer: Option<Arc<dyn RawEd25519TlsSigner>>,
}

impl KmsKeySource {
    /// Build a KMS key source from a KMS signing backend and a file source for the
    /// TLS materials (cert chain, TLS key, client-CA roots). No delegated TLS: the
    /// TLS key is read from the file source unchanged.
    pub fn new(backend: Box<dyn KmsEd25519Backend + Send + Sync>, tls: FileKeySource) -> Self {
        KmsKeySource {
            signer: KmsResponseSigner::new(backend),
            tls,
            tls_signer: None,
        }
    }

    /// Build a KMS key source whose TLS handshake is ALSO delegated to a
    /// non-exporting KMS key (issue #60, ADR-MCPS-028 §G): `tls_signer` is a SECOND,
    /// DISTINCT KMS key from `backend` (the object-signing key). The file source
    /// still provides the (public) TLS cert chain and client-CA roots; its TLS *key*
    /// path is NOT consulted (the exclusivity guard forbids an exported `--tls-key`
    /// on this path).
    pub fn new_with_delegated_tls(
        backend: Box<dyn KmsEd25519Backend + Send + Sync>,
        tls: FileKeySource,
        tls_signer: Arc<dyn RawEd25519TlsSigner>,
    ) -> Self {
        KmsKeySource {
            signer: KmsResponseSigner::new(backend),
            tls,
            tls_signer: Some(tls_signer),
        }
    }
}

impl ResponseSigner for KmsKeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.signer.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.signer.response_public_key()
    }
}

impl KeySource for KmsKeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.tls_server_cert_chain()
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        self.tls.tls_server_key()
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.client_ca_roots()
    }

    /// Issue #60 (ADR-MCPS-028 §G): `Some` when a distinct TLS KMS key id was
    /// configured (delegated TLS — the TLS private key never leaves KMS); `None`
    /// keeps the file-backed TLS key. The validated build path (#58) feeds this
    /// signer's public key into the cert↔signer match check, failing closed before
    /// any server starts.
    fn tls_delegated_signer(&self) -> Option<Arc<dyn RawEd25519TlsSigner>> {
        self.tls_signer.clone()
    }
}

#[cfg(test)]
mod tests {
    use mcps_core::b64url_decode;
    use mcps_core::verify_ed25519;
    use mcps_core::SigningKey;

    use std::sync::Arc;

    use super::ed25519_raw_point_from_spki;
    use super::FileKeySource;
    use super::KeyError;
    use super::KeySource;
    use super::KmsEd25519Backend;
    use super::KmsKeySource;
    use super::KmsResponseSigner;
    use super::RawEd25519TlsSigner;
    use super::ResponseSigner;
    use super::ED25519_SPKI_PREFIX;

    /// Build an RFC 8410 Ed25519 SPKI from a raw 32-byte point (what AWS/GCP return).
    fn ed25519_spki_from_raw(raw: &[u8; 32]) -> Vec<u8> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        der
    }

    /// A fake KMS backed by a LOCAL Ed25519 key — stands in for AWS/GCP KMS so the
    /// protocol mapping is provable against the real `mcps-core` verifier with no
    /// network. `sign_raw_ed25519` returns the raw 64 bytes a KMS `Sign` returns
    /// (decoded from `SigningKey::sign`'s Base64URL form).
    struct FakeKms {
        key: SigningKey,
    }
    impl KmsEd25519Backend for FakeKms {
        fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(b64url_decode(&self.key.sign(preimage)).expect("local sig is valid b64url"))
        }
        fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            Ok(ed25519_spki_from_raw(&self.key.public_key().to_bytes()))
        }
    }

    fn test_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[7u8; 32])
    }

    /// LOAD-BEARING: a signature produced through the KMS signer verifies under the
    /// public key the signer reports, using the UNMODIFIED `mcps-core` Ed25519
    /// verifier — proving byte-level protocol compatibility (raw PureEdDSA), and a
    /// tampered preimage is rejected. This is exactly the assertion the emulator/
    /// live lane will run against a real KMS.
    #[test]
    fn kms_signature_verifies_under_mcps_core_verifier() {
        let signer = KmsResponseSigner::new(Box::new(FakeKms { key: test_key() }));
        let preimage = b"mcps canonical response preimage";

        let sig = signer.sign_response(preimage).expect("sign");
        let pubkey = signer.response_public_key().expect("public key");

        verify_ed25519(preimage, &sig, &pubkey).expect("KMS signature must verify under mcps-core");
        assert!(
            verify_ed25519(b"tampered preimage", &sig, &pubkey).is_err(),
            "a signature must NOT verify over a different preimage"
        );
    }

    /// A backend that returns a wrong-length signature (i.e. not a raw 64-byte Ed25519
    /// signature) fails closed — the signer never emits it.
    #[test]
    fn wrong_length_signature_fails_closed() {
        struct ShortSig;
        impl KmsEd25519Backend for ShortSig {
            fn sign_raw_ed25519(&self, _preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
                Ok(vec![0u8; 63])
            }
            fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
                Ok(ed25519_spki_from_raw(&test_key().public_key().to_bytes()))
            }
        }
        let signer = KmsResponseSigner::new(Box::new(ShortSig));
        let err = signer.sign_response(b"x").expect_err("must fail closed");
        assert!(matches!(err, KeyError::Malformed(_)));
    }

    /// A non-Ed25519 / malformed public key (wrong SPKI) fails closed rather than
    /// being treated as an Ed25519 key.
    #[test]
    fn non_ed25519_public_key_fails_closed() {
        // Right length, wrong algorithm prefix (flip the OID's first byte).
        let mut bad = ed25519_spki_from_raw(&[9u8; 32]);
        bad[6] = 0xff;
        assert!(matches!(
            ed25519_raw_point_from_spki(&bad),
            Err(KeyError::Malformed(_))
        ));
        // Wrong length.
        assert!(matches!(
            ed25519_raw_point_from_spki(&[0u8; 10]),
            Err(KeyError::Malformed(_))
        ));
    }

    /// A backend that signs a PRE-HASH of the preimage (the forbidden Ed25519ph /
    /// DIGEST mode) produces a 64-byte signature that PASSES the length check but
    /// does NOT verify over the raw preimage. Finding #138: with verify-before-return
    /// centralized at the seam, `sign_response` itself catches this (fail closed) —
    /// the misconfigured DIGEST KMS key never yields an emitted signature, not even
    /// one that a later external verify would have to reject.
    #[test]
    fn prehash_mode_is_caught_at_the_seam() {
        struct PrehashKms {
            key: SigningKey,
        }
        impl KmsEd25519Backend for PrehashKms {
            fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
                // Sign a DIFFERENT message (a stand-in for "the digest, not the raw
                // bytes"); a real prehash KMS would do the analogous thing.
                let mut digestish = b"DIGEST:".to_vec();
                digestish.extend_from_slice(preimage);
                Ok(b64url_decode(&self.key.sign(&digestish)).expect("b64url"))
            }
            fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
                Ok(ed25519_spki_from_raw(&self.key.public_key().to_bytes()))
            }
        }
        let signer = KmsResponseSigner::new(Box::new(PrehashKms { key: test_key() }));
        let preimage = b"mcps canonical response preimage";
        assert!(
            matches!(
                signer.sign_response(preimage),
                Err(KeyError::Malformed(_))
            ),
            "a prehash/DIGEST signature must fail closed at the seam (it does not \
             verify over the raw preimage under the advertised key)"
        );
    }

    /// Finding #138 / ADR-MCPS-028 §D AT THE SEAM: a backend that returns a
    /// STRUCTURALLY VALID 64-byte Ed25519 signature that does NOT verify under the
    /// public key the same backend advertises (e.g. a future backend that forgot to
    /// self-verify, or one wired to a mismatched key) must be caught by
    /// `KmsResponseSigner::sign_response` itself — the seam — and never emitted. This
    /// is the property `DelegatedResponseSigner` enforces; here it is enforced for
    /// ANY `KmsEd25519Backend`, not only the concrete AWS/GCP ones that self-verify.
    #[test]
    fn mismatched_key_signature_fails_closed_at_the_seam() {
        // The backend signs with one key but advertises a DIFFERENT public key, so
        // the (well-formed, 64-byte) signature cannot verify under what it reports.
        struct MismatchedKms {
            signing_key: SigningKey,
            advertised: SigningKey,
        }
        impl KmsEd25519Backend for MismatchedKms {
            fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
                Ok(b64url_decode(&self.signing_key.sign(preimage)).expect("b64url"))
            }
            fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
                Ok(ed25519_spki_from_raw(&self.advertised.public_key().to_bytes()))
            }
        }
        let signer = KmsResponseSigner::new(Box::new(MismatchedKms {
            signing_key: SigningKey::from_seed_bytes(&[11u8; 32]),
            advertised: SigningKey::from_seed_bytes(&[12u8; 32]),
        }));
        // The signature is a valid 64-byte Ed25519 signature (passes the length
        // check), so only the verify-before-return at the seam can catch it.
        assert!(
            matches!(
                signer.sign_response(b"mcps canonical response preimage"),
                Err(KeyError::Malformed(_))
            ),
            "a 64-byte signature that does not verify under the advertised public key \
             must fail closed at the KmsResponseSigner seam"
        );
    }

    /// A local delegated TLS signer (stand-in for a SECOND KMS key) — used to prove
    /// `tls_delegated_signer()` reflects whether a distinct TLS key was wired.
    struct LocalTlsSigner(SigningKey);
    impl RawEd25519TlsSigner for LocalTlsSigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            Ok(ed25519_spki_from_raw(&self.0.public_key().to_bytes()))
        }
    }

    fn inert_file_source() -> FileKeySource {
        // The delegated path never reads these; the object responses come from the
        // KMS backend and the TLS sign from the delegated signer.
        FileKeySource {
            signing_key_seed_path: "/dev/null".to_string(),
            tls_cert_path: "/dev/null".to_string(),
            tls_key_path: "/dev/null".to_string(),
            client_ca_path: "/dev/null".to_string(),
        }
    }

    /// Issue #60 (test b): without a TLS key id the KMS source delegates NO TLS
    /// signer (`None` → file-backed TLS key); with a distinct TLS KMS key it returns
    /// `Some` — the seam the #58 validated build path consumes.
    #[test]
    fn tls_delegated_signer_is_none_without_tls_key_some_with() {
        let no_tls = KmsKeySource::new(Box::new(FakeKms { key: test_key() }), inert_file_source());
        assert!(
            no_tls.tls_delegated_signer().is_none(),
            "no TLS key id → file-backed TLS path (no delegated signer)"
        );

        let tls_key = SigningKey::from_seed_bytes(&[31u8; 32]);
        let expected_spki = ed25519_spki_from_raw(&tls_key.public_key().to_bytes());
        let with_tls = KmsKeySource::new_with_delegated_tls(
            Box::new(FakeKms { key: test_key() }),
            inert_file_source(),
            Arc::new(LocalTlsSigner(tls_key)),
        );
        let signer = with_tls
            .tls_delegated_signer()
            .expect("a distinct TLS KMS key id → delegated TLS signer");
        assert_eq!(
            signer.tls_public_key_spki_der().unwrap(),
            expected_spki,
            "the delegated signer advertises the TLS key's SPKI (the #58 cert-match basis)"
        );
    }
}
