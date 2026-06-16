//! Delegated TLS handshake signing (ADR-MCPS-028 §G).
//!
//! Closes the last key-export gap: even on the PKCS#11 / KMS object-signing paths,
//! the TLS *server* private key was still read from a file and handed to rustls
//! (`KeySource::tls_server_key`). This module lets the TLS handshake be signed by a
//! non-exporting device/KMS instead — a custom [`rustls::sign::SigningKey`] whose
//! signing operation forwards the to-be-signed handshake transcript to a
//! [`RawEd25519TlsSigner`] (a PKCS#11 token or AWS/GCP KMS), so the TLS private key
//! never leaves the device.
//!
//! Ed25519 only: rustls calls [`rustls::sign::Signer::sign`] with the full message
//! to be signed and, for `SignatureScheme::ED25519`, expects a PureEdDSA signature
//! over those exact bytes — precisely the "sign raw bytes with Ed25519" primitive
//! the KMS/PKCS#11 backends expose. The TLS server certificate MUST therefore be an
//! Ed25519 certificate whose key lives in the device/KMS. A non-Ed25519 TLS cert is
//! a deployment error (the handshake fails closed: no scheme is offered).
//!
//! The TLS key is a SEPARATE key from the response-signing key — both can be
//! non-exporting, but they are distinct credentials (distinct KMS key ids / token
//! objects). This module is transport-agnostic: it only needs the raw-sign closure.

use std::sync::Arc;

use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::sign::Signer;
use rustls::sign::SigningKey;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls_pki_types::CertificateDer;

use crate::key_source::KeyError;

/// The single operation a delegated TLS signer needs: a PureEdDSA (Ed25519, no
/// pre-hash) signature over the raw `message`, returning the raw 64-byte signature.
/// Implemented by the PKCS#11 token (CKM_EDDSA) and the AWS/GCP KMS backends
/// (`Sign` / `asymmetricSign` over RAW data) — the same primitive used for response
/// signing, but keyed by the TLS certificate's key.
pub trait RawEd25519TlsSigner: Send + Sync {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

const ED25519_SIGNATURE_LEN: usize = 64;

/// A [`rustls::sign::SigningKey`] that delegates Ed25519 handshake signing to a
/// non-exporting [`RawEd25519TlsSigner`].
pub struct DelegatedEd25519SigningKey {
    signer: Arc<dyn RawEd25519TlsSigner>,
}

impl std::fmt::Debug for DelegatedEd25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material or backend internals.
        f.write_str("DelegatedEd25519SigningKey(<non-exporting Ed25519>)")
    }
}

impl DelegatedEd25519SigningKey {
    pub fn new(signer: Arc<dyn RawEd25519TlsSigner>) -> Self {
        DelegatedEd25519SigningKey { signer }
    }
}

impl SigningKey for DelegatedEd25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Only Ed25519 — fail closed (no signer) if the peer does not offer it, so a
        // non-Ed25519 negotiation never silently proceeds with the wrong algorithm.
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(DelegatedEd25519Signer {
                signer: self.signer.clone(),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct DelegatedEd25519Signer {
    signer: Arc<dyn RawEd25519TlsSigner>,
}

impl std::fmt::Debug for DelegatedEd25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DelegatedEd25519Signer(<non-exporting Ed25519>)")
    }
}

impl Signer for DelegatedEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sig = self
            .signer
            .sign_tls_ed25519(message)
            .map_err(|e| rustls::Error::General(format!("delegated TLS Ed25519 sign: {e}")))?;
        // A wrong-length signature would corrupt the handshake; fail closed.
        if sig.len() != ED25519_SIGNATURE_LEN {
            return Err(rustls::Error::General(format!(
                "delegated TLS Ed25519 sign returned {} bytes; expected {ED25519_SIGNATURE_LEN}",
                sig.len()
            )));
        }
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A fixed-certificate [`ResolvesServerCert`] pairing the (public) Ed25519 server
/// certificate chain with a [`DelegatedEd25519SigningKey`]. Used via
/// `ServerConfig::builder(...).with_cert_resolver(...)` so rustls drives the
/// handshake signature through the device/KMS.
#[derive(Debug)]
pub struct DelegatedCertResolver {
    certified: Arc<CertifiedKey>,
}

impl DelegatedCertResolver {
    /// Pair the server certificate chain (public; loaded from a file) with the
    /// delegated signer for its key.
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
    ) -> Arc<Self> {
        let key = Arc::new(DelegatedEd25519SigningKey::new(signer));
        Arc::new(DelegatedCertResolver {
            certified: Arc::new(CertifiedKey::new(cert_chain, key)),
        })
    }
}

impl ResolvesServerCert for DelegatedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

#[cfg(test)]
mod tests {
    use mcps_core::b64url_decode;
    use mcps_core::SigningKey as McpsSigningKey;

    use super::*;

    /// A local-key delegated signer (stands in for the device/KMS): signs the raw
    /// message with a local Ed25519 key, exactly as a KMS RAW `Sign` would.
    struct LocalEd25519(McpsSigningKey);
    impl RawEd25519TlsSigner for LocalEd25519 {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
        }
    }

    #[test]
    fn offers_ed25519_only() {
        let key = DelegatedEd25519SigningKey::new(Arc::new(LocalEd25519(
            McpsSigningKey::from_seed_bytes(&[1u8; 32]),
        )));
        assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_some());
        // No Ed25519 on offer → fail closed (no signer), never a wrong algorithm.
        assert!(key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none());
    }

    #[test]
    fn signer_scheme_is_ed25519_and_signature_is_64_bytes() {
        let key = DelegatedEd25519SigningKey::new(Arc::new(LocalEd25519(
            McpsSigningKey::from_seed_bytes(&[2u8; 32]),
        )));
        let signer = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("signer");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
        let sig = signer.sign(b"tls handshake transcript").expect("sign");
        assert_eq!(sig.len(), 64);
    }

    /// A wrong-length raw signature (a misconfigured non-Ed25519 backend) corrupts
    /// the handshake — the signer fails closed rather than emitting it.
    #[test]
    fn wrong_length_signature_fails_closed() {
        struct ShortSig;
        impl RawEd25519TlsSigner for ShortSig {
            fn sign_tls_ed25519(&self, _m: &[u8]) -> Result<Vec<u8>, KeyError> {
                Ok(vec![0u8; 63])
            }
        }
        let key = DelegatedEd25519SigningKey::new(Arc::new(ShortSig));
        let signer = key.choose_scheme(&[SignatureScheme::ED25519]).unwrap();
        assert!(signer.sign(b"x").is_err());
    }
}
