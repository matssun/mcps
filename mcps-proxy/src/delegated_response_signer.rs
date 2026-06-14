//! `DelegatedResponseSigner` — a non-exporting reference [`ResponseSigner`]
//! (issue #3838, ADR-MCPS-014).
//!
//! This is a REAL implementation of the response-signing delegation seam that, by
//! construction, CANNOT export its private key — it owns only an opaque signing
//! callback plus the paired public [`VerificationKey`]. It is the in-tree proof
//! that a backend whose key never leaves the device (an HSM/KMS, or here a closure
//! that has captured a key the caller can no longer reach) drives the proxy's full
//! response-signing path exactly like an in-memory [`mcps_core::SigningKey`] does.
//!
//! It is NOT a mock: the callback performs a genuine Ed25519 signature, and a
//! signature it produces verifies under [`Self::response_public_key`]. It is also
//! NOT the production HSM/KMS adapter (that is the tracked follow-up — a separate
//! crate fronting a real device); it is the dependency-free reference that exercises
//! and pins the seam contract.

use mcps_core::verify_ed25519;
use mcps_core::VerificationKey;

use crate::key_source::KeyError;
use crate::key_source::ResponseSigner;

/// A [`ResponseSigner`] that holds ONLY a signing callback and the paired public
/// key — never the private key in any extractable form.
///
/// The signing capability is a boxed `Fn(&[u8]) -> Result<String, KeyError>`: it
/// may have captured a private key, a device handle, or a network session, but the
/// `DelegatedResponseSigner` exposes no accessor to recover any of that. The only
/// operations are "sign these bytes" and "hand me the public key" — precisely the
/// non-exporting contract a real HSM/KMS offers.
pub struct DelegatedResponseSigner {
    sign_fn: Box<dyn Fn(&[u8]) -> Result<String, KeyError> + Send + Sync>,
    public_key: VerificationKey,
}

impl DelegatedResponseSigner {
    /// Build a delegated signer from an opaque signing callback and the public key
    /// paired with whatever private key the callback signs under. The caller is
    /// responsible for the pairing (a real device returns its own public key); a
    /// signature from `sign_fn` must verify under `public_key`.
    pub fn new(
        sign_fn: Box<dyn Fn(&[u8]) -> Result<String, KeyError> + Send + Sync>,
        public_key: VerificationKey,
    ) -> Self {
        DelegatedResponseSigner {
            sign_fn,
            public_key,
        }
    }
}

impl ResponseSigner for DelegatedResponseSigner {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        // Enforce the seam contract: the opaque callback is alg-agnostic, so do
        // NOT trust whatever bytes it returns. The signature it produces MUST be a
        // valid Ed25519 signature over the EXACT canonical preimage that verifies
        // under the advertised public key. This fails closed on a malformed /
        // wrong-length / wrong-algorithm signature and on a key-pairing mismatch
        // (e.g. a future KMS/PKCS#11 adapter wired to the wrong key), so the proxy
        // never emits a response signature that its own advertised key cannot
        // verify (issue #22, cluster 3). One verify per response sign — negligible.
        let signature = (self.sign_fn)(preimage)?;
        verify_ed25519(preimage, &signature, &self.public_key).map_err(|_| {
            KeyError::Malformed(
                "delegated signer produced a signature that does not verify as Ed25519 under its \
                 advertised public key"
                    .to_string(),
            )
        })?;
        Ok(signature)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        Ok(self.public_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::DelegatedResponseSigner;
    use crate::key_source::KeyError;
    use crate::key_source::ResponseSigner;
    use mcps_core::verify_ed25519;
    use mcps_core::SigningKey;

    const SEED: [u8; 32] = [9u8; 32];

    /// A signature produced through the delegated (non-exporting) callback verifies
    /// under the public key the signer advertises — the core seam contract.
    #[test]
    fn delegated_signature_verifies_under_advertised_public_key() {
        // The private key is captured by the closure and is unreachable thereafter;
        // only the public key is handed to the signer.
        let key = SigningKey::from_seed_bytes(&SEED);
        let public_key = key.public_key();
        let signer = DelegatedResponseSigner::new(
            Box::new(move |preimage| Ok(key.sign(preimage))),
            public_key,
        );

        let preimage = b"canonical response preimage";
        let signature = signer.sign_response(preimage).expect("delegated sign");
        let advertised = signer.response_public_key().expect("public key");

        assert!(
            verify_ed25519(preimage, &signature, &advertised).is_ok(),
            "delegated signature must verify under the advertised public key"
        );
    }

    /// Issue #22: a callback that returns a structurally valid-looking but WRONG
    /// signature (here, a signature made by a DIFFERENT key than the advertised
    /// public key) must fail closed — `sign_response` verifies the callback output
    /// under the advertised key before returning, so a key-pairing mismatch never
    /// yields a signature the proxy's own key cannot verify.
    #[test]
    fn signature_not_matching_advertised_key_fails_closed() {
        let wrong_key = SigningKey::from_seed_bytes(&[7u8; 32]);
        let advertised = SigningKey::from_seed_bytes(&SEED).public_key();
        // The callback signs with `wrong_key`, but the signer advertises a
        // different public key — the produced signature cannot verify under it.
        let signer = DelegatedResponseSigner::new(
            Box::new(move |preimage| Ok(wrong_key.sign(preimage))),
            advertised,
        );
        assert!(
            matches!(
                signer.sign_response(b"canonical preimage").unwrap_err(),
                KeyError::Malformed(_)
            ),
            "a signature that does not verify under the advertised key must fail closed"
        );
    }

    /// Issue #22: a callback that returns non-Ed25519 / malformed bytes (not a
    /// valid signature at all) must fail closed rather than propagate.
    #[test]
    fn malformed_callback_signature_fails_closed() {
        let advertised = SigningKey::from_seed_bytes(&SEED).public_key();
        let signer = DelegatedResponseSigner::new(
            Box::new(|_preimage| Ok("not-a-real-ed25519-signature".to_string())),
            advertised,
        );
        assert!(matches!(
            signer.sign_response(b"x").unwrap_err(),
            KeyError::Malformed(_)
        ));
    }

    /// A non-exporting backend that is unavailable fails closed: the seam propagates
    /// the `KeyError` rather than producing a bogus signature.
    #[test]
    fn delegated_sign_failure_propagates() {
        let public_key = SigningKey::from_seed_bytes(&SEED).public_key();
        let signer = DelegatedResponseSigner::new(
            Box::new(|_preimage| Err(KeyError::NotFound("device offline".to_string()))),
            public_key,
        );
        assert!(matches!(
            signer.sign_response(b"x").unwrap_err(),
            KeyError::NotFound(_)
        ));
    }
}
