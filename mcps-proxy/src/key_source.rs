//! `KeySource` — loads the proxy's key material (MCPS-027, ADR-MCPS-014).
//!
//! A sidecar needs three pieces of material: the Ed25519 **signing key** (for
//! signing responses), the **TLS server certificate chain + private key** (to
//! terminate TLS), and the **client-CA trust anchors** (to verify mTLS client
//! certificates). `FileKeySource` loads them from disk; `EnvKeySource` from
//! environment variables. An HSM-backed source is a documented FUTURE
//! implementation of this trait — there is deliberately no stub here.
//!
//! The Ed25519 signing key is a 32-byte seed encoded Base64URL-no-pad (consistent
//! with the rest of MCP-S); `mcps-core` exposes only seed-based construction. The
//! TLS materials are PEM (parsed with rustls-pki-types' `PemObject`).

use std::fs;

use mcps_core::b64url_decode;
use mcps_core::SigningKey;
use mcps_core::VerificationKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

/// Errors loading key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// A source (file/env var) was missing or unreadable.
    #[error("key material not found: {0}")]
    NotFound(String),
    /// Material was present but malformed (bad Base64URL seed, wrong length, no
    /// PEM key, ...).
    #[error("key material malformed: {0}")]
    Malformed(String),
}

/// Response-signing DELEGATION seam (issue #3838, ADR-MCPS-014).
///
/// The proxy signs every response on the way back, but it must NEVER require the
/// raw private key in order to do so. A non-exporting HSM/KMS fundamentally cannot
/// hand out its private key; the only operation it offers is "sign these bytes".
/// `ResponseSigner` is exactly that operation, so a non-exporting backend can drive
/// the full proxy response-signing path:
///
///   * [`sign_response`](ResponseSigner::sign_response) takes the canonical
///     response preimage and returns the Base64URL-no-pad Ed25519 signature —
///     identical to what [`SigningKey::sign`] produces — WITHOUT ever exposing the
///     private seed. The seed (or HSM key handle) stays inside the implementation.
///   * [`response_public_key`](ResponseSigner::response_public_key) returns the
///     PUBLIC verification key, which IS exportable even from an HSM (it is what
///     relying parties verify against). It is derived from / paired with the same
///     private key that `sign_response` uses, so a signature produced by
///     `sign_response` always verifies under this key.
///
/// In-memory implementations ([`SigningKey`], [`FileKeySource`], [`EnvKeySource`])
/// satisfy this by holding the key PRIVATE and signing internally; the HSM/KMS
/// follow-up satisfies it by forwarding to the device. Either way the trait does
/// NOT demand export.
///
/// SCOPE / TRACKED FOLLOW-UP: this change lands ONLY the dependency-free delegation
/// SEAM (this trait, the in-memory impls, and the proxy wiring through it). It does
/// NOT deliver HSM-backed key custody. Still tracked as the follow-up (new crate +
/// device + repin): the concrete PKCS#11 / cloud-KMS `ResponseSigner` adapter, the
/// `--key-source hsm` CLI wiring that selects it, delegated TLS signing via a custom
/// `rustls::sign::SigningKey` (so the TLS private key — still exported through
/// [`KeySource::tls_server_key`] today — also never leaves the device), and a
/// live-device black-box conformance test. Until those land, "the response-signing
/// key never leaves the device" is ENABLED by this seam but only DELIVERED in-memory.
pub trait ResponseSigner {
    /// Sign the canonical response `preimage`, returning the Base64URL-no-pad
    /// Ed25519 signature. The private key never leaves the implementation.
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError>;
    /// The public verification key paired with the signing key. Exportable even
    /// from a non-exporting HSM/KMS; a signature from [`Self::sign_response`]
    /// verifies under it.
    fn response_public_key(&self) -> Result<VerificationKey, KeyError>;
}

/// A raw in-memory [`SigningKey`] is itself a response signer that never surrenders
/// its seed at the trait boundary: it owns the Ed25519 key and signs internally;
/// the seam never asks it to export the seed. This is what keeps every existing
/// `Proxy::new(signing_key, ...)` call site working after `KeySource` stopped
/// exporting the key.
impl ResponseSigner for SigningKey {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        Ok(self.sign(preimage))
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        Ok(self.public_key())
    }
}

/// Loads the proxy's key material. Each accessor is fallible and never panics.
///
/// Issue #3838: the response-signing key is exposed ONLY through the
/// [`ResponseSigner`] supertrait ([`sign_response`](ResponseSigner::sign_response)
/// / [`response_public_key`](ResponseSigner::response_public_key)) — there is no
/// `signing_key()` export on the trait, so a non-exporting HSM/KMS backend can
/// implement `KeySource` with NO stub methods. The TLS server key
/// ([`tls_server_key`](KeySource::tls_server_key)) is STILL an export accessor:
/// that is intentional and deliberately confined to a later change — issue #3838
/// targets the RESPONSE-signing key only. Delegated TLS signing — fronting a
/// non-exporting device behind a custom `rustls::sign::SigningKey` so the TLS
/// private key also never leaves the device — is part of the HSM/KMS-adapter
/// follow-up; the existing TLS path is unchanged here.
pub trait KeySource: ResponseSigner {
    /// The TLS server certificate chain (leaf first).
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError>;
    /// The TLS server private key. (Export accessor — see the trait note on the
    /// #3838 boundary and the delegated-TLS-signing follow-up.)
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError>;
    /// The client-CA trust anchors used to verify mTLS client certificates.
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError>;
}

/// A boxed `dyn KeySource` is itself a [`ResponseSigner`] (issue #3838): it forwards
/// to the contained source, which signs internally. This lets the production wiring
/// hand the proxy a `Box<dyn KeySource>` AS the response signer WITHOUT ever calling
/// an export accessor — the boxed source's `sign_response` is the delegation. (The
/// stdlib does not auto-upcast `Box<dyn KeySource>` to `Box<dyn ResponseSigner>` on
/// stable Rust, so this explicit forward is what bridges the supertrait at the boxed
/// trait object.)
impl ResponseSigner for Box<dyn KeySource> {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        (**self).sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        (**self).response_public_key()
    }
}

/// Decode a Base64URL-no-pad 32-byte Ed25519 seed into a [`SigningKey`].
///
/// MCPS-076 (audit gap G-3) secret hygiene: every OWNED temporary that holds the
/// raw private seed is wrapped in [`zeroize::Zeroizing`], so its bytes are scrubbed
/// from memory the instant it drops. `SigningKey::from_seed_bytes` only BORROWS the
/// seed (the resulting dalek key is itself `ZeroizeOnDrop` via the `zeroize`
/// feature), so the key is built first and the `Zeroizing` temporaries then drop
/// scrubbed at the end of this function.
fn signing_key_from_seed_b64url(seed_b64url: &str) -> Result<SigningKey, KeyError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        b64url_decode(seed_b64url.trim())
            .map_err(|_| KeyError::Malformed("signing-key seed is not Base64URL".to_string()))?,
    );
    if bytes.len() != 32 {
        return Err(KeyError::Malformed(
            "signing-key seed is not 32 bytes".to_string(),
        ));
    }
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_seed_bytes(&seed))
}

/// Parse a PEM certificate chain from bytes.
fn certs_from_pem(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, KeyError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KeyError::Malformed(format!("{what}: {e}")))?;
    if certs.is_empty() {
        return Err(KeyError::Malformed(format!("{what}: no certificates in PEM")));
    }
    Ok(certs)
}

/// Parse a single PEM private key from bytes.
fn key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, KeyError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| KeyError::Malformed(format!("tls key: {e}")))
}

/// Loads key material from files on disk.
#[derive(Debug, Clone)]
pub struct FileKeySource {
    /// Path to a file containing the Base64URL-no-pad Ed25519 signing-key seed.
    pub signing_key_seed_path: String,
    /// Path to the PEM TLS server certificate chain.
    pub tls_cert_path: String,
    /// Path to the PEM TLS server private key.
    pub tls_key_path: String,
    /// Path to the PEM client-CA trust anchors.
    pub client_ca_path: String,
}

impl FileKeySource {
    fn read(&self, path: &str) -> Result<Vec<u8>, KeyError> {
        fs::read(path).map_err(|e| KeyError::NotFound(format!("{path}: {e}")))
    }

    /// Load the Ed25519 signing key from the seed file. This is an INHERENT
    /// (non-trait) helper, NOT part of the [`KeySource`]/[`ResponseSigner`]
    /// contract — issue #3838 removed key export from the trait so a non-exporting
    /// HSM/KMS backend can satisfy it. `FileKeySource` owns the file holding the
    /// raw seed, so it CAN load the key; it routes its own [`ResponseSigner`] impl
    /// through here and signs internally. Tests that need the loaded key call this
    /// on the concrete type.
    pub fn signing_key(&self) -> Result<SigningKey, KeyError> {
        // MCPS-076: the file holds the raw private seed (Base64URL text). Hold the
        // file bytes and the decoded text in `Zeroizing` so both are scrubbed on
        // drop; only the borrowed dalek key (itself `ZeroizeOnDrop`) outlives them.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(self.read(&self.signing_key_seed_path)?);
        // Borrow the seed bytes as &str — NO owned copy. `bytes.to_vec()` would clone
        // the secret into a non-`Zeroizing` `Vec` that `String::from_utf8` then owns,
        // so a UTF-8 error would drop an UNSCRUBBED copy of the seed. `str::from_utf8`
        // borrows; on error its `Utf8Error` carries no payload, so the secret stays in
        // `bytes` (Zeroizing) and is scrubbed on drop. The b64url decode inside
        // `signing_key_from_seed_b64url` wraps its own decoded bytes in `Zeroizing`.
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| KeyError::Malformed("signing-key seed is not UTF-8".to_string()))?;
        signing_key_from_seed_b64url(text)
    }
}

/// `FileKeySource` signs internally (issue #3838): it loads its seed-backed
/// [`SigningKey`] and forwards to that key's [`ResponseSigner`] impl, so the seed
/// is never exported across the trait boundary. The loaded key (and every seed
/// temporary inside [`FileKeySource::signing_key`]) is `Zeroizing`/`ZeroizeOnDrop`,
/// so it is scrubbed at the end of each call.
impl ResponseSigner for FileKeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.signing_key()?.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.signing_key()?.response_public_key()
    }
}

impl KeySource for FileKeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(&self.read(&self.tls_cert_path)?, "tls cert chain")
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        key_from_pem(&self.read(&self.tls_key_path)?)
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(&self.read(&self.client_ca_path)?, "client CA")
    }
}

/// Loads key material from environment variables. Each field is the NAME of the
/// env var to read (the signing-key var holds the Base64URL seed; the others hold
/// PEM text).
///
/// MCPS-076 (audit gap G-3): DEV / CI ONLY, and gated behind the NON-DEFAULT
/// `dev_env_key_source` cargo feature — this type does NOT exist in a production
/// build. Environment variables are visible to the whole process tree, can leak
/// via crash dumps, `ps e`, `/proc/<pid>/environ`, and container/orchestrator
/// inspection, and are easy to log accidentally. Production deployments must use
/// [`FileKeySource`] (read once, scrubbed), or a future stdin/fd-injection or
/// non-exporting HSM/KMS source. Even in the dev build, the seed value is held in
/// [`zeroize::Zeroizing`] and the env var is REMOVED immediately after reading
/// (defense in depth). `KeyError` values carry only the env-var NAME and the parse
/// failure — never the secret bytes — so they are safe to log.
#[cfg(feature = "dev_env_key_source")]
#[derive(Debug, Clone)]
pub struct EnvKeySource {
    /// Env var holding the Base64URL-no-pad Ed25519 signing-key seed.
    pub signing_key_seed_var: String,
    /// Env var holding the PEM TLS server certificate chain.
    pub tls_cert_var: String,
    /// Env var holding the PEM TLS server private key.
    pub tls_key_var: String,
    /// Env var holding the PEM client-CA trust anchors.
    pub client_ca_var: String,
}

#[cfg(feature = "dev_env_key_source")]
impl EnvKeySource {
    /// Read an env var's value, returned in [`zeroize::Zeroizing`] so it is
    /// scrubbed when the caller drops it.
    ///
    /// This does NOT mutate the process environment (issue #25). `std::env::remove_var`
    /// is unsound in a multi-threaded program — the standard library now documents
    /// it as `unsafe` for exactly this reason (a concurrent `getenv`/`setenv` in
    /// another thread is a data race). Child-process secret isolation is NOT this
    /// function's job and never relied on the global removal: the inner server is
    /// launched with [`crate::inner_launch::InnerLaunchConfig`], which by default
    /// inherits NO environment and passes only an explicit allowlist, so a key in
    /// the proxy's own env is never forwarded regardless of whether it is removed
    /// here. (`EnvKeySource` is `dev_env_key_source`-gated — dev/CI only — and a
    /// production deployment uses a file/PKCS#11 source.)
    fn read(&self, var: &str) -> Result<Zeroizing<String>, KeyError> {
        let value = std::env::var(var).map_err(|_| KeyError::NotFound(format!("env var {var}")))?;
        Ok(Zeroizing::new(value))
    }

    /// Load the Ed25519 signing key from the seed env var. INHERENT (non-trait)
    /// helper — see [`FileKeySource::signing_key`] for why key export is not on the
    /// [`KeySource`]/[`ResponseSigner`] contract. The env source owns the var, so it
    /// CAN load the key; its [`ResponseSigner`] impl routes through here.
    pub fn signing_key(&self) -> Result<SigningKey, KeyError> {
        signing_key_from_seed_b64url(&self.read(&self.signing_key_seed_var)?)
    }
}

/// `EnvKeySource` (dev/CI only) signs internally just like [`FileKeySource`]:
/// it loads its seed-backed [`SigningKey`] and forwards to that key's signer, so
/// the seed is never exported across the trait boundary.
#[cfg(feature = "dev_env_key_source")]
impl ResponseSigner for EnvKeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.signing_key()?.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.signing_key()?.response_public_key()
    }
}

#[cfg(feature = "dev_env_key_source")]
impl KeySource for EnvKeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(self.read(&self.tls_cert_var)?.as_bytes(), "tls cert chain")
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        key_from_pem(self.read(&self.tls_key_var)?.as_bytes())
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(self.read(&self.client_ca_var)?.as_bytes(), "client CA")
    }
}
