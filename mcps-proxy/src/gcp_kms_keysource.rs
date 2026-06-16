//! Native GCP Cloud KMS Ed25519 response signer (ADR-MCPS-028 §C).
//!
//! A non-exporting [`KmsEd25519Backend`] backed by GCP Cloud KMS over blocking
//! HTTPS (`ureq`) with an OAuth2 bearer token. The response-signing key lives in
//! Cloud KMS and is NEVER exported; the adapter uses ONLY two operations —
//! `cryptoKeyVersions.getPublicKey` and `cryptoKeyVersions.asymmetricSign` — against
//! an `EC_SIGN_ED25519` key version (raw `data`, NOT `digest`; PureEdDSA, no
//! pre-hash). As with the AWS adapter (ADR-028 §B.1), the async google-cloud SDK /
//! tokio stack is intentionally NOT used (ADR-MCPS-018 lean-sync firewall); the
//! OCSP/AWS blocking-`ureq` path is the model.
//!
//! Credentials are an OAuth2 access token from a NARROW, explicit set of sources
//! ([`GcpAccessTokenSource`]): an operator-supplied token (`MCPS_GCP_ACCESS_TOKEN`)
//! or the GCE/GKE metadata server (workload identity). The service-account
//! JWT-file→token exchange (which needs RSA signing) is a deliberately deferred
//! follow-up, not a hidden default.
//!
//! Fail-closed posture (ADR-MCPS-028 §D): a key version whose algorithm is not
//! `EC_SIGN_ED25519`, or a public key that is not an RFC 8410 Ed25519 SPKI, is
//! rejected at construction; EVERY signature is verified locally against the
//! advertised public key (under the unmodified `mcps-core` verifier) BEFORE it is
//! emitted — a non-verifying signature is an error, never returned.

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mcps_core::b64url_encode;
use mcps_core::verify_ed25519;
use mcps_core::VerificationKey;
use zeroize::Zeroizing;

use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::KeyError;
use crate::kms_keysource::ed25519_raw_point_from_spki;
use crate::kms_keysource::KmsEd25519Backend;

/// The only Cloud KMS key algorithm this adapter accepts.
const ALGORITHM_ED25519: &str = "EC_SIGN_ED25519";
const ED25519_SIGNATURE_LEN: usize = 64;
/// Default Cloud KMS + metadata-server endpoints (overridable for emulators/tests).
const DEFAULT_KMS_ENDPOINT: &str = "https://cloudkms.googleapis.com";
const DEFAULT_METADATA_ENDPOINT: &str = "http://metadata.google.internal";
/// Refresh a metadata-server token this long before its stated expiry.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// MANDATORY per-request network timeout. The serve loop is blocking, so an
/// unbounded fetch (stalled connect/TLS handshake) would wedge the serving thread
/// indefinitely; every `ureq` call below carries this (mirrors the AWS/OCSP paths).
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on an HTTP *error* body read for diagnostics — never an unbounded read.
const MAX_ERROR_BODY_BYTES: u64 = 8 * 1024;

/// GCP Cloud KMS connection configuration. `key_version_name` is the full resource
/// path `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`;
/// `endpoint` overrides the default Cloud KMS host for an emulator/test endpoint.
pub struct GcpKmsConfig {
    pub key_version_name: String,
    pub endpoint: Option<String>,
}

/// A source of a currently-valid OAuth2 access token (bearer). Kept narrow and
/// explicit (ADR-MCPS-028 credential scope) — no silent application-default-
/// credentials discovery chain.
pub(crate) trait GcpAccessTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError>;
}

/// An operator-supplied access token read from `MCPS_GCP_ACCESS_TOKEN`. The
/// operator is responsible for refreshing it (tokens are ~1h); documented, not
/// silently managed.
pub(crate) struct EnvAccessTokenSource;

impl GcpAccessTokenSource for EnvAccessTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
        match std::env::var("MCPS_GCP_ACCESS_TOKEN") {
            Ok(t) if !t.is_empty() => Ok(Zeroizing::new(t)),
            _ => Err(KeyError::NotFound(
                "gcp-kms: MCPS_GCP_ACCESS_TOKEN not set".to_string(),
            )),
        }
    }
}

/// The GCE/GKE metadata server (workload identity). Fetches a token and caches it
/// until shortly before its stated expiry.
pub(crate) struct MetadataServerTokenSource {
    agent: ureq::Agent,
    endpoint: String,
    cache: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: Zeroizing<String>,
    expires_at: SystemTime,
}

impl MetadataServerTokenSource {
    pub(crate) fn new(endpoint: Option<String>) -> Self {
        MetadataServerTokenSource {
            agent: ureq::AgentBuilder::new().build(),
            endpoint: endpoint.unwrap_or_else(|| DEFAULT_METADATA_ENDPOINT.to_string()),
            cache: Mutex::new(None),
        }
    }
}

impl GcpAccessTokenSource for MetadataServerTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
        let now = SystemTime::now();
        {
            let cache = self
                .cache
                .lock()
                .map_err(|e| KeyError::NotFound(format!("gcp-kms: token cache poisoned: {e}")))?;
            if let Some(c) = cache.as_ref() {
                if now + TOKEN_REFRESH_MARGIN < c.expires_at {
                    return Ok(c.token.clone());
                }
            }
        }
        let url = format!(
            "{}/computeMetadata/v1/instance/service-account/default/token",
            self.endpoint
        );
        let body = match self
            .agent
            .get(&url)
            .set("Metadata-Flavor", "Google")
            .timeout(NETWORK_TIMEOUT)
            .call()
        {
            Ok(resp) => {
                let mut buf = String::new();
                resp.into_reader()
                    .take(64 * 1024)
                    .read_to_string(&mut buf)
                    .map_err(|e| KeyError::NotFound(format!("gcp-kms: read token: {e}")))?;
                buf
            }
            Err(e) => {
                return Err(KeyError::NotFound(format!(
                    "gcp-kms: metadata-server token fetch: {e}"
                )))
            }
        };
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| KeyError::Malformed(format!("gcp-kms: token JSON: {e}")))?;
        let token = v
            .get("access_token")
            .and_then(|s| s.as_str())
            .ok_or_else(|| KeyError::Malformed("gcp-kms: token has no access_token".to_string()))?;
        let expires_in = v.get("expires_in").and_then(|s| s.as_u64()).unwrap_or(0);
        let token = Zeroizing::new(token.to_string());
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| KeyError::NotFound(format!("gcp-kms: token cache poisoned: {e}")))?;
        *cache = Some(CachedToken {
            token: token.clone(),
            expires_at: now + Duration::from_secs(expires_in),
        });
        Ok(token)
    }
}

/// The blocking-HTTPS seam to Cloud KMS: the two KMS operations as raw-JSON-body
/// calls. A trait so the adapter's parsing + verify-before-return logic is
/// unit-testable with a local-key fake and no network.
pub(crate) trait GcpKmsTransport {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError>;
    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// Production [`GcpKmsTransport`]: bearer-authed `ureq` (rustls HTTPS).
pub(crate) struct UreqGcpClient {
    agent: ureq::Agent,
    token_source: Box<dyn GcpAccessTokenSource + Send + Sync>,
    sign_url: String,
    public_key_url: String,
}

impl UreqGcpClient {
    pub(crate) fn new(
        token_source: Box<dyn GcpAccessTokenSource + Send + Sync>,
        config: &GcpKmsConfig,
    ) -> Self {
        let base = config
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_KMS_ENDPOINT.to_string());
        let name = &config.key_version_name;
        UreqGcpClient {
            agent: ureq::AgentBuilder::new().build(),
            token_source,
            sign_url: format!("{base}/v1/{name}:asymmetricSign"),
            public_key_url: format!("{base}/v1/{name}/publicKey"),
        }
    }

    /// The `Authorization` header value, held in `Zeroizing` so the bearer token is
    /// scrubbed from memory on drop (repo secret-hygiene posture).
    fn bearer(&self) -> Result<Zeroizing<String>, KeyError> {
        Ok(Zeroizing::new(format!(
            "Bearer {}",
            self.token_source.access_token()?.as_str()
        )))
    }
}

impl GcpKmsTransport for UreqGcpClient {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
        let auth = self.bearer()?;
        match self
            .agent
            .get(&self.public_key_url)
            .set("Authorization", auth.as_str())
            .timeout(NETWORK_TIMEOUT)
            .call()
        {
            Ok(resp) => read_body(resp),
            Err(ureq::Error::Status(code, resp)) => Err(KeyError::NotFound(format!(
                "gcp-kms: getPublicKey HTTP {code}: {}",
                read_error_body(resp)
            ))),
            Err(e) => Err(KeyError::NotFound(format!("gcp-kms: getPublicKey: {e}"))),
        }
    }

    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        let auth = self.bearer()?;
        match self
            .agent
            .post(&self.sign_url)
            .set("Authorization", auth.as_str())
            .set("Content-Type", "application/json")
            .timeout(NETWORK_TIMEOUT)
            .send_bytes(body)
        {
            Ok(resp) => read_body(resp),
            Err(ureq::Error::Status(code, resp)) => Err(KeyError::NotFound(format!(
                "gcp-kms: asymmetricSign HTTP {code}: {}",
                read_error_body(resp)
            ))),
            Err(e) => Err(KeyError::NotFound(format!("gcp-kms: asymmetricSign: {e}"))),
        }
    }
}

fn read_body(resp: ureq::Response) -> Result<Vec<u8>, KeyError> {
    let mut buf = Vec::new();
    resp.into_reader()
        .take(256 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| KeyError::NotFound(format!("gcp-kms: read response: {e}")))?;
    Ok(buf)
}

/// Read a bounded, lossy string from an HTTP *error* response body (diagnostics
/// only). An emulator/overridden endpoint could otherwise return an arbitrarily
/// large body; cap it rather than `into_string()`'s unbounded read.
fn read_error_body(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_ERROR_BODY_BYTES)
        .read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The `asymmetricSign` request body for an Ed25519 (`EC_SIGN_ED25519`) key — raw
/// `data` (PureEdDSA), never `digest`.
fn sign_request_body(preimage: &[u8]) -> Vec<u8> {
    serde_json::json!({ "data": STANDARD.encode(preimage) })
        .to_string()
        .into_bytes()
}

/// Strip a PEM wrapper to the base64 body and standard-decode it to DER.
fn spki_der_from_pem(pem: &str) -> Result<Vec<u8>, KeyError> {
    let mut b64 = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            in_body = true;
        } else if t.starts_with("-----END") {
            break;
        } else if in_body {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err(KeyError::Malformed(
            "gcp-kms: public-key PEM has no body".to_string(),
        ));
    }
    STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: PEM base64: {e}")))
}

/// Parse a `getPublicKey` response: `algorithm` MUST be `EC_SIGN_ED25519` and `pem`
/// is the RFC 8410 Ed25519 SPKI. Fails closed on any other algorithm so a
/// non-Ed25519 key version can never be admitted.
fn parse_public_key_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: getPublicKey JSON: {e}")))?;
    let algorithm = v
        .get("algorithm")
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("gcp-kms: getPublicKey has no algorithm".to_string()))?;
    if algorithm != ALGORITHM_ED25519 {
        return Err(KeyError::Malformed(format!(
            "gcp-kms: key algorithm is '{algorithm}', not {ALGORITHM_ED25519}; the KMS key MUST be \
             an Ed25519 key"
        )));
    }
    let pem = v
        .get("pem")
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("gcp-kms: getPublicKey has no pem".to_string()))?;
    spki_der_from_pem(pem)
}

/// Parse an `asymmetricSign` response: `signature` is the standard-base64 raw
/// Ed25519 signature.
fn parse_sign_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: asymmetricSign JSON: {e}")))?;
    let sig_b64 = v.get("signature").and_then(|s| s.as_str()).ok_or_else(|| {
        KeyError::Malformed("gcp-kms: asymmetricSign response has no signature".to_string())
    })?;
    STANDARD
        .decode(sig_b64)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: signature base64: {e}")))
}

/// A non-exporting [`KmsEd25519Backend`] backed by GCP Cloud KMS.
pub struct GcpKmsEd25519Backend {
    transport: Box<dyn GcpKmsTransport + Send + Sync>,
    spki_der: Vec<u8>,
    verify_key: VerificationKey,
}

impl GcpKmsEd25519Backend {
    /// Build over an explicit transport — fetches and validates the public key once
    /// (Ed25519 SPKI, correct algorithm) and caches it for verify-before-return.
    pub(crate) fn with_transport(
        transport: Box<dyn GcpKmsTransport + Send + Sync>,
    ) -> Result<Self, KeyError> {
        let resp = transport.get_public_key()?;
        let spki_der = parse_public_key_response(&resp)?;
        let raw = ed25519_raw_point_from_spki(&spki_der)?;
        let verify_key = VerificationKey::from_bytes(&raw).map_err(|e| {
            KeyError::Malformed(format!("gcp-kms: invalid Ed25519 public key: {e}"))
        })?;
        Ok(GcpKmsEd25519Backend {
            transport,
            spki_der,
            verify_key,
        })
    }

    /// Build a production GCP Cloud KMS backend (ureq HTTPS + bearer token).
    /// `use_metadata_server` selects the workload-identity metadata token source;
    /// otherwise an operator-supplied `MCPS_GCP_ACCESS_TOKEN` is used.
    pub fn new(config: &GcpKmsConfig, use_metadata_server: bool) -> Result<Self, KeyError> {
        let token_source: Box<dyn GcpAccessTokenSource + Send + Sync> = if use_metadata_server {
            Box::new(MetadataServerTokenSource::new(None))
        } else {
            Box::new(EnvAccessTokenSource)
        };
        let client = UreqGcpClient::new(token_source, config);
        Self::with_transport(Box::new(client))
    }

    /// TEST-ONLY (issue #61): build a backend over an in-memory FAKE Cloud KMS
    /// transport backed by the LOCAL Ed25519 key with the given 32-byte `seed`, so an
    /// integration test (`tests/tls_test.rs`) can drive the full delegated-TLS mTLS
    /// handshake against a GCP backend with NO network and NO GCP credentials. The
    /// fake transport answers `getPublicKey` with the key's RFC 8410 Ed25519 SPKI
    /// (PEM-wrapped) and `asymmetricSign` with a PureEdDSA RAW signature over the raw
    /// `data` — exactly what a real Cloud KMS `EC_SIGN_ED25519` key version returns.
    /// There is NO production code path into this; it exists only to make the
    /// crate-internal fake-transport reachable from the integration test that mints a
    /// matching server certificate from the same `seed`.
    #[doc(hidden)]
    pub fn for_test_with_local_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        let transport = LocalKeyGcpTransport {
            key: mcps_core::SigningKey::from_seed_bytes(seed),
        };
        Self::with_transport(Box::new(transport))
    }
}

/// TEST-ONLY in-memory [`GcpKmsTransport`] backed by a LOCAL Ed25519 key — the same
/// fake-Cloud-KMS shape used by this module's unit tests, exposed (only via the
/// `#[doc(hidden)]` [`GcpKmsEd25519Backend::for_test_with_local_seed`]) so the
/// delegated-TLS handshake integration test can use a real GCP backend with no
/// network. NOT reachable from any production path.
#[doc(hidden)]
struct LocalKeyGcpTransport {
    key: mcps_core::SigningKey,
}

impl GcpKmsTransport for LocalKeyGcpTransport {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
        let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&self.key.public_key().to_bytes());
        let b64 = STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        Ok(serde_json::json!({
            "algorithm": ALGORITHM_ED25519,
            "pem": pem,
        })
        .to_string()
        .into_bytes())
    }

    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        let v: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: sign body: {e}")))?;
        let data = STANDARD
            .decode(v.get("data").and_then(|d| d.as_str()).unwrap_or(""))
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: data b64: {e}")))?;
        let raw = mcps_core::b64url_decode(&self.key.sign(&data))
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: sign: {e}")))?;
        Ok(serde_json::json!({ "signature": STANDARD.encode(&raw) })
            .to_string()
            .into_bytes())
    }
}

impl KmsEd25519Backend for GcpKmsEd25519Backend {
    fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
        let resp = self
            .transport
            .asymmetric_sign(&sign_request_body(preimage))?;
        let signature = parse_sign_response(&resp)?;
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(KeyError::Malformed(format!(
                "gcp-kms: asymmetricSign returned a {}-byte signature; expected a raw \
                 {ED25519_SIGNATURE_LEN}-byte Ed25519 signature",
                signature.len()
            )));
        }
        // VERIFY-BEFORE-RETURN (ADR-MCPS-028 §D): the signature MUST verify against
        // the advertised public key under the unmodified mcps-core verifier — fail
        // closed on any mismatch, never emit a non-verifying signature.
        verify_ed25519(preimage, &b64url_encode(&signature), &self.verify_key).map_err(|e| {
            KeyError::Malformed(format!(
                "gcp-kms: KMS signature did NOT verify against the advertised public key: {e}"
            ))
        })?;
        Ok(signature)
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.spki_der.clone())
    }
}

/// Delegated TLS handshake signing through GCP Cloud KMS (issue #61, ADR-MCPS-028 §G).
///
/// The TLS *server* key is a SECOND, DISTINCT Cloud KMS key VERSION (a separate
/// `key_version_name` and — the operator SHOULD give it — a distinct IAM policy)
/// from the object-signing key, custodied by its own [`GcpKmsEd25519Backend`]. The
/// TLS handshake signature is produced by the SAME RAW-Ed25519 `asymmetricSign` path
/// used for response signing (`EC_SIGN_ED25519`, PureEdDSA over the raw `data`, NOT a
/// digest), so the TLS private key never leaves Cloud KMS.
///
/// rustls verifies the handshake `CertificateVerify` it gets back, and the validated
/// delegated build path (#58) both enforces the 64-byte length and fails closed when
/// the (exportable, cached) public key here does not match the leaf TLS certificate —
/// so verify-before-return is NOT repeated on this path (it stays on the
/// object-signing `sign_raw_ed25519` path, which is reused unchanged).
impl RawEd25519TlsSigner for GcpKmsEd25519Backend {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        // Reuse the object-signing RAW-Ed25519 Cloud KMS `asymmetricSign` path
        // verbatim over the handshake transcript, length-checked + verified.
        self.sign_raw_ed25519(message)
    }

    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        // The advertised Cloud KMS public key, fetched + validated as Ed25519 at
        // construction; the #58 build path matches it against the leaf TLS cert.
        Ok(self.spki_der.clone())
    }
}

#[cfg(test)]
mod tests {
    use mcps_core::b64url_decode;
    use mcps_core::SigningKey;

    use super::*;
    use crate::kms_keysource::ED25519_SPKI_PREFIX;

    /// Build a PEM-wrapped RFC 8410 Ed25519 SPKI from a raw point (what GCP returns).
    fn pem_from_raw(raw: &[u8; 32]) -> String {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        let b64 = STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    #[test]
    fn pem_roundtrips_to_spki_der() {
        let raw = SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_bytes();
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw);
        assert_eq!(spki_der_from_pem(&pem_from_raw(&raw)).unwrap(), der);
    }

    /// A non-Ed25519 key version is rejected at parse time (guardrail #4).
    #[test]
    fn non_ed25519_algorithm_fails_closed() {
        let body = br#"{"algorithm":"RSA_SIGN_PSS_2048_SHA256","pem":"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"}"#;
        assert!(matches!(
            parse_public_key_response(body),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn get_public_key_parses_ed25519_pem() {
        let raw = SigningKey::from_seed_bytes(&[6u8; 32])
            .public_key()
            .to_bytes();
        let body = serde_json::json!({
            "algorithm": "EC_SIGN_ED25519",
            "pem": pem_from_raw(&raw),
        })
        .to_string();
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw);
        assert_eq!(parse_public_key_response(body.as_bytes()).unwrap(), der);
    }

    /// A fake Cloud KMS transport backed by a LOCAL Ed25519 key — exercises the full
    /// getPublicKey→construct→asymmetricSign→verify-before-return path with no
    /// network. `prehash` flips the sign side to a forbidden DIGEST-style signature.
    struct FakeGcp {
        key: SigningKey,
        prehash: bool,
    }
    impl GcpKmsTransport for FakeGcp {
        fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
            Ok(serde_json::json!({
                "algorithm": ALGORITHM_ED25519,
                "pem": pem_from_raw(&self.key.public_key().to_bytes()),
            })
            .to_string()
            .into_bytes())
        }
        fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            let data = STANDARD
                .decode(v.get("data").unwrap().as_str().unwrap())
                .unwrap();
            let to_sign = if self.prehash {
                let mut d = b"DIGEST:".to_vec();
                d.extend_from_slice(&data);
                d
            } else {
                data
            };
            let raw = b64url_decode(&self.key.sign(&to_sign)).unwrap();
            Ok(serde_json::json!({ "signature": STANDARD.encode(&raw) })
                .to_string()
                .into_bytes())
        }
    }

    /// LOAD-BEARING: the full adapter path produces a signature that verifies, and
    /// the SPKI it reports is the advertised key.
    #[test]
    fn gcp_backend_signs_and_verifies_end_to_end() {
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            key: SigningKey::from_seed_bytes(&[12u8; 32]),
            prehash: false,
        }))
        .expect("construct");
        let preimage = b"mcps canonical response preimage";
        let sig = backend.sign_raw_ed25519(preimage).expect("sign");
        assert_eq!(sig.len(), 64);
        let raw = ed25519_raw_point_from_spki(&backend.public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(preimage, &b64url_encode(&sig), &key).expect("verifies");
    }

    /// A DIGEST/prehash misconfiguration is caught by verify-before-return — the
    /// adapter NEVER returns a non-verifying signature (guardrail #5).
    #[test]
    fn prehash_signature_is_rejected_before_return() {
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            key: SigningKey::from_seed_bytes(&[12u8; 32]),
            prehash: true,
        }))
        .expect("construct");
        let err = backend
            .sign_raw_ed25519(b"mcps canonical response preimage")
            .expect_err("must fail closed");
        assert!(matches!(err, KeyError::Malformed(_)));
    }

    /// Issue #61 (test a): the GCP backend AS a [`RawEd25519TlsSigner`] signs a TLS
    /// handshake transcript over the fake Cloud KMS transport, returning a raw
    /// 64-byte signature that VERIFIES under the SPKI it reports — the exact
    /// assertion the validated #58 build path and rustls rely on. The TLS sign path
    /// reuses the object-signing RAW-Ed25519 `asymmetricSign`.
    #[test]
    fn gcp_backend_tls_sign_verifies_under_reported_spki() {
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            key: SigningKey::from_seed_bytes(&[24u8; 32]),
            prehash: false,
        }))
        .expect("construct");
        let transcript = b"tls handshake transcript bytes";
        let sig = backend.sign_tls_ed25519(transcript).expect("tls sign");
        assert_eq!(
            sig.len(),
            64,
            "delegated TLS signature is a raw 64-byte Ed25519 sig"
        );
        // The reported SPKI is the advertised Cloud KMS public key and verifies it.
        let raw = ed25519_raw_point_from_spki(&backend.tls_public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(transcript, &b64url_encode(&sig), &key).expect("tls sig verifies");
    }
}
