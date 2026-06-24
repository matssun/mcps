//! Live GCP Cloud KMS DELEGATED-TLS lane (ADR-MCPS-028 §G, issue #61).
//!
//! The enterprise claim this lane proves: the proxy's TLS *server* private key can
//! live entirely inside GCP Cloud KMS and NEVER leave it, yet a real, fully
//! validating rustls client still completes an mTLS handshake. Because the client
//! verifies the server's `CertificateVerify` signature against the server leaf's
//! Ed25519 public key, the handshake completes ONLY if a live Cloud KMS
//! `asymmetricSign` produced a wire-correct signature over the TLS transcript.
//! Nothing is bypassed — this is genuine proof, not a mock.
//!
//! What is in the cloud vs local (KMS is necessary, not sufficient):
//!   * IN GCP KMS: the TLS server private key (a SECOND, DISTINCT Ed25519 key from
//!     the response-signing key — ADR §G). Exercised only via `asymmetricSign` /
//!     `getPublicKey`; the private key is never materialised here.
//!   * LOCAL (rcgen): the test CA, the server LEAF cert that BINDS the KMS public
//!     key, and the client identity (cert + key + client-CA). KMS does not issue
//!     X.509 certs; that PKI is built around the cloud-held key.
//!
//! The server leaf is minted over the KMS key's PUBLIC key via rcgen's
//! `RemoteKeyPair` — the private key is NOT needed to issue a CA-signed leaf (the
//! CA signs it). The validated builder then fails closed unless the leaf's public
//! key equals the delegated signer's, so a successful build proves the cert binds
//! the cloud key.
//!
//! `#[ignore]` by default (needs network + a configured Ed25519 TLS key version);
//! run with `--features gcp_kms_keysource -- --ignored`.
//!
//! Required environment:
//!   * `MCPS_GCP_KEY_VERSION_TLS` — full resource path of the Ed25519 TLS key
//!     version (`.../cryptoKeyVersions/V`, algorithm `EC_SIGN_ED25519`).
//!   * one of: `MCPS_GCP_ACCESS_TOKEN` (operator bearer token), or
//!     `MCPS_GCP_USE_METADATA=1` for the workload-identity metadata server.
//!   * `MCPS_GCP_KMS_ENDPOINT` — OPTIONAL endpoint override (emulator).
#![cfg(feature = "gcp_kms_keysource")]

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use mcps_proxy::build_server_config_delegated_validated;
use mcps_proxy::serve_once;
use mcps_proxy::transport::IdentitySource;
use mcps_proxy::GcpKmsConfig;
use mcps_proxy::GcpKmsEd25519Backend;
use mcps_proxy::RawEd25519TlsSigner;
use mcps_proxy::ServerOptions;
use mcps_proxy::TlsError;

use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::BasicConstraints;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::RemoteKeyPair;
use rcgen::SanType;
use rcgen::SignatureAlgorithm;

use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::StreamOwned;
use rustls::crypto::ring;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

/// Read a REQUIRED env var or fail the lane loudly — this lane must run against a
/// real/emulated Cloud KMS; it never passes without actually verifying.
fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms delegated-TLS lane: required env var {name} is not set — this lane \
             must run against a real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

// ---------------------------------------------------------------------------
// Local PKI (rcgen): CA + client leaf. KMS does not issue these.
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcps-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("dns name"))
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("uri san"))
}

/// A normal LOCAL client leaf (the agent identity). Returns cert chain + key.
fn make_client_leaf(ca: &Ca, san: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(Vec::new()).expect("client params");
    params.subject_alt_names = vec![uri(san)];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("client leaf signed");
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (vec![cert.der().clone()], key_der)
}

// ---------------------------------------------------------------------------
// The crux: mint a server leaf over the GCP KMS key's PUBLIC key, no private key.
// ---------------------------------------------------------------------------

/// An rcgen subject key backed by a GCP KMS key: it exposes the cloud key's PUBLIC
/// point so a CA-signed leaf can BIND it, and delegates any signing to the cloud.
/// The private key never leaves GCP — `sign()` (unused for CA-signed leaf issuance)
/// would call `asymmetricSign`, never a local key.
struct GcpRemoteKey {
    raw_public: Vec<u8>,
    signer: Arc<GcpKmsEd25519Backend>,
}

impl RemoteKeyPair for GcpRemoteKey {
    fn public_key(&self) -> &[u8] {
        &self.raw_public
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Honest delegation: if rcgen ever needs the subject key to sign, it goes
        // to Cloud KMS — never a local key. (Not invoked for a CA-signed leaf.)
        RawEd25519TlsSigner::sign_tls_ed25519(self.signer.as_ref(), msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// Extract the 32-byte raw Ed25519 point from an RFC 8410 SPKI (44 bytes: 12-byte
/// prefix + 32-byte point), failing closed on any other shape.
fn raw_point_from_spki(spki: &[u8]) -> [u8; 32] {
    const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    assert!(
        spki.len() == 44 && spki.starts_with(&ED25519_SPKI_PREFIX),
        "expected an RFC 8410 Ed25519 SPKI (12-byte prefix + 32-byte point) from Cloud KMS, got {} bytes",
        spki.len()
    );
    spki[12..44].try_into().expect("32-byte ed25519 point")
}

/// Construct the live GCP KMS TLS backend from env, plus its (cached) public point.
/// Shared by the positive and negative lanes so they all custody the TLS key in GCP.
fn gcp_tls_backend() -> (Arc<GcpKmsEd25519Backend>, [u8; 32]) {
    let tls_config = GcpKmsConfig {
        key_version_name: require_env("MCPS_GCP_KEY_VERSION_TLS"),
        endpoint: std::env::var("MCPS_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCPS_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        require_env("MCPS_GCP_ACCESS_TOKEN");
    }
    let backend = Arc::new(
        GcpKmsEd25519Backend::new(&tls_config, use_metadata)
            .expect("construct GCP KMS TLS backend (getPublicKey must succeed and be Ed25519)"),
    );
    let spki = backend
        .tls_public_key_spki_der()
        .expect("Cloud KMS getPublicKey (TLS)");
    let raw_public = raw_point_from_spki(&spki);
    (backend, raw_public)
}

/// Mint a CA-signed Ed25519 server leaf whose SUBJECT public key is the GCP KMS
/// key's public key. The KMS private key is not used (the CA signs the leaf).
fn make_server_leaf_for_gcp_key(
    ca: &Ca,
    backend: Arc<GcpKmsEd25519Backend>,
    raw_public: [u8; 32],
) -> CertificateDer<'static> {
    let remote = GcpRemoteKey {
        raw_public: raw_public.to_vec(),
        signer: backend,
    };
    let subject_key = KeyPair::from_remote(Box::new(remote)).expect("rcgen from_remote");
    let mut params = CertificateParams::new(Vec::new()).expect("server params");
    params.subject_alt_names = vec![dns("localhost")];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .signed_by(&subject_key, &ca.cert, &ca.key)
        .expect("server leaf signed by CA over the GCP public key");
    cert.der().clone()
}

// ---------------------------------------------------------------------------
// Fully-validating rustls client (no bypass): chain-to-CA + hostname +
// CertificateVerify signature. The handshake completes only if the delegated
// (cloud) signature over the transcript is cryptographically valid.
// ---------------------------------------------------------------------------

fn client_config_validating(
    server_ca_root: CertificateDer<'static>,
    client_auth: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server_ca_root).expect("add server CA root");
    let provider = Arc::new(ring::default_provider());
    let (chain, key) = client_auth;
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("client auth cert")
}

fn client_round_trip(
    addr: std::net::SocketAddr,
    config: ClientConfig,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    let split = b"\r\n\r\n";
    let pos = response
        .windows(split.len())
        .position(|w| w == split)
        .map(|p| p + split.len())
        .unwrap_or(0);
    Ok(response[pos..].to_vec())
}

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS Ed25519 TLS key (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_delegated_tls_handshake_round_trip() {
    // The TLS server key lives in GCP KMS. We only ever fetch its PUBLIC key.
    let (tls_backend, raw_public) = gcp_tls_backend();

    // Local PKI built AROUND the cloud key.
    let server_ca = make_ca();
    let client_ca = make_ca();
    let server_leaf =
        make_server_leaf_for_gcp_key(&server_ca, tls_backend.clone(), raw_public);

    // Validated builder (issue #58): Ed25519-only + leaf-pubkey == signer-pubkey,
    // fail closed. A successful build PROVES the leaf binds the cloud key.
    let signer: Arc<dyn RawEd25519TlsSigner> = tls_backend.clone();
    let config = Arc::new(
        build_server_config_delegated_validated(
            vec![server_leaf],
            signer,
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated server config (leaf must bind the KMS public key)"),
    );

    let (client_chain, client_key) =
        make_client_leaf(&client_ca, "spiffe://example.org/agent-1");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, _identity| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                b"{\"ok\":true}".to_vec()
            },
        )
    });

    // Fully validating client: completing this handshake means a live Cloud KMS
    // asymmetricSign produced a valid Ed25519 CertificateVerify over the transcript.
    let response = client_round_trip(
        addr,
        client_config_validating(
            server_ca.cert.der().clone(),
            (client_chain, client_key),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip over a GCP-KMS-delegated TLS handshake");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(identity.value, "spiffe://example.org/agent-1");
    assert_eq!(identity.source, IdentitySource::UriSan);
}

// ---------------------------------------------------------------------------
// Negative lanes.
// ---------------------------------------------------------------------------

/// Negative 1 — wrong-key BINDING fails closed: a server leaf that does NOT carry
/// the cloud key's public key must be rejected at config construction. Without this
/// guard the proxy would present a certificate the KMS signer can't match and every
/// handshake would fail opaquely; instead it fails closed, loudly, up front.
#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS Ed25519 TLS key (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_delegated_tls_wrong_key_binding_fails_closed() {
    let (tls_backend, _raw_public) = gcp_tls_backend();
    let server_ca = make_ca();
    let client_ca = make_ca();

    // Mint a leaf bound to a DIFFERENT, local Ed25519 key — NOT the cloud key.
    let foreign = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("foreign ed25519 key");
    let mut params = CertificateParams::new(Vec::new()).expect("server params");
    params.subject_alt_names = vec![dns("localhost")];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let foreign_leaf = params
        .signed_by(&foreign, &server_ca.cert, &server_ca.key)
        .expect("foreign leaf signed")
        .der()
        .clone();

    let signer: Arc<dyn RawEd25519TlsSigner> = tls_backend;
    match build_server_config_delegated_validated(
        vec![foreign_leaf],
        signer,
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    ) {
        Ok(_) => panic!(
            "a server leaf NOT bound to the KMS TLS key must be rejected at construction \
             (fail closed)"
        ),
        Err(TlsError::DelegatedKeyMismatch(msg)) => assert!(
            msg.contains("does not match"),
            "expected a cert<->signer key-mismatch error, got: {msg}"
        ),
        Err(other) => panic!(
            "expected TlsError::DelegatedKeyMismatch (leaf does not bind the KMS key), \
             got {other:?} — failure may be unrelated to the binding check"
        ),
    }
}

/// Negative 2 — an UNTRUSTED client certificate must fail the mTLS handshake. The
/// server is the real GCP-KMS-delegated proxy config; the client presents a cert
/// from a CA the proxy does not trust, so client-auth fails closed.
#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS Ed25519 TLS key (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_delegated_tls_untrusted_client_rejected() {
    let (tls_backend, raw_public) = gcp_tls_backend();
    let server_ca = make_ca();
    let client_ca = make_ca(); // the proxy trusts THIS CA for client auth
    let rogue_ca = make_ca(); // the client cert is issued by THIS one — untrusted

    let server_leaf = make_server_leaf_for_gcp_key(&server_ca, tls_backend.clone(), raw_public);
    let signer: Arc<dyn RawEd25519TlsSigner> = tls_backend.clone();
    let config = Arc::new(
        build_server_config_delegated_validated(
            vec![server_leaf],
            signer,
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated server config"),
    );

    let (rogue_chain, rogue_key) = make_client_leaf(&rogue_ca, "spiffe://example.org/rogue");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |_request, _identity| b"{\"ok\":true}".to_vec(),
        )
    });

    let result = client_round_trip(
        addr,
        client_config_validating(server_ca.cert.der().clone(), (rogue_chain, rogue_key)),
        b"{\"jsonrpc\":\"2.0\"}",
    );
    assert!(
        result.is_err(),
        "an untrusted client certificate must fail the mTLS handshake (fail closed)"
    );
    // The server side also errors on the rejected handshake; don't unwrap it.
    let _ = server.join();
}
