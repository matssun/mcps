//! Full-stack CI smoke test for the production `mcps_proxy_cli` binary
//! (Phase 6.1 hardening — ADR-MCPS-014 follow-up).
//!
//! This proves the EXECUTABLE end to end, not just library behavior: it spawns
//! the real `mcps_proxy_cli` process (TLS-terminating PEP) wired to a real inner
//! MCP echo subprocess, with real client certificates over real mTLS, and drives
//! the security matrix the review requires:
//!
//!   * valid client cert + signed request → inner receives the injected verified
//!     context AND the response is signed and binds to the request hash;
//!   * NO client certificate → rejected at the handshake (fail closed);
//!   * UNTRUSTED client certificate → rejected at the handshake (fail closed);
//!   * valid cert + TAMPERED object signature → `mcps.invalid_signature`
//!     (mTLS never downgrades object verification);
//!   * valid cert + WRONG transport binding (signer ≠ cert identity) →
//!     `mcps.transport_binding_failed`.
//!
//! Certificates are minted in-process with `rcgen` (no committed key fixtures).
//! The two binaries are delivered via runfiles (`$(rlocationpath ...)`), the same
//! scheme the conformance harnesses use.

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_core::b64url_encode;
use mcps_core::request_hash;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VERIFIED_META_KEY;
use mcps_host::HostSigner;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;

use serde_json::json;
use serde_json::Value;

// --- identities ---------------------------------------------------------------

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const SIGNER_A: &str = "spiffe://example.org/agent-1"; // == client-cert URI SAN
const SIGNER_A_KEY_ID: &str = "key-a";
const SIGNER_B: &str = "spiffe://example.org/agent-2"; // trusted, but NOT the cert identity
const SIGNER_B_KEY_ID: &str = "key-b";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

fn server_seed() -> [u8; 32] {
    [2u8; 32]
}
fn signer_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn signer_b_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[3u8; 32])
}

// --- rcgen certificate authority + leaves -------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcps-fullstack-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    // A bounded, currently-valid window (≈15y) so the cert passes the handshake
    // date check; the matrix proxy runs with a generous max-lifetime, and a
    // dedicated case runs with a tiny max to exercise lifetime enforcement.
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
    (cert, key)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// --- temp key material on disk ------------------------------------------------

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mcps_fullstack_{}_{name}", std::process::id()))
}

/// Write all key material the CLI needs and return their paths.
/// Returns `(seed, server_cert, server_key, client_ca, trust)` and keeps the
/// minted client-CA so the test can issue both a trusted and a rogue client cert.
struct Material {
    seed_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    client_ca_path: PathBuf,
    trust_path: PathBuf,
    client_ca: Ca,
}

fn write_material() -> Material {
    let server_ca = make_ca();
    let (server_leaf, server_leaf_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let client_ca = make_ca();

    let seed_path = tmp("seed");
    let server_cert_path = tmp("server_cert.pem");
    let server_key_path = tmp("server_key.pem");
    let client_ca_path = tmp("client_ca.pem");
    let trust_path = tmp("trust.json");

    std::fs::write(&seed_path, b64url_encode(&server_seed())).unwrap();
    std::fs::write(&server_cert_path, server_leaf.pem()).unwrap();
    std::fs::write(&server_key_path, server_leaf_key.serialize_pem()).unwrap();
    std::fs::write(&client_ca_path, client_ca.cert.pem()).unwrap();

    // Trust BOTH request signers (object verification passes for either); the
    // transport binding is what distinguishes them.
    let trust = json!([
        { "signer": SIGNER_A, "key_id": SIGNER_A_KEY_ID, "public_key": signer_a_key().public_key().to_b64url() },
        { "signer": SIGNER_B, "key_id": SIGNER_B_KEY_ID, "public_key": signer_b_key().public_key().to_b64url() },
    ]);
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();

    Material {
        seed_path,
        server_cert_path,
        server_key_path,
        client_ca_path,
        trust_path,
        client_ca,
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        for p in [
            &self.seed_path,
            &self.server_cert_path,
            &self.server_key_path,
            &self.client_ca_path,
            &self.trust_path,
        ] {
            let _ = std::fs::remove_file(p);
        }
    }
}

// --- runfiles binary resolution (same scheme as the stdio harness) ------------

fn locate(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

// --- spawned CLI process (killed on drop) -------------------------------------

struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

fn spawn_proxy(material: &Material, max_cert_lifetime: &str) -> ProxyProcess {
    let cli = locate("MCPS_PROXY_CLI");
    let echo = locate("MCPS_ECHO_INNER");
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let addr: SocketAddr = bind.parse().expect("addr");

    let child = Command::new(&cli)
        .args([
            "--bind", &bind,
            "--audience", AUDIENCE,
            "--server-signer", SERVER,
            "--server-key-id", SERVER_KEY_ID,
            "--key-source", "file",
            "--signing-key-seed", &material.seed_path.to_string_lossy(),
            "--tls-cert", &material.server_cert_path.to_string_lossy(),
            "--tls-key", &material.server_key_path.to_string_lossy(),
            "--client-ca", &material.client_ca_path.to_string_lossy(),
            "--trust", &material.trust_path.to_string_lossy(),
            "--transport-binding", "exact",
            "--transport-identity-source", "uri_san",
            "--max-client-cert-lifetime", max_cert_lifetime,
            "--inner-command", &echo.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // stderr inherited: the CLI's diagnostics show in the test log on failure.
        .spawn()
        .expect("spawn mcps_proxy_cli");

    // Wait until the listener is accepting (TCP-level probe).
    let mut up = false;
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(up, "mcps_proxy_cli did not start listening on {addr}");

    ProxyProcess { child, addr }
}

// --- TLS client ---------------------------------------------------------------

#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer));
    match client_auth {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).expect("client auth"),
        None => builder.with_no_client_auth(),
    }
}

/// POST `body` over a fresh mTLS connection and return the response BODY bytes.
/// `Err` when the TLS handshake or IO fails (e.g. a rejected client certificate).
fn round_trip(
    addr: SocketAddr,
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

/// A trusted client certificate whose URI SAN is `SIGNER_A`.
fn trusted_client_cert(ca: &Ca) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let (leaf, key) = make_leaf(ca, vec![uri(SIGNER_A)], None, true);
    let der = leaf.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (vec![der], key_der)
}

// --- signed requests (real clock) ---------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sign a tools/call as `signer` using `key`, timestamped at the real clock so it
/// is fresh against the CLI's (uninjected) system clock.
fn signed_request(signer: &str, key_id: &str, key: SigningKey, nonce: &str) -> Vec<u8> {
    let now = now_unix();
    let issued_at = unix_to_rfc3339_utc(now);
    let expires_at = unix_to_rfc3339_utc(now + 300);
    HostSigner::new(key, signer, key_id)
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            &issued_at,
            &expires_at,
        )
        .expect("host signs")
}

fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, SigningKey::from_seed_bytes(&server_seed()).public_key());
    r
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse response");
    value["error"]["message"]
        .as_str()
        .unwrap_or("<no error message>")
        .to_string()
}

// --- the matrix (one running CLI, sequential connections) ---------------------

#[test]
fn full_stack_cli_security_matrix() {
    let material = write_material();
    // Matrix proxy runs with a generous cert-lifetime ceiling (≈20y) so the
    // bounded test certs (≈15y) pass; cert-lifetime ENFORCEMENT is exercised by
    // its own case (a second proxy with a tiny ceiling) below.
    let proxy = spawn_proxy(&material, "175200h");
    let addr = proxy.addr;

    // 1. Happy path: valid cert (identity == SIGNER_A) + request signed by A.
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-ok-1");
        let expected_hash =
            request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).unwrap();
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(addr, client_config(Some(cert)), &request)
            .expect("valid mTLS round trip");

        let response: Value = serde_json::from_slice(&body).expect("parse response body");
        assert!(
            response.get("error").is_none(),
            "valid request must not error: {response}"
        );
        // The inner subprocess received the proxy-injected verified-context block.
        let echoed_meta = &response["result"]["echoed_meta"];
        assert!(
            echoed_meta.get(VERIFIED_META_KEY).is_some(),
            "inner must receive the injected verified-context block; got: {echoed_meta}"
        );
        // The signed response verifies and binds to the request hash.
        let verified = verify_response(&body, &server_resolver(), &expected_hash)
            .expect("signed response verifies and binds");
        assert_eq!(verified.server_signer(), SERVER);
    }

    // 2. No client certificate → rejected at the handshake.
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-nocert");
        let result = round_trip(addr, client_config(None), &request);
        assert!(result.is_err(), "a connection with no client cert must fail closed");
    }

    // 3. Untrusted client certificate (rogue CA) → rejected at the handshake.
    {
        let rogue_ca = make_ca();
        let (leaf, key) = make_leaf(&rogue_ca, vec![uri(SIGNER_A)], None, true);
        let chain = vec![leaf.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-rogue");
        let result = round_trip(addr, client_config(Some((chain, key_der))), &request);
        assert!(result.is_err(), "an untrusted client cert must fail closed");
    }

    // 4. Valid cert + TAMPERED object signature → invalid_signature (no downgrade).
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-tamper");
        let mut value: Value = serde_json::from_slice(&request).unwrap();
        value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
        let tampered = serde_json::to_vec(&value).unwrap();
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(addr, client_config(Some(cert)), &tampered)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcps.invalid_signature");
    }

    // 5. Valid cert (identity A) + request signed by B → transport_binding_failed.
    {
        let request = signed_request(SIGNER_B, SIGNER_B_KEY_ID, signer_b_key(), "nonce-bind");
        let cert = trusted_client_cert(&material.client_ca); // identity == SIGNER_A
        let body = round_trip(addr, client_config(Some(cert)), &request)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcps.transport_binding_failed");
    }

    drop(proxy); // kill the matrix CLI

    // 6. Cert-lifetime enforcement: a second CLI with a 60s ceiling rejects the
    //    (≈15y) client cert even though signer, signature, and binding are all
    //    valid — the ONLY reason for rejection is the over-long certificate.
    {
        let proxy2 = spawn_proxy(&material, "60");
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-life");
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(proxy2.addr, client_config(Some(cert)), &request)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcps.transport_binding_failed");
        drop(proxy2);
    }
}
