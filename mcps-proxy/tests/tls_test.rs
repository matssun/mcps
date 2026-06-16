//! MCPS-025 — RustlsDirectProvider: identity extraction + mTLS round-trip
//! (ADR-MCPS-014).
//!
//! Certificates are minted in-process with `rcgen` (no committed private-key
//! fixtures). Two layers of test:
//!   1. `extract_identity` priority (URI SAN → DNS SAN → CN) over real DER.
//!   2. A full blocking TLS round-trip: the server terminates TLS, requires +
//!      verifies a client certificate, extracts its identity, and serves one
//!      request; a missing or untrusted client certificate fails closed.

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mcps_proxy::extract_identity;
use mcps_proxy::serve_once;
use mcps_proxy::transport::IdentityPolicy;
use mcps_proxy::transport::IdentitySource;
use mcps_proxy::RustlsDirectProvider;
use mcps_proxy::ServerOptions;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::CertificateRevocationListParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyIdMethod;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::RevocationReason;
use rcgen::RevokedCertParams;
use rcgen::SanType;
use rcgen::SerialNumber;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;

// ---------------------------------------------------------------------------
// Test certificate authority + leaves (rcgen).
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

/// A leaf signed by `ca`, with the given SANs / CN and (client or server) EKU.
fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed by ca");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// A leaf with an explicit validity window (day granularity, via `date_time_ymd`)
/// so its lifetime is deterministic for max-lifetime enforcement tests.
fn make_leaf_with_validity(
    ca: &Ca,
    sans: Vec<SanType>,
    client_auth: bool,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// A client leaf signed by `ca` with an EXPLICIT serial number, so a CRL can be
/// minted that revokes exactly this certificate (#3839).
fn make_client_leaf_with_serial(
    ca: &Ca,
    san: &str,
    serial: u64,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![uri(san)];
    params.serial_number = Some(SerialNumber::from(serial));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// Mint a CRL signed by `ca` that revokes the certificates with the given serials
/// (#3839). The CA carries `CrlSign` key usage (see `make_ca`), which rcgen
/// requires of a CRL issuer. Returns the CRL in the DER form rustls consumes.
fn make_crl(ca: &Ca, revoked_serials: &[u64]) -> CertificateRevocationListDer<'static> {
    let revoked_certs = revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: rcgen::date_time_ymd(2024, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        // Far-future nextUpdate: the proxy's default verifier does NOT enforce CRL
        // expiration (ExpirationPolicy::Ignore), but a future date keeps the CRL
        // well-formed regardless.
        next_update: rcgen::date_time_ymd(2999, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(&ca.cert, &ca.key)
        .expect("crl signed by ca");
    crl.der().clone()
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// ---------------------------------------------------------------------------
// 1. Policy-selected identity extraction (NO implicit fallback).
// ---------------------------------------------------------------------------

#[test]
fn uri_san_policy_reads_the_uri_san() {
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            dns("agent.example.org"),
            uri("spiffe://example.org/agent-1"),
        ],
        Some("ignored-cn"),
        true,
    );
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(id.value, "spiffe://example.org/agent-1");
    assert_eq!(id.source, IdentitySource::UriSan);
}

#[test]
fn dns_san_policy_reads_the_dns_san() {
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            dns("agent.example.org"),
            uri("spiffe://example.org/agent-1"),
        ],
        Some("ignored"),
        true,
    );
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
    assert_eq!(id.value, "agent.example.org");
    assert_eq!(id.source, IdentitySource::DnsSan);
}

#[test]
fn cn_legacy_policy_reads_the_common_name() {
    let ca = make_ca();
    let (leaf, _key) = make_leaf(&ca, vec![], Some("agent-cn"), true);
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::CnLegacy).expect("identity");
    assert_eq!(id.value, "agent-cn");
    assert_eq!(id.source, IdentitySource::CommonName);
}

#[test]
fn selected_source_absent_fails_closed_no_fallback() {
    let ca = make_ca();
    // A cert with ONLY a DNS SAN + CN, no URI SAN.
    let (leaf, _key) = make_leaf(&ca, vec![dns("agent.example.org")], Some("agent-cn"), true);
    // URI-SAN policy must NOT fall through to the DNS SAN or the CN.
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "URI-SAN policy must fail closed when no URI SAN is present"
    );
    // A cert with ONLY a URI SAN: DNS-SAN policy must not fall through to it.
    let (leaf2, _key2) = make_leaf(&ca, vec![uri("spiffe://example.org/a")], None, true);
    assert!(
        extract_identity(leaf2.as_ref(), IdentityPolicy::DnsSan).is_none(),
        "DNS-SAN policy must fail closed when no DNS SAN is present"
    );
}

// ---------------------------------------------------------------------------
// 1b. MCPS-078 (audit gap G-5): adversarial extract_identity — hostile-but-valid
//     SAN bytes, multiple SANs (deterministic selection), and empty SAN lists.
//     All assertions are black-box on the public `extract_identity`.
// ---------------------------------------------------------------------------

#[test]
fn multiple_uri_sans_select_first_deterministically() {
    // Two URI SANs. `extract_identity` (UriSan) is `find_map` over the cert's
    // general_names IN ORDER, so the FIRST URI SAN wins. Mint once, extract
    // repeatedly: the selection is stable (same cert → same identity).
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            uri("spiffe://example.org/agent-FIRST"),
            uri("spiffe://example.org/agent-SECOND"),
        ],
        None,
        true,
    );
    let first = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(
        first.value, "spiffe://example.org/agent-FIRST",
        "the FIRST URI SAN (find_map order) must win"
    );
    assert_eq!(first.source, IdentitySource::UriSan);
    // Determinism: repeated extraction over the SAME cert yields the SAME value.
    for _ in 0..8 {
        let again = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
        assert_eq!(again.value, first.value, "selection must be deterministic");
        assert_eq!(again.source, first.source);
    }
}

#[test]
fn multiple_dns_sans_select_first_deterministically() {
    // Analogous multi-DNS-SAN case for the DnsSan policy: FIRST DNS SAN wins,
    // deterministically.
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![dns("first.example.org"), dns("second.example.org")],
        None,
        true,
    );
    let first = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
    assert_eq!(
        first.value, "first.example.org",
        "the FIRST DNS SAN (find_map order) must win"
    );
    assert_eq!(first.source, IdentitySource::DnsSan);
    for _ in 0..8 {
        let again = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
        assert_eq!(again.value, first.value, "selection must be deterministic");
    }
}

#[test]
fn uri_san_with_nul_control_char_is_returned_verbatim() {
    // A NUL (0x00) and other C0 control chars are valid IA5 (ASCII 0x00-0x7F), so
    // `SanType::URI`'s `try_into` ACCEPTS them and the cert mints. The parser must
    // return the value VERBATIM — NOT truncated at the NUL — and must not panic.
    let ca = make_ca();
    let hostile = "spiffe://example.org/agent\u{0000}injected";
    // Confirm the byte is IA5-representable (the premise of this test).
    let san: SanType = SanType::URI(hostile.try_into().expect("NUL/C0 is valid IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(
        id.value, hostile,
        "the URI SAN must be returned verbatim, not truncated at the NUL"
    );
    assert_eq!(id.source, IdentitySource::UriSan);
    // Verbatim implies the embedded NUL survives round-trip.
    assert!(
        id.value.contains('\u{0000}'),
        "the embedded NUL must be preserved, proving no C-string truncation"
    );
}

#[test]
fn non_ia5_unicode_uri_san_is_rejected_at_mint_time() {
    // Unicode beyond ASCII is NOT IA5-representable, so `SanType::URI`'s `try_into`
    // REJECTS it: minting fails with an error rather than producing a surprising
    // identity. We assert the error path on the `try_into` directly (per the issue,
    // do not force a degenerate cert).
    let non_ia5 = "spiffe://example.org/agent-\u{00e9}"; // 'é' (U+00E9) > 0x7F
    let result: Result<rcgen::Ia5String, _> = non_ia5.try_into();
    assert!(
        result.is_err(),
        "a non-IA5 (non-ASCII unicode) URI SAN value must be rejected by try_into, \
         not silently coerced"
    );
}

#[test]
fn no_san_fails_closed_for_san_policies_cn_only_for_legacy() {
    // Empty SAN list. URI-SAN and DNS-SAN policies must both fail closed (None);
    // CnLegacy returns the CN only when present.
    let ca = make_ca();
    let (leaf, _key) = make_leaf(&ca, vec![], Some("legacy-cn"), true);
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "UriSan must fail closed with no SAN"
    );
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).is_none(),
        "DnsSan must fail closed with no SAN"
    );
    let cn = extract_identity(leaf.as_ref(), IdentityPolicy::CnLegacy).expect("cn identity");
    assert_eq!(cn.value, "legacy-cn");
    assert_eq!(cn.source, IdentitySource::CommonName);
    // NOTE: a truly CN-less leaf is not mintable via these rcgen 0.13 helpers —
    // `self_signed`/`signed_by` inject a default CN ("rcgen self signed cert")
    // when no DN is supplied, so CnLegacy would read THAT, not None. That is a
    // fixture artifact (rcgen always emits a subject), not a fault in
    // `extract_identity`, which faithfully returns whatever CN the cert carries.
    // The fail-closed contract for CnLegacy is therefore exercised by the
    // genuinely-absent SAN policies above (UriSan/DnsSan → None).
}

// ---------------------------------------------------------------------------
// 2. mTLS round-trip.
// ---------------------------------------------------------------------------

/// A client-side verifier that accepts any server certificate — the test server
/// is self-presented and the client is only exercising mTLS client-auth.
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A client config that FULLY validates the server: rustls's stock WebPKI server
/// verifier anchored at `server_ca_root` performs real chain building, validity,
/// hostname (SAN), AND `CertificateVerify` signature verification — nothing is
/// asserted. The delegated-TLS test uses this so the handshake completes only if
/// the server cert chains to the test CA, matches `localhost`, AND the delegated
/// Ed25519 signature over the transcript is cryptographically valid; a bogus
/// delegated signature (or an untrusted/mismatched cert) FAILS the handshake,
/// making the test genuinely load-bearing.
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

fn client_config(
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer));
    match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client auth cert"),
        None => builder.with_no_client_auth(),
    }
}

/// Connect as a TLS client, send one HTTP POST with `body`, return the response
/// body. Returns Err if the TLS handshake or IO fails (e.g. rejected client cert).
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
    // A peer that closes without close_notify surfaces as UnexpectedEof; tolerate
    // it and use what was read.
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    // Return the body (after the header terminator).
    let split = b"\r\n\r\n";
    let pos = response
        .windows(split.len())
        .position(|w| w == split)
        .map(|p| p + split.len())
        .unwrap_or(0);
    Ok(response[pos..].to_vec())
}

fn server_config_for(ca: &Ca) -> Arc<rustls::ServerConfig> {
    // Server presents its own leaf; the CLIENT-CA root is `ca` (the issuer of the
    // client certs we mint below).
    let server_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let config = RustlsDirectProvider::build_server_config(
        vec![server_cert],
        server_key,
        vec![ca.cert.der().clone()],
    )
    .expect("server config");
    Arc::new(config)
}

/// As [`server_config_for`], but with offline CRL revocation enabled (#3839):
/// the verifier checks presented client certs against `crls`, denying unknown
/// status by default (fail closed).
fn server_config_with_crls_for(
    ca: &Ca,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Arc<rustls::ServerConfig> {
    let server_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let config = RustlsDirectProvider::build_server_config_with_crls(
        vec![server_cert],
        server_key,
        vec![ca.cert.der().clone()],
        crls,
        false, // fail closed on unknown revocation status
    )
    .expect("server config with crls");
    Arc::new(config)
}

#[test]
fn mtls_round_trip_extracts_client_identity_and_serves_request() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let (client_cert, client_key) = make_leaf(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, identity| {
                // Echo the request body back; the identity is asserted via the join.
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                let _ = identity;
                b"{\"ok\":true}".to_vec()
            },
        )
    });

    let response = client_round_trip(
        addr,
        client_config(Some((vec![client_cert], client_key))),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(identity.value, "spiffe://example.org/agent-1");
    assert_eq!(identity.source, IdentitySource::UriSan);
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G: delegated TLS handshake signing. The server's TLS key is NOT
// exported to rustls; instead a `RawEd25519TlsSigner` (here a local Ed25519 key
// standing in for a PKCS#11 token / KMS) signs each handshake. A real rustls
// client completing the mTLS handshake PROVES the delegated Ed25519 signature is
// wire-correct (rustls verifies it against the server's Ed25519 certificate).
// ---------------------------------------------------------------------------

/// A delegated signer backed by a LOCAL Ed25519 key (stand-in for device/KMS):
/// signs the raw handshake transcript exactly as a KMS RAW `Sign` would.
#[derive(Debug)]
struct LocalEd25519Tls(mcps_core::SigningKey);
impl mcps_proxy::RawEd25519TlsSigner for LocalEd25519Tls {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcps_proxy::KeyError> {
        Ok(mcps_core::b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
    }
    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcps_proxy::KeyError> {
        Ok(ed25519_spki_from_raw(&self.0.public_key().to_bytes()))
    }
}

/// The fixed 12-byte RFC 8410 Ed25519 `SubjectPublicKeyInfo` prefix, the same one
/// the production SPKI parser anchors on. Building an SPKI from a raw point here
/// (mirroring what AWS/GCP KMS return) keeps the test signer's exported public key
/// in the exact wire form the validated build path parses.
const ED25519_TEST_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn ed25519_spki_from_raw(raw: &[u8; 32]) -> Vec<u8> {
    let mut der = ED25519_TEST_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw);
    der
}

/// Mint an Ed25519 server leaf signed by `ca`, returning the cert plus the local
/// delegated signer whose key is the cert's key (seed extracted from the rcgen
/// PKCS#8: a fixed 16-byte prefix `... 04 22 04 20` then the 32-byte seed).
fn make_ed25519_server_leaf(ca: &Ca) -> (CertificateDer<'static>, LocalEd25519Tls) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![dns("localhost")];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("ed25519 leaf signed");
    let der = cert.der().clone();
    let pkcs8 = key.serialize_der();
    // RFC 8410 PKCS#8 Ed25519: the 32-byte seed sits at bytes [16..48], immediately
    // after the Ed25519 AlgorithmIdentifier + OCTET-STRING headers. The outer
    // SEQUENCE length and version vary (rcgen emits the v2 form WITH the public key
    // appended, ~83 bytes), but bytes [5..16] — `30 05 06 03 2b 65 70 04 22 04 20`
    // (Ed25519 OID, then the `04 22` private-key wrapper and `04 20` inner OCTET
    // STRING) — are invariant and directly precede the seed. Anchor on that so a
    // future rcgen encoding change fails closed with a clear error rather than
    // silently slicing the wrong bytes.
    const ED25519_SEED_HEADER: [u8; 11] = [
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    assert!(
        pkcs8.len() >= 48,
        "expected an Ed25519 PKCS#8 key of at least 48 bytes, got {}",
        pkcs8.len()
    );
    assert_eq!(
        &pkcs8[5..16],
        &ED25519_SEED_HEADER,
        "unexpected Ed25519 PKCS#8 header; rcgen encoding may have changed"
    );
    let seed: [u8; 32] = pkcs8[16..48].try_into().expect("ed25519 pkcs8 seed");
    (
        der,
        LocalEd25519Tls(mcps_core::SigningKey::from_seed_bytes(&seed)),
    )
}

#[test]
fn delegated_ed25519_tls_handshake_round_trip() {
    let client_ca = make_ca();
    // Server CA issues the (Ed25519) server leaf; the proxy trusts `client_ca` for
    // CLIENT auth. The server's TLS private key never reaches rustls — the resolver
    // holds only the public cert + the delegated signer.
    let server_ca = make_ca();
    let (server_cert, delegated_signer) = make_ed25519_server_leaf(&server_ca);
    let resolver = mcps_proxy::DelegatedCertResolver::new(
        vec![server_cert],
        std::sync::Arc::new(delegated_signer),
    );
    let config = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_with_crls(
            resolver,
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("delegated server config"),
    );

    let (client_cert, client_key) = make_leaf(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, identity| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                let _ = identity;
                b"{\"ok\":true}".to_vec()
            },
        )
    });

    // Use a client that FULLY validates the server (chain to the test CA, hostname,
    // AND CertificateVerify signature): the handshake completes only if the delegated
    // signer produced a cryptographically valid Ed25519 CertificateVerify over the
    // transcript. Nothing is asserted/bypassed, so this proves delegated-signing
    // correctness end to end.
    let response = client_round_trip(
        addr,
        client_config_validating(
            server_ca.cert.der().clone(),
            (vec![client_cert], client_key),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip over a delegated-signed handshake");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    assert_eq!(
        identity.expect("verified client identity").value,
        "spiffe://example.org/agent-1"
    );
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G / issue #58: the VALIDATED delegated build path. It wraps the
// frozen `build_server_config_delegated_with_crls` with two fail-closed checks at
// CONFIG CONSTRUCTION (before any server starts): Ed25519-only leaf, and the
// signer's public key must match the leaf certificate's public key.
// ---------------------------------------------------------------------------

/// A delegated signer whose public key is INDEPENDENT of (and so cannot match) any
/// given leaf certificate — used to drive the cert↔signer mismatch fail-closed
/// path. Backed by a distinct local Ed25519 key.
#[derive(Debug)]
struct MismatchedEd25519Tls(mcps_core::SigningKey);
impl mcps_proxy::RawEd25519TlsSigner for MismatchedEd25519Tls {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcps_proxy::KeyError> {
        Ok(mcps_core::b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
    }
    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcps_proxy::KeyError> {
        Ok(ed25519_spki_from_raw(&self.0.public_key().to_bytes()))
    }
}

/// Mint an ECDSA (NIST P-256) server leaf signed by `ca` — a NON-Ed25519 leaf used
/// to drive the Ed25519-only fail-closed path of the validated delegated builder.
fn make_ecdsa_server_leaf(ca: &Ca) -> CertificateDer<'static> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![dns("localhost")];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("ecdsa leaf signed");
    cert.der().clone()
}

#[test]
fn validated_delegated_build_round_trip_and_corrupted_sig_fails() {
    // (b) The validated builder accepts a signer whose pubkey MATCHES the leaf cert,
    // and a real full-WebPKI client completes the mTLS handshake — proving the
    // delegated Ed25519 signature is wire-correct. Then a CORRUPTED signature breaks
    // the handshake (load-bearing).
    let client_ca = make_ca();
    let server_ca = make_ca();
    let (server_cert, delegated_signer) = make_ed25519_server_leaf(&server_ca);

    let config = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert],
            std::sync::Arc::new(delegated_signer),
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated server config (matching key) must build"),
    );

    let (client_cert, client_key) = make_leaf(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );

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

    let response = client_round_trip(
        addr,
        client_config_validating(
            server_ca.cert.der().clone(),
            (vec![client_cert], client_key),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip over the validated delegated handshake");
    assert_eq!(response, b"{\"ok\":true}");
    let _ = server.join().expect("join").expect("serve ok");

    // Corrupting the delegated signature must break the handshake (the validating
    // client verifies CertificateVerify). A signer that flips a bit of every raw
    // signature drives this.
    #[derive(Debug)]
    struct CorruptingEd25519Tls(LocalEd25519Tls);
    impl mcps_proxy::RawEd25519TlsSigner for CorruptingEd25519Tls {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            let mut sig = self.0.sign_tls_ed25519(message)?;
            sig[0] ^= 0x01; // corrupt one bit — the signature no longer verifies
            Ok(sig)
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            // Same public key as the honest signer: the cert↔signer check still
            // passes, so the build succeeds and the BREAK is at the handshake.
            self.0.tls_public_key_spki_der()
        }
    }

    let client_ca2 = make_ca();
    let server_ca2 = make_ca();
    let (server_cert2, honest_signer) = make_ed25519_server_leaf(&server_ca2);
    let corrupting = CorruptingEd25519Tls(honest_signer);
    let config2 = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert2],
            std::sync::Arc::new(corrupting),
            vec![client_ca2.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("build still succeeds: the public key matches; the BREAK is the bad signature"),
    );

    let (client_cert2, client_key2) = make_leaf(
        &client_ca2,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr2 = listener2.local_addr().expect("addr");
    let server2 = thread::spawn(move || {
        serve_once(
            &listener2,
            config2,
            &ServerOptions::default(),
            |_req, _id| b"{\"ok\":true}".to_vec(),
        )
    });
    let result = client_round_trip(
        addr2,
        client_config_validating(
            server_ca2.cert.der().clone(),
            (vec![client_cert2], client_key2),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    );
    assert!(
        result.is_err(),
        "a corrupted delegated signature MUST fail the validating handshake"
    );
    let _ = server2.join();
}

#[test]
fn validated_delegated_build_rejects_cert_signer_key_mismatch() {
    // (c) The signer signs for a DIFFERENT key than the leaf certificate presents.
    // The validated builder must FAIL CLOSED at construction — no server.
    let client_ca = make_ca();
    let server_ca = make_ca();
    let (server_cert, _matching_signer) = make_ed25519_server_leaf(&server_ca);
    // A signer with an unrelated key (seed 0xAA..) — its pubkey cannot equal the
    // leaf's.
    let mismatched = MismatchedEd25519Tls(mcps_core::SigningKey::from_seed_bytes(&[0xAAu8; 32]));

    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![server_cert],
        std::sync::Arc::new(mismatched),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a cert↔signer key mismatch must fail closed at config construction");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch, got {err:?}"
    );
}

#[test]
fn validated_delegated_build_rejects_non_ed25519_leaf() {
    // (d) A non-Ed25519 (ECDSA P-256) leaf under delegated mode must FAIL CLOSED:
    // delegated TLS is Ed25519-only. The signer's own key is irrelevant — the leaf
    // SPKI is rejected first.
    let client_ca = make_ca();
    let server_ca = make_ca();
    let ecdsa_leaf = make_ecdsa_server_leaf(&server_ca);
    let signer = LocalEd25519Tls(mcps_core::SigningKey::from_seed_bytes(&[3u8; 32]));

    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![ecdsa_leaf],
        std::sync::Arc::new(signer),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a non-Ed25519 leaf must fail closed under delegated mode");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch (Ed25519-only), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G / issue #60: AWS KMS delegated TLS handshake signing. The
// server's TLS key is a SECOND, DISTINCT KMS key; an `AwsKmsEd25519Backend` (over
// an in-memory FAKE KMS transport backed by a local Ed25519 key — no network, no
// AWS credentials) signs each handshake via the RAW-Ed25519 KMS `Sign` path. A real
// full-WebPKI client completing the mTLS handshake PROVES the delegated KMS
// signature is wire-correct. These tests run only under `--features
// aws_kms_keysource`.
// ---------------------------------------------------------------------------

/// Mint an Ed25519 server leaf signed by `ca` from a FIXED 32-byte seed, so a cloud
/// KMS backend constructed from the SAME seed advertises the leaf's public key
/// (cert↔signer match). Mirrors `make_ed25519_server_leaf` but with a deterministic
/// key so the KMS-side key and the certificate key are guaranteed identical.
#[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
fn make_ed25519_server_leaf_from_seed(ca: &Ca, seed: &[u8; 32]) -> CertificateDer<'static> {
    // RFC 8410 PKCS#8 v1 for an Ed25519 private key carrying exactly this seed:
    // SEQUENCE { version 0, AlgorithmIdentifier { id-Ed25519 }, OCTET STRING {
    // OCTET STRING(32) seed } }. 16-byte fixed header + 32-byte seed = 48 bytes.
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(seed);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_ED25519,
    )
    .expect("ed25519 key from seed");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![dns("localhost")];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("ed25519 leaf signed");
    cert.der().clone()
}

/// (c) #60: a full-WebPKI in-process mTLS handshake whose delegated signer is an AWS
/// KMS backend (over a fake transport) keyed to MATCH the server leaf cert. The
/// validating client completes the handshake only if the KMS-signed
/// `CertificateVerify` is cryptographically valid — proving the AWS RAW-Ed25519 sign
/// is wire-correct end to end. Corrupting the fake KMS signature breaks the handshake.
#[cfg(feature = "aws_kms_keysource")]
#[test]
fn aws_kms_delegated_tls_handshake_round_trip_and_corruption_fails() {
    let seed = [0x42u8; 32];
    let client_ca = make_ca();
    let server_ca = make_ca();
    let server_cert = make_ed25519_server_leaf_from_seed(&server_ca, &seed);
    let backend =
        mcps_proxy::AwsKmsEd25519Backend::for_test_with_local_seed(&seed, "alias/mcps-tls")
            .expect("aws kms backend over fake transport");

    let config = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert],
            std::sync::Arc::new(backend),
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated config with the matching KMS TLS key must build"),
    );

    let (client_cert, client_key) = make_leaf(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, _id| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                b"{\"ok\":true}".to_vec()
            },
        )
    });
    let response = client_round_trip(
        addr,
        client_config_validating(
            server_ca.cert.der().clone(),
            (vec![client_cert], client_key),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip over an AWS-KMS-delegated handshake");
    assert_eq!(response, b"{\"ok\":true}");
    let _ = server.join().expect("join").expect("serve ok");

    // Corrupt the KMS signature → the validating client's CertificateVerify check
    // fails the handshake. The wrapper keeps the SAME public key (so the cert↔signer
    // build check passes; the BREAK is the bad signature on the wire).
    struct CorruptingAwsKms(mcps_proxy::AwsKmsEd25519Backend);
    impl mcps_proxy::RawEd25519TlsSigner for CorruptingAwsKms {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            let mut sig = self.0.sign_tls_ed25519(message)?;
            sig[0] ^= 0x01;
            Ok(sig)
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            self.0.tls_public_key_spki_der()
        }
    }

    let seed2 = [0x7Eu8; 32];
    let client_ca2 = make_ca();
    let server_ca2 = make_ca();
    let server_cert2 = make_ed25519_server_leaf_from_seed(&server_ca2, &seed2);
    let backend2 =
        mcps_proxy::AwsKmsEd25519Backend::for_test_with_local_seed(&seed2, "alias/mcps-tls")
            .expect("aws kms backend 2");
    let config2 = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert2],
            std::sync::Arc::new(CorruptingAwsKms(backend2)),
            vec![client_ca2.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("build succeeds: public key matches; the BREAK is the corrupted signature"),
    );
    let (client_cert2, client_key2) = make_leaf(
        &client_ca2,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr2 = listener2.local_addr().expect("addr");
    let server2 = thread::spawn(move || {
        serve_once(
            &listener2,
            config2,
            &ServerOptions::default(),
            |_req, _id| b"{\"ok\":true}".to_vec(),
        )
    });
    let result = client_round_trip(
        addr2,
        client_config_validating(
            server_ca2.cert.der().clone(),
            (vec![client_cert2], client_key2),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    );
    assert!(
        result.is_err(),
        "a corrupted AWS-KMS delegated signature MUST fail the validating handshake"
    );
    let _ = server2.join();
}

/// (d) #60: an AWS KMS backend whose key does NOT match the leaf cert must FAIL
/// CLOSED at config construction (cert↔signer mismatch), and a non-Ed25519 (ECDSA)
/// leaf under the AWS-delegated path is likewise rejected (Ed25519-only).
#[cfg(feature = "aws_kms_keysource")]
#[test]
fn aws_kms_delegated_build_rejects_mismatch_and_non_ed25519_leaf() {
    let client_ca = make_ca();
    let server_ca = make_ca();

    // Mismatch: leaf minted from one seed, KMS backend keyed to a DIFFERENT seed.
    let leaf = make_ed25519_server_leaf_from_seed(&server_ca, &[0x11u8; 32]);
    let mismatched =
        mcps_proxy::AwsKmsEd25519Backend::for_test_with_local_seed(&[0x22u8; 32], "alias/mcps-tls")
            .expect("aws kms backend");
    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![leaf],
        std::sync::Arc::new(mismatched),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a cert↔KMS-key mismatch must fail closed at config construction");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch, got {err:?}"
    );

    // Non-Ed25519 leaf (ECDSA P-256): the leaf SPKI is rejected first (Ed25519-only).
    let ecdsa_leaf = make_ecdsa_server_leaf(&server_ca);
    let backend =
        mcps_proxy::AwsKmsEd25519Backend::for_test_with_local_seed(&[0x33u8; 32], "alias/mcps-tls")
            .expect("aws kms backend");
    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![ecdsa_leaf],
        std::sync::Arc::new(backend),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a non-Ed25519 leaf must fail closed under AWS-delegated mode");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch (Ed25519-only), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G / issue #61: GCP Cloud KMS delegated TLS handshake signing. The
// server's TLS key is a SECOND, DISTINCT Cloud KMS key version; a
// `GcpKmsEd25519Backend` (over an in-memory FAKE Cloud KMS transport backed by a
// local Ed25519 key — no network, no GCP credentials) signs each handshake via the
// RAW-Ed25519 `asymmetricSign` path. A real full-WebPKI client completing the mTLS
// handshake PROVES the delegated KMS signature is wire-correct. These tests run only
// under `--features gcp_kms_keysource`.
// ---------------------------------------------------------------------------

/// (c) #61: a full-WebPKI in-process mTLS handshake whose delegated signer is a GCP
/// Cloud KMS backend (over a fake transport) keyed to MATCH the server leaf cert.
/// The validating client completes the handshake only if the KMS-signed
/// `CertificateVerify` is cryptographically valid — proving the GCP RAW-Ed25519
/// `asymmetricSign` is wire-correct end to end. Corrupting the fake KMS signature
/// breaks the handshake.
#[cfg(feature = "gcp_kms_keysource")]
#[test]
fn gcp_kms_delegated_tls_handshake_round_trip_and_corruption_fails() {
    let seed = [0x42u8; 32];
    let client_ca = make_ca();
    let server_ca = make_ca();
    let server_cert = make_ed25519_server_leaf_from_seed(&server_ca, &seed);
    let backend = mcps_proxy::GcpKmsEd25519Backend::for_test_with_local_seed(&seed)
        .expect("gcp kms backend over fake transport");

    let config = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert],
            std::sync::Arc::new(backend),
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated config with the matching KMS TLS key must build"),
    );

    let (client_cert, client_key) = make_leaf(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, _id| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                b"{\"ok\":true}".to_vec()
            },
        )
    });
    let response = client_round_trip(
        addr,
        client_config_validating(
            server_ca.cert.der().clone(),
            (vec![client_cert], client_key),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("client round trip over a GCP-KMS-delegated handshake");
    assert_eq!(response, b"{\"ok\":true}");
    let _ = server.join().expect("join").expect("serve ok");

    // Corrupt the KMS signature → the validating client's CertificateVerify check
    // fails the handshake. The wrapper keeps the SAME public key (so the cert↔signer
    // build check passes; the BREAK is the bad signature on the wire).
    struct CorruptingGcpKms(mcps_proxy::GcpKmsEd25519Backend);
    impl mcps_proxy::RawEd25519TlsSigner for CorruptingGcpKms {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            let mut sig = self.0.sign_tls_ed25519(message)?;
            sig[0] ^= 0x01;
            Ok(sig)
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcps_proxy::KeyError> {
            self.0.tls_public_key_spki_der()
        }
    }

    let seed2 = [0x7Eu8; 32];
    let client_ca2 = make_ca();
    let server_ca2 = make_ca();
    let server_cert2 = make_ed25519_server_leaf_from_seed(&server_ca2, &seed2);
    let backend2 = mcps_proxy::GcpKmsEd25519Backend::for_test_with_local_seed(&seed2)
        .expect("gcp kms backend 2");
    let config2 = std::sync::Arc::new(
        mcps_proxy::build_server_config_delegated_validated(
            vec![server_cert2],
            std::sync::Arc::new(CorruptingGcpKms(backend2)),
            vec![client_ca2.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("build succeeds: public key matches; the BREAK is the corrupted signature"),
    );
    let (client_cert2, client_key2) = make_leaf(
        &client_ca2,
        vec![uri("spiffe://example.org/agent-1")],
        None,
        true,
    );
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr2 = listener2.local_addr().expect("addr");
    let server2 = thread::spawn(move || {
        serve_once(
            &listener2,
            config2,
            &ServerOptions::default(),
            |_req, _id| b"{\"ok\":true}".to_vec(),
        )
    });
    let result = client_round_trip(
        addr2,
        client_config_validating(
            server_ca2.cert.der().clone(),
            (vec![client_cert2], client_key2),
        ),
        b"{\"jsonrpc\":\"2.0\"}",
    );
    assert!(
        result.is_err(),
        "a corrupted GCP-KMS delegated signature MUST fail the validating handshake"
    );
    let _ = server2.join();
}

/// (d) #61: a GCP KMS backend whose key does NOT match the leaf cert must FAIL
/// CLOSED at config construction (cert↔signer mismatch), and a non-Ed25519 (ECDSA)
/// leaf under the GCP-delegated path is likewise rejected (Ed25519-only).
#[cfg(feature = "gcp_kms_keysource")]
#[test]
fn gcp_kms_delegated_build_rejects_mismatch_and_non_ed25519_leaf() {
    let client_ca = make_ca();
    let server_ca = make_ca();

    // Mismatch: leaf minted from one seed, KMS backend keyed to a DIFFERENT seed.
    let leaf = make_ed25519_server_leaf_from_seed(&server_ca, &[0x11u8; 32]);
    let mismatched = mcps_proxy::GcpKmsEd25519Backend::for_test_with_local_seed(&[0x22u8; 32])
        .expect("gcp kms backend");
    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![leaf],
        std::sync::Arc::new(mismatched),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a cert↔KMS-key mismatch must fail closed at config construction");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch, got {err:?}"
    );

    // Non-Ed25519 leaf (ECDSA P-256): the leaf SPKI is rejected first (Ed25519-only).
    let ecdsa_leaf = make_ecdsa_server_leaf(&server_ca);
    let backend = mcps_proxy::GcpKmsEd25519Backend::for_test_with_local_seed(&[0x33u8; 32])
        .expect("gcp kms backend");
    let err = mcps_proxy::build_server_config_delegated_validated(
        vec![ecdsa_leaf],
        std::sync::Arc::new(backend),
        vec![client_ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect_err("a non-Ed25519 leaf must fail closed under GCP-delegated mode");
    assert!(
        matches!(err, mcps_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch (Ed25519-only), got {err:?}"
    );
}

#[test]
fn missing_client_certificate_is_rejected() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    // Client presents NO certificate; the server requires one → fail closed.
    let _ = client_round_trip(addr, client_config(None), b"{}");
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "server must reject a connection with no client certificate"
    );
}

#[test]
fn untrusted_client_certificate_is_rejected() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);

    // A client cert signed by a DIFFERENT CA than the server's client-CA root.
    let rogue_ca = make_ca();
    let (rogue_cert, rogue_key) =
        make_leaf(&rogue_ca, vec![uri("spiffe://evil/agent")], None, true);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    let _ = client_round_trip(
        addr,
        client_config(Some((vec![rogue_cert], rogue_key))),
        b"{}",
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "server must reject a client certificate not signed by the configured client-CA"
    );
}

// ---------------------------------------------------------------------------
// 3. Max client-certificate lifetime enforcement (v1 revocation posture).
// ---------------------------------------------------------------------------

fn error_body(bytes: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"].as_str().unwrap_or("").to_string()
}

#[test]
fn over_long_client_cert_is_rejected() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    // Currently-valid but long-lived (2020..2035 ≈ 15y) cert.
    let (client_cert, client_key) = make_leaf_with_validity(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        true,
        (2020, 1, 1),
        (2035, 1, 1),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let options = ServerOptions {
        max_client_cert_lifetime: Some(Duration::from_secs(3600)), // 1h
        ..ServerOptions::default()
    };

    let server = thread::spawn(move || {
        serve_once(&listener, config, &options, |_req, _id| {
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".to_vec()
        })
    });
    let body = client_round_trip(
        addr,
        client_config(Some((vec![client_cert], client_key))),
        b"{\"jsonrpc\":\"2.0\",\"id\":1}",
    )
    .expect("handshake succeeds; app-level rejection");
    let _ = server.join();
    assert_eq!(
        error_body(&body),
        "mcps.transport_binding_failed",
        "a client cert exceeding the max lifetime must be rejected"
    );
}

#[test]
fn within_limit_client_cert_is_served() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    // Same 15y cert, but the configured max is generous (≈20y) → served.
    let (client_cert, client_key) = make_leaf_with_validity(
        &client_ca,
        vec![uri("spiffe://example.org/agent-1")],
        true,
        (2020, 1, 1),
        (2035, 1, 1),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let options = ServerOptions {
        max_client_cert_lifetime: Some(Duration::from_secs(20 * 365 * 24 * 3600)),
        ..ServerOptions::default()
    };

    let server = thread::spawn(move || {
        serve_once(&listener, config, &options, |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });
    let body = client_round_trip(
        addr,
        client_config(Some((vec![client_cert], client_key))),
        b"{\"jsonrpc\":\"2.0\",\"id\":1}",
    )
    .expect("round trip");
    let _ = server.join();
    assert_eq!(
        body, b"{\"ok\":true}",
        "a cert within the max lifetime is served"
    );
}

// ---------------------------------------------------------------------------
// 4. #3839 — offline CRL client-certificate revocation (OFFLINE only; no online
//    OCSP / CRL-distribution-point fetching, which is deferred to a follow-up).
//
//    Both tests mint a CA, issue a client cert with an explicit serial, build a
//    CRL signed by that CA, and configure the proxy's verifier with it:
//      (a) a NON-revoked client cert from the same CA still completes the mTLS
//          round-trip;
//      (b) the REVOKED client cert's handshake is REJECTED (fail closed).
// ---------------------------------------------------------------------------

#[test]
fn non_revoked_client_cert_completes_handshake_with_crl_configured() {
    let client_ca = make_ca();
    // The CRL revokes serial 0xBADBAD; this client uses a DIFFERENT serial.
    let crl = make_crl(&client_ca, &[0x00BA_DBAD]);
    let config = server_config_with_crls_for(&client_ca, vec![crl]);
    let (client_cert, client_key) =
        make_client_leaf_with_serial(&client_ca, "spiffe://example.org/agent-good", 0x0000_0042);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            |request, _id| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                b"{\"ok\":true}".to_vec()
            },
        )
    });

    let response = client_round_trip(
        addr,
        client_config(Some((vec![client_cert], client_key))),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("non-revoked client round trip");
    assert_eq!(
        response, b"{\"ok\":true}",
        "a non-revoked client cert from the same CA must still complete the mTLS round-trip"
    );
    server.join().expect("join").expect("serve ok");
}

#[test]
fn revoked_client_cert_handshake_is_rejected() {
    let client_ca = make_ca();
    let revoked_serial = 0x0000_0099;
    // The client cert and the CRL share the SAME serial → this cert is revoked.
    let (client_cert, client_key) = make_client_leaf_with_serial(
        &client_ca,
        "spiffe://example.org/agent-revoked",
        revoked_serial,
    );
    let crl = make_crl(&client_ca, &[revoked_serial]);
    let config = server_config_with_crls_for(&client_ca, vec![crl]);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    // The handshake must fail closed: a revoked client cert is rejected by the
    // verifier, so serve_once surfaces an error (the inner is never reached).
    let _ = client_round_trip(
        addr,
        client_config(Some((vec![client_cert], client_key))),
        b"{\"jsonrpc\":\"2.0\"}",
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "the server must reject a client certificate revoked by the configured CRL"
    );
}
