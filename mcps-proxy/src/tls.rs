//! `RustlsDirectProvider` — Rust-native TLS termination + mTLS (MCPS-025,
//! ADR-MCPS-014).
//!
//! The proxy terminates TLS itself with `rustls` (the `ring` provider), requires
//! and verifies a client certificate against a configured client-CA
//! (`WebPkiClientVerifier`), and extracts the verified client identity from the
//! leaf certificate (first URI SAN → DNS SAN → CN). It is blocking and uses
//! `std::net` + threads — NO async runtime — mirroring the Phase-3 std::net HTTP
//! framing. The extracted identity is handed to the request handler, where the
//! Phase-6 transport-binding policy (MCPS-026) ties it to the request `signer`.
//!
//! Streamable HTTP here is single-request-per-connection JSON (one POST in, one
//! JSON response out) — SSE streaming is intentionally not implemented.

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcps_core::json_rpc_error_object;
use mcps_core::McpsError;
use rustls::crypto::ring;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use crate::transport::IdentityPolicy;
use crate::transport::IdentitySource;
use crate::transport::RequestHeaders;
use crate::transport::ReverseProxyMtlsProvider;
use crate::transport::TransportBindingProvider;
use crate::transport::TransportIdentity;

/// Resource limits applied to every served connection — the blocking server's
/// defense against slow-loris, oversized-request, and connection-exhaustion
/// denial of service. Every limit fails closed: a connection that exceeds one is
/// dropped (or never accepted), never served partially.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Maximum bytes accepted before the end-of-headers marker. Caps header
    /// floods and unterminated header streams.
    pub max_header_bytes: usize,
    /// Maximum request body (`Content-Length`, and bytes actually read). Caps
    /// oversized payloads.
    pub max_body_bytes: usize,
    /// Per-socket read timeout (covers a stalled TLS handshake and slow-loris
    /// body trickling, since reading drives the handshake). `None` disables.
    pub read_timeout: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum simultaneously-served connections in the threaded [`serve`] loop.
    /// Connections beyond the cap are dropped (TCP-accepted then closed) rather
    /// than queued unboundedly.
    pub max_concurrent_connections: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            max_concurrent_connections: 256,
        }
    }
}

/// Where the served request's verified transport identity comes from. These are
/// mutually exclusive: a connection is bound EITHER by a locally-terminated mTLS
/// client certificate OR by a header set by a trusted upstream reverse proxy,
/// never both. The CLI enforces the exclusivity; the serve loop honours the one
/// chosen strategy and never mixes them on a single connection.
#[derive(Debug, Clone)]
pub enum IdentityStrategy {
    /// Direct mTLS: the identity is the configured field of the verified peer
    /// (leaf) certificate. This is the default and leaves the local-TLS path
    /// fully intact.
    DirectTls,
    /// Reverse-proxy ingress: mTLS is terminated UPSTREAM and the verified client
    /// identity is read from a trusted forwarded header. The local client-cert is
    /// NOT consulted for identity (the two sources are mutually exclusive). The
    /// operator asserts the listening socket is reachable only by the trusted
    /// upstream (see [`ReverseProxyMtlsProvider`]).
    ReverseProxyHeader(ReverseProxyMtlsProvider),
}

impl Default for IdentityStrategy {
    fn default() -> Self {
        IdentityStrategy::DirectTls
    }
}

/// How the serve loop turns a connection into a served request: which client-cert
/// field is the authoritative identity, the resource limits, and the maximum
/// client-certificate lifetime.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// The authoritative client-certificate identity field (no implicit fallback).
    /// Used for [`IdentityStrategy::DirectTls`]; for the reverse-proxy strategy the
    /// field is carried inside the provider instead.
    pub identity_policy: IdentityPolicy,
    /// Where the request's verified transport identity is taken from (local mTLS
    /// vs a trusted upstream header). Mutually exclusive by construction.
    pub identity_strategy: IdentityStrategy,
    /// Connection resource limits (DoS defense).
    pub limits: ServerLimits,
    /// Maximum allowed client-certificate validity span
    /// (`not_after - not_before`). This is the v1 revocation posture: with no
    /// online CRL/OCSP, a compromised client cert is usable until expiry, so the
    /// proxy ENFORCES short lifetimes — a cert whose span exceeds this (or whose
    /// validity cannot be parsed) is rejected with `mcps.transport_binding_failed`.
    /// `None` disables the check. The production CLI defaults this to 1 hour; this
    /// library `Default` leaves it `None` so existing callers are unchanged.
    ///
    /// Exposure window of a compromised transport credential is bounded by
    /// `max_client_cert_lifetime`. The end-to-end request-authority exposure
    /// window is `cert_lifetime + resolver_cache_ttl + request_lifetime +
    /// max_clock_skew`.
    pub max_client_cert_lifetime: Option<Duration>,
    /// ONLINE OCSP client-cert revocation (#4030), the online sibling of #3839's
    /// offline CRL posture. When `Some`, after the handshake the serve loop asks
    /// the leaf's OCSP responder whether it is revoked, BEFORE the handler, and
    /// fails closed (rejects) on `Revoked`/`Unknown`/error unless the checker is
    /// in soft-fail mode (see [`ocsp_rejection`]). `None` disables the online
    /// check (the default). This field — and the entire online check — exists
    /// ONLY in a build with the `online_ocsp` feature; the default build has no
    /// such field and the hook is a compile-time no-op, so it is byte-for-byte
    /// unchanged.
    #[cfg(feature = "online_ocsp")]
    pub ocsp_checker: Option<crate::ocsp::OcspChecker>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            identity_policy: IdentityPolicy::default(),
            identity_strategy: IdentityStrategy::default(),
            limits: ServerLimits::default(),
            max_client_cert_lifetime: None,
            #[cfg(feature = "online_ocsp")]
            ocsp_checker: None,
        }
    }
}

/// Errors building the TLS server configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A client-CA certificate could not be added to the trust store.
    #[error("invalid client CA certificate")]
    BadClientCa,
    /// The client-certificate verifier could not be built.
    #[error("client verifier build failed: {0}")]
    Verifier(String),
    /// The server certificate/key or protocol configuration was rejected.
    #[error("server TLS config failed: {0}")]
    Config(String),
}

/// Marker for the production direct-TLS transport-binding provider. The verified
/// identity is produced per connection by the serve loop (see [`serve_once`] /
/// [`serve`]); the binding policy (MCPS-026) consumes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustlsDirectProvider;

impl RustlsDirectProvider {
    /// Build a `rustls` server config that REQUIRES and verifies a client
    /// certificate against `client_ca`, presenting `server_chain` + `server_key`.
    /// Uses the `ring` provider explicitly (no process-global default install).
    ///
    /// Equivalent to [`build_server_config_with_crls`](Self::build_server_config_with_crls)
    /// with no CRLs — preserved byte-for-byte for callers that do not configure
    /// offline revocation.
    pub fn build_server_config(
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_ca: Vec<CertificateDer<'static>>,
    ) -> Result<ServerConfig, TlsError> {
        Self::build_server_config_with_crls(
            server_chain,
            server_key,
            client_ca,
            Vec::new(),
            false,
        )
    }

    /// As [`build_server_config`](Self::build_server_config), additionally checking
    /// each presented client certificate against the supplied OFFLINE certificate
    /// revocation lists (#3839). This is OFFLINE CRL revocation only: the CRLs are
    /// loaded from disk at startup and never refreshed over the network. ONLINE
    /// OCSP / CRL-distribution-point fetching is intentionally NOT implemented here
    /// (it would require an HTTP client + a live responder, expanding the
    /// firewalled supply chain) and is deferred to a follow-up.
    ///
    /// Fail-closed posture (the rustls 0.23 builder defaults, made explicit):
    ///   * a client cert listed as revoked by any CRL → handshake REJECTED;
    ///   * the FULL chain to the trust anchor has revocation checked
    ///     (`RevocationCheckDepth::Chain`, the default);
    ///   * a cert whose revocation status cannot be determined from the CRLs is
    ///     REJECTED (`UnknownStatusPolicy::Deny`, the default) UNLESS
    ///     `allow_unknown_revocation_status` is `true` (operator opt-out).
    ///
    /// When `crls` is empty this behaves exactly like the no-CRL path:
    /// `.with_crls([])` adds nothing and rustls performs no revocation checks, so
    /// `allow_unknown_revocation_status` has no effect.
    pub fn build_server_config_with_crls(
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_ca: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
        allow_unknown_revocation_status: bool,
    ) -> Result<ServerConfig, TlsError> {
        let provider = Arc::new(ring::default_provider());

        let mut roots = RootCertStore::empty();
        for ca in client_ca {
            roots.add(ca).map_err(|_| TlsError::BadClientCa)?;
        }
        let mut builder =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .with_crls(crls);
        // Default is the strict fail-closed posture (unknown status → reject); only
        // an explicit operator opt-out relaxes it. A malformed CRL surfaces from
        // `.build()` below as a startup `TlsError::Verifier` (fail closed).
        if allow_unknown_revocation_status {
            builder = builder.allow_unknown_revocation_status();
        }
        let verifier = builder
            .build()
            .map_err(|e| TlsError::Verifier(e.to_string()))?;

        // MCPS-079 fault injection ("test of the tests"), the symmetric mirror of
        // mcps-transport's `fault_accept_any_server`. When — and ONLY when — the
        // `fault_accept_any_client` feature is compiled in (off by default, never
        // in production or the default `bazel test //...`), the verifying
        // `WebPkiClientVerifier` above is DISCARDED and replaced by an accept-any
        // CLIENT verifier. This is the deliberately-broken client-auth control: it
        // lets the periodic fault-injection harness demonstrate that the proxy's
        // client-cert-rejection guards are load-bearing (with the fault active, a
        // missing OR untrusted client cert is NO LONGER rejected). The verifying
        // build never constructs this; the byte-for-byte default path is the
        // WebPkiClientVerifier branch below.
        #[cfg(feature = "fault_accept_any_client")]
        let server_config = {
            let _ = verifier; // the verifying path is intentionally bypassed
            ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| TlsError::Config(e.to_string()))?
                .with_client_cert_verifier(Arc::new(
                    fault_accept_any::AcceptAnyClientVerifier::new(provider),
                ))
                .with_single_cert(server_chain, server_key)
                .map_err(|e| TlsError::Config(e.to_string()))
        };

        #[cfg(not(feature = "fault_accept_any_client"))]
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(|e| TlsError::Config(e.to_string()));

        server_config
    }
}

/// Extract the verified client identity from a leaf certificate (DER) using the
/// authoritative field named by `policy`. There is NO fallback: the configured
/// field is read and nothing else. Returns `None` if the certificate cannot be
/// parsed or does not carry the selected field — the caller (transport binding)
/// then fails closed rather than accepting a weaker identity.
pub fn extract_identity(leaf_der: &[u8], policy: IdentityPolicy) -> Option<TransportIdentity> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;

    match policy {
        IdentityPolicy::UriSan => {
            let san = cert.subject_alternative_name().ok().flatten()?;
            san.value.general_names.iter().find_map(|name| match name {
                GeneralName::URI(uri) => Some(TransportIdentity::new(*uri, IdentitySource::UriSan)),
                _ => None,
            })
        }
        IdentityPolicy::DnsSan => {
            let san = cert.subject_alternative_name().ok().flatten()?;
            san.value.general_names.iter().find_map(|name| match name {
                GeneralName::DNSName(dns) => {
                    Some(TransportIdentity::new(*dns, IdentitySource::DnsSan))
                }
                _ => None,
            })
        }
        IdentityPolicy::CnLegacy => {
            // Bind to an owned String so the borrow of `cert` ends before return.
            let common_name: Option<String> = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(str::to_string);
            common_name.map(|cn| TransportIdentity::new(cn, IdentitySource::CommonName))
        }
    }
}

/// The verified client identity for an established server connection (the leaf of
/// the peer certificate chain) under `policy`, or `None` if no peer certificate
/// is present or it lacks the selected identity field.
fn connection_identity(conn: &ServerConnection, policy: IdentityPolicy) -> Option<TransportIdentity> {
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    extract_identity(leaf.as_ref(), policy)
}

/// Resolve the verified transport identity for one served request under the
/// configured [`IdentityStrategy`]. The two strategies are MUTUALLY EXCLUSIVE on
/// a per-connection basis:
///   * [`IdentityStrategy::DirectTls`] reads it from the verified peer
///     certificate via [`connection_identity`] and IGNORES request headers;
///   * [`IdentityStrategy::ReverseProxyHeader`] reads it from the trusted
///     forwarded header via the [`ReverseProxyMtlsProvider`] and NEVER consults
///     the local client certificate (mTLS is terminated upstream).
/// Either way a missing/unparseable identity is `None`, and the downstream
/// transport-binding policy fails closed.
fn resolve_identity(
    conn: &ServerConnection,
    options: &ServerOptions,
    headers: &RequestHeaders,
) -> Option<TransportIdentity> {
    match &options.identity_strategy {
        IdentityStrategy::DirectTls => connection_identity(conn, options.identity_policy),
        IdentityStrategy::ReverseProxyHeader(provider) => provider.verified_identity(headers),
    }
}

/// The validity span (`not_after - not_before`, seconds) of a leaf certificate,
/// or `None` if it cannot be parsed OR the span is negative/inverted
/// (`not_after < not_before`). A degenerate/inverted validity window is treated
/// exactly like an unparseable certificate: returning `None` makes the caller's
/// `is_some_and(|l| l <= max)` yield `false`, so `cert_lifetime_rejection` fails
/// closed (G-5) rather than silently admitting a cert whose negative span would
/// trivially satisfy any `<= max` bound.
fn leaf_cert_lifetime_secs(leaf_der: &[u8]) -> Option<i64> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    // Fail closed on a negative OR degenerate (zero-length) validity window:
    // `not_after <= not_before` would otherwise yield <= 0, which the caller's
    // `is_some_and(|l| l <= max)` treats as within ANY max lifetime, admitting an
    // inverted or instant-lifetime cert. `None` routes it to the rejection path.
    if not_after <= not_before {
        return None;
    }
    Some(not_after - not_before)
}

/// Enforce the configured maximum client-certificate lifetime (the v1 revocation
/// posture). Returns `Some(error_bytes)` — a `mcps.transport_binding_failed`
/// JSON-RPC error bound to the request id — when a limit is set and the verified
/// client cert's validity span exceeds it (or cannot be parsed); `None` when the
/// cert is within the limit or no limit is configured. Emitting the
/// transport-layer error here is consistent with the proxy being the sole holder
/// of the connection (see `transport` module docs).
fn cert_lifetime_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let max = options.max_client_cert_lifetime?;
    let leaf = conn.peer_certificates()?.first()?;
    let within_limit = leaf_cert_lifetime_secs(leaf.as_ref())
        .is_some_and(|lifetime| lifetime <= max.as_secs() as i64);
    if within_limit {
        return None;
    }
    // Over-long (or unparseable) cert → fail closed with the transport error,
    // bound to the request id when we can read it.
    let id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    Some(json_rpc_error_object(&McpsError::TransportBindingFailed, &id))
}

/// ADR-MCPS-025 routing-header hygiene rejection — runs at the SAME per-connection
/// point as [`cert_lifetime_rejection`] (after the verified handshake, before the
/// handler). Returns `Some(error_bytes)` when a SEP-2243 routing header
/// (`Mcp-Method` / `Mcp-Name`) is duplicated or malformed, `None` when the routing
/// headers are absent or well-formed.
///
/// The proxy never routes on these headers — the signed body is authoritative —
/// so this is anti-smuggling hygiene (ADR-MCPS-025 rule 4 applying the ADR-MCPS-023
/// strict-header rules). A defect maps to `mcps.transport_binding_failed`, the same
/// transport-boundary token the sibling cert-lifetime / OCSP rejections use.
fn routing_header_rejection(headers: &RequestHeaders, request: &[u8]) -> Option<Vec<u8>> {
    crate::transport::validate_routing_headers(headers)
        .err()
        .map(|_rejection| {
            let id = serde_json::from_slice::<serde_json::Value>(request)
                .ok()
                .and_then(|value| value.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);
            json_rpc_error_object(&McpsError::TransportBindingFailed, &id)
        })
}

/// Online OCSP revocation rejection (#4030) — the online sibling of
/// [`cert_lifetime_rejection`], running at the SAME per-connection point (after
/// the verified handshake, before the handler). Returns `Some(error_bytes)` (a
/// `mcps.transport_binding_failed` JSON-RPC error bound to the request id) when
/// an OCSP checker is configured AND the verified client leaf must be rejected;
/// `None` when no checker is configured or the leaf is admitted.
///
/// Fail-closed posture (mirrors the offline CRL deny-unknown default): the leaf
/// is REJECTED when the responder reports `Revoked` (always), or `Unknown`, or
/// the check errors (unreachable / timeout / parse), UNLESS the checker is in
/// soft-fail mode — in which case only `Revoked` rejects. The issuer is taken
/// from the verified peer chain (the cert directly after the leaf); a leaf with
/// no chained issuer cannot be checked and is treated as an indeterminate
/// result (rejected unless soft-fail). The HTTP fetch carries the checker's
/// mandatory timeout so this can never wedge the blocking serve thread.
#[cfg(feature = "online_ocsp")]
fn ocsp_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let checker = options.ocsp_checker.as_ref()?;
    let reject = || {
        let id = serde_json::from_slice::<serde_json::Value>(request)
            .ok()
            .and_then(|value| value.get("id").cloned())
            .unwrap_or(serde_json::Value::Null);
        Some(json_rpc_error_object(&McpsError::TransportBindingFailed, &id))
    };

    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    // The issuer is the next cert in the verified chain. Without it we cannot
    // build a CertID; treat as an indeterminate (Unknown) result and apply the
    // fail-closed policy (reject unless soft-fail).
    let Some(issuer) = certs.get(1) else {
        return if checker.allows_on_error() { None } else { reject() };
    };

    match checker.check(leaf.as_ref(), issuer.as_ref()) {
        Ok(status) => {
            if checker.allows(status) {
                None
            } else {
                reject()
            }
        }
        // Transport/codec error: indeterminate, fail closed unless soft-fail.
        Err(_) => {
            if checker.allows_on_error() {
                None
            } else {
                reject()
            }
        }
    }
}

/// The per-connection rejection decision: the lifetime guard then (under the
/// `online_ocsp` feature) the online OCSP guard, in that order. Returns the
/// first rejection's error bytes, or `None` if the connection is admitted. In a
/// default build this is exactly `cert_lifetime_rejection` (the OCSP arm does
/// not exist), so the path is byte-for-byte unchanged.
fn connection_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    if let Some(error) = cert_lifetime_rejection(conn, options, request) {
        return Some(error);
    }
    #[cfg(feature = "online_ocsp")]
    if let Some(error) = ocsp_rejection(conn, options, request) {
        return Some(error);
    }
    None
}

/// Accept ONE TLS connection, complete the handshake (mTLS — a missing or
/// untrusted client certificate fails here), read one HTTP request body (bounded
/// by `options.limits`), invoke `handler(request_bytes, identity)`, and write the
/// response. Returns the verified client identity that was observed (for test
/// assertions), extracted with `options.identity_policy`.
///
/// Blocking; the caller owns the accept loop policy (see [`serve`]).
pub fn serve_once<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    let (tcp, _peer) = listener.accept()?;
    apply_socket_timeouts(&tcp, &options.limits)?;
    let conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    // Reading the request drives the handshake to completion; an unauthenticated
    // or untrusted client certificate surfaces here as an error (fail closed).
    let request = read_http_request(&mut stream, &options.limits)?;
    let headers = RequestHeaders::parse(&request.header_block);
    let identity = resolve_identity(&stream.conn, options, &headers);
    // Enforce the per-connection rejection guards (max client-cert lifetime, then
    // online OCSP revocation under the `online_ocsp` feature) BEFORE the handler
    // (inner never reached when rejected).
    let response = match connection_rejection(&stream.conn, options, &request.body)
        .or_else(|| routing_header_rejection(&headers, &request.body))
    {
        Some(error) => error,
        None => handler(&request.body, identity.clone()),
    };
    write_http_response(&mut stream, &response)?;
    // Clean TLS shutdown: send close_notify so the peer does not see an
    // unexpected EOF, then flush it out.
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(identity)
}

/// Production accept loop: handle each connection on its own thread (blocking,
/// no async). Each connection runs `handler` once. The number of simultaneously-
/// served connections is capped at `options.limits.max_concurrent_connections`;
/// connections beyond the cap are accepted and immediately dropped (fail closed
/// against connection exhaustion) rather than queued without bound. Runs until
/// `listener` errors.
pub fn serve<H>(listener: TcpListener, config: Arc<ServerConfig>, options: ServerOptions, handler: H)
where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let options = Arc::new(options);
    let in_flight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(tcp) = incoming else { continue };
        let max = options.limits.max_concurrent_connections;
        // Reserve a slot; if the server is saturated, drop the connection.
        if in_flight.fetch_add(1, Ordering::AcqRel) >= max {
            in_flight.fetch_sub(1, Ordering::AcqRel);
            drop(tcp); // close immediately — do not serve beyond the cap
            continue;
        }
        let config = Arc::clone(&config);
        let handler = Arc::clone(&handler);
        let options = Arc::clone(&options);
        let in_flight = Arc::clone(&in_flight);
        std::thread::spawn(move || {
            let _ = serve_connection(tcp, config, &options, handler.as_ref());
            in_flight.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

/// Handle a single already-accepted TCP stream: handshake, extract identity, one
/// request/response, bounded by `options.limits`.
fn serve_connection<H>(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: &H,
) -> io::Result<()>
where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    apply_socket_timeouts(&tcp, &options.limits)?;
    let conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);
    let request = read_http_request(&mut stream, &options.limits)?;
    let headers = RequestHeaders::parse(&request.header_block);
    let identity = resolve_identity(&stream.conn, options, &headers);
    let response = match connection_rejection(&stream.conn, options, &request.body)
        .or_else(|| routing_header_rejection(&headers, &request.body))
    {
        Some(error) => error,
        None => handler(&request.body, identity),
    };
    write_http_response(&mut stream, &response)?;
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

/// Apply the configured read/write timeouts to a freshly-accepted socket.
fn apply_socket_timeouts(tcp: &TcpStream, limits: &ServerLimits) -> io::Result<()> {
    tcp.set_read_timeout(limits.read_timeout)?;
    tcp.set_write_timeout(limits.write_timeout)?;
    Ok(())
}

/// One parsed HTTP/1.1 request: the request/header block (text up to and
/// including the `\r\n\r\n` terminator) and the body bytes (the JSON-RPC
/// payload). The header block is retained so the reverse-proxy identity strategy
/// can read its trusted forwarded header; the direct-TLS path simply ignores it.
struct HttpRequest {
    /// The full header block (request line + headers + terminator), lossily
    /// decoded as UTF-8 (header bytes are ASCII in practice).
    header_block: String,
    /// The request body (the JSON-RPC payload).
    body: Vec<u8>,
}

/// Read one HTTP/1.1 request and return its header block + body bytes (the
/// JSON-RPC payload). Reads headers up to `\r\n\r\n`, honours `Content-Length`.
/// Minimal by design — single request per connection, no chunked encoding, no
/// SSE. Bounded by `limits`: the header block may not exceed `max_header_bytes`
/// and the body may not exceed `max_body_bytes` (either overflow fails closed
/// with an error rather than allocating without bound).
fn read_http_request<S: Read>(stream: &mut S, limits: &ServerLimits) -> io::Result<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    // Read until end-of-headers, capping total header bytes.
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > limits.max_header_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header block exceeds max_header_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of HTTP headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_block = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_length = parse_content_length(&header_block).unwrap_or(0);
    if content_length > limits.max_body_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Content-Length exceeds max_body_bytes",
        ));
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        // Defend against a Content-Length that under-states a flood of body bytes.
        if body.len() > limits.max_body_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body exceeds max_body_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(HttpRequest { header_block, body })
}

/// Write a minimal HTTP/1.1 JSON response carrying `body`.
fn write_http_response<S: Write>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

/// Parse the `Content-Length` header value (case-insensitive) from a header block.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod lifetime_tests {
    //! MCPS-078 (audit gap G-5): `leaf_cert_lifetime_secs` is private, so the
    //! fail-closed behaviour on an inverted validity window is exercised here,
    //! inline, over real DER minted with rcgen (mirroring the rcgen 0.13 idiom in
    //! `tests/tls_test.rs`). The caller `cert_lifetime_rejection` uses
    //! `leaf_cert_lifetime_secs(..).is_some_and(|l| l <= max)`; a `None` therefore
    //! fails closed (the cert is rejected), which is precisely what an
    //! inverted/degenerate span must produce.

    use super::leaf_cert_lifetime_secs;

    use rcgen::CertificateParams;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;

    /// Mint a self-signed leaf with an explicit validity window (day granularity)
    /// and return its DER bytes. Self-signed is sufficient here: the function
    /// under test only reads the validity fields, not the signature chain.
    fn mint_leaf_der(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    #[test]
    fn normal_validity_window_yields_positive_span() {
        // not_before (2020) < not_after (2021): a well-formed ~1y window.
        let der = mint_leaf_der((2020, 1, 1), (2021, 1, 1));
        let span = leaf_cert_lifetime_secs(&der).expect("a normal cert has a parseable span");
        assert!(
            span > 0,
            "a well-formed validity window must yield a positive lifetime, got {span}"
        );
    }

    #[test]
    fn inverted_validity_window_is_none_and_fails_closed() {
        // not_after (2020) < not_before (2021): inverted/degenerate window. The
        // G-5 fix returns None so the caller's `is_some_and(|l| l <= max)` is
        // false and `cert_lifetime_rejection` fails closed (rejects the cert).
        let der = mint_leaf_der((2021, 1, 1), (2020, 1, 1));
        assert!(
            leaf_cert_lifetime_secs(&der).is_none(),
            "an inverted validity window must yield None (fail closed), not a negative span"
        );
    }

    #[test]
    fn garbage_bytes_are_none() {
        // Not a certificate at all → unparseable → None (fail closed).
        let garbage = b"this is definitely not a DER X.509 certificate";
        assert!(
            leaf_cert_lifetime_secs(garbage).is_none(),
            "unparseable bytes must yield None"
        );
    }

    #[test]
    fn routing_header_rejection_fails_closed_on_bad_headers_only() {
        // ADR-MCPS-025 rule 4 enforcement at the transport seam. Clean/absent
        // routing headers pass; a duplicate or malformed one fails closed with
        // mcps.transport_binding_failed bound to the request id.
        use crate::transport::RequestHeaders;
        let req = br#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call"}"#;

        let clean = RequestHeaders::from_pairs([("Mcp-Method", "tools/call")]);
        assert!(super::routing_header_rejection(&clean, req).is_none());

        let duplicate =
            RequestHeaders::from_pairs([("Mcp-Method", "tools/call"), ("mcp-method", "tools/list")]);
        let rejected =
            super::routing_header_rejection(&duplicate, req).expect("duplicate must reject");
        let value: serde_json::Value = serde_json::from_slice(&rejected).expect("json error object");
        assert_eq!(value["error"]["message"], "mcps.transport_binding_failed");
        assert_eq!(value["id"], "req-1");

        let malformed = RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert!(super::routing_header_rejection(&malformed, req).is_some());
    }

    #[test]
    fn zero_length_validity_window_is_none_and_fails_closed() {
        // not_after == not_before: a DEGENERATE (zero-length) window. Without the
        // `<=` guard this returned Some(0), which `cert_lifetime_rejection` treats
        // as within ANY max lifetime — admitting a useless instant-lifetime cert.
        // The fix fails closed (None) for the degenerate span too, matching the
        // documented "negative OR degenerate span is rejected" contract.
        let der = mint_leaf_der((2021, 1, 1), (2021, 1, 1));
        assert!(
            leaf_cert_lifetime_secs(&der).is_none(),
            "a zero-length validity window must yield None (fail closed)"
        );
    }
}

#[cfg(test)]
mod identity_parity_tests {
    //! M23 (audit 0.2, MCPS-MED-7 / #4080): cross-strategy identity PARITY.
    //!
    //! The SAME verified client certificate must resolve to the SAME identity
    //! string under a given [`IdentityPolicy`] REGARDLESS of whether the cert was
    //! terminated locally (direct-TLS, [`extract_identity`]) or upstream and
    //! forwarded in an Envoy XFCC `Subject=` field (the [`ReverseProxyMtlsProvider`]).
    //! Before the fix, the direct-TLS `CnLegacy` path extracted only the CN
    //! (`agent-1`) while the XFCC `Subject=` path yielded the full RFC2253 DN
    //! (`CN=agent-1,OU=agents,O=example`) — so one `IdentityPolicy` resolved two
    //! different identities for the same cert, and the ExactMatch / Mapped binding
    //! could not be configured to admit both transports with one signer mapping.
    //!
    //! These are black-box tests over the two PUBLIC extraction paths: they mint a
    //! real cert (rcgen), read its identity via the direct-TLS path, build the XFCC
    //! header the way Envoy would (`Subject="<full DN>"`), read it via the
    //! reverse-proxy path, and assert the resolved identity strings are EQUAL.

    use super::extract_identity;

    use crate::transport::IdentityPolicy;
    use crate::transport::IdentitySource;
    use crate::transport::RequestHeaders;
    use crate::transport::ReverseProxyHeaderFormat;
    use crate::transport::ReverseProxyMtlsProvider;
    use crate::transport::TransportBindingProvider;

    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;

    /// Mint a self-signed client leaf whose subject carries the given CN, OU and O,
    /// plus a URI SAN and a DNS SAN. Returns `(der, rfc2253_subject_dn)` where the
    /// DN string is the Envoy-style `CN=..,OU=..,O=..` rendering an upstream proxy
    /// would put in the XFCC `Subject=` field.
    fn mint_client_leaf() -> (Vec<u8>, String) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["agent-1.example.org".to_string()]).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, "agent-1");
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "agents");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "example");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).expect("leaf self-signed");
        // The RFC2253 DN as a reverse-proxy would forward it in `Subject=`.
        let subject_dn = "CN=agent-1,OU=agents,O=example".to_string();
        (cert.der().as_ref().to_vec(), subject_dn)
    }

    /// Build the XFCC reverse-proxy identity for the given full Subject DN under the
    /// given policy (Envoy quotes a DN because it contains commas).
    fn xfcc_identity(subject_dn: &str, policy: IdentityPolicy) -> Option<String> {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            policy,
        );
        let header = format!("Hash=abc;Subject=\"{subject_dn}\"");
        let req = RequestHeaders::from_pairs([("x-forwarded-client-cert", header)]);
        provider.verified_identity(&req).map(|id| id.value)
    }

    #[test]
    fn cn_legacy_identity_is_equal_across_direct_tls_and_xfcc() {
        // THE PARITY ASSERTION (M23): the SAME cert, the SAME CnLegacy policy, must
        // yield the SAME identity string whether terminated locally or forwarded as
        // an XFCC Subject DN. Direct-TLS extracts the CN; the XFCC path must extract
        // the CN out of the Subject DN too — not the whole DN.
        let (der, subject_dn) = mint_client_leaf();

        let direct = extract_identity(&der, IdentityPolicy::CnLegacy)
            .expect("direct-TLS CnLegacy must extract the CN");
        assert_eq!(direct.source, IdentitySource::CommonName);

        let xfcc = xfcc_identity(&subject_dn, IdentityPolicy::CnLegacy)
            .expect("XFCC CnLegacy must extract an identity from the Subject DN");

        assert_eq!(
            direct.value, xfcc,
            "the SAME cert under CnLegacy must resolve to the SAME identity via \
             direct-TLS and via the XFCC Subject DN (got direct={:?}, xfcc={:?})",
            direct.value, xfcc
        );
        // And concretely: both are the bare CN, not the full DN.
        assert_eq!(direct.value, "agent-1");
        assert_eq!(xfcc, "agent-1");
    }

    #[test]
    fn explicit_cn_field_still_equals_direct_tls_cn() {
        // An upstream that forwards an explicit `CN=` pair (rather than a full
        // `Subject=` DN) must agree with the direct-TLS CN too.
        let (der, _dn) = mint_client_leaf();
        let direct = extract_identity(&der, IdentityPolicy::CnLegacy)
            .expect("direct-TLS CnLegacy CN")
            .value;

        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = RequestHeaders::from_pairs([("x-forwarded-client-cert", "Hash=abc;CN=agent-1")]);
        let xfcc = provider
            .verified_identity(&req)
            .expect("explicit CN pair")
            .value;
        assert_eq!(direct, xfcc, "explicit XFCC CN must equal the direct-TLS CN");
    }
}

/// MCPS-079 fault-injection module ("test of the tests"), the symmetric mirror of
/// mcps-transport's `fault_accept_any` (server-side). Compiled ONLY under the
/// `fault_accept_any_client` feature, which is off by default and never enabled by
/// production targets or the default `bazel test //...`. It re-introduces the
/// `AcceptAnyClient` anti-pattern the verifying proxy was built to eliminate, so
/// the periodic fault-injection harness can prove the proxy's client-cert
/// rejection guards (the more important boundary — the proxy guards the inner)
/// would FAIL if the control were broken.
#[cfg(feature = "fault_accept_any_client")]
mod fault_accept_any {
    use std::sync::Arc;

    use rustls::server::danger::ClientCertVerified;
    use rustls::server::danger::ClientCertVerifier;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::verify_tls12_signature;
    use rustls::crypto::verify_tls13_signature;
    use rustls::crypto::CryptoProvider;
    use rustls::DigitallySignedStruct;
    use rustls::DistinguishedName;
    use rustls::Error as RustlsError;
    use rustls::SignatureScheme;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::UnixTime;

    /// A client-certificate verifier that accepts ANY client certificate: any CA,
    /// any identity, any validity window — and, via the `client_auth_mandatory`
    /// override, also accepts a connection that presents NO client certificate at
    /// all. Handshake SIGNATURES are still checked via the crypto provider (so the
    /// TLS handshake completes against a real client) — only the trust/identity/
    /// expiry decision is neutered. This is the exact shape of the control break
    /// the proxy's client-auth tests exist to catch.
    #[derive(Debug)]
    pub struct AcceptAnyClientVerifier {
        provider: Arc<CryptoProvider>,
    }

    impl AcceptAnyClientVerifier {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            AcceptAnyClientVerifier { provider }
        }
    }

    impl ClientCertVerifier for AcceptAnyClientVerifier {
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, RustlsError> {
            // THE BREAK: trust, identity, and expiry are never checked.
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            // No trust anchors are advertised — the faulted verifier ignores trust
            // entirely, so there are no issuer hints to send to the client.
            &[]
        }

        fn client_auth_mandatory(&self) -> bool {
            // THE SECOND BREAK: a client certificate is no longer required. This is
            // what flips T1 (`missing_client_certificate_is_rejected`): with this
            // returning `false`, a connection presenting NO client cert completes
            // the handshake instead of being rejected. T2
            // (`untrusted_client_certificate_is_rejected`) flips via
            // `verify_client_cert` above accepting any presented cert.
            false
        }
    }
}
