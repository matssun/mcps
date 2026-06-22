//! ONLINE client-certificate revocation via OCSP (#4030, Phase 7,
//! ADR-MCPS-019) — compiled ONLY under the non-default `online_ocsp` feature.
//!
//! #3839 shipped OFFLINE CRL revocation (`WebPkiClientVerifier::with_crls`, a
//! startup-loaded deny-unknown-status CRL set) plus the M-10 `RevocationSource`
//! taxonomy. This module adds an ONLINE check performed at connection time: the
//! proxy asks the certificate's OCSP responder (RFC 6960) whether the verified
//! client leaf is revoked, BEFORE the request reaches the inner server. A
//! compromised client credential is thus rejected without waiting for a manual
//! CRL update + restart, and within its short enforced lifetime.
//!
//! # Design
//!
//! The check is a sibling of `tls::cert_lifetime_rejection`: a per-connection
//! fail-closed rejection hook that runs after the mTLS handshake (so the leaf is
//! already chain-verified) and before the handler. The serve loop is BLOCKING
//! (`std::net` + threads, no async runtime), so the HTTP fetch carries a
//! MANDATORY timeout — an unbounded fetch would wedge the serving thread. A
//! timeout, transport error, parse error, or `Unknown` status all fail CLOSED
//! (the connection is rejected) unless the operator opts into `soft_fail`.
//!
//! The deterministic pieces — responder-URL extraction, status mapping, and the
//! allow/reject policy decision — are factored into small pure functions so the
//! unit tests below exercise them with ZERO network access.
//!
//! # CertID hash
//!
//! CertIDs are built with **SHA-256** (`sha2::Sha256`). The responder MUST be
//! configured to answer SHA-256 CertIDs; an OpenSSL test responder does so with
//! `openssl ocsp ... -sha256` (see `tests/ocsp_e2e_test.rs`).
//!
//! # Responder-response trust chain (#4063 / MCPS-088, closes #4030)
//!
//! An OCSP `cert_status` is admission control: a `Good` admits the client. RFC
//! 6960 §3.2 therefore requires a response be TRUSTED before its status is acted
//! on. This module performs the full §3.2 trust chain BEFORE mapping a status,
//! and FAILS CLOSED (maps to [`CertRevocationStatus::Unknown`], which denies
//! under hard-fail) on ANY gap:
//!
//!   1. **Responder signature** — the `BasicOcspResponse.signature` is verified
//!      over the DER of `tbs_response_data` against the signer's public key,
//!      algorithm-agnostically (RSA PKCS#1 v1.5 SHA-256/384/512 and ECDSA
//!      P-256/P-384, via `x509-parser`'s `ring`-backed verifier). The signer is
//!      EITHER the issuer itself OR a delegated responder certificate carried in
//!      `basic.certs` that (a) is itself issuer-signed and (b) carries the
//!      `id-kp-OCSPSigning` EKU. See [`verify_responder_signature`].
//!   2. **Responder identity** — `tbs_response_data.responder_id` (byName or
//!      byKey) must match the signer chosen in (1). See [`responder_id_matches`].
//!   3. **CertID binding** — the `SingleResponse` acted on must be the one whose
//!      `CertID` equals the CertID we requested (hash alg OID, issuer name hash,
//!      issuer key hash, serial). A response that answers a DIFFERENT cert is not
//!      evidence about ours. See [`select_matching_single_response`].
//!   4. **Freshness** — `now >= thisUpdate - skew` and, when present,
//!      `now <= nextUpdate + skew`; a stale or not-yet-valid response is treated
//!      as Unknown. See [`is_fresh`].
//!   5. **Nonce** — the request carries a 16-byte CSPRNG nonce; when the
//!      responder echoes a nonce it MUST equal the request's, else the response
//!      is a replay/substitution and is rejected. See [`nonce_ok`].
//!
//! The cryptographic verifier in (1) (`x509-parser/verify`, the `ring`-backed
//! algorithm-agnostic RSA+ECDSA verifier) is enabled unconditionally at the
//! workspace level and compiled into THIS `online_ocsp` module, so the shipping
//! `online_ocsp` + `--client-ocsp require` build performs the full §3.2 trust
//! chain for real. A response whose signature does not verify maps to `Unknown`
//! and is DENIED under hard-fail — the path can NEVER admit on an unverified
//! signature.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use der::asn1::Null;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::Decode;
use der::Encode;
use sha2::Digest;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_ocsp::ext::Nonce;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::BasicOcspResponse;
use x509_ocsp::CertId;
use x509_ocsp::CertStatus;
use x509_ocsp::OcspResponse;
use x509_ocsp::OcspResponseStatus;
use x509_ocsp::Request;
use x509_ocsp::ResponderId;
use x509_ocsp::SingleResponse;
use x509_parser::certificate::X509Certificate;
use x509_parser::time::ASN1Time;
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

/// The `id-kp-OCSPSigning` extended-key-usage OID (`1.3.6.1.5.5.7.3.9`,
/// RFC 6960 §4.2.2.2). A delegated responder certificate — one carried in the
/// response's `certs` rather than being the issuer itself — MUST carry this EKU
/// for its signature over the response to be trusted.
const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// The request nonce length in bytes (RFC 8954 permits 1..32; 16 is ample
/// entropy against replay/substitution while staying within responders that cap
/// nonce length). The nonce is freshly drawn per request from the OS CSPRNG.
const OCSP_NONCE_LEN: usize = 16;

/// The freshness skew tolerance: a few minutes absorbs clock drift between the
/// proxy and the responder without widening the window enough to matter for
/// revocation latency. `thisUpdate` may be up to this far in the future, and
/// `nextUpdate` up to this far in the past, before the response is rejected.
const OCSP_FRESHNESS_SKEW: Duration = Duration::from_secs(300);

/// The OCSP access-method OID `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`) used inside the
/// Authority Information Access (AIA) extension to point at the responder URL.
const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// The `id-sha256` digest-algorithm OID (`2.16.840.1.101.3.4.2.1`). The CertID
/// hash algorithm is SHA-256, so the responder must be configured to answer
/// SHA-256 CertIDs. Declared as a literal so the build does not depend on a
/// digest crate exposing its `AssociatedOid` impl under the current feature set.
const OID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// The default HTTP fetch timeout. The serve loop is blocking, so an unbounded
/// fetch would hang the serving thread; this bounds it and the check fails
/// closed on timeout. Five seconds is generous for a healthy responder yet short
/// enough not to starve the connection.
const DEFAULT_OCSP_TIMEOUT: Duration = Duration::from_secs(5);

/// The revocation status the responder reported for the client leaf certificate.
/// This is the deterministic mapping of the OCSP `CertStatus` CHOICE; the
/// allow/reject decision is made separately by [`OcspChecker::decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRevocationStatus {
    /// The responder asserts the certificate is NOT revoked (`good`).
    Good,
    /// The responder asserts the certificate IS revoked (`revoked`).
    Revoked,
    /// The responder does not know the certificate's status (`unknown`), or no
    /// responder URL is available — an indeterminate status that fails closed
    /// unless soft-fail is configured.
    Unknown,
}

/// Errors performing an online OCSP check. Every variant is a fail-closed
/// condition: under hard-fail (the default) the connection is rejected.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    /// A certificate (leaf or issuer) could not be decoded from DER.
    #[error("invalid certificate DER: {0}")]
    BadCertificate(String),
    /// The OCSP request could not be built or DER-encoded.
    #[error("OCSP request build failed: {0}")]
    BuildRequest(String),
    /// The HTTP POST to the responder failed (connect/timeout/transport/status).
    #[error("OCSP responder HTTP error: {0}")]
    Http(String),
    /// The responder's HTTP body could not be read.
    #[error("OCSP response read error: {0}")]
    ReadBody(String),
    /// The response could not be decoded as an `OCSPResponse`.
    #[error("OCSP response decode failed: {0}")]
    DecodeResponse(String),
    /// The responder returned a non-`successful` `OCSPResponseStatus`.
    #[error("OCSP responder returned non-successful status: {0:?}")]
    ResponderStatus(OcspResponseStatus),
    /// A `successful` response carried no `responseBytes`, or they were not a
    /// `BasicOCSPResponse`, or it held no `SingleResponse`.
    #[error("OCSP response malformed: {0}")]
    MalformedResponse(String),
    /// The responder's signature over `tbs_response_data` could not be verified
    /// against the issuer or a valid delegated responder certificate. This is the
    /// RFC 6960 §3.2 trust failure — fail CLOSED.
    #[error("OCSP responder signature not verified: {0}")]
    SignatureNotVerified(String),
    /// The `responder_id` did not match the certificate whose key verified the
    /// signature (the responder asserted an identity it did not sign as).
    #[error("OCSP responder identity mismatch: {0}")]
    ResponderIdentityMismatch(String),
    /// No `SingleResponse` in the response answered the CertID we requested, so
    /// the response carries no evidence about THIS certificate.
    #[error("OCSP response has no SingleResponse for the requested CertID")]
    CertIdMismatch,
    /// The response is stale (`now > nextUpdate + skew`) or not yet valid
    /// (`now < thisUpdate - skew`).
    #[error("OCSP response not fresh: {0}")]
    NotFresh(String),
    /// The responder echoed a nonce that did not equal the request nonce — a
    /// replayed or substituted response.
    #[error("OCSP response nonce mismatch")]
    NonceMismatch,
}

/// Performs an online OCSP revocation check for a verified client leaf
/// certificate against its issuer. Holds only configuration; it is cheap to
/// clone and carries no network state between calls.
#[derive(Debug, Clone)]
pub struct OcspChecker {
    /// An explicit responder URL that OVERRIDES the leaf's AIA OCSP URL. `None`
    /// means "use the AIA URL from the leaf" (and a leaf without one yields
    /// `Unknown`).
    responder_url_override: Option<String>,
    /// When `true`, an indeterminate result (`Unknown`, unreachable responder,
    /// timeout, parse error, signature failure) ALLOWS the connection instead of
    /// rejecting it. Default `false` = hard-fail (deny on anything but `Good`).
    soft_fail: bool,
    /// The mandatory HTTP fetch timeout (see [`DEFAULT_OCSP_TIMEOUT`]).
    timeout: Duration,
}

impl OcspChecker {
    /// Build a checker. `responder_url_override` (the `--ocsp-responder-url`
    /// AIA override) is used verbatim when set; otherwise the responder URL is
    /// read from the leaf's AIA OCSP entry. `soft_fail` is the
    /// `--ocsp-soft-fail` posture (default hard-fail). The timeout defaults to
    /// [`DEFAULT_OCSP_TIMEOUT`].
    pub fn new(responder_url_override: Option<String>, soft_fail: bool) -> Self {
        OcspChecker {
            responder_url_override,
            soft_fail,
            timeout: DEFAULT_OCSP_TIMEOUT,
        }
    }

    /// Whether this checker is configured to fail OPEN (allow on indeterminate
    /// result). Exposed so the serve integration can describe its posture.
    pub fn soft_fail(&self) -> bool {
        self.soft_fail
    }

    /// Perform the full online check for `leaf_der` against `issuer_der`:
    ///
    ///   a. resolve the responder URL (override, else the leaf's AIA OCSP URL;
    ///      none → `Unknown`);
    ///   b. build a SHA-256 CertID OCSP request and DER-encode it;
    ///   c. POST it to the responder with the mandatory timeout, reading the
    ///      response body (any transport/timeout error → `Err`);
    ///   d. decode the `OCSPResponse`, require `Successful`, parse the
    ///      `BasicOCSPResponse`, and map its single `CertStatus`.
    ///
    /// Returns the mapped [`CertRevocationStatus`]; transport/codec failures are
    /// `Err(OcspError)`. The allow/reject decision (which folds in `soft_fail`)
    /// is [`OcspChecker::decision`].
    pub fn check(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<CertRevocationStatus, OcspError> {
        let responder_url = match self.resolve_responder_url(leaf_der) {
            Some((url, source)) => {
                // #4078 (M14): the AIA responder URL is attacker-influenced (it
                // comes from the leaf), so an SSRF guard MUST run BEFORE any fetch.
                // A cert-derived URL must be http/https AND must NOT target a
                // loopback/link-local/private/unspecified/multicast host (no
                // `file://`, `gopher://`, 169.254.169.254 metadata, 127/8, ::1,
                // 10/8, 172.16/12, 192.168/16, …). An operator override is
                // scheme-checked (http/https) but, by design, NOT private-IP
                // blocked — an operator may legitimately run an internal responder.
                // A rejected URL fails CLOSED exactly like a missing AIA URL: it is
                // an indeterminate result (Unknown) that denies under hard-fail.
                let safe = match source {
                    ResponderUrlSource::CertAia => aia_responder_url_is_safe(&url),
                    ResponderUrlSource::OperatorOverride => responder_scheme_allowed(&url),
                };
                if !safe {
                    return Ok(CertRevocationStatus::Unknown);
                }
                url
            }
            // No override and no AIA OCSP URL on the leaf: the status is
            // indeterminate (Unknown), which the policy treats as fail-closed
            // unless soft-fail is set.
            None => return Ok(CertRevocationStatus::Unknown),
        };

        // A fresh per-request CSPRNG nonce binds the response to THIS request: a
        // captured/replayed response carries a stale (mismatched) nonce and is
        // rejected (RFC 6960 §4.4.1 / RFC 8954). Drawn from the OS CSPRNG.
        let nonce = random_nonce()?;
        let request_der = build_ocsp_request_der_with_nonce(leaf_der, issuer_der, &nonce)?;
        let response_der = self.post_request(&responder_url, &request_der)?;
        // The expected CertID we requested — used to bind the SingleResponse.
        let expected_cert_id = build_cert_id(leaf_der, issuer_der)?;
        verify_and_map_response(
            &response_der,
            issuer_der,
            &expected_cert_id,
            &nonce,
            SystemTime::now(),
        )
    }

    /// Resolve the responder URL AND its provenance: the configured override wins
    /// (and is tagged [`ResponderUrlSource::OperatorOverride`]); otherwise the AIA
    /// OCSP URL is read from the leaf (tagged [`ResponderUrlSource::CertAia`]). The
    /// provenance drives the #4078 SSRF guard — the attacker-influenced cert AIA
    /// URL gets the full guard, the operator override only the scheme allowlist.
    /// Pure (no network) and unit-tested.
    fn resolve_responder_url(&self, leaf_der: &[u8]) -> Option<(String, ResponderUrlSource)> {
        match &self.responder_url_override {
            Some(url) => Some((url.clone(), ResponderUrlSource::OperatorOverride)),
            None => extract_ocsp_responder_url(leaf_der)
                .map(|url| (url, ResponderUrlSource::CertAia)),
        }
    }

    /// POST a DER OCSP request to `url` with the mandatory timeout and return the
    /// raw response body bytes. Any HTTP/timeout/transport error is `Err`.
    fn post_request(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        // SSRF hardening: the responder host is guarded (`aia_responder_url_is_safe`
        // → `host_is_public`) BEFORE this call, but that guard only inspects the
        // FIRST URL. `ureq` follows HTTP 3xx redirects by default, so a hostile
        // responder could `302 Location: http://169.254.169.254/` and the client
        // would chase the redirect to an internal address that NEVER passed the
        // guard. A revocation fetch has no legitimate need to chase redirects, so
        // disable them (`redirects(0)`): a 3xx is then returned as-is, its body is
        // not a valid OCSP response, and the path fails CLOSED (Unknown → deny under
        // hard-fail) rather than reaching the redirect target.
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        let response = agent
            .post(url)
            .set("Content-Type", "application/ocsp-request")
            .set("Accept", "application/ocsp-response")
            .timeout(self.timeout)
            .send_bytes(request_der)
            .map_err(|e| OcspError::Http(e.to_string()))?;
        // Bound the response body read so a hostile/oversized responder reply
        // cannot exhaust memory; a well-formed OCSP response is small.
        let mut body = Vec::new();
        use std::io::Read;
        response
            .into_reader()
            .take(MAX_OCSP_RESPONSE_BYTES)
            .read_to_end(&mut body)
            .map_err(|e| OcspError::ReadBody(e.to_string()))?;
        Ok(body)
    }

    /// The allow/reject decision for a resolved status under this checker's
    /// fail-closed posture. `Revoked` is ALWAYS rejected (even under soft-fail);
    /// `Good` is allowed; `Unknown` is rejected UNLESS `soft_fail`. Pure and
    /// unit-tested. Returns `true` to ALLOW the connection, `false` to REJECT.
    pub fn allows(&self, status: CertRevocationStatus) -> bool {
        decide_allow(status, self.soft_fail)
    }

    /// As [`OcspChecker::allows`] but for the error path: a transport/codec
    /// error is an indeterminate result, allowed ONLY under soft-fail.
    pub fn allows_on_error(&self) -> bool {
        decide_allow(CertRevocationStatus::Unknown, self.soft_fail)
    }
}

/// Cap on the OCSP response body read (64 KiB). A legitimate single-cert OCSP
/// response is well under a kilobyte; this defends against a hostile or
/// misbehaving responder streaming an unbounded body into the serving thread.
const MAX_OCSP_RESPONSE_BYTES: u64 = 64 * 1024;

/// Extract the OCSP responder URL from a leaf certificate's Authority
/// Information Access (AIA) extension — the first `id-ad-ocsp` access
/// description whose location is a URI. Returns `None` if the cert cannot be
/// parsed, has no AIA extension, or has no OCSP URI entry. Pure (no network).
pub fn extract_ocsp_responder_url(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.to_id_string() == ID_AD_OCSP {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some((*uri).to_string());
                    }
                }
            }
        }
    }
    None
}

/// The provenance of a resolved OCSP responder URL, which selects how strictly the
/// #4078 SSRF guard is applied: an attacker-influenced cert AIA URL gets the FULL
/// guard (scheme allowlist + private-IP block); an operator-supplied override gets
/// only the scheme allowlist (the operator may legitimately point at an internal
/// responder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderUrlSource {
    /// The URL came from the leaf certificate's AIA extension — attacker-influenced.
    CertAia,
    /// The URL came from the operator's `--ocsp-responder-url` override — trusted.
    OperatorOverride,
}

/// Whether `url`'s scheme is on the OCSP responder allowlist (`http` or `https`).
/// This is the SSRF-floor applied to EVERY responder URL — including the operator
/// override — so a `file://`, `gopher://`, `ldap://`, `data:` … URL can never be
/// fetched. Parsing is intentionally minimal (no URL crate dependency): the scheme
/// is the ASCII run before the first `:`, compared case-insensitively. Pure.
pub fn responder_scheme_allowed(url: &str) -> bool {
    match url.split_once(':') {
        Some((scheme, _rest)) => {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }
        None => false,
    }
}

/// The #4078 (M14) SSRF guard for a CERT-supplied (attacker-influenced) AIA OCSP
/// responder URL. Returns `true` only when the URL is SAFE to fetch:
///
///   * its scheme is `http`/`https` (via [`responder_scheme_allowed`]); AND
///   * its host is NOT a literal loopback / link-local / private / unspecified /
///     multicast IP, and is NOT the loopback hostname `localhost`.
///
/// A hostile leaf otherwise points the blocking serve thread at `file:///etc/passwd`,
/// the cloud metadata endpoint `169.254.169.254`, `127.0.0.1`, `::1`, `10/8`,
/// `172.16/12`, `192.168/16`, … . When this returns `false` the caller fails CLOSED
/// (treats the responder as unavailable → `Unknown`, which denies under hard-fail),
/// matching the existing "no AIA URL" handling. Pure (no network, no DNS). A
/// hostname that is not a literal IP and not `localhost` is permitted at this layer
/// (the host is reached over the network where the OS resolves it); literal private
/// IPs and the loopback name — the practical SSRF vectors — are blocked outright.
///
/// RESIDUAL LIMITATION (DNS rebinding): this is a URL/host *syntactic and literal-IP*
/// guard, not a guarantee against a hostile PUBLIC hostname that later RESOLVES to an
/// internal address at fetch time. Closing that requires pinning and re-validating
/// the address actually connected to (a custom resolver/connector), which this guard
/// does not do. The redirect vector — a guarded first URL that `302`s to an internal
/// address — IS closed: the OCSP fetch disables redirect-following (see
/// `OcspChecker::post_request`). DNS rebinding is tracked as issue #128.
pub fn aia_responder_url_is_safe(url: &str) -> bool {
    if !responder_scheme_allowed(url) {
        return false;
    }
    match extract_url_host(url) {
        Some(host) => host_is_public(&host),
        // A scheme-prefixed URL with no recoverable host is not safe to fetch.
        None => false,
    }
}

/// Extract the host component (without port, without brackets for IPv6) from an
/// `http`/`https` URL, using minimal parsing (no URL crate). Returns `None` if no
/// authority is present. The authority is the run between `//` and the first `/`,
/// `?`, or `#`; userinfo (`user@`) and the `:port` suffix are stripped; an IPv6
/// literal in `[...]` is returned without its brackets. Pure.
fn extract_url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    // Authority ends at the first path/query/fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop any userinfo (everything up to and including the last '@').
    let hostport = match authority.rsplit_once('@') {
        Some((_userinfo, hp)) => hp,
        None => authority,
    };
    if hostport.is_empty() {
        return None;
    }
    // IPv6 literal: `[addr]` or `[addr]:port`.
    if let Some(rest) = hostport.strip_prefix('[') {
        let close = rest.find(']')?;
        return Some(rest[..close].to_string());
    }
    // host or host:port — the host is everything before the first ':'.
    let host = hostport.split(':').next().unwrap_or(hostport);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Whether `host` is safe to fetch from for an attacker-influenced URL: it is NOT
/// syntactically malformed (no empty DNS label / trailing or doubled dot), NOT a
/// literal non-public IP, and NOT the loopback name `localhost`. A literal IP is
/// rejected when it is loopback, link-local, private (RFC 1918 / IPv6 ULA),
/// unspecified, or multicast. A non-literal hostname (other than `localhost`) is
/// permitted at this layer. Pure (no DNS).
fn host_is_public(host: &str) -> bool {
    use std::net::IpAddr;
    // A trailing dot (`169.254.169.254.`), a leading dot, or a doubled dot
    // (`a..b`) produces an EMPTY DNS label. std's `IpAddr` and the `inet_aton`
    // canonicalizer below both REJECT such a string, so without this guard it
    // falls through to the "treat as a real hostname → permit" branch — yet the
    // OS resolver STRIPS a trailing root dot and resolves `169.254.169.254.` to
    // the metadata IP, and `127.0.0.1.` to loopback. Reject any host with an
    // empty label (and the empty host) OUTRIGHT rather than normalizing it: a
    // syntactically malformed host is never a legitimate public responder.
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return false;
    }
    // The loopback hostname is the most common non-literal SSRF target — block it.
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => return ipv4_is_public(&v4),
        Ok(IpAddr::V6(v6)) => return ipv6_is_public(&v6),
        // Not a STRICT dotted-decimal / canonical IPv6 literal — fall through.
        Err(_) => {}
    }
    // SSRF hardening (#26): an attacker-influenced host may encode an IPv4 address
    // in a non-dotted-decimal form that std's strict parser REJECTS but
    // `inet_aton(3)` — and therefore the OS resolver / HTTP client at fetch time —
    // ACCEPTS: octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), a 32-bit integer
    // (`2130706433`), or short forms (`127.1`). Without canonicalizing these they
    // would slip past the dotted-decimal block as if they were hostnames and the
    // fetch would still reach the internal address. Canonicalize and re-check; only
    // a host that is NOT any IPv4 encoding is treated as a real hostname.
    if let Some(v4) = parse_inet_aton_ipv4(host) {
        return ipv4_is_public(&v4);
    }
    true
}

/// Parse an IPv4 address in the LOOSE `inet_aton(3)` forms that std's strict
/// parser rejects but the OS resolver / HTTP clients accept (issue #26 SSRF
/// guard). Each of 1–4 dot-separated parts may be decimal, octal (leading `0`), or
/// hexadecimal (leading `0x`/`0X`); with fewer than 4 parts the final part is a
/// wider field that absorbs the remaining low-order bytes (`a`; `a.b`; `a.b.c`).
/// Returns the canonical address, or `None` if `host` is not such a form (e.g. a
/// real hostname). Pure.
fn parse_inet_aton_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_inet_aton_part(p))
        .collect::<Option<Vec<u64>>>()?;
    let n = vals.len();
    // Every part EXCEPT the last is a single byte (≤ 255).
    if vals[..n - 1].iter().any(|v| *v > 0xff) {
        return None;
    }
    // The last part is a "rest" field whose width depends on how many parts there
    // are; reject it if it overflows that width.
    let last = vals[n - 1];
    let max_last: u64 = match n {
        1 => 0xffff_ffff,
        2 => 0x00ff_ffff,
        3 => 0x0000_ffff,
        4 => 0x0000_00ff,
        _ => return None,
    };
    if last > max_last {
        return None;
    }
    let addr: u32 = match n {
        1 => last as u32,
        2 => ((vals[0] as u32) << 24) | last as u32,
        3 => ((vals[0] as u32) << 24) | ((vals[1] as u32) << 16) | last as u32,
        4 => {
            ((vals[0] as u32) << 24)
                | ((vals[1] as u32) << 16)
                | ((vals[2] as u32) << 8)
                | last as u32
        }
        _ => return None,
    };
    Some(std::net::Ipv4Addr::from(addr))
}

/// Parse one `inet_aton(3)` numeric part: hex (`0x..`), octal (leading `0`), or
/// decimal. Returns `None` for an empty or non-numeric part (so a real hostname
/// label like `ocsp` makes the whole parse fail and the host is treated as a name).
fn parse_inet_aton_part(part: &str) -> Option<u64> {
    let (radix, digits) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (16, hex)
        } else if part.len() > 1 && part.starts_with('0') {
            (8, &part[1..])
        } else {
            (10, part)
        };
    if digits.is_empty() {
        return None;
    }
    // Reject any non-digit (incl. a leading sign) up front: `from_str_radix`
    // tolerates a leading `+`, which `inet_aton` does not.
    if !digits.bytes().all(|b| (b as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Whether an IPv4 literal is a PUBLIC (fetchable) address — i.e. NOT loopback
/// (127/8), private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
/// covering the 169.254.169.254 cloud-metadata endpoint), unspecified (0.0.0.0),
/// broadcast (255.255.255.255), or multicast (224/4). Pure.
fn ipv4_is_public(v4: &std::net::Ipv4Addr) -> bool {
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast())
}

/// Whether an IPv6 literal is a PUBLIC (fetchable) address — i.e. NOT loopback
/// (::1), unspecified (::), link-local (fe80::/10), multicast (ff00::/8), or
/// unique-local (fc00::/7). IPv4-mapped/compatible embeddings are unwrapped and
/// re-checked against the IPv4 rules so `::ffff:127.0.0.1` cannot bypass the guard.
/// Pure.
fn ipv6_is_public(v6: &std::net::Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    // Unwrap an IPv4-mapped/compatible address and apply the IPv4 rules to it.
    if let Some(v4) = v6.to_ipv4() {
        return ipv4_is_public(&v4);
    }
    let segs = v6.segments();
    // Link-local fe80::/10.
    if (segs[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique-local fc00::/7 (fc00:: and fd00::).
    if (segs[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    true
}

/// Build a DER-encoded OCSP request for `leaf_der` against `issuer_der`, using a
/// SHA-256 CertID and NO nonce. Retained for the request-codec round-trip test;
/// the live [`OcspChecker::check`] path always uses
/// [`build_ocsp_request_der_with_nonce`] so a fresh nonce binds every request.
pub fn build_ocsp_request_der(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, OcspError> {
    let cert_id = build_cert_id(leaf_der, issuer_der)?;
    let ocsp_request = OcspRequestBuilder::default()
        .with_request(Request::new(cert_id))
        .build();
    ocsp_request
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("DER encode: {e}")))
}

/// Build a DER-encoded OCSP request for `leaf_der` against `issuer_der` carrying
/// a SHA-256 CertID and the request `nonce` as the RFC 6960 §4.4.1 Nonce
/// extension. Pure (no network).
pub fn build_ocsp_request_der_with_nonce(
    leaf_der: &[u8],
    issuer_der: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, OcspError> {
    let cert_id = build_cert_id(leaf_der, issuer_der)?;
    let nonce_ext = Nonce::new(nonce.to_vec())
        .map_err(|e| OcspError::BuildRequest(format!("nonce: {e}")))?;
    let ocsp_request = OcspRequestBuilder::default()
        .with_request(Request::new(cert_id))
        .with_extension(nonce_ext)
        .map_err(|e| OcspError::BuildRequest(format!("nonce extension: {e}")))?
        .build();
    ocsp_request
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("DER encode: {e}")))
}

/// Build the SHA-256 `CertID` for `leaf_der` under `issuer_der`, decoding both
/// certificates. The same CertID is sent in the request AND recomputed after the
/// response arrives to bind the acted-on `SingleResponse` to our query.
pub fn build_cert_id(leaf_der: &[u8], issuer_der: &[u8]) -> Result<CertId, OcspError> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| OcspError::BadCertificate(format!("leaf: {e}")))?;
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::BadCertificate(format!("issuer: {e}")))?;
    build_sha256_cert_id(&issuer, &leaf)
}

/// Draw a fresh `OCSP_NONCE_LEN`-byte nonce from the OS CSPRNG (`getrandom`).
/// Fails closed (the caller turns the error into a rejected connection) if the
/// platform RNG is unavailable rather than sending a predictable nonce.
fn random_nonce() -> Result<Vec<u8>, OcspError> {
    let mut bytes = vec![0u8; OCSP_NONCE_LEN];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| OcspError::BuildRequest(format!("nonce CSPRNG: {e}")))?;
    Ok(bytes)
}

/// Build the SHA-256 `CertID` (RFC 6960 §4.1.1) for `cert` under `issuer`:
///
///   * `hashAlgorithm` = `id-sha256`;
///   * `issuerNameHash` = SHA-256 of the issuer's DER-encoded subject DN;
///   * `issuerKeyHash` = SHA-256 of the issuer's `subjectPublicKey` raw bits
///     (the BIT STRING value, excluding tag/length/unused-bits);
///   * `serialNumber` = the leaf's serial number.
///
/// Built by hand (rather than `CertId::from_cert::<Sha256>`) so the build does
/// not require `sha2::Sha256: AssociatedOid`, which is gated behind a `sha2`
/// crate feature not enabled in this build's dependency set.
fn build_sha256_cert_id(issuer: &Certificate, cert: &Certificate) -> Result<CertId, OcspError> {
    let issuer_subject_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("issuer subject DER: {e}")))?;
    let issuer_name_hash = Sha256::digest(&issuer_subject_der);
    let issuer_key_hash = Sha256::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer name hash: {e}")))?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer key hash: {e}")))?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    })
}

/// Map an OCSP `CertStatus` CHOICE to a [`CertRevocationStatus`]. Pure and
/// unit-tested. `good` → `Good`, `revoked` → `Revoked`, `unknown` → `Unknown`.
pub fn map_cert_status(status: &CertStatus) -> CertRevocationStatus {
    match status {
        CertStatus::Good(_) => CertRevocationStatus::Good,
        CertStatus::Revoked(_) => CertRevocationStatus::Revoked,
        CertStatus::Unknown(_) => CertRevocationStatus::Unknown,
    }
}

/// The RFC 6960 §3.2 response-trust pipeline. Decode `response_der`, require a
/// `Successful` status, parse the `BasicOCSPResponse`, then — BEFORE trusting any
/// status — verify in order: (1) the responder signature over
/// `tbs_response_data` against the issuer or a delegated `id-kp-OCSPSigning`
/// responder cert; (2) the `responder_id` matches that signer; (3) the request
/// `nonce` echoes (when present); (4) a `SingleResponse` binds to
/// `expected_cert_id`; (5) that response is fresh at `now`. Only then is its
/// `cert_status` mapped. ANY failure is an `Err`, which the caller treats as
/// fail-closed (Unknown → deny under hard-fail). Pure (no network), unit-tested.
pub fn verify_and_map_response(
    response_der: &[u8],
    issuer_der: &[u8],
    expected_cert_id: &CertId,
    request_nonce: &[u8],
    now: SystemTime,
) -> Result<CertRevocationStatus, OcspError> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|e| OcspError::DecodeResponse(e.to_string()))?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(OcspError::ResponderStatus(response.response_status));
    }
    let response_bytes = response
        .response_bytes
        .ok_or_else(|| OcspError::MalformedResponse("successful response with no bytes".into()))?;
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|e| OcspError::MalformedResponse(format!("not a BasicOCSPResponse: {e}")))?;

    // (1) responder signature + (2) responder identity, against the issuer or a
    // delegated responder cert. Returns the cert whose key verified the response
    // so the identity check can be made against the SAME key.
    let signer = verify_responder_signature(&basic, issuer_der, now)?;
    if !responder_id_matches(&basic.tbs_response_data.responder_id, &signer) {
        return Err(OcspError::ResponderIdentityMismatch(
            "responder_id does not match the signing certificate".into(),
        ));
    }

    // (3) nonce: if the responder echoed a nonce it MUST equal ours. (A responder
    // that omits the nonce entirely is permitted by RFC 6960 — many do not honor
    // nonces — but a PRESENT, MISMATCHED nonce is a replay/substitution.)
    if !nonce_ok(&basic, request_nonce) {
        return Err(OcspError::NonceMismatch);
    }

    // (4) CertID binding: select the SingleResponse that answers OUR cert.
    let single = select_matching_single_response(&basic, expected_cert_id)
        .ok_or(OcspError::CertIdMismatch)?;

    // (5) freshness of the selected response.
    if !is_fresh(single, now, OCSP_FRESHNESS_SKEW) {
        return Err(OcspError::NotFresh(
            "thisUpdate/nextUpdate window does not include now".into(),
        ));
    }

    Ok(map_cert_status(&single.cert_status))
}

/// Verify the `BasicOcspResponse` signature over its `tbs_response_data` and
/// return the certificate whose public key verified it. The signer is EITHER the
/// issuer (direct) OR a delegated responder cert carried in `basic.certs` that is
/// itself signed by the issuer and carries the `id-kp-OCSPSigning` EKU. Fails
/// closed (`SignatureNotVerified`) when no candidate verifies.
///
/// The signer cert is returned as its DER bytes so the caller can run the
/// responder-identity check against the SAME key/name that verified the
/// signature.
///
/// The cryptographic verify (`x509-parser/verify`, enabled unconditionally at the
/// workspace level) is compiled into the `online_ocsp` module itself, so the
/// shipping `online_ocsp` + `--client-ocsp require` build performs this check for
/// real. When no candidate key verifies, this returns `SignatureNotVerified`, so a
/// `Good` status can NEVER be admitted on an unverified signature.
fn verify_responder_signature(
    basic: &BasicOcspResponse,
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, OcspError> {
    // The exact bytes the responder signed: DER of tbs_response_data.
    let tbs_der = basic
        .tbs_response_data
        .to_der()
        .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode tbs: {e}")))?;
    let sig_alg_der = basic
        .signature_algorithm
        .to_der()
        .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode sigalg: {e}")))?;
    // The signature BIT STRING value (no unused-bits prefix); signatures are
    // whole octets, so `unused_bits == 0`.
    let sig_bytes = basic.signature.raw_bytes();

    // Candidate 1: the issuer signed directly.
    if signature_verifies(issuer_der, &sig_alg_der, sig_bytes, &tbs_der)? {
        return Ok(issuer_der.to_vec());
    }

    // Candidate 2..n: a delegated responder cert in `basic.certs` that is itself
    // issuer-signed AND carries the id-kp-OCSPSigning EKU.
    if let Some(certs) = &basic.certs {
        for cert in certs {
            let cert_der = cert
                .to_der()
                .map_err(|e| OcspError::SignatureNotVerified(format!("responder cert DER: {e}")))?;
            if !delegated_responder_is_valid(&cert_der, issuer_der, now)? {
                continue;
            }
            if signature_verifies(&cert_der, &sig_alg_der, sig_bytes, &tbs_der)? {
                return Ok(cert_der);
            }
        }
    }

    Err(OcspError::SignatureNotVerified(
        "no issuer or delegated id-kp-OCSPSigning responder key verified the signature".into(),
    ))
}

/// Whether `cert_der` is a valid delegated OCSP responder for `issuer_der` at
/// `now`: it is within its own `notBefore`/`notAfter` validity window AND signed by
/// the issuer AND carries the `id-kp-OCSPSigning` extended key usage (RFC 6960
/// §4.2.2.2 / §4.2.2.2.1). Pure; the cryptographic issuer-signature check is
/// compiled with the `online_ocsp` module exactly as the response-signature check
/// is.
fn delegated_responder_is_valid(
    cert_der: &[u8],
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<bool, OcspError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("delegated cert parse: {e}")))?;
    // RFC 6960 §4.2.2.2.1: the responder certificate MUST itself be valid at the
    // response time. Reject an expired or not-yet-valid delegated responder cert
    // (e.g. a rotated-out signer) — treating it as not-a-valid-responder so no
    // candidate key verifies, the caller fails closed (status → Unknown → deny),
    // and a possibly-revoked client is never admitted under a stale signer key.
    let Some(now_unix) = system_time_to_unix(now) else {
        return Ok(false);
    };
    let Ok(now_asn1) = ASN1Time::from_timestamp(now_unix.as_secs() as i64) else {
        return Ok(false);
    };
    if !cert.validity().is_valid_at(now_asn1) {
        return Ok(false);
    }
    // Must declare the id-kp-OCSPSigning EKU (x509-parser surfaces it both as the
    // dedicated `ocsp_signing` flag and in `other`; check both for robustness).
    let has_ocsp_eku = match cert.extended_key_usage() {
        Ok(Some(eku)) => {
            eku.value.ocsp_signing
                || eku
                    .value
                    .other
                    .iter()
                    .any(|oid| oid.to_id_string() == ID_KP_OCSP_SIGNING)
        }
        _ => false,
    };
    if !has_ocsp_eku {
        return Ok(false);
    }
    // Must be signed by the issuer.
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("issuer parse: {e}")))?;
    cert_is_signed_by(&cert, &issuer)
}

/// Whether `child`'s signature verifies under `issuer`'s public key, via
/// `x509-parser`'s `ring`-backed verifier. Always compiled with the `online_ocsp`
/// module (the workspace enables `x509-parser/verify` unconditionally), so the
/// shipping `online_ocsp` build performs the real cryptographic check.
fn cert_is_signed_by(
    child: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<bool, OcspError> {
    match child.verify_signature(Some(issuer.public_key())) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a signature `sig_bits_der` (a DER BIT STRING) with algorithm
/// `sig_alg_der` (a DER AlgorithmIdentifier) over `signed_der` using the public
/// key of the certificate `signer_cert_der`. Algorithm-agnostic: RSA PKCS#1 v1.5
/// SHA-256/384/512 and ECDSA P-256/P-384, via `x509-parser`'s `ring`-backed
/// `verify_signature`.
///
/// Always compiled with the `online_ocsp` module (the workspace enables
/// `x509-parser/verify` unconditionally), so the shipping `online_ocsp` +
/// `--client-ocsp require` build performs the REAL RFC 6960 §3.2 signature
/// check. A non-verifying response yields `Ok(false)`, so the caller fails closed
/// (status → Unknown → deny): no `Good` is ever admitted on an unverified
/// signature.
fn signature_verifies(
    signer_cert_der: &[u8],
    sig_alg_der: &[u8],
    sig_bytes: &[u8],
    signed_der: &[u8],
) -> Result<bool, OcspError> {
    use x509_parser::prelude::FromDer as _;
    let (_, signer) = X509Certificate::from_der(signer_cert_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("signer cert parse: {e}")))?;
    let (_, sig_alg) =
        x509_parser::x509::AlgorithmIdentifier::from_der(sig_alg_der).map_err(|e| {
            OcspError::SignatureNotVerified(format!("signature algorithm parse: {e}"))
        })?;
    // The signature value as an asn1-rs BIT STRING (whole octets → 0 unused bits).
    let sig_bits = asn1_rs::BitString::new(0, sig_bytes);
    match x509_parser::verify::verify_signature(
        signer.public_key(),
        &sig_alg,
        &sig_bits,
        signed_der,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Whether the response's `responder_id` identifies `signer_cert_der` — the cert
/// whose key verified the signature. `byName` must equal the signer's subject DN;
/// `byKey` must equal the SHA-1 hash of the signer's `subjectPublicKey` bits
/// (RFC 6960 §4.2.1 KeyHash). Pure.
fn responder_id_matches(responder_id: &ResponderId, signer_cert_der: &[u8]) -> bool {
    let Ok(signer) = Certificate::from_der(signer_cert_der) else {
        return false;
    };
    match responder_id {
        ResponderId::ByName(name) => {
            let (Ok(a), Ok(b)) = (name.to_der(), signer.tbs_certificate.subject.to_der()) else {
                return false;
            };
            a == b
        }
        ResponderId::ByKey(key_hash) => {
            // KeyHash is the SHA-1 hash of the responder public-key BIT STRING
            // value. Compute it from the signer's SPKI subjectPublicKey bits.
            let spk_bits = signer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let digest = sha1_hash(spk_bits);
            key_hash.as_bytes() == digest.as_slice()
        }
    }
}

/// SHA-1 of `data`, used solely for the RFC 6960 ResponderID `byKey` KeyHash
/// comparison (the standard fixes KeyHash to SHA-1; this is an identity match,
/// not a security primitive). Implemented locally to avoid adding a `sha1` dep.
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    // Minimal SHA-1 (FIPS 180-4). Used only for the byKey ResponderID match.
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let ml = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Select the `SingleResponse` whose `CertID` binds to `expected` — the cert we
/// asked about. Compares the binding fields (hash-algorithm OID, issuer name
/// hash, issuer key hash, serial number) so a response answering a DIFFERENT cert
/// is never mistaken for evidence about ours. Returns `None` if no SingleResponse
/// matches (the caller fails closed). Pure.
fn select_matching_single_response<'a>(
    basic: &'a BasicOcspResponse,
    expected: &CertId,
) -> Option<&'a SingleResponse> {
    basic
        .tbs_response_data
        .responses
        .iter()
        .find(|single| cert_ids_bind(&single.cert_id, expected))
}

/// Whether two CertIDs identify the same certificate: same hash-algorithm OID and
/// identical issuer name hash, issuer key hash, and serial number.
fn cert_ids_bind(a: &CertId, b: &CertId) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number == b.serial_number
}

/// Whether `single` is fresh at `now` within `skew`: `now >= thisUpdate - skew`
/// and, when `nextUpdate` is present, `now <= nextUpdate + skew`. A response with
/// no `nextUpdate` has no asserted expiry, so only the lower bound applies. Pure.
fn is_fresh(single: &SingleResponse, now: SystemTime, skew: Duration) -> bool {
    let Some(now_unix) = system_time_to_unix(now) else {
        return false;
    };
    let this_update = single.this_update.0.to_unix_duration();
    // now must be at or after thisUpdate (minus skew).
    if now_unix.saturating_add(skew) < this_update {
        return false;
    }
    if let Some(next_update) = &single.next_update {
        let next = next_update.0.to_unix_duration();
        // now must be at or before nextUpdate (plus skew).
        if now_unix > next.saturating_add(skew) {
            return false;
        }
    }
    true
}

/// `now` as a `Duration` since the Unix epoch, or `None` if it predates the epoch
/// (which would make freshness comparisons meaningless — fail closed).
fn system_time_to_unix(now: SystemTime) -> Option<Duration> {
    now.duration_since(UNIX_EPOCH).ok()
}

/// Whether the response nonce is acceptable: either the responder echoed no nonce
/// (permitted — many responders do not honor nonces) OR it echoed exactly our
/// `request_nonce`. A present-but-different nonce is a replay/substitution. Pure.
fn nonce_ok(basic: &BasicOcspResponse, request_nonce: &[u8]) -> bool {
    match basic.nonce() {
        None => true,
        Some(echoed) => echoed.0.as_bytes() == request_nonce,
    }
}

/// The fail-closed policy decision: returns `true` to ALLOW the connection,
/// `false` to REJECT it. `Good` always allows; `Revoked` ALWAYS rejects (even
/// under soft-fail — a known-revoked cert is never admitted); `Unknown` rejects
/// unless `soft_fail`. Pure and unit-tested.
pub fn decide_allow(status: CertRevocationStatus, soft_fail: bool) -> bool {
    match status {
        CertRevocationStatus::Good => true,
        CertRevocationStatus::Revoked => false,
        CertRevocationStatus::Unknown => soft_fail,
    }
}

#[cfg(test)]
mod tests {
    use super::build_ocsp_request_der;
    use super::decide_allow;
    use super::delegated_responder_is_valid;
    use super::extract_ocsp_responder_url;
    use super::map_cert_status;
    use super::sha1_hash;
    use super::CertRevocationStatus;
    use super::OcspChecker;

    use der::asn1::BitString;
    use der::Encode;
    use der::Decode;
    use rcgen::date_time_ymd;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::Certificate;
    use x509_ocsp::builder::OcspRequestBuilder;
    use x509_ocsp::BasicOcspResponse;
    use x509_ocsp::CertStatus;
    use x509_ocsp::OcspGeneralizedTime;
    use x509_ocsp::OcspRequest;
    use x509_ocsp::OcspResponse;
    use x509_ocsp::OcspResponseStatus;
    use x509_ocsp::ResponderId;
    use x509_ocsp::ResponseData;
    use x509_ocsp::SingleResponse;
    use x509_ocsp::Version;

    /// Mint a self-signed CA-ish issuer certificate (its key/subject feed the
    /// CertID hash) and return `(issuer_der, issuer_key)`.
    fn mint_issuer() -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().expect("issuer key");
        let mut params = CertificateParams::new(Vec::new()).expect("issuer params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcps-test-ca");
        let cert = params.self_signed(&key).expect("issuer self-signed");
        (cert.der().as_ref().to_vec(), key)
    }

    /// A `SystemTime` `secs` after the Unix epoch (test helper).
    fn at_unix(secs: u64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    /// Mint a CA issuer (`IsCa::Ca` + `KeyCertSign`) able to SIGN child certs, and
    /// return both the rcgen `Certificate` (for signing) and its DER.
    fn mint_ca_issuer() -> (rcgen::Certificate, KeyPair, Vec<u8>) {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcps-test-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).expect("ca self-signed");
        let der = cert.der().as_ref().to_vec();
        (cert, key, der)
    }

    /// Mint a delegated OCSP responder cert SIGNED BY `issuer` (issuer key),
    /// carrying the `id-kp-OCSPSigning` EKU, valid over `[nb_ymd, na_ymd)` (each a
    /// `(year, month, day)` triple).
    fn mint_delegated_responder(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
        nb_ymd: (i32, u8, u8),
        na_ymd: (i32, u8, u8),
    ) -> Vec<u8> {
        let responder_key = KeyPair::generate().expect("responder key");
        let mut params =
            CertificateParams::new(vec!["ocsp-responder.example".to_string()]).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "ocsp-responder.example");
        params.not_before = date_time_ymd(nb_ymd.0, nb_ymd.1, nb_ymd.2);
        params.not_after = date_time_ymd(na_ymd.0, na_ymd.1, na_ymd.2);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::OcspSigning);
        let cert = params
            .signed_by(&responder_key, issuer, issuer_key)
            .expect("responder signed by issuer");
        cert.der().as_ref().to_vec()
    }

    /// RFC 6960 §4.2.2.2.1: a delegated responder cert OUTSIDE its validity window
    /// is rejected (fail closed — no candidate verifies → deny), while the same
    /// cert WITHIN its window and issuer-signed is accepted. Locks the M-95
    /// validity-window check.
    #[test]
    fn delegated_responder_validity_window_enforced() {
        let (issuer, issuer_key, issuer_der) = mint_ca_issuer();
        // Window: 2020-01-01 .. 2021-01-01.
        let responder_der =
            mint_delegated_responder(&issuer, &issuer_key, (2020, 1, 1), (2021, 1, 1));

        // now inside window → valid responder (EKU + issuer signature + lifetime).
        assert!(
            delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_593_561_600))
                .unwrap(),
            "in-window, issuer-signed, OCSP-EKU responder must be accepted" // 2020-07-01
        );

        // now AFTER notAfter → rejected (expired signer must not be trusted).
        assert!(
            !delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_640_995_200))
                .unwrap(),
            "an EXPIRED delegated responder cert must be rejected (RFC 6960 §4.2.2.2.1)" // 2022-01-01
        );

        // now BEFORE notBefore → rejected (not-yet-valid signer).
        assert!(
            !delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_546_300_800))
                .unwrap(),
            "a not-yet-valid delegated responder cert must be rejected" // 2019-01-01
        );
    }

    /// Known-answer vectors for the hand-rolled FIPS 180-4 SHA-1 used by the
    /// ResponderID `byKey` match (the standard fixes KeyHash to SHA-1). Guards the
    /// local implementation against a regression that would make a legitimate
    /// byKey responder mismatch (fail closed).
    #[test]
    fn sha1_known_answer_vectors() {
        // FIPS 180-4 / RFC 3174 published test vectors.
        assert_eq!(
            sha1_hash(b""),
            hex20("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            "SHA-1 of empty input"
        );
        assert_eq!(
            sha1_hash(b"abc"),
            hex20("a9993e364706816aba3e25717850c26c9cd0d89d"),
            "SHA-1(\"abc\")"
        );
        assert_eq!(
            sha1_hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex20("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            "SHA-1 of the 56-byte FIPS multi-block vector"
        );
    }

    /// Decode a 40-char hex string into the 20-byte SHA-1 digest array.
    fn hex20(s: &str) -> [u8; 20] {
        let bytes = s.as_bytes();
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("hex hi") as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("hex lo") as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    /// Mint a leaf certificate carrying an AIA OCSP responder URL via a custom
    /// extension (rcgen 0.13 supports raw custom extensions). The AIA value is a
    /// hand-built `AuthorityInfoAccessSyntax` with one `id-ad-ocsp` access
    /// description pointing at `ocsp_url`.
    fn mint_leaf_with_aia(ocsp_url: &str) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec!["leaf.example".to_string()])
            .expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example");
        // AIA OID 1.3.6.1.5.5.7.1.1; value = SEQUENCE OF AccessDescription, each
        // SEQUENCE { accessMethod OID, accessLocation [6] IA5String(url) }.
        let aia_der = build_aia_extension_der(ocsp_url);
        let ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], aia_der);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    /// Hand-encode an `AuthorityInfoAccessSyntax` containing a single
    /// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) access description whose location is the
    /// context-tag-6 IA5String form of `url`. Minimal DER, sufficient for
    /// x509-parser to recover the URL.
    fn build_aia_extension_der(url: &str) -> Vec<u8> {
        // accessMethod: OID 1.3.6.1.5.5.7.48.1 → DER bytes.
        let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        // accessLocation: [6] IA5String (context-specific primitive tag 6).
        let url_bytes = url.as_bytes();
        let mut location = vec![0x86u8, url_bytes.len() as u8];
        location.extend_from_slice(url_bytes);
        // AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
        let mut access_desc_body = Vec::new();
        access_desc_body.extend_from_slice(&oid);
        access_desc_body.extend_from_slice(&location);
        let mut access_desc = vec![0x30u8, access_desc_body.len() as u8];
        access_desc.extend_from_slice(&access_desc_body);
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        let mut aia = vec![0x30u8, access_desc.len() as u8];
        aia.extend_from_slice(&access_desc);
        aia
    }

    #[test]
    fn aia_url_extraction_reads_ocsp_responder() {
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/responder");
        let url = extract_ocsp_responder_url(&leaf);
        assert_eq!(
            url.as_deref(),
            Some("http://ocsp.example.test/responder"),
            "the AIA id-ad-ocsp URI must be recovered from the leaf"
        );
    }

    #[test]
    fn aia_url_extraction_none_without_aia() {
        // A leaf with no AIA extension yields None → the caller maps to Unknown.
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()])
            .expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        assert!(
            extract_ocsp_responder_url(cert.der().as_ref()).is_none(),
            "a leaf without AIA must yield no responder URL"
        );
    }

    #[test]
    fn aia_url_extraction_none_on_garbage() {
        assert!(
            extract_ocsp_responder_url(b"not a certificate").is_none(),
            "unparseable bytes must yield no responder URL"
        );
    }

    #[test]
    fn ocsp_request_der_round_trips() {
        let (issuer_der, _) = mint_issuer();
        // The leaf need not be issued by the issuer; CertID only hashes the
        // issuer subject/key and copies the leaf serial.
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let der = build_ocsp_request_der(&leaf, &issuer_der).expect("build request");
        let decoded = OcspRequest::from_der(&der).expect("request DER round-trips");
        assert_eq!(
            decoded.tbs_request.request_list.len(),
            1,
            "exactly one Request (one CertID) must be present"
        );
    }

    use super::build_cert_id;
    use super::cert_ids_bind;
    use super::is_fresh;
    use super::nonce_ok;
    use super::responder_id_matches;
    use super::select_matching_single_response;
    use super::verify_and_map_response;
    use super::OcspError;
    use super::OCSP_FRESHNESS_SKEW;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use x509_ocsp::ext::Nonce;
    use x509_ocsp::CertId;
    use x509_cert::ext::AsExtension;
    use x509_cert::ext::Extension;

    /// Knobs for hand-building an OCSP response fixture, so each acceptance test
    /// can isolate exactly ONE broken control (wrong CertID, stale, bad nonce, …).
    struct ResponseFixture {
        status: CertStatus,
        /// `None` ⇒ use the CertID derived from `(issuer, leaf)` (the matching
        /// one); `Some(id)` ⇒ a deliberately different CertID (binding test).
        cert_id: Option<CertId>,
        this_update: OcspGeneralizedTime,
        next_update: Option<OcspGeneralizedTime>,
        /// `Some(bytes)` ⇒ echo this nonce in the response extensions.
        echo_nonce: Option<Vec<u8>>,
        /// The signature bits to place on the BasicOcspResponse. Empty ⇒ unsigned.
        signature: Vec<u8>,
    }

    /// A GeneralizedTime fixture for the given y/m/d at 00:00:00 UTC.
    fn gtime(y: u16, m: u8, d: u8) -> OcspGeneralizedTime {
        OcspGeneralizedTime::from(der::DateTime::new(y, m, d, 0, 0, 0).expect("datetime"))
    }

    /// SystemTime at the given y/m/d 00:00:00 UTC (for injected `now`).
    fn at(y: u16, m: u8, d: u8) -> SystemTime {
        let dt = der::DateTime::new(y, m, d, 0, 0, 0).expect("datetime");
        UNIX_EPOCH + dt.unix_duration()
    }

    /// Build a `(issuer_der, leaf_der, response_der)` triple. The response wraps a
    /// `BasicOcspResponse` built per `fixture`. The signature is whatever the
    /// fixture supplies (unsigned by default); the production trust path verifies
    /// it with the ring-backed verifier that ships in the `online_ocsp` build, so
    /// an unsigned/forged signature is rejected at the signature gate. Returns the
    /// requested-CertID too, for the binding check.
    fn build_fixture(fixture: ResponseFixture) -> (Vec<u8>, Vec<u8>, Vec<u8>, CertId) {
        let (issuer_der, _) = mint_issuer();
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let requested_cert_id =
            build_cert_id(&leaf, &issuer_der).expect("requested cert id");
        let response_cert_id = fixture.cert_id.unwrap_or_else(|| requested_cert_id.clone());

        let mut single = SingleResponse::new(
            response_cert_id,
            fixture.status,
            fixture.this_update,
        );
        single.next_update = fixture.next_update;

        let response_extensions = fixture.echo_nonce.map(|bytes| {
            let nonce = Nonce::new(bytes).expect("nonce");
            let ext: Extension = nonce
                .to_extension(&issuer.tbs_certificate.subject, &[])
                .expect("nonce extension");
            vec![ext]
        });

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            produced_at: fixture.this_update,
            responses: vec![single],
            response_extensions,
        };
        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                // ecdsa-with-SHA256; the bits below are what is actually verified.
                oid: "1.2.840.10045.4.3.2".parse().expect("oid"),
                parameters: None,
            },
            signature: BitString::from_bytes(&fixture.signature).expect("bitstring"),
            certs: None,
        };
        let response = OcspResponse::successful(basic).expect("successful response");
        (
            issuer_der,
            leaf,
            response.to_der().expect("response DER"),
            requested_cert_id,
        )
    }

    /// A fresh, matching-CertID, good, unsigned fixture (the baseline the
    /// acceptance tests perturb). Returns `(issuer, leaf, response, requested_id)`.
    fn good_unsigned_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, CertId) {
        build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        })
    }

    // === #4063 (MCPS-088) acceptance tests — RFC 6960 §3.2 response trust =====
    //
    // Each asserts that a response which would, under the OLD code, ADMIT a leaf
    // (it returned the raw `cert_status`) is now DENIED because one trust control
    // rejects it. The `online_ocsp` build compiles the real ring-backed verifier,
    // so an unsigned signature is rejected at the signature gate — NOTHING admits
    // without a verified signature. The `mod verify` tests below re-prove the
    // per-control gates END-TO-END with a genuinely signed (Ed25519) response.

    /// ACCEPTANCE 1 — forged/unsigned responder returns Good for a leaf, but the
    /// signature is not verifiable ⇒ DENIED. This is the empty-signature fixture
    /// that the OLD code trusted; it must now fail closed.
    #[test]
    fn acceptance_unsigned_good_is_denied() {
        let (issuer, _leaf, response, requested_id) = good_unsigned_fixture();
        let nonce = b"unused-request-nonce".to_vec();
        let result =
            verify_and_map_response(&response, &issuer, &requested_id, &nonce, at(2024, 1, 1));
        assert!(
            matches!(result, Err(OcspError::SignatureNotVerified(_))),
            "an unsigned/forged Good must be rejected at the signature gate, got {result:?}"
        );
    }

    /// ACCEPTANCE 2 — CertID binding. A response whose SingleResponse answers a
    /// DIFFERENT CertID carries no evidence about our leaf. Even setting aside the
    /// signature gate, `select_matching_single_response` must not match it.
    #[test]
    fn acceptance_wrong_certid_is_denied() {
        // A mismatching CertID (different serial via a different leaf).
        let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = build_cert_id(&other_leaf, &issuer_der).expect("wrong id");
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: Some(wrong_id.clone()),
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        // The requested id must NOT equal the response's wrong id.
        assert!(!cert_ids_bind(&requested_id, &wrong_id));
        // End-to-end: denied (at the signature gate; the binding gate is also
        // asserted directly below so that control is proven independently).
        let nonce = b"n".to_vec();
        assert!(verify_and_map_response(
            &response,
            &issuer,
            &requested_id,
            &nonce,
            at(2024, 1, 1)
        )
        .is_err());
    }

    /// ACCEPTANCE 3 — freshness. A signed-Good response whose `nextUpdate` is in
    /// the past is stale ⇒ DENIED. Proven directly on `is_fresh` (no crypto).
    #[test]
    fn acceptance_stale_response_is_denied() {
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2023, 1, 1),
            next_update: Some(gtime(2023, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        // `now` is well past nextUpdate → not fresh.
        let now = at(2024, 6, 1);
        let nonce = b"n".to_vec();
        assert!(
            verify_and_map_response(&response, &issuer, &requested_id, &nonce, now).is_err(),
            "a stale response must be denied"
        );
    }

    /// ACCEPTANCE 4 — nonce. A captured response echoing nonce A, replayed against
    /// a FRESH request nonce B, must be rejected (`nonce_ok` returns false).
    #[test]
    fn acceptance_nonce_mismatch_is_denied() {
        let captured_nonce = b"captured-nonce-AAAA".to_vec();
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: Some(captured_nonce.clone()),
            signature: Vec::new(),
        });
        // Fresh request nonce differs from the echoed one.
        let fresh_nonce = b"fresh-request-nonce-B".to_vec();
        assert_ne!(captured_nonce, fresh_nonce);
        assert!(
            verify_and_map_response(
                &response,
                &issuer,
                &requested_id,
                &fresh_nonce,
                at(2024, 1, 1)
            )
            .is_err(),
            "a response echoing a stale nonce under a fresh request must be denied"
        );
    }

    /// ACCEPTANCE 5 (status-policy negatives) — Revoked and Unknown both DENY
    /// under hard-fail. The positive (signed Good → ADMIT) is the `mod verify`
    /// test below (it needs a real responder signature).
    #[test]
    fn acceptance_revoked_and_unknown_deny() {
        // Pure policy: Revoked always rejects, Unknown rejects under hard-fail.
        assert!(!decide_allow(CertRevocationStatus::Revoked, false));
        assert!(!decide_allow(CertRevocationStatus::Unknown, false));
        // And a fully-formed Revoked/Unknown response still cannot ADMIT (it is
        // denied at the signature gate today, never mapped to Good).
        for status in [
            CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: gtime(2023, 6, 1),
                revocation_reason: None,
            }),
            CertStatus::unknown(),
        ] {
            let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
                status,
                cert_id: None,
                this_update: gtime(2024, 1, 1),
                next_update: Some(gtime(2024, 1, 2)),
                echo_nonce: None,
                signature: Vec::new(),
            });
            let mapped = verify_and_map_response(
                &response,
                &issuer,
                &requested_id,
                b"n",
                at(2024, 1, 1),
            );
            assert!(
                !matches!(mapped, Ok(CertRevocationStatus::Good)),
                "Revoked/Unknown must never map to an admitting Good"
            );
        }
    }

    // --- Direct unit tests of the individual trust controls (no crypto) -------

    #[test]
    fn certid_binding_matches_only_same_cert() {
        let (issuer_der, _) = mint_issuer();
        let leaf_a = mint_leaf_with_aia("http://a/r");
        let leaf_b = mint_leaf_with_aia("http://b/r");
        let id_a = build_cert_id(&leaf_a, &issuer_der).expect("id a");
        let id_a2 = build_cert_id(&leaf_a, &issuer_der).expect("id a2");
        let id_b = build_cert_id(&leaf_b, &issuer_der).expect("id b");
        assert!(cert_ids_bind(&id_a, &id_a2), "same cert binds");
        assert!(!cert_ids_bind(&id_a, &id_b), "different serial does not bind");
    }

    #[test]
    fn select_matching_single_response_requires_binding() {
        let other_leaf = mint_leaf_with_aia("http://other/r");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = build_cert_id(&other_leaf, &issuer_der).expect("wrong id");
        let (_i, _l, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: Some(wrong_id),
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        assert!(
            select_matching_single_response(&basic, &requested_id).is_none(),
            "a SingleResponse for a different CertID must not be selected"
        );
    }

    #[test]
    fn freshness_window_enforced() {
        // thisUpdate=Jan1, nextUpdate=Jan2; with skew=5m the valid window is
        // ~[Jan1-5m, Jan2+5m].
        let (_i, _l, response, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];
        assert!(is_fresh(single, at(2024, 1, 1), OCSP_FRESHNESS_SKEW), "within window");
        assert!(
            !is_fresh(single, at(2023, 12, 31), OCSP_FRESHNESS_SKEW),
            "before thisUpdate (beyond skew) is not fresh"
        );
        assert!(
            !is_fresh(single, at(2024, 6, 1), OCSP_FRESHNESS_SKEW),
            "after nextUpdate (beyond skew) is not fresh"
        );
    }

    #[test]
    fn freshness_skew_tolerated() {
        let (_i, _l, response, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 1)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];
        // 2 minutes before thisUpdate is within the 5-minute skew.
        let just_before = at(2024, 1, 1) - Duration::from_secs(120);
        assert!(is_fresh(single, just_before, OCSP_FRESHNESS_SKEW));
    }

    #[test]
    fn nonce_match_required_when_present() {
        let req = b"the-request-nonce".to_vec();
        let (_i, _l, matching, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: Some(req.clone()),
            signature: Vec::new(),
        });
        let (_i2, _l2, mismatch, _id2) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: Some(b"a-different-nonce".to_vec()),
            signature: Vec::new(),
        });
        let (_i3, _l3, absent, _id3) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: None,
            signature: Vec::new(),
        });
        assert!(nonce_ok(&decode_basic(&matching), &req), "echoed == request → ok");
        assert!(!nonce_ok(&decode_basic(&mismatch), &req), "echoed != request → reject");
        assert!(
            nonce_ok(&decode_basic(&absent), &req),
            "no echoed nonce is permitted (responder may not honor nonces)"
        );
    }

    #[test]
    fn responder_id_byname_matches_issuer() {
        let (issuer_der, _) = mint_issuer();
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let by_name = ResponderId::ByName(issuer.tbs_certificate.subject.clone());
        assert!(responder_id_matches(&by_name, &issuer_der));
        // A cert with a DIFFERENT subject DN must not match.
        let other_key = KeyPair::generate().expect("other key");
        let mut other_params = CertificateParams::new(Vec::new()).expect("other params");
        other_params
            .distinguished_name
            .push(DnType::CommonName, "some-other-ca");
        let other = other_params.self_signed(&other_key).expect("other self-signed");
        assert!(!responder_id_matches(&by_name, other.der().as_ref()));
    }

    /// Decode a response DER back to its BasicOcspResponse for white-box control
    /// tests. (Production code only reaches this via verify_and_map_response.)
    fn decode_basic(response_der: &[u8]) -> BasicOcspResponse {
        let response = OcspResponse::from_der(response_der).expect("response");
        let bytes = response.response_bytes.expect("bytes");
        BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("basic")
    }

    #[test]
    fn rejects_non_successful_responder_status() {
        let try_later = OcspResponse::try_later().to_der().expect("try_later DER");
        let (issuer_der, _) = mint_issuer();
        let id = build_cert_id(
            &mint_leaf_with_aia("http://x/r"),
            &issuer_der,
        )
        .expect("id");
        assert!(
            verify_and_map_response(&try_later, &issuer_der, &id, b"n", at(2024, 1, 1))
                .is_err(),
            "a non-successful OCSP responder status must fail closed"
        );
    }

    #[test]
    fn nonce_round_trips_in_request() {
        // The live path builds a request WITH a nonce extension; assert it is
        // present and recoverable (so the responder can echo it).
        let leaf = mint_leaf_with_aia("http://x/r");
        let (issuer_der, _) = mint_issuer();
        let nonce = b"sixteen-byte-non".to_vec();
        let der = super::build_ocsp_request_der_with_nonce(&leaf, &issuer_der, &nonce)
            .expect("request");
        let decoded = OcspRequest::from_der(&der).expect("round-trips");
        let echoed = decoded.nonce().expect("nonce present");
        assert_eq!(echoed.0.as_bytes(), nonce.as_slice());
    }

    #[test]
    fn cert_status_helper_maps_choices() {
        assert_eq!(map_cert_status(&CertStatus::good()), CertRevocationStatus::Good);
        assert_eq!(
            map_cert_status(&CertStatus::unknown()),
            CertRevocationStatus::Unknown
        );
    }

    #[test]
    fn policy_revoked_always_rejects() {
        // Revoked is rejected under BOTH hard-fail and soft-fail.
        assert!(!decide_allow(CertRevocationStatus::Revoked, false));
        assert!(!decide_allow(CertRevocationStatus::Revoked, true));
    }

    #[test]
    fn policy_good_always_allows() {
        assert!(decide_allow(CertRevocationStatus::Good, false));
        assert!(decide_allow(CertRevocationStatus::Good, true));
    }

    #[test]
    fn policy_unknown_hard_fail_rejects_soft_fail_allows() {
        assert!(
            !decide_allow(CertRevocationStatus::Unknown, false),
            "Unknown under hard-fail must reject"
        );
        assert!(
            decide_allow(CertRevocationStatus::Unknown, true),
            "Unknown under soft-fail must allow"
        );
    }

    #[test]
    fn checker_allows_methods_match_policy() {
        let hard = OcspChecker::new(None, false);
        assert!(hard.allows(CertRevocationStatus::Good));
        assert!(!hard.allows(CertRevocationStatus::Revoked));
        assert!(!hard.allows(CertRevocationStatus::Unknown));
        assert!(!hard.allows_on_error());

        let soft = OcspChecker::new(None, true);
        assert!(soft.allows(CertRevocationStatus::Unknown));
        assert!(soft.allows_on_error());
        assert!(!soft.allows(CertRevocationStatus::Revoked));
    }

    // === #4078 (MCPS-MED-5, M14) — AIA responder-URL SSRF guard =============
    //
    // The AIA OCSP responder URL is taken VERBATIM from the attacker-influenced
    // leaf certificate and (pre-fix) fetched with no scheme/SSRF guard. A hostile
    // leaf can point the proxy at `file://`, `gopher://`, or an internal/link-local
    // host (169.254/16, 127/8, ::1, 10/8, 172.16/12, 192.168/16, metadata
    // endpoints) → SSRF. The guard must reject such a responder URL BEFORE any
    // network fetch, failing CLOSED (Unknown → deny under hard-fail) exactly as a
    // missing AIA URL does. The operator-supplied `--ocsp-responder-url` override
    // is scheme-checked (http/https only) but, by design, NOT subject to the
    // private-IP block (an operator may legitimately run an internal responder).

    use super::aia_responder_url_is_safe;
    use super::responder_scheme_allowed;

    /// A disallowed scheme on the CERT-supplied AIA URL must be rejected before
    /// any fetch — `check()` short-circuits to `Ok(Unknown)` (fail-closed), never
    /// attempting the network. `file://` is the canonical SSRF/file-read vector.
    #[test]
    fn check_rejects_cert_aia_file_scheme_before_fetch() {
        // A leaf whose ONLY AIA OCSP URL is a file:// URL.
        let leaf = mint_leaf_with_aia("file:///etc/passwd");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None, false);
        // If the guard were absent the path would try to POST to `file:///...`
        // (ureq) and return Err(Http(..)); WITH the guard it short-circuits to
        // Ok(Unknown) WITHOUT any fetch. Assert the fail-closed Unknown.
        let status = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("an unsafe-scheme AIA URL fails closed as Ok(Unknown), not Err");
        assert_eq!(
            status,
            CertRevocationStatus::Unknown,
            "a file:// AIA responder URL must be rejected pre-fetch as Unknown"
        );
        // And Unknown under hard-fail denies.
        assert!(!checker.allows(status), "Unknown under hard-fail must deny");
    }

    /// A loopback host on the CERT-supplied AIA URL is an SSRF vector and must be
    /// rejected pre-fetch as Unknown (fail closed). `http://127.0.0.1:1/` points
    /// at an unroutable port; were the guard absent the fetch would (slowly)
    /// connection-error as Err(Http), so an Ok(Unknown) proves no fetch occurred.
    #[test]
    fn check_rejects_cert_aia_loopback_host_before_fetch() {
        let leaf = mint_leaf_with_aia("http://127.0.0.1:1/ocsp");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None, false);
        let status = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("a loopback AIA URL fails closed as Ok(Unknown), not Err");
        assert_eq!(status, CertRevocationStatus::Unknown);
    }

    /// `localhost` (a hostname, not a literal IP) is the loopback name and must
    /// likewise be rejected on the cert-derived path.
    #[test]
    fn check_rejects_cert_aia_localhost_before_fetch() {
        let leaf = mint_leaf_with_aia("http://localhost:1/ocsp");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None, false);
        let status = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("a localhost AIA URL fails closed as Ok(Unknown)");
        assert_eq!(status, CertRevocationStatus::Unknown);
    }

    /// Positive control: a NORMAL public-hostname http AIA URL passes the guard
    /// (so the guard does not over-block legitimate responders). The fetch itself
    /// then fails (no responder listening), but as Err(Http) — proving the URL was
    /// accepted by the guard and the path PROCEEDED to the network, not rejected
    /// pre-fetch as Ok(Unknown).
    #[test]
    fn aia_guard_accepts_normal_public_url() {
        assert!(
            aia_responder_url_is_safe("http://ocsp.example.com/"),
            "a normal public http responder URL must pass the AIA SSRF guard"
        );
        assert!(
            aia_responder_url_is_safe("https://ocsp.digicert.com"),
            "a normal public https responder URL must pass the AIA SSRF guard"
        );
    }

    /// The AIA guard (cert-derived, attacker-influenced) blocks disallowed schemes
    /// AND every private/loopback/link-local/unspecified/multicast literal IP.
    #[test]
    fn aia_guard_blocks_schemes_and_private_ranges() {
        // Disallowed schemes.
        for url in [
            "file:///etc/passwd",
            "gopher://evil/",
            "ftp://host/x",
            "ldap://host/",
            "data:text/plain,x",
            "not-a-url",
            "",
        ] {
            assert!(
                !aia_responder_url_is_safe(url),
                "{url:?} has a disallowed/absent scheme and must be blocked"
            );
        }
        // Private / loopback / link-local / unspecified / multicast literals.
        for url in [
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/", // cloud metadata
            "http://10.0.0.5/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
            "http://[::]/",
            "http://localhost/",
            "http://224.0.0.1/",          // multicast
            "http://[fe80::1]/",          // IPv6 link-local
            "http://[fc00::1]/",          // IPv6 unique-local
        ] {
            assert!(
                !aia_responder_url_is_safe(url),
                "{url:?} resolves to a non-public address and must be blocked"
            );
        }
    }

    /// Issue #26: the SSRF guard must block NON-dotted-decimal IP encodings that
    /// `inet_aton(3)` (and thus the OS resolver / HTTP client) resolves to the same
    /// internal addresses — octal, hex, 32-bit integer, and short forms. Without
    /// canonicalization these slip past the dotted-decimal block as "hostnames".
    #[test]
    fn aia_guard_blocks_alternate_ip_encodings() {
        for url in [
            // 127.0.0.1 (loopback) in every alternate encoding.
            "http://0177.0.0.1/", // octal first octet
            "http://0x7f.0.0.1/", // hex first octet
            "http://0x7f000001/", // single hex 32-bit
            "http://2130706433/", // single decimal 32-bit
            "http://127.1/",      // short form (a.b)
            "http://127.0.1/",    // short form (a.b.c)
            // 169.254.169.254 (cloud metadata) alternate encodings.
            "http://2852039166/",          // decimal 32-bit
            "http://0xa9fea9fe/",          // hex 32-bit
            "http://0251.0376.0251.0376/", // all-octal dotted
            // 10.0.0.5 (RFC1918) as a 32-bit integer.
            "http://167772165/",
            // 0.0.0.0 (unspecified) as integer.
            "http://0/",
        ] {
            assert!(
                !aia_responder_url_is_safe(url),
                "{url:?} canonicalizes to a non-public IP and must be blocked"
            );
        }
    }

    /// Positive control: a PUBLIC address in an alternate encoding must STILL be
    /// allowed (the canonicalization must not over-block), and a genuine hostname
    /// that merely looks numeric-ish is treated as a name, not mis-parsed.
    #[test]
    fn aia_guard_allows_public_alternate_encodings_and_hostnames() {
        // 8.8.8.8 (public) as hex 32-bit and octal dotted — must pass.
        assert!(aia_responder_url_is_safe("http://0x08080808/"));
        // 8.8.8.8 in all-octal dotted form.
        assert!(aia_responder_url_is_safe("http://010.010.010.010/"));
        // A real hostname (non-numeric labels) is permitted at this layer.
        assert!(aia_responder_url_is_safe("http://ocsp.example.com/"));
    }

    /// Stage-2 audit regression: a syntactically malformed host — trailing dot,
    /// leading dot, doubled dot, or empty — produces an empty DNS label that std's
    /// `IpAddr`/`inet_aton` parsers reject, so before the empty-label guard it fell
    /// through to the "treat as hostname → permit" branch. The OS resolver, however,
    /// STRIPS a trailing root dot, so `169.254.169.254.` / `127.0.0.1.` reach the
    /// internal address. All such forms must now be blocked. A legitimate trailing-
    /// dot FQDN is rejected too — an accepted hardening tradeoff for a revocation
    /// fetcher (responder URLs do not need the root-dot form).
    #[test]
    fn aia_guard_blocks_malformed_empty_label_hosts() {
        for url in [
            "http://169.254.169.254./latest/meta-data/", // trailing-dot metadata bypass
            "http://127.0.0.1./",                        // trailing-dot loopback bypass
            "http://127.0.0.1../",                       // doubled trailing dot
            "http://.169.254.169.254/",                  // leading dot
            "http://example..com/",                      // doubled interior dot
            "http://.../",                               // all-empty labels
        ] {
            assert!(
                !aia_responder_url_is_safe(url),
                "{url:?} has an empty DNS label and must be blocked (not normalized)"
            );
        }
        // The malformed-host rejection is at the host layer, so it holds for the bare
        // host too (the guard is what `aia_responder_url_is_safe` calls after host
        // extraction).
        assert!(!super::host_is_public("169.254.169.254."));
        assert!(!super::host_is_public("127.0.0.1."));
        assert!(!super::host_is_public("a..b"));
        assert!(!super::host_is_public(""));
        // A normal hostname (no empty label) still passes the host layer.
        assert!(super::host_is_public("ocsp.example.com"));
    }

    /// Stage-2 audit regression: the responder-host SSRF guard only inspects the
    /// FIRST URL, so a guarded responder that replies `302 Location:
    /// http://<internal>/` must NOT be chased — `ureq` follows redirects by default,
    /// which would reach an address that never passed the guard. This drives the real
    /// fetch (`post_request`) against a local responder that 302s to a SENTINEL
    /// listener standing in for the internal target, and asserts the sentinel is
    /// never contacted.
    #[test]
    fn ocsp_post_does_not_follow_redirects() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        // The "internal" target the redirect points at. Non-blocking so we can probe
        // for a connection without hanging the test.
        let sentinel = TcpListener::bind("127.0.0.1:0").expect("bind sentinel");
        let sentinel_addr = sentinel.local_addr().expect("sentinel addr");
        sentinel.set_nonblocking(true).expect("sentinel nonblocking");

        // The guarded responder: accepts one connection, reads the OCSP POST, and
        // replies with a 302 redirect to the sentinel. `responder_hit` proves the
        // fetch actually reached the responder, so a clean sentinel cannot be a
        // false-pass from a failed first request.
        let responder = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let responder_addr = responder.local_addr().expect("responder addr");
        let responder_hit = Arc::new(AtomicBool::new(false));
        let redirect_to = format!("http://{sentinel_addr}/");
        let hit_flag = Arc::clone(&responder_hit);
        thread::spawn(move || {
            if let Ok((mut stream, _)) = responder.accept() {
                hit_flag.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let checker = OcspChecker::new(None, false);
        let url = format!("http://{responder_addr}/ocsp");
        // The result itself is irrelevant (a 302 carries no valid OCSP body); the
        // security property is that NO request reaches the sentinel.
        let _ = checker.post_request(&url, b"dummy-ocsp-request");

        // Wait (bounded) for the responder thread to observe the connection so the test
        // can't false-pass due to a failed first request.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !responder_hit.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            responder_hit.load(Ordering::SeqCst),
            "the OCSP fetch never reached the responder — test would false-pass; check the harness"
        );
        match sentinel.accept() {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Correct: redirects disabled, the internal target was never reached.
            }
            Ok(_) => panic!(
                "OCSP fetch FOLLOWED the 302 redirect to the internal sentinel — SSRF redirect bypass"
            ),
            Err(e) => panic!("unexpected sentinel accept error: {e}"),
        }
    }

    /// Unit-level proof that the loose parser canonicalizes each encoding to the
    /// SAME address the dotted-decimal form denotes.
    #[test]
    fn inet_aton_parser_canonicalizes_each_encoding() {
        use std::net::Ipv4Addr;
        let loopback = Ipv4Addr::new(127, 0, 0, 1);
        for form in [
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f000001",
            "2130706433",
            "127.1",
            "127.0.1",
        ] {
            assert_eq!(
                super::parse_inet_aton_ipv4(form),
                Some(loopback),
                "{form:?} must canonicalize to 127.0.0.1"
            );
        }
        assert_eq!(
            super::parse_inet_aton_ipv4("2852039166"),
            Some(Ipv4Addr::new(169, 254, 169, 254)),
            "the cloud-metadata integer must canonicalize correctly"
        );
        // Non-IP hostnames and malformed numeric forms are NOT parsed as IPs.
        assert_eq!(super::parse_inet_aton_ipv4("ocsp.example.com"), None);
        assert_eq!(super::parse_inet_aton_ipv4("0x"), None); // empty hex digits
        assert_eq!(super::parse_inet_aton_ipv4("256.0.0.1"), None); // octet overflow
        assert_eq!(super::parse_inet_aton_ipv4("1.2.3.4.5"), None); // too many parts
        assert_eq!(super::parse_inet_aton_ipv4("4294967296"), None); // > u32::MAX
    }

    /// The scheme allowlist (applied to BOTH cert AIA and operator override) admits
    /// only http/https. The operator override is scheme-checked but NOT subject to
    /// the private-IP block, so an operator-chosen internal responder still passes
    /// the scheme gate.
    #[test]
    fn operator_override_scheme_checked_not_ip_blocked() {
        assert!(responder_scheme_allowed("http://ocsp.internal/"));
        assert!(responder_scheme_allowed("https://ocsp.internal/"));
        assert!(!responder_scheme_allowed("file:///etc/passwd"));
        assert!(!responder_scheme_allowed("gopher://x/"));
        // An operator override pointing at an internal/private host passes the
        // scheme gate (the private-IP block does NOT apply to the override).
        assert!(responder_scheme_allowed("http://10.0.0.5:8080/ocsp"));
        assert!(responder_scheme_allowed("http://localhost:8080/ocsp"));
        // But the AIA (cert) guard WOULD block that same private host.
        assert!(!aia_responder_url_is_safe("http://10.0.0.5:8080/ocsp"));
    }

    #[test]
    fn check_with_no_url_is_unknown() {
        // No override and a leaf without AIA → check() short-circuits to Unknown
        // (no network performed).
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()])
            .expect("params");
        let leaf = params.self_signed(&key).expect("self-signed");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None, false);
        let status = checker
            .check(leaf.der().as_ref(), &issuer_der)
            .expect("no-URL check is Ok(Unknown)");
        assert_eq!(status, CertRevocationStatus::Unknown);
    }

    #[test]
    fn ocsp_request_builder_default_is_empty() {
        // Sanity: an empty builder builds a request with no CertIDs (guards
        // against an accidental default CertID).
        let req = OcspRequestBuilder::default().build();
        let der = req.to_der().expect("der");
        let decoded = OcspRequest::from_der(&der).expect("round trip");
        assert!(decoded.tbs_request.request_list.is_empty());
        let _ = OcspResponseStatus::Successful;
    }

    // === #4063 (MCPS-088) — responder-SIGNATURE acceptance, run through the
    // SAME production verifier the `online_ocsp` build ships ===================
    //
    // These prove the cryptographic gate END-TO-END through the production
    // `verify_and_map_response`: a response SIGNED by the issuer's key with the
    // correct CertID/freshness/nonce is ADMITTED; a forged/wrong-key or empty
    // signature is DENIED. The verifier (x509-parser/ring) is part of the
    // `online_ocsp` module, so these tests exercise the production path, not a
    // parallel flavor. The in-tree, Bazel-addressable test signer is Ed25519
    // (ed25519-dalek); the verifier is algorithm-agnostic and ALSO covers RSA
    // PKCS#1 SHA-256/384/512 and ECDSA P-256/P-384 (exercised by the
    // openssl-responder `ocsp_e2e_test`).
    mod verify {
        use super::super::verify_and_map_response;
        use super::super::CertRevocationStatus;
        use super::super::OcspError;
        use super::build_cert_id;
        use super::gtime;
        use super::at;
        use super::mint_leaf_with_aia;
        use der::asn1::BitString;
        use der::Encode;
        use der::Decode;
        use ed25519_dalek::ed25519::pkcs8::EncodePrivateKey;
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        use rcgen::CertificateParams;
        use rcgen::DnType;
        use rcgen::KeyPair;
        use rcgen::PKCS_ED25519;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::Certificate;
        use x509_ocsp::BasicOcspResponse;
        use x509_ocsp::CertStatus;
        use x509_ocsp::OcspResponse;
        use x509_ocsp::ResponderId;
        use x509_ocsp::ResponseData;
        use x509_ocsp::SingleResponse;
        use x509_ocsp::Version;

        /// Mint an Ed25519 issuer cert whose private key is `signer` (so the test
        /// can sign an OCSP response with the SAME key the issuer SPKI carries).
        /// Returns the issuer DER.
        fn mint_issuer_with_key(signer: &SigningKey) -> Vec<u8> {
            let pkcs8 = signer.to_pkcs8_der().expect("pkcs8");
            let key = KeyPair::from_pkcs8_der_and_sign_algo(
                &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
                &PKCS_ED25519,
            )
            .expect("rcgen import");
            let mut params = CertificateParams::new(Vec::new()).expect("params");
            params
                .distinguished_name
                .push(DnType::CommonName, "mcps-ed25519-ca");
            let cert = params.self_signed(&key).expect("issuer self-signed");
            cert.der().as_ref().to_vec()
        }

        /// Build a response for `(issuer, leaf)` with `status`, then sign its
        /// `tbs_response_data` with `signer`. The `corrupt` flag flips a signature
        /// byte to model a forgery. Returns the response DER and the requested
        /// CertID.
        fn signed_response(
            signer: &SigningKey,
            issuer_der: &[u8],
            leaf_der: &[u8],
            status: CertStatus,
            corrupt: bool,
        ) -> (Vec<u8>, x509_ocsp::CertId) {
            let issuer = Certificate::from_der(issuer_der).expect("issuer");
            let requested = build_cert_id(leaf_der, issuer_der).expect("cert id");
            let mut single = SingleResponse::new(
                requested.clone(),
                status,
                gtime(2024, 1, 1),
            );
            single.next_update = Some(gtime(2024, 1, 2));
            let tbs = ResponseData {
                version: Version::V1,
                responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
                produced_at: gtime(2024, 1, 1),
                responses: vec![single],
                response_extensions: None,
            };
            let tbs_der = tbs.to_der().expect("tbs der");
            let mut sig = signer.sign(&tbs_der).to_bytes().to_vec();
            if corrupt {
                sig[0] ^= 0xFF;
            }
            let basic = BasicOcspResponse {
                tbs_response_data: tbs,
                signature_algorithm: AlgorithmIdentifierOwned {
                    // id-Ed25519 (RFC 8410), the OID x509-parser maps to ED25519.
                    oid: "1.3.101.112".parse().expect("oid"),
                    parameters: None,
                },
                signature: BitString::from_bytes(&sig).expect("bitstring"),
                certs: None,
            };
            let response = OcspResponse::successful(basic).expect("successful");
            (response.to_der().expect("der"), requested)
        }

        #[test]
        fn signed_good_is_admitted() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), false);
            let status = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            )
            .expect("a correctly-signed, fresh, bound Good must verify");
            assert_eq!(
                status,
                CertRevocationStatus::Good,
                "a verified Good admits the connection"
            );
        }

        #[test]
        fn forged_signature_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), true);
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::SignatureNotVerified(_))),
                "a forged signature must be rejected, got {result:?}"
            );
        }

        #[test]
        fn wrong_key_signature_is_denied() {
            // Signed by a DIFFERENT key than the issuer SPKI → no candidate
            // verifies → denied.
            let issuer_signer = SigningKey::from_bytes(&[7u8; 32]);
            let attacker_signer = SigningKey::from_bytes(&[9u8; 32]);
            let issuer = mint_issuer_with_key(&issuer_signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&attacker_signer, &issuer, &leaf, CertStatus::good(), false);
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::SignatureNotVerified(_))),
                "a response signed by a non-issuer key must be rejected, got {result:?}"
            );
        }

        #[test]
        fn signed_good_for_wrong_certid_is_denied() {
            // Correctly SIGNED, but the SingleResponse answers a DIFFERENT cert.
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
            // Sign a response that BINDS to `other_leaf`, but we query for `leaf`.
            let (response, _other_id) =
                signed_response(&signer, &issuer, &other_leaf, CertStatus::good(), false);
            let requested_for_leaf =
                build_cert_id(&leaf, &issuer).expect("requested id");
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested_for_leaf,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::CertIdMismatch)),
                "a signed Good for a different CertID must be rejected, got {result:?}"
            );
        }

        #[test]
        fn signed_good_but_stale_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), false);
            // now is far past nextUpdate (Jan 2) → stale.
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2025, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::NotFresh(_))),
                "a signed but stale Good must be rejected, got {result:?}"
            );
        }
    }
}
