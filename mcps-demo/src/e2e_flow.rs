//! The shared multi-process mTLS positive-path flow (MCPS-056, Phase 6.6,
//! epic #3948).
//!
//! This is the ONE orchestration both the hermetic `rust_test` (#3943) and the
//! human-facing `bazel run //mcps-demo:demo_e2e` wrapper drive against a REAL,
//! separately-spawned `mcps_proxy_cli` process over a REAL mTLS socket. It
//! reinvents NOTHING:
//!
//!   * signing, nonce, freshness, and `request_hash` correlation stay in
//!     `mcps-host`'s [`HostSession`](mcps_host::HostSession) (driven through the
//!     demo's [`DemoHostClient`](crate::DemoHostClient));
//!   * the mTLS connection, server-cert + server-identity verification, client-
//!     cert presentation, and HTTP framing stay in `mcps-transport`'s
//!     [`MtlsClient`](mcps_transport::MtlsClient);
//!   * the reference authorization grant is minted by `mcps-policy` via the
//!     demo's [`mint_demo_grant`](crate::mint_demo_grant);
//!   * the response verification (bind to the STORED request hash) is the
//!     session's own job.
//!
//! The flow ORCHESTRATES the positive path (matrix P1): the client signs ONE
//! authorized `list_files`, ATTACHES the reference grant under
//! `params._meta[<authorization key>]`, POSTs the signed bytes over mTLS to the
//! proxy, and verifies the signed response against the request hash it stored at
//! sign time. The proxy (its own OS process) enforces `--transport-binding
//! exact`, so the run only succeeds because the mTLS client identity (the client
//! cert's URI SAN) EQUALS the request signer.
//!
//! Boundary (LOCKED): this module holds NO transport, signing, or policy logic —
//! it stitches the proven crates together. It does not open a socket or speak
//! `rustls`/`jwt` directly; it does not compute a hash by hand.

use std::net::SocketAddr;

use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationKey;
use mcps_host::HostSigner;
use mcps_host::SystemClock;
use mcps_host::SystemNonceSource;
use mcps_host::UnwrappedResult;
use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

use crate::client::DemoHostClient;
use crate::demo_authorization::mint_demo_grant;
use crate::demo_authorization::DemoGrant;
use crate::demo_authorization::DemoGrantSpec;
use crate::demo_fixtures::DemoFixtures;

/// The demo `tools/call` tool the grant authorizes and the client invokes.
pub const E2E_TOOL: &str = "list_files";
/// The single demo-root subdirectory the grant authorizes and the client lists.
/// It exists in the committed `demo_root/` fixture (`reports/`), so a successful
/// listing proves the inner fileserver actually executed.
pub const E2E_PATH: &str = "reports";
/// The party the request is signed on behalf of (the human/user identity).
pub const E2E_ON_BEHALF_OF: &str = "did:example:user-1";
/// The JSON-RPC id the single demo request carries.
pub const E2E_REQUEST_ID: &str = "req-e2e-1";

/// A fully verified positive round trip — the data the test asserts on and the
/// `demo_e2e` bin prints. It carries identities + the correlated hash and the
/// returned fixture entry names (which prove the inner fileserver ran), never a
/// secret.
#[derive(Debug, Clone)]
pub struct E2eOutcome {
    /// The request signer identity (== the mTLS client cert URI SAN, so the
    /// proxy's `exact` transport binding is satisfied — not bypassed).
    pub signer: String,
    /// The audience the request was signed for (the proxy's identity).
    pub audience: String,
    /// The Core-computed request hash the session stored at sign time and the
    /// signed response bound back to.
    pub request_hash: String,
    /// The `authorization_hash` binding the request to the attached grant.
    pub authorization_hash: String,
    /// The server signer identity that signed the verified response.
    pub server_signer: String,
    /// The entry NAMES the inner fileserver returned for `list_files` on
    /// [`E2E_PATH`] — proof the inner subprocess actually executed.
    pub entries: Vec<String>,
}

/// An error driving the positive flow. Each variant names the boundary that
/// failed so both the test and the bin can surface it loudly and precisely; the
/// libraries this orchestrates never panic on bad input.
#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    /// Building the verifying mTLS client (TLS material) failed.
    #[error("building mTLS client: {0}")]
    Client(String),
    /// Minting or hashing the reference authorization grant failed.
    #[error("authorization grant: {0}")]
    Grant(String),
    /// Signing the request via the [`HostSession`](mcps_host::HostSession) failed.
    #[error("signing failed: {0}")]
    Sign(String),
    /// The mTLS round trip (handshake / IO) failed.
    #[error("mTLS transport failed: {0}")]
    Transport(String),
    /// The proxy returned a JSON-RPC error response (carried verbatim) — a
    /// positive run must NOT see one.
    #[error("proxy returned an error response: {0}")]
    ProxyError(String),
    /// A response could not be parsed / lacked the expected shape.
    #[error("malformed response: {0}")]
    BadResponse(String),
    /// The session refused to bind the signed response to the stored request
    /// hash, or a post-condition (pending count, returned entries) failed.
    #[error("response verification failed: {0}")]
    Verify(String),
    /// The verified response unwrapped to an INNER ERROR (issue #4077): the proxy
    /// signed an inner error under `result.inner_error`. A positive run must NOT
    /// see one — surfaced here as a real error, never as a success result.
    #[error("verified response carried an inner error: {0}")]
    InnerError(String),
}

/// The signing identity the demo positive flow uses, derived from the fixture
/// spec so the mTLS client cert identity, the request signer, and the grant
/// grantee are ONE identity (which is exactly what `--transport-binding exact`
/// requires).
fn signer_key(fixtures: &DemoFixtures) -> SigningKey {
    SigningKey::from_seed_bytes(&fixtures.signer_seed())
}

/// The proxy's response-signing public key, the client's trust anchor for the
/// signed response. Built from the fixture's SERVER seed.
fn server_public_key(fixtures: &DemoFixtures) -> VerificationKey {
    SigningKey::from_seed_bytes(&fixtures.server_seed())
        .public_key()
}

/// Mint the reference grant authorizing `list_files` on [`E2E_PATH`], valid
/// around the real clock `now_unix` (`[now - skew, now + lifetime]`), so a
/// SYSTEM-clock client request signed now falls inside the window and the proxy
/// (also on the real clock) accepts it. The grant is ISSUED BY the signer
/// identity (self-issued), so the single fixture `trust.json` entry already
/// carries the issuer key the proxy resolves for the policy-signature check.
fn build_grant(
    fixtures: &DemoFixtures,
    now_unix: i64,
    skew_secs: i64,
    lifetime_secs: i64,
) -> Result<DemoGrant, E2eError> {
    let spec = DemoGrantSpec {
        issuer: fixtures.signer().to_string(),
        grantee: fixtures.signer().to_string(),
        subject: E2E_ON_BEHALF_OF.to_string(),
        audience: fixtures.audience().to_string(),
        allowed_path: E2E_PATH.to_string(),
        not_before: mcps_core::unix_to_rfc3339_utc(now_unix - skew_secs),
        expires_at: mcps_core::unix_to_rfc3339_utc(now_unix + lifetime_secs),
        revocation_id: "demo-e2e-positive".to_string(),
    };
    mint_demo_grant(&spec, &signer_key(fixtures), fixtures.signer_key_id())
        .map_err(|e| E2eError::Grant(format!("{e:?}")))
}

/// The trust anchor for verifying the SIGNED RESPONSE: the proxy's server signer
/// public key.
fn response_resolver(fixtures: &DemoFixtures) -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(
        fixtures.server_signer(),
        fixtures.server_key_id(),
        server_public_key(fixtures),
    );
    resolver
}

/// Drive the positive multi-process flow against an ALREADY-LISTENING proxy at
/// `proxy_addr` (a separate OS process the caller spawned), using `fixtures` for
/// all security material and `now_unix` (the real clock) to size the grant
/// window.
///
/// Steps (each delegated to the owning crate):
///   1. mint the reference grant (`mcps-policy`) and derive its
///      `authorization_hash`;
///   2. SIGN ONE `list_files` request with the grant attached under
///      `params._meta` (`mcps-host` `HostSession`), storing the request hash by
///      id;
///   3. POST the signed bytes over mTLS (`mcps-transport` `MtlsClient`) — the
///      handshake authenticates the proxy's server cert against the fixture
///      server CA and presents the client cert whose URI SAN equals the signer;
///   4. VERIFY the signed response against the STORED request hash (the session)
///      and confirm the pending count returns to 0;
///   5. extract the returned fixture entry names (proof the inner ran).
///
/// `skew_secs` / `lifetime_secs` size the freshness + grant windows; pass the
/// proxy's `--max-clock-skew` (default 300) and a comfortable request lifetime.
pub fn run_positive_e2e(
    fixtures: &DemoFixtures,
    proxy_addr: SocketAddr,
    now_unix: i64,
    skew_secs: i64,
    lifetime_secs: i64,
) -> Result<E2eOutcome, E2eError> {
    // 1. The reference grant + its binding hash.
    let grant = build_grant(fixtures, now_unix, skew_secs, lifetime_secs)?;
    let authorization_hash = grant
        .authorization_hash()
        .map_err(|e| E2eError::Grant(format!("authorization_hash: {e:?}")))?;

    // The verifying mTLS client (transport owns TLS): present the client cert,
    // verify the proxy's server cert + identity against the fixture server CA.
    let tls = ClientTlsConfig::from_pem(
        fixtures.client_cert_pem().as_bytes(),
        fixtures.client_key_pem().as_bytes(),
        fixtures.server_ca_pem().as_bytes(),
    )
    .map_err(|e| E2eError::Client(format!("{e}")))?;
    let client = MtlsClient::new(tls, fixtures.server_name())
        .map_err(|e| E2eError::Client(format!("{e}")))?;

    // 2. SIGN one authorized list_files with the grant attached under _meta. The
    //    session (real clock + real RNG) authors nonce/issued_at/expires_at and
    //    stores the request hash by id.
    let mut session = DemoHostClient::with_defaults(
        HostSigner::new(
            signer_key(fixtures),
            fixtures.signer(),
            fixtures.signer_key_id(),
        ),
        SystemClock,
        SystemNonceSource,
    );
    let id = Value::String(E2E_REQUEST_ID.to_string());
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(E2E_TOOL.to_string()));
    params.insert("arguments".to_string(), json!({ "path": E2E_PATH }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));

    let request = session
        .sign_request(
            &id,
            "tools/call",
            params,
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &authorization_hash,
        )
        .map_err(|e| E2eError::Sign(format!("{e:?}")))?;
    let stored_hash = session
        .stored_request_hash(&id)
        .ok_or_else(|| E2eError::Sign("no stored request hash after signing".to_string()))?
        .to_string();

    // 3. POST over mTLS to the SEPARATE proxy process (server-auth in handshake).
    let response = client
        .round_trip(proxy_addr, &request)
        .map_err(|e| E2eError::Transport(format!("{e}")))?;

    // 3b. Surface a JSON-RPC error response before attempting to bind it.
    let parsed: Value = serde_json::from_slice(&response)
        .map_err(|e| E2eError::BadResponse(format!("response is not JSON: {e}")))?;
    if let Some(error) = parsed.get("error") {
        return Err(E2eError::ProxyError(error.to_string()));
    }

    // 4. VERIFY the signed response against the STORED request hash (the session
    //    never trusts a caller-supplied expected hash). Confirm the binding hash
    //    and that the pending set drains.
    // 4. VERIFY + UNWRAP (issue #4077): verification proves the signature/binding;
    //    unwrap restores the ORIGINAL MCP shape the proxy reshaped before signing,
    //    so an inner ERROR surfaces as an error here, never as a success result.
    let verified_result = session
        .verify_and_unwrap_response(&response, &response_resolver(fixtures))
        .map_err(|e| E2eError::Verify(format!("{e:?}")))?;
    let (verified, unwrapped) = verified_result.into_parts();
    if verified.request_hash() != stored_hash {
        return Err(E2eError::Verify(
            "verified response did not bind to the stored request hash".to_string(),
        ));
    }
    if session.pending_count() != 0 {
        return Err(E2eError::Verify(
            "pending count did not return to 0 after a verified response".to_string(),
        ));
    }

    // The fileserver returns an OBJECT result signed in place, so the unwrapped
    // payload is that object with the signature `_meta` stripped.
    let result_payload = match unwrapped {
        UnwrappedResult::Object(value) | UnwrappedResult::Scalar(value) => value,
        UnwrappedResult::InnerError(inner) => {
            return Err(E2eError::InnerError(inner.to_string()));
        }
    };

    // 5. The returned fixture entry names — proof the inner fileserver executed.
    let entries = result_payload["structuredContent"]["entries"]
        .as_array()
        .ok_or_else(|| E2eError::BadResponse("response has no entries array".to_string()))?
        .iter()
        .filter_map(|e| e["name"].as_str().map(str::to_string))
        .collect::<Vec<String>>();
    if entries.is_empty() {
        return Err(E2eError::BadResponse(
            "inner returned an empty listing; expected the reports/ fixture entries".to_string(),
        ));
    }

    Ok(E2eOutcome {
        signer: fixtures.signer().to_string(),
        audience: fixtures.audience().to_string(),
        request_hash: stored_hash,
        authorization_hash,
        server_signer: verified.server_signer().to_string(),
        entries,
    })
}
