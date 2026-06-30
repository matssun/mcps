//! MCPS-51 (#198) — end-to-end four-hop integration topology + the ADR-MCPS-044
//! §10 conformance suite over the REAL wiring.
//!
//! Topology (all in-process, but each hop is the real component):
//!
//!   ordinary MCP client  →  local MCP-S proxy (mcps-client-proxy)
//!                        →  remote MCP-S server (verify draft-02 request, sign
//!                           draft-02 response)  →  ordinary MCP server (echo)
//!
//! The ordinary client speaks PLAIN MCP and the ordinary server is MCP-S-unaware;
//! all signing/verification lives in the proxy (client leg) and the remote
//! (server leg). [`RemoteMcpsServer`] is the [`RemoteTransport`] that performs the
//! remote-side hops 3-4: verify the signed request with `mcps-core`, run the
//! ordinary echo server, and sign the bound draft-02 response.
//!
//! §10 cases proven here: signed round-trip, unsigned-rejected, unexpected-signer,
//! request_hash mismatch, legacy-under-policy, no-silent-downgrade, deadline
//! cleanup, nonce reuse, and authz-system-reference with/without a resolver.

use mcps_client_core::AudienceTuple;
use mcps_client_core::AuthorizationBindingPolicy;
use mcps_client_core::AuthorizationBindingProvider;
use mcps_client_core::AuthorizationReferenceResolver;
use mcps_client_core::AuthzReference;
use mcps_client_core::AuthzSystemReferenceProvider;
use mcps_client_core::BindingRequestContext;
use mcps_client_core::BindingTypeTag;
use mcps_client_core::ClientPath;
use mcps_client_core::EnforcementMode;
use mcps_client_core::Environment;
use mcps_client_core::OpaqueBytesProvider;
use mcps_client_core::SignerAudienceBinding;
use mcps_client_core::SignerPolicy;
use mcps_client_core::SoftwareSigner;
use mcps_client_proxy::CallParams;
use mcps_client_proxy::ClientProxy;
use mcps_client_proxy::ProxyError;
use mcps_client_proxy::RemoteTransport;
use mcps_client_proxy::Route;
use mcps_client_proxy::RouteRegistry;
use mcps_client_proxy::TransportError;
use mcps_core::parse_rfc3339_utc;
use mcps_core::response_signing_preimage;
use mcps_core::verify_request_draft02;

use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::{
    CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const OTHER_SEED: [u8; 32] = [7u8; 32];
const CLIENT_SIGNER: &str = "did:example:client";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUED_AT: &str = "2026-06-30T20:00:00Z";
const EXPIRES_AT: &str = "2026-06-30T20:05:00Z";

fn audience() -> AudienceTuple {
    AudienceTuple::new("https", "remote.example", 443, "acme", "tools", "prod").unwrap()
}

/// How the remote behaves on the server leg — the lever for the §10 negative cases.
#[derive(Clone, Copy)]
enum RemoteBehavior {
    /// Honest: verify, run ordinary server, sign a correct bound response.
    Honest,
    /// Sign with a server identity the client does not expect.
    WrongSigner,
    /// Bind a different request_hash than the verified one.
    WrongHash,
    /// Emit a downgrade-shaped response (tampered protected version).
    TamperedVersion,
    /// Behave as a plain, MCP-S-unaware server (no envelope).
    LegacyPlain,
}

/// The remote MCP-S server (hops 3-4): verifies the signed request, runs the
/// ordinary echo server, and signs the bound draft-02 response.
struct RemoteMcpsServer {
    behavior: RemoteBehavior,
}

impl RemoteMcpsServer {
    /// The ordinary, MCP-S-unaware server: echo the call's arguments back.
    fn ordinary_server(request: &Value) -> Value {
        let args = request["params"]["arguments"].clone();
        json!({ "content": [{ "type": "echo", "args": args }] })
    }
}

impl RemoteTransport for RemoteMcpsServer {
    fn round_trip(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Legacy server: does not understand MCP-S; returns a plain response.
        if let RemoteBehavior::LegacyPlain = self.behavior {
            let req: Value = serde_json::from_slice(request_bytes).unwrap();
            return Ok(serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": req["id"].clone(),
                "result": RemoteMcpsServer::ordinary_server(&req)
            }))
            .unwrap());
        }

        // Hop 3: verify the signed request (the server leg's MCP-S verifier).
        let client_key = SigningKey::from_seed_bytes(&CLIENT_SEED);
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert(CLIENT_SIGNER, CLIENT_KEY_ID, client_key.public_key());
        let mut replay = InMemoryReplayCache::new(60);
        let config = VerificationConfig {
            expected_audience: audience().to_audience_string(),
            max_clock_skew_secs: 60,
        };
        let now = parse_rfc3339_utc(ISSUED_AT).unwrap();
        let verified = verify_request_draft02(request_bytes, &resolver, &mut replay, &config, now)
            .map_err(|e| TransportError::new(format!("remote verify failed: {e}")))?;

        // Hop 3.5: run the ordinary MCP server on the verified request.
        let req: Value = serde_json::from_slice(request_bytes).unwrap();
        let result = RemoteMcpsServer::ordinary_server(&req);

        // Hop 4: sign the bound draft-02 response (with the negative-case levers).
        let (seed, signer, key_id) = match self.behavior {
            RemoteBehavior::WrongSigner => (OTHER_SEED, "did:example:imposter", "imposter-key"),
            _ => (SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID),
        };
        let request_hash = match self.behavior {
            RemoteBehavior::WrongHash => {
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
            }
            _ => verified.request_hash.clone(),
        };
        let version = match self.behavior {
            RemoteBehavior::TamperedVersion => "draft-99",
            _ => VERSION_DRAFT_02,
        };

        let key = SigningKey::from_seed_bytes(&seed);
        let mut object = json!({
            "jsonrpc": "2.0", "id": req["id"].clone(),
            "result": { "content": result["content"].clone(), "_meta": { RESPONSE_META_KEY: {
                "version": version,
                "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                "request_hash": request_hash,
                "server_signer": signer,
                "issued_at": "2026-06-30T20:00:01Z",
                "signature": { "alg": SIG_ALG_ED25519, "key_id": key_id },
            }}}
        });
        let preimage = response_signing_preimage(&object).unwrap();
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(key.sign(&preimage));
        Ok(serde_json::to_vec(&object).unwrap())
    }
}

/// A reference resolver for the authz-system-reference §10 case.
struct FixedReferenceResolver;
impl AuthorizationReferenceResolver for FixedReferenceResolver {
    fn resolve(&self, _ctx: &BindingRequestContext) -> Result<AuthzReference, McpsError> {
        Ok(AuthzReference {
            authorization_system_id: "sys-1".to_string(),
            reference_scheme_id: "scheme-1".to_string(),
            reference_value: "grant-42".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        })
    }
}

fn route_with(
    mode: EnforcementMode,
    legacy_allowed: bool,
    authz_provider: Box<dyn AuthorizationBindingProvider>,
    authz_policy: AuthorizationBindingPolicy,
) -> Route {
    Route {
        route_id: "tools".to_string(),
        enforcement_mode: mode,
        legacy_allowed,
        signer_audience: SignerAudienceBinding {
            expected_server_signer: SERVER_SIGNER.to_string(),
            audience: audience(),
        },
        authz_policy,
        authz_provider,
    }
}

fn default_route(mode: EnforcementMode, legacy_allowed: bool) -> Route {
    route_with(
        mode,
        legacy_allowed,
        Box::new(OpaqueBytesProvider::new(b"grant".to_vec())),
        AuthorizationBindingPolicy::both_base_forms(),
    )
}

fn proxy(route: Route, behavior: RemoteBehavior) -> ClientProxy {
    let signer = SoftwareSigner::new(
        SigningKey::from_seed_bytes(&CLIENT_SEED),
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
    );
    let mut trust = InMemoryTrustResolver::new();
    trust.insert(
        SERVER_SIGNER,
        SERVER_KEY_ID,
        SigningKey::from_seed_bytes(&SERVER_SEED).public_key(),
    );
    ClientProxy::new(
        RouteRegistry::new().register(route),
        Box::new(signer),
        SignerPolicy::new(CLIENT_SIGNER, Environment::Production, true),
        Box::new(trust),
        Box::new(RemoteMcpsServer { behavior }),
    )
}

fn plain_request() -> Value {
    json!({
        "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
        "params": { "name": "echo", "arguments": { "text": "ping" } }
    })
}

fn params() -> CallParams {
    CallParams {
        on_behalf_of: "user:alice".to_string(),
        nonce: "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA".to_string(),
        issued_at: ISSUED_AT.to_string(),
        expires_at: EXPIRES_AT.to_string(),
        now_unix: parse_rfc3339_utc(ISSUED_AT).unwrap(),
        deadline_unix: parse_rfc3339_utc(EXPIRES_AT).unwrap(),
    }
}

// §10.1 — signed round-trip across all four hops, plain MCP in and out.
#[test]
fn s10_signed_round_trip() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::Honest,
    );
    let out = p
        .handle("tools", &plain_request(), &params())
        .expect("round trip");
    assert_eq!(out.path, ClientPath::McpsVerified);
    assert_eq!(
        out.plain_response["result"]["content"][0]["args"]["text"],
        "ping"
    );
    // Transparency: the response handed to the ordinary client carries no envelope.
    assert!(out.plain_response["result"]["_meta"].is_null());
}

// §10.2 — unsigned remote response rejected under require_mcps (no silent downgrade).
#[test]
fn s10_unsigned_rejected() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::LegacyPlain,
    );
    let err = p.handle("tools", &plain_request(), &params()).unwrap_err();
    assert_eq!(err, ProxyError::FailedClosed(McpsError::MissingEnvelope));
}

// §10.3 — unexpected server_signer rejected.
#[test]
fn s10_unexpected_signer_rejected() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::WrongSigner,
    );
    let err = p.handle("tools", &plain_request(), &params()).unwrap_err();
    // The imposter signer does not resolve against the client's trust anchor.
    assert!(matches!(
        err,
        ProxyError::FailedClosed(McpsError::ActorBindingFailed)
    ));
}

// §10.4 — request_hash mismatch rejected.
#[test]
fn s10_request_hash_mismatch_rejected() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::WrongHash,
    );
    let err = p.handle("tools", &plain_request(), &params()).unwrap_err();
    assert!(matches!(
        err,
        ProxyError::FailedClosed(McpsError::ResponseHashMismatch)
    ));
}

// §10.5 — legacy under explicit policy succeeds and is marked legacy.
#[test]
fn s10_legacy_under_policy() {
    let mut p = proxy(
        default_route(EnforcementMode::AllowLegacyExplicit, true),
        RemoteBehavior::LegacyPlain,
    );
    let out = p
        .handle("tools", &plain_request(), &params())
        .expect("legacy ok");
    assert_eq!(out.path, ClientPath::LegacyExplicit);
}

// §10.6 — no silent downgrade: a downgrade-shaped (tampered version) response fails
// closed in EVERY mode, even where legacy is allowed.
#[test]
fn s10_no_silent_downgrade() {
    for (mode, legacy) in [
        (EnforcementMode::RequireMcps, false),
        (EnforcementMode::AllowLegacyExplicit, true),
    ] {
        let mut p = proxy(default_route(mode, legacy), RemoteBehavior::TamperedVersion);
        let err = p.handle("tools", &plain_request(), &params()).unwrap_err();
        assert!(
            matches!(err, ProxyError::FailedClosed(_)),
            "tampered version must fail closed under {mode:?}, got {err:?}"
        );
    }
}

// §10.7 — deadline cleanup: a stale clock (now past the request deadline) makes the
// response uncorrelatable/expired and fails closed.
#[test]
fn s10_deadline_cleanup_fails_closed() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::Honest,
    );
    let mut stale = params();
    // now is AFTER the deadline -> the correlation entry is expired on take.
    stale.now_unix = parse_rfc3339_utc(EXPIRES_AT).unwrap() + 10;
    let err = p.handle("tools", &plain_request(), &stale).unwrap_err();
    assert!(
        matches!(err, ProxyError::FailedClosed(_)),
        "expired correlation must fail closed"
    );
}

// §10.8 — nonce reuse within the window is rejected (second call, same nonce).
#[test]
fn s10_nonce_reuse_rejected() {
    let mut p = proxy(
        default_route(EnforcementMode::RequireMcps, false),
        RemoteBehavior::Honest,
    );
    // First call succeeds.
    let mut first = params();
    first.now_unix = parse_rfc3339_utc(ISSUED_AT).unwrap();
    p.handle("tools", &plain_request(), &first)
        .expect("first ok");
    // Second call reuses the SAME nonce within the window (different id).
    let mut req2 = plain_request();
    req2["id"] = json!("req-2");
    let err = p.handle("tools", &req2, &first).unwrap_err();
    assert_eq!(err, ProxyError::FailedClosed(McpsError::ReplayDetected));
}

// §10.9 — authz-system-reference: with a resolver it round-trips; without one it
// fails closed at the binding hook BEFORE anything is forwarded.
#[test]
fn s10_authz_system_reference_with_and_without_resolver() {
    // With a resolver: the reference binding is produced and the call succeeds.
    let with = route_with(
        EnforcementMode::RequireMcps,
        false,
        Box::new(AuthzSystemReferenceProvider::with_resolver(Box::new(
            FixedReferenceResolver,
        ))),
        AuthorizationBindingPolicy::new([BindingTypeTag::AuthzSystemReference]),
    );
    let mut p = proxy(with, RemoteBehavior::Honest);
    assert!(p.handle("tools", &plain_request(), &params()).is_ok());

    // Without a resolver: fails closed at the authz hook (nothing forwarded).
    let without = route_with(
        EnforcementMode::RequireMcps,
        false,
        Box::new(AuthzSystemReferenceProvider::without_resolver()),
        AuthorizationBindingPolicy::new([BindingTypeTag::AuthzSystemReference]),
    );
    let mut p2 = proxy(without, RemoteBehavior::Honest);
    let err = p2.handle("tools", &plain_request(), &params()).unwrap_err();
    assert_eq!(
        err,
        ProxyError::FailedClosed(McpsError::AuthorizationBindingMissing)
    );
}
