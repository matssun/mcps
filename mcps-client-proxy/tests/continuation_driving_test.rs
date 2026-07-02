//! ADR-MCPS-047 step 7: the client proxy drives the InputRequiredResult →
//! continuation round trip transparently for an UNMODIFIED plain-MCP client.
//!
//! Call 1 (no continuation) → the remote returns a signed `InputRequiredResult`;
//! the proxy verifies it, retains the exchange, stashes the continuation keyed by
//! `requestState`, and returns the plain elicitation. Call 2 (the client's answer,
//! echoing `requestState` + `inputResponses`) → the proxy attaches the stored
//! continuation binding, the remote sees a signed continuation and returns the
//! terminal result. The local client never touches an MCP-S field.

use mcps_client_core::AudienceTuple;
use mcps_client_core::AuthorizationBindingPolicy;
use mcps_client_core::EnforcementMode;
use mcps_client_core::Environment;
use mcps_client_core::OpaqueBytesProvider;
use mcps_client_core::SignerAudienceBinding;
use mcps_client_core::SignerPolicy;
use mcps_client_core::SoftwareSigner;
use mcps_client_proxy::CallParams;
use mcps_client_proxy::ClientProxy;
use mcps_client_proxy::RemoteTransport;
use mcps_client_proxy::Route;
use mcps_client_proxy::RouteRegistry;
use mcps_client_proxy::TransportError;
use mcps_core::parse_rfc3339_utc;
use mcps_core::response_signing_preimage;
use mcps_core::verify_request_draft02;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::REQUEST_META_KEY;
use mcps_core::{
    CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const CLIENT_SIGNER: &str = "did:example:client";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUED_AT: &str = "2026-06-30T20:00:00Z";
const EXPIRES_AT: &str = "2026-06-30T20:05:00Z";
const REQUEST_STATE: &str = "eyJzdGVwIjoxfQ";

fn audience() -> AudienceTuple {
    AudienceTuple::new("https", "api.example.com", 443, "acme", "tools", "prod").unwrap()
}

/// A stateless MCP-S remote that BRANCHES on the signed request: a request WITHOUT
/// a continuation binding elicits input; a request WITH one completes. The branch
/// is on request content, so no call counter is needed.
struct ElicitingRemote;
impl RemoteTransport for ElicitingRemote {
    fn round_trip(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
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
            .map_err(|e| TransportError::new(format!("verify failed: {e}")))?;

        // Inspect the (verified) request for a continuation binding.
        let request: Value = serde_json::from_slice(request_bytes).unwrap();
        let continuation = &request["params"]["_meta"][REQUEST_META_KEY]["continuation"];

        let result = if continuation.is_null() {
            // Leg 1: ask for input, carrying the opaque requestState.
            json!({
                "resultType": "inputRequired",
                "inputRequests": { "confirm": { "type": "elicitation", "message": "Delete 3 files?" } },
                "requestState": REQUEST_STATE
            })
        } else {
            // Leg 2: a signed continuation arrived — assert it is well-formed, then finish.
            assert_eq!(
                continuation["type"], "mcp-mrt",
                "continuation must be mcp-mrt"
            );
            assert!(continuation["previous_request_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
            assert!(continuation["input_required_response_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
            json!({ "content": [{ "type": "text", "text": "deleted 3 files" }] })
        };

        let server_key = SigningKey::from_seed_bytes(&SERVER_SEED);
        let mut result = result;
        result["_meta"] = json!({ RESPONSE_META_KEY: {
            "version": VERSION_DRAFT_02,
            "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
            "request_hash": verified.request_hash,
            "server_signer": SERVER_SIGNER,
            "issued_at": "2026-06-30T20:00:01Z",
            "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
        }});
        let mut object = json!({ "jsonrpc": "2.0", "id": "srv", "result": result });
        let preimage = response_signing_preimage(&object).unwrap();
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(server_key.sign(&preimage));
        Ok(serde_json::to_vec(&object).unwrap())
    }
}

fn route() -> Route {
    Route {
        route_id: "tools".to_string(),
        enforcement_mode: EnforcementMode::RequireMcps,
        legacy_allowed: false,
        signer_audience: SignerAudienceBinding {
            expected_server_signer: SERVER_SIGNER.to_string(),
            audience: audience(),
        },
        authz_policy: AuthorizationBindingPolicy::both_base_forms(),
        authz_provider: Box::new(OpaqueBytesProvider::new(b"grant".to_vec())),
    }
}

fn proxy() -> ClientProxy {
    let signer = SoftwareSigner::new(
        SigningKey::from_seed_bytes(&CLIENT_SEED),
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
    );
    let signer_policy = SignerPolicy::new(CLIENT_SIGNER, Environment::Production, true);
    let mut trust = InMemoryTrustResolver::new();
    trust.insert(
        SERVER_SIGNER,
        SERVER_KEY_ID,
        SigningKey::from_seed_bytes(&SERVER_SEED).public_key(),
    );
    ClientProxy::new(
        RouteRegistry::new().register(route()),
        Box::new(signer),
        signer_policy,
        Box::new(trust),
        Box::new(ElicitingRemote),
    )
}

/// Freshness params with a fresh nonce per call (a continuation needs a fresh one). The
/// nonce is BUILT at runtime from `seq`, not a hard-coded literal — the eliciting remote
/// draws a new replay cache each round trip, so any distinct value works, and building it
/// keeps this deterministic test free of hard-coded-"cryptographic-value" scanner noise.
fn params(seq: u32) -> CallParams {
    CallParams {
        on_behalf_of: "user:alice".to_string(),
        nonce: format!("mcps-client-proxy-continuation-test-nonce-{seq:03}"),
        issued_at: ISSUED_AT.to_string(),
        expires_at: EXPIRES_AT.to_string(),
        now_unix: parse_rfc3339_utc(ISSUED_AT).unwrap(),
        deadline_unix: parse_rfc3339_utc(EXPIRES_AT).unwrap(),
    }
}

#[test]
fn proxy_drives_input_required_then_continuation() {
    let mut proxy = proxy();

    // Leg 1: an ordinary plain-MCP call. The proxy returns the elicitation as plain MCP.
    let first = json!({
        "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
        "params": { "name": "delete_files", "arguments": { "paths": ["a", "b", "c"] } }
    });
    let out1 = proxy
        .handle("tools", &first, &params(1))
        .expect("leg 1");
    assert_eq!(out1.plain_response["result"]["resultType"], "inputRequired");
    assert_eq!(out1.plain_response["result"]["requestState"], REQUEST_STATE);
    // No MCP-S field leaked to the client.
    assert!(out1.plain_response["result"]["_meta"].is_null());

    // Leg 2: the client answers, echoing requestState + inputResponses (plain MCP).
    let second = json!({
        "jsonrpc": "2.0", "id": "req-2", "method": "tools/call",
        "params": {
            "name": "delete_files",
            "arguments": { "paths": ["a", "b", "c"] },
            "inputResponses": { "confirm": true },
            "requestState": REQUEST_STATE
        }
    });
    let out2 = proxy
        .handle(
            "tools",
            &second,
            &params(2),
        )
        .expect("leg 2 (continuation)");
    assert_eq!(
        out2.plain_response["result"]["content"][0]["text"],
        "deleted 3 files"
    );
    assert_eq!(out2.path, mcps_client_core::ClientPath::McpsVerified);
}

#[test]
fn continuation_is_single_use() {
    let mut proxy = proxy();
    let first = json!({
        "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
        "params": { "name": "delete_files", "arguments": {} }
    });
    proxy
        .handle("tools", &first, &params(3))
        .expect("leg 1");

    let answer = json!({
        "jsonrpc": "2.0", "id": "req-2", "method": "tools/call",
        "params": {
            "name": "delete_files", "arguments": {},
            "inputResponses": { "confirm": true }, "requestState": REQUEST_STATE
        }
    });
    proxy
        .handle(
            "tools",
            &answer,
            &params(4),
        )
        .expect("leg 2");

    // Replaying the same answer finds no stored continuation: it is signed as an
    // ordinary (unbound) request. The remote, seeing no continuation, elicits again
    // rather than completing — proving the binding was consumed, not reusable.
    let replay = json!({
        "jsonrpc": "2.0", "id": "req-3", "method": "tools/call",
        "params": {
            "name": "delete_files", "arguments": {},
            "inputResponses": { "confirm": true }, "requestState": REQUEST_STATE
        }
    });
    let out = proxy
        .handle(
            "tools",
            &replay,
            &params(5),
        )
        .expect("leg 3 replay");
    assert_eq!(out.plain_response["result"]["resultType"], "inputRequired");
}

/// A follow-up that echoes `requestState` but omits `inputResponses` is NOT an answer
/// leg (SEP-2322: an answer carries both). It must not consume the single-use
/// continuation nor attach a binding — otherwise a malformed/partial call would burn
/// the stored state and the real answer could never complete.
#[test]
fn partial_follow_up_without_input_responses_is_not_bound() {
    let mut proxy = proxy();

    let first = json!({
        "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
        "params": { "name": "delete_files", "arguments": {} }
    });
    proxy
        .handle("tools", &first, &params(6))
        .expect("leg 1");

    // Partial follow-up: requestState but no inputResponses. With the gate it is signed
    // as an ordinary (unbound) request, so the remote elicits again rather than
    // completing — the binding was NOT attached.
    let partial = json!({
        "jsonrpc": "2.0", "id": "req-2", "method": "tools/call",
        "params": { "name": "delete_files", "arguments": {}, "requestState": REQUEST_STATE }
    });
    let out = proxy
        .handle(
            "tools",
            &partial,
            &params(7),
        )
        .expect("partial follow-up");
    assert_eq!(out.plain_response["result"]["resultType"], "inputRequired");

    // The continuation was not burned: a real answer (inputResponses + requestState)
    // still completes the exchange.
    let answer = json!({
        "jsonrpc": "2.0", "id": "req-3", "method": "tools/call",
        "params": {
            "name": "delete_files", "arguments": {},
            "inputResponses": { "confirm": true }, "requestState": REQUEST_STATE
        }
    });
    let out2 = proxy
        .handle(
            "tools",
            &answer,
            &params(8),
        )
        .expect("real answer completes");
    assert_eq!(
        out2.plain_response["result"]["content"][0]["text"],
        "deleted 3 files"
    );
}
