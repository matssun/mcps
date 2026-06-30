//! MCPS-41 (#188) client round-trip vector: sign a request with the client core,
//! have a simulated server produce the bound signed response (via `mcps-core`'s
//! server-side helpers), then verify it back through the client core. Proves the
//! full client-side loop — request_hash flows out on the request and binds the
//! response on the way back — over the PUBLIC API only.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::verify_signed_response;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::ResponseExpectation;
use mcps_core::response_signing_preimage;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::{
    parse_rfc3339_utc, verify_request_draft02, CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY,
    SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const CLIENT_SIGNER: &str = "did:example:client";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server";

/// Simulate the server: verify the client request, then sign a draft-02 response
/// binding the verifier's recomputed request_hash + the same canonicalization_id.
fn server_handle(request_bytes: &[u8]) -> Vec<u8> {
    let client_key = SigningKey::from_seed_bytes(&CLIENT_SEED);
    let mut req_resolver = InMemoryTrustResolver::new();
    req_resolver.insert(CLIENT_SIGNER, CLIENT_KEY_ID, client_key.public_key());
    let mut replay = InMemoryReplayCache::new(60);
    let config = VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: 60,
    };
    let now = parse_rfc3339_utc("2026-06-30T20:00:00Z").unwrap();
    let verified =
        verify_request_draft02(request_bytes, &req_resolver, &mut replay, &config, now).unwrap();

    let server_key = SigningKey::from_seed_bytes(&SERVER_SEED);
    let mut object = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [{ "type": "text", "text": "pong" }],
            "_meta": {
                RESPONSE_META_KEY: {
                    "version": VERSION_DRAFT_02,
                    "canonicalization_id": verified.canonicalization_id.clone().unwrap(),
                    "request_hash": verified.request_hash,
                    "server_signer": SERVER_SIGNER,
                    "issued_at": "2026-06-30T20:00:01Z",
                    "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
                }
            }
        }
    });
    let preimage = response_signing_preimage(&object).unwrap();
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(server_key.sign(&preimage));
    serde_json::to_vec(&object).unwrap()
}

fn sign_request() -> mcps_client_core::SignedRequest {
    let key = SigningKey::from_seed_bytes(&CLIENT_SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
        "user:alice",
        AUDIENCE,
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    build_signed_tool_call(&json!("req-1"), "ping", json!({}), &inputs, &key).unwrap()
}

fn client_resolver() -> InMemoryTrustResolver {
    let server_key = SigningKey::from_seed_bytes(&SERVER_SEED);
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER_SIGNER, SERVER_KEY_ID, server_key.public_key());
    r
}

#[test]
fn full_client_round_trip_verifies_the_bound_response() {
    let signed = sign_request();
    let response = server_handle(signed.wire_bytes());

    let expectation = ResponseExpectation::new(signed.request_hash(), CANONICALIZATION_ID_INT53_V1)
        .with_expected_server_signer(SERVER_SIGNER);
    let verified = verify_signed_response(&response, &client_resolver(), &expectation)
        .expect("bound response must verify");
    assert_eq!(verified.server_signer(), SERVER_SIGNER);
    assert_eq!(verified.request_hash(), signed.request_hash());
}

#[test]
fn response_bound_to_a_different_request_fails_closed() {
    // The client sent request A but holds the expectation for a DIFFERENT request
    // hash — the genuine, validly-signed response for A must not satisfy it.
    let signed = sign_request();
    let response = server_handle(signed.wire_bytes());
    let wrong = ResponseExpectation::new(
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        CANONICALIZATION_ID_INT53_V1,
    );
    assert_eq!(
        verify_signed_response(&response, &client_resolver(), &wrong).unwrap_err(),
        McpsError::ResponseHashMismatch
    );
}
