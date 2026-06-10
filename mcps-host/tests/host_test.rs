//! MCPS-014 — host signs requests a verifier accepts and verifies bound
//! responses, without ever exposing the private key.

use mcps_core::request_hash;
use mcps_core::response_signing_preimage;
use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_host::verify_response;
use mcps_host::HostSigner;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

fn inbound_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    resolver
}

fn server_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    resolver
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn signed_echo_request() -> Vec<u8> {
    host()
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            NONCE,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs request")
}

/// Build a server-signed response bound to `request_hash` (server side; the
/// host only VERIFIES this — it never signs responses).
fn signed_response(bound_hash: &str) -> Vec<u8> {
    let mut response = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [ { "type": "text", "text": "hello" } ],
            "_meta": {
                RESPONSE_META_KEY: {
                    "request_hash": bound_hash,
                    "server_signer": SERVER,
                    "issued_at": ISSUED_AT,
                    "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID }
                }
            }
        }
    });
    let preimage = response_signing_preimage(&response).expect("response preimage");
    let signature = server_key().sign(&preimage);
    response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(signature);
    serde_json::to_vec(&response).expect("serialize response")
}

#[test]
fn host_signs_request_accepted_by_verifier() {
    let bytes = signed_echo_request();
    let now = mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60;

    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified = verify_request(&bytes, &inbound_resolver(), &mut replay, &config(), now)
        .expect("verifier accepts the host-signed request");

    assert_eq!(verified.verified_signer, SIGNER);
    assert_eq!(verified.on_behalf_of, ON_BEHALF_OF);
    assert_eq!(verified.audience, AUDIENCE);
    assert_eq!(verified.authorization_hash, AUTH_HASH);
}

#[test]
fn host_verifies_signed_response_and_binding() {
    let request = signed_echo_request();
    let request_value: Value = serde_json::from_slice(&request).expect("parse request");
    let expected_hash = request_hash(&request_value).expect("request_hash");

    // A response correctly bound to the request verifies.
    let good = signed_response(&expected_hash);
    let verified = verify_response(&good, &server_resolver(), &expected_hash)
        .expect("host verifies bound response");
    assert_eq!(verified.server_signer, SERVER);
    assert_eq!(verified.request_hash, expected_hash);
}

#[test]
fn host_rejects_response_bound_to_wrong_request() {
    let request = signed_echo_request();
    let request_value: Value = serde_json::from_slice(&request).expect("parse request");
    let expected_hash = request_hash(&request_value).expect("request_hash");

    // The response is signed but bound to a DIFFERENT hash than the host expects.
    let response = signed_response("sha256:some-other-request-hash");
    let result = verify_response(&response, &server_resolver(), &expected_hash);
    assert_eq!(result.err(), Some(McpsError::ResponseHashMismatch));
}

#[test]
fn host_overwrites_caller_supplied_request_envelope() {
    // A caller that tries to smuggle its own _meta envelope must not influence
    // the signed result: the host is the sole author of the *.request block.
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("echo".to_string()));
    params.insert("arguments".to_string(), json!({ "text": "hello" }));
    params.insert(
        "_meta".to_string(),
        json!({ "se.syncom/mcps.request": { "signer": "did:evil:impostor" } }),
    );

    let bytes = host()
        .sign_request(
            &Value::String("req-1".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            NONCE,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs");

    let now = mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60;
    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified = verify_request(&bytes, &inbound_resolver(), &mut replay, &config(), now)
        .expect("host-authored envelope verifies");
    assert_eq!(
        verified.verified_signer, SIGNER,
        "the host's signer must win over the smuggled impostor"
    );
}
