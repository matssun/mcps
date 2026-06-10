//! MCPS-046 (MCPS-EPIC-P6.5, Child Issue 2) — demo `HostSession` client.
//!
//! These tests pin the demo client's behaviour DETERMINISTICALLY under a fixed
//! clock + seeded RNG. The client is a thin demo harness over the UNCHANGED
//! [`HostSession`]: it signs requests (nonce from injected RNG, freshness from
//! injected clock + configured lifetime), tracks the `request_hash` by JSON-RPC
//! id, and verifies a signed server response against the STORED hash — never a
//! caller-supplied expected hash. The model never holds keys: there is no
//! private-key accessor on the client.

use mcps_core::request_hash;
use mcps_core::response_signing_preimage;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_demo::DemoHostClient;
use mcps_host::FixedClock;
use mcps_host::HostSigner;
use mcps_host::SeededNonceSource;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

// Fixed clock: 2026-05-28T20:00:00Z (see mcps-core time tests).
const NOW_UNIX: i64 = 1_779_998_400;
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
// Default lifetime is the conservative 5-minute window (300s) -> 20:05:00Z.
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

fn host_signer() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// A demo client at the fixed clock with a seeded (deterministic) nonce source
/// and the default request lifetime.
fn client() -> DemoHostClient<FixedClock, SeededNonceSource> {
    DemoHostClient::with_defaults(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
}

fn server_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    resolver
}

/// Build a server-signed response bound to `request_hash` (server side; the demo
/// client only VERIFIES this).
fn signed_response(id: &Value, bound_hash: &str) -> Vec<u8> {
    let mut response = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
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

// ---------------------------------------------------------------------------

#[test]
fn client_creates_a_signed_request_with_injected_clock_and_rng() {
    let mut client = client();
    let id = Value::String("req-1".to_string());
    let bytes = client
        .sign_tool_call(&id, "list_files", json!({ "path": "." }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("client signs");

    let value: Value = serde_json::from_slice(&bytes).expect("parse signed request");
    let envelope = &value["params"]["_meta"]["se.syncom/mcps.request"];

    // Freshness stamped from the injected clock + default 5-minute lifetime.
    assert_eq!(envelope["issued_at"], json!(ISSUED_AT));
    assert_eq!(envelope["expires_at"], json!(EXPIRES_AT));

    // Nonce drawn from the injected (seeded) RNG, Base64URL-safe (no +, /, =).
    let nonce = envelope["nonce"].as_str().expect("nonce string");
    assert_eq!(nonce, mcps_core::b64url_encode(&[0xABu8; 16]));
    assert!(!nonce.contains('+') && !nonce.contains('/') && !nonce.contains('='));

    // The hash was stored under this id for later response correlation.
    assert_eq!(client.pending_count(), 1);
    assert!(client.stored_request_hash(&id).is_some());
}

#[test]
fn client_verifies_a_response_bound_to_the_stored_hash() {
    let mut client = client();
    let id = Value::String("req-1".to_string());
    let request = client
        .sign_tool_call(&id, "list_files", json!({ "path": "." }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("client signs");
    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let expected_hash = request_hash(&request_value).expect("request_hash");

    // The client takes NO caller expected hash — it binds to the one it stored.
    let good = signed_response(&id, &expected_hash);
    let verified = client
        .verify_response(&good, &server_resolver())
        .expect("client verifies the bound response against the stored hash");
    assert_eq!(verified.server_signer, SERVER);
    assert_eq!(verified.request_hash, expected_hash);
    // Success-path eviction: the id is free again.
    assert_eq!(client.pending_count(), 0);
}

#[test]
fn client_fails_closed_on_a_wrong_response_hash() {
    let mut client = client();
    let id = Value::String("req-1".to_string());
    client
        .sign_tool_call(&id, "list_files", json!({ "path": "." }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("client signs");

    // Server-signed but bound to a DIFFERENT request hash than the stored one.
    let response = signed_response(&id, "sha256:some-other-request-hash");
    let result = client.verify_response(&response, &server_resolver());
    assert_eq!(result.err(), Some(McpsError::ResponseHashMismatch));
    // A failed verification does NOT evict the pending entry.
    assert_eq!(client.pending_count(), 1);
}

#[test]
fn client_rejects_an_unknown_response_id() {
    // No request was signed for this id, so there is no stored hash to bind
    // against. The client refuses to verify rather than trust the response.
    let mut client = client();
    let id = Value::String("never-sent".to_string());
    let response = signed_response(&id, "sha256:whatever");
    let result = client.verify_response(&response, &server_resolver());
    assert_eq!(result.err(), Some(McpsError::MissingEnvelope));
}

#[test]
fn client_rejects_a_duplicate_pending_request_id() {
    // A second sign reusing the SAME in-flight id is a replay of that id; the
    // client refuses rather than clobber the first request's stored hash.
    let mut client = client();
    let id = Value::String("req-1".to_string());
    client
        .sign_tool_call(&id, "list_files", json!({ "path": "." }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("first sign succeeds");
    let stored = client.stored_request_hash(&id).expect("stored").to_string();

    let result = client.sign_tool_call(
        &id,
        "list_files",
        json!({ "path": "sub" }),
        ON_BEHALF_OF,
        AUDIENCE,
        AUTH_HASH,
    );
    assert_eq!(result.err(), Some(McpsError::ReplayDetected));
    // The duplicate did not replace the stored hash for the in-flight id.
    assert_eq!(client.stored_request_hash(&id), Some(stored.as_str()));
}

#[test]
fn client_exposes_the_signer_identity_but_no_private_key() {
    // The identity is public; the key is not. This compiles only because the
    // client (like HostSession/HostSigner) has NO private-key accessor — the
    // demo proves the model can drive signing without ever holding the key.
    let client = client();
    assert_eq!(client.signer(), SIGNER);
}
