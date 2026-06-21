//! MCPS-011 — native MCP-S echo server round-trip tests (in-process).
//!
//! Drives [`EchoServer`] with known-valid and tampered/replayed requests and
//! asserts the signed responses verify and bind to the request (and that
//! failures surface the correct `mcps.*` wire codes).

use mcps_conformance::build_signed_request;
use mcps_conformance::EchoServer;
use mcps_core::parse_rfc3339_utc;
use mcps_core::request_hash;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;

/// `now` 60s after issued_at — comfortably inside the freshness window.
fn now_unix() -> i64 {
    parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

/// Resolver the SERVER uses to verify inbound requests (knows the signer key).
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}

/// Resolver the TEST uses to verify responses (knows the server key).
fn response_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

fn make_server() -> EchoServer {
    EchoServer::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
    )
}

fn signed_request(nonce: &str, text: &str, id: &str) -> Vec<u8> {
    build_signed_request(
        &signer_key(),
        SIGNER,
        SIGNER_KEY_ID,
        AUDIENCE,
        ON_BEHALF_OF,
        AUTH_HASH,
        nonce,
        ISSUED_AT,
        EXPIRES_AT,
        text,
        id,
    )
    .expect("build signed request")
}

/// The locally computed request_hash for a request's bytes.
fn req_hash(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse request");
    request_hash(&value).expect("request_hash")
}

fn error_message(bytes: &[u8]) -> String {
    let v: Value = serde_json::from_slice(bytes).expect("parse error object");
    v["error"]["message"]
        .as_str()
        .expect("error.message string")
        .to_string()
}

#[test]
fn valid_request_yields_signed_bound_response() {
    let server = make_server();
    let req = signed_request("nonce-roundtrip-0001", "hello", "req-1");
    let expected_hash = req_hash(&req);

    let resp = server.handle(&req, now_unix());

    // The response verifies under the server key and binds to the request hash.
    let verified = verify_response(&resp, &response_resolver(), &expected_hash)
        .expect("response should verify and bind");
    assert_eq!(verified.server_signer(), SERVER);
    assert_eq!(verified.request_hash(), expected_hash);

    // The echoed text round-trips.
    let v: Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(v["result"]["content"][0]["text"].as_str(), Some("hello"));
}

#[test]
fn tampered_request_is_rejected_invalid_signature() {
    let server = make_server();
    let req = signed_request("nonce-tamper-0001", "hello", "req-1");

    // Tamper with the tool argument WITHOUT re-signing.
    let mut v: Value = serde_json::from_slice(&req).unwrap();
    v["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
    let tampered = serde_json::to_vec(&v).unwrap();

    let resp = server.handle(&tampered, now_unix());
    assert_eq!(error_message(&resp), "mcps.invalid_signature");
}

#[test]
fn replayed_request_is_rejected_on_second_submission() {
    let server = make_server();
    let req = signed_request("nonce-replay-0001", "hello", "req-1");

    let first = server.handle(&req, now_unix());
    // First submission verifies and produces a signed response.
    assert!(verify_response(&first, &response_resolver(), &req_hash(&req)).is_ok());

    // Second submission of the same (signer, audience, nonce) is a replay.
    let second = server.handle(&req, now_unix());
    assert_eq!(error_message(&second), "mcps.replay_detected");
}

#[test]
fn response_bound_to_wrong_request_fails_hash_mismatch() {
    let server = make_server();

    // Request B is fully valid; the server returns a response bound to B.
    let req_b = signed_request("nonce-bindB-0001", "world", "req-b");
    let resp_b = server.handle(&req_b, now_unix());

    // Request A has a different hash.
    let req_a = signed_request("nonce-bindA-0001", "hello", "req-a");
    let hash_a = req_hash(&req_a);

    // Verifying B's response against A's request hash: signature is valid, but
    // the binding check fails (Vector-4B semantics at the server level).
    let result = verify_response(&resp_b, &response_resolver(), &hash_a);
    assert_eq!(result.err(), Some(McpsError::ResponseHashMismatch));
}
