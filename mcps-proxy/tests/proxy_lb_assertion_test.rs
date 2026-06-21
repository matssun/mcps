//! Issue #71 (ADR-MCPS-023 Tier 3) — LB-signed, request-bound ingress assertion
//! wired into the proxy serving path.
//!
//! These are SERVE-LEVEL acceptance tests: they drive the SAME
//! `Proxy::handle_with_transport` entry point the production serve loop calls
//! (`main.rs` -> `tls::serve_once_with_assertion`), proving the Tier-3 assertion is
//! ENFORCED end-to-end — not merely that the unit verifier in `transport.rs` works.
//!
//! The proxy is built with `with_lb_assertion(..)` + the SAME `ExactMatchBinding`
//! the direct-TLS path uses, mirroring `main.rs`'s `BindingKind::LbAssertion` wiring.
//! An inner server records whether it was reached, so "rejected before dispatch" is
//! an observable, black-box fact (the inner is never called on a rejection).
//!
//! Coverage:
//!   * a valid assertion bound to THIS request's hash → inner reached, response
//!     returned (and the signed response verifies against the request hash);
//!   * a cross-request assertion (bound to a different request) → rejected;
//!   * a tampered assertion (mutated wire field) → rejected;
//!   * an unknown-LB-key assertion → rejected;
//!   * a stale assertion (outside the freshness window) → rejected;
//!   * a MISSING assertion header under LB mode → rejected;
//!   * the object-sig-before-binding invariant: a tampered object signature fails
//!     regardless of a perfectly valid assertion (object verify runs first).
//! Every rejection asserts the inner was NEVER reached.

use std::cell::RefCell;
use std::rc::Rc;

use mcps_core::b64url_encode;
use mcps_core::request_hash;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use mcps_proxy::ExactMatchBinding;
use mcps_proxy::IdentitySource;
use mcps_proxy::LbAssertion;
use mcps_proxy::LbAssertionBinding;
use mcps_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "spiffe://example.org/agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;
const LB_KEY_ID: &str = "lb-1";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn lb_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[7u8; 32])
}
fn now() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}
fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

type Calls = Rc<RefCell<Vec<Value>>>;

/// A proxy wired EXACTLY as `main.rs` wires `BindingKind::LbAssertion`: the SAME
/// ExactMatchBinding plus the Tier-3 verifier trusting `lb_key` under `LB_KEY_ID`.
fn lb_proxy() -> (Proxy, Calls) {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let calls_for_inner = Rc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.borrow_mut().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } })).unwrap()
    };
    let mut binding = LbAssertionBinding::new(IdentitySource::UriSan);
    binding.add_key(LB_KEY_ID, lb_key().public_key());
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_transport_binding(Box::new(ExactMatchBinding::new()))
    .with_lb_assertion(binding);
    (proxy, calls)
}

fn signed_request(nonce: &str) -> Vec<u8> {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

/// The `request_hash` the proxy will bind against — derived from the SAME canonical
/// request the proxy verifies (signature.value is excluded from the hash preimage,
/// so signing does not perturb it). Mirrors `proxy.rs`'s `expected_request_hash`.
fn request_hash_of(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse signed request");
    request_hash(&value).expect("request_hash")
}

/// Mint a Tier-3 assertion the SAME way an LB would (and the SAME way the
/// `transport.rs` unit tests do): length-prefixed canonical preimage signed by the
/// LB key, then the five-field base64url wire form.
fn mint_assertion(
    lb: &SigningKey,
    key_id: &str,
    identity: &str,
    bound_request_hash: &str,
    validation_time: i64,
) -> String {
    let assertion = LbAssertion {
        key_id: key_id.to_string(),
        asserted_client_identity: identity.to_string(),
        request_hash: bound_request_hash.to_string(),
        validation_time,
    };
    let signature = lb.sign(&assertion.signing_preimage());
    format!(
        "{}.{}.{}.{}.{}",
        b64url_encode(key_id.as_bytes()),
        b64url_encode(identity.as_bytes()),
        b64url_encode(bound_request_hash.as_bytes()),
        b64url_encode(&validation_time.to_be_bytes()),
        signature,
    )
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"]
        .as_str()
        .expect("message")
        .to_string()
}

// ---- happy path: a valid, request-bound assertion reaches the inner ----

#[test]
fn valid_request_bound_assertion_reaches_inner_and_response_verifies() {
    let (proxy, calls) = lb_proxy();
    let nonce = "nonce-lb-ok-1";
    let req = signed_request(nonce);
    let rh = request_hash_of(&req);
    // The asserted client identity equals the request signer so ExactMatchBinding
    // admits it (the assertion SUPPLIES the verified identity the policy checks).
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.borrow().len(), 1, "a valid request-bound assertion must reach the inner");
    // The returned envelope is a real signed, request-bound response.
    verify_response(&response, &server_resolver(), &rh)
        .expect("the response must be a signed, request-bound envelope");
}

// ---- rejections: each must be BEFORE dispatch (inner never reached) ----

#[test]
fn cross_request_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-cross-1");
    // The assertion is validly signed but bound to a DIFFERENT request's hash.
    let other_hash = request_hash_of(&signed_request("nonce-lb-cross-OTHER"));
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &other_hash, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.borrow().len(), 0, "a cross-request assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn tampered_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-tamper-1");
    let rh = request_hash_of(&req);
    let valid = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());
    // Flip the last character of the wire form (the signature field) — the Ed25519
    // signature no longer verifies under the LB key.
    let mut tampered = valid.clone();
    let last = tampered.pop().expect("non-empty assertion");
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    let response = proxy.handle_with_transport(&req, now(), None, Some(&tampered));

    assert_eq!(calls.borrow().len(), 0, "a tampered assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn unknown_lb_key_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-unknown-1");
    let rh = request_hash_of(&req);
    // Signed by an UNTRUSTED LB key id the proxy does not know.
    let rogue = SigningKey::from_seed_bytes(&[9u8; 32]);
    let assertion = mint_assertion(&rogue, "lb-rogue", SIGNER, &rh, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.borrow().len(), 0, "an unknown-key assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn stale_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-stale-1");
    let rh = request_hash_of(&req);
    // validation_time far in the past relative to `now()` (default window 30s).
    let stale_time = now() - (mcps_proxy::DEFAULT_LB_ASSERTION_MAX_AGE_SECS + 60);
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, stale_time);

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.borrow().len(), 0, "a stale assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn missing_assertion_header_under_lb_mode_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-missing-1");
    // No assertion header presented while the LB verifier is configured.
    let response = proxy.handle_with_transport(&req, now(), None, None);

    assert_eq!(calls.borrow().len(), 0, "a missing assertion header must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

// ---- core invariant: object signature is verified BEFORE the assertion binding ----

#[test]
fn tampered_object_signature_fails_regardless_of_a_valid_assertion() {
    // No transport downgrade: object verification runs first and fails closed, so a
    // perfectly valid request-bound assertion can NEVER rescue a tampered object
    // signature. The inner is never reached and the failure is the SIGNATURE error,
    // not the transport-binding one — proving the ordering.
    let (proxy, calls) = lb_proxy();
    let nonce = "nonce-lb-objtamper-1";
    let req = signed_request(nonce);
    // The assertion is bound to the ORIGINAL request's hash and is fully valid.
    let rh = request_hash_of(&req);
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());

    // Tamper a signed field AFTER minting the assertion; the object signature no
    // longer matches (and the hash now differs too, but object verify fails first).
    let mut value: Value = serde_json::from_slice(&req).expect("parse signed request");
    value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize");

    let response = proxy.handle_with_transport(&tampered, now(), None, Some(&assertion));

    assert_eq!(calls.borrow().len(), 0, "a tampered object must never reach the inner");
    assert_eq!(
        error_message(&response),
        "mcps.invalid_signature",
        "object-signature verification must fail BEFORE the assertion binding is consulted"
    );
}
