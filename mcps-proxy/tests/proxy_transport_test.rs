//! MCPS-026 — transport binding wired into the proxy serving path
//! (ADR-MCPS-014).
//!
//! After Core verification (and any authorization policy), the verified `signer`
//! is bound to the connection's verified transport identity. A mismatch — or a
//! required-but-absent identity — fails closed with `mcps.transport_binding_failed`
//! and the inner server is never reached. Without a binding policy the transport
//! identity is ignored (a pre-Phase-6 sidecar).

use std::cell::RefCell;
use std::rc::Rc;

use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use mcps_proxy::ExactMatchBinding;
use mcps_proxy::IdentitySource;
use mcps_proxy::Proxy;
use mcps_proxy::TransportIdentity;
use serde_json::json;
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

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}
fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}

type Calls = Rc<RefCell<Vec<Value>>>;

fn proxy(bind: bool) -> (Proxy, Calls) {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let calls_for_inner = Rc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.borrow_mut().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })).unwrap()
    };
    let mut p = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    );
    if bind {
        p = p.with_transport_binding(Box::new(ExactMatchBinding::new()));
    }
    (p, calls)
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

fn identity(value: &str) -> TransportIdentity {
    TransportIdentity::new(value, IdentitySource::UriSan)
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"].as_str().expect("message").to_string()
}

#[test]
fn signer_bound_to_matching_identity_is_allowed() {
    let (proxy, calls) = proxy(true);
    let req = signed_request("nonce-bind-ok-1");
    let id = identity(SIGNER);
    let response = proxy.handle_with_transport(&req, now(), Some(&id), None);
    assert_eq!(calls.borrow().len(), 1, "bound request reaches the inner");
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert!(value.get("error").is_none(), "no error for a bound request");
}

#[test]
fn mismatched_identity_is_denied_before_dispatch() {
    let (proxy, calls) = proxy(true);
    let req = signed_request("nonce-bind-mm-1");
    let id = identity("did:example:someone-else");
    let response = proxy.handle_with_transport(&req, now(), Some(&id), None);
    assert_eq!(calls.borrow().len(), 0, "mismatch must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn absent_identity_is_denied_when_binding_required() {
    let (proxy, calls) = proxy(true);
    let req = signed_request("nonce-bind-none1");
    let response = proxy.handle_with_transport(&req, now(), None, None);
    assert_eq!(calls.borrow().len(), 0, "absent identity must not reach the inner");
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}

#[test]
fn without_binding_the_transport_identity_is_ignored() {
    let (proxy, calls) = proxy(false);
    let req = signed_request("nonce-bind-off1");
    // Even a clearly-wrong identity is ignored when no binding is configured.
    let id = identity("did:example:irrelevant");
    let response = proxy.handle_with_transport(&req, now(), Some(&id), None);
    assert_eq!(calls.borrow().len(), 1, "no binding → request is forwarded");
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert!(value.get("error").is_none());
}

#[test]
fn valid_identity_does_not_rescue_a_tampered_signature() {
    // CORE INVARIANT (no transport downgrade): a verified mTLS identity that
    // satisfies the binding must NOT let an object-signature failure through.
    // Object verification runs first and fails closed before the binding is even
    // consulted; the inner server is never reached.
    let (proxy, calls) = proxy(true);
    let req = signed_request("nonce-tamper-1");
    let mut value: Value = serde_json::from_slice(&req).expect("parse signed request");
    // Tamper a signed field — the signature no longer matches the object.
    value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize");

    // The transport identity MATCHES the signer (binding would pass on its own).
    let id = identity(SIGNER);
    let response = proxy.handle_with_transport(&tampered, now(), Some(&id), None);

    assert_eq!(calls.borrow().len(), 0, "a tampered request must never reach the inner");
    assert_eq!(error_message(&response), "mcps.invalid_signature");
}

#[test]
fn plain_handle_is_equivalent_to_no_identity() {
    // handle() must behave as handle_with_transport(.., None): with binding on,
    // that means fail closed (no identity).
    let (proxy, calls) = proxy(true);
    let req = signed_request("nonce-bind-plain");
    let response = proxy.handle(&req, now());
    assert_eq!(calls.borrow().len(), 0);
    assert_eq!(error_message(&response), "mcps.transport_binding_failed");
}
