//! ADR-MCPS-039 (D1): the sidecar's expected-version posture is WIRED — the
//! `Proxy`'s `version_policy` field flows into `verify_request_dispatch`, so the
//! proxy admits or refuses an inbound wire profile per its configured policy.
//!
//! These tests pin the two behaviours that matter for the four-hop walkthrough:
//!
//!   1. the constructor DEFAULT ([`ExpectedVersionPolicy::Draft01AndDraft02`])
//!      admits a legacy draft-01 request end-to-end (the existing `mcps-host`
//!      fleet keeps working untouched);
//!   2. a proxy tightened to [`ExpectedVersionPolicy::Draft02Only`] refuses the
//!      SAME draft-01 request as a downgrade (`mcps.downgrade_forbidden`) BEFORE
//!      dispatch — the inner server is never reached.
//!
//! `mcps-host` signs draft-01, so it is the draft-01 producer here; the draft-02
//! admit path is exercised by the client-proxy four-hop tests (it signs draft-02).

use std::cell::RefCell;
use std::rc::Rc;

use mcps_core::ExpectedVersionPolicy;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use mcps_proxy::Proxy;
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

fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}

/// A captured record of every request the inner server received — the proof that
/// (or that NOT) dispatch was reached.
type Calls = Rc<RefCell<Vec<Value>>>;

/// Build a proxy wrapping a plain-MCP echo inner that records its calls. The
/// `tighten` flag selects the expected-version posture: `false` keeps the
/// constructor default (admit both), `true` applies `Draft02Only`.
fn proxy_with_recorder(draft02_only: bool) -> (Proxy, Calls) {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let calls_for_inner = Rc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses request");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let text = value["params"]["arguments"]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        calls_for_inner.borrow_mut().push(value);
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [ { "type": "text", "text": text } ] }
        });
        serde_json::to_vec(&response).expect("serialize inner response")
    };

    let mut proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    );
    if draft02_only {
        proxy = proxy.with_expected_version_policy(ExpectedVersionPolicy::Draft02Only);
    }
    (proxy, calls)
}

/// A draft-01 signed `tools/call` (mcps-host signs draft-01).
fn signed_draft01_echo(nonce: &str) -> Vec<u8> {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hi" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs draft-01")
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn default_policy_admits_draft01_end_to_end() {
    let (proxy, calls) = proxy_with_recorder(false);
    let response = proxy.handle(&signed_draft01_echo("nonce-d1-default"), now());

    let parsed: Value = serde_json::from_slice(&response).expect("parse response");
    assert!(parsed.get("error").is_none(), "expected success: {parsed}");
    assert_eq!(calls.borrow().len(), 1, "default policy must reach the inner");
}

#[test]
fn draft02_only_refuses_draft01_as_downgrade_before_dispatch() {
    let (proxy, calls) = proxy_with_recorder(true);
    let response = proxy.handle(&signed_draft01_echo("nonce-d1-strict"), now());

    assert_eq!(error_message(&response), "mcps.downgrade_forbidden");
    assert!(
        calls.borrow().is_empty(),
        "a downgrade-refused request must NOT reach the inner"
    );
}
