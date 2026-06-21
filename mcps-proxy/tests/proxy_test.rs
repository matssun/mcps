//! MCPS-015 + MCPS-016 — the sidecar verifies before dispatch, fails closed,
//! forwards only verified+stripped requests, injects a sole-writer verified
//! context, and signs the inner server's response.

use std::cell::RefCell;
use std::rc::Rc;

use mcps_core::request_hash;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::REQUEST_META_KEY;
use mcps_core::VERIFIED_META_KEY;
use mcps_host::FixedClock;
use mcps_host::HostSession;
use mcps_host::HostSigner;
use mcps_host::SeededNonceSource;
use mcps_host::UnwrappedResult;
use mcps_proxy::DelegatedResponseSigner;
use mcps_proxy::Proxy;
use mcps_proxy::ResponseSigner;
use serde_json::json;
use serde_json::Value;

// Fixed clock matching ISSUED_AT (2026-05-28T20:00:00Z) so a session-signed
// request lands inside its own freshness window when the proxy verifies at now().
const NOW_UNIX: i64 = 1_779_998_400;

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
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

/// A captured record of every request the inner server received.
type Calls = Rc<RefCell<Vec<Value>>>;

/// Build a proxy wrapping a plain-MCP echo inner that records its calls.
fn proxy_with_recorder() -> (Proxy, Calls) {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let calls_for_inner = Rc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses request");
        let text = value["params"]["arguments"]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.borrow_mut().push(value);
        // Plain MCP response — the inner server knows nothing about MCP-S.
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [ { "type": "text", "text": text } ] }
        });
        serde_json::to_vec(&response).expect("serialize inner response")
    };

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    );
    (proxy, calls)
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

fn signed_echo_request(nonce: &str, text: &str) -> Vec<u8> {
    host()
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": text }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse error object");
    value["error"]["message"]
        .as_str()
        .expect("error.message")
        .to_string()
}

#[test]
fn verified_request_is_forwarded_stripped_and_response_is_signed() {
    let (proxy, calls) = proxy_with_recorder();
    let request = signed_echo_request("nonce-proxy-0001", "hello");
    let expected_hash = request_hash(&serde_json::from_slice::<Value>(&request).unwrap())
        .expect("request_hash");

    let response = proxy.handle(&request, now());

    // The inner server was reached exactly once.
    assert_eq!(calls.borrow().len(), 1, "inner reached once");
    let forwarded = &calls.borrow()[0];

    // The external transport envelope was stripped; the tool call is intact.
    let meta = &forwarded["params"]["_meta"];
    assert!(
        meta.get(REQUEST_META_KEY).is_none(),
        "external *.request envelope must be removed"
    );
    assert_eq!(forwarded["params"]["name"].as_str(), Some("echo"));
    assert_eq!(
        forwarded["params"]["arguments"]["text"].as_str(),
        Some("hello")
    );

    // A fresh verified-context block was injected by the proxy (the verifier).
    let verified_ctx = &meta[VERIFIED_META_KEY];
    assert_eq!(verified_ctx["verified_signer"].as_str(), Some(SIGNER));
    assert_eq!(verified_ctx["on_behalf_of"].as_str(), Some(ON_BEHALF_OF));
    assert_eq!(verified_ctx["verifier"].as_str(), Some(SERVER));
    assert_eq!(
        verified_ctx["request_hash"].as_str(),
        Some(expected_hash.as_str())
    );

    // The response is signed by the server key and binds to the request.
    let verified = verify_response(&response, &server_resolver(), &expected_hash)
        .expect("proxy response verifies and binds");
    assert_eq!(verified.server_signer(), SERVER);
}

#[test]
fn unsigned_request_is_blocked_and_never_forwarded() {
    let (proxy, calls) = proxy_with_recorder();
    // A plain MCP request with NO MCP-S envelope.
    let plain = serde_json::to_vec(&json!({
        "id": "req-1",
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": { "name": "echo", "arguments": { "text": "hello" } }
    }))
    .unwrap();

    let response = proxy.handle(&plain, now());

    assert_eq!(calls.borrow().len(), 0, "inner must NOT be reached");
    assert_eq!(error_message(&response), "mcps.missing_envelope");
}

#[test]
fn tampered_request_is_blocked_and_never_forwarded() {
    let (proxy, calls) = proxy_with_recorder();
    let request = signed_echo_request("nonce-proxy-tamper", "hello");
    let mut value: Value = serde_json::from_slice(&request).unwrap();
    value["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
    let tampered = serde_json::to_vec(&value).unwrap();

    let response = proxy.handle(&tampered, now());

    assert_eq!(calls.borrow().len(), 0, "inner must NOT be reached");
    assert_eq!(error_message(&response), "mcps.invalid_signature");
}

#[test]
fn caller_supplied_verified_context_is_stripped_even_when_signed() {
    let (proxy, calls) = proxy_with_recorder();

    // Sign a request that smuggles its OWN verified-context under _meta. Because
    // it is part of the signed params, verification still passes — but the proxy
    // is the sole writer and must discard the caller's block.
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("echo".to_string()));
    params.insert("arguments".to_string(), json!({ "text": "hello" }));
    params.insert(
        "_meta".to_string(),
        json!({ VERIFIED_META_KEY: { "verified_signer": "did:evil:impostor", "verifier": "did:evil:impostor" } }),
    );
    let request = host()
        .sign_request(
            &Value::String("req-1".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            "nonce-proxy-solewriter",
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs");

    let _ = proxy.handle(&request, now());

    assert_eq!(calls.borrow().len(), 1, "verified request is forwarded");
    let forwarded = &calls.borrow()[0];
    let verified_ctx = &forwarded["params"]["_meta"][VERIFIED_META_KEY];
    assert_eq!(
        verified_ctx["verified_signer"].as_str(),
        Some(SIGNER),
        "the proxy's verified_signer must replace the smuggled one"
    );
    assert_eq!(
        verified_ctx["verifier"].as_str(),
        Some(SERVER),
        "the proxy is the sole writer of the verified context"
    );
}

/// Issue #3838 (ADR-MCPS-014): a NON-EXPORTING response signer drives the proxy's
/// full response-signing path, and the produced signature verifies under the public
/// key that signer advertises. The private key is captured inside the signing
/// closure and is unreachable from the `DelegatedResponseSigner` — the proxy holds
/// only a "sign these bytes" capability, exactly as it would with an HSM/KMS — yet
/// the end-to-end signed response still verifies and binds to the request.
#[test]
fn non_exporting_signer_drives_response_signing_and_verifies() {
    // The server signing key is moved INTO the closure; after this the test (and
    // the proxy) can only ask the signer to sign — never recover the key.
    let key = server_key();
    let advertised_public_key = key.public_key();
    let signer = DelegatedResponseSigner::new(
        Box::new(move |preimage| Ok(key.sign(preimage))),
        advertised_public_key,
    );

    // A trust resolver built from the public key the NON-EXPORTING signer advertises
    // (via `response_public_key`) — not from any exported private key.
    let mut response_resolver = InMemoryTrustResolver::new();
    response_resolver.insert(
        SERVER,
        SERVER_KEY_ID,
        signer
            .response_public_key()
            .expect("non-exporting signer advertises its public key"),
    );

    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses request");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [ { "type": "text", "text": "hello" } ] }
        });
        serde_json::to_vec(&response).expect("serialize inner response")
    };

    let proxy = Proxy::new(
        signer,
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    );

    let request = signed_echo_request("nonce-proxy-delegated", "hello");
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("request_hash");

    let response = proxy.handle(&request, now());

    let verified = verify_response(&response, &response_resolver, &expected_hash)
        .expect("response signed via the delegation seam verifies under the advertised public key");
    assert_eq!(verified.server_signer(), SERVER);
}

// ---------------------------------------------------------------------------
// Issue #4077 (MCPS-MED-4) — END-TO-END ROUND-TRIP: the proxy reshapes every
// inner result before signing (scalar -> {value}, error -> {inner_error}, object
// signed in place); the client's verify + `unwrap_verified_result` MUST restore
// the ORIGINAL MCP shape, and an inner error MUST surface as an error rather than
// a JSON-RPC success. Black-box: build a REAL signed proxy response and drive it
// through the REAL client path (`HostSession::verify_and_unwrap_response`).
// ---------------------------------------------------------------------------

/// A session at the fixed clock + seeded RNG so a signed request is fresh at the
/// proxy's `now()` and the response binds to the STORED request hash.
fn roundtrip_session() -> HostSession<FixedClock, SeededNonceSource> {
    HostSession::with_defaults(
        host(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
}

/// A proxy whose inner returns the caller-supplied JSON-RPC response verbatim
/// (echoing the request id), letting a test pick the inner `result` shape — or
/// omit `result` entirely to model an inner error.
fn proxy_returning(inner_response: Value) -> Proxy {
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses request");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let mut response = inner_response.clone();
        response["id"] = id;
        response["jsonrpc"] = Value::String("2.0".to_string());
        serde_json::to_vec(&response).expect("serialize inner response")
    };
    Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
}

/// Sign a `tools/call` through the SESSION (so the request is pending and the
/// response can be verified+unwrapped against the stored hash), drive it through
/// `proxy`, and return the signed proxy response bytes.
fn roundtrip(session: &mut HostSession<FixedClock, SeededNonceSource>, proxy: &Proxy) -> Vec<u8> {
    let request = session
        .sign_tool_call(
            &Value::String("rt-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
        )
        .expect("session signs the tool call");
    proxy.handle(&request, NOW_UNIX + 60)
}

#[test]
fn roundtrip_scalar_result_is_restored_to_the_scalar() {
    let mut session = roundtrip_session();
    let proxy = proxy_returning(json!({ "result": 42 }));
    let response = roundtrip(&mut session, &proxy);

    let outcome = session
        .verify_and_unwrap_response(&response, &server_resolver())
        .expect("verify + unwrap");
    // The consumer sees the original scalar 42 — NOT the {"value":42} wrapper.
    assert_eq!(outcome.unwrapped(), &UnwrappedResult::Scalar(json!(42)));
    assert!(!outcome.unwrapped().is_inner_error());
}

#[test]
fn roundtrip_array_result_is_restored_to_the_array() {
    let mut session = roundtrip_session();
    let proxy = proxy_returning(json!({ "result": [1, 2, 3] }));
    let response = roundtrip(&mut session, &proxy);

    let outcome = session
        .verify_and_unwrap_response(&response, &server_resolver())
        .expect("verify + unwrap");
    assert_eq!(outcome.unwrapped(), &UnwrappedResult::Scalar(json!([1, 2, 3])));
}

#[test]
fn roundtrip_object_result_is_returned_unchanged_minus_meta() {
    let mut session = roundtrip_session();
    let inner_object = json!({ "content": [ { "type": "text", "text": "hello" } ] });
    let proxy = proxy_returning(json!({ "result": inner_object.clone() }));
    let response = roundtrip(&mut session, &proxy);

    let outcome = session
        .verify_and_unwrap_response(&response, &server_resolver())
        .expect("verify + unwrap");
    // Signed in place: the object comes back unchanged, just without `_meta`.
    assert_eq!(outcome.unwrapped(), &UnwrappedResult::Object(inner_object));
}

#[test]
fn roundtrip_inner_error_surfaces_as_an_error_not_a_success() {
    let mut session = roundtrip_session();
    // Inner response carries NO `result` — an inner error the proxy wraps under
    // `inner_error` and signs.
    let inner_error_body = json!({ "error": { "code": -32000, "message": "boom" } });
    let proxy = proxy_returning(inner_error_body.clone());
    let response = roundtrip(&mut session, &proxy);

    let outcome = session
        .verify_and_unwrap_response(&response, &server_resolver())
        .expect("verify + unwrap");

    // THE REGRESSION GUARD: an inner error MUST be signalled as an error, never as
    // a success result. Without the client-side unwrap the consumer would instead
    // read the raw wire `result` = {"inner_error":…,"_meta":…} as a SUCCESS — see
    // `roundtrip_inner_error_is_a_success_without_unwrap` for that proof.
    assert!(
        outcome.unwrapped().is_inner_error(),
        "inner error must surface as an error"
    );
    match outcome.unwrapped() {
        UnwrappedResult::InnerError(inner) => {
            assert_eq!(inner["error"]["code"], json!(-32000));
        }
        other => panic!("expected an inner error, got {other:?}"),
    }
}

/// RED-with-teeth companion: proves that the BUG this change fixes is real. The
/// SAME signed proxy response, read the OLD way (raw wire `result`, exactly as
/// the consumers did before #4077), looks like a JSON-RPC SUCCESS with no
/// top-level `error` — an error masquerading as success. The unwrap above is what
/// turns this into a real error; this test pins the pre-unwrap behaviour so the
/// regression cannot silently return.
#[test]
fn roundtrip_inner_error_is_a_success_without_unwrap() {
    let mut session = roundtrip_session();
    let inner_error_body = json!({ "error": { "code": -32000, "message": "boom" } });
    let proxy = proxy_returning(inner_error_body);
    let response = roundtrip(&mut session, &proxy);

    // The OLD consumer path: verify (succeeds — the envelope is valid) then read
    // the raw wire `result` directly.
    let verified = verify_response(
        &response,
        &server_resolver(),
        session.stored_request_hash(&Value::String("rt-1".to_string())).expect("stored hash"),
    );
    assert!(verified.is_ok(), "the signed inner-error envelope verifies");

    let wire: Value = serde_json::from_slice(&response).expect("parse response");
    // No top-level JSON-RPC error: the OLD reader would treat this as a success...
    assert!(
        wire.get("error").is_none(),
        "the wrapped inner error carries NO top-level error — this is the masquerade"
    );
    // ...and the inner error is buried under `result.inner_error`, invisible to a
    // reader that just takes `result`.
    assert!(
        wire["result"]["inner_error"]["error"].is_object(),
        "the inner error is hidden inside result.inner_error on the wire"
    );
}
