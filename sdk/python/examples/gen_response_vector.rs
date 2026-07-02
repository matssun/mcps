//! Generate the golden vectors for the Python `verify_response` binding.
//!
//! Independent oracle: builds server-signed (and malformed) draft-02 responses and
//! runs the real `mcps-client-core` return-leg chain (verify → classify → decide →
//! audit) per scenario, capturing the exact decision/path/reason. The Python parity
//! test then asserts the binding reproduces each outcome.
//!
//!   cargo run --example gen_response_vector > tests/fixtures/verify_response_vectors.json

use mcps_client_core::{
    audit_for_decision, build_signed_request, classify_response_result, decide,
    verify_and_classify_response, ClientOutcome, ClientPath, EnforcementDecision, EnforcementMode,
    RequestSigningInputs, ResponseExpectation,
};
use mcps_core::{
    response_signing_preimage, AuthorizationBinding, InMemoryTrustResolver, ResultClass,
    SigningKey, CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::{json, Map, Value};

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const EVIL_SEED: [u8; 32] = [7u8; 32];
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The request_hash a client holds after signing (the value the response must bind).
fn client_request_hash() -> String {
    let key = SigningKey::from_seed_bytes(&CLIENT_SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        "did:example:client",
        "client-key-1",
        "user:alice",
        "did:example:server",
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    let mut params = Map::new();
    params.insert("name".into(), json!("echo"));
    params.insert("arguments".into(), json!({ "text": "hi" }));
    build_signed_request(&json!("req-1"), "tools/call", params, &inputs, &key)
        .unwrap()
        .request_hash()
        .to_string()
}

/// A server-signed draft-02 response binding `request_hash`.
fn signed_response(
    request_hash: &str,
    server_seed: &[u8; 32],
    signer: &str,
    key_id: &str,
) -> Value {
    let key = SigningKey::from_seed_bytes(server_seed);
    let mut object = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [{ "type": "text", "text": "hi" }],
            "_meta": { RESPONSE_META_KEY: {
                "version": VERSION_DRAFT_02,
                "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                "request_hash": request_hash,
                "server_signer": signer,
                "issued_at": "2026-06-30T20:00:01Z",
                "signature": { "alg": SIG_ALG_ED25519, "key_id": key_id },
            }}
        }
    });
    let preimage = response_signing_preimage(&object).unwrap();
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(key.sign(&preimage));
    object
}

/// A server-signed InputRequiredResult response (ADR-MCPS-047 / D2): a non-terminal
/// elicitation result, signed as an ordinary draft-02 response.
fn signed_input_required_response(request_hash: &str) -> Value {
    let key = SigningKey::from_seed_bytes(&SERVER_SEED);
    let mut object = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "resultType": "inputRequired",
            "inputRequests": { "confirm": { "type": "elicitation", "message": "Delete 3 files?" } },
            "requestState": "eyJzdGVwIjoxfQ",
            "_meta": { RESPONSE_META_KEY: {
                "version": VERSION_DRAFT_02,
                "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                "request_hash": request_hash,
                "server_signer": SERVER_SIGNER,
                "issued_at": "2026-06-30T20:00:01Z",
                "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
            }}
        }
    });
    let preimage = response_signing_preimage(&object).unwrap();
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(key.sign(&preimage));
    object
}

#[allow(clippy::too_many_arguments)]
fn scenario(
    name: &str,
    response: &Value,
    resolver: &InMemoryTrustResolver,
    expected_request_hash: &str,
    expected_canon: Option<&str>,
    expected_signer: Option<&str>,
    mode_str: &str,
    legacy_allowed: bool,
) -> Value {
    let bytes = serde_json::to_vec(response).unwrap();
    let canon = expected_canon.unwrap_or(CANONICALIZATION_ID_INT53_V1);
    let mut expectation = ResponseExpectation::new(expected_request_hash, canon);
    if let Some(s) = expected_signer {
        expectation = expectation.with_expected_server_signer(s);
    }
    let mode = match mode_str {
        "require_mcps" => EnforcementMode::RequireMcps,
        "allow_legacy_explicit" => EnforcementMode::AllowLegacyExplicit,
        _ => unreachable!(),
    };

    let classified = verify_and_classify_response(&bytes, resolver, &expectation);
    let verified = classified.as_ref().ok().map(|c| {
        (
            c.verified.server_signer().to_string(),
            c.verified.key_id().to_string(),
            c.verified.request_hash().to_string(),
        )
    });
    let (result_class, response_hash) = match classified.as_ref().ok() {
        Some(c) => (
            match c.class {
                ResultClass::Terminal => "terminal",
                ResultClass::InputRequired => "input_required",
            },
            json!(c.response_hash),
        ),
        None => ("terminal", Value::Null),
    };
    let outcome = classify_response_result(classified.map(|c| c.verified));
    let decision = decide(mode, legacy_allowed, &outcome);
    let audit = audit_for_decision(&decision);

    let (decision_str, accepted) = match &decision {
        EnforcementDecision::AcceptMcps => ("accept", true),
        EnforcementDecision::FallBackToLegacy { .. } => ("fallback", false),
        EnforcementDecision::FailClosed(_) => ("fail-closed", false),
    };
    let path = match audit.path {
        ClientPath::McpsVerified => "mcps-verified",
        ClientPath::LegacyExplicit => "legacy-explicit",
    };
    let outcome_str = match audit.outcome {
        ClientOutcome::Accepted => "accepted",
        ClientOutcome::FellBackToLegacy => "fell-back",
        ClientOutcome::Rejected => "rejected",
    };
    let (ss, kid, rh) = match verified {
        Some((s, k, h)) => (json!(s), json!(k), json!(h)),
        None => (Value::Null, Value::Null, Value::Null),
    };

    json!({
        "name": name,
        "response_bytes": String::from_utf8(bytes).unwrap(),
        "params": {
            "expected_request_hash": expected_request_hash,
            "expected_canonicalization_id": expected_canon,
            "expected_server_signer": expected_signer,
            "enforcement_mode": mode_str,
            "legacy_allowed": legacy_allowed,
        },
        "expected": {
            "decision": decision_str,
            "path": path,
            "outcome": outcome_str,
            "reason": audit.reason,
            "server_signer": ss,
            "key_id": kid,
            "request_hash": rh,
            "accepted": accepted,
            "result_class": result_class,
            "response_hash": response_hash,
        },
    })
}

fn main() {
    let rh = client_request_hash();
    let server_pk = SigningKey::from_seed_bytes(&SERVER_SEED)
        .public_key()
        .to_bytes();

    // The resolver every scenario uses: the legitimate server's public key only.
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(
        SERVER_SIGNER,
        SERVER_KEY_ID,
        SigningKey::from_seed_bytes(&SERVER_SEED).public_key(),
    );

    let valid = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);

    // tampered: flip a result byte AFTER signing.
    let mut tampered = valid.clone();
    tampered["result"]["content"][0]["text"] = json!("tampered");

    // unsigned: a plain MCP response with no MCP-S envelope.
    let unsigned = json!({
        "jsonrpc": "2.0", "id": "req-1",
        "result": { "content": [{ "type": "text", "text": "hi" }] }
    });

    // signed by an unknown (evil) server identity the resolver does not know.
    let evil = signed_response(&rh, &EVIL_SEED, "did:example:evil", "evil-key");

    // validly signed, but binds a DIFFERENT request_hash than the client sent.
    let wrong_hash = signed_response(
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &SERVER_SEED,
        SERVER_SIGNER,
        SERVER_KEY_ID,
    );

    // A verified, NON-TERMINAL InputRequiredResult (ADR-MCPS-047): accepted evidence
    // that classifies as input_required and carries a response_hash.
    let input_required = signed_input_required_response(&rh);

    // Tampered elicitation prompt / continuation state (ADR-MCPS-047 / D2): both are
    // inside the signed response preimage, so flipping them AFTER signing breaks the
    // signature — a server prompt or requestState cannot be forged in flight.
    let mut ir_tampered_requests = input_required.clone();
    ir_tampered_requests["result"]["inputRequests"]["confirm"]["message"] =
        json!("Keep all files?");
    let mut ir_tampered_state = input_required.clone();
    ir_tampered_state["result"]["requestState"] = json!("dGFtcGVyZWQtc3RhdGU");

    let scenarios = json!([
        scenario(
            "valid",
            &valid,
            &resolver,
            &rh,
            None,
            Some(SERVER_SIGNER),
            "require_mcps",
            false
        ),
        scenario(
            "input_required",
            &input_required,
            &resolver,
            &rh,
            None,
            Some(SERVER_SIGNER),
            "require_mcps",
            false
        ),
        scenario(
            "input_required_tampered_input_requests",
            &ir_tampered_requests,
            &resolver,
            &rh,
            None,
            Some(SERVER_SIGNER),
            "require_mcps",
            false
        ),
        scenario(
            "input_required_tampered_request_state",
            &ir_tampered_state,
            &resolver,
            &rh,
            None,
            Some(SERVER_SIGNER),
            "require_mcps",
            false
        ),
        scenario(
            "unsigned_require_mcps",
            &unsigned,
            &resolver,
            &rh,
            None,
            None,
            "require_mcps",
            false
        ),
        scenario(
            "tampered_signature",
            &tampered,
            &resolver,
            &rh,
            None,
            None,
            "require_mcps",
            false
        ),
        scenario(
            "unresolvable_signer",
            &evil,
            &resolver,
            &rh,
            None,
            None,
            "require_mcps",
            false
        ),
        scenario(
            "request_hash_mismatch",
            &wrong_hash,
            &resolver,
            &rh,
            None,
            None,
            "require_mcps",
            false
        ),
        scenario(
            "canonicalization_mismatch",
            &valid,
            &resolver,
            &rh,
            Some("mcps-jcs-int53-json-v9-mismatch"),
            None,
            "require_mcps",
            false
        ),
        scenario(
            "pinned_signer_mismatch",
            &valid,
            &resolver,
            &rh,
            None,
            Some("did:example:other-tenant"),
            "require_mcps",
            false
        ),
    ]);

    let fixture = json!({
        "_comment": "Golden vectors for the Python verify_response binding. Generated by \
                     `cargo run --example gen_response_vector` from mcps-client-core (independent \
                     oracle; same return-leg chain the proxy uses). Do not edit by hand.",
        "server": {
            "signer_id": SERVER_SIGNER,
            "key_id": SERVER_KEY_ID,
            "seed_hex": hex(&SERVER_SEED),
            "public_key_hex": hex(&server_pk),
        },
        "client_request_hash": rh,
        "scenarios": scenarios,
    });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
