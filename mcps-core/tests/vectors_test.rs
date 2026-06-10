//! MCP-S conformance vectors: generator + golden + Phase-1 primitive assertions
//! (MCPS-002).
//!
//! This single integration-test crate:
//!   1. Builds every conformance vector from MCPS_SPEC §10 with REAL crypto, using
//!      fixed/documented test keypairs (see `tests/vectors/README.md`). Stale
//!      brief names (`actor`/`capability_hash`/`server_actor`/`trust_label`) are
//!      NOT used — only the FROZEN §2 vocabulary.
//!   2. Asserts each committed fixture in `tests/vectors/` byte-equals (parsed)
//!      the regenerated vector, so vector drift fails CI.
//!   3. Asserts the Phase-1 primitive outcomes (V1/V2/V3/V4/V4B/tampered-id/
//!      JCS-01..08) directly through the committed fixtures.
//!
//! Pipeline-dependent OUTCOMES (replay/expired/audience/missing-envelope/batch/
//! notification/unknown-field, and V4B's hash-mismatch verdict) are NOT asserted
//! here — those need the verify pipeline (MCPS-008). Such fixtures carry
//! `requires_pipeline: true` and are only structurally validated here.

use mcps_core::canonicalize;
use mcps_core::request_hash;
use mcps_core::request_signing_preimage;
use mcps_core::response_signing_preimage;
use mcps_core::verify_ed25519;
use mcps_core::verify_ed25519_with;
use mcps_core::verify_request;
use mcps_core::verify_response;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::VerificationKey;
use serde_json::json;
use serde_json::Value;

// ===========================================================================
// Fixed, documented test keypairs (NEVER random — vectors must be reproducible).
// Mirrored in tests/vectors/README.md.
// ===========================================================================

const SIGNER_SEED: [u8; 32] = [1u8; 32];
const SERVER_SEED: [u8; 32] = [2u8; 32];

const SIGNER_ID: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER_SIGNER_ID: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";

const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const RESPONSE_ISSUED_AT: &str = "2026-05-28T20:00:01Z";

const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const AUTHORIZATION_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

const REQUEST_META_KEY: &str = "se.syncom/mcps.request";
const RESPONSE_META_KEY: &str = "se.syncom/mcps.response";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SIGNER_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}
fn signer_pubkey_b64url() -> String {
    signer_key().public_key().to_b64url()
}
fn server_pubkey_b64url() -> String {
    server_key().public_key().to_b64url()
}

// ===========================================================================
// Envelope builders (frozen vocabulary).
// ===========================================================================

fn request_object_unsigned(id: Value, arg_text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": arg_text },
            "_meta": {
                REQUEST_META_KEY: {
                    "version": "draft-01",
                    "signer": SIGNER_ID,
                    "on_behalf_of": ON_BEHALF_OF,
                    "audience": AUDIENCE,
                    "authorization_hash": AUTHORIZATION_HASH,
                    "nonce": NONCE,
                    "issued_at": ISSUED_AT,
                    "expires_at": EXPIRES_AT,
                    "signature": {
                        "alg": "Ed25519",
                        "key_id": SIGNER_KEY_ID,
                        "value": null
                    }
                }
            }
        }
    })
}

fn sign_request(object: &mut Value) {
    object["params"]["_meta"][REQUEST_META_KEY]["signature"]
        .as_object_mut()
        .expect("signature object")
        .remove("value");
    let preimage = request_signing_preimage(object).expect("request preimage");
    let sig = signer_key().sign(&preimage);
    object["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(sig);
}

fn signed_valid_request() -> Value {
    let mut obj = request_object_unsigned(Value::String("req-1".to_string()), "hello");
    sign_request(&mut obj);
    obj
}

fn response_object_unsigned(request_hash_value: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [{ "type": "text", "text": "hello" }],
            "_meta": {
                RESPONSE_META_KEY: {
                    "request_hash": request_hash_value,
                    "server_signer": SERVER_SIGNER_ID,
                    "issued_at": RESPONSE_ISSUED_AT,
                    "signature": {
                        "alg": "Ed25519",
                        "key_id": SERVER_KEY_ID,
                        "value": null
                    }
                }
            }
        }
    })
}

fn sign_response(object: &mut Value) {
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]
        .as_object_mut()
        .expect("signature object")
        .remove("value");
    let preimage = response_signing_preimage(object).expect("response preimage");
    let sig = server_key().sign(&preimage);
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
}

fn signed_valid_response() -> Value {
    let req_hash = request_hash(&signed_valid_request()).expect("request_hash");
    let mut obj = response_object_unsigned(&req_hash);
    sign_response(&mut obj);
    obj
}

const WRONG_HASH: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ===========================================================================
// Fixture model.
// ===========================================================================

#[derive(Debug, Clone)]
struct Fixture {
    name: &'static str,
    file: &'static str,
    kind: &'static str, // "request" | "response" | "raw"
    message: Value,
    raw_text: Option<String>,
    raw_bytes_b64url: Option<String>,
    expected: &'static str, // "verify_ok" | "mcps.*"
    resolver: Option<(String, String)>,
    requires_pipeline: bool,
}

impl Fixture {
    fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), Value::String(self.name.into()));
        obj.insert("kind".into(), Value::String(self.kind.into()));
        obj.insert("expected".into(), Value::String(self.expected.into()));
        obj.insert(
            "requires_pipeline".into(),
            Value::Bool(self.requires_pipeline),
        );
        if self.kind == "raw" {
            if let Some(text) = &self.raw_text {
                obj.insert("raw_text".into(), Value::String(text.clone()));
            }
            if let Some(b64) = &self.raw_bytes_b64url {
                obj.insert("raw_bytes_b64url".into(), Value::String(b64.clone()));
            }
        } else {
            obj.insert("message".into(), self.message.clone());
        }
        if let Some((id, pk)) = &self.resolver {
            obj.insert(
                "resolver".into(),
                json!({ "signer_key": id, "public_key_b64url": pk }),
            );
        }
        Value::Object(obj)
    }

    fn to_pretty_json_string(&self) -> String {
        to_sorted_pretty(&self.to_json())
    }
}

/// Deterministic pretty JSON: keys sorted (via BTreeMap round-trip), trailing
/// newline. Order-independent so the committed files are stable.
fn to_sorted_pretty(value: &Value) -> String {
    let sorted = sort_value(value);
    let mut s = serde_json::to_string_pretty(&sorted).expect("pretty");
    s.push('\n');
    s
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, Value> =
                std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_value(v));
            }
            serde_json::to_value(sorted).expect("sorted obj")
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

fn signer_resolver() -> Option<(String, String)> {
    Some((format!("{SIGNER_ID}#{SIGNER_KEY_ID}"), signer_pubkey_b64url()))
}
fn server_resolver() -> Option<(String, String)> {
    Some((
        format!("{SERVER_SIGNER_ID}#{SERVER_KEY_ID}"),
        server_pubkey_b64url(),
    ))
}

fn raw_fixture(
    name: &'static str,
    file: &'static str,
    text: &str,
    expected: &'static str,
) -> Fixture {
    Fixture {
        name,
        file,
        kind: "raw",
        message: Value::Null,
        raw_text: Some(text.to_string()),
        raw_bytes_b64url: None,
        expected,
        resolver: None,
        requires_pipeline: false,
    }
}

/// Build every conformance fixture (MCPS_SPEC §10), deterministically.
fn all_fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();

    // V1 — valid signed request.
    out.push(Fixture {
        name: "v1_valid_request",
        file: "v1_valid_request.json",
        kind: "request",
        message: signed_valid_request(),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "verify_ok",
        resolver: signer_resolver(),
        requires_pipeline: false,
    });

    // V2 — tampered argument (mutated AFTER signing).
    let mut v2 = signed_valid_request();
    v2["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
    out.push(Fixture {
        name: "v2_tampered_argument",
        file: "v2_tampered_argument.json",
        kind: "request",
        message: v2,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.invalid_signature",
        resolver: signer_resolver(),
        requires_pipeline: false,
    });

    // tampered id (mutated AFTER signing).
    let mut tid = signed_valid_request();
    tid["id"] = Value::String("req-evil".to_string());
    out.push(Fixture {
        name: "tampered_id",
        file: "tampered_id.json",
        kind: "request",
        message: tid,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.invalid_signature",
        resolver: signer_resolver(),
        requires_pipeline: false,
    });

    // V3 — valid signed response.
    out.push(Fixture {
        name: "v3_valid_response",
        file: "v3_valid_response.json",
        kind: "response",
        message: signed_valid_response(),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "verify_ok",
        resolver: server_resolver(),
        requires_pipeline: false,
    });

    // V4 — wrong request_hash + GARBAGE (non-64-byte) signature. Sig step fails.
    let mut v4 = response_object_unsigned(WRONG_HASH);
    v4["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String("Z2FyYmFnZQ".to_string());
    out.push(Fixture {
        name: "v4_wrong_hash_garbage_sig_response",
        file: "v4_wrong_hash_garbage_sig_response.json",
        kind: "response",
        message: v4,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.response_sig_invalid",
        resolver: server_resolver(),
        requires_pipeline: false,
    });

    // V4B — SIGNED over a WRONG request_hash. Sig valid; mismatch fires at step 7.
    let mut v4b = response_object_unsigned(WRONG_HASH);
    sign_response(&mut v4b);
    out.push(Fixture {
        name: "v4b_signed_wrong_hash_response",
        file: "v4b_signed_wrong_hash_response.json",
        kind: "response",
        message: v4b,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.response_hash_mismatch",
        resolver: server_resolver(),
        requires_pipeline: true,
    });

    // replay — same nonce twice; the SECOND submission is mcps.replay_detected.
    out.push(Fixture {
        name: "replay_request",
        file: "replay_request.json",
        kind: "request",
        message: signed_valid_request(),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.replay_detected",
        resolver: signer_resolver(),
        requires_pipeline: true,
    });

    // expired — expires_at far in the past; re-signed so freshness is the only fail.
    let mut expired = request_object_unsigned(Value::String("req-expired".to_string()), "hello");
    {
        let env = &mut expired["params"]["_meta"][REQUEST_META_KEY];
        env["issued_at"] = Value::String("2020-01-01T00:00:00Z".to_string());
        env["expires_at"] = Value::String("2020-01-01T00:05:00Z".to_string());
    }
    sign_request(&mut expired);
    out.push(Fixture {
        name: "expired_request",
        file: "expired_request.json",
        kind: "request",
        message: expired,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.expired_request",
        resolver: signer_resolver(),
        requires_pipeline: true,
    });

    // wrong audience — re-signed so audience is the only fail.
    let mut wrong_aud =
        request_object_unsigned(Value::String("req-wrong-aud".to_string()), "hello");
    wrong_aud["params"]["_meta"][REQUEST_META_KEY]["audience"] =
        Value::String("did:example:someone-else".to_string());
    sign_request(&mut wrong_aud);
    out.push(Fixture {
        name: "wrong_audience_request",
        file: "wrong_audience_request.json",
        kind: "request",
        message: wrong_aud,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.invalid_audience",
        resolver: signer_resolver(),
        requires_pipeline: true,
    });

    // missing envelope — no request _meta key.
    out.push(Fixture {
        name: "missing_envelope_request",
        file: "missing_envelope_request.json",
        kind: "request",
        message: json!({
            "jsonrpc": "2.0",
            "id": "req-missing",
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hello" } }
        }),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.missing_envelope",
        resolver: None,
        requires_pipeline: true,
    });

    // batch — top-level array.
    out.push(Fixture {
        name: "batch",
        file: "batch.json",
        kind: "request",
        message: json!([
            { "jsonrpc": "2.0", "id": "a", "method": "tools/call", "params": {} },
            { "jsonrpc": "2.0", "id": "b", "method": "tools/call", "params": {} }
        ]),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.batch_forbidden",
        resolver: None,
        requires_pipeline: true,
    });

    // security notification — no `id`.
    out.push(Fixture {
        name: "security_notification",
        file: "security_notification.json",
        kind: "request",
        message: json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hello" } }
        }),
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.notification_forbidden",
        resolver: None,
        requires_pipeline: true,
    });

    // unknown envelope field — re-signed so the unknown field is the only fail.
    let mut unknown = request_object_unsigned(Value::String("req-unknown".to_string()), "hello");
    unknown["params"]["_meta"][REQUEST_META_KEY]
        .as_object_mut()
        .expect("envelope object")
        .insert("unexpected".into(), Value::String("x".to_string()));
    sign_request(&mut unknown);
    out.push(Fixture {
        name: "unknown_envelope_field",
        file: "unknown_envelope_field.json",
        kind: "request",
        message: unknown,
        raw_text: None,
        raw_bytes_b64url: None,
        expected: "mcps.unknown_envelope_field",
        resolver: signer_resolver(),
        requires_pipeline: true,
    });

    // ---- JCS-01..08 ----
    out.push(raw_fixture(
        "jcs_01_duplicate_key",
        "jcs_01_duplicate_key.json",
        r#"{"a":1,"a":2}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(raw_fixture(
        "jcs_02_unsafe_integer_id",
        "jcs_02_unsafe_integer_id.json",
        r#"{"id":9007199254740993}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(raw_fixture(
        "jcs_03_unsafe_integer_arguments",
        "jcs_03_unsafe_integer_arguments.json",
        r#"{"arguments":{"amount":9007199254740993}}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(raw_fixture(
        "jcs_04_non_integer_number",
        "jcs_04_non_integer_number.json",
        r#"{"v":1.5}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(raw_fixture(
        "jcs_05_exponent_number",
        "jcs_05_exponent_number.json",
        r#"{"v":1e3}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(raw_fixture(
        "jcs_06_unpaired_surrogate",
        "jcs_06_unpaired_surrogate.json",
        r#"{"v":"\uD800"}"#,
        "mcps.canonicalization_failed",
    ));
    out.push(Fixture {
        name: "jcs_07_invalid_utf8",
        file: "jcs_07_invalid_utf8.json",
        kind: "raw",
        message: Value::Null,
        raw_text: None,
        raw_bytes_b64url: Some(mcps_core::b64url_encode(&[0x22u8, 0xFF, 0x22])),
        expected: "mcps.canonicalization_failed",
        resolver: None,
        requires_pipeline: false,
    });
    out.push(raw_fixture(
        "jcs_08_large_id_as_string",
        "jcs_08_large_id_as_string.json",
        r#"{"id":"9007199254740993"}"#,
        "verify_ok",
    ));

    out
}

// ===========================================================================
// LOCAL one-shot writer (NOT part of the bazel suite — `#[ignore]`d).
//   cargo test --test vectors_test write_fixtures -- --ignored
// ===========================================================================

#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    std::fs::create_dir_all(&dir).expect("create vectors dir");
    let mut manifest: Vec<Value> = Vec::new();
    for fixture in all_fixtures() {
        std::fs::write(dir.join(fixture.file), fixture.to_pretty_json_string())
            .expect("write fixture");
        manifest.push(json!({
            "name": fixture.name,
            "file": fixture.file,
            "kind": fixture.kind,
            "expected": fixture.expected,
            "requires_pipeline": fixture.requires_pipeline,
        }));
    }
    std::fs::write(
        dir.join("manifest.json"),
        to_sorted_pretty(&Value::Array(manifest)),
    )
    .expect("write manifest");
}

// ===========================================================================
// Committed fixtures (compile-time embedded — no runtime fs / runfiles).
// ===========================================================================

macro_rules! fixture_src {
    ($file:literal) => {
        ($file, include_str!(concat!("vectors/", $file)))
    };
}

/// (file, committed JSON text) for every fixture. Kept in sync with all_fixtures().
fn committed() -> Vec<(&'static str, &'static str)> {
    vec![
        fixture_src!("v1_valid_request.json"),
        fixture_src!("v2_tampered_argument.json"),
        fixture_src!("tampered_id.json"),
        fixture_src!("v3_valid_response.json"),
        fixture_src!("v4_wrong_hash_garbage_sig_response.json"),
        fixture_src!("v4b_signed_wrong_hash_response.json"),
        fixture_src!("replay_request.json"),
        fixture_src!("expired_request.json"),
        fixture_src!("wrong_audience_request.json"),
        fixture_src!("missing_envelope_request.json"),
        fixture_src!("batch.json"),
        fixture_src!("security_notification.json"),
        fixture_src!("unknown_envelope_field.json"),
        fixture_src!("jcs_01_duplicate_key.json"),
        fixture_src!("jcs_02_unsafe_integer_id.json"),
        fixture_src!("jcs_03_unsafe_integer_arguments.json"),
        fixture_src!("jcs_04_non_integer_number.json"),
        fixture_src!("jcs_05_exponent_number.json"),
        fixture_src!("jcs_06_unpaired_surrogate.json"),
        fixture_src!("jcs_07_invalid_utf8.json"),
        fixture_src!("jcs_08_large_id_as_string.json"),
    ]
}

const COMMITTED_MANIFEST: &str = include_str!("vectors/manifest.json");

fn committed_for(file: &str) -> Value {
    let text = committed()
        .into_iter()
        .find(|(f, _)| *f == file)
        .unwrap_or_else(|| panic!("no committed fixture for {file}"))
        .1;
    serde_json::from_str(text).unwrap_or_else(|e| panic!("parse committed {file}: {e}"))
}

/// The `message` Value from a committed request/response fixture.
fn committed_message(file: &str) -> Value {
    committed_for(file)
        .get("message")
        .cloned()
        .unwrap_or_else(|| panic!("fixture {file} has no message"))
}

// ===========================================================================
// (2) GOLDEN: regenerate each fixture and assert it byte/parse-equals the file.
// ===========================================================================

#[test]
fn golden_every_fixture_matches_committed() {
    for fixture in all_fixtures() {
        let regenerated: Value =
            serde_json::from_str(&fixture.to_pretty_json_string()).expect("regen parse");
        let on_disk = committed_for(fixture.file);
        assert_eq!(
            regenerated, on_disk,
            "fixture drift for {} ({}): committed JSON differs from regenerated. \
             Re-run `cargo test --test vectors_test write_fixtures -- --ignored`.",
            fixture.name, fixture.file
        );
    }
}

#[test]
fn golden_manifest_matches_committed() {
    let mut expected: Vec<Value> = Vec::new();
    for f in all_fixtures() {
        expected.push(json!({
            "name": f.name,
            "file": f.file,
            "kind": f.kind,
            "expected": f.expected,
            "requires_pipeline": f.requires_pipeline,
        }));
    }
    let regenerated: Value =
        serde_json::from_str(&to_sorted_pretty(&Value::Array(expected))).expect("regen manifest");
    let on_disk: Value = serde_json::from_str(COMMITTED_MANIFEST).expect("parse manifest");
    assert_eq!(regenerated, on_disk, "manifest drift");
}

#[test]
fn every_fixture_is_committed_and_vice_versa() {
    let generated: std::collections::BTreeSet<String> =
        all_fixtures().iter().map(|f| f.file.to_string()).collect();
    let on_disk: std::collections::BTreeSet<String> =
        committed().iter().map(|(f, _)| f.to_string()).collect();
    assert_eq!(generated, on_disk, "fixture set drift");
}

// ===========================================================================
// Resolver helpers (read pubkey from the committed fixture).
// ===========================================================================

fn resolver_pubkey(file: &str) -> VerificationKey {
    let pk = committed_for(file)["resolver"]["public_key_b64url"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture {file} has no resolver pubkey"))
        .to_string();
    VerificationKey::from_b64url(&pk).expect("resolver pubkey decodes")
}

fn request_sig_value(message: &Value) -> String {
    message["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"]
        .as_str()
        .expect("request signature value")
        .to_string()
}

fn response_sig_value(message: &Value) -> String {
    message["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"]
        .as_str()
        .expect("response signature value")
        .to_string()
}

// ===========================================================================
// (V1) valid request verifies OK through the committed fixture.
// ===========================================================================

#[test]
fn v1_request_signature_verifies() {
    let msg = committed_message("v1_valid_request.json");
    let preimage = request_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("v1_valid_request.json");
    let sig = request_sig_value(&msg);
    assert!(
        verify_ed25519(&preimage, &sig, &key).is_ok(),
        "V1 must verify"
    );
}

// ===========================================================================
// (V2) tampered argument -> InvalidSignature.
// ===========================================================================

#[test]
fn v2_tampered_argument_fails_signature() {
    let msg = committed_message("v2_tampered_argument.json");
    let preimage = request_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("v2_tampered_argument.json");
    let sig = request_sig_value(&msg);
    assert_eq!(
        verify_ed25519(&preimage, &sig, &key).unwrap_err(),
        McpsError::InvalidSignature
    );
}

// ===========================================================================
// (tampered id) -> InvalidSignature.
// ===========================================================================

#[test]
fn tampered_id_fails_signature() {
    let msg = committed_message("tampered_id.json");
    let preimage = request_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("tampered_id.json");
    let sig = request_sig_value(&msg);
    assert_eq!(
        verify_ed25519(&preimage, &sig, &key).unwrap_err(),
        McpsError::InvalidSignature
    );
}

// ===========================================================================
// (V3) valid response verifies OK with the server pubkey.
// ===========================================================================

#[test]
fn v3_response_signature_verifies() {
    let msg = committed_message("v3_valid_response.json");
    let preimage = response_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("v3_valid_response.json");
    let sig = response_sig_value(&msg);
    assert!(
        verify_ed25519_with(&preimage, &sig, &key, McpsError::ResponseSigInvalid).is_ok(),
        "V3 must verify"
    );
}

// ===========================================================================
// (V4) wrong-hash + garbage sig -> ResponseSigInvalid (fails at the sig step).
// ===========================================================================

#[test]
fn v4_garbage_response_signature_fails() {
    let msg = committed_message("v4_wrong_hash_garbage_sig_response.json");
    let preimage = response_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("v4_wrong_hash_garbage_sig_response.json");
    let sig = response_sig_value(&msg);
    assert_eq!(
        verify_ed25519_with(&preimage, &sig, &key, McpsError::ResponseSigInvalid).unwrap_err(),
        McpsError::ResponseSigInvalid
    );
}

// ===========================================================================
// (V4B) signature VALID over the wrong-hash preimage, AND request_hash mismatches
// the matching request's true hash -> proves response_hash_mismatch fires AFTER a
// valid signature.
// ===========================================================================

#[test]
fn v4b_signature_valid_but_request_hash_mismatches() {
    let msg = committed_message("v4b_signed_wrong_hash_response.json");

    // Step 6: signature is VALID over the (wrong-hash) preimage.
    let preimage = response_signing_preimage(&msg).expect("preimage");
    let key = resolver_pubkey("v4b_signed_wrong_hash_response.json");
    let sig = response_sig_value(&msg);
    assert!(
        verify_ed25519_with(&preimage, &sig, &key, McpsError::ResponseSigInvalid).is_ok(),
        "V4B response signature must be valid over its (wrong-hash) preimage"
    );

    // Step 7: the carried request_hash != the matching request's true hash.
    let carried = msg["result"]["_meta"][RESPONSE_META_KEY]["request_hash"]
        .as_str()
        .expect("request_hash");
    let true_hash = request_hash(&committed_message("v1_valid_request.json")).expect("true hash");
    assert_ne!(
        carried, true_hash,
        "V4B carried request_hash must NOT equal the matching request's true hash"
    );
}

// ===========================================================================
// (JCS-01..08) feed the committed raw fixtures through canonicalize.
// ===========================================================================

fn raw_bytes_for(file: &str) -> Vec<u8> {
    let fx = committed_for(file);
    if let Some(text) = fx.get("raw_text").and_then(|v| v.as_str()) {
        text.as_bytes().to_vec()
    } else if let Some(b64) = fx.get("raw_bytes_b64url").and_then(|v| v.as_str()) {
        mcps_core::b64url_decode(b64).expect("raw bytes decode")
    } else {
        panic!("raw fixture {file} has neither raw_text nor raw_bytes_b64url");
    }
}

#[test]
fn jcs_01_through_07_fail_canonicalization() {
    let files = [
        "jcs_01_duplicate_key.json",
        "jcs_02_unsafe_integer_id.json",
        "jcs_03_unsafe_integer_arguments.json",
        "jcs_04_non_integer_number.json",
        "jcs_05_exponent_number.json",
        "jcs_06_unpaired_surrogate.json",
        "jcs_07_invalid_utf8.json",
    ];
    for file in files {
        let bytes = raw_bytes_for(file);
        assert_eq!(
            canonicalize(&bytes).unwrap_err(),
            McpsError::CanonicalizationFailed,
            "{file} must fail canonicalization"
        );
    }
}

#[test]
fn jcs_08_large_id_as_string_canonicalizes_ok() {
    let bytes = raw_bytes_for("jcs_08_large_id_as_string.json");
    let out = canonicalize(&bytes).expect("JCS-08 must canonicalize");
    assert_eq!(out, br#"{"id":"9007199254740993"}"#);
}

// ===========================================================================
// (MCPS-008) Full verify_request / verify_response pipeline against committed
// fixtures. The fixtures store a `message` Value; we serialize it to wire bytes
// and feed it through the pipeline with a resolver built from the documented
// seeds and a `now_unix` derived from the fixture's own issued_at.
// ===========================================================================

const SKEW: i64 = 30;

/// The Unix epoch of the canonical valid request issued_at (2026-05-28T20:00:00Z).
/// Asserted against `time::parse_rfc3339_utc` semantics in that module.
const VALID_ISSUED_EPOCH: i64 = 1_779_998_400;

fn pipeline_config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn signer_trust_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER_ID, SIGNER_KEY_ID, signer_key().public_key());
    r
}

fn server_trust_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER_SIGNER_ID, SERVER_KEY_ID, server_key().public_key());
    r
}

/// Serialize a committed fixture's `message` to wire bytes.
fn fixture_bytes(file: &str) -> Vec<u8> {
    serde_json::to_vec(&committed_message(file)).expect("serialize fixture message")
}

#[test]
fn pipeline_v1_valid_request_verifies_with_matching_fields() {
    let raw = fixture_bytes("v1_valid_request.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified = verify_request(
        &raw,
        &signer_trust_resolver(),
        &mut replay,
        &pipeline_config(),
        VALID_ISSUED_EPOCH + 60,
    )
    .expect("V1 must verify through the pipeline");

    assert_eq!(verified.verified_signer, SIGNER_ID);
    assert_eq!(verified.key_id, SIGNER_KEY_ID);
    assert_eq!(verified.on_behalf_of, ON_BEHALF_OF);
    assert_eq!(verified.audience, AUDIENCE);
    assert_eq!(verified.authorization_hash, AUTHORIZATION_HASH);
    assert_eq!(verified.nonce, NONCE);
    assert_eq!(verified.issued_at, ISSUED_AT);
    assert_eq!(verified.expires_at, EXPIRES_AT);
    assert!(!verified.request_hash.is_empty());
    assert!(verified.request_hash.starts_with("sha256:"));
}

#[test]
fn pipeline_v2_tampered_argument_is_invalid_signature() {
    let raw = fixture_bytes("v2_tampered_argument.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(
            &raw,
            &signer_trust_resolver(),
            &mut replay,
            &pipeline_config(),
            VALID_ISSUED_EPOCH + 60
        ),
        Err(McpsError::InvalidSignature)
    );
}

#[test]
fn pipeline_tampered_id_is_invalid_signature() {
    let raw = fixture_bytes("tampered_id.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(
            &raw,
            &signer_trust_resolver(),
            &mut replay,
            &pipeline_config(),
            VALID_ISSUED_EPOCH + 60
        ),
        Err(McpsError::InvalidSignature)
    );
}

#[test]
fn pipeline_replay_first_ok_second_detected() {
    let raw = fixture_bytes("replay_request.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    let now = VALID_ISSUED_EPOCH + 60;
    assert!(
        verify_request(&raw, &signer_trust_resolver(), &mut replay, &pipeline_config(), now)
            .is_ok(),
        "first submission must verify"
    );
    assert_eq!(
        verify_request(&raw, &signer_trust_resolver(), &mut replay, &pipeline_config(), now),
        Err(McpsError::ReplayDetected),
        "second submission (same cache) must be a replay"
    );
}

#[test]
fn pipeline_expired_request_is_expired() {
    // expired_request.json uses issued_at 2020-01-01T00:00:00Z, expires +5min.
    // Evaluate well past expiry+skew.
    let raw = fixture_bytes("expired_request.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    // 2020-01-01T00:05:00Z epoch = 1577836800 + 300; + skew + 1 is past the window.
    let now = 1_577_836_800 + 300 + SKEW + 1;
    assert_eq!(
        verify_request(&raw, &signer_trust_resolver(), &mut replay, &pipeline_config(), now),
        Err(McpsError::ExpiredRequest)
    );
}

#[test]
fn pipeline_wrong_audience_is_invalid_audience() {
    let raw = fixture_bytes("wrong_audience_request.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(
            &raw,
            &signer_trust_resolver(),
            &mut replay,
            &pipeline_config(),
            VALID_ISSUED_EPOCH + 60
        ),
        Err(McpsError::InvalidAudience)
    );
}

#[test]
fn pipeline_missing_envelope_is_missing_envelope() {
    let raw = fixture_bytes("missing_envelope_request.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(
            &raw,
            &signer_trust_resolver(),
            &mut replay,
            &pipeline_config(),
            VALID_ISSUED_EPOCH + 60
        ),
        Err(McpsError::MissingEnvelope)
    );
}

#[test]
fn pipeline_batch_is_batch_forbidden() {
    let raw = fixture_bytes("batch.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(&raw, &signer_trust_resolver(), &mut replay, &pipeline_config(), 0),
        Err(McpsError::BatchForbidden)
    );
}

#[test]
fn pipeline_security_notification_is_notification_forbidden() {
    let raw = fixture_bytes("security_notification.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(&raw, &signer_trust_resolver(), &mut replay, &pipeline_config(), 0),
        Err(McpsError::NotificationForbidden)
    );
}

#[test]
fn pipeline_unknown_envelope_field_is_unknown_envelope_field() {
    let raw = fixture_bytes("unknown_envelope_field.json");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request(
            &raw,
            &signer_trust_resolver(),
            &mut replay,
            &pipeline_config(),
            VALID_ISSUED_EPOCH + 60
        ),
        Err(McpsError::UnknownEnvelopeField)
    );
}

#[test]
fn pipeline_v3_valid_response_verifies() {
    // expected_request_hash = request_hash of the matching v1 request.
    let true_hash =
        request_hash(&committed_message("v1_valid_request.json")).expect("true request hash");
    let raw = fixture_bytes("v3_valid_response.json");
    let verified = verify_response(&raw, &server_trust_resolver(), &true_hash)
        .expect("V3 must verify through the pipeline");
    assert_eq!(verified.server_signer, SERVER_SIGNER_ID);
    assert_eq!(verified.key_id, SERVER_KEY_ID);
    assert_eq!(verified.request_hash, true_hash);
}

#[test]
fn pipeline_v4b_signed_wrong_hash_is_hash_mismatch_not_sig_invalid() {
    // The signature is VALID over the wrong-hash preimage; step 7 must catch the
    // mismatch — and it must NOT surface as ResponseSigInvalid.
    let true_hash =
        request_hash(&committed_message("v1_valid_request.json")).expect("true request hash");
    let raw = fixture_bytes("v4b_signed_wrong_hash_response.json");
    let result = verify_response(&raw, &server_trust_resolver(), &true_hash);
    assert_eq!(result, Err(McpsError::ResponseHashMismatch));
    assert_ne!(result, Err(McpsError::ResponseSigInvalid));
}
