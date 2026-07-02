//! Draft-02 (v0.6) conformance corpus + frozen static interop oracle
//! (ADR-MCPS-042 / decision H.1).
//!
//! This is a SEPARATE, byte-frozen corpus under `tests/vectors/draft-02/` so the
//! draft-01 golden set stays provably untouched (the ADR-MCPS-041 no-leak
//! property is mechanical, not a human promise). Each signed fixture carries a
//! frozen static **oracle** — the committed canonical preimage bytes, its
//! SHA-256, the signature value, and the request hash — so a THIRD-PARTY
//! implementation can check itself against frozen ground truth rather than this
//! project's own regenerated opinion. The harness asserts bytes and hashes and
//! the black-box wire code, never a printed "OK".
//!
//! Two oracle modes run together (ADR-MCPS-042):
//!   1. regenerate every fixture with the project's own Ed25519 + canonicalizer
//!      and assert it byte-equals the committed file (internal drift guard);
//!   2. assert the committed `oracle` fields equal the recomputed preimage /
//!      digest / signature / request_hash (cross-implementation ground truth).
//!
//! Regenerate the committed corpus after a deliberate change with:
//!   cargo test --test draft02_vectors_test write_draft02_fixtures -- --ignored

use mcps_core::b64url_encode;
use mcps_core::request_hash;
use mcps_core::request_signing_preimage;
use mcps_core::response_signing_preimage;
use mcps_core::sha256_hash_id;
use mcps_core::verify_response_draft02;
use mcps_core::ExpectedVersionPolicy;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::REQUEST_META_KEY;
use mcps_core::RESPONSE_META_KEY;
use serde_json::json;
use serde_json::Value;

// Fixed, documented seeds — identical to the draft-01 corpus so the two share a
// trust root and the oracle is reproducible by any implementation.
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
const ISSUED_EPOCH: i64 = 1_779_998_400;
const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const SKEW: i64 = 30;

const CANON_ID: &str = "mcps-jcs-int53-json-v1";
const DIGEST_VALUE: &str = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SIGNER_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn signer_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER_ID, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER_SIGNER_ID, SERVER_KEY_ID, server_key().public_key());
    r
}

// ---------------------------------------------------------------------------
// Object builders.
// ---------------------------------------------------------------------------

/// An unsigned draft-02 request with an opaque-bytes authorization binding.
fn request_unsigned(id: &str, arg_text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": arg_text },
            "_meta": {
                REQUEST_META_KEY: {
                    "version": "draft-02",
                    "canonicalization_id": CANON_ID,
                    "signer": SIGNER_ID,
                    "on_behalf_of": ON_BEHALF_OF,
                    "audience": AUDIENCE,
                    "authorization_binding": {
                        "binding_type": "opaque-bytes",
                        "digest_alg": "sha256",
                        "digest_value": DIGEST_VALUE
                    },
                    "nonce": NONCE,
                    "issued_at": ISSUED_AT,
                    "expires_at": EXPIRES_AT,
                    "signature": { "alg": "Ed25519", "key_id": SIGNER_KEY_ID, "value": null }
                }
            }
        }
    })
}

fn sign_request(object: &mut Value) {
    object["params"]["_meta"][REQUEST_META_KEY]["signature"]
        .as_object_mut()
        .expect("sig obj")
        .remove("value");
    let preimage = request_signing_preimage(object).expect("preimage");
    let sig = signer_key().sign(&preimage);
    object["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(sig);
}

fn response_unsigned(request_hash_value: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [{ "type": "text", "text": "hello" }],
            "_meta": {
                RESPONSE_META_KEY: {
                    "version": "draft-02",
                    "canonicalization_id": CANON_ID,
                    "request_hash": request_hash_value,
                    "server_signer": SERVER_SIGNER_ID,
                    "issued_at": "2026-05-28T20:00:01Z",
                    "signature": { "alg": "Ed25519", "key_id": SERVER_KEY_ID, "value": null }
                }
            }
        }
    })
}

fn sign_response(object: &mut Value) {
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]
        .as_object_mut()
        .expect("sig obj")
        .remove("value");
    let preimage = response_signing_preimage(object).expect("preimage");
    let sig = server_key().sign(&preimage);
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
}

// ---------------------------------------------------------------------------
// Fixture model + corpus.
// ---------------------------------------------------------------------------

/// How the harness must verify a fixture and what it must observe.
#[derive(Debug, Clone)]
enum Check {
    /// A draft-02 request via the dual dispatcher under the given policy.
    Request { policy: ExpectedVersionPolicy },
    /// A draft-02 response via verify_response_draft02 with the bound expectations.
    Response {
        expected_request_hash: String,
        expected_canonicalization_id: String,
    },
}

#[derive(Debug, Clone)]
struct Fixture {
    name: &'static str,
    file: &'static str,
    /// The wire message, or `None` for a raw-text fixture (malformed-before-parse).
    message: Option<Value>,
    /// Raw text for fixtures that must fail before serde can model them.
    raw_text: Option<String>,
    check: Check,
    /// Expected outcome: `"verify_ok"` or an `mcps.*` wire code.
    expected: &'static str,
}

/// The frozen static oracle for a signed, canonicalizable fixture.
fn oracle_for_request(message: &Value) -> Value {
    let preimage = request_signing_preimage(message).expect("preimage");
    let sig = message["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"]
        .as_str()
        .unwrap_or("")
        .to_string();
    json!({
        "canonical_preimage_b64url": b64url_encode(&preimage),
        "canonical_preimage_sha256": sha256_hash_id(&preimage),
        "signature_value": sig,
        "request_hash": request_hash(message).expect("request_hash"),
    })
}

fn oracle_for_response(message: &Value) -> Value {
    let preimage = response_signing_preimage(message).expect("preimage");
    let sig = message["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let request_hash_value = message["result"]["_meta"][RESPONSE_META_KEY]["request_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();
    json!({
        "canonical_preimage_b64url": b64url_encode(&preimage),
        "canonical_preimage_sha256": sha256_hash_id(&preimage),
        "signature_value": sig,
        "request_hash": request_hash_value,
    })
}

/// Build the full draft-02 corpus, deterministically.
fn corpus() -> Vec<Fixture> {
    let mut out = Vec::new();
    let only = Check::Request {
        policy: ExpectedVersionPolicy::Draft02Only,
    };

    // d01 — valid signed request, opaque-bytes binding.
    let mut d01 = request_unsigned("req-1", "hello");
    sign_request(&mut d01);
    out.push(Fixture {
        name: "d01_valid_request_opaque",
        file: "d01_valid_request_opaque.json",
        message: Some(d01),
        raw_text: None,
        check: only.clone(),
        expected: "verify_ok",
    });

    // d02 — valid signed request, authz-system-reference binding (Core binds; the
    // policy resolver interprets — not exercised here).
    let mut d02 = request_unsigned("req-2", "hello");
    d02["params"]["_meta"][REQUEST_META_KEY]["authorization_binding"] = json!({
        "binding_type": "authz-system-reference",
        "authorization_system_id": "acme-authz",
        "reference_scheme_id": "acme/decision-v1",
        "reference_value": "decision-123",
        "digest_alg": "sha256",
        "digest_value": DIGEST_VALUE
    });
    sign_request(&mut d02);
    out.push(Fixture {
        name: "d02_valid_request_authz_reference",
        file: "d02_valid_request_authz_reference.json",
        message: Some(d02),
        raw_text: None,
        check: only.clone(),
        expected: "verify_ok",
    });

    // d03 — int53 honesty: a float-bearing signed payload fails closed (the
    // documented limitation, machine-checked). Cannot be signed (the preimage
    // canonicalizer rejects the float), so a placeholder signature is used;
    // verification rejects at the raw-bytes JCS domain check before the signature.
    let mut d03 = request_unsigned("req-3", "hello");
    d03["params"]["arguments"] = json!({ "temperature": 0.7, "price": 19.99 });
    d03["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!("AA");
    out.push(Fixture {
        name: "d03_int53_float_rejected",
        file: "d03_int53_float_rejected.json",
        message: Some(d03),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.canonicalization_failed",
    });

    // d04 — unknown-but-correctly-signed canonicalization_id: signed over the
    // unknown id, so the signature is VALID — proving the policy failure
    // (canonicalization_id_unknown) is distinct from a signature failure and
    // fires FIRST (the allowlist check precedes crypto).
    let mut d04 = request_unsigned("req-4", "hello");
    d04["params"]["_meta"][REQUEST_META_KEY]["canonicalization_id"] = json!("mcps-jcs-unknown-v9");
    sign_request(&mut d04);
    out.push(Fixture {
        name: "d04_unknown_signed_canon_id",
        file: "d04_unknown_signed_canon_id.json",
        message: Some(d04),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.canonicalization_id_unknown",
    });

    // d05 — signed-wrong-profile: signed correctly as draft-02, then the version
    // is flipped to draft-01 on the wire. Dispatched to the draft-01 verifier,
    // which rejects the draft-02-only fields (no cross-acceptance, integrity
    // boundary holds). Uses the migration policy so the draft-01 profile is
    // reachable at dispatch.
    let mut d05 = request_unsigned("req-5", "hello");
    sign_request(&mut d05);
    d05["params"]["_meta"][REQUEST_META_KEY]["version"] = json!("draft-01");
    out.push(Fixture {
        name: "d05_signed_wrong_profile_version_flip",
        file: "d05_signed_wrong_profile_version_flip.json",
        message: Some(d05),
        raw_text: None,
        check: Check::Request {
            policy: ExpectedVersionPolicy::Draft01AndDraft02,
        },
        expected: "mcps.unknown_envelope_field",
    });

    // d06 — authorization-binding oneof violation: opaque-bytes carrying
    // reference-only fields (both forms present) is ambiguous.
    let mut d06 = request_unsigned("req-6", "hello");
    d06["params"]["_meta"][REQUEST_META_KEY]["authorization_binding"]
        .as_object_mut()
        .unwrap()
        .insert("authorization_system_id".into(), json!("acme-authz"));
    sign_request(&mut d06);
    out.push(Fixture {
        name: "d06_binding_oneof_violation",
        file: "d06_binding_oneof_violation.json",
        message: Some(d06),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.authorization_binding_ambiguous_bytes",
    });

    // d07 — downgrade: a valid draft-01-versioned request under a draft-02-only
    // policy is a recognized-but-forbidden profile.
    let mut d07 = request_unsigned("req-7", "hello");
    // Present as draft-01 by removing draft-02-only fields (it never reaches a
    // verifier — the policy refuses the version at dispatch).
    {
        let env = d07["params"]["_meta"][REQUEST_META_KEY]
            .as_object_mut()
            .unwrap();
        env.insert("version".into(), json!("draft-01"));
        env.remove("canonicalization_id");
        env.remove("authorization_binding");
        env.insert("authorization_hash".into(), json!("sha256:AAAA"));
    }
    out.push(Fixture {
        name: "d07_draft01_under_draft02_only_downgrade",
        file: "d07_draft01_under_draft02_only_downgrade.json",
        message: Some(d07),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.downgrade_forbidden",
    });

    // d08 — raw duplicate protected field: a literal duplicate `canonicalization_id`
    // must fail at the raw-bytes JCS domain check BEFORE serde collapses it.
    let dup = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"req-8\",\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"text\":\"hello\"}},\"_meta\":{{\"{REQUEST_META_KEY}\":{{\"version\":\"draft-02\",\"canonicalization_id\":\"{CANON_ID}\",\"canonicalization_id\":\"{CANON_ID}\",\"signer\":\"{SIGNER_ID}\",\"on_behalf_of\":\"{ON_BEHALF_OF}\",\"audience\":\"{AUDIENCE}\",\"authorization_binding\":{{\"binding_type\":\"opaque-bytes\",\"digest_alg\":\"sha256\",\"digest_value\":\"{DIGEST_VALUE}\"}},\"nonce\":\"{NONCE}\",\"issued_at\":\"{ISSUED_AT}\",\"expires_at\":\"{EXPIRES_AT}\",\"signature\":{{\"alg\":\"Ed25519\",\"key_id\":\"{SIGNER_KEY_ID}\",\"value\":\"AA\"}}}}}}}}}}"
    );
    out.push(Fixture {
        name: "d08_raw_duplicate_canon_id",
        file: "d08_raw_duplicate_canon_id.json",
        message: None,
        raw_text: Some(dup),
        check: only.clone(),
        expected: "mcps.canonicalization_failed",
    });

    // d09 — valid signed response (bound to d01's request_hash).
    let req_hash = request_hash(&{
        let mut r = request_unsigned("req-1", "hello");
        sign_request(&mut r);
        r
    })
    .expect("request_hash");
    let mut d09 = response_unsigned(&req_hash);
    sign_response(&mut d09);
    out.push(Fixture {
        name: "d09_valid_response",
        file: "d09_valid_response.json",
        message: Some(d09),
        raw_text: None,
        check: Check::Response {
            expected_request_hash: req_hash.clone(),
            expected_canonicalization_id: CANON_ID.to_string(),
        },
        expected: "verify_ok",
    });

    // d10 — response/request profile mismatch: a correctly signed response whose
    // scheme does not match the bound request's scheme.
    let mut d10 = response_unsigned(&req_hash);
    sign_response(&mut d10);
    out.push(Fixture {
        name: "d10_response_profile_mismatch",
        file: "d10_response_profile_mismatch.json",
        message: Some(d10),
        raw_text: None,
        check: Check::Response {
            expected_request_hash: req_hash.clone(),
            // The verified request used a DIFFERENT (forward-compat) scheme.
            expected_canonicalization_id: "mcps-jcs-future-floats-v2".to_string(),
        },
        expected: "mcps.canonicalization_id_mismatch",
    });

    // d11 — historical trust material: a valid request verified at a time within
    // its freshness window (near issued_at), proving verification binds the
    // issued_at context rather than depending on "current" wall-clock state.
    let mut d11 = request_unsigned("req-11", "hello");
    sign_request(&mut d11);
    out.push(Fixture {
        name: "d11_historical_trust_material",
        file: "d11_historical_trust_material.json",
        message: Some(d11),
        raw_text: None,
        check: only.clone(),
        expected: "verify_ok",
    });

    // d12 — valid signed continuation request (ADR-MCPS-047 / D4): an ordinary
    // draft-02 request carrying a well-formed `continuation` binding, signed over
    // the whole preimage. Verifies like any request; the continuation is protected.
    let prev_hash = format!("sha256:{DIGEST_VALUE}");
    let resp_hash = "sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    let mut d12 = request_unsigned("req-12", "hello");
    d12["params"]["_meta"][REQUEST_META_KEY]["continuation"] = json!({
        "type": "mcp-mrt",
        "previous_request_hash": prev_hash,
        "input_required_response_hash": resp_hash,
    });
    sign_request(&mut d12);
    out.push(Fixture {
        name: "d12_valid_continuation_request",
        file: "d12_valid_continuation_request.json",
        message: Some(d12),
        raw_text: None,
        check: only.clone(),
        expected: "verify_ok",
    });

    // d13 — continuation with an unsupported `type`, signed over it (VALID
    // signature) so the vector proves the structural check fires FIRST and is
    // distinct from a signature failure (D4 fail-closed).
    let mut d13 = request_unsigned("req-13", "hello");
    d13["params"]["_meta"][REQUEST_META_KEY]["continuation"] = json!({
        "type": "future-mrt-profile",
        "previous_request_hash": prev_hash,
        "input_required_response_hash": resp_hash,
    });
    sign_request(&mut d13);
    out.push(Fixture {
        name: "d13_continuation_type_unsupported",
        file: "d13_continuation_type_unsupported.json",
        message: Some(d13),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.continuation_type_unsupported",
    });

    // d14 — structurally malformed continuation (missing a mandatory hash), signed
    // over it: the malformed-binding token surfaces before crypto.
    let mut d14 = request_unsigned("req-14", "hello");
    d14["params"]["_meta"][REQUEST_META_KEY]["continuation"] = json!({
        "type": "mcp-mrt",
        "previous_request_hash": prev_hash,
    });
    sign_request(&mut d14);
    out.push(Fixture {
        name: "d14_continuation_malformed",
        file: "d14_continuation_malformed.json",
        message: Some(d14),
        raw_text: None,
        check: only.clone(),
        expected: "mcps.continuation_malformed",
    });

    // d15 — signed InputRequiredResult response (ADR-MCPS-047 / D2): a non-terminal
    // elicitation result verifies as an ordinary signed draft-02 response. The
    // client classifies + continues only AFTER this verifies. Bound to d09's req_hash.
    let mut d15 = response_unsigned(&req_hash);
    d15["result"]["resultType"] = json!("inputRequired");
    d15["result"]["inputRequests"] =
        json!({ "confirm": { "type": "elicitation", "message": "Delete 3 files?" } });
    d15["result"]["requestState"] = json!("eyJzdGVwIjoxfQ");
    sign_response(&mut d15);
    out.push(Fixture {
        name: "d15_signed_input_required_response",
        file: "d15_signed_input_required_response.json",
        message: Some(d15),
        raw_text: None,
        check: Check::Response {
            expected_request_hash: req_hash.clone(),
            expected_canonicalization_id: CANON_ID.to_string(),
        },
        expected: "verify_ok",
    });

    out
}

// ---------------------------------------------------------------------------
// The harness.
// ---------------------------------------------------------------------------

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("draft-02")
}

/// Run a fixture's verification and return the observed outcome as a wire token.
fn observe(fixture: &Fixture) -> String {
    let raw: Vec<u8> = match (&fixture.message, &fixture.raw_text) {
        (Some(msg), _) => serde_json::to_vec(msg).expect("serialize"),
        (None, Some(text)) => text.clone().into_bytes(),
        (None, None) => panic!("fixture {} has neither message nor raw_text", fixture.name),
    };
    let result: Result<(), McpsError> = match &fixture.check {
        Check::Request { policy } => {
            let mut replay = InMemoryReplayCache::new(SKEW);
            mcps_core::verify_request_dispatch(
                &raw,
                &signer_resolver(),
                &mut replay,
                &config(),
                ISSUED_EPOCH + 60,
                *policy,
            )
            .map(|_| ())
        }
        Check::Response {
            expected_request_hash,
            expected_canonicalization_id,
        } => verify_response_draft02(
            &raw,
            &server_resolver(),
            expected_request_hash,
            expected_canonicalization_id,
        )
        .map(|_| ()),
    };
    match result {
        Ok(()) => "verify_ok".to_string(),
        Err(e) => e.wire_code().to_string(),
    }
}

/// Deterministic pretty JSON with sorted keys + trailing newline (stable files).
fn to_sorted_pretty(value: &Value) -> String {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut b: std::collections::BTreeMap<String, Value> = Default::default();
                for (k, v) in map {
                    b.insert(k.clone(), sort(v));
                }
                serde_json::to_value(b).unwrap()
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    let mut s = serde_json::to_string_pretty(&sort(value)).expect("pretty");
    s.push('\n');
    s
}

/// The committed wire body for a fixture (the message, pretty-printed, or the
/// raw text verbatim).
fn fixture_file_body(fixture: &Fixture) -> String {
    match (&fixture.message, &fixture.raw_text) {
        (Some(msg), _) => to_sorted_pretty(msg),
        (None, Some(text)) => format!("{text}\n"),
        _ => unreachable!(),
    }
}

/// The manifest entry for a fixture (ADR-MCPS-042 schema).
fn manifest_entry(fixture: &Fixture) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("name".into(), json!(fixture.name));
    entry.insert("file".into(), json!(fixture.file));
    entry.insert("expected".into(), json!(fixture.expected));
    entry.insert("envelope_version".into(), json!("draft-02"));

    match &fixture.check {
        Check::Request { policy } => {
            entry.insert("kind".into(), json!("request"));
            let (accepted, downgrade): (Vec<&str>, bool) = match policy {
                ExpectedVersionPolicy::Draft02Only => (vec!["draft-02"], true),
                ExpectedVersionPolicy::Draft01AndDraft02 => (vec!["draft-01", "draft-02"], false),
            };
            entry.insert(
                "version_policy".into(),
                json!({ "accepted_versions": accepted, "downgrade": downgrade }),
            );
        }
        Check::Response {
            expected_request_hash,
            expected_canonicalization_id,
        } => {
            entry.insert("kind".into(), json!("response"));
            entry.insert("expected_request_hash".into(), json!(expected_request_hash));
            entry.insert(
                "expected_canonicalization_id".into(),
                json!(expected_canonicalization_id),
            );
        }
    }

    // canonicalization_id is required whenever a draft-02 envelope is present
    // (all fixtures here except the raw-malformed one, which has no parseable
    // envelope but still declares the intended scheme for the harness).
    entry.insert("canonicalization_id".into(), json!(CANON_ID));

    // The frozen static oracle — present for every SIGNED fixture whose
    // canonicalization succeeds. Absent for the float-rejection and raw-duplicate
    // vectors (no preimage exists) and the downgrade vector (unsigned; it fails
    // at policy dispatch before any signing is relevant).
    let has_oracle = !matches!(
        fixture.name,
        "d03_int53_float_rejected"
            | "d08_raw_duplicate_canon_id"
            | "d07_draft01_under_draft02_only_downgrade"
    );
    if has_oracle {
        let oracle = match &fixture.check {
            Check::Request { .. } => oracle_for_request(fixture.message.as_ref().unwrap()),
            Check::Response { .. } => oracle_for_response(fixture.message.as_ref().unwrap()),
        };
        entry.insert("oracle".into(), oracle);
    }
    Value::Object(entry)
}

/// Generator: (re)write the committed corpus + manifest. Ignored in normal runs;
/// run deliberately after a reviewed change to the corpus.
#[test]
#[ignore]
fn write_draft02_fixtures() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).expect("create vectors/draft-02");
    let mut manifest = Vec::new();
    for fixture in corpus() {
        std::fs::write(dir.join(fixture.file), fixture_file_body(&fixture)).expect("write fixture");
        manifest.push(manifest_entry(&fixture));
    }
    let manifest_doc = json!({
        "schema": "mcps-draft-02-conformance/v1",
        "envelope_version": "draft-02",
        "canonicalization_id": CANON_ID,
        "note": "ADR-MCPS-042 — separate frozen draft-02 corpus with static interop oracle. \
                 draft-01 corpus is untouched. Regenerate via `cargo test --test \
                 draft02_vectors_test write_draft02_fixtures -- --ignored`.",
        "vectors": manifest,
    });
    std::fs::write(dir.join("manifest.json"), to_sorted_pretty(&manifest_doc))
        .expect("write manifest");
}

/// Drift guard: every committed fixture byte-equals the regenerated one (the
/// corpus is frozen and reproducible).
#[test]
fn committed_corpus_matches_regenerated() {
    let dir = vectors_dir();
    for fixture in corpus() {
        let path = dir.join(fixture.file);
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read committed {path:?}: {e} (run write_draft02_fixtures)")
        });
        assert_eq!(
            committed,
            fixture_file_body(&fixture),
            "committed fixture {} drifted from the regenerated bytes",
            fixture.name
        );
    }
}

/// Black-box verification: every fixture produces exactly its expected wire code
/// (or `verify_ok`) through the public verifier API — never a printed diagnostic.
#[test]
fn every_fixture_verifies_to_its_expected_wire_code() {
    for fixture in corpus() {
        let observed = observe(&fixture);
        assert_eq!(
            observed, fixture.expected,
            "fixture {} expected {} but observed {}",
            fixture.name, fixture.expected, observed
        );
    }
}

/// Static interop oracle: the committed manifest's `oracle` fields equal the
/// recomputed preimage bytes / digest / signature / request_hash — the
/// cross-implementation ground truth, asserted as bytes and hashes.
#[test]
fn static_oracle_matches_recomputed_bytes() {
    let dir = vectors_dir();
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json"))
            .expect("read manifest (run write_draft02_fixtures)"),
    )
    .expect("parse manifest");
    let entries = manifest["vectors"].as_array().expect("vectors array");

    let mut checked = 0;
    for fixture in corpus() {
        let entry = entries
            .iter()
            .find(|e| e["name"] == json!(fixture.name))
            .unwrap_or_else(|| panic!("manifest missing {}", fixture.name));
        let Some(oracle) = entry.get("oracle") else {
            continue; // malformed-before-preimage fixtures carry no oracle.
        };
        let message = fixture
            .message
            .as_ref()
            .expect("oracle fixture has a message");
        let recomputed = match &fixture.check {
            Check::Request { .. } => oracle_for_request(message),
            Check::Response { .. } => oracle_for_response(message),
        };
        assert_eq!(
            oracle, &recomputed,
            "oracle for {} drifted from the recomputed preimage/digest/signature",
            fixture.name
        );
        checked += 1;
    }
    assert!(
        checked >= 7,
        "expected a healthy set of oracle-backed fixtures, got {checked}"
    );
}

/// The draft-01 corpus is provably untouched: its manifest is a sibling
/// directory and contains no draft-02 fields (the ADR-MCPS-041 no-leak property
/// made mechanical by the separate-corpus structure).
#[test]
fn draft01_corpus_is_separate_and_untouched() {
    let draft01_manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("manifest.json");
    let body = std::fs::read_to_string(&draft01_manifest).expect("read draft-01 manifest");
    assert!(
        !body.contains("draft-02") && !body.contains("authorization_binding"),
        "the draft-01 manifest must carry no draft-02 surface"
    );
}
