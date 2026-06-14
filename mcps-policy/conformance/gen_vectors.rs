//! Generator for the Phase 5 conformance vectors (MCPS-022, ADR-MCPS-013).
//!
//! Emits a JSON array of vectors to stdout with REAL crypto and fixed, documented
//! seeds (never random — vectors must be reproducible). Each vector is a complete
//! host-signed request (carrying the `.authorization` block) plus the world needed
//! to replay it: trust entries (request signer + grant issuer public keys), the
//! verification config, `now_unix`, revoked ids, and the expected decision.
//!
//! Run: `bazel run //components/mcps/mcps-policy:gen_phase5_vectors > \
//!   components/mcps/mcps-policy/tests/vectors/phase5_vectors.json`
//!
//! The committed output is the executable spec exercised by `vectors_test.rs`,
//! which replays each vector through `mcps_core::verify_request` (must succeed —
//! Core-level failures are Phase 1–4's vectors) and `PolicyEvaluator::evaluate`.

use mcps_core::canonicalize;
use mcps_core::sha256_hash_id;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use mcps_policy::mint_reference_grant;
use mcps_policy::GrantedOperation;
use mcps_policy::ReferenceGrantSpec;
use mcps_policy::AUTHORIZATION_META_KEY;
use mcps_policy::REFERENCE_PROFILE_ID;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

// Fixed seeds (mirrored in tests/vectors/README.md).
const SIGNER_SEED: [u8; 32] = [1u8; 32];
const ISSUER_SEED: [u8; 32] = [42u8; 32];

const SIGNER_ID: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const ISSUER_ID: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";

// Request freshness window + now (now inside the request window for every vector
// so Core verification always succeeds).
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;
// now = issued_at + 60s.
const NOW_OFFSET: i64 = 60;

// Grant validity window (valid grants are live at `now`).
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
// A future window (used only for the expired vector).
const GRANT_FUTURE_NOT_BEFORE: &str = "2026-05-28T23:00:00Z";
const GRANT_FUTURE_EXPIRES_AT: &str = "2026-05-29T00:00:00Z";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SIGNER_SEED)
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ISSUER_SEED)
}
fn now_unix() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + NOW_OFFSET
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER_ID, SIGNER_KEY_ID)
}

/// The trust entries every vector shares (request signer + grant issuer).
fn trust_entries() -> Value {
    json!([
        { "signer": SIGNER_ID, "key_id": SIGNER_KEY_ID, "public_key": signer_key().public_key().to_b64url() },
        { "signer": ISSUER_ID, "key_id": ISSUER_KEY_ID, "public_key": issuer_key().public_key().to_b64url() },
    ])
}

/// A grant spec granting `tools/call` on `echo`, valid at `now`, unless fields are
/// overridden by the caller.
fn base_spec() -> ReferenceGrantSpec {
    ReferenceGrantSpec {
        issuer: ISSUER_ID.to_string(),
        grantee: SIGNER_ID.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        operations: vec![GrantedOperation {
            method: "tools/call".to_string(),
            tool: "echo".to_string(),
            arguments: None,
        }],
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "rev-1".to_string(),
    }
}

/// Build the `.authorization` block value for given artifact bytes + profile id.
fn authorization_block(profile_id: &str, artifact_bytes: &[u8]) -> Value {
    json!({
        "profile": profile_id,
        "artifact": mcps_core::b64url_encode(artifact_bytes),
    })
}

/// Sign a `tools/call` request for `tool`/`arguments`, carrying the given
/// `.authorization` block and `authorization_hash`. Returns the parsed signed
/// request object.
#[allow(clippy::too_many_arguments)]
fn signed_request(
    nonce: &str,
    tool: &str,
    arguments: Value,
    authorization_block: Option<Value>,
    authorization_hash: &str,
) -> Value {
    let mut params = Map::new();
    params.insert("name".to_string(), json!(tool));
    params.insert("arguments".to_string(), arguments);
    if let Some(block) = authorization_block {
        let mut meta = Map::new();
        meta.insert(AUTHORIZATION_META_KEY.to_string(), block);
        params.insert("_meta".to_string(), Value::Object(meta));
    }
    let bytes = host()
        .sign_request(
            &Value::String("req-1".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs request");
    serde_json::from_slice(&bytes).expect("parse signed request")
}

/// `authorization_hash` for artifact bytes (== what the host signs over).
fn hash_of(artifact_bytes: &[u8]) -> String {
    let canon = canonicalize(artifact_bytes).expect("canonicalize artifact");
    sha256_hash_id(&canon)
}

fn vector(
    name: &str,
    description: &str,
    request: Value,
    now_offset_override: Option<&str>,
    revoked: Vec<&str>,
    expected: &str,
) -> Value {
    let now = match now_offset_override {
        Some(ts) => mcps_core::parse_rfc3339_utc(ts).expect("parse override now"),
        None => now_unix(),
    };
    json!({
        "name": name,
        "description": description,
        "request": request,
        "trust": trust_entries(),
        "config": { "expected_audience": AUDIENCE, "max_clock_skew_secs": SKEW },
        "now_unix": now,
        "revoked": revoked,
        "expected": expected,
    })
}

fn main() {
    let echo_args = json!({ "text": "hello" });
    let mut vectors: Vec<Value> = Vec::new();

    // 1. allow — fully valid grant.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-allow-0001", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "allow",
            "Valid reference grant: signer/subject/audience bound, live window, in scope.",
            req,
            None,
            vec![],
            "allow",
        ));
    }

    // 2. authorization_block_missing — signed request without the .authorization block.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let req = signed_request("nonce-noblock-001", "echo", echo_args.clone(), None, &hash_of(&artifact));
        vectors.push(vector(
            "authorization_block_missing",
            "Core verifies but no .authorization sibling block is present.",
            req,
            None,
            vec![],
            "mcps.authorization_block_missing",
        ));
    }

    // 3. authorization_profile_unsupported — unknown profile id in the block.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block("se.syncom/mcps-authz-biscuit-v1", &artifact);
        let req = signed_request("nonce-unsupp-001", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_profile_unsupported",
            "Block names a profile not registered with the verifier.",
            req,
            None,
            vec![],
            "mcps.authorization_profile_unsupported",
        ));
    }

    // 4. authorization_malformed — artifact bytes are valid base64 but not JSON.
    {
        let bad = b"this is not json";
        let block = authorization_block(REFERENCE_PROFILE_ID, bad);
        // Sign over the hash of the malformed bytes so Core passes & the evaluator
        // reaches the profile's hash computation (which canonicalizes -> fails).
        let req = signed_request("nonce-malf-0001", "echo", echo_args.clone(), Some(block), &sha256_hash_id(bad));
        vectors.push(vector(
            "authorization_malformed",
            "Artifact decodes but does not parse as a canonical JSON object.",
            req,
            None,
            vec![],
            "mcps.authorization_malformed",
        ));
    }

    // 5. authorization_hash_mismatch — attached artifact does not hash to the
    //    signed authorization_hash.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        // Sign over the hash of DIFFERENT bytes.
        let req = signed_request("nonce-hashmm-01", "echo", echo_args.clone(), Some(block), &sha256_hash_id(b"different bytes"));
        vectors.push(vector(
            "authorization_hash_mismatch",
            "sha256(attached artifact) != the signed authorization_hash.",
            req,
            None,
            vec![],
            "mcps.authorization_hash_mismatch",
        ));
    }

    // 6. authorization_signature_invalid — artifact tampered after signing.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let mut value: Value = serde_json::from_slice(&artifact).unwrap();
        value["subject"] = json!("did:evil:impostor");
        let tampered = serde_json::to_vec(&value).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &tampered);
        let req = signed_request("nonce-siginv-01", "echo", echo_args.clone(), Some(block), &hash_of(&tampered));
        vectors.push(vector(
            "authorization_signature_invalid",
            "Artifact content changed after issuer signing; hash binds the tampered bytes.",
            req,
            None,
            vec![],
            "mcps.authorization_signature_invalid",
        ));
    }

    // 7. authorization_signer_mismatch — grant.grantee != request signer.
    {
        let mut spec = base_spec();
        spec.grantee = "did:example:other-agent".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-signmm-01", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_signer_mismatch",
            "Grant grantee differs from the Core-verified request signer.",
            req,
            None,
            vec![],
            "mcps.authorization_signer_mismatch",
        ));
    }

    // 8. authorization_subject_mismatch — grant.subject != on_behalf_of.
    {
        let mut spec = base_spec();
        spec.subject = "did:example:other-user".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-subjmm-01", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_subject_mismatch",
            "Grant subject differs from the verified on_behalf_of.",
            req,
            None,
            vec![],
            "mcps.authorization_subject_mismatch",
        ));
    }

    // 9. authorization_audience_mismatch — grant.audience != audience.
    {
        let mut spec = base_spec();
        spec.audience = "did:example:other-server".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-audmm-001", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_audience_mismatch",
            "Grant audience differs from the verified audience.",
            req,
            None,
            vec![],
            "mcps.authorization_audience_mismatch",
        ));
    }

    // 10. authorization_expired — grant window is in the future relative to now.
    {
        let mut spec = base_spec();
        spec.not_before = GRANT_FUTURE_NOT_BEFORE.to_string();
        spec.expires_at = GRANT_FUTURE_EXPIRES_AT.to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-expired-1", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_expired",
            "now precedes the grant not_before (Core request window still fresh).",
            req,
            None,
            vec![],
            "mcps.authorization_expired",
        ));
    }

    // 11. authorization_revoked — revocation source lists the grant id.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-revoked-1", "echo", echo_args.clone(), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_revoked",
            "Grant revocation_id is present in the revocation source.",
            req,
            None,
            vec!["rev-1"],
            "mcps.authorization_revoked",
        ));
    }

    // 12. authorization_scope_denied — request a tool the grant does not cover.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let block = authorization_block(REFERENCE_PROFILE_ID, &artifact);
        let req = signed_request("nonce-scope-001", "delete_everything", json!({}), Some(block), &hash_of(&artifact));
        vectors.push(vector(
            "authorization_scope_denied",
            "Requested tool is outside the granted scope.",
            req,
            None,
            vec![],
            "mcps.authorization_scope_denied",
        ));
    }

    // 13. authorization_duplicate_key — artifact carries a DUPLICATE object member
    //     (issue #20, cluster 1). JCS rejects duplicates rather than last-wins
    //     dedup-and-verify; the evaluator's raw `canonicalize` hash step (and the
    //     profile's own raw canonicalize) fail closed as authorization_malformed.
    {
        let artifact = mint_reference_grant(&base_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        // Inject a second top-level `subject` member after the opening brace.
        // serde_json::Value cannot represent a duplicate, so the bytes are built
        // textually; they are otherwise well-formed JSON whose only defect is the
        // duplicate member.
        let text = String::from_utf8(artifact).expect("artifact is utf8");
        let dup = format!("{{\"subject\":\"{ON_BEHALF_OF}\",{}", &text[1..]);
        let dup_bytes = dup.into_bytes();
        let block = authorization_block(REFERENCE_PROFILE_ID, &dup_bytes);
        // Sign over the raw sha256 of the duplicate bytes (canonicalize would
        // reject them) so Core verification passes and the evaluator reaches the
        // profile's hash computation, which canonicalizes and fails closed.
        let req = signed_request(
            "nonce-dupkey-01",
            "echo",
            echo_args.clone(),
            Some(block),
            &sha256_hash_id(&dup_bytes),
        );
        vectors.push(vector(
            "authorization_duplicate_key",
            "Artifact contains a duplicate object member; JCS rejects it (never \
             last-wins dedup-and-verify).",
            req,
            None,
            vec![],
            "mcps.authorization_malformed",
        ));
    }

    let document = Value::Array(vectors);
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serialize vectors")
    );
}
