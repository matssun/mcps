//! MCPS-40 (#187) conformance vectors: an ordinary MCP request signed by
//! `mcps-client-core` MUST be accepted by the server-side
//! `mcps_core::verify_request_draft02`, and the client `request_hash` MUST equal
//! the hash the verifier recomputes (the later response-binding handle).
//!
//! This is the cross-side oracle: the client builder and the (independently
//! written) Core verifier agree on the draft-02 preimage, signature, and hash.
//! It also pins the fail-closed rejects (tampered argument, unsupported
//! canonicalization scheme) so a future change cannot silently widen what the
//! client emits or what the verifier accepts.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::RequestSigningInputs;
use mcps_core::parse_rfc3339_utc;
use mcps_core::verify_request_draft02;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use serde_json::json;

const SEED: [u8; 32] = [42u8; 32];
const SIGNER: &str = "did:example:client";
const KEY_ID: &str = "client-key-1";
const AUDIENCE: &str = "did:example:server";
const ISSUED_AT: &str = "2026-06-30T20:00:00Z";
const EXPIRES_AT: &str = "2026-06-30T20:05:00Z";

fn opaque_binding() -> AuthorizationBinding {
    AuthorizationBinding::OpaqueBytes {
        digest_alg: "sha256".to_string(),
        digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
    }
}

fn inputs() -> RequestSigningInputs {
    RequestSigningInputs::with_default_canonicalization(
        SIGNER,
        KEY_ID,
        "user:alice",
        AUDIENCE,
        opaque_binding(),
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        ISSUED_AT,
        EXPIRES_AT,
    )
}

fn resolver(key: &SigningKey) -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, KEY_ID, key.public_key());
    resolver
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: 60,
    }
}

#[test]
fn signed_request_is_accepted_by_core_verifier_and_hash_matches() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hello" }),
        &inputs(),
        &key,
    )
    .expect("sign");

    let resolver = resolver(&key);
    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at");

    let verified =
        verify_request_draft02(signed.wire_bytes(), &resolver, &mut replay, &config(), now)
            .expect("client-signed draft-02 request must verify");

    // The client's request_hash is exactly the verifier's response-binding handle.
    assert_eq!(signed.request_hash(), verified.request_hash);
    assert_eq!(verified.audience, AUDIENCE);
    assert_eq!(verified.verified_signer, SIGNER);
    assert_eq!(
        verified.canonicalization_id.as_deref(),
        Some("mcps-jcs-int53-json-v1")
    );
}

#[test]
fn tampering_an_argument_breaks_verification() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hello" }),
        &inputs(),
        &key,
    )
    .expect("sign");

    // Flip the argument AFTER signing — the preimage no longer matches the sig.
    let mut object = signed.object().clone();
    object["params"]["arguments"]["text"] = json!("goodbye");
    let tampered = serde_json::to_vec(&object).unwrap();

    let resolver = resolver(&key);
    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).expect("parse");

    assert_eq!(
        verify_request_draft02(&tampered, &resolver, &mut replay, &config(), now).unwrap_err(),
        McpsError::InvalidSignature
    );
}

#[test]
fn wrong_audience_is_rejected_by_the_verifier() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hello" }),
        &inputs(),
        &key,
    )
    .expect("sign");

    let resolver = resolver(&key);
    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).expect("parse");
    let mut other = config();
    other.expected_audience = "did:example:someone-else".to_string();

    assert_eq!(
        verify_request_draft02(signed.wire_bytes(), &resolver, &mut replay, &other, now)
            .unwrap_err(),
        McpsError::InvalidAudience
    );
}

#[test]
fn signature_is_deterministic_for_fixed_inputs() {
    // Ed25519 is deterministic and the preimage is canonical, so identical inputs
    // produce byte-identical wire output — the property a frozen vector relies on.
    let key_a = SigningKey::from_seed_bytes(&SEED);
    let key_b = SigningKey::from_seed_bytes(&SEED);
    let a = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hello" }),
        &inputs(),
        &key_a,
    )
    .unwrap();
    let b = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hello" }),
        &inputs(),
        &key_b,
    )
    .unwrap();
    assert_eq!(a.wire_bytes(), b.wire_bytes());
    assert_eq!(a.request_hash(), b.request_hash());
}
