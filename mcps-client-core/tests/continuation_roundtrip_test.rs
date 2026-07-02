//! ADR-MCPS-047 continuation-binding cross-side oracle: a continuation request
//! signed by `mcps-client-core` (with a `continuation` binding inside the signed
//! preimage) MUST be accepted by the server-side `mcps_core::verify_request_draft02`
//! — the same verify path the proxy PEP uses — and any tampering of, or defect in,
//! the continuation binding MUST fail closed.
//!
//! This pins the server-side story (implementation-plan step 6): the continuation
//! object rides the ordinary draft-02 request verification, so a malformed / typed-
//! wrong / mismatched binding is rejected with no bespoke proxy code.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::RequestSigningInputs;
use mcps_core::build_mcp_mrt_continuation;
use mcps_core::parse_rfc3339_utc;
use mcps_core::verify_request_draft02;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::REQUEST_META_KEY;
use serde_json::json;

const SEED: [u8; 32] = [42u8; 32];
const SIGNER: &str = "did:example:client";
const KEY_ID: &str = "client-key-1";
const AUDIENCE: &str = "did:example:server";
const ISSUED_AT: &str = "2026-06-30T20:00:00Z";
const EXPIRES_AT: &str = "2026-06-30T20:05:00Z";
const PREV_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const RESP_HASH: &str = "sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

fn opaque_binding() -> AuthorizationBinding {
    AuthorizationBinding::OpaqueBytes {
        digest_alg: "sha256".to_string(),
        digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
    }
}

fn continuation_inputs() -> RequestSigningInputs {
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
    .with_continuation(build_mcp_mrt_continuation(PREV_HASH, RESP_HASH))
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

fn sign_continuation() -> mcps_client_core::SignedRequest {
    let key = SigningKey::from_seed_bytes(&SEED);
    build_signed_tool_call(
        &json!("cont-1"),
        "delete_files",
        json!({ "inputResponses": { "confirm": true }, "requestState": "eyJzdGVwIjoxfQ" }),
        &continuation_inputs(),
        &key,
    )
    .expect("sign continuation")
}

#[test]
fn signed_continuation_is_accepted_by_the_server_verify_path() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = sign_continuation();
    // The continuation binding is inside the signed preimage.
    let cont = &signed.object()["params"]["_meta"][REQUEST_META_KEY]["continuation"];
    assert_eq!(cont["type"], "mcp-mrt");
    assert_eq!(cont["previous_request_hash"], PREV_HASH);
    assert_eq!(cont["input_required_response_hash"], RESP_HASH);

    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).unwrap();
    let verified = verify_request_draft02(
        signed.wire_bytes(),
        &resolver(&key),
        &mut replay,
        &config(),
        now,
    )
    .expect("server must accept a well-formed signed continuation");
    assert_eq!(signed.request_hash(), verified.request_hash);
}

#[test]
fn tampering_the_continuation_hash_breaks_the_signature() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = sign_continuation();
    // Swap the response-hash binding AFTER signing to a different (still well-formed)
    // hash id: the structural check passes but the signed preimage no longer matches.
    let mut object = signed.object().clone();
    object["params"]["_meta"][REQUEST_META_KEY]["continuation"]["input_required_response_hash"] =
        json!(PREV_HASH);
    let tampered = serde_json::to_vec(&object).unwrap();

    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).unwrap();
    assert_eq!(
        verify_request_draft02(&tampered, &resolver(&key), &mut replay, &config(), now)
            .unwrap_err(),
        McpsError::InvalidSignature
    );
}

#[test]
fn structurally_malformed_continuation_fails_closed_before_signature() {
    let key = SigningKey::from_seed_bytes(&SEED);
    let signed = sign_continuation();
    // Remove a mandatory field: the structural validator fires before the signature
    // check, so the precise taxonomy token surfaces (not a generic sig failure).
    let mut object = signed.object().clone();
    object["params"]["_meta"][REQUEST_META_KEY]["continuation"]
        .as_object_mut()
        .unwrap()
        .remove("previous_request_hash");
    let malformed = serde_json::to_vec(&object).unwrap();

    let mut replay = InMemoryReplayCache::new(60);
    let now = parse_rfc3339_utc(ISSUED_AT).unwrap();
    assert_eq!(
        verify_request_draft02(&malformed, &resolver(&key), &mut replay, &config(), now)
            .unwrap_err(),
        McpsError::ContinuationMalformed
    );
}
