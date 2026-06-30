//! MCPS-42 (#189): the AcceptMcps path needs a real `VerifiedResponse` (its
//! constructor is private to mcps-core), so this integration test produces one by
//! actually verifying a signed response, then asserts the enforcement engine
//! accepts it in BOTH normative modes. The absence/invalid/fail-closed matrix is
//! exhaustively unit-tested in `src/enforcement.rs`.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::classify_response_result;
use mcps_client_core::decide;
use mcps_client_core::verify_signed_response;
use mcps_client_core::EnforcementDecision;
use mcps_client_core::EnforcementMode;
use mcps_client_core::EvidenceOutcome;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::ResponseExpectation;
use mcps_core::response_signing_preimage;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::{
    CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";

fn verified_outcome() -> EvidenceOutcome {
    let client_key = SigningKey::from_seed_bytes(&CLIENT_SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        "did:example:client",
        "client-key-1",
        "user:alice",
        SERVER_SIGNER,
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    let signed =
        build_signed_tool_call(&json!("req-1"), "ping", json!({}), &inputs, &client_key).unwrap();

    let server_key = SigningKey::from_seed_bytes(&SERVER_SEED);
    let mut object = json!({
        "jsonrpc": "2.0", "id": "req-1",
        "result": { "content": [], "_meta": { RESPONSE_META_KEY: {
            "version": VERSION_DRAFT_02,
            "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
            "request_hash": signed.request_hash(),
            "server_signer": SERVER_SIGNER,
            "issued_at": "2026-06-30T20:00:01Z",
            "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
        }}}
    });
    let preimage = response_signing_preimage(&object).unwrap();
    object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(server_key.sign(&preimage));
    let bytes = serde_json::to_vec(&object).unwrap();

    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SERVER_SIGNER, SERVER_KEY_ID, server_key.public_key());
    let expectation = ResponseExpectation::new(signed.request_hash(), CANONICALIZATION_ID_INT53_V1);

    classify_response_result(verify_signed_response(&bytes, &resolver, &expectation))
}

#[test]
fn verified_exchange_is_accepted_in_both_modes() {
    let outcome = verified_outcome();
    assert!(matches!(outcome, EvidenceOutcome::Verified(_)));
    for mode in [
        EnforcementMode::RequireMcps,
        EnforcementMode::AllowLegacyExplicit,
    ] {
        // The legacy allowlist is irrelevant for a verified exchange.
        assert_eq!(
            decide(mode, false, &outcome),
            EnforcementDecision::AcceptMcps
        );
        assert_eq!(
            decide(mode, true, &outcome),
            EnforcementDecision::AcceptMcps
        );
    }
}
