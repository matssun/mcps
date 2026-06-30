//! MCPS-44 (#191): the first VERIFIED signed exchange is proof+discovery —
//! ProvenSupport is minted only from a real VerifiedResponse, and an advisory
//! advert (present, stripped, or tampered) never changes the capability verdict.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::evaluate_capability;
use mcps_client_core::parse_legacy_advert;
use mcps_client_core::verify_signed_response;
use mcps_client_core::CapabilityPolicy;
use mcps_client_core::CapabilityVerdict;
use mcps_client_core::ExchangeCapability;
use mcps_client_core::ProvenSupport;
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

fn verified_response() -> mcps_core::VerifiedResponse {
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
    verify_signed_response(
        &bytes,
        &resolver,
        &ResponseExpectation::new(signed.request_hash(), CANONICALIZATION_ID_INT53_V1),
    )
    .expect("verified")
}

#[test]
fn first_verified_exchange_is_proof_and_discovery() {
    let verified = verified_response();
    let proof = ProvenSupport::from_verified_response(&verified);
    assert_eq!(proof.server_signer(), SERVER_SIGNER);
}

#[test]
fn verdict_is_satisfies_for_the_verified_draft02_exchange() {
    // The exchange we actually verified used draft-02 + the int53 scheme.
    let exchange = ExchangeCapability {
        version: VERSION_DRAFT_02.to_string(),
        canonicalization_id: Some(CANONICALIZATION_ID_INT53_V1.to_string()),
    };
    assert_eq!(
        evaluate_capability(&exchange, &CapabilityPolicy::draft02_only()),
        CapabilityVerdict::SatisfiesPolicy
    );
}

#[test]
fn stripped_or_tampered_advert_does_not_change_the_verdict() {
    let exchange = ExchangeCapability {
        version: VERSION_DRAFT_02.to_string(),
        canonicalization_id: Some(CANONICALIZATION_ID_INT53_V1.to_string()),
    };
    let policy = CapabilityPolicy::draft02_only();
    let baseline = evaluate_capability(&exchange, &policy);

    // Stripped: capabilities carry no advert at all.
    assert!(parse_legacy_advert(&json!({ "experimental": {} })).is_none());
    assert_eq!(evaluate_capability(&exchange, &policy), baseline);

    // Tampered: an advert claiming only legacy draft-01 support (a downgrade hint).
    let tampered = json!({ "experimental": { "se.syncom/mcps": { "versions": ["draft-01"] } } });
    let advert = parse_legacy_advert(&tampered).unwrap();
    assert_eq!(advert.versions, vec!["draft-01".to_string()]);
    // The verdict (driven by the verified exchange) is unchanged — no downgrade.
    assert_eq!(evaluate_capability(&exchange, &policy), baseline);
}
