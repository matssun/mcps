//! MCPS-46 (#193): a request built through the `ClientSigner` custody seam (with
//! the policy gate) verifies server-side, and the evidence names the signer. Pairs
//! with the exhaustive fail-closed unit matrix in `src/signer.rs`.

use mcps_client_core::build_signed_request_with_signer;
use mcps_client_core::Environment;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::SignerPolicy;
use mcps_client_core::SoftwareSigner;
use mcps_core::parse_rfc3339_utc;
use mcps_core::verify_request_draft02;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SEED: [u8; 32] = [42u8; 32];
const SIGNER: &str = "did:example:client";
const KEY_ID: &str = "client-key-1";
const AUDIENCE: &str = "did:example:server";

#[test]
fn signer_built_request_verifies_and_names_the_signer() {
    let signer = SoftwareSigner::new(SigningKey::from_seed_bytes(&SEED), SIGNER, KEY_ID);
    let policy = SignerPolicy::new(SIGNER, Environment::Production, true);

    // inputs carry a DIFFERENT signer id on purpose — the signer identity wins.
    let inputs = RequestSigningInputs::with_default_canonicalization(
        "did:example:WRONG",
        "wrong-key",
        "user:alice",
        AUDIENCE,
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );

    let mut params = Map::new();
    params.insert("name".into(), Value::String("echo".into()));
    params.insert("arguments".into(), json!({ "text": "hi" }));

    let signed = build_signed_request_with_signer(
        &json!("req-1"),
        "tools/call",
        params,
        &inputs,
        &signer,
        &policy,
    )
    .expect("authorized + signed");

    // Evidence names the ACTUAL signer, not the inputs' bogus identity.
    let env = &signed.object()["params"]["_meta"]["se.syncom/mcps.request"];
    assert_eq!(env["signer"], json!(SIGNER));
    assert_eq!(env["signature"]["key_id"], json!(KEY_ID));

    // And the request verifies against the real signer's key.
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(
        SIGNER,
        KEY_ID,
        SigningKey::from_seed_bytes(&SEED).public_key(),
    );
    let mut replay = InMemoryReplayCache::new(60);
    let config = VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: 60,
    };
    let now = parse_rfc3339_utc("2026-06-30T20:00:00Z").unwrap();
    let verified =
        verify_request_draft02(signed.wire_bytes(), &resolver, &mut replay, &config, now).unwrap();
    assert_eq!(verified.verified_signer, SIGNER);
    assert_eq!(verified.key_id, KEY_ID);
}
