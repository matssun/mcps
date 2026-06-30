//! Live GCP Cloud KMS — draft-02 (v0.6) end-to-end envelope lane
//! (ADR-MCPS-028 §C + ADR-MCPS-038/039/041).
//!
//! The sibling `gcp_kms_live_test` proves a real Cloud KMS `asymmetricSign`
//! verifies under the bare `mcps-core` Ed25519 primitive. This lane closes the
//! v0.6 gap: it proves Cloud KMS can sign a COMPLETE draft-02 **envelope** — over
//! the real draft-02 signing preimage (the protected `version` +
//! `canonicalization_id` + `authorization_binding`) — that the UNMODIFIED
//! draft-02 verifier (`verify_request_draft02` / `verify_response_draft02`)
//! accepts, with tamper negatives. Same Ed25519 key the response-signing lane
//! uses; the private key never leaves KMS.
//!
//! `#[ignore]` by default; run in the live lane with
//! `cargo test --features gcp_kms_keysource --test gcp_kms_draft02_live_test -- --ignored`.
//! FAILS LOUDLY if its required configuration is absent — never a silent pass.
//!
//! Required environment (same as the response-signing lane):
//!   * `MCPS_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCPS_GCP_ACCESS_TOKEN` (bearer) or `MCPS_GCP_USE_METADATA=1`.
//!   * `MCPS_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use mcps_core::parse_rfc3339_utc;
use mcps_core::request_signing_preimage;
use mcps_core::response_signing_preimage;
use mcps_core::verify_request_draft02;
use mcps_core::verify_response_draft02;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::VerificationConfig;
use mcps_core::VerificationKey;
use mcps_core::REQUEST_META_KEY;
use mcps_core::RESPONSE_META_KEY;
use mcps_proxy::GcpKmsConfig;
use mcps_proxy::GcpKmsEd25519Backend;
use mcps_proxy::KmsResponseSigner;
use mcps_proxy::ResponseSigner;
use serde_json::json;
use serde_json::Value;

// Envelope identities (the resolver maps both to the one KMS public key).
const SIGNER_ID: &str = "did:example:gcp-kms-agent";
const SIGNER_KEY_ID: &str = "gcp-kms-key-1";
const SERVER_SIGNER_ID: &str = "did:example:gcp-kms-server";
const SERVER_KEY_ID: &str = "gcp-kms-key-1";
const AUDIENCE: &str = "did:example:gcp-kms-server";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const CANON_ID: &str = "mcps-jcs-int53-json-v1";
const DIGEST_VALUE: &str = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const SKEW: i64 = 30;

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms draft-02 lane: required env var {name} is not set — this lane must run \
             against a real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

/// Construct the live KMS signer + its public key, failing loudly if unconfigured.
fn kms_signer() -> (KmsResponseSigner, VerificationKey) {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCPS_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCPS_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCPS_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        require_env("MCPS_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    let signer = KmsResponseSigner::new(Box::new(backend));
    let pubkey = signer.response_public_key().expect("Cloud KMS public key");
    (signer, pubkey)
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn now_in_window() -> i64 {
    parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

/// An unsigned draft-02 request (opaque-bytes binding); `value` is null.
fn draft02_request_unsigned() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "req-gcp-1",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": "hello" },
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

fn draft02_response_unsigned(request_hash_value: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "req-gcp-1",
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

/// A resolver mapping a (signer, key_id) identity to the live KMS public key.
fn resolver_for(signer: &str, key_id: &str, pubkey: &VerificationKey) -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(signer, key_id, pubkey.clone());
    r
}

/// Cloud KMS signs a full draft-02 REQUEST envelope; the unmodified draft-02
/// verifier accepts it, and a post-signing tamper of a protected field is
/// rejected as an invalid signature.
#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_draft02_request_round_trip() {
    let (signer, pubkey) = kms_signer();

    let mut request = draft02_request_unsigned();
    let preimage = request_signing_preimage(&request).expect("draft-02 request preimage");
    let sig = signer
        .sign_response(&preimage)
        .expect("Cloud KMS asymmetricSign over the draft-02 request preimage");
    request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!(sig);

    let raw = serde_json::to_vec(&request).expect("serialize");
    let resolver = resolver_for(SIGNER_ID, SIGNER_KEY_ID, &pubkey);
    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified = verify_request_draft02(&raw, &resolver, &mut replay, &config(), now_in_window())
        .expect("a Cloud KMS-signed draft-02 request MUST verify under verify_request_draft02");
    assert_eq!(verified.canonicalization_id.as_deref(), Some(CANON_ID));

    // Negative — tamper a PROTECTED field (canonicalization_id is in the preimage)
    // after signing: the live signature must no longer verify.
    let mut tampered = request.clone();
    tampered["params"]["_meta"][REQUEST_META_KEY]["canonicalization_id"] = json!(CANON_ID);
    tampered["params"]["arguments"]["text"] = json!("goodbye");
    let raw_t = serde_json::to_vec(&tampered).expect("serialize");
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request_draft02(&raw_t, &resolver, &mut replay, &config(), now_in_window()),
        Err(McpsError::InvalidSignature),
        "a post-signing tamper of the signed payload must fail closed"
    );

    // Negative — wrong identity: the live signature must not verify under a key
    // the resolver maps to a DIFFERENT public key.
    let foreign = mcps_core::SigningKey::from_seed_bytes(&[0x09; 32]).public_key();
    let foreign_resolver = resolver_for(SIGNER_ID, SIGNER_KEY_ID, &foreign);
    let mut replay = InMemoryReplayCache::new(SKEW);
    assert_eq!(
        verify_request_draft02(&raw, &foreign_resolver, &mut replay, &config(), now_in_window()),
        Err(McpsError::InvalidSignature),
        "a Cloud KMS draft-02 signature must NOT verify under a foreign key"
    );
}

/// Cloud KMS signs a full draft-02 RESPONSE envelope; the unmodified draft-02
/// response verifier accepts it (bound to the request hash + scheme), and a
/// post-signing tamper is rejected.
#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_draft02_response_round_trip() {
    let (signer, pubkey) = kms_signer();

    // First sign a request and recover its request_hash to bind the response.
    let mut request = draft02_request_unsigned();
    let req_preimage = request_signing_preimage(&request).expect("request preimage");
    let req_sig = signer.sign_response(&req_preimage).expect("KMS sign request");
    request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!(req_sig);
    let raw_req = serde_json::to_vec(&request).expect("serialize");
    let req_resolver = resolver_for(SIGNER_ID, SIGNER_KEY_ID, &pubkey);
    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified_req =
        verify_request_draft02(&raw_req, &req_resolver, &mut replay, &config(), now_in_window())
            .expect("request verifies");

    // Now KMS-sign the bound draft-02 response.
    let mut response = draft02_response_unsigned(&verified_req.request_hash);
    let resp_preimage = response_signing_preimage(&response).expect("draft-02 response preimage");
    let resp_sig = signer
        .sign_response(&resp_preimage)
        .expect("Cloud KMS asymmetricSign over the draft-02 response preimage");
    response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = json!(resp_sig);
    let raw_resp = serde_json::to_vec(&response).expect("serialize");

    let server_resolver = resolver_for(SERVER_SIGNER_ID, SERVER_KEY_ID, &pubkey);
    let verified_resp = verify_response_draft02(
        &raw_resp,
        &server_resolver,
        &verified_req.request_hash,
        verified_req.canonicalization_id.as_deref().unwrap(),
    )
    .expect("a Cloud KMS-signed draft-02 response MUST verify and bind the request");
    assert_eq!(verified_resp.server_signer(), SERVER_SIGNER_ID);

    // Negative — tamper the signed response body after signing.
    let mut tampered = response.clone();
    tampered["result"]["content"][0]["text"] = json!("tampered");
    let raw_t = serde_json::to_vec(&tampered).expect("serialize");
    assert_eq!(
        verify_response_draft02(
            &raw_t,
            &server_resolver,
            &verified_req.request_hash,
            verified_req.canonicalization_id.as_deref().unwrap(),
        ),
        Err(McpsError::ResponseSigInvalid),
        "a post-signing tamper of the response must fail closed"
    );
}
