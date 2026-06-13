// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-024 conformance: replay safety under MCP multi round-trip requests
//! (SEP-2322).
//!
//! ADR-024's decision is that a multi round-trip exchange is NOT a security unit:
//! each leg is an independent signed MCP-S request verified per ADR-006/020, and
//! the SEP-2322 `requestState` resume payload is opaque, client-held, untrusted
//! data that confers neither freshness nor replay-exemption nor authorization.
//!
//! These black-box vectors drive the real `verify_request` pipeline with a shared
//! replay cache across legs and prove the ADR's conformance vectors. SEP-2322's
//! field names are not locked upstream, so `requestState` is modelled as an
//! ordinary `params` member — wherever it ends up living, it is inside the signed
//! JSON-RPC object (ADR-004 signs the whole object) and is never consulted for any
//! security decision.

use mcps_core::error::McpsError;
use mcps_core::ids::REQUEST_META_KEY;
use mcps_core::request_signing_preimage;
use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use serde_json::json;
use serde_json::Value;

const SIGNER_SEED: [u8; 32] = [1u8; 32];
const SIGNER_ID: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTHORIZATION_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const ISSUED_EPOCH: i64 = 1_779_998_400;
const SKEW: i64 = 30;

// Distinct, equal-length base64url nonces — one fresh nonce per leg / retry.
const NONCE_LEG_1: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const NONCE_LEG_2: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MB";
const NONCE_RETRY: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MC";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SIGNER_SEED)
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER_ID, SIGNER_KEY_ID, signer_key().public_key());
    r
}

/// Build a signed leg with the given nonce and an optional `request_state` member
/// in `params` (the SEP-2322 resume payload, modelled as opaque app data).
fn signed_leg(id: &str, nonce: &str, request_state: Option<&str>) -> Vec<u8> {
    let mut params = json!({
        "name": "echo",
        "arguments": { "text": "hi" },
        "_meta": {
            REQUEST_META_KEY: {
                "version": "draft-01",
                "signer": SIGNER_ID,
                "on_behalf_of": ON_BEHALF_OF,
                "audience": AUDIENCE,
                "authorization_hash": AUTHORIZATION_HASH,
                "nonce": nonce,
                "issued_at": ISSUED_AT,
                "expires_at": EXPIRES_AT,
                "signature": { "alg": "Ed25519", "key_id": SIGNER_KEY_ID, "value": null }
            }
        }
    });
    if let Some(state) = request_state {
        params["requestState"] = Value::String(state.to_string());
    }
    let mut obj = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params });

    obj["params"]["_meta"][REQUEST_META_KEY]["signature"]
        .as_object_mut()
        .expect("sig obj")
        .remove("value");
    let preimage = request_signing_preimage(&obj).expect("preimage");
    let sig = signer_key().sign(&preimage);
    obj["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(sig);
    serde_json::to_vec(&obj).expect("serialize")
}

fn now() -> i64 {
    ISSUED_EPOCH + 60
}

#[test]
fn continuation_leg_with_fresh_nonce_is_accepted() {
    // A shared replay cache stands in for "any instance may continue the exchange"
    // (SEP-2567): leg 1 then leg 2, each a fresh nonce, both accepted.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let leg1 = signed_leg("req-1", NONCE_LEG_1, Some("resume-after-leg-1"));
    let leg2 = signed_leg("req-2", NONCE_LEG_2, Some("resume-after-leg-1"));

    assert!(verify_request(&leg1, &resolver(), &mut replay, &config(), now()).is_ok());
    assert!(
        verify_request(&leg2, &resolver(), &mut replay, &config(), now()).is_ok(),
        "a continuation leg with a fresh nonce must NOT be treated as a replay"
    );
}

#[test]
fn replaying_a_leg_with_its_original_nonce_is_rejected() {
    // Re-sending leg 1 verbatim (same nonce) mid-exchange is a replay.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let leg1 = signed_leg("req-1", NONCE_LEG_1, Some("s"));
    assert!(verify_request(&leg1, &resolver(), &mut replay, &config(), now()).is_ok());
    assert_eq!(
        verify_request(&leg1, &resolver(), &mut replay, &config(), now()),
        Err(McpsError::ReplayDetected)
    );
}

#[test]
fn request_state_does_not_purchase_replay_exemption() {
    // The SAME requestState echoed back with a REUSED nonce is still a replay:
    // requestState confers no freshness or replay-exemption.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let leg = signed_leg("req-1", NONCE_LEG_1, Some("identical-resume-state"));
    assert!(verify_request(&leg, &resolver(), &mut replay, &config(), now()).is_ok());

    let resumed_same_nonce = signed_leg("req-2", NONCE_LEG_1, Some("identical-resume-state"));
    assert_eq!(
        verify_request(
            &resumed_same_nonce,
            &resolver(),
            &mut replay,
            &config(),
            now()
        ),
        Err(McpsError::ReplayDetected),
        "a reused nonce is a replay regardless of the requestState payload"
    );
}

#[test]
fn forged_request_state_breaks_the_signature() {
    // requestState is inside the signed JSON-RPC object (ADR-004 signs the whole
    // object). Mutating it after signing fails verification — a forged resume
    // payload cannot ride on a captured leg's signature.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let mut obj: Value =
        serde_json::from_slice(&signed_leg("req-1", NONCE_LEG_1, Some("authentic-state")))
            .expect("parse");
    obj["params"]["requestState"] = Value::String("forged-state".to_string());
    let tampered = serde_json::to_vec(&obj).expect("serialize");

    assert_eq!(
        verify_request(&tampered, &resolver(), &mut replay, &config(), now()),
        Err(McpsError::InvalidSignature)
    );
}

#[test]
fn retry_with_a_fresh_nonce_is_accepted_but_reused_nonce_is_rejected() {
    // Availability: a dropped leg retried with a NEW nonce is accepted; the same
    // leg retried with the SAME nonce is rejected. Idempotency lives in
    // fresh-nonce-per-attempt, never in nonce reuse.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let attempt = signed_leg("req-1", NONCE_LEG_1, None);
    assert!(verify_request(&attempt, &resolver(), &mut replay, &config(), now()).is_ok());

    let retry_reused = signed_leg("req-1", NONCE_LEG_1, None);
    assert_eq!(
        verify_request(&retry_reused, &resolver(), &mut replay, &config(), now()),
        Err(McpsError::ReplayDetected)
    );

    let retry_fresh = signed_leg("req-1", NONCE_RETRY, None);
    assert!(
        verify_request(&retry_fresh, &resolver(), &mut replay, &config(), now()).is_ok(),
        "a retry with a fresh nonce must be accepted, not mistaken for a replay"
    );
}
