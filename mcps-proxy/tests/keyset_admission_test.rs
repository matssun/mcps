// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-022 conformance: per-node / shared response-signing identity admitted
//! through the real Core `verify_response` pipeline.
//!
//! These are black-box vectors: a server node signs a genuine response envelope,
//! and a client verifies it using a [`KeySetTrustResolver`] anchored on an
//! explicit authorized key set. The point is to prove the ADR-022 admission rules
//! hold end-to-end through Core's verification (step 5 trust resolution), not just
//! in the resolver's own unit tests — and that they map onto the frozen wire
//! taxonomy (`mcps.actor_binding_failed`) with no new error or `_meta` key.

use mcps_core::error::McpsError;
use mcps_core::ids::RESPONSE_META_KEY;
use mcps_core::pipeline::verify_response;
use mcps_core::response_signing_preimage;
use mcps_core::SigningKey;
use mcps_proxy::trust_cache::system_clock;
use mcps_proxy::AuthorizedKeyEntry;
use mcps_proxy::AuthorizedKeySet;
use mcps_proxy::BoundedTrustCache;
use mcps_proxy::KeySetTrustResolver;
use mcps_proxy::KeyStatus;
use serde_json::json;
use serde_json::Value;

const AUDIENCE: &str = "did:example:server-1";
const REQUEST_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

const SEED_NODE_A: [u8; 32] = [10u8; 32];
const SEED_NODE_B: [u8; 32] = [11u8; 32];
const SEED_UNKNOWN: [u8; 32] = [99u8; 32];

fn node_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_seed_bytes(seed)
}

/// Build a genuine signed response: a node `(server_signer, key_id)` signs the
/// response envelope over `REQUEST_HASH` with `signing_key`. `alg` is overridable
/// so the algorithm-boundary vector can present a non-Ed25519 block.
fn signed_response(
    server_signer: &str,
    key_id: &str,
    signing_key: &SigningKey,
    alg: &str,
) -> Vec<u8> {
    let mut obj: Value = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [{ "type": "text", "text": "hello" }],
            "_meta": {
                RESPONSE_META_KEY: {
                    "request_hash": REQUEST_HASH,
                    "server_signer": server_signer,
                    "issued_at": "2026-05-28T20:00:01Z",
                    "signature": { "alg": alg, "key_id": key_id, "value": null }
                }
            }
        }
    });
    // Remove the placeholder value, compute the preimage, sign, reinsert.
    obj["result"]["_meta"][RESPONSE_META_KEY]["signature"]
        .as_object_mut()
        .expect("sig obj")
        .remove("value");
    let preimage = response_signing_preimage(&obj).expect("preimage");
    let sig = signing_key.sign(&preimage);
    obj["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
    serde_json::to_vec(&obj).expect("serialize")
}

fn entry(key_id: &str, seed: &[u8; 32], status: KeyStatus) -> AuthorizedKeyEntry {
    AuthorizedKeyEntry {
        key_id: key_id.to_string(),
        public_key: node_key(seed).public_key(),
        issuer: "did:example:root".to_string(),
        audience: AUDIENCE.to_string(),
        node_label: format!("node-{key_id}"),
        valid_from: 0,
        valid_until: None,
        status,
        generation: 1,
    }
}

fn per_node_resolver(entries: Vec<AuthorizedKeyEntry>) -> KeySetTrustResolver {
    let set = AuthorizedKeySet::new(entries).expect("authorized key set");
    KeySetTrustResolver::per_node_keyset(set, AUDIENCE, system_clock())
}

#[test]
fn per_node_keyset_node_a_and_node_b_accepted() {
    let resolver = per_node_resolver(vec![
        entry("node-a", &SEED_NODE_A, KeyStatus::Active),
        entry("node-b", &SEED_NODE_B, KeyStatus::Active),
    ]);

    let resp_a = signed_response(AUDIENCE, "node-a", &node_key(&SEED_NODE_A), "Ed25519");
    let resp_b = signed_response(AUDIENCE, "node-b", &node_key(&SEED_NODE_B), "Ed25519");

    let verified_a = verify_response(&resp_a, &resolver, REQUEST_HASH).expect("node-a accepted");
    let verified_b = verify_response(&resp_b, &resolver, REQUEST_HASH).expect("node-b accepted");
    assert_eq!(verified_a.key_id, "node-a");
    assert_eq!(verified_b.key_id, "node-b");
}

#[test]
fn per_node_keyset_unknown_key_rejected() {
    // node-a is authorized; the response is signed by an UNKNOWN key presenting a
    // key_id that is not in the set.
    let resolver = per_node_resolver(vec![entry("node-a", &SEED_NODE_A, KeyStatus::Active)]);
    let rogue = signed_response(AUDIENCE, "node-rogue", &node_key(&SEED_UNKNOWN), "Ed25519");
    assert_eq!(
        verify_response(&rogue, &resolver, REQUEST_HASH),
        Err(McpsError::ActorBindingFailed)
    );
}

#[test]
fn per_node_keyset_revoked_key_rejected() {
    // node-a is present but revoked; even a correctly-signed response is rejected.
    let resolver = per_node_resolver(vec![entry("node-a", &SEED_NODE_A, KeyStatus::Revoked)]);
    let resp = signed_response(AUDIENCE, "node-a", &node_key(&SEED_NODE_A), "Ed25519");
    assert_eq!(
        verify_response(&resp, &resolver, REQUEST_HASH),
        Err(McpsError::ActorBindingFailed)
    );
}

#[test]
fn shared_remote_signer_only_shared_key_accepted() {
    let set =
        AuthorizedKeySet::new(vec![entry("shared", &SEED_NODE_A, KeyStatus::Active)]).expect("set");
    let resolver =
        KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "shared", system_clock())
            .expect("shared resolver");

    let shared_resp = signed_response(AUDIENCE, "shared", &node_key(&SEED_NODE_A), "Ed25519");
    assert!(verify_response(&shared_resp, &resolver, REQUEST_HASH).is_ok());
}

#[test]
fn shared_remote_signer_per_node_key_rejected_mixed_mode() {
    // Audience is shared-only; a per-node key (different key_id) is rejected even
    // though it is a well-formed active-looking entry in the set.
    let set = AuthorizedKeySet::new(vec![
        entry("shared", &SEED_NODE_A, KeyStatus::Active),
        entry("node-b", &SEED_NODE_B, KeyStatus::Disabled),
    ])
    .expect("set");
    let resolver =
        KeySetTrustResolver::shared_remote_signer(set, AUDIENCE, "shared", system_clock())
            .expect("shared resolver");
    let resp = signed_response(AUDIENCE, "node-b", &node_key(&SEED_NODE_B), "Ed25519");
    assert_eq!(
        verify_response(&resp, &resolver, REQUEST_HASH),
        Err(McpsError::ActorBindingFailed)
    );
}

#[test]
fn algorithm_boundary_non_ed25519_rejected_regardless_of_keyset() {
    // A non-Ed25519 signature block is rejected by Core before trust resolution;
    // ADR-022 must not create a path that admits a disallowed algorithm.
    let resolver = per_node_resolver(vec![entry("node-a", &SEED_NODE_A, KeyStatus::Active)]);
    let resp = signed_response(AUDIENCE, "node-a", &node_key(&SEED_NODE_A), "Ed448");
    assert_eq!(
        verify_response(&resp, &resolver, REQUEST_HASH),
        Err(McpsError::ResponseSigInvalid)
    );
}

#[test]
fn composes_with_bounded_trust_cache_admits_active_and_denies_unknown() {
    // ADR-021 (BoundedTrustCache) wraps the ADR-022 authorized-key-set resolver:
    // an active node key is admitted, an unknown key fails closed.
    let set =
        AuthorizedKeySet::new(vec![entry("node-a", &SEED_NODE_A, KeyStatus::Active)]).expect("set");
    let inner = KeySetTrustResolver::per_node_keyset(set, AUDIENCE, system_clock());
    let cached = BoundedTrustCache::new(Box::new(inner), 60, 5, system_clock());

    let ok = signed_response(AUDIENCE, "node-a", &node_key(&SEED_NODE_A), "Ed25519");
    assert!(verify_response(&ok, &cached, REQUEST_HASH).is_ok());

    let rogue = signed_response(AUDIENCE, "node-rogue", &node_key(&SEED_UNKNOWN), "Ed25519");
    assert_eq!(
        verify_response(&rogue, &cached, REQUEST_HASH),
        Err(McpsError::ActorBindingFailed)
    );
}
