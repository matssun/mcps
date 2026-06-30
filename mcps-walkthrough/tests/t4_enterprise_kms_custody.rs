//! Tier T4 — "Enterprise key custody" (ADR-MCPS-045).
//!
//! Persona: a larger enterprise that will not let a private signing key touch
//! disk. BOTH object-signing identities live in GCP Cloud KMS, non-exporting: the
//! client proxy signs every request with a Cloud KMS key, and the server PEP signs
//! every response with a DISTINCT Cloud KMS key. The harness fetches both public
//! keys from KMS to wire trust (the client key into the server's `--trust`, the
//! server key into the client's `--server-pubkey`) — the same backend that signs.
//!
//! What this tier adds over T3: the one new concept is KEY CUSTODY. Everything
//! else (the real four-hop, mTLS-on-loopback, draft-02 verify-and-serve) is
//! unchanged — only the two signing keys move from fixture seeds to the cloud.
//!
//! This is the INTEGRATED four-hop the component KMS lanes (server object-signing,
//! client signer) each proved in isolation; here both run together over one real
//! socket. It is LIVE and `#[ignore]`d: it needs real Cloud KMS credentials and is
//! run from the cloud script (`scripts/test-gcp-cloud.sh.example`), never in the
//! offline gate. It FAILS LOUDLY if its configuration is absent — never a silent
//! pass.
//!
//! Run (both CLIs must be built WITH their KMS features so the harness spawns
//! KMS-capable binaries):
//!
//! ```sh
//! cargo build -p mcps-client-proxy-cli --features gcp_kms
//! cargo build -p mcps-proxy            --features gcp_kms_keysource
//! MCPS_GCP_ACCESS_TOKEN=… \
//!   MCPS_GCP_KEY_VERSION=<server key version> \
//!   MCPS_GCP_KEY_VERSION_CLIENT=<client key version> \
//!   cargo test -p mcps-walkthrough --features gcp_kms \
//!     --test t4_enterprise_kms_custody -- --ignored --nocapture
//! ```
#![cfg(feature = "gcp_kms")]

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::SEED_TEXT;

/// Read a required env var or FAIL LOUDLY. A live lane that silently passes when
/// it was never actually pointed at the cloud is worse than no lane at all.
fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "{name} must be set — run scripts/test-gcp-cloud.sh.example with GCP credentials; \
             this live lane must FAIL LOUDLY, never silently pass"
        ),
    }
}

#[test]
#[ignore = "live GCP Cloud KMS; run from the cloud script with real credentials"]
fn both_identities_in_cloud_kms_round_trip_the_four_hop() {
    let client_key_version = require_env("MCPS_GCP_KEY_VERSION_CLIENT");
    let server_key_version = require_env("MCPS_GCP_KEY_VERSION");
    // The harness + both CLIs reach KMS with this token (or the metadata server).
    if std::env::var("MCPS_GCP_USE_METADATA").ok().as_deref() != Some("1") {
        require_env("MCPS_GCP_ACCESS_TOKEN");
    }

    let mut hop = FourHop::launch_kms(&client_key_version, &server_key_version);

    // One plain `tools/call` in → plain result out. In between, across four real
    // processes: the request was signed by the CLIENT's Cloud KMS key, verified at
    // the PEP against the KMS public key the harness wired into `--trust`, served,
    // the response signed by the SERVER's Cloud KMS key, and that binding verified
    // by the client proxy against the server's KMS public key.
    let response = hop.call(&tool_call(
        "kms-1",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    let content = structured(&response)["content"]
        .as_str()
        .expect("read_file returns content");
    assert_eq!(content, SEED_TEXT, "the seeded text round-trips both cloud signatures");

    // Transparency: the ordinary client never sees an MCP-S envelope — the
    // cloud-signed response was verified and stripped by the client proxy.
    assert!(
        response["result"]["_meta"].is_null(),
        "no MCP-S envelope may leak to the ordinary client: {response}"
    );

    // The verified request actually reached the inner fileserver.
    assert!(hop.inner_spawn_count() >= 1, "the inner server must be reached");

    // A SECOND call proves both KMS signers are reusable across requests — not a
    // one-shot artifact of a single asymmetricSign call. Fresh nonce, fresh
    // deadline, both signatures re-minted in the cloud.
    let second = hop.call(&tool_call(
        "kms-2",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    assert_eq!(
        structured(&second)["content"].as_str(),
        Some(SEED_TEXT),
        "the cloud signers serve a second request too: {second}"
    );
}
