//! End-to-end POSITIVE happy-path test (MCPS-049, MCPS-EPIC-P6 Child Issue 5).
//!
//! This is the COHESIVE good path: the demo [`DemoHostClient`] (the stateful
//! `HostSession` client, NOT the bare `HostSigner`) signs ONE authorized
//! `list_files` request; the policy-enabled demo proxy verifies the Core
//! envelope, checks freshness/replay, evaluates Phase 5 authorization (allow),
//! strips the external MCP-S request envelope, injects the sidecar-owned verified
//! context, forwards to the REAL `mcps-demo-fileserver` inner subprocess, signs
//! the inner result, and the client verifies that signed response against the
//! `request_hash` it STORED at sign time.
//!
//! It proves, in one flow:
//!   * the fixture entries of the allowed path come back (`q1.txt`, `q2.txt`);
//!   * the inner subprocess WAS reached (the capturing [`InnerLogSink`] records
//!     `inner_*` lifecycle events) and the proxy SIGNED the response
//!     (`inner_response_signed`);
//!   * [`DemoHostClient::verify_response`] accepts the signed response against the
//!     STORED request hash (no caller-supplied expected hash); and
//!   * the client's pending count returns to 0 (success-path eviction).
//!
//! The pieces are the ones built by #3924 (client), #3925 (proxy wiring), and
//! #3926 (authorization). Nothing is reinvented here; this is the assembly.
//!
//! The inner binary + the `demo_root/` fixture are delivered via Bazel runfiles
//! (BUILD `data` deps); nothing here hardcodes an absolute path or uses cargo.

use std::path::PathBuf;
use std::sync::Arc;

use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_demo::build_demo_proxy_with_policy;
use mcps_demo::demo_policy_evaluator;
use mcps_demo::demo_revocation_source;
use mcps_demo::mint_demo_grant;
use mcps_demo::DemoGrant;
use mcps_demo::DemoGrantSpec;
use mcps_demo::DemoHostClient;
use mcps_demo::DemoProxyConfig;
use mcps_host::FixedClock;
use mcps_host::HostSigner;
use mcps_host::SeededNonceSource;
use mcps_proxy::InnerLogSink;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";

// Fixed clock: 2026-05-28T20:00:00Z. The session stamps issued_at/expires_at
// from this; the proxy verifies at the same instant + a small offset.
const NOW_UNIX: i64 = 1_779_998_400;
// Grant validity window straddling NOW.
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

/// The one path the demo grant authorizes; its committed fixture listing.
const ALLOWED_PATH: &str = "reports";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[42u8; 32])
}

/// The instant the proxy verifies at: inside the session's freshness window.
fn now() -> i64 {
    NOW_UNIX + 60
}

fn host_signer() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// The demo CLIENT (HostSession), at the fixed clock + a seeded nonce source.
fn client() -> DemoHostClient<FixedClock, SeededNonceSource> {
    DemoHostClient::with_defaults(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
}

/// A resolver holding BOTH the request-signer key (Core verification) and the
/// grant-issuer key (policy signature check) — the proxy reuses one resolver.
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
    r
}

/// The resolver the CLIENT uses to verify the proxy's signed response.
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

/// The demo grant authorizing `list_files` on exactly `ALLOWED_PATH`.
fn demo_grant() -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        allowed_path: ALLOWED_PATH.to_string(),
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "demo-rev-positive".to_string(),
    };
    mint_demo_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint demo grant")
}

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var against the runfiles roots, returning the first that exists.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn inner_binary() -> String {
    resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}

fn demo_root() -> String {
    resolve_runfile("DEMO_ROOT_README")
        .parent()
        .expect("readme.txt has a parent")
        .to_string_lossy()
        .into_owned()
}

/// A capturing lifecycle sink: the `inner_*` event tags prove the inner
/// subprocess was reached and the proxy signed the response.
#[derive(Default)]
struct CapturingSink {
    events: std::sync::Mutex<Vec<String>>,
}

impl InnerLogSink for CapturingSink {
    fn log(&self, _inner_identity: &str, event: &mcps_proxy::InnerLogEvent) {
        self.events.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}

impl CapturingSink {
    fn event_tags(&self) -> Vec<String> {
        self.events.lock().expect("lock").clone()
    }
    fn has(&self, tag: &str) -> bool {
        self.event_tags().iter().any(|t| t == tag)
    }
}

fn build_proxy(sink: Arc<CapturingSink>) -> mcps_proxy::Proxy {
    build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_binary: inner_binary(),
            demo_root: demo_root(),
            server_signing_key: server_key(),
            server_signer: SERVER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        },
        Box::new(inbound_resolver()),
        sink,
        demo_policy_evaluator(),
        Box::new(demo_revocation_source()),
    )
    .expect("policy-enabled demo proxy builds against the resolved binary + demo_root")
}

#[test]
fn authorized_list_files_round_trips_client_through_proxy_to_inner() {
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink));
    let grant = demo_grant();
    let authorization_hash = grant.authorization_hash().expect("authorization_hash");

    // The CLIENT (HostSession) signs the authorized list_files request: nonce
    // from the seeded RNG, freshness from the fixed clock, the grant attached.
    let mut client = client();
    let id = Value::String("req-positive-1".to_string());
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("list_files".to_string()));
    params.insert("arguments".to_string(), json!({ "path": ALLOWED_PATH }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));

    let request = client
        .sign_request(&id, "tools/call", params, ON_BEHALF_OF, AUDIENCE, &authorization_hash)
        .expect("client signs the authorized list_files");

    // The client stored exactly one pending request, keyed by id.
    assert_eq!(client.pending_count(), 1);
    let stored_hash = client
        .stored_request_hash(&id)
        .expect("a hash was stored under the request id")
        .to_string();

    // Drive the FULL proxy path: verify -> freshness/replay -> authorize (allow)
    // -> strip envelope -> inject verified context -> inner list_files -> sign.
    let response = proxy.handle(&request, now());

    // The authorized request reached the inner subprocess and the proxy signed
    // the response.
    assert!(
        sink.has("inner_spawned"),
        "authorized request must spawn the inner: {:?}",
        sink.event_tags()
    );
    assert!(
        sink.has("inner_request_forwarded"),
        "verified context must be forwarded to the inner: {:?}",
        sink.event_tags()
    );
    assert!(
        sink.has("inner_response_signed"),
        "the proxy must sign the inner result: {:?}",
        sink.event_tags()
    );

    // The CLIENT verifies the signed response against the STORED request hash
    // (never a caller-supplied expected hash) and binds it.
    let parsed: Value = serde_json::from_slice(&response).expect("parse response");
    assert!(parsed.get("error").is_none(), "response: {parsed}");
    let verified = client
        .verify_response(&response, &server_resolver())
        .expect("client verifies the signed response against the stored request hash");
    assert_eq!(verified.server_signer(), SERVER);
    assert_eq!(
        verified.request_hash(), stored_hash,
        "the verified response binds to the request hash the client stored"
    );

    // Success-path eviction: the pending id is free again.
    assert_eq!(client.pending_count(), 0);

    // The fixture entries of the allowed path came back.
    let entries = parsed["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["q1.txt", "q2.txt"]);
}
