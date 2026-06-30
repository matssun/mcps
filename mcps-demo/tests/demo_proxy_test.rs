//! Integration test for the demo proxy wiring (MCPS-047, MCPS-EPIC-P6 Child 3).
//!
//! These tests drive the EXISTING `mcps-proxy` serving path IN-PROCESS while it
//! launches the REAL `mcps-demo-fileserver` binary as its inner stdio
//! subprocess. The full signed happy-path round trip is #3927 and the negative
//! suite is #3928; here we prove the wiring + the inner-launch / isolation /
//! verified-context-injection guarantees of Child Issue 3:
//!
//!   1. the proxy spawns `mcps-demo-fileserver` and a verified request reaches
//!      it (a `tools/list` flows through and returns the demo tool);
//!   2. a request carrying caller-supplied `.verified` metadata has that block
//!      stripped before the inner server sees it — the sidecar-owned verified
//!      context is what arrives (sole-writer);
//!   3. the inner runs under the explicit working dir / minimized env and a
//!      real `list_files` listing returns the committed fixture, proving the
//!      stdout protocol stream is clean (inner stderr is captured separately).
//!
//! The inner binary + the `demo_root/` fixture are delivered via Bazel runfiles
//! (BUILD `data` deps); nothing here hardcodes an absolute path or uses cargo.

use std::path::PathBuf;
use std::sync::Arc;

use mcps_core::request_hash;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VERIFIED_META_KEY;
use mcps_demo::build_demo_proxy;
use mcps_demo::DemoProxyConfig;
use mcps_host::HostSigner;
use mcps_proxy::InnerLogSink;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}

fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var against the runfiles roots, returning the first that exists.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

/// Absolute path to the `mcps-demo-fileserver` binary in runfiles.
fn inner_binary() -> String {
    resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}

/// Absolute path to the committed `demo_root/` fixture in runfiles (the parent
/// of the delivered `readme.txt`).
fn demo_root() -> String {
    resolve_runfile("DEMO_ROOT_README")
        .parent()
        .expect("readme.txt has a parent")
        .to_string_lossy()
        .into_owned()
}

/// A capturing lifecycle sink so the test can assert on the inner-process
/// events (spawn / exit / captured stderr) without scraping real stderr.
#[derive(Default)]
struct CapturingSink {
    events: std::sync::Mutex<Vec<String>>,
    stderr: std::sync::Mutex<Vec<u8>>,
}

impl InnerLogSink for CapturingSink {
    fn log(&self, _inner_identity: &str, event: &mcps_proxy::InnerLogEvent) {
        self.events.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, captured: &[u8]) {
        self.stderr.lock().expect("lock").extend_from_slice(captured);
    }
}

impl CapturingSink {
    fn event_tags(&self) -> Vec<String> {
        self.events.lock().expect("lock").clone()
    }
    fn captured_stderr(&self) -> Vec<u8> {
        self.stderr.lock().expect("lock").clone()
    }
}

fn build_proxy(
    sink: Arc<CapturingSink>,
) -> mcps_proxy::Proxy {
    build_demo_proxy(
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
    )
    .expect("demo proxy builds against the resolved binary + demo_root")
}

#[test]
fn proxy_spawns_fileserver_and_tools_list_flows_through() {
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink));

    let request = host()
        .sign_request(
            &Value::String("req-list".to_string()),
            "tools/list",
            serde_json::Map::new(),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            "nonce-demo-list-0001",
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs tools/list");
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("request_hash");

    let response_bytes = proxy.handle(&request, now());
    let response: Value = serde_json::from_slice(&response_bytes).expect("parse response");

    // The inner subprocess was actually spawned and exited.
    let tags = sink.event_tags();
    assert!(tags.iter().any(|t| t == "inner_spawned"), "tags: {tags:?}");
    assert!(tags.iter().any(|t| t == "inner_exited"), "tags: {tags:?}");
    assert!(
        tags.iter().any(|t| t == "inner_request_forwarded"),
        "the verified request must be forwarded: {tags:?}"
    );

    // The demo fileserver's four tools came back through the proxy, and the
    // response is signed by the server key + bound to the request hash.
    assert!(response.get("error").is_none(), "response: {response}");
    let verified = verify_response(&response_bytes, &server_resolver(), &expected_hash)
        .expect("proxy response verifies + binds to request_hash");
    assert_eq!(verified.server_signer(), SERVER);
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec!["list_files", "read_file", "stat", "write_file"],
        "the four demo fileserver tools must flow through the proxy"
    );
}

#[test]
fn caller_supplied_verified_metadata_is_stripped_before_the_inner_server() {
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink));

    // Smuggle a caller-owned `.verified` block inside the SIGNED params. It
    // verifies (it is part of the signed payload) but the proxy is the sole
    // writer of `.verified`: the inner fileserver must see the SIDECAR context,
    // not the impostor one. We prove the strip+inject indirectly: a forged
    // verified block does not let the caller smuggle anything that changes the
    // listing, and the bound, signed result still carries the proxy's hash.
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("list_files".to_string()));
    params.insert("arguments".to_string(), json!({ "path": "." }));
    params.insert(
        "_meta".to_string(),
        json!({ VERIFIED_META_KEY: { "verified_signer": "did:evil:impostor", "verifier": "did:evil:impostor" } }),
    );
    let request = host()
        .sign_request(
            &Value::String("req-strip".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            "nonce-demo-strip-0001",
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs tools/call with a smuggled verified block");
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("request_hash");

    let response_bytes = proxy.handle(&request, now());
    let response: Value = serde_json::from_slice(&response_bytes).expect("parse response");

    // The request reached the inner server (it is verified) and returned a real
    // listing of the committed demo root — the smuggled `.verified` neither
    // blocked nor altered it.
    assert!(response.get("error").is_none(), "response: {response}");
    let verified = verify_response(&response_bytes, &server_resolver(), &expected_hash)
        .expect("response verifies + binds: the sidecar (not the impostor) is the verifier");
    assert_eq!(
        verified.server_signer(), SERVER,
        "the SIDECAR signs as SERVER; the impostor verifier was discarded"
    );
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    let entries = result["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["config.yaml", "data.csv", "readme.txt", "reports"]);
}

#[test]
fn inner_runs_under_explicit_workdir_and_clean_stdout_stream() {
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink));

    // list_files with a RELATIVE path: it resolves against the inner server's
    // demo root. The inner runs in the explicit working dir (the demo root) and
    // its stdout carries ONLY the JSON-RPC protocol stream — so the proxy can
    // frame, sign, and bind the result. Any inner stderr is captured separately.
    let request = host()
        .sign_tool_call(
            &Value::String("req-sub".to_string()),
            "list_files",
            json!({ "path": "reports" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            "nonce-demo-sub-0001",
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs list_files");
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("request_hash");

    let response_bytes = proxy.handle(&request, now());
    let response: Value = serde_json::from_slice(&response_bytes).expect("parse response");

    // Clean stdout protocol stream: a parseable, signed, bound response.
    assert!(response.get("error").is_none(), "response: {response}");
    verify_response(&response_bytes, &server_resolver(), &expected_hash)
        .expect("clean stdout stream yields a verifiable bound response");
    let entries = response["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["q1.txt", "q2.txt"]);

    // No protocol-error event: the inner stdout was a clean JSON-RPC frame, and
    // stderr (captured separately) never corrupted it.
    let tags = sink.event_tags();
    assert!(
        !tags.iter().any(|t| t == "inner_protocol_error"),
        "stdout protocol stream must stay clean: {tags:?}"
    );
    // The fileserver writes nothing to stderr on a successful call.
    assert!(
        sink.captured_stderr().is_empty(),
        "unexpected inner stderr: {:?}",
        String::from_utf8_lossy(&sink.captured_stderr())
    );
}
