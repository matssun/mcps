//! Tier T2 (MCPS-045) — scoped delegated authorization: reader vs admin.
//!
//! This is the "small company, internal roles" rung of the persona ladder. It
//! drives the SAME `mcps-proxy` serving path as `demo_authorization_test`, with
//! Phase 5 (ADR-MCPS-013) policy enforcement on and the real
//! `mcps-demo-fileserver` as the inner subprocess — but here the grant carries a
//! ROLE's toolset rather than a single `list_files` path:
//!
//!   * a **reader** grant authorizes `list_files` / `read_file` / `stat`;
//!   * an **admin** grant authorizes those PLUS `write_file`.
//!
//! The one security invariant T2 proves is that scope is enforced at the
//! MCP-S boundary, BEFORE dispatch:
//!
//!   1. a reader-signed `write_file` → `mcps.authorization_scope_denied`, and the
//!      inner fileserver is NEVER reached (zero `inner_*` lifecycle events) — so
//!      nothing is written to disk;
//!   2. an admin-signed `write_file` → reaches the inner, returns a signed,
//!      request-hash-bound response, and the file actually appears on disk;
//!   3. the reader role is not "deny everything": a reader-signed `read_file` and
//!      `list_files` both reach the inner and return real results.
//!
//! "Denied never reaches the inner" is proven exactly as in
//! `demo_authorization_test`: through the proxy's own lifecycle sink (an
//! `inner_spawned` event fires only when the subprocess is launched, which a
//! denial short-circuits). The independent on-disk `--received-log` cross-check
//! is the cross-process T3 proof, not this in-process tier.
//!
//! The inner binary is delivered via Bazel runfiles (or the cargo fallback). The
//! demo root here is a per-test WRITABLE directory (not the read-only fixture),
//! since the admin path actually writes; it is seeded with one file so the
//! reader read/list positives have something real to return.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcps_core::request_hash;
use mcps_core::verify_response;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_demo::build_demo_proxy_with_policy;
use mcps_demo::demo_policy_evaluator;
use mcps_demo::demo_revocation_source;
use mcps_demo::mint_demo_role_grant;
use mcps_demo::DemoGrant;
use mcps_demo::DemoProxyConfig;
use mcps_demo::DemoRole;
use mcps_demo::DemoRoleGrantSpec;
use mcps_host::HostSigner;
use mcps_proxy::InnerLogSink;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";

// Request envelope freshness window.
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
// Grant validity window.
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

// The file the writable demo root is seeded with (for the reader read/list
// positives), plus the file the admin write test creates.
const SEED_NAME: &str = "seed.txt";
const SEED_TEXT: &str = "seeded so the reader has something real to read\n";
const ADMIN_OUT_NAME: &str = "written-by-admin.txt";
const ADMIN_OUT_TEXT: &str = "admin wrote this\n";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[42u8; 32])
}
fn now() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}

/// A resolver holding BOTH the request-signer key (Core verification) and the
/// grant-issuer key (policy signature check) — the proxy reuses one resolver.
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
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

/// Mint a grant for `role`, valid across the whole grant window. The reader and
/// admin grants differ ONLY in the toolset they enumerate ([`DemoRole::tools`]).
fn role_grant(role: DemoRole) -> DemoGrant {
    let spec = DemoRoleGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        role,
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "demo-rev-role-1".to_string(),
    };
    mint_demo_role_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint role grant")
}

/// Sign a `tools/call` for `tool` with `arguments`, attaching `grant`'s
/// `.authorization` block and binding the request to its `authorization_hash`.
fn signed_call(nonce: &str, tool: &str, arguments: Value, grant: &DemoGrant) -> Vec<u8> {
    let authorization_hash = grant.authorization_hash().expect("authorization_hash");

    let mut params = Map::new();
    params.insert("name".to_string(), json!(tool));
    params.insert("arguments".to_string(), arguments);
    let mut meta = Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));

    host()
        .sign_request(
            &Value::String(format!("req-{nonce}")),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs tools/call")
}

fn inner_binary() -> String {
    mcps_test_paths::resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}

/// A fresh WRITABLE demo root, seeded with [`SEED_NAME`]. Unlike the read-only
/// runfiles fixture, the admin path writes here. Resolution order mirrors the
/// fileserver's own write tests: `CARGO_TARGET_TMPDIR` (cargo) → `TEST_TMPDIR`
/// (bazel) → the system temp dir; a per-call counter keeps roots disjoint so
/// parallel tests never collide.
fn writable_demo_root() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .or_else(|| std::env::var_os("TEST_TMPDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = base.join(format!("mcps-demo-scope-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create writable demo root");
    std::fs::write(root.join(SEED_NAME), SEED_TEXT).expect("seed the demo root");
    root
}

/// A capturing lifecycle sink: the `inner_*` event tags it records are the proof
/// that (or that NOT) the inner subprocess was reached.
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
    /// True iff the inner subprocess was launched at all (any `inner_*` event).
    fn inner_was_reached(&self) -> bool {
        self.event_tags().iter().any(|t| t.starts_with("inner_"))
    }
}

fn build_proxy(sink: Arc<CapturingSink>, demo_root: &str) -> mcps_proxy::Proxy {
    build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_binary: inner_binary(),
            demo_root: demo_root.to_string(),
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
    .expect("policy-enabled demo proxy builds against the resolved binary + writable root")
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Run `request` through the proxy and assert the response is a real, signed,
/// request-hash-bound success that reached the inner. Returns the parsed result.
fn expect_authorized_success(
    proxy: &mcps_proxy::Proxy,
    sink: &CapturingSink,
    request: &[u8],
) -> Value {
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(request).unwrap()).expect("request_hash");
    let response = proxy.handle(request, now());

    assert!(
        sink.inner_was_reached(),
        "authorized request must reach the inner: {:?}",
        sink.event_tags()
    );
    let parsed: Value = serde_json::from_slice(&response).expect("parse response");
    assert!(parsed.get("error").is_none(), "unexpected error: {parsed}");
    verify_response(&response, &server_resolver(), &expected_hash)
        .expect("authorized response verifies + binds to request_hash");
    parsed
}

#[test]
fn reader_write_file_is_denied_before_dispatch() {
    let root = writable_demo_root();
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink), &root.to_string_lossy());
    let reader = role_grant(DemoRole::Reader);

    // The reader grant covers list/read/stat but NOT write_file → scope denied.
    let request = signed_call(
        "scope-reader-write-1",
        "write_file",
        json!({ "path": ADMIN_OUT_NAME, "content": "reader should not be able to write this" }),
        &reader,
    );
    let response = proxy.handle(&request, now());

    assert_eq!(error_message(&response), "mcps.authorization_scope_denied");
    assert!(
        !sink.inner_was_reached(),
        "denied write must NOT reach the inner: {:?}",
        sink.event_tags()
    );
    // Deny-before-dispatch means nothing was written: the file never appears.
    assert!(
        !root.join(ADMIN_OUT_NAME).exists(),
        "a denied write must leave no file on disk"
    );
}

#[test]
fn admin_write_file_succeeds_end_to_end() {
    let root = writable_demo_root();
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink), &root.to_string_lossy());
    let admin = role_grant(DemoRole::Admin);

    let request = signed_call(
        "scope-admin-write-1",
        "write_file",
        json!({ "path": ADMIN_OUT_NAME, "content": ADMIN_OUT_TEXT }),
        &admin,
    );
    expect_authorized_success(&proxy, &sink, &request);

    // The admin write reached the real fileserver and landed on disk.
    let written = std::fs::read_to_string(root.join(ADMIN_OUT_NAME)).expect("admin write on disk");
    assert_eq!(written, ADMIN_OUT_TEXT);
}

#[test]
fn reader_read_file_succeeds_end_to_end() {
    let root = writable_demo_root();
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink), &root.to_string_lossy());
    let reader = role_grant(DemoRole::Reader);

    let request = signed_call(
        "scope-reader-read-1",
        "read_file",
        json!({ "path": SEED_NAME }),
        &reader,
    );
    let parsed = expect_authorized_success(&proxy, &sink, &request);

    // The reader role IS allowed to read: the seeded text comes back.
    let content = parsed["result"]["structuredContent"]["content"]
        .as_str()
        .expect("read_file returns content");
    assert_eq!(content, SEED_TEXT);
}

#[test]
fn reader_list_files_succeeds_end_to_end() {
    let root = writable_demo_root();
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_proxy(Arc::clone(&sink), &root.to_string_lossy());
    let reader = role_grant(DemoRole::Reader);

    let request = signed_call(
        "scope-reader-list-1",
        "list_files",
        json!({ "path": "." }),
        &reader,
    );
    let parsed = expect_authorized_success(&proxy, &sink, &request);

    // The reader can list: the seeded file is among the entries.
    let entries = parsed["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert!(names.contains(&SEED_NAME), "listing should include the seed: {names:?}");
}
