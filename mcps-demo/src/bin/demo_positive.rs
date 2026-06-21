//! Runnable positive happy-path demo (MCPS-049, MCPS-EPIC-P6 Child Issue 5).
//!
//! Drives the COHESIVE good path end to end and prints a structured
//! allow-decision line, then the returned fixture entries:
//!
//! ```text
//! HostSession (client) signs the authorized list_files request
//!   -> mcps-proxy verifies the Core envelope
//!   -> mcps-proxy checks freshness / replay
//!   -> mcps-proxy evaluates Phase 5 authorization (ALLOW)
//!   -> mcps-proxy strips the external MCP-S request envelope
//!   -> mcps-proxy injects the verified context (sole writer)
//!   -> mcps-demo-fileserver executes list_files
//!   -> mcps-proxy signs the response
//!   -> HostSession (client) verifies the response vs the STORED request hash
//! ```
//!
//! Run it with:
//!
//! ```sh
//! bazel run //mcps-demo:demo_positive
//! ```
//!
//! (from `components/mcps`). The inner `mcps-demo-fileserver` binary and the
//! committed `demo_root/` fixture are delivered via Bazel runfiles; the bin
//! resolves them from the `INNER_FILESERVER_BIN` / `DEMO_ROOT_README` env vars
//! the BUILD target stamps with `$(rlocationpath ...)`. Nothing is hardcoded and
//! the demo never holds a private key outside the signer it constructs.
//!
//! This is a DEMO entry point: it fails LOUDLY (non-zero exit, clear message) on
//! any error rather than masking it. The library paths it drives never panic on
//! bad input — they fail closed with a JSON-RPC error, which the demo surfaces.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
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
use mcps_proxy::InnerLogEvent;
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

const NOW_UNIX: i64 = 1_779_998_400; // 2026-05-28T20:00:00Z
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;
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
fn resolve_runfile(env_key: &str) -> Result<PathBuf, String> {
    let rel = std::env::var(env_key).map_err(|_| {
        format!("{env_key} must be set by the BUILD target (run via `bazel run`)")
    })?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for root_key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
        if let Ok(root) = std::env::var(root_key) {
            candidates.push(PathBuf::from(&root).join(&rel));
        }
    }
    // Under `bazel run` on this workspace, no runfiles env var is set but the cwd
    // IS the runfiles `_main` dir, so the runfiles root is its PARENT. Try the cwd
    // and its parent as roots before the bare relative path.
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(&rel));
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.join(&rel));
        }
    }
    candidates.push(PathBuf::from(&rel));
    candidates
        .into_iter()
        .find(|c| c.exists())
        .ok_or_else(|| format!("cannot locate runfile via {env_key}='{rel}'"))
}

fn inner_binary() -> Result<String, String> {
    Ok(resolve_runfile("INNER_FILESERVER_BIN")?
        .to_string_lossy()
        .into_owned())
}

fn demo_root() -> Result<String, String> {
    Ok(resolve_runfile("DEMO_ROOT_README")?
        .parent()
        .ok_or("readme.txt has no parent")?
        .to_string_lossy()
        .into_owned())
}

/// A capturing lifecycle sink so the demo can report which inner / proxy
/// lifecycle events fired during the round trip.
#[derive(Default)]
struct CapturingSink {
    events: std::sync::Mutex<Vec<String>>,
}

impl InnerLogSink for CapturingSink {
    fn log(&self, _inner_identity: &str, event: &InnerLogEvent) {
        self.events.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}

impl CapturingSink {
    fn event_tags(&self) -> Vec<String> {
        self.events.lock().expect("lock").clone()
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("demo_positive FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let inner_binary = inner_binary()?;
    let demo_root = demo_root()?;

    let grant = demo_grant();
    let authorization_hash = grant
        .authorization_hash()
        .map_err(|e| format!("authorization_hash: {e:?}"))?;

    // 1. The CLIENT (HostSession) signs the authorized list_files request.
    let mut client = DemoHostClient::with_defaults(
        HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    );
    let id = Value::String("req-positive-1".to_string());
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("list_files".to_string()));
    params.insert("arguments".to_string(), json!({ "path": ALLOWED_PATH }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));

    let request = client
        .sign_request(&id, "tools/call", params, ON_BEHALF_OF, AUDIENCE, &authorization_hash)
        .map_err(|e| format!("client sign_request: {e:?}"))?;
    let stored_hash = client
        .stored_request_hash(&id)
        .ok_or("no stored request hash after signing")?
        .to_string();

    // 2. Render + print the structured ALLOW decision through the SAME evaluator
    //    the proxy uses (verify the Core envelope, then evaluate Phase 5 authz).
    //    This is for the operator-facing log line; the proxy performs its own
    //    authoritative verification + evaluation below in `handle`.
    let resolver = inbound_resolver();
    let mut replay = InMemoryReplayCache::new(SKEW);
    let config = VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    };
    let verified = verify_request(&request, &resolver, &mut replay, &config, now())
        .map_err(|e| format!("verify_request (for log): {e:?}"))?;
    let request_value: Value =
        serde_json::from_slice(&request).map_err(|e| format!("parse request: {e}"))?;
    let decision = demo_policy_evaluator().evaluate(
        &verified,
        &request_value,
        &resolver,
        &demo_revocation_source(),
        now(),
    );
    let policy_result = if decision.is_allowed() {
        "allow".to_string()
    } else {
        format!("deny:{:?}", decision.denial())
    };
    println!(
        "allow-decision signer={} on_behalf_of={} audience={} request_hash={} authorization_hash={} method=tools/call tool=list_files path={} policy_result={}",
        verified.verified_signer,
        verified.on_behalf_of,
        verified.audience,
        verified.request_hash,
        verified.authorization_hash,
        ALLOWED_PATH,
        policy_result,
    );
    if !decision.is_allowed() {
        return Err(format!("authorization denied: {policy_result}"));
    }

    // 3. Run the FULL policy-enabled proxy: verify -> freshness/replay -> authz
    //    -> strip envelope -> inject verified context -> inner list_files -> sign.
    let sink = Arc::new(CapturingSink::default());
    let proxy = build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_binary,
            demo_root,
            server_signing_key: server_key(),
            server_signer: SERVER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        },
        Box::new(inbound_resolver()),
        Arc::clone(&sink) as Arc<dyn InnerLogSink + Send + Sync>,
        demo_policy_evaluator(),
        Box::new(demo_revocation_source()),
    )?;
    let response = proxy.handle(&request, now());

    // 4. The CLIENT verifies the signed response against the STORED request hash.
    let parsed: Value =
        serde_json::from_slice(&response).map_err(|e| format!("parse response: {e}"))?;
    if let Some(error) = parsed.get("error") {
        return Err(format!("proxy returned an error response: {error}"));
    }
    let verified_response = client
        .verify_response(&response, &server_resolver())
        .map_err(|e| format!("client verify_response: {e:?}"))?;
    if verified_response.request_hash() != stored_hash {
        return Err("verified response did not bind to the stored request hash".to_string());
    }
    if client.pending_count() != 0 {
        return Err("pending count did not return to 0 after a verified response".to_string());
    }

    // 5. Report the returned fixture entries + the lifecycle events that fired.
    let entries = parsed["result"]["structuredContent"]["entries"]
        .as_array()
        .ok_or("response has no entries array")?;
    let names: Vec<String> = entries
        .iter()
        .filter_map(|e| e["name"].as_str().map(str::to_string))
        .collect();
    println!(
        "response-verified server_signer={} request_hash={} entries={:?}",
        verified_response.server_signer(), verified_response.request_hash(), names,
    );
    println!("lifecycle-events {:?}", sink.event_tags());
    println!("OK: authorized list_files round-tripped client -> proxy -> inner -> client");
    Ok(())
}
