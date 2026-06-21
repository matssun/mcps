//! Runnable NEGATIVE / security-path demo (MCPS-050, MCPS-EPIC-P6 Child Issue 6).
//!
//! The fail-closed counterpart to `demo_positive`: it drives each rejected case
//! end to end and prints ONE structured denial line per case, carrying the frozen
//! `mcps.*` reason code the proxy (or the HostSession client, for the response-
//! side cases) emitted:
//!
//! ```text
//! denial case=1_tampered_body         reason=mcps.invalid_signature        inner_reached=false
//! denial case=2_tampered_id           reason=mcps.invalid_signature        inner_reached=false
//! denial case=3_replay                reason=mcps.replay_detected          inner_reached=true
//! ...
//! ```
//!
//! Run it with:
//!
//! ```sh
//! bazel run //mcps-demo:demo_negative
//! ```
//!
//! (from `components/mcps`). The inner `mcps-demo-fileserver` binary and the
//! committed `demo_root/` fixture are delivered via Bazel runfiles; the bin
//! resolves them from the `INNER_FILESERVER_BIN` / `DEMO_ROOT_README` env vars the
//! BUILD target stamps with `$(rlocationpath ...)`. Nothing is hardcoded.
//!
//! This is a DEMO entry point: it fails LOUDLY (non-zero exit, clear message) if
//! ANY case is not rejected with the EXPECTED reason — a missing rejection is a
//! security regression, not a quiet pass. The library paths it drives never panic
//! on bad input; they fail closed with a JSON-RPC error, surfaced here.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use mcps_core::request_hash;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::REQUEST_META_KEY;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::VERIFIED_META_KEY;
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
use mcps_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const WRONG_AUDIENCE: &str = "did:example:server-OTHER";
const ON_BEHALF_OF: &str = "did:example:user-1";

const NOW_UNIX: i64 = 1_779_998_400; // 2026-05-28T20:00:00Z
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;
const ALLOWED_PATH: &str = "reports";
const UNAUTHORIZED_PATH: &str = ".";

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
    NOW_UNIX + 60
}

fn host_signer() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

fn client() -> DemoHostClient<FixedClock, SeededNonceSource> {
    DemoHostClient::with_defaults(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
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
        revocation_id: "demo-rev-negative".to_string(),
    };
    mint_demo_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint demo grant")
}

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
    fn inner_was_reached(&self) -> bool {
        self.events.lock().expect("lock").iter().any(|t| t.starts_with("inner_"))
    }
}

fn build_proxy(
    sink: Arc<CapturingSink>,
    inner_binary: &str,
    demo_root: &str,
) -> Result<Proxy, String> {
    build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_binary: inner_binary.to_string(),
            demo_root: demo_root.to_string(),
            server_signing_key: server_key(),
            server_signer: SERVER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        },
        Box::new(inbound_resolver()),
        sink as Arc<dyn InnerLogSink + Send + Sync>,
        demo_policy_evaluator(),
        Box::new(demo_revocation_source()),
    )
}

fn list_files_params(path: &str, grant: &DemoGrant) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("list_files".to_string()));
    params.insert("arguments".to_string(), json!({ "path": path }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// The structured denial reason carried on a rejected response (`error.message`),
/// or `None` for a success response.
fn denial_reason(response: &[u8]) -> Result<Option<String>, String> {
    let value: Value = serde_json::from_slice(response).map_err(|e| format!("parse: {e}"))?;
    match value.get("error") {
        None => Ok(None),
        Some(error) => Ok(Some(
            error["message"].as_str().ok_or("error.message")?.to_string(),
        )),
    }
}

/// Print + check one denial line. Fails loudly if the observed reason does not
/// equal the expected one, or if the inner-reach expectation is violated.
fn report(
    case: &str,
    expected: &str,
    observed: &str,
    inner_reached: bool,
    expect_inner_reached: bool,
) -> Result<(), String> {
    println!("denial case={case:<24} reason={observed:<36} inner_reached={inner_reached}");
    if observed != expected {
        return Err(format!("case {case}: expected reason {expected}, observed {observed}"));
    }
    if inner_reached != expect_inner_reached {
        return Err(format!(
            "case {case}: expected inner_reached={expect_inner_reached}, observed {inner_reached}"
        ));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("OK: all 10 negative cases rejected with the expected mcps.* reason");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("demo_negative FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let inner_binary = inner_binary()?;
    let demo_root = demo_root()?;
    let grant = demo_grant();
    let auth_hash = grant.authorization_hash().map_err(|e| format!("authorization_hash: {e:?}"))?;

    // Case 1: tampered request body.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-tamper-body".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["params"]["arguments"]["path"] = json!("tampered");
        let tampered = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = proxy.handle(&tampered, now());
        let reason = denial_reason(&response)?.ok_or("case 1: expected a denial")?;
        report("1_tampered_body", McpsError::InvalidSignature.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 2: tampered JSON-RPC id.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-tamper-id".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["id"] = json!("req-neg-tamper-id-SWAPPED");
        let tampered = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = proxy.handle(&tampered, now());
        let reason = denial_reason(&response)?.ok_or("case 2: expected a denial")?;
        report("2_tampered_id", McpsError::InvalidSignature.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 3: replayed request (first send dispatches; second is replay).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-replay".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let first = proxy.handle(&signed, now());
        if denial_reason(&first)?.is_some() {
            return Err("case 3: first send unexpectedly denied".to_string());
        }
        let second = proxy.handle(&signed, now());
        let reason = denial_reason(&second)?.ok_or("case 3: expected a replay denial")?;
        // The inner WAS reached by the (accepted) first send; the replay verdict
        // on the second send is the security property.
        report("3_replay", McpsError::ReplayDetected.wire_code(), &reason, sink.inner_was_reached(), true)?;
    }

    // Case 4: expired request (verified far past its freshness window).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-expired".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = proxy.handle(&signed, NOW_UNIX + 10 * 3600);
        let reason = denial_reason(&response)?.ok_or("case 4: expected a denial")?;
        report("4_expired", McpsError::ExpiredRequest.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 5: wrong audience.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-audience".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, WRONG_AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = proxy.handle(&signed, now());
        let reason = denial_reason(&response)?.ok_or("case 5: expected a denial")?;
        report("5_wrong_audience", McpsError::InvalidAudience.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 6: missing MCP-S request envelope.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-noenv".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["params"]["_meta"]
            .as_object_mut()
            .ok_or("_meta object")?
            .remove(REQUEST_META_KEY);
        let stripped = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = proxy.handle(&stripped, now());
        let reason = denial_reason(&response)?.ok_or("case 6: expected a denial")?;
        report("6_missing_envelope", McpsError::MissingEnvelope.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 7: caller-supplied `.verified` is stripped + replaced (NOT a denial:
    // the request still authorizes; the proxy's sidecar context replaces the
    // impostor and the response binds + verifies under the SERVER key).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let mut params = list_files_params(ALLOWED_PATH, &grant);
        params
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .ok_or("_meta")?
            .insert(
                VERIFIED_META_KEY.to_string(),
                json!({ "verified_signer": "did:evil:impostor", "verifier": "did:evil:impostor" }),
            );
        let id = Value::String("req-neg-verified".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", params, ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let stored = cl.stored_request_hash(&id).ok_or("stored hash")?.to_string();
        let response = proxy.handle(&signed, now());
        if denial_reason(&response)?.is_some() {
            return Err("case 7: smuggled .verified should not deny".to_string());
        }
        let verified = cl
            .verify_response(&response, &server_resolver())
            .map_err(|e| format!("case 7 verify_response: {e:?}"))?;
        if verified.server_signer() != SERVER || verified.request_hash() != stored {
            return Err("case 7: sidecar did not replace the impostor .verified".to_string());
        }
        println!(
            "denial case={:<24} reason={:<36} inner_reached={} (impostor .verified stripped; verifier={})",
            "7_caller_verified", "stripped+replaced", sink.inner_was_reached(), verified.server_signer(),
        );
    }

    // Case 8: valid signature, failed Phase 5 authorization (unauthorized path).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-unauthorized".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(UNAUTHORIZED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = proxy.handle(&signed, now());
        let reason = denial_reason(&response)?.ok_or("case 8: expected a denial")?;
        report("8_unauthorized", "mcps.authorization_scope_denied", &reason, sink.inner_was_reached(), false)?;
    }

    // Case 9: wrong response hash — the HostSession client refuses the binding.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-resphash".to_string());
        // Client signs A (stores hash A); proxy runs a DIFFERENT B (same id) and
        // signs a response bound to hash B.
        let _signed_a = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign A: {e:?}"))?;
        let signed_b = host_signer()
            .sign_request(
                &id,
                "tools/call",
                list_files_params(ALLOWED_PATH, &grant),
                ON_BEHALF_OF,
                AUDIENCE,
                &auth_hash,
                "nonce-neg-resphash-B",
                "2026-05-28T20:00:30Z",
                "2026-05-28T20:05:30Z",
            )
            .map_err(|e| format!("sign B: {e:?}"))?;
        let _ = request_hash(&serde_json::from_slice::<Value>(&signed_b).map_err(|e| format!("parse B: {e}"))?);
        let response_b = proxy.handle(&signed_b, now());
        if denial_reason(&response_b)?.is_some() {
            return Err("case 9: proxy unexpectedly denied request B".to_string());
        }
        let err = cl
            .verify_response(&response_b, &server_resolver())
            .err()
            .ok_or("case 9: client must reject the wrong-hash binding")?;
        report("9_wrong_response_hash", McpsError::ResponseHashMismatch.wire_code(), err.wire_code(), sink.inner_was_reached(), true)?;
    }

    // Case 10: invalid response signature — the HostSession client refuses it.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_binary, &demo_root)?;
        let mut cl = client();
        let id = Value::String("req-neg-respsig".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = proxy.handle(&signed, now());
        if denial_reason(&response)?.is_some() {
            return Err("case 10: proxy unexpectedly denied".to_string());
        }
        let mut value: Value = serde_json::from_slice(&response).map_err(|e| format!("parse: {e}"))?;
        let sig = value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"]
            .as_str()
            .ok_or("signature value")?
            .to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(chars.into_iter().collect());
        let corrupted = serde_json::to_vec(&value).map_err(|e| format!("serialize: {e}"))?;
        let err = cl
            .verify_response(&corrupted, &server_resolver())
            .err()
            .ok_or("case 10: client must reject the invalid response signature")?;
        report("10_bad_response_signature", McpsError::ResponseSigInvalid.wire_code(), err.wire_code(), sink.inner_was_reached(), true)?;
    }

    Ok(())
}
