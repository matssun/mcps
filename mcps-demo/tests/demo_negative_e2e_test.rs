//! Multi-process application-layer NEGATIVE suite over REAL mTLS (MCPS-057,
//! Phase 6.6, epic #3948) — the over-the-wire counterpart of the in-process
//! P6.5 negative suite (`demo_negative_test.rs`).
//!
//! Every one of the ten fail-closed cases the in-process suite proved against a
//! `Proxy` value is re-run HERE against the REAL, separately-spawned
//! `mcps_proxy_cli` OS process, reached over a REAL mTLS socket via the exported
//! `mcps-transport` client. Nothing reinvents crypto, policy, or transport: a
//! validly signed request (authored by the `mcps-host` `HostSession` / bare
//! `HostSigner`) is MUTATED after signing exactly as in-process — tamper body /
//! id, replay (resent on a FRESH mTLS connection), expire, wrong audience, drop
//! envelope, smuggle a forged `.verified` block, violate the granted path — and
//! the signed RESPONSE is corrupted (wrong hash / bad signature) so the client
//! refuses to bind it. Each case asserts the SPECIFIC frozen `mcps.*` reason
//! code carried in the JSON-RPC `error` object the real proxy returns.
//!
//! The CENTRAL invariant: for every PRE-DISPATCH failure (A1–A6, A8) the inner
//! fileserver is NEVER reached. Over the wire that is observed at the proxy's OWN
//! diagnostic channel: the production `StderrLogSink` prints
//! `mcps-proxy: inner-event inner_spawned …` on its stderr the instant it
//! launches the inner subprocess, and `inner_request_forwarded` once it forwards.
//! A pre-dispatch rejection never enters `run()`, so NO such line is emitted. We
//! pipe each spawned proxy's stderr into a drained buffer and assert ZERO
//! `inner_spawned` lines for the pre-dispatch cases (and ≥1 for the cases that
//! legitimately reach the inner: A7, A9, A10).
//!
//! Each case spawns its OWN proxy process so its stderr capture and durable
//! replay cache are isolated — no cross-case contamination — matching the
//! task's explicit allowance (a fresh proxy per case is acceptable). Readiness
//! is the same TCP port probe as the positive harness (#3943); each proxy is
//! killed + reaped and its replay dir removed on Drop.
//!
//! Proxy binary + inner binary + `demo_root/` fixture are delivered via Bazel
//! runfiles (`data` deps), resolved via `$(rlocationpath …)` — no hardcoded
//! path, no cargo.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_core::request_hash;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::REQUEST_META_KEY;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::VERIFIED_META_KEY;
use mcps_demo::mint_demo_grant;
use mcps_demo::DemoFixtureFiles;
use mcps_demo::DemoFixtures;
use mcps_demo::DemoGrant;
use mcps_demo::DemoGrantSpec;
use mcps_demo::DemoHostClient;
use mcps_demo::E2E_ON_BEHALF_OF;
use mcps_demo::E2E_PATH;
use mcps_demo::E2E_TOOL;
use mcps_host::FixedClock;
use mcps_host::HostSigner;
use mcps_host::SystemClock;
use mcps_host::SystemNonceSource;
use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;
/// A path the demo grant does NOT authorize (it authorizes only [`E2E_PATH`]).
const UNAUTHORIZED_PATH: &str = ".";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Runfiles resolution (identical scheme to the positive harness, #3943).
// ---------------------------------------------------------------------------

fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn proxy_cli() -> PathBuf {
    resolve_runfile("MCPS_PROXY_CLI")
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

/// Parse the proxy's OS-resolved listen address from its startup marker
/// `mcps-proxy: listening on <addr> (PEP; …)` (mcps-proxy/src/main.rs). Requires
/// the trailing space so a partially-captured line never yields a truncated
/// address; returns None until the complete marker is present.
fn parse_listening_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "mcps-proxy: listening on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

// ---------------------------------------------------------------------------
// The spawned proxy, with its stderr captured so "inner not reached" is
// observable over the wire (no `inner_spawned` line => the inner never ran).
// ---------------------------------------------------------------------------

/// A spawned `mcps_proxy_cli` OS process whose stderr is drained into a shared
/// buffer. Killed (and reaped) on drop; its durable replay dir is removed.
struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
    stderr: Arc<Mutex<String>>,
    _files: DemoFixtureFiles,
    _replay_dir: PathBuf,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._replay_dir);
    }
}

impl ProxyProcess {
    /// The number of times the proxy launched the inner subprocess, read from
    /// its diagnostic stderr (`inner-event inner_spawned …`). Zero proves the
    /// inner fileserver was never reached.
    fn inner_spawn_count(&self) -> usize {
        self.stderr
            .lock()
            .expect("stderr lock")
            .matches("inner_spawned")
            .count()
    }

    /// True iff the inner subprocess was launched at all (any spawn line).
    fn inner_was_reached(&self) -> bool {
        self.inner_spawn_count() > 0
    }
}

/// Spawn the real `mcps_proxy_cli` with the full P1 flag set (mTLS,
/// `--authz reference`, durable `--replay-cache file`, `--transport-binding
/// exact`, inner = the demo fileserver over `demo_root`), draining its stderr,
/// then poll the port until it accepts. Panics if it never listens.
fn spawn_proxy(fixtures: &DemoFixtures) -> ProxyProcess {
    let files = fixtures.write_files().expect("materialize fixture files");
    let cli = proxy_cli();
    let inner = inner_binary();
    let root = demo_root();

    // Let the PROXY pick the port: bind 127.0.0.1:0 and read the OS-resolved
    // address back from its startup marker. This deletes the free_port() TOCTOU
    // (binding :0 in the test, dropping it, then handing the bare port to the
    // subprocess, which races another process for the same port under load).
    let bind = "127.0.0.1:0".to_string();

    // Unique durable-replay dir per spawn — with the proxy choosing the port we
    // no longer have one to name the dir by; a process-wide counter keeps
    // concurrent test threads isolated.
    static SPAWN_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SPAWN_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let replay_dir = std::env::temp_dir().join(format!(
        "mcps_neg_e2e_replay_{}_{}",
        std::process::id(),
        seq,
    ));
    std::fs::create_dir_all(&replay_dir).expect("mkdir replay dir");
    let replay_path = replay_dir.join("replay.json");

    let mut child = Command::new(&cli)
        .args([
            "--bind",
            &bind,
            "--audience",
            fixtures.audience(),
            "--server-signer",
            fixtures.server_signer(),
            "--server-key-id",
            fixtures.server_key_id(),
            "--max-clock-skew",
            &SKEW_SECS.to_string(),
            "--key-source",
            "file",
            "--signing-key-seed",
            &files.signing_seed_path().to_string_lossy(),
            "--tls-cert",
            &files.server_cert_path().to_string_lossy(),
            "--tls-key",
            &files.server_key_path().to_string_lossy(),
            "--client-ca",
            &files.client_ca_path().to_string_lossy(),
            "--trust",
            &files.trust_path().to_string_lossy(),
            "--replay-cache",
            "file",
            "--replay-path",
            &replay_path.to_string_lossy(),
            "--transport-binding",
            "exact",
            "--transport-identity-source",
            "uri_san",
            "--authz",
            "reference",
            "--allow-empty-revocation",
            "--max-client-cert-lifetime",
            "175200h",
            "--inner-working-dir",
            &root,
            "--inner-command",
            &inner,
            "--demo-root",
            &root,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcps_proxy_cli");

    // Drain stderr on a dedicated thread into a shared buffer: the proxy emits
    // `inner-event inner_spawned …` here the instant it launches the inner, so
    // the buffer is the wire-observable "inner reached?" signal.
    let stderr = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&stderr);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut buf) = sink.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Readiness WITHOUT consuming a connection. The proxy is a single-request-
    // per-connection serve loop, so a `TcpStream::connect` probe would itself be
    // accepted as a (doomed, TLS-less) connection and race the first real round
    // trip — an intermittent ConnectionRefused/reset (MCPS-087). Instead wait for
    // the proxy's own startup marker, printed by `mcps_proxy_cli` immediately
    // AFTER `TcpListener::bind` succeeds (mcps-proxy/src/main.rs): once it appears
    // the socket is bound and the OS backlog queues the first real connection.
    // The budget is generous (≈30s) because a saturated machine — many e2e
    // tests each spawning a proxy + inner subprocess concurrently — can delay
    // when this proxy is scheduled to emit the marker. A proxy that REFUSES to
    // start (config/posture failure) exits instead, so poll its liveness and
    // fail fast with the captured diagnostic rather than burning the budget.
    let mut addr: Option<SocketAddr> = None;
    for _ in 0..1200 {
        if let Some(parsed) = stderr.lock().ok().and_then(|buf| parse_listening_addr(&buf)) {
            addr = Some(parsed);
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcps_proxy_cli exited before listening (status {status}):\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let addr = addr.expect("mcps_proxy_cli did not report a listening address within budget");

    ProxyProcess {
        child,
        addr,
        stderr,
        _files: files,
        _replay_dir: replay_dir,
    }
}

// ---------------------------------------------------------------------------
// Signing + transport helpers (delegating to mcps-host + mcps-transport).
// ---------------------------------------------------------------------------

fn signer_key(fixtures: &DemoFixtures) -> SigningKey {
    SigningKey::from_seed_bytes(&fixtures.signer_seed())
}

/// The verifying mTLS client: presents the positive client cert (URI SAN ==
/// signer) and verifies the proxy's server cert against the fixture server CA.
fn mtls_client(fixtures: &DemoFixtures) -> MtlsClient {
    let tls = ClientTlsConfig::from_pem(
        fixtures.client_cert_pem().as_bytes(),
        fixtures.client_key_pem().as_bytes(),
        fixtures.server_ca_pem().as_bytes(),
    )
    .expect("client TLS config from fixture PEM");
    MtlsClient::new(tls, fixtures.server_name()).expect("verifying mTLS client")
}

/// Mint the reference grant authorizing `list_files` on [`E2E_PATH`], sized
/// around the real clock so a SYSTEM-clock request signed now falls inside the
/// window (the proxy verifies on the same real clock). Self-issued by the
/// signer, so the single fixture `trust.json` entry already carries the issuer
/// key the proxy resolves for the policy-signature check.
fn build_grant(fixtures: &DemoFixtures, now: i64) -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: fixtures.signer().to_string(),
        grantee: fixtures.signer().to_string(),
        subject: E2E_ON_BEHALF_OF.to_string(),
        audience: fixtures.audience().to_string(),
        allowed_path: E2E_PATH.to_string(),
        not_before: unix_to_rfc3339_utc(now - SKEW_SECS),
        expires_at: unix_to_rfc3339_utc(now + REQUEST_LIFETIME_SECS),
        revocation_id: "demo-neg-e2e".to_string(),
    };
    mint_demo_grant(&spec, &signer_key(fixtures), fixtures.signer_key_id()).expect("mint demo grant")
}

/// `params` for an authorized `list_files` on `path`, carrying the grant block.
fn list_files_params(path: &str, grant: &DemoGrant) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(E2E_TOOL.to_string()));
    params.insert("arguments".to_string(), json!({ "path": path }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// A `HostSession`-backed demo client on the SYSTEM clock + RNG (so the request
/// it signs falls inside the proxy's real-clock freshness window).
fn system_client(fixtures: &DemoFixtures) -> DemoHostClient<SystemClock, SystemNonceSource> {
    DemoHostClient::with_defaults(
        HostSigner::new(
            signer_key(fixtures),
            fixtures.signer().to_string(),
            fixtures.signer_key_id().to_string(),
        ),
        SystemClock,
        SystemNonceSource,
    )
}

/// The trust anchor for verifying the SIGNED RESPONSE: the proxy's server
/// signer public key (derived from the fixture server seed).
fn response_resolver(fixtures: &DemoFixtures) -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(
        fixtures.server_signer(),
        fixtures.server_key_id(),
        SigningKey::from_seed_bytes(&fixtures.server_seed()).public_key(),
    );
    resolver
}

/// Parse the JSON-RPC denial reason (`error.message`, which equals
/// `error.data.mcps_error`) from a proxy response. `None` for a success.
fn denial_reason(response: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(response).expect("parse response");
    let error = value.get("error")?;
    let message = error["message"].as_str().expect("error.message").to_string();
    assert_eq!(
        error["data"]["mcps_error"].as_str().expect("data.mcps_error"),
        message,
        "structured denial: message and data.mcps_error must agree"
    );
    Some(message)
}

// ===========================================================================
// A1 — tampered request body → invalid_signature; inner NOT reached.
// ===========================================================================

#[test]
fn a1_tampered_request_body_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a1-tamper-body".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    // Mutate the (signed) path argument AFTER signing: the body no longer
    // matches the signature preimage.
    let mut request: Value = serde_json::from_slice(&signed).expect("parse");
    request["params"]["arguments"]["path"] = json!("tampered");
    let tampered = serde_json::to_vec(&request).expect("serialize");

    let response = client.round_trip(proxy.addr, &tampered).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpsError::InvalidSignature.wire_code())
    );
    assert!(!proxy.inner_was_reached(), "tampered body must NOT reach inner");
}

// ===========================================================================
// A2 — tampered JSON-RPC id → invalid_signature; inner NOT reached.
// ===========================================================================

#[test]
fn a2_tampered_jsonrpc_id_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a2-tamper-id".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    // The JSON-RPC id is part of the signed preimage; swapping it post-signing
    // breaks the signature.
    let mut request: Value = serde_json::from_slice(&signed).expect("parse");
    request["id"] = json!("req-a2-tamper-id-SWAPPED");
    let tampered = serde_json::to_vec(&request).expect("serialize");

    let response = client.round_trip(proxy.addr, &tampered).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpsError::InvalidSignature.wire_code())
    );
    assert!(!proxy.inner_was_reached(), "tampered id must NOT reach inner");
}

// ===========================================================================
// A3 — replay on a FRESH mTLS connection → replay_detected; inner not reached
//      on the replay (the durable file cache catches the second send).
// ===========================================================================

#[test]
fn a3_replayed_request_rejected_on_fresh_connection() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a3-replay".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    // First send (its OWN mTLS connection): succeeds + reaches the inner.
    let first = client.round_trip(proxy.addr, &signed).expect("first mTLS round trip");
    assert!(
        denial_reason(&first).is_none(),
        "first send must succeed: {:?}",
        denial_reason(&first)
    );
    assert!(proxy.inner_was_reached(), "the first (valid) send reaches the inner");
    let spawns_after_first = proxy.inner_spawn_count();

    // Resend the SAME bytes (same signer/audience/nonce) on a FRESH mTLS
    // connection: `round_trip` opens a new socket each call, so this proves the
    // durable replay cache catches a replay across connections.
    let second = client.round_trip(proxy.addr, &signed).expect("replay mTLS round trip");
    assert_eq!(
        denial_reason(&second).as_deref(),
        Some(McpsError::ReplayDetected.wire_code())
    );
    // The replay was rejected PRE-DISPATCH: no NEW inner spawn beyond the first.
    assert_eq!(
        proxy.inner_spawn_count(),
        spawns_after_first,
        "the replay must NOT spawn the inner again"
    );
}

// ===========================================================================
// A4 — expired request → expired_request; inner not reached.
// ===========================================================================

#[test]
fn a4_expired_request_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();

    // The grant must still be valid at the real clock (it is the PB sig that
    // policy checks) — only the REQUEST freshness window is stale. Sign the
    // request on a FixedClock far in the past so `expires_at` is well behind the
    // proxy's real-clock verification instant (past the skew).
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    let stale_at = now - 10 * 3600;
    let mut cl = DemoHostClient::with_defaults(
        HostSigner::new(
            signer_key(&fixtures),
            fixtures.signer().to_string(),
            fixtures.signer_key_id().to_string(),
        ),
        FixedClock::new(stale_at),
        SystemNonceSource,
    );
    let id = Value::String("req-a4-expired".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs an already-stale request");

    let response = client.round_trip(proxy.addr, &signed).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpsError::ExpiredRequest.wire_code())
    );
    assert!(!proxy.inner_was_reached(), "expired request must NOT reach inner");
}

// ===========================================================================
// A5 — wrong audience → invalid_audience; inner not reached.
// ===========================================================================

#[test]
fn a5_wrong_audience_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // Sign for a DIFFERENT audience than the proxy expects. The audience is part
    // of the signed envelope, so this is a fully valid signature over the wrong
    // audience; the proxy's audience check fails closed.
    let wrong_audience = format!("{}-OTHER", fixtures.audience());
    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a5-audience".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            &wrong_audience,
            &auth_hash,
        )
        .expect("client signs for the wrong audience");

    let response = client.round_trip(proxy.addr, &signed).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpsError::InvalidAudience.wire_code())
    );
    assert!(!proxy.inner_was_reached(), "wrong-audience request must NOT reach inner");
}

// ===========================================================================
// A6 — missing MCP-S request envelope → missing_envelope; inner not reached.
// ===========================================================================

#[test]
fn a6_missing_envelope_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a6-noenv".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    // Strip the MCP-S request envelope from _meta: the proxy can no longer
    // locate it and fails closed before dispatch.
    let mut request: Value = serde_json::from_slice(&signed).expect("parse");
    request["params"]["_meta"]
        .as_object_mut()
        .expect("_meta object")
        .remove(REQUEST_META_KEY);
    let stripped = serde_json::to_vec(&request).expect("serialize");

    let response = client.round_trip(proxy.addr, &stripped).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpsError::MissingEnvelope.wire_code())
    );
    assert!(!proxy.inner_was_reached(), "envelope-less request must NOT reach inner");
}

// ===========================================================================
// A7 — smuggled `.verified` metadata → stripped & replaced (call still
//      succeeds; the sidecar's verified context is authoritative).
// ===========================================================================

#[test]
fn a7_smuggled_verified_metadata_stripped_and_replaced_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // Smuggle a caller-owned `.verified` block INTO the signed params: it is part
    // of the signed payload (so it verifies), but the proxy is the SOLE writer of
    // `.verified`. The impostor block must be stripped and replaced by the
    // sidecar-owned context — proven because the request still authorizes,
    // reaches the inner, and the response binds + verifies under the SIDECAR
    // (server) key, never the forged verifier.
    let mut params = list_files_params(E2E_PATH, &grant);
    let meta = params.get_mut("_meta").and_then(Value::as_object_mut).expect("_meta");
    meta.insert(
        VERIFIED_META_KEY.to_string(),
        json!({ "verified_signer": "did:evil:impostor", "verifier": "did:evil:impostor" }),
    );

    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a7-verified".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            params,
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs with a smuggled .verified block");
    let stored_hash = cl.stored_request_hash(&id).expect("stored hash").to_string();

    let response = client.round_trip(proxy.addr, &signed).expect("mTLS round trip");

    // The smuggled block neither blocked nor altered the call: it reached the
    // inner and returned the real listing.
    assert!(
        denial_reason(&response).is_none(),
        "smuggled .verified must not deny: {:?}",
        denial_reason(&response)
    );
    assert!(proxy.inner_was_reached(), "authorized request must reach the inner");

    // The response binds to the stored request hash and verifies under the SERVER
    // (sidecar) key — the impostor verifier was discarded, not trusted.
    let verified = cl
        .verify_response(&response, &response_resolver(&fixtures))
        .expect("client verifies the signed response: sidecar replaced the impostor .verified");
    assert_eq!(verified.server_signer(), fixtures.server_signer());
    assert_eq!(verified.request_hash(), stored_hash);
    // The signed response's verified context names the REAL signer, not the
    // forged impostor verifier.
    let value: Value = serde_json::from_slice(&response).expect("parse response");
    let response_str = value.to_string();
    assert!(
        !response_str.contains("did:evil:impostor"),
        "the forged verifier must be gone from the response"
    );
}

// ===========================================================================
// A8 — valid signature, failed Phase 5 authorization (unauthorized path) →
//      authorization_scope_denied; deny-before-dispatch, inner not reached.
// ===========================================================================

#[test]
fn a8_unauthorized_path_rejected_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // Fully valid signature + attached grant, but the grant authorizes only
    // `reports`; ask for `.`. Phase 5 denies BEFORE dispatch.
    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a8-unauthorized".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(UNAUTHORIZED_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs an unauthorized-path request");

    let response = client.round_trip(proxy.addr, &signed).expect("mTLS round trip");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some("mcps.authorization_scope_denied")
    );
    assert!(!proxy.inner_was_reached(), "unauthorized path must NOT reach inner");
}

// ===========================================================================
// A9 — wrong response hash → client response_hash_mismatch.
// ===========================================================================

#[test]
fn a9_wrong_response_hash_rejected_by_client_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // Sign request A under the id and STORE hash A (never sent). Then run a
    // DIFFERENT request B (same id, different nonce/freshness via a bare
    // HostSigner) over the wire: the proxy validly signs a response bound to
    // hash B. The client then verifies B's response while expecting hash A — the
    // signature is VALID but the binding mismatches, so the session refuses it
    // (verify-order: signature step 6 before request-hash bind step 7).
    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a9-resphash".to_string());
    let _signed_a = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs request A (stores hash A)");
    let stored_a = cl.stored_request_hash(&id).expect("stored hash A").to_string();

    let bare = HostSigner::new(
        signer_key(&fixtures),
        fixtures.signer().to_string(),
        fixtures.signer_key_id().to_string(),
    );
    let signed_b = bare
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
            "nonce-a9-resphash-B",
            &unix_to_rfc3339_utc(now),
            &unix_to_rfc3339_utc(now + REQUEST_LIFETIME_SECS),
        )
        .expect("bare signer produces request B (same id, different envelope)");
    let hash_b = request_hash(&serde_json::from_slice::<Value>(&signed_b).expect("parse B"))
        .expect("hash B");
    assert_ne!(hash_b, stored_a, "B must bind a different request hash than A");

    let response_b = client.round_trip(proxy.addr, &signed_b).expect("mTLS round trip");
    assert!(proxy.inner_was_reached(), "request B is valid + authorized and reaches the inner");
    assert!(
        denial_reason(&response_b).is_none(),
        "the proxy signs B's response: {:?}",
        denial_reason(&response_b)
    );

    // The client expects hash A; B's response carries hash B → binding mismatch.
    let err = cl
        .verify_response(&response_b, &response_resolver(&fixtures))
        .expect_err("client must reject the wrong-hash binding");
    assert_eq!(err, McpsError::ResponseHashMismatch);
    assert_eq!(cl.pending_count(), 1, "a refused response leaves the pending entry");
}

// ===========================================================================
// A10 — bad response signature → client response_sig_invalid.
// ===========================================================================

#[test]
fn a10_bad_response_signature_rejected_by_client_over_wire() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // Run the full authorized path so the proxy produces a genuinely signed
    // response, then corrupt the response signature value AFTER signing. The
    // signature no longer verifies over the response preimage → ResponseSigInvalid
    // (the client refuses the response before the hash binding is consulted).
    let mut cl = system_client(&fixtures);
    let id = Value::String("req-a10-respsig".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(E2E_PATH, &grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    let response = client.round_trip(proxy.addr, &signed).expect("mTLS round trip");
    assert!(proxy.inner_was_reached(), "authorized request reaches the inner");
    assert!(
        denial_reason(&response).is_none(),
        "the proxy signs the response: {:?}",
        denial_reason(&response)
    );

    let mut value: Value = serde_json::from_slice(&response).expect("parse signed response");
    let sig = value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"]
        .as_str()
        .expect("signature value")
        .to_string();
    // Flip the first base64url char to a different valid one to corrupt the bytes.
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let corrupted: String = chars.into_iter().collect();
    assert_ne!(corrupted, sig, "signature must actually change");
    value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(corrupted);
    let corrupted_response = serde_json::to_vec(&value).expect("serialize corrupted response");

    let err = cl
        .verify_response(&corrupted_response, &response_resolver(&fixtures))
        .expect_err("client must reject the invalid response signature");
    assert_eq!(err, McpsError::ResponseSigInvalid);
    assert_eq!(cl.pending_count(), 1, "a refused response leaves the pending entry");
}
