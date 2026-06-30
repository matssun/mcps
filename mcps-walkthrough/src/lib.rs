//! The MCP-S persona-ladder walkthrough harness (ADR-MCPS-045).
//!
//! This crate's tests are a LADDER: each tier (T0..T3) spins up the SAME real
//! four-hop topology as separate OS processes and demonstrates exactly one new
//! security concept. The library here is the shared harness; the `tests/`
//! directory has one file per tier, and the crate `README.md` IS the ladder.
//!
//! The four hops, every one a real process:
//!
//! ```text
//!   ordinary MCP client (this test)
//!     │  plain MCP JSON-RPC over the child's stdio
//!     ▼
//!   mcps-client-proxy-cli   ── signs a draft-02 envelope, dials mTLS ──┐
//!                                                                       │
//!   mcps-proxy (server PEP) ◀── verifying mTLS over loopback ──────────┘
//!     │  verify draft-02 (Draft02Only) → strip → inject verified ctx → forward
//!     ▼
//!   mcps-demo-fileserver    ── ordinary, MCP-S-unaware stdio MCP server
//! ```
//!
//! The local client speaks ONLY plain MCP; all signing/verification lives in the
//! two proxies. The transport is mTLS-on-loopback throughout — MCP-S's guarantee
//! is message-level, so T0/T1 demonstrate it WITHOUT binding the transport
//! identity to the signer (`--transport-binding none`); T3 adds that binding
//! (`exact`) and its negatives. The server runs the recommended strict posture
//! (`--expected-version-policy draft-02-only`).
//!
//! All material is ephemeral: [`DemoFixtures`] mints the mTLS certs/keys/trust in
//! a temp dir wiped on drop, and the writable demo root is a temp dir wiped on
//! drop. The proxy + fileserver binaries are resolved via `mcps-test-paths`
//! (Bazel runfiles OR the cargo target dir).

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Child;
use std::process::ChildStdin;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use mcps_client_core::AudienceTuple;
use mcps_demo::DemoFixtureFiles;
use mcps_demo::DemoFixtures;
use serde_json::json;
use serde_json::Value;

/// Whether the server PEP binds the verified mTLS identity to the request signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportBinding {
    /// No identity binding (T0/T1): mTLS still authenticates the channel, but the
    /// client cert identity is not required to equal the request signer.
    None,
    /// Exact identity binding (T3): the request signer MUST equal the verified
    /// mTLS client identity (URI SAN), else `mcps.transport_binding_failed`.
    Exact,
}

/// Which client certificate the client proxy presents in the mTLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCert {
    /// The fixture's positive client leaf — URI SAN == the request signer
    /// (`did:example:agent-1`). Passes `exact` transport binding.
    Matching,
    /// The fixture's MISMATCHED client leaf — same client CA (handshake succeeds)
    /// but URI SAN != the request signer, so `exact` binding fails closed.
    Mismatched,
}

/// Knobs the tiers vary. Defaults give the T0/T1 posture.
#[derive(Debug, Clone)]
pub struct FourHopOptions {
    /// Transport-identity binding posture (default [`TransportBinding::None`]).
    pub transport_binding: TransportBinding,
    /// Which client certificate the client proxy presents (default
    /// [`ClientCert::Matching`]).
    pub client_cert: ClientCert,
    /// When set, the inner fileserver records every dispatched `tools/call` to
    /// this append-only file (T3 cross-process deny proof). Default `None`.
    pub received_log: Option<PathBuf>,
    /// Client-proxy `--server-name`; defaults to the fixture server cert SAN.
    /// Override to a WRONG name to exercise a server-identity negative.
    pub server_name_override: Option<String>,
}

impl Default for FourHopOptions {
    fn default() -> Self {
        FourHopOptions {
            transport_binding: TransportBinding::None,
            client_cert: ClientCert::Matching,
            received_log: None,
            server_name_override: None,
        }
    }
}

/// A temp directory removed on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a uniquely-named temp dir (cargo `CARGO_TARGET_TMPDIR` → bazel
    /// `TEST_TMPDIR` → system temp), disjoint per call so parallel tiers cannot
    /// collide.
    fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .or_else(|| std::env::var_os("TEST_TMPDIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("mcps-walkthrough-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The seed file every tier's writable demo root starts with.
pub const SEED_NAME: &str = "hello.txt";
/// The seed file's contents.
pub const SEED_TEXT: &str = "hello from the inner fileserver\n";

/// A running four-hop topology. Holds both proxy subprocesses; [`Drop`] kills
/// them and the temp material is wiped.
pub struct FourHop {
    server: ServerProc,
    client_in: ChildStdin,
    client_out: BufReader<ChildStdout>,
    client: Child,
    demo_root: TempDir,
    _files: DemoFixtureFiles,
}

impl FourHop {
    /// Launch the topology with default (T0/T1) options.
    pub fn launch() -> Self {
        Self::launch_with(FourHopOptions::default())
    }

    /// Launch the topology with explicit options.
    pub fn launch_with(opts: FourHopOptions) -> Self {
        let fixtures = DemoFixtures::generate_default();
        let files = fixtures.write_files().expect("write fixture material");

        // A writable demo root, seeded so reads/lists have something real.
        let demo_root = TempDir::new("root").expect("create demo root");
        std::fs::write(demo_root.path.join(SEED_NAME), SEED_TEXT).expect("seed demo root");

        // The canonical audience both proxies must agree on. The client gets the
        // 6 fields; the server gets the derived string — they MUST match.
        let audience = AudienceTuple::new("https", fixtures.server_name(), 8443, "acme", "tools", "prod")
            .expect("audience tuple");

        let inner_bin = resolve_bin("INNER_FILESERVER_BIN");
        let server = ServerProc::spawn(
            &resolve_bin("MCPS_PROXY_CLI"),
            &files,
            &audience.to_audience_string(),
            &inner_bin,
            demo_root.path.to_str().expect("utf-8 demo root"),
            &opts,
        );

        let server_name = opts
            .server_name_override
            .clone()
            .unwrap_or_else(|| fixtures.server_name().to_string());
        let (client, client_in, client_out) = spawn_client(
            &resolve_bin("MCPS_CLIENT_PROXY_CLI"),
            &files,
            &fixtures,
            &audience,
            server.addr,
            &server_name,
            opts.client_cert,
        );

        FourHop {
            server,
            client_in,
            client_out,
            client,
            demo_root,
            _files: files,
        }
    }

    /// Send ONE plain-MCP request through the client proxy and return the plain
    /// response it yields (the local client never sees an MCP-S field).
    pub fn call(&mut self, request: &Value) -> Value {
        let line = serde_json::to_string(request).expect("serialize request");
        writeln!(self.client_in, "{line}").expect("write to client proxy stdin");
        self.client_in.flush().expect("flush client proxy stdin");
        let mut response_line = String::new();
        let n = self
            .client_out
            .read_line(&mut response_line)
            .expect("read client proxy stdout");
        assert!(n > 0, "client proxy closed stdout without a response");
        serde_json::from_str(&response_line)
            .unwrap_or_else(|e| panic!("client proxy response not JSON ({e}): {response_line:?}"))
    }

    /// The absolute path of a file inside the writable demo root (test assertions
    /// on what actually landed on disk).
    pub fn root_file(&self, name: &str) -> PathBuf {
        self.demo_root.path.join(name)
    }

    /// How many times the server PEP spawned the inner fileserver (deny-before-
    /// dispatch proof: a denied call never spawns the inner). Counts the
    /// `inner_spawned` lifecycle marker in the server's stderr.
    pub fn inner_spawn_count(&self) -> usize {
        self.server.stderr_contains_count("inner_spawned")
    }

    /// The server PEP's captured stderr so far (diagnostics).
    pub fn server_stderr(&self) -> String {
        self.server.stderr.lock().expect("stderr lock").clone()
    }
}

impl Drop for FourHop {
    fn drop(&mut self) {
        let _ = self.client.kill();
        let _ = self.client.wait();
        // server + temp dirs clean themselves up via their own Drop impls.
    }
}

/// Resolve a child binary via `mcps-test-paths` (Bazel runfiles OR cargo target).
fn resolve_bin(env_key: &str) -> String {
    mcps_test_paths::resolve_runfile(env_key)
        .to_string_lossy()
        .into_owned()
}

/// The server `mcps-proxy` subprocess + its captured stderr (for the listening
/// marker and the `inner_spawned` lifecycle proof).
struct ServerProc {
    child: Child,
    addr: SocketAddr,
    stderr: Arc<Mutex<String>>,
}

impl ServerProc {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        proxy_bin: &str,
        files: &DemoFixtureFiles,
        audience_string: &str,
        inner_bin: &str,
        demo_root: &str,
        opts: &FourHopOptions,
    ) -> ServerProc {
        let mut args: Vec<String> = vec![
            "--bind".into(), "127.0.0.1:0".into(),
            "--audience".into(), audience_string.into(),
            "--server-signer".into(), "did:example:server-1".into(),
            "--server-key-id".into(), "server-key-1".into(),
            "--max-clock-skew".into(), "300".into(),
            // The recommended strict posture: refuse draft-01 as a downgrade.
            "--expected-version-policy".into(), "draft-02-only".into(),
            "--key-source".into(), "file".into(),
            "--signing-key-seed".into(), path(files.signing_seed_path()),
            "--tls-cert".into(), path(files.server_cert_path()),
            "--tls-key".into(), path(files.server_key_path()),
            "--client-ca".into(), path(files.client_ca_path()),
            "--trust".into(), path(files.trust_path()),
            // The fixture leaves are long-lived; lift the 1h default ceiling.
            "--max-client-cert-lifetime".into(), "175200h".into(),
        ];
        match opts.transport_binding {
            TransportBinding::None => {
                args.push("--transport-binding".into());
                args.push("none".into());
            }
            TransportBinding::Exact => {
                args.push("--transport-binding".into());
                args.push("exact".into());
                args.push("--transport-identity-source".into());
                args.push("uri_san".into());
            }
        }
        args.push("--inner-working-dir".into());
        args.push(demo_root.to_string());
        // --inner-command MUST be last (it swallows the rest of argv as the
        // inner server's argv).
        args.push("--inner-command".into());
        args.push(inner_bin.to_string());
        args.push("--demo-root".into());
        args.push(demo_root.to_string());
        if let Some(log) = &opts.received_log {
            args.push("--received-log".into());
            args.push(log.to_string_lossy().into_owned());
        }

        let mut child = Command::new(proxy_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn server proxy {proxy_bin}: {e}"));

        // Drain stderr into a shared buffer (readiness marker + lifecycle events).
        let stderr = Arc::new(Mutex::new(String::new()));
        let reader = child.stderr.take().expect("server stderr piped");
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                let mut buf = sink.lock().expect("stderr lock");
                buf.push_str(&line);
                buf.push('\n');
            }
        });

        let addr = await_listening(&mut child, &stderr);
        ServerProc { child, addr, stderr }
    }

    fn stderr_contains_count(&self, needle: &str) -> usize {
        self.stderr
            .lock()
            .expect("stderr lock")
            .matches(needle)
            .count()
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Poll the server's stderr for the `mcps-proxy: listening on <addr>` marker and
/// return the OS-resolved bound address. Fails fast if the child exits early.
fn await_listening(child: &mut Child, stderr: &Arc<Mutex<String>>) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(addr) = stderr
            .lock()
            .expect("stderr lock")
            .lines()
            .find_map(parse_listening_addr)
        {
            return addr;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().expect("stderr lock").clone();
            panic!("server proxy exited early ({status}) before listening:\n{captured}");
        }
        if Instant::now() > deadline {
            let captured = stderr.lock().expect("stderr lock").clone();
            panic!("server proxy did not report listening within 20s:\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Parse `mcps-proxy: listening on 127.0.0.1:PORT (PEP; inner = ...)`.
fn parse_listening_addr(line: &str) -> Option<SocketAddr> {
    let rest = line.split("listening on ").nth(1)?;
    let token = rest.split_whitespace().next()?;
    token.parse().ok()
}

/// Spawn the client `mcps-client-proxy-cli` with stdio piped; returns the child
/// plus its stdin and a buffered stdout reader.
#[allow(clippy::too_many_arguments)]
fn spawn_client(
    client_bin: &str,
    files: &DemoFixtureFiles,
    fixtures: &DemoFixtures,
    audience: &AudienceTuple,
    server_addr: SocketAddr,
    server_name: &str,
    client_cert: ClientCert,
) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let (cert_path, key_path) = match client_cert {
        ClientCert::Matching => (files.client_cert_path(), files.client_key_path()),
        ClientCert::Mismatched => (
            files.mismatched_client_cert_path(),
            files.mismatched_client_key_path(),
        ),
    };
    let audience_fields = format!(
        "https,{},8443,acme,tools,prod",
        fixtures.server_name()
    );
    debug_assert_eq!(
        audience_fields_to_string(&audience_fields),
        audience.to_audience_string(),
        "client audience fields must derive the server's audience string"
    );
    let args: Vec<String> = vec![
        "--remote-addr".into(), server_addr.to_string(),
        "--server-name".into(), server_name.to_string(),
        "--signer-id".into(), fixtures.signer().to_string(),
        "--key-id".into(), fixtures.signer_key_id().to_string(),
        "--signing-key-seed".into(), format!("@{}", path(files.signer_seed_path())),
        "--server-signer".into(), fixtures.server_signer().to_string(),
        "--server-key-id".into(), fixtures.server_key_id().to_string(),
        "--server-pubkey".into(), fixtures.server_public_key_b64url(),
        "--audience".into(), audience_fields,
        "--tls-cert".into(), path(cert_path),
        "--tls-key".into(), path(key_path),
        "--server-ca".into(), path(files.server_ca_path()),
        "--on-behalf-of".into(), "user:alice".into(),
    ];

    let mut child = Command::new(client_bin)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn client proxy {client_bin}: {e}"));

    // Drain the client's stderr (startup line + per-request audit) so the pipe
    // never fills and blocks the child.
    let reader = child.stderr.take().expect("client stderr piped");
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if std::env::var_os("WALKTHROUGH_DEBUG").is_some() {
                eprintln!("[client] {line}");
            }
        }
    });

    let stdin = child.stdin.take().expect("client stdin piped");
    let stdout = BufReader::new(child.stdout.take().expect("client stdout piped"));
    (child, stdin, stdout)
}

/// Recompute the canonical audience string from the 6 comma-separated client
/// fields (debug cross-check only — keeps the two sides provably in lock-step).
fn audience_fields_to_string(fields: &str) -> String {
    let f: Vec<&str> = fields.split(',').collect();
    AudienceTuple::new(f[0], f[1], f[2].parse::<u16>().unwrap(), f[3], f[4], f[5])
        .expect("audience tuple")
        .to_audience_string()
}

fn path(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

// --- Plain-MCP request builders (the ordinary client's view) ----------------

/// A plain `tools/call` request the ordinary client would send.
pub fn tool_call(id: &str, tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    })
}

/// Extract `result.structuredContent` from a plain response (panics on an error
/// response, surfacing the wire reason).
pub fn structured(response: &Value) -> &Value {
    assert!(
        response.get("error").is_none(),
        "expected success, got error: {response}"
    );
    &response["result"]["structuredContent"]
}

/// Extract the `error.message` (the surfaced `mcps.*` wire reason) from a
/// plain error response.
pub fn error_message(response: &Value) -> String {
    response["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}
