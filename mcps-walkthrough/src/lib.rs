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

/// Where the object-layer SIGNING keys live: the fixture software seeds
/// (default, T0..T3) or GCP Cloud KMS (T4 — both client request signer and server
/// response signer non-exporting in the cloud). mTLS material is file-backed in
/// both modes; only the object-signing identities move to KMS.
#[derive(Debug, Clone)]
pub enum SigningMode {
    /// Software keys from the demo fixtures (the default for every offline tier).
    Software,
    /// Both object-signing keys held in GCP Cloud KMS, named by their key-version
    /// resource paths. Compiled only under the `gcp_kms` feature (Tier T4).
    #[cfg(feature = "gcp_kms")]
    GcpKms {
        /// The client request-signer's Cloud KMS key version.
        client_key_version: String,
        /// The server response-signer's Cloud KMS key version (a DISTINCT key).
        server_key_version: String,
    },
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
    /// Where the object-signing keys live (default [`SigningMode::Software`]).
    pub signing: SigningMode,
}

impl Default for FourHopOptions {
    fn default() -> Self {
        FourHopOptions {
            transport_binding: TransportBinding::None,
            client_cert: ClientCert::Matching,
            received_log: None,
            server_name_override: None,
            signing: SigningMode::Software,
        }
    }
}

/// The resolved object-layer signing identities + key-source CLI args for BOTH
/// proxies, plus the public keys each side must trust. The software profile reads
/// the fixture seeds; the KMS profile (T4) fetches both public keys from Cloud KMS
/// and writes a `--trust` file binding the client's KMS key to its signer id.
///
/// This is the ONE place the two halves are kept consistent: the server signs
/// responses as (`server_signer`, `server_key_id`) and the client trusts exactly
/// that pair via `client_server_pubkey`; the client signs requests as
/// (`client_signer_id`, `client_key_id`) and the server trusts exactly that pair
/// via `server_trust_path`.
struct SigningProfile {
    // Server PEP — its own response-signing identity + the request signers it trusts.
    server_signer: String,
    server_key_id: String,
    /// `--key-source ...` (+ `--signing-key-seed` or `--gcp-kms-key-version`).
    server_key_source: Vec<String>,
    /// Path to the `--trust` file listing accepted request signers.
    server_trust_path: String,
    // Client proxy — its own request-signing identity + the server key it trusts.
    client_signer_id: String,
    client_key_id: String,
    /// `--signing-key-seed @path` (software) or `--key-source gcp-kms ...` (KMS).
    client_key_source: Vec<String>,
    /// The server response-signer public key the client verifies (`--server-pubkey`).
    client_server_pubkey: String,
    /// Holds the KMS `--trust` temp dir alive for the server's lifetime (`None`
    /// for software, whose trust file lives in the fixture material).
    _trust_tmp: Option<TempDir>,
}

impl SigningProfile {
    /// The default profile: fixture software seeds, fixture trust file. Byte-for-
    /// byte the legacy T0..T3 wiring.
    fn software(fixtures: &DemoFixtures, files: &DemoFixtureFiles) -> Self {
        SigningProfile {
            server_signer: fixtures.server_signer().to_string(),
            server_key_id: fixtures.server_key_id().to_string(),
            server_key_source: vec![
                "--key-source".into(),
                "file".into(),
                "--signing-key-seed".into(),
                path(files.signing_seed_path()),
            ],
            server_trust_path: path(files.trust_path()),
            client_signer_id: fixtures.signer().to_string(),
            client_key_id: fixtures.signer_key_id().to_string(),
            client_key_source: vec![
                "--signing-key-seed".into(),
                format!("@{}", path(files.signer_seed_path())),
            ],
            client_server_pubkey: fixtures.server_public_key_b64url(),
            _trust_tmp: None,
        }
    }

    /// Tier T4: both object-signing keys in Cloud KMS. Fetches each Ed25519 public
    /// key from KMS (the SAME backend that signs), synthesizes the server's
    /// `--trust` file from the client's KMS key, and hands the server's KMS key to
    /// the client as `--server-pubkey`. mTLS stays file-backed.
    #[cfg(feature = "gcp_kms")]
    fn gcp_kms(
        client_key_version: &str,
        server_key_version: &str,
        files: &DemoFixtureFiles,
    ) -> Self {
        // Stable cloud-custody identities (labels for the KMS keys); the trust
        // wiring binds each to the public key actually fetched from KMS.
        const CLIENT_SIGNER: &str = "did:example:kms-client";
        const CLIENT_KEY_ID: &str = "gcp-kms-client-1";
        const SERVER_SIGNER: &str = "did:example:kms-server";
        const SERVER_KEY_ID: &str = "gcp-kms-server-1";

        let client_pubkey = fetch_kms_pubkey_b64url(client_key_version);
        let server_pubkey = fetch_kms_pubkey_b64url(server_key_version);

        // The server PEP trusts the CLIENT's KMS public key as the request signer.
        let trust_tmp = TempDir::new("kms-trust").expect("create kms trust dir");
        let trust = serde_json::to_string_pretty(&json!([{
            "signer": CLIENT_SIGNER,
            "key_id": CLIENT_KEY_ID,
            "public_key": client_pubkey,
        }]))
        .expect("serialize kms trust");
        let trust_path = trust_tmp.path.join("trust.json");
        std::fs::write(&trust_path, trust).expect("write kms trust file");

        SigningProfile {
            server_signer: SERVER_SIGNER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            server_key_source: vec![
                "--key-source".into(),
                "gcp-kms".into(),
                "--gcp-kms-key-version".into(),
                server_key_version.to_string(),
                // Required by the server CLI but UNUSED under gcp-kms (object
                // signing is the KMS backend; the TLS key comes from --tls-key).
                "--signing-key-seed".into(),
                path(files.signing_seed_path()),
            ],
            server_trust_path: path(&trust_path),
            client_signer_id: CLIENT_SIGNER.to_string(),
            client_key_id: CLIENT_KEY_ID.to_string(),
            client_key_source: vec![
                "--key-source".into(),
                "gcp-kms".into(),
                "--gcp-kms-key-version".into(),
                client_key_version.to_string(),
            ],
            client_server_pubkey: server_pubkey,
            _trust_tmp: Some(trust_tmp),
        }
    }
}

/// Fetch an Ed25519 public key from GCP Cloud KMS as raw-32 Base64URL-no-pad (the
/// trust-file / `--server-pubkey` wire format). Uses the proxy's own KMS backend,
/// so the key returned is exactly the one that signs. Token via
/// `MCPS_GCP_ACCESS_TOKEN` or, with `MCPS_GCP_USE_METADATA=1`, the metadata server.
#[cfg(feature = "gcp_kms")]
fn fetch_kms_pubkey_b64url(key_version: &str) -> String {
    use mcps_proxy::kms_keysource::KmsEd25519Backend;
    use mcps_proxy::GcpKmsConfig;
    use mcps_proxy::GcpKmsEd25519Backend;

    let config = GcpKmsConfig {
        key_version_name: key_version.to_string(),
        endpoint: std::env::var("MCPS_GCP_KMS_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCPS_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    let spki = backend
        .public_key_spki_der()
        .expect("fetch KMS Ed25519 SPKI public key");
    // RFC 8410 Ed25519 SPKI ends in the raw 32-byte point.
    let raw: [u8; 32] = spki[spki.len() - 32..]
        .try_into()
        .expect("Ed25519 SPKI ends in a 32-byte point");
    mcps_core::VerificationKey::from_bytes(&raw)
        .expect("valid Ed25519 verification key")
        .to_b64url()
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
    /// Held so the (KMS) `--trust` temp file outlives the running server.
    _signing: SigningProfile,
}

impl FourHop {
    /// Launch the topology with default (T0/T1) options.
    pub fn launch() -> Self {
        Self::launch_with(FourHopOptions::default())
    }

    /// Tier T4: launch the four-hop with BOTH object-signing keys held in GCP
    /// Cloud KMS (named by their key-version resource paths). mTLS stays
    /// file-backed; the harness fetches both KMS public keys to wire trust.
    #[cfg(feature = "gcp_kms")]
    pub fn launch_kms(client_key_version: &str, server_key_version: &str) -> Self {
        Self::launch_with(FourHopOptions {
            signing: SigningMode::GcpKms {
                client_key_version: client_key_version.to_string(),
                server_key_version: server_key_version.to_string(),
            },
            ..FourHopOptions::default()
        })
    }

    /// Launch the topology with explicit options.
    pub fn launch_with(opts: FourHopOptions) -> Self {
        let fixtures = DemoFixtures::generate_default();
        let files = fixtures.write_files().expect("write fixture material");

        // Resolve where the object-signing keys live (software seeds or Cloud KMS).
        let profile = match &opts.signing {
            SigningMode::Software => SigningProfile::software(&fixtures, &files),
            #[cfg(feature = "gcp_kms")]
            SigningMode::GcpKms {
                client_key_version,
                server_key_version,
            } => SigningProfile::gcp_kms(client_key_version, server_key_version, &files),
        };

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
            &profile,
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
            &profile,
        );

        FourHop {
            server,
            client_in,
            client_out,
            client,
            demo_root,
            _files: files,
            _signing: profile,
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
        profile: &SigningProfile,
    ) -> ServerProc {
        let mut args: Vec<String> = vec![
            "--bind".into(), "127.0.0.1:0".into(),
            "--audience".into(), audience_string.into(),
            "--server-signer".into(), profile.server_signer.clone(),
            "--server-key-id".into(), profile.server_key_id.clone(),
            "--max-clock-skew".into(), "300".into(),
            // The recommended strict posture: refuse draft-01 as a downgrade.
            "--expected-version-policy".into(), "draft-02-only".into(),
        ];
        // Object-signing key source: fixture seed (software) or Cloud KMS (T4).
        args.extend(profile.server_key_source.iter().cloned());
        args.extend([
            "--tls-cert".into(), path(files.server_cert_path()),
            "--tls-key".into(), path(files.server_key_path()),
            "--client-ca".into(), path(files.client_ca_path()),
            "--trust".into(), profile.server_trust_path.clone(),
            // The fixture leaves are long-lived; lift the 1h default ceiling.
            "--max-client-cert-lifetime".into(), "175200h".into(),
        ]);
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
    profile: &SigningProfile,
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
    let mut args: Vec<String> = vec![
        "--remote-addr".into(), server_addr.to_string(),
        "--server-name".into(), server_name.to_string(),
        "--signer-id".into(), profile.client_signer_id.clone(),
        "--key-id".into(), profile.client_key_id.clone(),
    ];
    // Request-signing key source: fixture seed (software) or Cloud KMS (T4).
    args.extend(profile.client_key_source.iter().cloned());
    args.extend([
        // The server's own response-signing identity + the key the client trusts.
        "--server-signer".into(), profile.server_signer.clone(),
        "--server-key-id".into(), profile.server_key_id.clone(),
        "--server-pubkey".into(), profile.client_server_pubkey.clone(),
        "--audience".into(), audience_fields,
        "--tls-cert".into(), path(cert_path),
        "--tls-key".into(), path(key_path),
        "--server-ca".into(), path(files.server_ca_path()),
        "--on-behalf-of".into(), "user:alice".into(),
    ]);

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
