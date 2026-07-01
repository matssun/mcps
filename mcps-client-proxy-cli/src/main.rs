//! `mcps-client-proxy-cli` — the binary front-end for the local client-side MCP-S
//! proxy (ADR-MCPS-045 Phase 3, ADR-MCPS-044 §Proxy transparency).
//!
//! The local client speaks PLAIN MCP to this process over stdio: one
//! newline-delimited JSON-RPC request per line on stdin, one plain JSON-RPC
//! response per line on stdout. For each request the proxy (via
//! `mcps-client-core`) signs a draft-02 envelope, forwards it to the remote MCP-S
//! server/proxy over verifying mTLS, verifies the signed response, applies the
//! enforcement decision, and returns plain MCP. The local client never sees an
//! MCP-S field — only surfaced security errors leak.
//!
//! This binary owns exactly the MODE-SPECIFIC pieces the pure library leaves to
//! its caller: the stdio listener, the per-call freshness (clock + OS-CSPRNG
//! nonce) wiring, and the concrete mTLS [`MtlsRemoteTransport`]. Arg parsing is
//! std-only (no clap), consistent with the sibling stdio binaries.
//!
//! Usage:
//!   mcps-client-proxy-cli \
//!     --remote-addr <host:port> --server-name <tls-san> \
//!     --signer-id <id> --key-id <kid> --signing-key-seed <b64url|@file> \
//!     --server-signer <id> --server-key-id <kid> --server-pubkey <b64url> \
//!     --audience <scheme,host,port,tenant,route,realm> \
//!     --tls-cert <pem> --tls-key <pem> --server-ca <pem> \
//!     [--route-id tools] [--on-behalf-of <principal>] [--ttl-secs 300]

// The client-side Cloud KMS signer (ADR-MCPS-045 Phase 4 / T4) is compiled only
// under the optional `gcp_kms` feature; a default build is mTLS + software keys.
#[cfg(feature = "gcp_kms")]
mod kms_signer;
mod transport;

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process::ExitCode;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_client_core::AudienceTuple;
use mcps_client_core::AuthorizationBindingPolicy;
use mcps_client_core::ClientSigner;
use mcps_client_core::EnforcementMode;
use mcps_client_core::Environment;
use mcps_client_core::OpaqueBytesProvider;
use mcps_client_core::SignerAudienceBinding;
use mcps_client_core::SignerPolicy;
use mcps_client_core::SoftwareSigner;
use mcps_client_proxy::CallParams;
use mcps_client_proxy::ClientProxy;
use mcps_client_proxy::ProxyError;
use mcps_client_proxy::Route;
use mcps_client_proxy::RouteRegistry;
use mcps_core::b64url_decode;
use mcps_core::b64url_encode;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationKey;
use mcps_host::NonceSource;
use mcps_host::SystemNonceSource;
use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

use crate::transport::MtlsRemoteTransport;

/// Where the client's request-signing key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeySource {
    /// A seed-backed in-process software key (`--signing-key-seed`).
    File,
    /// A non-exporting GCP Cloud KMS `EC_SIGN_ED25519` key (`--gcp-kms-*`); the
    /// hardening profile is enforced (NonExporting custody required).
    GcpKms,
}

/// The parsed CLI configuration.
#[derive(Debug)]
struct CliArgs {
    remote_addr: String,
    server_name: String,
    signer_id: String,
    key_id: String,
    key_source: KeySource,
    /// Required for [`KeySource::File`]; unused for KMS (the key never leaves KMS).
    signing_key_seed: Option<String>,
    /// Full Cloud KMS resource path; required for [`KeySource::GcpKms`].
    gcp_kms_key_version: Option<String>,
    gcp_kms_endpoint: Option<String>,
    gcp_kms_use_metadata: bool,
    server_signer: String,
    server_key_id: String,
    server_pubkey: String,
    audience: String,
    tls_cert: String,
    tls_key: String,
    server_ca: String,
    route_id: String,
    on_behalf_of: String,
    ttl_secs: i64,
}

fn parse_args(argv: &[String]) -> Result<CliArgs, String> {
    let mut remote_addr = None;
    let mut server_name = None;
    let mut signer_id = None;
    let mut key_id = None;
    let mut key_source = "file".to_string();
    let mut signing_key_seed = None;
    let mut gcp_kms_key_version = None;
    let mut gcp_kms_endpoint = None;
    let mut gcp_kms_use_metadata = false;
    let mut server_signer = None;
    let mut server_key_id = None;
    let mut server_pubkey = None;
    let mut audience = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut server_ca = None;
    let mut route_id = "tools".to_string();
    let mut on_behalf_of = "user:demo".to_string();
    let mut ttl_secs: i64 = 300;

    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        let mut take = |flag: &str| -> Result<String, String> {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match arg.as_str() {
            "--remote-addr" => remote_addr = Some(take("--remote-addr")?),
            "--server-name" => server_name = Some(take("--server-name")?),
            "--signer-id" => signer_id = Some(take("--signer-id")?),
            "--key-id" => key_id = Some(take("--key-id")?),
            "--signing-key-seed" => signing_key_seed = Some(take("--signing-key-seed")?),
            "--key-source" => key_source = take("--key-source")?,
            "--gcp-kms-key-version" => gcp_kms_key_version = Some(take("--gcp-kms-key-version")?),
            "--gcp-kms-endpoint" => gcp_kms_endpoint = Some(take("--gcp-kms-endpoint")?),
            "--gcp-kms-use-metadata" => gcp_kms_use_metadata = true,
            "--server-signer" => server_signer = Some(take("--server-signer")?),
            "--server-key-id" => server_key_id = Some(take("--server-key-id")?),
            "--server-pubkey" => server_pubkey = Some(take("--server-pubkey")?),
            "--audience" => audience = Some(take("--audience")?),
            "--tls-cert" => tls_cert = Some(take("--tls-cert")?),
            "--tls-key" => tls_key = Some(take("--tls-key")?),
            "--server-ca" => server_ca = Some(take("--server-ca")?),
            "--route-id" => route_id = take("--route-id")?,
            "--on-behalf-of" => on_behalf_of = take("--on-behalf-of")?,
            "--ttl-secs" => {
                ttl_secs = take("--ttl-secs")?
                    .parse()
                    .map_err(|_| "invalid --ttl-secs".to_string())?
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    let req = |opt: Option<String>, flag: &str| opt.ok_or_else(|| format!("{flag} is required"));
    let key_source = match key_source.as_str() {
        "file" => KeySource::File,
        "gcp-kms" => KeySource::GcpKms,
        other => return Err(format!("unknown --key-source '{other}' (file|gcp-kms)")),
    };
    // Per-source required fields: a file key needs a seed; a KMS key needs a key
    // version (and the key never leaves KMS, so no seed).
    match key_source {
        KeySource::File if signing_key_seed.is_none() => {
            return Err("--signing-key-seed is required for --key-source file".to_string())
        }
        KeySource::GcpKms if gcp_kms_key_version.is_none() => {
            return Err(
                "--gcp-kms-key-version is required for --key-source gcp-kms".to_string(),
            )
        }
        _ => {}
    }
    Ok(CliArgs {
        remote_addr: req(remote_addr, "--remote-addr")?,
        server_name: req(server_name, "--server-name")?,
        signer_id: req(signer_id, "--signer-id")?,
        key_id: req(key_id, "--key-id")?,
        key_source,
        signing_key_seed,
        gcp_kms_key_version,
        gcp_kms_endpoint,
        gcp_kms_use_metadata,
        server_signer: req(server_signer, "--server-signer")?,
        server_key_id: req(server_key_id, "--server-key-id")?,
        server_pubkey: req(server_pubkey, "--server-pubkey")?,
        audience: req(audience, "--audience")?,
        tls_cert: req(tls_cert, "--tls-cert")?,
        tls_key: req(tls_key, "--tls-key")?,
        server_ca: req(server_ca, "--server-ca")?,
        route_id,
        on_behalf_of,
        ttl_secs,
    })
}

/// A b64url string, or `@<path>` to read the value from a file (trimmed).
fn resolve_inline_or_file(value: &str) -> Result<String, String> {
    match value.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("read '{path}': {e}")),
        None => Ok(value.to_string()),
    }
}

/// Decode a b64url Ed25519 32-byte seed into a [`SigningKey`].
fn signing_key_from_seed_b64url(seed_b64url: &str) -> Result<SigningKey, String> {
    let bytes = b64url_decode(seed_b64url).map_err(|_| "invalid --signing-key-seed b64url".to_string())?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing key seed must be 32 bytes".to_string())?;
    Ok(SigningKey::from_seed_bytes(&array))
}

/// Parse the 6-field `--audience` value into an [`AudienceTuple`].
fn parse_audience(value: &str) -> Result<AudienceTuple, String> {
    let f: Vec<&str> = value.split(',').collect();
    if f.len() != 6 {
        return Err(format!(
            "--audience must be scheme,host,port,tenant,route,realm (got {} fields)",
            f.len()
        ));
    }
    let port: u16 = f[2].parse().map_err(|_| "audience port must be u16".to_string())?;
    AudienceTuple::new(f[0], f[1], port, f[3], f[4], f[5])
        .map_err(|e| format!("invalid --audience: {e}"))
}

/// Build the request signer + its custody policy from the configured key source.
/// File keys are software custody (base posture); a Cloud KMS key is non-exporting
/// custody and the hardening profile is REQUIRED (T4 "keys in cloud KMS").
fn build_signer(args: &CliArgs) -> Result<(Box<dyn ClientSigner>, SignerPolicy), String> {
    let base_policy = SignerPolicy::new(&args.signer_id, Environment::Production, true);
    match args.key_source {
        KeySource::File => {
            let seed = args
                .signing_key_seed
                .as_deref()
                .ok_or("--signing-key-seed is required for --key-source file")?;
            let seed_b64url = resolve_inline_or_file(seed)?;
            let signer = SoftwareSigner::new(
                signing_key_from_seed_b64url(&seed_b64url)?,
                &args.signer_id,
                &args.key_id,
            );
            Ok((Box::new(signer), base_policy))
        }
        KeySource::GcpKms => build_kms_signer(args, base_policy),
    }
}

/// The Cloud KMS arm of [`build_signer`], compiled only under the `gcp_kms`
/// feature; a default build refuses `--key-source gcp-kms` with a clear message
/// rather than silently degrading.
#[cfg(feature = "gcp_kms")]
fn build_kms_signer(
    args: &CliArgs,
    base_policy: SignerPolicy,
) -> Result<(Box<dyn ClientSigner>, SignerPolicy), String> {
    let key_version = args
        .gcp_kms_key_version
        .clone()
        .ok_or("--gcp-kms-key-version is required for --key-source gcp-kms")?;
    let config = mcps_proxy::GcpKmsConfig {
        key_version_name: key_version,
        endpoint: args.gcp_kms_endpoint.clone(),
    };
    let signer = kms_signer::KmsClientSigner::new(
        &config,
        args.gcp_kms_use_metadata,
        &args.signer_id,
        &args.key_id,
    )?;
    // Cloud KMS keys are non-exporting; enforce the hardening profile so a
    // software key can never be silently substituted for this route.
    Ok((Box::new(signer), base_policy.require_non_exporting()))
}

#[cfg(not(feature = "gcp_kms"))]
fn build_kms_signer(
    args: &CliArgs,
    _base_policy: SignerPolicy,
) -> Result<(Box<dyn ClientSigner>, SignerPolicy), String> {
    // Acknowledge the KMS args (parsed regardless of feature) so a default build
    // stays dead-code-clean; this build cannot honor them.
    let _ = (
        &args.gcp_kms_key_version,
        &args.gcp_kms_endpoint,
        args.gcp_kms_use_metadata,
    );
    Err("--key-source gcp-kms requires a build with the `gcp_kms` feature".to_string())
}

/// Build the configured [`ClientProxy`] from the parsed args.
fn build_proxy(args: &CliArgs) -> Result<(ClientProxy, SocketAddr), String> {
    let (signer, signer_policy) = build_signer(args)?;

    // Trust the remote's response-signing public key.
    let server_pubkey_b64url = resolve_inline_or_file(&args.server_pubkey)?;
    let server_key = VerificationKey::from_b64url(&server_pubkey_b64url)
        .map_err(|e| format!("invalid --server-pubkey: {e}"))?;
    let mut trust = InMemoryTrustResolver::new();
    trust.insert(&args.server_signer, &args.server_key_id, server_key);

    // The static route: strict (require_mcps), no legacy fallback. The authz
    // binding is an opaque-bytes binding over a demo grant (bind-not-interpret —
    // the server verifies the binding structurally; policy interpretation, if
    // any, is the server's separate concern).
    let route = Route {
        route_id: args.route_id.clone(),
        enforcement_mode: EnforcementMode::RequireMcps,
        legacy_allowed: false,
        signer_audience: SignerAudienceBinding {
            expected_server_signer: args.server_signer.clone(),
            audience: parse_audience(&args.audience)?,
        },
        authz_policy: AuthorizationBindingPolicy::both_base_forms(),
        authz_provider: Box::new(OpaqueBytesProvider::new(b"mcps-walkthrough-grant".to_vec())),
    };

    // Verifying mTLS transport to the remote MCP-S server/proxy.
    let tls = ClientTlsConfig::from_pem(
        &std::fs::read(&args.tls_cert).map_err(|e| format!("read --tls-cert: {e}"))?,
        &std::fs::read(&args.tls_key).map_err(|e| format!("read --tls-key: {e}"))?,
        &std::fs::read(&args.server_ca).map_err(|e| format!("read --server-ca: {e}"))?,
    )
    .map_err(|e| format!("client TLS config: {e}"))?;
    let mtls = MtlsClient::new(tls, &args.server_name).map_err(|e| format!("mtls client: {e}"))?;
    let addr = args
        .remote_addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve --remote-addr '{}': {e}", args.remote_addr))?
        .next()
        .ok_or_else(|| format!("--remote-addr '{}' resolved to no address", args.remote_addr))?;

    let proxy = ClientProxy::new(
        RouteRegistry::new().register(route),
        signer,
        signer_policy,
        Box::new(trust),
        Box::new(MtlsRemoteTransport::new(mtls, addr)),
    );
    Ok((proxy, addr))
}

/// Build the per-call freshness parameters from the OS clock + CSPRNG nonce.
fn call_params(nonce_source: &mut SystemNonceSource, on_behalf_of: &str, ttl_secs: i64) -> CallParams {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64;
    let deadline_unix = now_unix + ttl_secs;
    let mut nonce_bytes = [0u8; 16]; // 128 bits of OS entropy
    nonce_source.fill(&mut nonce_bytes);
    CallParams {
        on_behalf_of: on_behalf_of.to_string(),
        nonce: b64url_encode(&nonce_bytes),
        issued_at: unix_to_rfc3339_utc(now_unix),
        expires_at: unix_to_rfc3339_utc(deadline_unix),
        now_unix,
        deadline_unix,
    }
}

/// Render a plain JSON-RPC error line for a failed exchange. The local client
/// only ever sees plain MCP: a fail-closed MCP-S verdict surfaces as its frozen
/// `mcps.*` wire reason; a transport/local failure surfaces as a diagnostic.
fn error_response(id: Value, err: &ProxyError) -> Value {
    let (code, message) = match err {
        ProxyError::FailedClosed(e) => (-32001, e.wire_code().to_string()),
        ProxyError::Transport(t) => (-32002, format!("transport: {}", t.detail)),
        ProxyError::UnknownRoute(r) => (-32601, format!("unknown route: {r}")),
        ProxyError::MalformedRequest => (-32600, "malformed request".to_string()),
    };
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;
    let (mut proxy, addr) = build_proxy(&args)?;
    // Startup diagnostic: keep this message constant to avoid emitting any
    // user-supplied or runtime-derived values to stderr/log sinks.
    eprintln!("mcps-client-proxy-cli: proxy started");

    let mut nonce_source = SystemNonceSource::new();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in BufReader::new(stdin.lock()).lines() {
        let line = line.map_err(|e| format!("read stdin: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = error_response(Value::Null, &ProxyError::MalformedRequest);
                eprintln!("mcps-client-proxy-cli: parse error: {e}");
                writeln!(stdout, "{resp}").map_err(|e| format!("write stdout: {e}"))?;
                stdout.flush().map_err(|e| format!("flush: {e}"))?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let params = call_params(&mut nonce_source, &args.on_behalf_of, args.ttl_secs);
        let response = match proxy.handle(&args.route_id, &request, &params) {
            Ok(ok) => {
                eprintln!("mcps-client-proxy-cli: path={:?}", ok.path);
                ok.plain_response
            }
            Err(err) => {
                eprintln!("mcps-client-proxy-cli: fail: {err:?}");
                error_response(id, &err)
            }
        };
        writeln!(stdout, "{response}").map_err(|e| format!("write stdout: {e}"))?;
        stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcps-client-proxy-cli: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_argv() -> Vec<String> {
        [
            "--remote-addr", "127.0.0.1:8443",
            "--server-name", "proxy.local",
            "--signer-id", "did:example:client",
            "--key-id", "client-key-1",
            "--signing-key-seed", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--server-signer", "did:example:server",
            "--server-key-id", "server-key-1",
            "--server-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--audience", "https,remote.example,443,acme,tools,prod",
            "--tls-cert", "/c.pem",
            "--tls-key", "/k.pem",
            "--server-ca", "/ca.pem",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn parse_args_fills_defaults() {
        let args = parse_args(&base_argv()).expect("parse");
        assert_eq!(args.route_id, "tools");
        assert_eq!(args.on_behalf_of, "user:demo");
        assert_eq!(args.ttl_secs, 300);
    }

    #[test]
    fn parse_args_requires_remote_addr() {
        let argv: Vec<String> = base_argv().into_iter().skip(2).collect(); // drop --remote-addr pair
        let err = parse_args(&argv).unwrap_err();
        assert!(err.contains("--remote-addr"), "{err}");
    }

    #[test]
    fn audience_must_have_six_fields() {
        assert!(parse_audience("https,h,443,acme,tools").is_err());
        assert!(parse_audience("https,h,443,acme,tools,prod").is_ok());
    }

    #[test]
    fn call_params_nonce_is_128_bit_b64url() {
        let mut ns = SystemNonceSource::new();
        let p = call_params(&mut ns, "user:x", 300);
        // 16 bytes -> 22 base64url chars (unpadded).
        assert_eq!(p.nonce.len(), 22);
        assert_eq!(p.deadline_unix - p.now_unix, 300);
    }
}
