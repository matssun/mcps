//! Configuration + wiring for the production `mcps-proxy` CLI (MCPS-029,
//! ADR-MCPS-014; folds in MCPS-018 #3807).
//!
//! The pure, testable pieces of the binary live here: argument parsing, the
//! trust-file loader, the subprocess inner server, and the builders that turn a
//! [`Config`] into a [`KeySource`] / [`TrustResolver`] / [`Proxy`]. `main.rs` is a
//! thin shell that parses, builds, and runs the blocking serve loop.

use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcps_core::InMemoryTrustResolver;
use mcps_core::VerificationKey;
use serde_json::Value;

use crate::inner_launch::BoundedStderr;
use crate::inner_launch::InnerLaunchConfig;
use crate::inner_launch::InnerLogEvent;
use crate::inner_launch::InnerLogSink;
use crate::inner_launch::StderrLogSink;
// MCPS-076 (audit gap G-3): EnvKeySource is dev/CI-only — compiled only under the
// non-default `dev_env_key_source` feature.
#[cfg(feature = "dev_env_key_source")]
use crate::key_source::EnvKeySource;
use crate::key_source::FileKeySource;
use crate::key_source::KeyError;
use crate::key_source::KeySource;
use crate::proxy::InnerServer;
use crate::sandbox::NetworkPolicy;
use crate::sandbox::SandboxMode;
use crate::tls::ServerLimits;
use crate::transport::IdentityPolicy;
use crate::transport::ReverseProxyHeaderFormat;

/// Where key material is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceKind {
    /// Files on disk (locations are paths).
    File,
    /// Environment variables (locations are variable names).
    Env,
    /// PKCS#11 token (issue #4034): the Ed25519 response-signing key lives on a
    /// hardware/software token and is exercised only via `C_Sign` — it never
    /// leaves the device. The TLS cert/key/CA still come from files in this
    /// build. Honored ONLY in a build with the `pkcs11_keysource` feature; a
    /// default build parses it but FAILS CLOSED at construction (mirrors `Env`).
    Pkcs11,
}

/// Replay-cache backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayKind {
    /// In-memory (lost on restart).
    Memory,
    /// Durable file-backed (SINGLE-NODE only).
    File,
    /// Shared, server-side-atomic cache for HORIZONTALLY-SCALED replay safety
    /// (issue #3837). No production shared backend ships in this build (the Redis
    /// adapter + crate repin + live-backend test are tracked separately), so
    /// selecting `shared` parses but FAILS CLOSED at construction with a clear
    /// "not yet available in this build" error (mirrors the env-keysource gate).
    Shared,
}

/// Transport-binding policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// No transport binding (the mTLS identity is ignored).
    None,
    /// Exact match: request `signer` must equal the verified transport identity.
    Exact,
}

/// ONLINE client-cert OCSP revocation selection (#4030). The online sibling of
/// the offline `--client-crl` posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspKind {
    /// No online OCSP check (the default). Revocation, if any, comes only from
    /// the offline `--client-crl` set.
    Off,
    /// Require an online OCSP check at connection time. A verified client leaf is
    /// rejected on `Revoked` (always) and on `Unknown`/unreachable/timeout/parse
    /// error UNLESS `--ocsp-soft-fail` is set. Honored ONLY in a build with the
    /// `online_ocsp` feature; a default build parses it but FAILS CLOSED at
    /// construction (mirrors the env-keysource / shared-replay gates).
    Require,
}

/// Authorization-policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzKind {
    /// No authorization policy.
    Off,
    /// The reference signed-authorization profile.
    Reference,
}

/// Inner-server process model selection (MCPS-066, MCPS-EPIC-P6.6B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerModeKind {
    /// One-shot: spawn the inner command per request, write the request to its
    /// stdin, read its stdout to EOF, and expect it to exit (the default; fronts
    /// the one-shot-shaped `mcps-demo-fileserver`).
    OneShot,
    /// Persistent: spawn the inner command ONCE, perform the MCP `initialize`
    /// handshake, and keep it alive across many newline-delimited requests
    /// (fronts a long-lived MCP server, e.g. `mcps-demo-server`).
    Persistent,
}

/// Fully-parsed CLI configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address, e.g. `127.0.0.1:8443`.
    pub bind: String,
    /// Expected audience (this server's identity).
    pub audience: String,
    /// Response-signing signer identity.
    pub server_signer: String,
    /// Response-signing key id.
    pub server_key_id: String,
    /// Symmetric clock skew (seconds).
    pub max_clock_skew: i64,
    /// Where key material is read from.
    pub key_source: KeySourceKind,
    /// Location (path or env var) of the Base64URL Ed25519 signing-key seed.
    pub signing_key_seed: String,
    /// Location of the PEM TLS server certificate chain.
    pub tls_cert: String,
    /// Location of the PEM TLS server private key.
    pub tls_key: String,
    /// Location of the PEM client-CA trust anchors.
    pub client_ca: String,
    /// Paths to offline client-certificate revocation lists (CRLs), PEM or DER
    /// (#3839). Each `--client-crl` value (comma-separated and/or repeated) adds a
    /// file; empty disables revocation checking (the pre-#3839 behavior). OFFLINE
    /// only — there is no online OCSP / distribution-point fetching.
    pub client_crl_paths: Vec<String>,
    /// Relax the fail-closed revocation posture: when `true`, a client cert whose
    /// revocation status cannot be determined from the configured CRLs is ALLOWED
    /// rather than rejected. Default `false` (deny unknown status — fail closed).
    /// Has no effect when no CRLs are configured.
    pub crl_allow_unknown_status: bool,
    /// ONLINE OCSP client-cert revocation selection (#4030). `Off` (default) does
    /// no online check; `Require` checks the leaf's OCSP responder at connection
    /// time. Honored ONLY in an `online_ocsp` build; a default build fails closed
    /// at construction when `Require` is selected.
    pub client_ocsp: OcspKind,
    /// Explicit OCSP responder URL overriding the leaf's AIA OCSP URL (#4030).
    /// `None` uses the AIA URL from the certificate. Only meaningful when
    /// `client_ocsp == Require`.
    pub ocsp_responder_url: Option<String>,
    /// Relax the OCSP fail-closed posture (#4030): when `true`, an indeterminate
    /// online result (`Unknown`, unreachable responder, timeout, parse/signature
    /// error) ALLOWS the connection instead of rejecting it. A `Revoked` status
    /// ALWAYS rejects regardless. Default `false` = hard-fail (deny on anything
    /// but `Good`). Only meaningful when `client_ocsp == Require`.
    pub ocsp_soft_fail: bool,
    /// Path to the JSON trust file (request signers + authorization issuers).
    pub trust_path: String,
    /// Replay-cache backend.
    pub replay: ReplayKind,
    /// Replay-cache file path (required when `replay == File`).
    pub replay_path: Option<String>,
    /// Shared replay-store connection URL (required when `replay == Shared`),
    /// e.g. `redis://127.0.0.1:6379` (issue #3837).
    pub replay_redis_url: Option<String>,
    /// Declared replay-store durability tier (ADR-MCPS-020). Required when
    /// `replay == Shared` — the tier is an explicit deployment assertion that
    /// determines the horizontal replay-safety claim. `None` for single-node
    /// `Memory` / `File` backends.
    pub replay_durability_tier: Option<crate::replay_tier::ReplayDurabilityTier>,
    /// Transport-binding selection.
    pub binding: BindingKind,
    /// The authoritative identity field (no implicit fallback). For the default
    /// direct-TLS path this is the client-certificate field; for reverse-proxy
    /// mode it selects which forwarded-header field is authoritative.
    pub identity_source: IdentityPolicy,
    /// Reverse-proxy ingress (MCPS-3840): when `Some`, the proxy reads the
    /// verified client identity from this TRUSTED forwarded header (set by an
    /// upstream mTLS-terminating reverse proxy) instead of extracting it from a
    /// locally-terminated client certificate. Enabling this is an explicit
    /// operator assertion that the listening socket is reachable ONLY by the
    /// trusted upstream. Mutually exclusive with local client-cert identity.
    pub reverse_proxy_identity_header: Option<String>,
    /// The wire format of the trusted reverse-proxy identity header (plain
    /// identity string or Envoy XFCC). Only meaningful when
    /// `reverse_proxy_identity_header` is set.
    pub reverse_proxy_header_format: ReverseProxyHeaderFormat,
    /// Authorization-policy selection.
    pub authz: AuthzKind,
    /// Inner-server process model: one-shot (default) or persistent (MCPS-066).
    pub inner_mode: InnerModeKind,
    /// Allow the (dev/CI-only) environment-variable key source in this run.
    /// Required when `key_source == Env`; absent, env keys are refused.
    pub allow_env_keysource: bool,
    /// PKCS#11 module (provider `.so`/`.dylib`) path. Required when
    /// `key_source == Pkcs11` (issue #4034).
    pub pkcs11_module: Option<String>,
    /// PKCS#11 token User PIN (SENSITIVE). Required when `key_source == Pkcs11`.
    pub pkcs11_pin: Option<String>,
    /// PKCS#11 token label selecting the slot whose token holds the signing key
    /// (token labels are stable across reboots; slot ids are not). Required when
    /// `key_source == Pkcs11`.
    pub pkcs11_token_label: Option<String>,
    /// CKA_LABEL of the Ed25519 signing-key object on the token. Required when
    /// `key_source == Pkcs11`.
    pub pkcs11_key_label: Option<String>,
    /// Connection resource limits (DoS defense).
    pub limits: ServerLimits,
    /// Maximum client-certificate lifetime (v1 revocation posture). Defaults to
    /// 1 hour; `None` disables enforcement (strongly discouraged).
    pub max_client_cert_lifetime: Option<Duration>,
    /// The inner MCP server command + args (`[cmd, arg, ...]`).
    pub inner_command: Vec<String>,
    /// How the inner subprocess's environment is constructed (MCPS-035): cleared
    /// by default, then only an explicit allowlist (`--inner-env` /
    /// `--inner-env-allow`). Full inheritance is opt-in (`--inherit-env`).
    pub inner_launch: InnerLaunchConfig,
    /// Strict/production posture (MCPS-3842, `--strict`/`--production`). When
    /// `true`, insecure-posture configurations that are otherwise only WARNED
    /// about become HARD startup errors ("reject, not warn"). Default `false`
    /// keeps the legacy warn-only behavior unchanged.
    pub strict: bool,
    /// Whether `--inner-sandbox off` was passed EXPLICITLY (#4082, M09). The
    /// inner-sandbox default is also `Off`, but no kernel backend ships in this
    /// build, so a blanket strict `enforce` requirement would fail closed
    /// everywhere. We therefore distinguish a DELIBERATE `--inner-sandbox off`
    /// (an explicit request for zero inner containment) from the unset default:
    /// under `--strict`, the explicit form is a violation, the default is not.
    pub sandbox_explicitly_off: bool,
}

/// Every proxy/security flag this parser recognizes (excluding `--inner-command`
/// itself). Used to scan the inner-command tail for a misplaced proxy flag.
///
/// `--inner-command` consumes the remainder of argv as the inner server's argv,
/// so any token after it is NEVER interpreted by the proxy. If that token is in
/// fact a known proxy/security flag (#4066 / MCPS-091), it was almost certainly
/// mis-placed by the operator: silently swallowing it would (a) drop a security
/// control with NO warning — e.g. `--strict` would leave `strict == false`, a
/// fail-open trust-posture downgrade — and (b) leak the flag verbatim into the
/// hostile inner server's argv. So the tail is scanned and any such flag is a
/// HARD parse error (fail closed) instructing the operator to move it before
/// `--inner-command`.
const KNOWN_PROXY_FLAGS: &[&str] = &[
    // Valueless boolean flags.
    "--allow-env-keysource",
    "--crl-allow-unknown-status",
    "--ocsp-soft-fail",
    "--strict",
    "--production",
    // Value-taking flags.
    "--bind",
    "--audience",
    "--server-signer",
    "--server-key-id",
    "--max-clock-skew",
    "--key-source",
    "--pkcs11-module",
    "--pkcs11-pin",
    "--pkcs11-token-label",
    "--pkcs11-key-label",
    "--signing-key-seed",
    "--tls-cert",
    "--tls-key",
    "--client-ca",
    "--client-crl",
    "--trust",
    "--client-ocsp",
    "--ocsp-responder-url",
    "--replay-cache",
    "--replay-path",
    "--replay-redis-url",
    "--replay-durability-tier",
    "--transport-binding",
    "--transport-identity-source",
    "--reverse-proxy-identity-header",
    "--reverse-proxy-header-format",
    "--authz",
    "--inner-mode",
    "--max-header-bytes",
    "--max-body-bytes",
    "--read-timeout-secs",
    "--write-timeout-secs",
    "--inner-read-timeout-secs",
    "--max-connections",
    "--max-client-cert-lifetime",
    "--inherit-env",
    "--inner-env",
    "--inner-env-allow",
    "--inner-working-dir",
    "--inner-stderr-cap-bytes",
    "--inner-stderr-cap-lines",
    "--inner-rlimit-nofile",
    "--inner-rlimit-cpu-seconds",
    "--inner-rlimit-as-bytes",
    "--inner-rlimit-data-bytes",
    "--inner-rlimit-core-bytes",
    "--inner-rlimit-fsize-bytes",
    "--inner-rlimit-best-effort",
    "--inner-sandbox",
    "--inner-fs-allow-read",
    "--inner-fs-allow-write",
    "--inner-net",
];

/// Parse CLI arguments (excluding argv[0]) into a [`Config`]. Returns a
/// human-readable error string on any missing/invalid argument.
pub fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut bind = None;
    let mut audience = None;
    let mut server_signer = None;
    let mut server_key_id = None;
    let mut max_clock_skew: i64 = 300;
    let mut key_source = KeySourceKind::File;
    let mut signing_key_seed = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut client_ca = None;
    // #3839 offline CRL revocation: zero or more CRL file paths, fail-closed on
    // unknown status by default.
    let mut client_crl_paths: Vec<String> = Vec::new();
    let mut crl_allow_unknown_status = false;
    // #4030 online OCSP revocation: off by default; responder-URL override
    // optional; hard-fail (deny on indeterminate) by default.
    let mut client_ocsp = OcspKind::Off;
    let mut ocsp_responder_url: Option<String> = None;
    let mut ocsp_soft_fail = false;
    let mut trust_path = None;
    let mut replay = ReplayKind::Memory;
    let mut replay_path = None;
    let mut replay_redis_url = None;
    let mut replay_durability_tier: Option<crate::replay_tier::ReplayDurabilityTier> = None;
    let mut binding = BindingKind::Exact;
    let mut identity_source = IdentityPolicy::UriSan;
    let mut reverse_proxy_identity_header: Option<String> = None;
    let mut reverse_proxy_header_format = ReverseProxyHeaderFormat::Xfcc;
    let mut authz = AuthzKind::Off;
    // Inner process model: one-shot by default (preserves the existing behavior
    // for the one-shot-shaped fileserver); persistent fronts a long-lived server.
    let mut inner_mode = InnerModeKind::OneShot;
    let mut allow_env_keysource = false;
    // #4034 PKCS#11 key source: module path, User PIN (sensitive), token label,
    // and signing-key object label. Required only when `--key-source pkcs11`.
    let mut pkcs11_module: Option<String> = None;
    let mut pkcs11_pin: Option<String> = None;
    let mut pkcs11_token_label: Option<String> = None;
    let mut pkcs11_key_label: Option<String> = None;
    let mut limits = ServerLimits::default();
    // v1 revocation posture: short-lived client certs, proxy-enforced, default 1h.
    let mut max_client_cert_lifetime = Some(Duration::from_secs(3600));
    let mut inner_command: Vec<String> = Vec::new();
    // MCPS-035 inner-server environment minimization. Secure defaults: clear the
    // child environment and apply only the explicit allowlist below.
    let mut inner_launch = InnerLaunchConfig::new();
    // MCPS-3842 strict/production posture: off by default (warn-only). When set,
    // insecure-posture configs are rejected at startup instead of merely warned.
    let mut strict = false;
    // #4082 (M09): track whether `--inner-sandbox off` was given EXPLICITLY, so
    // strict can reject a deliberate no-containment request without rejecting the
    // (identical-valued) default that ships when the flag is omitted.
    let mut sandbox_explicitly_off = false;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        // `--inner-command` consumes the remainder of argv as the inner server's
        // argv. A known proxy/security flag in that tail is a misplacement (#4066
        // / MCPS-091): swallowing it would silently drop a security control and
        // leak the flag into the hostile inner server. Fail closed with a loud,
        // actionable error rather than downgrade the trust posture in silence.
        if flag == "--inner-command" {
            let tail = &args[i + 1..];
            if let Some(misplaced) = tail.iter().find(|t| KNOWN_PROXY_FLAGS.contains(&t.as_str())) {
                return Err(format!(
                    "proxy flag {misplaced} appears AFTER --inner-command, where it would be \
                     silently passed to the inner server instead of configuring the proxy; \
                     move {misplaced} (and any other proxy flags) BEFORE --inner-command"
                ));
            }
            inner_command = tail.to_vec();
            break;
        }
        // Valueless boolean flag.
        if flag == "--allow-env-keysource" {
            allow_env_keysource = true;
            i += 1;
            continue;
        }
        // Valueless boolean flag: relax the CRL unknown-status posture (#3839).
        if flag == "--crl-allow-unknown-status" {
            crl_allow_unknown_status = true;
            i += 1;
            continue;
        }
        // Valueless boolean flag (#4030): relax the online OCSP posture to
        // fail-OPEN on an indeterminate result. Default OFF (hard-fail).
        if flag == "--ocsp-soft-fail" {
            ocsp_soft_fail = true;
            i += 1;
            continue;
        }
        // Valueless boolean flag (#3842): strict/production mode — reject (not
        // warn) unsafe configs. `--production` is an alias. Without this arm the
        // `strict` flag was never set, so `strict_violations` below was dead.
        if flag == "--strict" || flag == "--production" {
            strict = true;
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        match flag {
            "--bind" => bind = Some(value.clone()),
            "--audience" => audience = Some(value.clone()),
            "--server-signer" => server_signer = Some(value.clone()),
            "--server-key-id" => server_key_id = Some(value.clone()),
            "--max-clock-skew" => {
                max_clock_skew = value.parse().map_err(|_| "invalid --max-clock-skew".to_string())?
            }
            "--key-source" => {
                key_source = match value.as_str() {
                    "file" => KeySourceKind::File,
                    "env" => KeySourceKind::Env,
                    "pkcs11" => KeySourceKind::Pkcs11,
                    other => {
                        return Err(format!("unknown --key-source '{other}' (file|env|pkcs11)"))
                    }
                }
            }
            // #4034 PKCS#11 key source. `--pkcs11-pin` is SENSITIVE: prefer a
            // mechanism that keeps it off the argv visible via `ps`/`/proc`.
            "--pkcs11-module" => pkcs11_module = Some(value.clone()),
            "--pkcs11-pin" => pkcs11_pin = Some(value.clone()),
            "--pkcs11-token-label" => pkcs11_token_label = Some(value.clone()),
            "--pkcs11-key-label" => pkcs11_key_label = Some(value.clone()),
            "--signing-key-seed" => signing_key_seed = Some(value.clone()),
            "--tls-cert" => tls_cert = Some(value.clone()),
            "--tls-key" => tls_key = Some(value.clone()),
            "--client-ca" => client_ca = Some(value.clone()),
            // #3839: repeatable and/or comma-separated CRL file paths. An empty
            // segment (e.g. a trailing comma) is rejected so a typo cannot
            // silently load zero CRLs and quietly disable revocation checking.
            "--client-crl" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --client-crl '{value}' (empty path segment)"
                        ));
                    }
                    client_crl_paths.push(segment.to_string());
                }
            }
            "--trust" => trust_path = Some(value.clone()),
            // #4030 online OCSP revocation mode.
            "--client-ocsp" => {
                client_ocsp = match value.as_str() {
                    "off" => OcspKind::Off,
                    "require" => OcspKind::Require,
                    other => {
                        return Err(format!("unknown --client-ocsp '{other}' (off|require)"))
                    }
                }
            }
            // #4030 AIA-override responder URL. Must be non-empty when present.
            "--ocsp-responder-url" => {
                if value.trim().is_empty() {
                    return Err("--ocsp-responder-url requires a non-empty URL".to_string());
                }
                ocsp_responder_url = Some(value.clone());
            }
            "--replay-cache" => {
                replay = match value.as_str() {
                    "memory" => ReplayKind::Memory,
                    "file" => ReplayKind::File,
                    "shared" => ReplayKind::Shared,
                    other => {
                        return Err(format!(
                            "unknown --replay-cache '{other}' (memory|file|shared)"
                        ))
                    }
                }
            }
            "--replay-path" => replay_path = Some(value.clone()),
            "--replay-redis-url" => replay_redis_url = Some(value.clone()),
            "--replay-durability-tier" => {
                replay_durability_tier =
                    Some(crate::replay_tier::ReplayDurabilityTier::parse(value)?)
            }
            "--transport-binding" => {
                binding = match value.as_str() {
                    "none" => BindingKind::None,
                    "exact" => BindingKind::Exact,
                    other => return Err(format!("unknown --transport-binding '{other}' (none|exact)")),
                }
            }
            "--transport-identity-source" => {
                identity_source = match value.as_str() {
                    "uri_san" => IdentityPolicy::UriSan,
                    "dns_san" => IdentityPolicy::DnsSan,
                    "cn_legacy" => IdentityPolicy::CnLegacy,
                    other => {
                        return Err(format!(
                            "unknown --transport-identity-source '{other}' (uri_san|dns_san|cn_legacy)"
                        ))
                    }
                }
            }
            "--reverse-proxy-identity-header" => {
                // The trusted forwarded header name. Presence of this flag selects
                // reverse-proxy ingress mode (mTLS terminated upstream).
                if value.trim().is_empty() {
                    return Err("--reverse-proxy-identity-header requires a non-empty header name".to_string());
                }
                reverse_proxy_identity_header = Some(value.clone());
            }
            "--reverse-proxy-header-format" => {
                reverse_proxy_header_format = match value.as_str() {
                    "plain" => ReverseProxyHeaderFormat::Plain,
                    "xfcc" => ReverseProxyHeaderFormat::Xfcc,
                    other => {
                        return Err(format!(
                            "unknown --reverse-proxy-header-format '{other}' (plain|xfcc)"
                        ))
                    }
                }
            }
            "--authz" => {
                authz = match value.as_str() {
                    "off" => AuthzKind::Off,
                    "reference" => AuthzKind::Reference,
                    other => return Err(format!("unknown --authz '{other}' (off|reference)")),
                }
            }
            "--inner-mode" => {
                inner_mode = match value.as_str() {
                    "oneshot" => InnerModeKind::OneShot,
                    "persistent" => InnerModeKind::Persistent,
                    other => {
                        return Err(format!("unknown --inner-mode '{other}' (oneshot|persistent)"))
                    }
                }
            }
            "--max-header-bytes" => {
                limits.max_header_bytes =
                    value.parse().map_err(|_| "invalid --max-header-bytes".to_string())?
            }
            "--max-body-bytes" => {
                limits.max_body_bytes =
                    value.parse().map_err(|_| "invalid --max-body-bytes".to_string())?
            }
            "--read-timeout-secs" => {
                limits.read_timeout = parse_timeout(value, "--read-timeout-secs")?
            }
            "--write-timeout-secs" => {
                limits.write_timeout = parse_timeout(value, "--write-timeout-secs")?
            }
            "--inner-read-timeout-secs" => {
                inner_launch.inner_read_timeout =
                    parse_positive_timeout(value, "--inner-read-timeout-secs")?
            }
            "--max-connections" => {
                let n: usize =
                    value.parse().map_err(|_| "invalid --max-connections".to_string())?;
                if n == 0 {
                    return Err("--max-connections must be > 0".to_string());
                }
                limits.max_concurrent_connections = n;
            }
            "--max-client-cert-lifetime" => {
                max_client_cert_lifetime = parse_cert_lifetime(value)?
            }
            "--inherit-env" => {
                inner_launch.inherit_env = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!("unknown --inherit-env '{other}' (true|false)"))
                    }
                }
            }
            "--inner-env" => {
                inner_launch.explicit_env.push(parse_env_pair(value)?);
            }
            "--inner-env-allow" => {
                inner_launch.allow_env_names.push(value.clone());
            }
            "--inner-working-dir" => {
                inner_launch.working_dir = Some(value.clone());
            }
            "--inner-stderr-cap-bytes" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "invalid --inner-stderr-cap-bytes".to_string())?;
                if n == 0 {
                    return Err("--inner-stderr-cap-bytes must be > 0".to_string());
                }
                inner_launch.stderr_cap_bytes = n;
            }
            "--inner-stderr-cap-lines" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "invalid --inner-stderr-cap-lines".to_string())?;
                if n == 0 {
                    return Err("--inner-stderr-cap-lines must be > 0".to_string());
                }
                inner_launch.stderr_cap_lines = n;
            }
            // MCPS-037 inner-server Unix setrlimit resource hardening (NOT
            // sandboxing). Each ceiling is individually configurable; `0` is a
            // valid (very tight) ceiling, so these accept any u64.
            "--inner-rlimit-nofile" => {
                inner_launch.rlimits.nofile = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-cpu-seconds" => {
                inner_launch.rlimits.cpu_seconds = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-as-bytes" => {
                inner_launch.rlimits.address_space_bytes = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-data-bytes" => {
                inner_launch.rlimits.data_bytes = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-core-bytes" => {
                inner_launch.rlimits.core_bytes = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-fsize-bytes" => {
                inner_launch.rlimits.fsize_bytes = parse_rlimit_value(flag, value)?;
            }
            "--inner-rlimit-best-effort" => {
                inner_launch.rlimits.best_effort = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!(
                            "unknown --inner-rlimit-best-effort '{other}' (true|false)"
                        ))
                    }
                }
            }
            // #3865 OS sandbox profile: top-level mode. `enforce` REQUIRES kernel
            // containment or refuses to start (fail closed); `off` (default) keeps
            // today's no-containment behavior exactly.
            "--inner-sandbox" => {
                inner_launch.sandbox.mode = match value.as_str() {
                    "off" => {
                        // #4082 (M09): record the EXPLICIT off so strict can refuse
                        // a deliberate no-containment request.
                        sandbox_explicitly_off = true;
                        SandboxMode::Off
                    }
                    "enforce" => SandboxMode::Enforce,
                    other => {
                        return Err(format!("unknown --inner-sandbox '{other}' (off|enforce)"))
                    }
                }
            }
            // #3865 filesystem read-allowlist: repeatable and/or comma-separated,
            // mirroring `--client-crl`. An empty segment (e.g. a trailing comma) is
            // rejected so a typo cannot silently widen filesystem access.
            "--inner-fs-allow-read" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --inner-fs-allow-read '{value}' (empty path segment)"
                        ));
                    }
                    inner_launch.sandbox.fs_allow_read.push(segment.to_string());
                }
            }
            // #3865 filesystem write-allowlist: same parsing as the read allowlist.
            "--inner-fs-allow-write" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --inner-fs-allow-write '{value}' (empty path segment)"
                        ));
                    }
                    inner_launch.sandbox.fs_allow_write.push(segment.to_string());
                }
            }
            // #3865 network egress policy. Default is deny-all; `allow` is no
            // network containment (explicit operator choice).
            "--inner-net" => {
                inner_launch.sandbox.network = match value.as_str() {
                    "deny" => NetworkPolicy::DenyAll,
                    "allow" => NetworkPolicy::Allow,
                    other => {
                        return Err(format!("unknown --inner-net '{other}' (deny|allow)"))
                    }
                }
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }

    let require = |opt: Option<String>, name: &str| opt.ok_or_else(|| format!("missing required {name}"));
    if replay == ReplayKind::File && replay_path.is_none() {
        return Err("--replay-cache file requires --replay-path".to_string());
    }
    if replay == ReplayKind::Shared && replay_redis_url.is_none() {
        return Err("--replay-cache shared requires --replay-redis-url".to_string());
    }
    // ADR-MCPS-020: the durability tier is an explicit deployment assertion that
    // determines the horizontal replay-safety claim, so a shared store MUST
    // declare it (fail closed rather than assume a tier).
    if replay == ReplayKind::Shared && replay_durability_tier.is_none() {
        return Err("--replay-cache shared requires --replay-durability-tier \
                    (redis-async | redis-wait-quorum:<quorum>:<timeout_ms> | linearizable | \
                    single-store-fail-closed)"
            .to_string());
    }
    // EnvKeySource is dev/CI-only: refuse env key material unless explicitly
    // opted in. Environment variables are visible to the process tree and may
    // leak via crash dumps / `ps e` / orchestrator inspection.
    if key_source == KeySourceKind::Env && !allow_env_keysource {
        return Err(
            "--key-source env requires --allow-env-keysource (env key material is dev/CI-only; \
             use --key-source file in production)"
                .to_string(),
        );
    }
    // #4034 PKCS#11 key source: the module path, User PIN, token label, and
    // signing-key object label are all required when this source is selected.
    // Each is checked here (not in build_key_source) so a missing flag is a clear
    // parse error regardless of which feature the binary was built with.
    if key_source == KeySourceKind::Pkcs11 {
        if pkcs11_module.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-module <path>".to_string());
        }
        if pkcs11_pin.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-pin <pin>".to_string());
        }
        if pkcs11_token_label.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-token-label <label>".to_string());
        }
        if pkcs11_key_label.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-key-label <label>".to_string());
        }
    }
    if inner_command.is_empty() {
        return Err("missing required --inner-command <cmd> [args...]".to_string());
    }

    // MCPS-3840 reverse-proxy ingress: identity comes EITHER from a locally-
    // terminated client certificate OR from a trusted forwarded header, never
    // both (the two identity sources are mutually exclusive). When the header
    // strategy is selected, the proxy does NOT extract identity from a local
    // client cert, so a configured local client-cert-lifetime enforcement is
    // contradictory (there is no local client cert to bound). Require it be
    // explicitly disabled (`--max-client-cert-lifetime none`) so the operator
    // cannot believe a local-cert control is in force when it is not.
    if reverse_proxy_identity_header.is_some() && max_client_cert_lifetime.is_some() {
        return Err(
            "--reverse-proxy-identity-header terminates mTLS UPSTREAM, so the local \
             client-certificate identity path is disabled and a local \
             --max-client-cert-lifetime cannot be enforced; pass \
             --max-client-cert-lifetime none to acknowledge that local client-cert \
             controls do not apply in reverse-proxy mode"
                .to_string(),
        );
    }

    // #4063 (MCPS-088) online-OCSP gating — fail CLOSED at the CLI trust boundary.
    // These arms ensure an operator can never believe an OCSP control is in force
    // when it is not, and that `require` is rejected outright in a build that
    // cannot perform the verified online check.
    //
    // (a) The OCSP knobs are only honored under `--client-ocsp require`. A dangling
    //     `--ocsp-responder-url` or `--ocsp-soft-fail` without it would SILENTLY do
    //     nothing — a dangerous illusion of revocation/soft-fail posture — so it is
    //     a hard error.
    if client_ocsp != OcspKind::Require {
        if ocsp_responder_url.is_some() {
            return Err(
                "--ocsp-responder-url has no effect without --client-ocsp require"
                    .to_string(),
            );
        }
        if ocsp_soft_fail {
            return Err(
                "--ocsp-soft-fail has no effect without --client-ocsp require".to_string(),
            );
        }
    }
    // (b) `--client-ocsp require` demands the verified online OCSP path, which is
    //     compiled ONLY under the `online_ocsp` feature. In a build without it,
    //     `require` must FAIL CLOSED at parse time rather than silently skipping
    //     the revocation check (the proxy must never start believing it enforces
    //     online revocation when the code to do so is not present).
    #[cfg(not(feature = "online_ocsp"))]
    if client_ocsp == OcspKind::Require {
        return Err(
            "--client-ocsp require needs the online_ocsp feature, which is \
             not available in this build (rebuild with --features online_ocsp)"
                .to_string(),
        );
    }
    // (c) Under the feature, OCSP checks the LOCALLY-terminated client cert, which
    //     does not exist in reverse-proxy (forwarded-header) ingress mode.
    #[cfg(feature = "online_ocsp")]
    if client_ocsp == OcspKind::Require && reverse_proxy_identity_header.is_some() {
        return Err(
            "--client-ocsp require checks the locally-terminated client certificate, \
             which is absent in reverse-proxy mode (--reverse-proxy-identity-header); \
             online OCSP cannot apply there"
                .to_string(),
        );
    }

    let config = Config {
        bind: require(bind, "--bind")?,
        audience: require(audience, "--audience")?,
        server_signer: require(server_signer, "--server-signer")?,
        server_key_id: require(server_key_id, "--server-key-id")?,
        max_clock_skew,
        key_source,
        signing_key_seed: require(signing_key_seed, "--signing-key-seed")?,
        tls_cert: require(tls_cert, "--tls-cert")?,
        tls_key: require(tls_key, "--tls-key")?,
        client_ca: require(client_ca, "--client-ca")?,
        client_crl_paths,
        crl_allow_unknown_status,
        client_ocsp,
        ocsp_responder_url,
        ocsp_soft_fail,
        trust_path: require(trust_path, "--trust")?,
        replay,
        replay_path,
        replay_redis_url,
        replay_durability_tier,
        binding,
        identity_source,
        reverse_proxy_identity_header,
        reverse_proxy_header_format,
        authz,
        inner_mode,
        allow_env_keysource,
        pkcs11_module,
        pkcs11_pin,
        pkcs11_token_label,
        pkcs11_key_label,
        limits,
        max_client_cert_lifetime,
        inner_command,
        inner_launch,
        strict,
        sandbox_explicitly_off,
    };

    // MCPS-3842 ("reject, not warn"): under strict/production posture, refuse to
    // start with any insecure-posture configuration that is otherwise only
    // warned about. The decision lives in the pure [`strict_violations`] helper
    // so it is black-box testable and shared with `main.rs` (which adds the
    // filesystem-dependent key-file-permission check). The proxy never even
    // constructs when a parse-time violation is present.
    if config.strict {
        let violations = strict_violations(&config);
        if !violations.is_empty() {
            return Err(format!(
                "--strict/--production refuses unsafe configuration:\n  - {}",
                violations.join("\n  - ")
            ));
        }
    }

    Ok(config)
}

/// Collect the parse-time strict-posture violations for `config` (MCPS-3842).
///
/// This is the pure, black-box-testable core of `--strict`/`--production`: each
/// returned string names the offending flag and how to fix it. It covers ONLY
/// the conditions knowable from the parsed [`Config`] — the group/world-readable
/// key-file check is filesystem-dependent and lives in `main.rs` (which reads the
/// file mode and reuses the same fail-closed posture).
///
/// Deliberately EXCLUDED: a `--max-client-cert-lifetime` greater than the
/// recommended 1h. That is a RECOMMENDATION (the default is 1h), not an unsafe
/// posture — a longer-but-still-enforced lifetime is a tradeoff, not a hole — so
/// it stays a warning even under strict. Only DISABLED enforcement (`none`/`0`,
/// i.e. `max_client_cert_lifetime == None`) is an unsafe posture and is rejected.
///
/// Also deliberately EXCLUDED (#4082): the DEFAULT `--inner-sandbox off`,
/// `--inner-net allow`, and `--authz off`. No kernel sandbox backend ships in
/// this build, so requiring `--inner-sandbox enforce` (and the network policy it
/// gates) under strict would fail closed on every platform; only an EXPLICIT
/// `--inner-sandbox off` is rejected (see `sandbox_explicitly_off`). `authz off`
/// is the established default authorization mode, not a downgrade of an enforced
/// one. The postures rejected here are the pure-config, platform-independent
/// fail-open ones: explicit no-sandbox, reverse-proxy header ingress (M10/M22),
/// `--transport-binding none` (M11), and the OCSP/CRL fail-open relaxations (M12).
pub fn strict_violations(config: &Config) -> Vec<String> {
    let mut violations = Vec::new();
    if config.key_source == KeySourceKind::Env {
        violations.push(
            "--key-source env (env key material is visible to the process tree and dev/CI-only); \
             use --key-source file"
                .to_string(),
        );
    }
    if config.max_client_cert_lifetime.is_none() {
        violations.push(
            "--max-client-cert-lifetime none/0 disables client-cert lifetime enforcement; \
             set a bounded lifetime (default 1h)"
                .to_string(),
        );
    }
    if config.inner_launch.inherit_env {
        violations.push(
            "--inherit-env true passes the proxy's ENTIRE environment to the inner server \
             (leaks env-loaded secrets); use --inherit-env false with explicit \
             --inner-env / --inner-env-allow"
                .to_string(),
        );
    }
    if config.identity_source == IdentityPolicy::CnLegacy {
        violations.push(
            "--transport-identity-source cn_legacy is a deprecated, insecure identity binding; \
             use uri_san or dns_san"
                .to_string(),
        );
    }
    if config.inner_launch.rlimits.best_effort {
        violations.push(
            "--inner-rlimit-best-effort true silently degrades resource ceilings to logged \
             no-ops; production must fail closed (--inner-rlimit-best-effort false)"
                .to_string(),
        );
    }
    // ADR-MCPS-020: under strict/production a shared replay store must declare a
    // durability tier of REDIS_WAIT_QUORUM or stronger. REDIS_ASYNC carries a
    // bounded-but-real failover replay window, and SINGLE_STORE_FAIL_CLOSED is a
    // single point of availability failure — both are rejected (not just warned)
    // so production cannot silently run on the weaker replay-safety claim.
    if config.replay == ReplayKind::Shared {
        if let Some(tier) = &config.replay_durability_tier {
            if !tier.meets_strict_production_minimum() {
                violations.push(format!(
                    "--replay-durability-tier {} is weaker than the strict-production minimum; \
                     declare redis-wait-quorum:<quorum>:<timeout_ms> or a linearizable tier",
                    tier.wire_name()
                ));
            }
        }
    }
    // #4082 (M09): a DELIBERATE `--inner-sandbox off` asks for zero inner
    // containment against a potentially hostile inner server. Only the EXPLICIT
    // form is rejected — the (identical-valued) default is left a warning because
    // no kernel sandbox backend ships in this build, so a blanket `enforce`
    // requirement would fail closed on every platform (see
    // `sandbox_enforce_fails_closed_on_this_platform`). `network == Allow` and
    // `authz == Off` remain warnings for the same reason they always have:
    // network policy is honored only under an enforcing backend, and authz-off is
    // the established default mode, not an unsafe downgrade of an enforced one.
    if config.sandbox_explicitly_off {
        violations.push(
            "--inner-sandbox off explicitly disables inner-server containment (the inner \
             server can reach any file/socket its OS credentials permit); production must \
             request containment (--inner-sandbox enforce)"
                .to_string(),
        );
    }
    // #4082 (M10/M22): reverse-proxy identity-header ingress takes the verified
    // identity from a forwarded header and trusts, on the operator's word alone,
    // that the socket is reachable ONLY by the upstream — a process that can
    // reach the socket can SPOOF any identity. Strict refuses to enable this
    // documented spoofable posture silently.
    if config.reverse_proxy_identity_header.is_some() {
        violations.push(
            "--reverse-proxy-identity-header trusts a forwarded identity header that any peer \
             able to reach the socket can spoof; production must terminate mTLS locally (omit \
             --reverse-proxy-identity-header)"
                .to_string(),
        );
    }
    // #4082 (M11): `--transport-binding none` ignores the mTLS channel identity,
    // so a request signed by identity A can be presented over a channel
    // authenticated as identity B. The channel-to-signer binding must be enforced
    // in production.
    if config.binding == BindingKind::None {
        violations.push(
            "--transport-binding none ignores the mTLS channel identity, decoupling the \
             verified request signer from the authenticated channel; production must bind \
             them (--transport-binding exact)"
                .to_string(),
        );
    }
    // #4082 (M12): both revocation relaxations convert a fail-closed posture into
    // fail-open, exactly the inconsistency the symmetric best-effort-rlimit arm
    // above already rejects. The CRL relaxation is only flagged when CRLs are
    // actually configured (it has no effect otherwise — mirroring its parse-time
    // semantics), so a strict run without CRLs is not spuriously rejected.
    if config.crl_allow_unknown_status && !config.client_crl_paths.is_empty() {
        violations.push(
            "--crl-allow-unknown-status admits a client cert whose revocation status cannot be \
             determined from the configured CRLs (fail-open); production must fail closed \
             (omit --crl-allow-unknown-status)"
                .to_string(),
        );
    }
    if config.ocsp_soft_fail {
        violations.push(
            "--ocsp-soft-fail admits a connection on an indeterminate online-OCSP result \
             (Unknown/unreachable/timeout/parse error — fail-open); production must fail \
             closed (omit --ocsp-soft-fail)"
                .to_string(),
        );
    }
    violations
}

/// Whether a Unix file mode is group- or world-accessible (MCPS-3842). Pure
/// predicate factored out of `main.rs`'s key-file-permission check so the
/// warn-vs-reject decision is black-box testable without touching the filesystem.
/// A sensitive key file must be restricted to the owner (mode `0600`); any
/// group/world permission bit set is an insecure posture.
pub fn key_file_mode_is_insecure(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Parse an `--inner-env` value of the form `KEY=VALUE`. The key must be
/// non-empty and contain no `=`; the value (which may itself contain `=`) is
/// everything after the first `=`. An empty value is allowed (`KEY=`).
fn parse_env_pair(value: &str) -> Result<(String, String), String> {
    match value.split_once('=') {
        Some((key, _)) if key.is_empty() => {
            Err(format!("invalid --inner-env '{value}' (empty key; expected KEY=VALUE)"))
        }
        Some((key, val)) => Ok((key.to_string(), val.to_string())),
        None => Err(format!("invalid --inner-env '{value}' (expected KEY=VALUE)")),
    }
}

/// Parse an `--inner-rlimit-*` value into the resource ceiling to set. A bare
/// non-negative integer is the ceiling (`0` is a valid, very tight ceiling — it
/// is NOT "no limit"); the literal `none` clears the ceiling so that resource is
/// left at the OS default (used e.g. to RE-ENABLE core dumps that default off).
fn parse_rlimit_value(flag: &str, value: &str) -> Result<Option<u64>, String> {
    if value == "none" {
        return Ok(None);
    }
    let n: u64 = value
        .parse()
        .map_err(|_| format!("invalid {flag} '{value}' (expected a non-negative integer or 'none')"))?;
    Ok(Some(n))
}

/// Parse a timeout in whole seconds; `0` disables the timeout (`None`).
fn parse_timeout(value: &str, flag: &str) -> Result<Option<Duration>, String> {
    let secs: u64 = value.parse().map_err(|_| format!("invalid {flag}"))?;
    Ok(if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    })
}

/// The maximum accepted `--inner-read-timeout-secs` (MCPS-074): 1 day. Generous
/// for any legitimate inner yet far below the range that would overflow
/// `Instant::now() + timeout` in the deadline reader, making that overflow
/// practically unreachable (the `checked_add` there is defense-in-depth).
const MAX_INNER_READ_TIMEOUT_SECS: u64 = 86_400;

/// Parse a POSITIVE timeout in whole seconds, rejecting `0` (MCPS-074). The
/// persistent-inner read timeout is ALWAYS bounded — there is no "disable", so
/// unlike [`parse_timeout`] this never maps `0` to a disabled timeout. `0` (or a
/// non-integer) is a clear error rather than a silent never-hang regression. The
/// value is also CAPPED at [`MAX_INNER_READ_TIMEOUT_SECS`] so an absurdly large
/// timeout cannot overflow the `Instant` deadline in the fail-closed read path.
fn parse_positive_timeout(value: &str, flag: &str) -> Result<Duration, String> {
    let secs: u64 = value
        .parse()
        .map_err(|_| format!("invalid {flag} '{value}' (expected a positive integer of seconds)"))?;
    if secs == 0 {
        return Err(format!(
            "{flag} must be > 0 (the inner read timeout is always bounded; there is no disable)"
        ));
    }
    if secs > MAX_INNER_READ_TIMEOUT_SECS {
        return Err(format!(
            "{flag} must be <= {MAX_INNER_READ_TIMEOUT_SECS} seconds (1 day); got {secs}"
        ));
    }
    Ok(Duration::from_secs(secs))
}

/// Parse a client-cert lifetime: a number with an optional `h`/`m`/`s` suffix
/// (bare = seconds), or `none`/`0` to disable enforcement. E.g. `1h`, `30m`,
/// `3600`, `none`.
fn parse_cert_lifetime(value: &str) -> Result<Option<Duration>, String> {
    if value == "none" {
        return Ok(None);
    }
    let (digits, multiplier) = match value.strip_suffix('h') {
        Some(d) => (d, 3600),
        None => match value.strip_suffix('m') {
            Some(d) => (d, 60),
            None => (value.strip_suffix('s').unwrap_or(value), 1),
        },
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid --max-client-cert-lifetime '{value}' (e.g. 1h, 30m, 3600, none)"))?;
    Ok(if n == 0 {
        None
    } else {
        Some(Duration::from_secs(n * multiplier))
    })
}

/// Build the configured [`KeySource`].
///
/// MCPS-076 (audit gap G-3): [`KeySourceKind::Env`] is honored ONLY in a build with
/// the non-default `dev_env_key_source` feature. A default (production) build does
/// not compile [`EnvKeySource`] at all and FAILS CLOSED here with a clear error —
/// `--key-source env` still parses (so the message is precise), but no env-backed
/// key can be constructed.
pub fn build_key_source(config: &Config) -> Result<Box<dyn KeySource>, KeyError> {
    match config.key_source {
        KeySourceKind::File => Ok(Box::new(FileKeySource {
            signing_key_seed_path: config.signing_key_seed.clone(),
            tls_cert_path: config.tls_cert.clone(),
            tls_key_path: config.tls_key.clone(),
            client_ca_path: config.client_ca.clone(),
        })),
        #[cfg(feature = "dev_env_key_source")]
        KeySourceKind::Env => Ok(Box::new(EnvKeySource {
            signing_key_seed_var: config.signing_key_seed.clone(),
            tls_cert_var: config.tls_cert.clone(),
            tls_key_var: config.tls_key.clone(),
            client_ca_var: config.client_ca.clone(),
        })),
        #[cfg(not(feature = "dev_env_key_source"))]
        KeySourceKind::Env => Err(KeyError::NotFound(
            "env key source is development-only; rebuild with \
             --features dev_env_key_source (production must use --key-source file)"
                .to_string(),
        )),
        // #4034 PKCS#11 token-backed source. `parse_args` already guaranteed the
        // four pkcs11 flags are present when this kind is selected, so unwrapping
        // them here cannot be reached with a `None`; surface a clear error rather
        // than panicking if that invariant is ever violated.
        #[cfg(feature = "pkcs11_keysource")]
        KeySourceKind::Pkcs11 => {
            let require = |opt: &Option<String>, flag: &str| -> Result<String, KeyError> {
                opt.clone()
                    .ok_or_else(|| KeyError::NotFound(format!("--key-source pkcs11 requires {flag}")))
            };
            let module = require(&config.pkcs11_module, "--pkcs11-module")?;
            let pin = require(&config.pkcs11_pin, "--pkcs11-pin")?;
            let token_label = require(&config.pkcs11_token_label, "--pkcs11-token-label")?;
            let key_label = require(&config.pkcs11_key_label, "--pkcs11-key-label")?;
            Ok(Box::new(crate::pkcs11_keysource::Pkcs11KeySource::open(
                &module,
                &pin,
                &token_label,
                &key_label,
                &config.tls_cert,
                &config.tls_key,
                &config.client_ca,
            )?))
        }
        // Default build: the PKCS#11 backend is not compiled, so `--key-source
        // pkcs11` FAILS CLOSED here (mirrors the env-keysource gate). The flag
        // still PARSES so the message is precise; no token-backed key is built.
        #[cfg(not(feature = "pkcs11_keysource"))]
        KeySourceKind::Pkcs11 => Err(KeyError::NotFound(
            "pkcs11 key source requires the pkcs11_keysource feature (build with \
             --features pkcs11_keysource); not available in this build"
                .to_string(),
        )),
    }
}

/// Build the SHARED replay cache selected by `--replay-cache shared` (issue
/// #3837), backed by Redis under the `redis_replay` feature (issue #4028).
///
/// Under `--features redis_replay` this connects to `replay_redis_url` and wires
/// a [`SharedReplayCache`](crate::shared_replay::SharedReplayCache) over a
/// [`RedisAtomicReplayStore`](crate::redis_store::RedisAtomicReplayStore), giving
/// real horizontally-scaled replay safety (a nonce accepted on one node is
/// rejected as a replay on every node sharing that Redis). A connect failure
/// fails closed with a clear error rather than degrading to a non-shared cache.
///
/// In a DEFAULT build the Redis backend is not compiled, so this mirrors
/// [`build_key_source`]'s dev-only gate: `--replay-cache shared` always PARSES
/// (so the message is precise), but it FAILS CLOSED here — there is no shared
/// backend to construct.
///
/// `replay_redis_url` is the connection URL (already required by `parse_args`).
/// `read_timeout` / `write_timeout` are the server's configured socket timeouts
/// (`--read-timeout-secs` / `--write-timeout-secs`); they BOUND the Redis connect
/// and each blocking replay op so a stalled backend fails closed (Unavailable)
/// within a finite window instead of wedging the single-threaded serve loop
/// (MCPS-090 / H-10). The connect timeout is derived from the read timeout (a
/// stalled connect and a stalled read are the same hazard), falling back to a
/// bounded default when the read timeout is disabled (`0`).
#[cfg(feature = "redis_replay")]
pub fn build_shared_replay_cache(
    replay_redis_url: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tier: &crate::replay_tier::ReplayDurabilityTier,
) -> Result<Box<dyn mcps_core::ReplayCache>, String> {
    use crate::replay_tier::ReplayDurabilityTier;
    // A disabled socket timeout would re-introduce the hang, so the connect
    // timeout is always bounded: prefer the configured read timeout, else a
    // bounded default.
    let connect_timeout = read_timeout.unwrap_or(Duration::from_secs(30));
    let store = crate::redis_store::RedisAtomicReplayStore::connect_with(
        replay_redis_url,
        connect_timeout,
        read_timeout,
        write_timeout,
        crate::redis_store::system_clock(),
    )
    .map_err(|e| format!("shared replay cache: {e}"))?;
    // Apply the declared durability tier (ADR-MCPS-020). REDIS_WAIT_QUORUM adds
    // the per-insert WAIT; REDIS_ASYNC / SINGLE_STORE_FAIL_CLOSED are the plain
    // SET NX PX path (the tier is the operator's topology assertion). LINEARIZABLE
    // cannot be backed by Redis — it requires the CP/etcd backend — so it fails
    // closed here rather than silently over-claiming.
    let store = match tier {
        ReplayDurabilityTier::RedisWaitQuorum { quorum, timeout_ms } => {
            store.with_wait_quorum(*quorum, *timeout_ms)
        }
        ReplayDurabilityTier::RedisAsyncBounded
        | ReplayDurabilityTier::SingleStoreFailClosed => store,
        ReplayDurabilityTier::Linearizable => {
            return Err("LINEARIZABLE durability tier requires a CP/linearizable store \
                        (the etcd backend); the Redis backend cannot provide a \
                        linearizable guarantee. Use redis-async, \
                        redis-wait-quorum:<quorum>:<timeout_ms>, or \
                        single-store-fail-closed."
                .to_string());
        }
    };
    Ok(Box::new(crate::shared_replay::SharedReplayCache::new(
        Box::new(store),
        max_clock_skew,
    )))
}

/// Default-build fail-closed stub: no shared backend is compiled without the
/// `redis_replay` feature, so `--replay-cache shared` fails closed here. See the
/// feature-enabled variant above for the real Redis wiring.
#[cfg(not(feature = "redis_replay"))]
pub fn build_shared_replay_cache(
    replay_redis_url: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tier: &crate::replay_tier::ReplayDurabilityTier,
) -> Result<Box<dyn mcps_core::ReplayCache>, String> {
    let _ = (replay_redis_url, max_clock_skew, read_timeout, write_timeout, tier);
    Err("shared replay cache backend is not yet available in this build (the Redis \
         adapter is behind the non-default redis_replay feature; the etcd \
         LINEARIZABLE backend is tracked separately); use --replay-cache file for \
         single-node durability"
        .to_string())
}

/// Load a JSON trust file into an [`InMemoryTrustResolver`]. The file is an array
/// of `{ "signer", "key_id", "public_key" }` (the public key Base64URL-no-pad);
/// it carries both request-signer keys and authorization-issuer keys.
pub fn load_trust(bytes: &[u8]) -> Result<InMemoryTrustResolver, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut resolver = InMemoryTrustResolver::new();
    for entry in array {
        let signer = entry["signer"].as_str().ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"].as_str().ok_or("trust entry missing key_id")?;
        let pk = entry["public_key"]
            .as_str()
            .ok_or("trust entry missing public_key")?;
        let key = VerificationKey::from_b64url(pk)
            .map_err(|_| format!("trust entry {signer}#{key_id}: invalid public_key"))?;
        resolver.insert(signer, key_id, key);
    }
    Ok(resolver)
}

/// Load the configured offline client-certificate revocation lists (#3839) into
/// the DER form rustls' `WebPkiClientVerifier` consumes. Each path may hold one or
/// more CRLs in PEM (`-----BEGIN X509 CRL-----`) or a single raw DER CRL. Fails
/// closed: a missing or malformed CRL file is a hard startup error (`Err`) rather
/// than a silently-skipped revocation check. An empty `paths` yields an empty vec
/// (revocation checking disabled — the pre-#3839 behavior).
///
/// OFFLINE only: these bytes are read once at startup and never refreshed over the
/// network. Online OCSP / CRL-distribution-point fetching is deliberately NOT done
/// here and is deferred to a follow-up (it needs an HTTP client + a live
/// responder, which would expand the firewalled supply chain).
pub fn load_client_crls(
    paths: &[String],
) -> Result<Vec<rustls_pki_types::CertificateRevocationListDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateRevocationListDer;

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("client CRL {path}: {e}"))?;
        // Try PEM first (one file may carry several `X509 CRL` blocks). If the file
        // contains no PEM CRL block, treat the whole file as a single DER CRL.
        let pem: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client CRL {path}: malformed PEM: {e}"))?;
        if pem.is_empty() {
            // No PEM CRL block found → interpret the bytes as one DER CRL. Empty
            // input cannot be a valid DER CRL, so reject it (fail closed) rather
            // than load a no-op file.
            if bytes.is_empty() {
                return Err(format!("client CRL {path}: file is empty"));
            }
            crls.push(CertificateRevocationListDer::from(bytes));
        } else {
            crls.extend(pem);
        }
    }
    Ok(crls)
}

/// Build the ONLINE OCSP checker selected by `--client-ocsp require` (#4030),
/// or `None` when `--client-ocsp off` (the default). Compiled ONLY under the
/// `online_ocsp` feature; `parse_args` already fails closed for `require` in a
/// build without the feature, so this is only reached with the backend present.
///
/// The checker uses `ocsp_responder_url` as the AIA override (else the leaf's
/// AIA OCSP URL) and `ocsp_soft_fail` as the fail-open posture (default
/// hard-fail). Its HTTP fetch carries a mandatory timeout (fail closed on
/// timeout) so it can never wedge the blocking serve loop.
#[cfg(feature = "online_ocsp")]
pub fn build_ocsp_checker(config: &Config) -> Option<crate::ocsp::OcspChecker> {
    match config.client_ocsp {
        OcspKind::Off => None,
        OcspKind::Require => Some(crate::ocsp::OcspChecker::new(
            config.ocsp_responder_url.clone(),
            config.ocsp_soft_fail,
        )),
    }
}

/// An inner MCP server backed by a subprocess: each request spawns the command,
/// writes the request bytes to its stdin, and reads its **stdout** as the
/// response (the MCP protocol stream). Per-request spawn keeps it trivially
/// correct under the (single-threaded) serve loop; a failure yields a JSON-RPC
/// internal error rather than reaching for a fallback.
///
/// MCPS-036 inner-server hygiene:
///   * the inner server is launched in a CONTROLLED working directory (never
///     silently the proxy's cwd) — see [`InnerLaunchConfig::apply_working_dir`];
///   * its **stdout is reserved for the protocol stream** and read as the
///     response bytes;
///   * its **stderr is captured separately** into a BOUNDED structured log
///     ([`BoundedStderr`]) and NEVER forwarded as MCP content;
///   * lifecycle events (`inner_spawned`, `inner_exited`, `inner_killed`,
///     `inner_stderr_truncated`, `inner_protocol_error`, `inner_spawn_failed`)
///     are emitted to the proxy's own [`InnerLogSink`].
pub struct SubprocessInner {
    command: String,
    args: Vec<String>,
    launch: InnerLaunchConfig,
    /// A stable identity for this inner server, tagged onto every lifecycle
    /// event so emissions stay attributable.
    inner_identity: String,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
}

impl SubprocessInner {
    /// Build from an `[cmd, arg, ...]` vector (non-empty), with the inner-launch
    /// policy validated against the proxy's OWN environment and working dir.
    ///
    /// This validation is where a configured-but-unappliable policy fails LOUDLY
    /// rather than at spawn time — e.g. an `--inner-env-allow KEY` naming a
    /// variable absent from the proxy's environment, or an `--inner-working-dir`
    /// that is not an existing directory, is rejected here, at startup, so the
    /// proxy never serves with a silently-dropped behavior.
    pub fn new(inner_command: &[String], launch: InnerLaunchConfig) -> Result<Self, String> {
        SubprocessInner::with_log_sink(inner_command, launch, Arc::new(StderrLogSink))
    }

    /// As [`SubprocessInner::new`], with an injected lifecycle-event sink (used by
    /// tests to capture emissions deterministically).
    pub fn with_log_sink(
        inner_command: &[String],
        launch: InnerLaunchConfig,
        log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    ) -> Result<Self, String> {
        // Validate the env + working-dir policy up front against the real process
        // environment; a failure aborts startup (the same fail-closed posture as
        // key loading). Both must be appliable before we agree to serve.
        let mut probe = Command::new(&inner_command[0]);
        launch.apply_env(&mut probe, |name| std::env::var(name).ok())?;
        launch.apply_working_dir(&mut probe)?;
        // Resource-hardening ceilings (MCPS-037): startup platform validation
        // (non-Unix + required = fail closed) plus the pre_exec setrlimit hook.
        launch.apply_rlimits(&mut probe)?;
        // OS sandbox profile (#3865): the fail-closed platform/capability gate is
        // checked HERE, at startup, before any inner server is spawned. Under
        // `--inner-sandbox enforce` this refuses to start unless a kernel backend
        // can actually enforce containment (none ships yet); `off` (default) is
        // inert and passes through.
        launch.apply_sandbox(&mut probe)?;
        Ok(SubprocessInner {
            command: inner_command[0].clone(),
            args: inner_command[1..].to_vec(),
            launch,
            inner_identity: inner_command[0].clone(),
            log_sink,
        })
    }

    fn emit(&self, event: InnerLogEvent) {
        self.log_sink.log(&self.inner_identity, &event);
    }

    fn run(&self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr is PIPED (not null) so it is captured separately into the
            // bounded log; it is never merged into stdout (the protocol stream).
            .stderr(Stdio::piped());
        // Apply the (already validated) env + working-dir policy. Resolution
        // against the proxy env/fs is stable for the process lifetime, so a
        // repeat failure here is not expected; surface it as an IO error rather
        // than silently spawning with an unintended launch context.
        self.launch
            .apply_env(&mut command, |name| std::env::var(name).ok())
            .map_err(std::io::Error::other)?;
        self.launch
            .apply_working_dir(&mut command)
            .map_err(std::io::Error::other)?;
        // Install the Unix setrlimit ceilings (MCPS-037) as a pre_exec hook. A
        // required limit the kernel refuses fails the spawn below (fail closed),
        // never a silently-unbounded inner server.
        self.launch
            .apply_rlimits(&mut command)
            .map_err(std::io::Error::other)?;
        // OS sandbox profile (#3865). Already gated at startup; re-applied here so
        // the (future) kernel enforcement is installed on the actual spawn
        // command, and so a still-ungated `enforce` can never spawn unsandboxed.
        self.launch
            .apply_sandbox(&mut command)
            .map_err(std::io::Error::other)?;
        // M15 (audit 0.2, #4080): close every inherited fd above stdio in the child
        // before exec (registered last), so the inner never inherits the proxy's
        // own open sockets — a leak a seccomp egress filter cannot revoke.
        self.launch
            .apply_close_extra_fds(&mut command)
            .map_err(std::io::Error::other)?;

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.emit(InnerLogEvent::SpawnFailed { reason: e.to_string() });
                return Err(e);
            }
        };
        let pid = child.id();
        self.emit(InnerLogEvent::Spawned { pid });

        // Bound the one-shot interaction so a wedged inner cannot hang the
        // single-threaded serve loop (MCPS-084 / audit M-7). A watchdog thread
        // waits for completion OR the inner-read deadline; on timeout the inner
        // is not draining stdin or not closing stdout, so SIGKILL it to unblock
        // the write_all + wait_with_output below. `recv_timeout` means the kill
        // fires ONLY on a real timeout, and the child is not reaped until
        // wait_with_output() — so `pid` is unambiguously this child (no reuse
        // race) at the moment we signal.
        let timeout = self.launch.inner_read_timeout;
        let timed_out = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let wd_flag = Arc::clone(&timed_out);
        let watchdog = std::thread::spawn(move || {
            if done_rx.recv_timeout(timeout).is_err() {
                wd_flag.store(true, Ordering::SeqCst);
                // SAFETY: kill(2) on a child pid we own and have not yet reaped.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        });

        // Drain stderr on a dedicated thread into the BOUNDED capture so a noisy
        // or hostile inner server can neither deadlock the pipe nor exhaust proxy
        // memory. The capture is moved back when the thread joins.
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("no child stderr"))?;
        let mut capture = self.launch.new_stderr_capture();
        let stderr_thread = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match stderr_pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => capture.push(&chunk[..n]),
                    Err(_) => break,
                }
            }
            capture
        });

        // Capture (do NOT early-return on) a stdin write error: a wedged inner
        // that the watchdog kills makes write_all fail with a broken pipe, and we
        // must still reap the child and join the watchdog before surfacing it.
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no child stdin"))
            .and_then(|mut stdin| stdin.write_all(request));

        let output = child.wait_with_output()?;
        // Reaped: tell the watchdog to stand down (it never kills a reaped pid).
        let _ = done_tx.send(());
        let _ = watchdog.join();
        let capture: BoundedStderr = stderr_thread
            .join()
            .unwrap_or_else(|_| self.launch.new_stderr_capture());

        self.emit(InnerLogEvent::Exited {
            code: output.status.code(),
        });
        if capture.truncated() {
            self.emit(InnerLogEvent::StderrTruncated {
                captured_bytes: capture.bytes().len(),
                cap_bytes: capture.cap_bytes(),
            });
        }
        if !capture.bytes().is_empty() {
            // The captured stderr goes ONLY to the proxy's structured log (via the
            // dedicated stderr channel), never onto stdout (the protocol stream)
            // and never into MCP content.
            self.log_sink.log_stderr(&self.inner_identity, capture.bytes());
        }
        // The inner exceeded its read deadline and was terminated: fail closed
        // with a timeout rather than treating the (partial / empty) stdout as a
        // response. This is the one-shot analogue of the persistent path's
        // per-read deadline (MCPS-074); together they honour the never-hang
        // posture for BOTH inner modes.
        if timed_out.load(Ordering::SeqCst) {
            self.emit(InnerLogEvent::ProtocolError {
                detail: format!("inner exceeded inner_read_timeout ({timeout:?}); terminated"),
            });
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("inner exceeded inner_read_timeout ({timeout:?}) and was terminated"),
            ));
        }
        // Surface a genuine (non-timeout) stdin write failure now that the child
        // is reaped and the watchdog has stood down.
        write_result?;

        // The inner server's stdout is the MCP protocol stream: if it is not a
        // JSON object the proxy can frame, flag a protocol error (the dirty bytes
        // are still returned for the proxy's normal error handling, but the
        // observability event makes the dirty-stream case attributable).
        if serde_json::from_slice::<Value>(&output.stdout).is_err() {
            self.emit(InnerLogEvent::ProtocolError {
                detail: "inner stdout is not a JSON-RPC frame".to_string(),
            });
        }
        Ok(output.stdout)
    }
}

impl InnerServer for SubprocessInner {
    fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        match self.run(request) {
            Ok(response) => response,
            Err(e) => serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": { "code": -32603, "message": "inner server unavailable", "data": e.to_string() }
            }))
            .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::load_trust;
    use super::parse_args;
    use super::strict_violations;
    use super::AuthzKind;
    use super::BindingKind;
    use super::IdentityPolicy;
    use super::ReverseProxyHeaderFormat;
    use super::InnerLaunchConfig;
    use super::InnerModeKind;
    use super::InnerServer;
    use super::KeySourceKind;
    use super::OcspKind;
    use super::ReplayKind;
    use crate::rlimits::RLimits;
    use super::InnerLogEvent;
    use super::InnerLogSink;
    use super::SubprocessInner;
    use crate::sandbox::NetworkPolicy;
    use crate::sandbox::SandboxMode;
    use crate::sandbox::SandboxProfile;
    use mcps_core::SigningKey;
    use mcps_core::TrustResolver;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Build a `/bin/sh -c` inner whose script first DRAINS the dispatched request
    /// from stdin (`cat >/dev/null`), then runs `script`. This mirrors a real inner
    /// MCP server, which reads its request before responding. Without the drain a
    /// `printf`-only fixture exits immediately, closing its stdin read-end; the
    /// proxy's `write_all(request)` then races that close and, on Linux,
    /// deterministically loses — surfacing as a broken-pipe write error instead of
    /// the fixture's intended output. (The race is benign on macOS, which is why it
    /// hid until the Linux CI gate ran these to completion.) Every shell fixture
    /// that the proxy dispatches a request to goes through this helper so the whole
    /// class is fixed at the source rather than per-test.
    fn sh_inner(script: &str) -> Vec<String> {
        args(&["/bin/sh", "-c", &format!("cat >/dev/null; {script}")])
    }

    /// MCPS-084 / audit M-7: a one-shot inner that never drains stdin and never
    /// exits must NOT hang the single-threaded serve loop — the per-read deadline
    /// terminates it and the call fails closed within the budget. Load-bearing:
    /// without the watchdog, `wait_with_output` would block forever and this test
    /// would hang (time out) instead of returning an error response.
    #[test]
    fn oneshot_inner_that_never_exits_is_bounded_by_timeout() {
        let launch = InnerLaunchConfig {
            inner_read_timeout: std::time::Duration::from_millis(300),
            ..InnerLaunchConfig::new()
        };
        // `sleep` ignores stdin and never writes stdout nor exits.
        let inner = SubprocessInner::new(&args(&["sleep", "3600"]), launch).expect("construct");
        let start = std::time::Instant::now();
        let response = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":1}");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "a wedged one-shot inner must be bounded by inner_read_timeout, not hang (took {elapsed:?})"
        );
        let value: Value = serde_json::from_slice(&response).expect("error response is JSON");
        assert_eq!(
            value["error"]["message"].as_str(),
            Some("inner server unavailable"),
            "a timed-out inner must surface as unavailable, got {value}"
        );
    }

    // --- MCPS-036 lifecycle / stderr capture proofs ---------------------------

    /// A capturing log sink: records every lifecycle event and every captured
    /// stderr chunk so tests can assert what the proxy emitted (deterministic,
    /// no scraping of the real proxy stderr).
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(String, InnerLogEvent)>>,
        stderr: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl InnerLogSink for RecordingSink {
        fn log(&self, inner_identity: &str, event: &InnerLogEvent) {
            self.events
                .lock()
                .expect("lock")
                .push((inner_identity.to_string(), event.clone()));
        }
        fn log_stderr(&self, inner_identity: &str, captured: &[u8]) {
            self.stderr
                .lock()
                .expect("lock")
                .push((inner_identity.to_string(), captured.to_vec()));
        }
    }

    impl RecordingSink {
        fn tags(&self) -> Vec<String> {
            self.events
                .lock()
                .expect("lock")
                .iter()
                .map(|(_, e)| e.tag().to_string())
                .collect()
        }
        fn captured_stderr(&self) -> Vec<u8> {
            self.stderr
                .lock()
                .expect("lock")
                .iter()
                .flat_map(|(_, bytes)| bytes.clone())
                .collect()
        }
    }

    #[test]
    fn inner_launches_in_explicit_working_dir_not_proxy_cwd() {
        // The fixture prints its OWN cwd to stdout (after draining the request).
        // With an explicit --inner-working-dir, the child must run there, NOT in
        // the proxy's cwd.
        let tmp = std::env::temp_dir();
        let dir = tmp.join(format!("mcps036_wd_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // macOS resolves /var -> /private/var; canonicalize both sides.
        let canonical = std::fs::canonicalize(&dir).expect("canonicalize");
        let launch = InnerLaunchConfig {
            working_dir: Some(dir.to_string_lossy().into_owned()),
            ..InnerLaunchConfig::new()
        };
        let cmd = sh_inner("pwd -P");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let seen = String::from_utf8(inner.dispatch(b"{}")).expect("utf8");
        let proxy_cwd = std::env::current_dir().expect("cwd");
        assert_ne!(
            seen.trim(),
            proxy_cwd.to_string_lossy(),
            "inner ran in the proxy's cwd instead of the explicit working dir"
        );
        assert_eq!(seen.trim(), canonical.to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_explicit_working_dir_fails_construction() {
        let launch = InnerLaunchConfig {
            working_dir: Some("/no/such/dir/MCPS036_MISSING".to_string()),
            ..InnerLaunchConfig::new()
        };
        match SubprocessInner::new(&args(&["/bin/true"]), launch) {
            Ok(_) => panic!("a working dir that cannot be honored must fail closed"),
            Err(err) => assert!(err.contains("MCPS036_MISSING"), "got: {err}"),
        }
    }

    // --- MCPS-037 setrlimit resource-hardening proofs ------------------------

    #[cfg(unix)]
    #[test]
    fn rlimit_nofile_actually_constrains_the_child() {
        // EFFECT test: with RLIMIT_NOFILE applied, the child's OWN view of its
        // soft fd limit (`ulimit -n`, which reads RLIMIT_NOFILE) must equal what
        // we set — proving the pre_exec setrlimit took effect on the child, not
        // just the parent's Command config.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                nofile: Some(48),
                core_bytes: None,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        // The inner prints its soft fd limit; `sh_inner` drains the request stdin
        // first so it behaves like a real one-shot inner and the EFFECT assertion
        // is deterministic on every platform (see `sh_inner` for the race).
        let cmd = sh_inner("ulimit -n");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let seen = String::from_utf8(inner.dispatch(b"{}")).expect("utf8");
        assert_eq!(
            seen.trim(),
            "48",
            "RLIMIT_NOFILE was not applied to the child (saw ulimit -n = {seen:?})"
        );
    }

    #[cfg(unix)]
    #[test]
    fn required_unappliable_rlimit_fails_the_spawn_not_silently() {
        // FAIL-CLOSED test: ask for an RLIMIT_NOFILE ceiling far above the
        // current HARD limit. As a non-root process the kernel REFUSES to raise
        // the hard limit (EPERM/EINVAL), so the pre_exec setrlimit returns an
        // error, which (strict mode) aborts the spawn. The dispatch must surface
        // an inner-server error — NEVER a silently-unbounded successful run.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                // 2^60 fds is unattainable; raising the hard limit there fails.
                nofile: Some(1u64 << 63),
                core_bytes: None,
                best_effort: false,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        // The child WOULD print a clean frame if it ever ran; it must not.
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct (validation is unix-ok)");
        let out = inner.dispatch(b"{}");
        let parsed: Value = serde_json::from_slice(&out).expect("dispatch returns a JSON frame");
        assert!(
            parsed.get("error").is_some(),
            "a required-but-unappliable rlimit must fail the spawn closed, not run unbounded: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], -32603);
    }

    #[cfg(unix)]
    #[test]
    fn best_effort_unappliable_rlimit_does_not_block_the_spawn() {
        // In explicit best-effort mode the SAME unattainable ceiling is
        // downgraded: the setrlimit failure is ignored in the child and the
        // inner server still runs (the relaxation is opt-in + warned, never the
        // default). Contrast with the strict test above.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                nofile: Some(1u64 << 63),
                core_bytes: None,
                best_effort: true,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let out = inner.dispatch(b"{}");
        let parsed: Value = serde_json::from_slice(&out).expect("JSON frame");
        assert_eq!(
            parsed["jsonrpc"], "2.0",
            "best-effort mode must let the inner server run despite an unappliable limit: {parsed}"
        );
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn inner_stderr_is_captured_separately_and_stdout_stays_protocol_only() {
        // The fixture writes a JSON-RPC frame to STDOUT and noise to STDERR.
        // stdout (the protocol stream) must contain ONLY the JSON frame; the
        // stderr noise must land in the bounded capture, never on stdout.
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner(
            "printf 'STDERR-NOISE-LEAK' 1>&2; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'",
        );
        let inner =
            SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
                .expect("construct");
        let stdout = inner.dispatch(b"{}");
        let stdout_str = String::from_utf8(stdout).expect("utf8");
        assert!(
            !stdout_str.contains("STDERR-NOISE-LEAK"),
            "stderr leaked onto the stdout protocol stream: {stdout_str:?}"
        );
        let parsed: Value = serde_json::from_str(&stdout_str).expect("stdout is a clean JSON frame");
        assert_eq!(parsed["jsonrpc"], "2.0");
        let captured = String::from_utf8(sink.captured_stderr()).expect("utf8");
        assert!(
            captured.contains("STDERR-NOISE-LEAK"),
            "inner stderr was not captured into the bounded log: {captured:?}"
        );
    }

    #[test]
    fn oversized_inner_stderr_is_bounded_and_emits_truncation_event() {
        // The fixture floods stderr well past the byte cap. The capture must be
        // bounded to the cap and an `inner_stderr_truncated` event emitted.
        let sink = Arc::new(RecordingSink::default());
        let launch = InnerLaunchConfig {
            stderr_cap_bytes: 16,
            stderr_cap_lines: 1000,
            ..InnerLaunchConfig::new()
        };
        // 1000 'A' bytes to stderr; valid frame to stdout.
        let cmd = sh_inner(
            "for i in $(seq 1 1000); do printf 'A' 1>&2; done; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'",
        );
        let inner = SubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        let captured = sink.captured_stderr();
        assert!(captured.len() <= 16, "stderr capture exceeded the cap: {}", captured.len());
        assert!(
            sink.tags().iter().any(|t| t == "inner_stderr_truncated"),
            "expected inner_stderr_truncated; got: {:?}",
            sink.tags()
        );
    }

    #[test]
    fn lifecycle_events_spawn_and_exit_are_emitted() {
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        let tags = sink.tags();
        assert!(tags.iter().any(|t| t == "inner_spawned"), "got: {tags:?}");
        assert!(tags.iter().any(|t| t == "inner_exited"), "got: {tags:?}");
    }

    #[test]
    fn dirty_stdout_emits_protocol_error_event() {
        // The fixture writes non-JSON to stdout: the protocol stream is dirty.
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner("printf 'NOT JSON AT ALL'");
        let inner = SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        assert!(
            sink.tags().iter().any(|t| t == "inner_protocol_error"),
            "expected inner_protocol_error; got: {:?}",
            sink.tags()
        );
    }

    // --- MCPS-035 environment-minimization leak proofs ------------------------
    //
    // The inner command is a tiny shell that IGNORES stdin and prints the value
    // of a chosen variable to stdout. Driving it through the real
    // `SubprocessInner` proves what the spawned child actually receives.

    /// An inner command (`[cmd, arg...]`) that prints `${name}` (or empty if
    /// unset) to stdout. Uses `sh_inner` so it drains the request stdin first
    /// (portable on the unix CI hosts; see `sh_inner` for the EPIPE race).
    fn dump_var_command(name: &str) -> Vec<String> {
        sh_inner(&format!("printf '%s' \"${{{name}}}\""))
    }

    fn run_inner(inner: &SubprocessInner) -> String {
        String::from_utf8(inner.dispatch(b"{}")).expect("utf8 child stdout")
    }

    #[test]
    fn secret_in_proxy_env_is_not_visible_to_inner_by_default() {
        // A secret-looking var is present in THIS (the proxy's) process env, as
        // an env-backed KeySource would put it. With the secure default
        // (inherit_env = false, no allowlist) the inner server must NOT see it.
        let var = "MCPS035_SECRET_DEFAULT";
        std::env::set_var(var, "TOP-SECRET-KEY-MATERIAL");
        let inner = SubprocessInner::new(&dump_var_command(var), InnerLaunchConfig::new())
            .expect("construct");
        let seen = run_inner(&inner);
        assert_eq!(
            seen, "",
            "inner server leaked an env-loaded secret under default minimization; saw: {seen:?}"
        );
        std::env::remove_var(var);
    }

    #[test]
    fn explicit_inner_env_pair_is_visible_to_inner() {
        let launch = InnerLaunchConfig {
            explicit_env: vec![("MCPS035_EXPLICIT".to_string(), "hello".to_string())],
            ..InnerLaunchConfig::new()
        };
        let inner =
            SubprocessInner::new(&dump_var_command("MCPS035_EXPLICIT"), launch).expect("construct");
        assert_eq!(run_inner(&inner), "hello");
    }

    #[test]
    fn allowlisted_var_passes_through_but_others_do_not() {
        // Two vars in the proxy env; only one is allowlisted.
        let allowed = "MCPS035_ALLOWED";
        let blocked = "MCPS035_BLOCKED";
        std::env::set_var(allowed, "pass");
        std::env::set_var(blocked, "leak");
        let launch = InnerLaunchConfig {
            allow_env_names: vec![allowed.to_string()],
            ..InnerLaunchConfig::new()
        };
        let inner_allowed =
            SubprocessInner::new(&dump_var_command(allowed), launch.clone()).expect("construct");
        assert_eq!(run_inner(&inner_allowed), "pass");

        let inner_blocked =
            SubprocessInner::new(&dump_var_command(blocked), launch).expect("construct");
        assert_eq!(
            run_inner(&inner_blocked),
            "",
            "a non-allowlisted proxy var must not reach the inner server"
        );
        std::env::remove_var(allowed);
        std::env::remove_var(blocked);
    }

    #[test]
    fn inherit_env_true_exposes_the_proxy_env() {
        // The escape hatch: with inheritance ON, the proxy env IS visible. This
        // is the loudly-warned, opt-in behavior — the contrast that proves the
        // default actually clears the environment.
        let var = "MCPS035_INHERITED";
        std::env::set_var(var, "inherited-value");
        let launch = InnerLaunchConfig {
            inherit_env: true,
            ..InnerLaunchConfig::new()
        };
        let inner = SubprocessInner::new(&dump_var_command(var), launch).expect("construct");
        assert_eq!(run_inner(&inner), "inherited-value");
        std::env::remove_var(var);
    }

    // --- M15 (audit 0.2, #4080): inherited-fd leak across exec --------------------
    //
    // The inner must NOT inherit a non-stdio descriptor the proxy holds open. The
    // threat: an already-connected socket survives `exec`, so a seccomp egress
    // filter (which denies CREATING sockets) cannot revoke it. The proxy closes
    // every fd >= 3 in the child before exec (`apply_close_extra_fds`). This is a
    // black-box test of that hook over the REAL `SubprocessInner` launch pipeline:
    // it opens a pipe whose read end has O_CLOEXEC CLEARED (so std/Command would
    // otherwise leak it across exec), then spawns an inner that reports whether
    // that exact fd is open in the child. Without the close hook the fd LEAKS
    // (RED); with it, the fd is CLOSED in the child (GREEN). Cross-platform Unix:
    // it tests the fd-close itself, not any Linux-only sandbox.

    /// An inner command that prints `LEAKED` if `/dev/fd/<fd>` exists in the child
    /// (the descriptor was inherited across exec) or `CLOSED` otherwise. `/dev/fd`
    /// reflects the calling process's own descriptors on both Linux and macOS.
    /// Uses `sh_inner` so it drains the request stdin first (see that helper).
    fn probe_fd_command(fd: libc::c_int) -> Vec<String> {
        sh_inner(&format!(
            "if [ -e /dev/fd/{fd} ]; then printf LEAKED; else printf CLOSED; fi"
        ))
    }

    #[test]
    fn inner_does_not_inherit_a_non_cloexec_fd_across_exec() {
        // Create a pipe; the read end is the descriptor we will try to leak.
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` writes two fds into the provided length-2 array.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed: {}", std::io::Error::last_os_error());
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // Clear O_CLOEXEC on the read end so that, absent the proxy's close hook,
        // it WOULD survive exec into the child (this is the leak we are guarding).
        // SAFETY: F_GETFD/F_SETFD read/clear the close-on-exec flag on our own fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", std::io::Error::last_os_error());
        let set = unsafe { libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(set, 0, "F_SETFD clear CLOEXEC failed: {}", std::io::Error::last_os_error());
        // Confirm the flag is actually cleared — otherwise the test would pass
        // vacuously (std's own CLOEXEC, not our hook, would close it).
        let after = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        assert_eq!(after & libc::FD_CLOEXEC, 0, "CLOEXEC must be cleared for a meaningful test");

        let inner = SubprocessInner::new(&probe_fd_command(read_fd), InnerLaunchConfig::new())
            .expect("construct inner for fd-leak probe");
        let seen = run_inner(&inner);

        // SAFETY: closing our own pipe fds after the child has been spawned + run.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        assert_eq!(
            seen, "CLOSED",
            "a non-CLOEXEC fd ({read_fd}) the proxy held open LEAKED into the inner across exec \
             — the proxy must close every fd >= 3 before exec so an inherited (already-connected) \
             socket cannot survive a seccomp egress filter"
        );
    }

    #[test]
    fn close_extra_fds_hook_is_registered_on_the_launch_pipeline() {
        // A cross-platform unit check that the hook exists and is appliable on the
        // launch config used by every spawn (complements the exec-level probe).
        let mut command = std::process::Command::new("/bin/true");
        InnerLaunchConfig::new()
            .apply_close_extra_fds(&mut command)
            .expect("close-extra-fds hook must apply cleanly");
    }

    #[test]
    fn unsatisfiable_allowlist_fails_construction_loudly() {
        let launch = InnerLaunchConfig {
            allow_env_names: vec!["MCPS035_DEFINITELY_UNSET".to_string()],
            ..InnerLaunchConfig::new()
        };
        match SubprocessInner::new(&dump_var_command("x"), launch) {
            Ok(_) => panic!("a configured pass-through that cannot be satisfied must fail"),
            Err(err) => assert!(err.contains("MCPS035_DEFINITELY_UNSET"), "got: {err}"),
        }
    }

    fn minimal() -> Vec<String> {
        args(&[
            "--bind", "127.0.0.1:8443",
            "--audience", "did:example:server-1",
            "--server-signer", "did:example:server-1",
            "--server-key-id", "server-key-1",
            "--signing-key-seed", "/seed",
            "--tls-cert", "/cert",
            "--tls-key", "/key",
            "--client-ca", "/ca",
            "--trust", "/trust.json",
            "--inner-command", "my-server", "--flag",
        ])
    }

    #[test]
    fn parses_a_minimal_config_with_defaults() {
        let config = parse_args(&minimal()).expect("parse");
        assert_eq!(config.bind, "127.0.0.1:8443");
        assert_eq!(config.audience, "did:example:server-1");
        assert_eq!(config.max_clock_skew, 300);
        assert_eq!(config.key_source, KeySourceKind::File);
        assert_eq!(config.replay, ReplayKind::Memory);
        assert_eq!(config.binding, BindingKind::Exact);
        // Safe defaults: URI SAN identity, env keys refused, bounded resources.
        assert_eq!(config.identity_source, IdentityPolicy::UriSan);
        assert!(!config.allow_env_keysource);
        assert_eq!(config.authz, AuthzKind::Off);
        // The inner process model defaults to one-shot (existing behavior).
        assert_eq!(config.inner_mode, InnerModeKind::OneShot);
        assert_eq!(config.limits.max_header_bytes, 64 * 1024);
        assert_eq!(config.limits.max_body_bytes, 16 * 1024 * 1024);
        assert_eq!(config.limits.max_concurrent_connections, 256);
        assert!(config.limits.read_timeout.is_some());
        // v1 revocation posture: enforced 1-hour client-cert lifetime by default.
        assert_eq!(
            config.max_client_cert_lifetime,
            Some(std::time::Duration::from_secs(3600))
        );
        assert_eq!(config.inner_command, vec!["my-server", "--flag"]);
        // MCPS-035 secure defaults: no inheritance, empty allowlist.
        assert!(!config.inner_launch.inherit_env);
        assert!(config.inner_launch.explicit_env.is_empty());
        assert!(config.inner_launch.allow_env_names.is_empty());
    }

    #[test]
    fn parses_inner_env_minimization_flags() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--inherit-env", "false",
                "--inner-env", "MCP_MODE=prod",
                "--inner-env", "PATH=/usr/bin",
                "--inner-env-allow", "HOME",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert!(!config.inner_launch.inherit_env);
        assert_eq!(
            config.inner_launch.explicit_env,
            vec![
                ("MCP_MODE".to_string(), "prod".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ]
        );
        assert_eq!(config.inner_launch.allow_env_names, vec!["HOME".to_string()]);
    }

    #[test]
    fn parses_inner_working_dir_and_stderr_caps() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--inner-working-dir", "/srv/inner",
                "--inner-stderr-cap-bytes", "2048",
                "--inner-stderr-cap-lines", "32",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.inner_launch.working_dir, Some("/srv/inner".to_string()));
        assert_eq!(config.inner_launch.stderr_cap_bytes, 2048);
        assert_eq!(config.inner_launch.stderr_cap_lines, 32);
    }

    #[test]
    fn parses_inner_rlimit_flags() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--inner-rlimit-nofile", "256",
                "--inner-rlimit-cpu-seconds", "30",
                "--inner-rlimit-as-bytes", "1073741824",
                "--inner-rlimit-data-bytes", "536870912",
                "--inner-rlimit-core-bytes", "0",
                "--inner-rlimit-fsize-bytes", "1048576",
                "--inner-rlimit-best-effort", "true",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        let r = &config.inner_launch.rlimits;
        assert_eq!(r.nofile, Some(256));
        assert_eq!(r.cpu_seconds, Some(30));
        assert_eq!(r.address_space_bytes, Some(1_073_741_824));
        assert_eq!(r.data_bytes, Some(536_870_912));
        assert_eq!(r.core_bytes, Some(0));
        assert_eq!(r.fsize_bytes, Some(1_048_576));
        assert!(r.best_effort);
    }

    #[test]
    fn rlimit_defaults_disable_core_dumps_and_are_strict() {
        let config = parse_args(&minimal()).expect("parse");
        let r = &config.inner_launch.rlimits;
        assert_eq!(r.core_bytes, Some(0), "core dumps disabled by default");
        assert!(!r.best_effort, "default posture is strict/required");
        assert!(r.nofile.is_none());
    }

    #[test]
    fn rlimit_none_clears_the_ceiling() {
        // `none` re-enables the OS default (e.g. to allow core dumps).
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-rlimit-core-bytes", "none"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.inner_launch.rlimits.core_bytes, None);
    }

    #[test]
    fn rlimit_rejects_non_integer_value() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-rlimit-nofile", "lots"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-rlimit-nofile"), "got: {err}");
    }

    #[test]
    fn rlimit_best_effort_rejects_bad_value() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-rlimit-best-effort", "maybe"]));
        assert!(parse_args(&a).unwrap_err().contains("--inner-rlimit-best-effort"));
    }

    #[test]
    fn working_dir_defaults_to_controlled_not_proxy_cwd() {
        let config = parse_args(&minimal()).expect("parse");
        assert!(config.inner_launch.working_dir.is_none());
        let proxy_cwd = std::env::current_dir().expect("cwd").to_string_lossy().into_owned();
        assert_ne!(config.inner_launch.effective_working_dir(), proxy_cwd);
    }

    #[test]
    fn zero_stderr_cap_bytes_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-stderr-cap-bytes", "0"]));
        assert!(parse_args(&a).unwrap_err().contains("must be > 0"));
    }

    #[test]
    fn zero_stderr_cap_lines_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-stderr-cap-lines", "0"]));
        assert!(parse_args(&a).unwrap_err().contains("must be > 0"));
    }

    #[test]
    fn inherit_env_true_parses() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inherit-env", "true"]));
        assert!(parse_args(&a).expect("parse").inner_launch.inherit_env);
    }

    #[test]
    fn unknown_inherit_env_value_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inherit-env", "maybe"]));
        assert!(parse_args(&a).unwrap_err().contains("maybe"));
    }

    #[test]
    fn inner_env_value_may_contain_equals() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-env", "OPTS=a=b=c"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_launch.explicit_env,
            vec![("OPTS".to_string(), "a=b=c".to_string())]
        );
    }

    #[test]
    fn inner_env_without_equals_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-env", "NOEQUALS"]));
        assert!(parse_args(&a).unwrap_err().contains("KEY=VALUE"));
    }

    #[test]
    fn inner_env_empty_key_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-env", "=value"]));
        assert!(parse_args(&a).unwrap_err().contains("empty key"));
    }

    #[test]
    fn parses_client_cert_lifetime_forms() {
        let cases = [
            ("30m", Some(1800)),
            ("2h", Some(7200)),
            ("90s", Some(90)),
            ("45", Some(45)),
            ("none", None),
            ("0", None),
        ];
        for (input, expected) in cases {
            let mut a = minimal();
            a.splice(0..0, args(&["--max-client-cert-lifetime", input]));
            let got = parse_args(&a).expect("parse").max_client_cert_lifetime;
            assert_eq!(
                got,
                expected.map(std::time::Duration::from_secs),
                "input {input}"
            );
        }
    }

    #[test]
    fn unparseable_client_cert_lifetime_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "soon"]));
        assert!(parse_args(&a).unwrap_err().contains("max-client-cert-lifetime"));
    }

    #[test]
    fn parses_identity_source_selection() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "dns_san"]));
        assert_eq!(parse_args(&a).expect("parse").identity_source, IdentityPolicy::DnsSan);

        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "cn_legacy"]));
        assert_eq!(parse_args(&a).expect("parse").identity_source, IdentityPolicy::CnLegacy);
    }

    #[test]
    fn unknown_identity_source_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "email_san"]));
        assert!(parse_args(&a).unwrap_err().contains("email_san"));
    }

    // --- MCPS-3840 reverse-proxy ingress flags --------------------------------

    #[test]
    fn no_reverse_proxy_header_by_default() {
        let config = parse_args(&minimal()).expect("parse");
        assert_eq!(config.reverse_proxy_identity_header, None);
        // The default format is irrelevant when the header is unset, but it is
        // the safer XFCC (structured) shape rather than the trust-the-whole-value
        // plain shape.
        assert_eq!(config.reverse_proxy_header_format, ReverseProxyHeaderFormat::Xfcc);
    }

    #[test]
    fn parses_reverse_proxy_header_and_format() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header", "x-forwarded-client-cert",
                "--reverse-proxy-header-format", "xfcc",
                // Reverse-proxy mode terminates mTLS upstream, so the local
                // client-cert lifetime must be explicitly disabled.
                "--max-client-cert-lifetime", "none",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.reverse_proxy_identity_header.as_deref(),
            Some("x-forwarded-client-cert")
        );
        assert_eq!(config.reverse_proxy_header_format, ReverseProxyHeaderFormat::Xfcc);
    }

    #[test]
    fn parses_reverse_proxy_plain_format() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header", "x-client-identity",
                "--reverse-proxy-header-format", "plain",
                "--max-client-cert-lifetime", "none",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.reverse_proxy_header_format, ReverseProxyHeaderFormat::Plain);
    }

    #[test]
    fn unknown_reverse_proxy_header_format_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header", "x-client-identity",
                "--reverse-proxy-header-format", "der",
                "--max-client-cert-lifetime", "none",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("der"));
    }

    #[test]
    fn empty_reverse_proxy_header_name_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--reverse-proxy-identity-header", "   "]));
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("non-empty header name"));
    }

    #[test]
    fn reverse_proxy_mode_conflicts_with_local_cert_lifetime() {
        // The default 1h client-cert lifetime is a LOCAL-mTLS control. Enabling
        // reverse-proxy mode (mTLS terminated upstream) while it is still in force
        // is contradictory and must fail closed at parse time.
        let mut a = minimal();
        a.splice(0..0, args(&["--reverse-proxy-identity-header", "x-forwarded-client-cert"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("reverse-proxy-identity-header")
                && err.contains("max-client-cert-lifetime none"),
            "expected a mutual-exclusion error pointing at the fix; got: {err}"
        );
    }

    #[test]
    fn reverse_proxy_mode_honours_identity_source_selection() {
        // The reverse-proxy provider reuses the SAME identity-source selector as
        // the direct-TLS path, so the downstream binding policy is unchanged.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header", "x-forwarded-client-cert",
                "--transport-identity-source", "dns_san",
                "--max-client-cert-lifetime", "none",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.identity_source, IdentityPolicy::DnsSan);
        assert!(config.reverse_proxy_identity_header.is_some());
    }

    #[test]
    fn env_key_source_requires_explicit_opt_in() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--allow-env-keysource"), "got: {err}");
    }

    #[test]
    fn env_key_source_allowed_with_opt_in() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        a.splice(0..0, args(&["--allow-env-keysource"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Env);
        assert!(config.allow_env_keysource);
    }

    // MCPS-076 (audit gap G-3): in a DEFAULT build (no `dev_env_key_source`
    // feature) the env key source is not compiled and `build_key_source` must FAIL
    // CLOSED on `KeySourceKind::Env` with a clear, actionable error — `--key-source
    // env` still parses so the message is precise, but no env-backed key is built.
    #[cfg(not(feature = "dev_env_key_source"))]
    #[test]
    fn default_build_rejects_env_key_source() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        a.splice(0..0, args(&["--allow-env-keysource"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Env);
        let err = super::build_key_source(&config)
            .err()
            .expect("default build must refuse an env key source");
        let rendered = err.to_string();
        assert!(
            rendered.contains("development-only")
                && rendered.contains("dev_env_key_source"),
            "expected a clear dev-only/feature-rebuild message; got: {rendered}"
        );
    }

    // --- #4034 PKCS#11 key source (CLI parsing + fail-closed gate) -----------

    /// The four pkcs11 flags that `--key-source pkcs11` requires.
    fn pkcs11_flags() -> Vec<String> {
        args(&[
            "--key-source", "pkcs11",
            "--pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so",
            "--pkcs11-pin", "1234",
            "--pkcs11-token-label", "mcps-test",
            "--pkcs11-key-label", "mcps-response-signing",
        ])
    }

    #[test]
    fn parses_pkcs11_key_source_flags() {
        let mut a = minimal();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Pkcs11);
        assert_eq!(
            config.pkcs11_module.as_deref(),
            Some("/usr/lib/softhsm/libsofthsm2.so")
        );
        assert_eq!(config.pkcs11_pin.as_deref(), Some("1234"));
        assert_eq!(config.pkcs11_token_label.as_deref(), Some("mcps-test"));
        assert_eq!(
            config.pkcs11_key_label.as_deref(),
            Some("mcps-response-signing")
        );
    }

    #[test]
    fn pkcs11_key_source_requires_each_flag() {
        // Drop one required flag at a time; each omission is a clear parse error
        // naming the missing flag. (File/env arms are unchanged: --signing-key-seed
        // and the TLS paths are supplied by `minimal()`.)
        for missing in [
            "--pkcs11-module",
            "--pkcs11-pin",
            "--pkcs11-token-label",
            "--pkcs11-key-label",
        ] {
            let mut flags = pkcs11_flags();
            // Remove the flag and its value.
            let idx = flags.iter().position(|f| f == missing).expect("flag present");
            flags.drain(idx..idx + 2);
            let mut a = minimal();
            a.splice(0..0, flags);
            let err = parse_args(&a).unwrap_err();
            assert!(err.contains(missing), "expected error to name {missing}; got: {err}");
        }
    }

    #[test]
    fn unknown_key_source_lists_pkcs11() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "yubikey"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("file|env|pkcs11"), "got: {err}");
    }

    // In a DEFAULT build (no `pkcs11_keysource` feature) the PKCS#11 backend is
    // not compiled and `build_key_source` must FAIL CLOSED on
    // `KeySourceKind::Pkcs11` with a clear, actionable error — `--key-source
    // pkcs11` still parses so the message is precise, but no token-backed key is
    // built. Mirrors `default_build_rejects_env_key_source`.
    #[cfg(not(feature = "pkcs11_keysource"))]
    #[test]
    fn default_build_rejects_pkcs11_key_source() {
        let mut a = minimal();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Pkcs11);
        let err = super::build_key_source(&config)
            .err()
            .expect("default build must refuse a pkcs11 key source");
        let rendered = err.to_string();
        assert!(
            rendered.contains("pkcs11_keysource") && rendered.contains("not available in this build"),
            "expected a clear feature-rebuild message; got: {rendered}"
        );
    }

    // MCPS-076: the File key source is always constructible (default + dev builds).
    #[test]
    fn file_key_source_is_always_constructible() {
        let config = parse_args(&minimal()).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::File);
        assert!(super::build_key_source(&config).is_ok());
    }

    // MCPS-076: in a build WITH the dev feature, `build_key_source` honors the env
    // key source (constructs an EnvKeySource rather than failing closed).
    #[cfg(feature = "dev_env_key_source")]
    #[test]
    fn dev_build_constructs_env_key_source() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        a.splice(0..0, args(&["--allow-env-keysource"]));
        let config = parse_args(&a).expect("parse");
        assert!(super::build_key_source(&config).is_ok());
    }

    #[test]
    fn parses_configurable_limits() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--max-body-bytes", "1024",
                "--max-connections", "8",
                "--read-timeout-secs", "0",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.limits.max_body_bytes, 1024);
        assert_eq!(config.limits.max_concurrent_connections, 8);
        assert_eq!(config.limits.read_timeout, None, "0 disables the timeout");
    }

    #[test]
    fn inner_read_timeout_defaults_to_30s() {
        // MCPS-074: absent the flag, the persistent-inner read timeout is the
        // bounded 30s default (mirrors the socket read_timeout default).
        let config = parse_args(&minimal()).expect("parse");
        assert_eq!(
            config.inner_launch.inner_read_timeout,
            std::time::Duration::from_secs(30),
        );
    }

    #[test]
    fn parses_inner_read_timeout_secs() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-read-timeout-secs", "5"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_launch.inner_read_timeout,
            std::time::Duration::from_secs(5),
        );
    }

    #[test]
    fn inner_read_timeout_secs_rejects_zero() {
        // No-disable policy: 0 is a clear error, NOT a disabled (never-hang) timeout.
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-read-timeout-secs", "0"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("must be > 0"), "got: {err}");
        assert!(err.contains("--inner-read-timeout-secs"), "got: {err}");
    }

    #[test]
    fn inner_read_timeout_secs_rejects_above_max() {
        // MCPS-074: an absurdly large timeout is rejected at parse time so it can
        // never overflow the Instant deadline in the fail-closed read path. The
        // cap is 1 day (86_400s); cap+1 and u64::MAX must both be refused.
        for over in ["86401", "18446744073709551615"] {
            let mut a = minimal();
            a.splice(0..0, args(&["--inner-read-timeout-secs", over]));
            let err = parse_args(&a).unwrap_err();
            assert!(err.contains("--inner-read-timeout-secs"), "got: {err}");
            assert!(err.contains("86400"), "got: {err}");
        }
        // The cap itself (86_400) is still accepted.
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-read-timeout-secs", "86400"]));
        let config = parse_args(&a).expect("the cap value itself parses");
        assert_eq!(
            config.inner_launch.inner_read_timeout,
            std::time::Duration::from_secs(86_400),
        );
    }

    #[test]
    fn inner_read_timeout_secs_rejects_non_integer() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-read-timeout-secs", "soon"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-read-timeout-secs"), "got: {err}");
    }

    #[test]
    fn inner_command_captures_the_remainder() {
        let mut a = minimal();
        // Append flags AFTER --inner-command; they belong to the inner command.
        a.extend(args(&["--not-a-proxy-flag", "value"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_command,
            vec!["my-server", "--flag", "--not-a-proxy-flag", "value"]
        );
    }

    // #4066 (MCPS-091): a valueless proxy/security flag placed AFTER
    // `--inner-command` must NEVER be silently swallowed into the inner argv. The
    // historic greedy-varargs terminator turned `--inner-command srv --strict`
    // into `inner_command = [srv, --strict]` with `strict == false` and NO
    // warning — a silent fail-open trust-posture downgrade that also leaked the
    // flag into the hostile inner server. The parser must HARD-ERROR instead.
    #[test]
    fn proxy_security_flags_after_inner_command_are_rejected_not_swallowed() {
        for flag in ["--strict", "--production", "--allow-env-keysource"] {
            let mut a = minimal();
            a.extend(args(&[flag]));
            match parse_args(&a) {
                // Acceptable outcome: the flag was interpreted (strict turned on).
                Ok(config) => {
                    assert!(
                        config.strict || flag == "--allow-env-keysource",
                        "{flag} after --inner-command must be interpreted, not dropped"
                    );
                    assert!(
                        !config.inner_command.iter().any(|t| t == flag),
                        "{flag} leaked into inner_command: {:?}",
                        config.inner_command
                    );
                }
                // Acceptable outcome: a loud parse error naming the flag.
                Err(err) => assert!(
                    err.contains(flag),
                    "error for misplaced {flag} must name it; got: {err}"
                ),
            }
        }
    }

    #[test]
    fn missing_required_flag_errors() {
        let mut a = minimal();
        // Drop --bind and its value.
        a.drain(0..2);
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--bind"), "got: {err}");
    }

    #[test]
    fn file_replay_requires_path() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-cache", "file"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-path"), "got: {err}");
    }

    // Issue #3837: `--replay-cache shared` parses (it is a real selection) and
    // requires a connection URL.
    #[test]
    fn parses_shared_replay_selection() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-async",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.replay, ReplayKind::Shared);
        assert_eq!(
            config.replay_redis_url.as_deref(),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            config.replay_durability_tier,
            Some(crate::replay_tier::ReplayDurabilityTier::RedisAsyncBounded)
        );
    }

    #[test]
    fn shared_replay_requires_url() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-cache", "shared"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-redis-url"), "got: {err}");
    }

    // ADR-MCPS-020: a shared store must declare its durability tier.
    #[test]
    fn shared_replay_requires_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--replay-cache", "shared", "--replay-redis-url", "redis://127.0.0.1:6379"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
    }

    #[test]
    fn parses_wait_quorum_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.replay_durability_tier,
            Some(crate::replay_tier::ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 2,
                timeout_ms: 500
            })
        );
    }

    #[test]
    fn rejects_unknown_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "cluster",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown replay durability tier"), "got: {err}");
    }

    #[test]
    fn unknown_replay_cache_lists_shared() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-cache", "cluster"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("memory|file|shared"), "got: {err}");
    }

    // Issue #3837: in a DEFAULT build there is no shared replay backend, so
    // constructing the shared replay cache must FAIL CLOSED with the clear
    // not-yet-available error — never silently degrade to a non-shared cache.
    // Mirrors the env-keysource gate. Under `--features redis_replay` (#4028) the
    // real Redis backend is wired instead, so this default-build assertion is
    // compiled only when that feature is OFF.
    #[cfg(not(feature = "redis_replay"))]
    #[test]
    fn default_build_shared_replay_fails_closed() {
        let err = super::build_shared_replay_cache(
            "redis://127.0.0.1:6379",
            300,
            Some(std::time::Duration::from_secs(30)),
            Some(std::time::Duration::from_secs(30)),
            &crate::replay_tier::ReplayDurabilityTier::RedisAsyncBounded,
        )
        .err()
        .expect("this build must refuse the shared replay cache");
        assert!(
            err.contains("not yet available in this build"),
            "expected a clear not-yet-available message; got: {err}"
        );
    }

    // Phase 0 (production packaging): under `--features redis_replay` the shared
    // replay cache wires the REAL Redis backend. If Redis is UNREACHABLE at startup
    // (nothing listening → connection REFUSED), construction must FAIL CLOSED
    // (return Err) so the proxy refuses to start rather than accepting traffic with
    // no replay safety. This drives the production path end-to-end:
    //   build_shared_replay_cache (cli.rs)
    //     → RedisAtomicReplayStore::connect_with (redis_store.rs)
    //       → bounded_connect → get_connection_with_timeout → connection refused
    //         → ReplayStoreError::Unavailable → Err(String) out of the builder.
    // Distinct from `stalled_redis_fails_closed_within_timeout_not_hang` in
    // redis_store.rs, which covers the SINKHOLE (TCP accepts, never answers) case;
    // here NOTHING is listening, so the connect is REFUSED immediately — fast and
    // deterministic, NOT a slow timeout.
    //
    // RED without fail-closed: if `connect_with`/`bounded_connect` swallowed the
    // connect error and returned a degraded non-failing cache, this returns Ok and
    // the `expect` on `.err()` panics — the test fails. Proven by neutralization.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn connection_refused_redis_fails_closed_at_construction() {
        // Port 1 on loopback has nothing listening → connection REFUSED at once.
        let unreachable = "redis://127.0.0.1:1/";
        // A bounded connect deadline; a refused connect returns well inside it.
        let connect_timeout = std::time::Duration::from_secs(2);

        let start = std::time::Instant::now();
        let result = super::build_shared_replay_cache(
            unreachable,
            300,
            Some(connect_timeout),
            Some(std::time::Duration::from_secs(2)),
            &crate::replay_tier::ReplayDurabilityTier::RedisAsyncBounded,
        );
        let elapsed = start.elapsed();

        let err = result
            .err()
            .expect("an unreachable Redis must make the shared replay cache FAIL CLOSED");
        // The builder maps the Unavailable store error into its "shared replay
        // cache: ..." String — assert we got that fail-closed surface, not a
        // degraded usable cache.
        assert!(
            err.contains("shared replay cache"),
            "expected the fail-closed shared-replay-cache error; got: {err}"
        );
        // Connection-REFUSED is immediate: it must complete well within the bounded
        // connect deadline (NOT hang to the full timeout). Generous upper bound to
        // stay robust on a loaded CI box while still proving boundedness.
        assert!(
            elapsed < connect_timeout,
            "refused connect must fail closed PROMPTLY (well inside the {connect_timeout:?} \
             deadline); took {elapsed:?}"
        );
    }

    #[test]
    fn parses_inner_mode_selection() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-mode", "persistent"]));
        assert_eq!(parse_args(&a).expect("parse").inner_mode, InnerModeKind::Persistent);

        let mut a = minimal();
        a.splice(0..0, args(&["--inner-mode", "oneshot"]));
        assert_eq!(parse_args(&a).expect("parse").inner_mode, InnerModeKind::OneShot);
    }

    #[test]
    fn unknown_inner_mode_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-mode", "forever"]));
        assert!(parse_args(&a).unwrap_err().contains("forever"));
    }

    #[test]
    fn unknown_flag_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--bogus", "x"]));
        assert!(parse_args(&a).unwrap_err().contains("--bogus"));
    }

    // --- #3839 offline CRL flags ---------------------------------------------

    #[test]
    fn default_has_no_crls_and_fails_closed_on_unknown_status() {
        let config = parse_args(&minimal()).expect("parse");
        assert!(
            config.client_crl_paths.is_empty(),
            "no CRLs by default (revocation checking disabled until configured)"
        );
        assert!(
            !config.crl_allow_unknown_status,
            "default posture is fail-closed: unknown revocation status is DENIED"
        );
    }

    #[test]
    fn parses_a_single_client_crl_path() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-crl", "/etc/mcps/clients.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.client_crl_paths, vec!["/etc/mcps/clients.crl".to_string()]);
    }

    #[test]
    fn parses_comma_separated_client_crls() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-crl", "/a.crl,/b.crl,/c.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.client_crl_paths,
            vec!["/a.crl".to_string(), "/b.crl".to_string(), "/c.crl".to_string()]
        );
    }

    #[test]
    fn repeated_client_crl_flags_accumulate() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--client-crl", "/a.crl", "--client-crl", "/b.crl"]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.client_crl_paths,
            vec!["/a.crl".to_string(), "/b.crl".to_string()]
        );
    }

    #[test]
    fn empty_client_crl_segment_errors() {
        // A trailing comma (or empty value) must not silently load zero CRLs and
        // quietly disable revocation — it is a clear error.
        let mut a = minimal();
        a.splice(0..0, args(&["--client-crl", "/a.crl,"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("empty path segment"), "got: {err}");
    }

    #[test]
    fn parses_crl_allow_unknown_status_flag() {
        let mut a = minimal();
        a.splice(0..0, args(&["--crl-allow-unknown-status"]));
        let config = parse_args(&a).expect("parse");
        assert!(config.crl_allow_unknown_status);
    }

    #[test]
    fn missing_client_crl_file_fails_closed() {
        // A configured-but-unreadable CRL path is a hard error, never a silently
        // skipped revocation check.
        let err = super::load_client_crls(&["/no/such/MCPS3839_MISSING.crl".to_string()])
            .unwrap_err();
        assert!(err.contains("MCPS3839_MISSING"), "got: {err}");
    }

    #[test]
    fn no_crl_paths_loads_empty_vec() {
        // The no-CRL path: empty input → empty vec (revocation disabled), no error.
        let crls = super::load_client_crls(&[]).expect("empty load");
        assert!(crls.is_empty());
    }

    // --- #4030 online OCSP flag parsing -------------------------------------

    #[test]
    fn default_has_online_ocsp_off_and_hard_fail() {
        let config = parse_args(&minimal()).expect("parse");
        assert_eq!(
            config.client_ocsp,
            OcspKind::Off,
            "online OCSP is OFF by default (offline-CRL-only posture preserved)"
        );
        assert!(
            !config.ocsp_soft_fail,
            "default OCSP posture is hard-fail (deny on indeterminate)"
        );
        assert!(config.ocsp_responder_url.is_none());
    }

    #[test]
    fn parses_client_ocsp_require_and_knobs() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--client-ocsp",
                "require",
                "--ocsp-responder-url",
                "http://ocsp.example.test/r",
                "--ocsp-soft-fail",
            ]),
        );
        // In a build WITHOUT the online_ocsp feature, `--client-ocsp require`
        // fails closed at parse time; under the feature it parses fully.
        match parse_args(&a) {
            Ok(config) => {
                assert_eq!(config.client_ocsp, OcspKind::Require);
                assert_eq!(
                    config.ocsp_responder_url.as_deref(),
                    Some("http://ocsp.example.test/r")
                );
                assert!(config.ocsp_soft_fail);
            }
            Err(err) => assert!(
                err.contains("online_ocsp feature"),
                "without the feature, require must fail closed; got: {err}"
            ),
        }
    }

    #[test]
    fn unknown_client_ocsp_value_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "maybe"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --client-ocsp"), "got: {err}");
    }

    #[test]
    fn responder_url_without_require_errors() {
        // A dangling --ocsp-responder-url (no --client-ocsp require) must not
        // silently do nothing.
        let mut a = minimal();
        a.splice(0..0, args(&["--ocsp-responder-url", "http://x/r"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--ocsp-responder-url has no effect"),
            "got: {err}"
        );
    }

    #[test]
    fn soft_fail_without_require_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--ocsp-soft-fail"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ocsp-soft-fail has no effect"), "got: {err}");
    }

    #[test]
    fn empty_responder_url_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "require", "--ocsp-responder-url", "   "]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("non-empty URL"), "got: {err}");
    }

    #[cfg(not(feature = "online_ocsp"))]
    #[test]
    fn client_ocsp_require_fails_closed_without_feature() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "require"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("online_ocsp feature") && err.contains("not available in this build"),
            "require must fail closed without the feature; got: {err}"
        );
    }

    #[cfg(feature = "online_ocsp")]
    #[test]
    fn client_ocsp_require_in_reverse_proxy_mode_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--client-ocsp",
                "require",
                "--reverse-proxy-identity-header",
                "x-client-id",
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("reverse-proxy mode"),
            "OCSP checks the local client cert, absent in reverse-proxy mode; got: {err}"
        );
    }

    #[test]
    fn loads_a_trust_file() {
        let key = SigningKey::from_seed_bytes(&[1u8; 32]).public_key().to_b64url();
        let json = format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{key}"}}]"#
        );
        let resolver = load_trust(json.as_bytes()).expect("load");
        assert!(resolver.resolve("did:example:agent-1", "key-1").is_ok());
        assert!(resolver.resolve("did:example:agent-1", "other").is_err());
    }

    #[test]
    fn trust_file_with_bad_key_errors() {
        let json = r#"[{"signer":"s","key_id":"k","public_key":"!!!not-base64"}]"#;
        assert!(load_trust(json.as_bytes()).is_err());
    }

    // --- MCPS-3842 strict/production posture ("reject, not warn") ------------
    //
    // Black-box parser tests: under `--strict` (and the `--production` alias)
    // each insecure-posture config that is otherwise only warned about becomes a
    // HARD parse error. The matching non-strict control proves the SAME config
    // still parses Ok (warn-only) without the flag — strict is purely additive.

    #[test]
    fn strict_flag_defaults_off_and_parses_on() {
        // Default: warn-only posture.
        assert!(!parse_args(&minimal()).expect("parse").strict);
        // --strict turns it on for an otherwise-safe config.
        let mut a = minimal();
        a.splice(0..0, args(&["--strict"]));
        assert!(parse_args(&a).expect("parse").strict);
    }

    #[test]
    fn production_alias_maps_to_strict_true() {
        let mut a = minimal();
        a.splice(0..0, args(&["--production"]));
        let config = parse_args(&a).expect("parse");
        assert!(config.strict, "--production must map to strict = true");
    }

    #[test]
    fn strict_accepts_a_fully_safe_config() {
        // The minimal config uses every secure default; --strict must accept it.
        let mut a = minimal();
        a.splice(0..0, args(&["--strict"]));
        let config = parse_args(&a).expect("a fully-safe config must parse under --strict");
        assert!(config.strict);
        assert!(
            strict_violations(&config).is_empty(),
            "a safe config must have no strict violations"
        );
    }

    // ADR-MCPS-020: strict/production rejects a shared store declared at a tier
    // weaker than REDIS_WAIT_QUORUM.
    #[test]
    fn strict_rejects_weak_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-async",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
        assert!(err.contains("strict-production minimum"), "got: {err}");
    }

    #[test]
    fn strict_accepts_wait_quorum_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("wait-quorum tier must be strict-acceptable");
        assert!(
            strict_violations(&config)
                .iter()
                .all(|v| !v.contains("replay-durability-tier")),
            "wait-quorum must not be a replay-tier strict violation"
        );
    }

    #[test]
    fn strict_rejects_env_key_source() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--key-source", "env", "--allow-env-keysource"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--key-source env"), "got: {err}");
    }

    #[test]
    fn non_strict_env_key_source_with_opt_in_is_ok() {
        // Control: the same env key source (with its own opt-in) parses Ok
        // without --strict — it is only WARNED about at runtime.
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env", "--allow-env-keysource"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Env);
        assert!(!config.strict);
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_none() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--max-client-cert-lifetime", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_zero() {
        // `0` parses to the same disabled (None) enforcement as `none`.
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--max-client-cert-lifetime", "0"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    #[test]
    fn non_strict_disabled_cert_lifetime_is_ok() {
        // Control: disabled enforcement parses Ok without --strict (warn-only).
        let mut a = minimal();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "none"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.max_client_cert_lifetime, None);
        assert!(!config.strict);
    }

    #[test]
    fn strict_keeps_over_recommended_lifetime_as_warning_not_error() {
        // MCPS-3842: a lifetime > 1h is a RECOMMENDATION, not an unsafe posture
        // (still enforced, just longer), so it must NOT error even under strict.
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--max-client-cert-lifetime", "2h"]));
        let config = parse_args(&a).expect("an over-recommended-but-enforced lifetime is allowed");
        assert_eq!(
            config.max_client_cert_lifetime,
            Some(std::time::Duration::from_secs(7200))
        );
        assert!(
            strict_violations(&config).is_empty(),
            "a longer-but-enforced lifetime must not be a strict violation"
        );
    }

    #[test]
    fn strict_rejects_inherit_env_true() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--inherit-env", "true"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--inherit-env true"), "got: {err}");
    }

    #[test]
    fn non_strict_inherit_env_true_is_ok() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inherit-env", "true"]));
        let config = parse_args(&a).expect("parse");
        assert!(config.inner_launch.inherit_env);
        assert!(!config.strict);
    }

    #[test]
    fn strict_rejects_cn_legacy_identity_source() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--transport-identity-source", "cn_legacy"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("cn_legacy"), "got: {err}");
    }

    #[test]
    fn non_strict_cn_legacy_identity_source_is_ok() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "cn_legacy"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.identity_source, IdentityPolicy::CnLegacy);
        assert!(!config.strict);
    }

    #[test]
    fn strict_rejects_best_effort_rlimits() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--inner-rlimit-best-effort", "true"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--inner-rlimit-best-effort"), "got: {err}");
    }

    #[test]
    fn non_strict_best_effort_rlimits_is_ok() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-rlimit-best-effort", "true"]));
        let config = parse_args(&a).expect("parse");
        assert!(config.inner_launch.rlimits.best_effort);
        assert!(!config.strict);
    }

    #[test]
    fn strict_reports_all_violations_at_once() {
        // The error aggregates every parse-time violation so the operator can fix
        // the whole posture in one pass, not one error per restart.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--key-source", "env",
                "--allow-env-keysource",
                "--max-client-cert-lifetime", "none",
                "--inherit-env", "true",
                "--transport-identity-source", "cn_legacy",
                "--inner-rlimit-best-effort", "true",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--key-source env"), "got: {err}");
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
        assert!(err.contains("--inherit-env true"), "got: {err}");
        assert!(err.contains("cn_legacy"), "got: {err}");
        assert!(err.contains("--inner-rlimit-best-effort"), "got: {err}");
    }

    // --- #4082 (MCPS-MED-1) additional strict/production posture rejections -----
    //
    // M09/M10/M11/M12/M22: under `--strict`/`--production`, these otherwise
    // warn-only postures become HARD parse errors. Each strict test is paired
    // with a non-strict control proving the SAME posture still parses Ok.

    // M09 — an EXPLICIT `--inner-sandbox off` under --strict is a deliberate
    // request for zero inner containment and is refused. (The DEFAULT off, with
    // no flag, stays accepted — `strict_accepts_a_fully_safe_config` covers that
    // — because no kernel backend ships in this build, so a blanket enforce
    // requirement would fail closed everywhere.)
    #[test]
    fn strict_rejects_explicit_inner_sandbox_off() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--inner-sandbox", "off"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--inner-sandbox"), "got: {err}");
    }

    #[test]
    fn non_strict_explicit_inner_sandbox_off_is_ok() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-sandbox", "off"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.inner_launch.sandbox.mode, SandboxMode::Off);
        assert!(!config.strict);
    }

    // M10/M22 — reverse-proxy identity-header ingress is the documented
    // identity-spoofable posture; --strict refuses to enable it silently.
    #[test]
    fn strict_rejects_reverse_proxy_identity_header_ingress() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--reverse-proxy-identity-header",
                "x-forwarded-client-cert",
                // The local-cert lifetime is meaningless in reverse-proxy mode,
                // so it must be explicitly disabled (existing parse rule); that
                // disabled lifetime is itself a strict violation, but the
                // reverse-proxy ingress rejection is what we assert here.
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--reverse-proxy-identity-header"), "got: {err}");
    }

    #[test]
    fn non_strict_reverse_proxy_identity_header_ingress_is_ok() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header",
                "x-forwarded-client-cert",
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert!(config.reverse_proxy_identity_header.is_some());
        assert!(!config.strict);
    }

    // M11 — `--transport-binding none` decouples the verified request signer
    // from the mTLS channel identity; --strict refuses it.
    #[test]
    fn strict_rejects_transport_binding_none() {
        let mut a = minimal();
        a.splice(0..0, args(&["--strict", "--transport-binding", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--transport-binding"), "got: {err}");
    }

    #[test]
    fn non_strict_transport_binding_none_is_ok() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-binding", "none"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.binding, BindingKind::None);
        assert!(!config.strict);
    }

    // M12 — `--crl-allow-unknown-status` is a CRL fail-open relaxation; --strict
    // refuses it when CRLs are actually configured (mirrors its
    // no-effect-without-CRLs semantics).
    #[test]
    fn strict_rejects_crl_allow_unknown_status_with_crls() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--client-crl",
                "/crl.pem",
                "--crl-allow-unknown-status",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--crl-allow-unknown-status"), "got: {err}");
    }

    #[test]
    fn non_strict_crl_allow_unknown_status_is_ok() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--client-crl", "/crl.pem", "--crl-allow-unknown-status"]),
        );
        let config = parse_args(&a).expect("parse");
        assert!(config.crl_allow_unknown_status);
        assert!(!config.strict);
    }

    // M12 — `--ocsp-soft-fail` is an online-OCSP fail-open relaxation; --strict
    // refuses it. It is only reachable in an `online_ocsp` build (otherwise
    // `--client-ocsp require` fails closed at parse before the strict gate), so
    // this test is feature-gated to the build that can exercise the strict arm.
    #[cfg(feature = "online_ocsp")]
    #[test]
    fn strict_rejects_ocsp_soft_fail() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--strict",
                "--client-ocsp",
                "require",
                "--ocsp-soft-fail",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--strict"), "got: {err}");
        assert!(err.contains("--ocsp-soft-fail"), "got: {err}");
    }

    // --- #3865 inner-server OS sandbox profile (CLI parsing + fail-closed gate) ---
    //
    // The enforce gate's outcome is platform/kernel dependent: on darwin (and any
    // Linux kernel without Landlock at the required ABI) no kernel backend can
    // enforce, so requesting `enforce` MUST fail closed; on a Linux kernel that
    // CAN enforce, construction succeeds and the backend is installed at spawn.
    // The tests below assert the correct branch by consulting the SAME runtime
    // capability probe the production gate uses (`backend_can_enforce`), so they
    // hold on every runner (darwin dev, Linux CI with or without Landlock).

    #[test]
    fn sandbox_defaults_off_and_deny_all() {
        let config = parse_args(&minimal()).expect("parse");
        let s = &config.inner_launch.sandbox;
        assert_eq!(s.mode, SandboxMode::Off, "default mode must be off");
        assert_eq!(s.network, NetworkPolicy::DenyAll, "default net policy must be deny-all");
        assert!(s.fs_allow_read.is_empty());
        assert!(s.fs_allow_write.is_empty());
    }

    #[test]
    fn sandbox_off_parses_and_does_not_trip_the_gate() {
        // --inner-sandbox off behaves exactly as the default: parses Ok, no gate.
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-sandbox", "off"]));
        let config = parse_args(&a).expect("--inner-sandbox off must parse and not gate");
        assert_eq!(config.inner_launch.sandbox.mode, SandboxMode::Off);
    }

    #[test]
    fn sandbox_enforce_gate_matches_backend_capability() {
        // The load-bearing honesty gate, asserted against the SAME runtime probe
        // the production path uses (`SandboxProfile::backend_can_enforce`): where
        // no kernel backend can enforce (darwin, or a Linux kernel without
        // Landlock), `enforce` MUST refuse to start at construction time; where the
        // kernel CAN enforce (Linux + Landlock at the required ABI), construction
        // succeeds and the backend is installed lazily at spawn. The gate is
        // exercised through SubprocessInner::new (startup validation), the same
        // path main.rs takes before any inner server is spawned.
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-sandbox", "enforce"]));
        let config = parse_args(&a).expect("flags parse; the gate fires at construction");
        assert_eq!(config.inner_launch.sandbox.mode, SandboxMode::Enforce);

        let result = SubprocessInner::new(&config.inner_command, config.inner_launch.clone());
        if SandboxProfile::backend_can_enforce() {
            // A platform/kernel that CAN enforce: construction must succeed (the
            // Landlock ruleset + seccomp filter install as a pre_exec hook later).
            assert!(
                result.is_ok(),
                "enforce must construct where the kernel backend can enforce"
            );
        } else {
            // No kernel backend: the gate MUST fail closed BEFORE any spawn. Match
            // rather than `.expect_err` so the assertion does not require
            // `SubprocessInner: Debug` (the Ok value is never printed here).
            let err = match result {
                Ok(_) => panic!("enforce without a kernel backend must fail closed before spawn"),
                Err(e) => e,
            };
            assert!(err.contains("enforce"), "got: {err}");
            assert!(err.contains("refusing to start"), "got: {err}");
            assert!(
                err.contains("#3865"),
                "error must point at the follow-up: {err}"
            );
        }
    }

    #[test]
    fn sandbox_unknown_mode_is_rejected() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-sandbox", "maybe"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-sandbox"), "got: {err}");
        assert!(err.contains("off|enforce"), "got: {err}");
    }

    #[test]
    fn fs_allow_read_repeated_and_comma_separated_accumulate() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--inner-fs-allow-read", "/etc/inner",
                "--inner-fs-allow-read", "/var/data,/opt/cfg",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_launch.sandbox.fs_allow_read,
            vec!["/etc/inner".to_string(), "/var/data".to_string(), "/opt/cfg".to_string()],
        );
    }

    #[test]
    fn fs_allow_write_repeated_and_comma_separated_accumulate() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--inner-fs-allow-write", "/tmp/a,/tmp/b"]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_launch.sandbox.fs_allow_write,
            vec!["/tmp/a".to_string(), "/tmp/b".to_string()],
        );
    }

    #[test]
    fn fs_allow_read_empty_segment_is_rejected() {
        // A trailing comma (empty segment) must be an error so a typo can never
        // silently widen filesystem access — mirrors the --client-crl posture.
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-fs-allow-read", "/etc/inner,"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-fs-allow-read"), "got: {err}");
        assert!(err.contains("empty path segment"), "got: {err}");
    }

    #[test]
    fn fs_allow_write_empty_segment_is_rejected() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-fs-allow-write", ",/tmp/x"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-fs-allow-write"), "got: {err}");
        assert!(err.contains("empty path segment"), "got: {err}");
    }

    #[test]
    fn net_policy_defaults_deny_and_allow_flips_it() {
        // Default deny-all proven in sandbox_defaults_off_and_deny_all; here prove
        // --inner-net allow flips it and --inner-net deny is explicit.
        let mut allow = minimal();
        allow.splice(0..0, args(&["--inner-net", "allow"]));
        assert_eq!(
            parse_args(&allow).expect("parse").inner_launch.sandbox.network,
            NetworkPolicy::Allow,
        );
        let mut deny = minimal();
        deny.splice(0..0, args(&["--inner-net", "deny"]));
        assert_eq!(
            parse_args(&deny).expect("parse").inner_launch.sandbox.network,
            NetworkPolicy::DenyAll,
        );
    }

    #[test]
    fn net_policy_unknown_is_rejected() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-net", "filtered"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--inner-net"), "got: {err}");
        assert!(err.contains("deny|allow"), "got: {err}");
    }

    #[test]
    fn key_file_mode_predicate_flags_group_and_world_bits() {
        // The pure file-perm predicate used by main.rs's strict key-file check:
        // owner-only (0600) is safe; any group/world bit is insecure.
        assert!(!super::key_file_mode_is_insecure(0o600), "0600 owner-only is safe");
        assert!(!super::key_file_mode_is_insecure(0o400), "0400 owner-read is safe");
        assert!(super::key_file_mode_is_insecure(0o640), "group-readable is insecure");
        assert!(super::key_file_mode_is_insecure(0o604), "world-readable is insecure");
        assert!(super::key_file_mode_is_insecure(0o660), "group-writable is insecure");
        assert!(super::key_file_mode_is_insecure(0o777), "world-everything is insecure");
    }
}
