//! The production `mcps-proxy` CLI (MCPS-029, ADR-MCPS-014; folds in MCPS-018).
//!
//! Terminates TLS, verifies the mTLS client certificate, verifies the MCP-S
//! object signature, optionally evaluates authorization (Phase 5) and transport
//! binding (Phase 6), then forwards verified requests to an inner MCP server
//! subprocess and signs the response. Blocking single-threaded serve loop (no
//! async). All wiring/parsing logic lives in `cli` (and is unit-tested there);
//! this shell parses, builds, and runs.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_policy::InMemoryRevocationSource;
use mcps_policy::PolicyEvaluator;
use mcps_policy::ReferenceProfile;
use mcps_policy::REFERENCE_PROFILE_ID;
use mcps_proxy::cli;
use mcps_proxy::cli::AuthzKind;
use mcps_proxy::cli::BindingKind;
use mcps_proxy::cli::InnerModeKind;
use mcps_proxy::cli::KeySourceKind;
use mcps_proxy::cli::ReplayKind;
use mcps_proxy::tls;
use mcps_proxy::transport::ExactMatchBinding;
use mcps_proxy::DurableReplayCache;
use mcps_proxy::IdentityPolicy;
use mcps_proxy::ReplayDurabilityTier;
use mcps_proxy::IdentityStrategy;
use mcps_proxy::InnerServer;
use mcps_proxy::PersistentSubprocessInner;
use mcps_proxy::Proxy;
use mcps_proxy::RevocationTier;
use mcps_proxy::ReverseProxyMtlsProvider;
use mcps_proxy::ServerOptions;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A wall-clock reading below this Unix-seconds threshold at startup is treated as a
/// host-clock fault (audit #94 F5). `now_unix()` clamps a pre-epoch SystemTime error
/// to 0, and a host whose clock is unset typically reads at/near the epoch; either
/// way every freshness check will fail closed. The threshold is 2000-01-01 UTC — far
/// below any plausible real deployment time, so a legitimate clock never trips it,
/// but a 0/epoch clock always does.
const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// The production [`UnixClock`] the revocation-tier resolver wrapping uses to bound
/// the propagation window `T` (ADR-MCPS-021). Delegates to the trust-cache's
/// system clock so production and the unit-tested helper share one clock type.
fn trust_clock() -> mcps_proxy::trust_cache::UnixClock {
    mcps_proxy::trust_cache::system_clock()
}

/// Enforce the key-file-permission posture for a sensitive key file. In the
/// default (warn-only) posture a group/world-accessible key file produces a
/// WARNING; under `--strict`/`--production` (MCPS-3842, "reject, not warn") the
/// same condition is a HARD error returned to the caller so startup refuses. The
/// warn-vs-reject decision uses the pure [`cli::key_file_mode_is_insecure`]
/// predicate so it stays consistent with (and testable alongside) the
/// parse-time strict checks.
#[cfg(unix)]
fn check_key_file_perms(path: &str, strict: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if cli::key_file_mode_is_insecure(mode) {
            if strict {
                return Err(format!(
                    "--strict/--production refuses unsafe configuration:\n  - key file {path} \
                     is group/world-accessible (mode {:o}); restrict to 0600",
                    mode & 0o777
                ));
            }
            eprintln!(
                "mcps-proxy: WARNING: key file {path} is group/world-accessible (mode {:o}); \
                 restrict to 0600",
                mode & 0o777
            );
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_key_file_perms(_path: &str, _strict: bool) -> Result<(), String> {
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = cli::parse_args(&args)?;

    // Clock-fault diagnosis (audit #94 F5). `now_unix()` deliberately maps a
    // pre-epoch SystemTime error to 0 (fail CLOSED — every request then fails its
    // freshness check rather than admitting a stale one), but a clock that reads
    // at/near the Unix epoch would otherwise surface only as an unexplained flood of
    // freshness denials. Emit a ONE-TIME loud startup warning so a broken/unset host
    // clock is diagnosed at the source instead of masked. We do not refuse to start
    // (the fail-closed posture is already safe), but the operator is told why every
    // request will be denied.
    // Read the clock ONCE so the comparison and the reported value are consistent
    // (a second now_unix() call could read a different instant).
    let startup_now_unix = now_unix();
    if startup_now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS {
        eprintln!(
            "mcps-proxy: WARNING: the system clock reads at/near the Unix epoch ({} < {}s); this \
             almost certainly means the host clock is unset or broken. Freshness checks will \
             FAIL CLOSED (every request denied) until the clock is corrected — fix the host clock \
             (NTP/RTC) rather than treating the resulting denials as a load problem.",
            startup_now_unix,
            EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
        );
    }

    // Security posture warnings (config already enforced the hard guards).
    if config.identity_source == IdentityPolicy::CnLegacy {
        eprintln!(
            "mcps-proxy: WARNING: --transport-identity-source cn_legacy is deprecated; \
             prefer uri_san or dns_san"
        );
    }
    if config.key_source == KeySourceKind::Env {
        eprintln!(
            "mcps-proxy: WARNING: --key-source env is dev/CI-only; env key material is visible \
             to the process tree. Use --key-source file in production."
        );
    }
    // MCPS-3840 reverse-proxy ingress trust assumption — emit LOUDLY. When the
    // identity is read from a trusted forwarded header, mTLS is terminated by an
    // upstream proxy and the local client certificate is NOT consulted for
    // identity. This is only safe if the listening socket is reachable ONLY by
    // the trusted upstream; anyone who can reach the port could otherwise spoof
    // any identity by setting the header. (Strict ingress enforcement is #3842.)
    if let Some(header) = &config.reverse_proxy_identity_header {
        eprintln!(
            "mcps-proxy: WARNING: reverse-proxy identity mode is ENABLED (reading the trusted \
             header '{header}', format {:?}, identity field {:?}). mTLS is assumed terminated \
             UPSTREAM and the local client certificate is NOT used for identity. You are \
             asserting the listening socket {} is reachable ONLY by the trusted upstream \
             (loopback / private network / its own mTLS link) and that the upstream STRIPS any \
             client-supplied copy of '{header}' before setting its own. If the socket is \
             reachable by untrusted clients, they can SPOOF any identity.",
            config.reverse_proxy_header_format,
            config.identity_source,
            config.bind,
        );
    }
    if config.key_source == KeySourceKind::File {
        // MCPS-3842: under strict/production a group/world-readable key file is a
        // HARD error (refuse startup), not a warning. The other strict checks are
        // parse-time and already enforced inside `cli::parse_args`; this one is
        // filesystem-dependent so it lives here.
        check_key_file_perms(&config.signing_key_seed, config.strict)?;
        check_key_file_perms(&config.tls_key, config.strict)?;
    }
    match config.max_client_cert_lifetime {
        None => eprintln!(
            "mcps-proxy: WARNING: client-certificate lifetime enforcement is DISABLED; with no \
             online revocation a compromised client cert is usable until expiry. Set \
             --max-client-cert-lifetime (default 1h)."
        ),
        // MCPS-3842: a lifetime > 1h is a RECOMMENDATION (the default is 1h), not
        // an unsafe posture — a longer-but-still-enforced lifetime is a tradeoff,
        // not a hole — so it stays a WARNING even under --strict. Only DISABLED
        // enforcement (the `None` arm above) is rejected by strict mode.
        Some(d) if d.as_secs() > 3600 => eprintln!(
            "mcps-proxy: WARNING: --max-client-cert-lifetime {}s exceeds the recommended 1h for the \
             short-lived-cert revocation posture.",
            d.as_secs()
        ),
        Some(_) => {}
    }

    // Key material + trust.
    //
    // Issue #3838 (ADR-MCPS-014): the response-signing key is NOT extracted here.
    // We pull the TLS materials (still export accessors, by #3838 scope) and the
    // client-CA roots from the key source, then hand the SAME boxed source to the
    // proxy AS its response signer (`Box<dyn KeySource>: ResponseSigner`). The proxy
    // signs by delegation (`sign_response`), so a non-exporting HSM/KMS source would
    // never need to surrender its private key — there is deliberately no
    // `signing_key()` export call on the wiring path anymore.
    let key_source = cli::build_key_source(&config).map_err(|e| e.to_string())?;
    let server_chain = key_source.tls_server_cert_chain().map_err(|e| e.to_string())?;
    let client_ca = key_source.client_ca_roots().map_err(|e| e.to_string())?;
    // ADR-MCPS-028 §G / issue #58: TLS signing is DELEGATED xor EXPORTED. When the
    // source offers a delegated TLS signer the server private key never leaves the
    // device — we never call `tls_server_key()`. The exported key is loaded ONLY on
    // the non-delegated path. The CLI exclusivity guard (`cli::parse_args`) already
    // rejected a config that asks for both.
    let tls_delegated_signer = key_source.tls_delegated_signer();
    let server_key = match &tls_delegated_signer {
        Some(_) => None,
        None => Some(key_source.tls_server_key().map_err(|e| e.to_string())?),
    };
    let trust_bytes = std::fs::read(&config.trust_path)
        .map_err(|e| format!("{}: {e}", config.trust_path))?;
    let base_resolver = cli::load_trust(&trust_bytes)?;

    // ADR-MCPS-021 Axis 2: surface the DECLARED revocation tier and its honest
    // guarantee at startup. The proxy emits the tier's OWN guarantee string — never
    // a hardcoded stronger one — so it cannot surface a revocation window stronger
    // than the configured tier proves (the tier-claim ceiling). Tier 1
    // (bounded-cache) is the default when --revocation-tier is absent.
    eprintln!(
        "mcps-proxy: {}",
        config.revocation_tier.startup_audit_line("trust-store")
    );
    // ADR-MCPS-021 Axis 2: APPLY the declared tier to the resolver so the runtime
    // behavior actually matches the surfaced guarantee (Tier 1 bounds cached active
    // trust to T; Tier 2 consults the store live every request; Tier 3 evicts on a
    // pushed event, else falls back to bounded T). Without this wrapping the tier
    // line above would be a claim the resolver does not enforce.
    if let RevocationTier::Push { .. } = config.revocation_tier {
        // Honesty (Tier 3): no networked event source ships yet, so the in-process
        // reference channel is inert — Tier 3 currently runs at its bounded-`T`
        // fallback (already reflected in the tier's `guarantee()` string above). It
        // does NOT operate an active near-zero push channel until a push backend
        // ships.
        eprintln!(
            "mcps-proxy: NOTE: revocation-tier PUSH has no networked event source in this \
             build, so it runs at its bounded-T fallback (no active near-zero push channel \
             ships yet); a push backend is a follow-up."
        );
    }
    let resolver =
        cli::build_revocation_resolver(&config.revocation_tier, Box::new(base_resolver), trust_clock());

    // Inner-server environment minimization (MCPS-035, ADR-MCPS-016). By default
    // the child environment is cleared and only the explicit allowlist is passed,
    // closing the full-inheritance leak (env-loaded key material is not visible to
    // the inner server unless explicitly allowlisted). Full inheritance is opt-in
    // and loudly warned.
    if config.inner_launch.inherit_env {
        eprintln!(
            "mcps-proxy: WARNING: --inherit-env true passes the proxy's ENTIRE environment to the \
             inner server, including any env-loaded key material (e.g. an env-backed KeySource). \
             This re-opens the full-inheritance leak; prefer --inherit-env false (default) with \
             explicit --inner-env / --inner-env-allow."
        );
    }

    // Inner-server working-dir + output hygiene (MCPS-036, ADR-MCPS-016). The
    // inner server launches in a CONTROLLED working directory (the explicit
    // --inner-working-dir, else the system temp dir — never silently the proxy's
    // cwd). This is a controlled STARTING directory, NOT a filesystem sandbox:
    // the inner server can still chdir and open any path its OS credentials
    // allow. Its stderr is captured separately into a bounded log; bounded is not
    // secrets-safe.
    eprintln!(
        "mcps-proxy: inner working dir = {} (controlled start dir, NOT a filesystem sandbox); \
         inner stderr captured to a bounded log ({} bytes / {} lines), never forwarded as MCP content; \
         inner stdout per-read timeout = {:?} (always bounded, no disable — never-hang posture)",
        config.inner_launch.effective_working_dir(),
        config.inner_launch.stderr_cap_bytes,
        config.inner_launch.stderr_cap_lines,
        config.inner_launch.inner_read_timeout,
    );

    // Inner-server resource hardening (MCPS-037, ADR-MCPS-016). Unix `setrlimit`
    // ceilings applied to the inner subprocess before exec. This is RESOURCE
    // HARDENING, NOT SANDBOXING: it bounds resource abuse (fds, CPU, memory,
    // core/file size), not access — the inner server can still reach any file or
    // socket its OS credentials permit. A configured limit is never silently
    // dropped: on Unix a setrlimit the kernel refuses fails the spawn; on a
    // non-Unix platform a configured limit is a hard startup error unless
    // best-effort is opted in.
    {
        let r = &config.inner_launch.rlimits;
        if r.any_configured() {
            eprintln!(
                "mcps-proxy: inner resource limits (RESOURCE HARDENING, NOT a sandbox): \
                 nofile={:?} cpu_s={:?} as_bytes={:?} data_bytes={:?} core_bytes={:?} \
                 fsize_bytes={:?} best_effort={}",
                r.nofile, r.cpu_seconds, r.address_space_bytes, r.data_bytes, r.core_bytes,
                r.fsize_bytes, r.best_effort,
            );
        }
        if r.best_effort && r.any_configured() {
            eprintln!(
                "mcps-proxy: WARNING: --inner-rlimit-best-effort true — a resource limit that \
                 cannot be applied will be downgraded to a logged no-op instead of failing \
                 closed. Prefer the default strict posture in production."
            );
        }
    }

    // Inner-server OS sandbox profile (#3865, ADR-MCPS-016). This is the PROFILE +
    // fail-closed platform gate, NOT enforcement. With --inner-sandbox off
    // (default) there is NO fs/network containment: the inner server can still
    // reach any file or socket its OS credentials permit — the working-dir /
    // rlimit hardening above is not a sandbox. With --inner-sandbox enforce the
    // proxy REFUSES to start unless a kernel backend (Linux Landlock/seccomp) can
    // actually enforce containment; no such backend ships in this build yet, so
    // enforce currently fails closed on every platform (the inner server is never
    // spawned unsandboxed while having been asked to sandbox it). The gate fires
    // inside SubprocessInner / PersistentSubprocessInner construction below.
    {
        let s = &config.inner_launch.sandbox;
        if s.is_enforced() {
            eprintln!(
                "mcps-proxy: inner sandbox = ENFORCE requested (fs read-allow={:?}, \
                 fs write-allow={:?}, net={:?}); kernel enforcement backend is a follow-up and \
                 ships on no platform yet, so startup will FAIL CLOSED (see #3865).",
                s.fs_allow_read, s.fs_allow_write, s.network,
            );
        } else {
            eprintln!(
                "mcps-proxy: inner sandbox = off (NO fs/network containment; the inner server can \
                 still reach any file or socket its OS credentials permit — this is not a sandbox)"
            );
        }
    }

    // Build the proxy (PEP).
    let log_sink: Arc<dyn mcps_proxy::InnerLogSink + Send + Sync> =
        Arc::new(mcps_proxy::StderrLogSink);
    // Select the inner-server process model (MCPS-066). One-shot (default) spawns
    // the inner command per request; persistent spawns it ONCE, performs the MCP
    // initialize handshake, and forwards many requests over the same long-lived
    // process — the only way to front a genuinely long-lived MCP server.
    let inner: Box<dyn InnerServer> = match config.inner_mode {
        InnerModeKind::OneShot => Box::new(cli::SubprocessInner::with_log_sink(
            &config.inner_command,
            config.inner_launch.clone(),
            Arc::clone(&log_sink),
        )?),
        InnerModeKind::Persistent => {
            eprintln!(
                "mcps-proxy: inner process model = persistent (spawn-once + initialize handshake; \
                 long-lived inner serves many requests over one process)"
            );
            Box::new(PersistentSubprocessInner::with_log_sink(
                &config.inner_command,
                config.inner_launch.clone(),
                Arc::clone(&log_sink),
            )?)
        }
    };
    let mut proxy = Proxy::new(
        key_source,
        config.server_signer.clone(),
        config.server_key_id.clone(),
        resolver,
        config.audience.clone(),
        config.max_clock_skew,
        inner,
    )
    .with_expected_version_policy(config.expected_version_policy)
    .with_log_sink(Arc::clone(&log_sink));
    if config.replay == ReplayKind::File {
        let path = config
            .replay_path
            .clone()
            .ok_or("--replay-cache file requires --replay-path")?;
        let cache = DurableReplayCache::open(&path, config.max_clock_skew)
            .map_err(|e| format!("replay cache {path}: {e}"))?;
        proxy = proxy.with_replay_cache(Box::new(cache));
    }
    if config.replay == ReplayKind::Shared {
        // Issue #3837 / #69: shared, server-side-atomic cache for horizontally-
        // scaled replay safety. The DECLARED durability tier selects the backend
        // (ADR-MCPS-020): LINEARIZABLE → the CP / etcd store (issue #69),
        // every other tier → the Redis store (issue #4028). Either backend FAILS
        // CLOSED if its adapter feature is not compiled in this build, never
        // silently degrading to a non-shared / weaker cache.
        let tier = config
            .replay_durability_tier
            .as_ref()
            .ok_or("--replay-cache shared requires --replay-durability-tier")?;
        let cache = if matches!(tier, ReplayDurabilityTier::Linearizable) {
            // CP / LINEARIZABLE: etcd endpoint required (parse_args already
            // enforced its presence for this tier — fail closed otherwise).
            let endpoint = config
                .cpstore_etcd_endpoint
                .clone()
                .ok_or("--replay-durability-tier linearizable requires --cpstore-etcd-endpoint")?;
            let backend = if cfg!(feature = "cpstore_etcd") {
                "etcd"
            } else {
                "none"
            };
            eprintln!(
                "mcps-proxy: replay cache = shared (CP/linearizable; {backend} backend, issue #69)"
            );
            eprintln!("mcps-proxy: {}", tier.startup_audit_line(backend));
            cli::build_cpstore_replay_cache(
                &endpoint,
                config.max_clock_skew,
                config.limits.read_timeout,
                config.limits.write_timeout,
            )?
        } else {
            // Redis tiers (REDIS_ASYNC / REDIS_WAIT_QUORUM / SINGLE_STORE_FAIL_CLOSED).
            let url = config
                .replay_redis_url
                .clone()
                .ok_or("--replay-cache shared requires --replay-redis-url")?;
            let backend = if cfg!(feature = "redis_replay") {
                "redis"
            } else {
                "none"
            };
            eprintln!(
                "mcps-proxy: replay cache = shared (horizontally-scaled replay safety; \
                 Redis backend, issue #4028)"
            );
            eprintln!("mcps-proxy: {}", tier.startup_audit_line(backend));
            cli::build_shared_replay_cache(
                &url,
                config.max_clock_skew,
                config.limits.read_timeout,
                config.limits.write_timeout,
                tier,
            )?
        };
        proxy = proxy.with_replay_cache(cache);
    }
    // #78 (ADR-MCPS-020), OBJECT-LEVEL defense in depth beneath the CLI-flag gate:
    // the CLI's strict_violations rejects the `--replay-cache memory` SELECTION,
    // but the proxy's replay cache is a `Box<dyn ReplayCache>` that can also be
    // INJECTED (`with_replay_cache`). Assert the cache the proxy actually holds
    // self-declares a durable posture under strict/production, so a volatile
    // single-process reference cache can never reach a production verify path even
    // if it arrived by injection rather than the default selection. mcps-core's
    // `durability_class()` defaults (fail closed) to the single-process reference,
    // so an undeclared cache is rejected here too.
    if config.strict
        && proxy.replay_durability_class()
            == mcps_core::ReplayDurabilityClass::SingleProcessReference
    {
        return Err(
            "strict/production: the configured replay cache self-declares the volatile \
             single-process reference posture (admitted nonces are lost on restart and \
             invisible to peer verifiers); a durable replay store is required — use \
             --replay-cache file or --replay-cache shared, or inject a cache that declares \
             ReplayDurabilityClass::Durable"
                .into(),
        );
    }
    if config.authz == AuthzKind::Reference {
        let mut evaluator = PolicyEvaluator::new();
        evaluator.register(Box::new(ReferenceProfile::new()));
        // ADR-MCPS-013: surface the ACTIVE authorization profile and its non-production
        // posture at startup so an operator can never silently treat the reference
        // (conformance) profile as the production authority. Reaching here required the
        // explicit `--allow-reference-authz` acknowledgement (parse-time guard) and is
        // refused under --strict/--production.
        eprintln!(
            "mcps-proxy: authorization = ENABLED, active profile '{}' (ACKNOWLEDGED non-production \
             via --allow-reference-authz). The reference profile is a real, signature-verifying, \
             fully-bound profile but is a CONFORMANCE/reference implementation, NOT the long-term \
             recommendation (ADR-MCPS-013; Biscuit is the intended production profile). It is \
             refused under --strict/--production.",
            REFERENCE_PROFILE_ID,
        );
        // ADR-MCPS-013 policy-layer revocation. `parse_args` has already failed
        // closed unless a deny-list was supplied or --allow-empty-revocation was
        // EXPLICITLY given, so reaching here with an empty list is an acknowledged
        // posture — surfaced loudly at startup so it can never be a silent illusion.
        let revoked = cli::load_revocation_list(&config.revocation_list_paths)?;
        let revoked_count = revoked.len();
        let mut revocation = InMemoryRevocationSource::new();
        for id in revoked {
            revocation.revoke(id);
        }
        if revoked_count == 0 {
            eprintln!(
                "mcps-proxy: WARNING: policy revocation deny-list is EMPTY \
                 (--allow-empty-revocation) — no authorization grant can be revoked this run"
            );
        } else {
            eprintln!(
                "mcps-proxy: policy revocation enabled — {revoked_count} revoked grant id(s) \
                 loaded (OFFLINE static list; restart to update)"
            );
        }
        proxy = proxy.with_policy_enforcement(evaluator, Box::new(revocation));
    }
    if config.binding == BindingKind::Exact {
        proxy = proxy.with_transport_binding(Box::new(ExactMatchBinding::new()));
    }
    // ADR-MCPS-023 Tier 3 (issue #71): LB-signed, request-bound ingress assertion.
    // The verified transport identity comes from a cryptographically-verified
    // assertion bound to THIS request's hash (checked post-verification, inside the
    // proxy), then binds to the request signer through the SAME ExactMatchBinding
    // the direct-TLS path uses. `parse_args` already required at least one trusted
    // `--ingress-lb-key`. Honestly downgraded — NOT end_to_end_mtls.
    if config.binding == BindingKind::LbAssertion {
        let lb_assertion = cli::build_lb_assertion_binding(&config)?
            .ok_or("internal error: lb-assertion binding selected but no verifier built")?;
        eprintln!(
            "mcps-proxy: transport binding = LB-signed request-bound ingress assertion \
             ({} trusted LB key(s), guarantee '{}', identity field {:?}, header '{}'). This is \
             request-bound INGRESS assertion, NOT end-to-end client-node mTLS: the LB terminates \
             the client's mTLS and re-asserts identity; the node verifies the LB signature + the \
             request-hash binding, not the client's own key.",
            config.ingress_lb_keys.len(),
            mcps_proxy::LbAssertionBinding::GUARANTEE,
            config.identity_source,
            tls::MCP_INGRESS_ASSERTION_HEADER,
        );
        proxy = proxy
            .with_transport_binding(Box::new(ExactMatchBinding::new()))
            .with_lb_assertion(lb_assertion);
    }

    // Offline client-cert CRLs (#3839). Loaded once at startup; a missing or
    // malformed CRL file fails closed here. OFFLINE revocation only — there is no
    // online OCSP / distribution-point fetching (deferred to a follow-up).
    let client_crls = cli::load_client_crls(&config.client_crl_paths)?;
    if !client_crls.is_empty() {
        eprintln!(
            "mcps-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown status \
             {} (OFFLINE only; no online OCSP/CRL-DP fetching)",
            config.client_crl_paths.len(),
            if config.crl_allow_unknown_status { "ALLOWED (relaxed)" } else { "DENIED (fail closed)" },
        );
    } else if config.crl_allow_unknown_status {
        eprintln!(
            "mcps-proxy: WARNING: --crl-allow-unknown-status has no effect without --client-crl"
        );
    }

    // TLS server. ADR-MCPS-028 §G / issue #58: on the delegated path rustls drives
    // the handshake signature through the device/KMS signer (TLS private key never
    // exported); the validated builder fails closed at construction if the leaf cert
    // is not Ed25519 or its key does not match the signer. Otherwise the exported-key
    // path is used verbatim.
    let server_config = match tls_delegated_signer {
        Some(signer) => tls::build_server_config_delegated_validated(
            server_chain,
            signer,
            client_ca,
            client_crls,
            config.crl_allow_unknown_status,
        )
        .map_err(|e| e.to_string())?,
        None => {
            let server_key = server_key.ok_or_else(|| {
                "internal error: exported TLS key missing on the non-delegated path".to_string()
            })?;
            tls::RustlsDirectProvider::build_server_config_with_crls(
                server_chain,
                server_key,
                client_ca,
                client_crls,
                config.crl_allow_unknown_status,
            )
            .map_err(|e| e.to_string())?
        }
    };
    let server_config = Arc::new(server_config);
    // Select the identity strategy (MCPS-3840): direct mTLS (default) extracts the
    // identity from the verified peer certificate; reverse-proxy mode reads it from
    // the trusted forwarded header and ignores the local client cert. These are
    // mutually exclusive on a connection (enforced at parse time, honoured here).
    // ADR-MCPS-023 Tier 3 (issue #71): under `--transport-binding lb-assertion` the
    // identity is NOT resolved at the connection seam — it is carried by the signed,
    // request-bound assertion header and verified post-verification inside the proxy.
    // The serve loop therefore selects the LbAssertion strategy so it extracts the
    // assertion header (failing closed on a duplicate) instead of reading a local
    // client cert or a forwarded identity header. The three strategies are mutually
    // exclusive; the CLI forbids combining lb-assertion with a reverse-proxy header.
    let identity_strategy = if config.binding == BindingKind::LbAssertion {
        IdentityStrategy::LbAssertion
    } else {
        match &config.reverse_proxy_identity_header {
            None => IdentityStrategy::DirectTls,
            Some(header) => IdentityStrategy::ReverseProxyHeader(ReverseProxyMtlsProvider::new(
                header.clone(),
                config.reverse_proxy_header_format,
                config.identity_source,
            )),
        }
    };
    // #4030 ONLINE OCSP client-cert revocation. Built only under the
    // `online_ocsp` feature; `parse_args` already fails closed for
    // `--client-ocsp require` in a build without the feature.
    #[cfg(feature = "online_ocsp")]
    let ocsp_checker = cli::build_ocsp_checker(&config);
    #[cfg(feature = "online_ocsp")]
    if let Some(checker) = &ocsp_checker {
        eprintln!(
            "mcps-proxy: ONLINE OCSP client-cert revocation enabled (SHA-256 CertIDs; \
             responder URL {}; on indeterminate result: {}). The OCSP responder must answer \
             SHA-256 CertIDs.",
            config
                .ocsp_responder_url
                .as_deref()
                .map(|u| format!("override {u}"))
                .unwrap_or_else(|| "from each leaf's AIA".to_string()),
            if checker.soft_fail() { "ALLOW (soft-fail)" } else { "REJECT (hard-fail)" },
        );
    }
    let serve_options = ServerOptions {
        identity_policy: config.identity_source,
        identity_strategy,
        limits: config.limits.clone(),
        max_client_cert_lifetime: config.max_client_cert_lifetime,
        #[cfg(feature = "online_ocsp")]
        ocsp_checker,
    };
    let listener = std::net::TcpListener::bind(&config.bind)
        .map_err(|e| format!("bind {}: {e}", config.bind))?;
    // Report the OS-RESOLVED address, not the requested one: when `--bind` asks
    // for port 0 the kernel assigns an ephemeral port, and a caller (e.g. a test
    // harness) that lets the proxy pick the port avoids the bind-after-free-port
    // TOCTOU race. For a fixed `--bind` port this prints the same address.
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr after bind {}: {e}", config.bind))?;
    eprintln!("mcps-proxy: listening on {} (PEP; inner = {:?})", local_addr, config.inner_command);

    // Blocking single-threaded serve loop: the Proxy's replay cache is single-
    // threaded interior state, so connections are handled one at a time.
    loop {
        let config_arc = Arc::clone(&server_config);
        if let Err(e) = tls::serve_once_with_assertion(
            &listener,
            config_arc,
            &serve_options,
            |request, identity, assertion| {
                proxy.handle_with_transport(request, now_unix(), identity.as_ref(), assertion)
            },
        ) {
            // A single rejected/aborted connection (e.g. failed mTLS) must not
            // bring the server down — log and keep serving.
            eprintln!("mcps-proxy: connection error: {e}");
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mcps-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
