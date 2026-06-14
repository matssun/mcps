//! MCPS-035 / MCPS-036 (ADR-MCPS-016) — inner-server launch hardening.
//!
//! [`InnerLaunchConfig`] is the single place that decides what the inner MCP
//! server subprocess *sees* when it is launched: its environment (MCPS-035), its
//! working directory, and how its stdout/stderr are handled (MCPS-036). The
//! present default behavior of `std::process::Command` is to inherit the proxy's
//! ENTIRE environment and run in the proxy's OWN working directory; both leak
//! proxy-side state into the unmodified inner server. This config closes those
//! leaks.
//!
//! ADR-MCPS-016 scope: this is portable, parent-process launch hardening — the
//! proxy controls what the child SEES (env, cwd, output handling) and, via
//! `setrlimit` (#3857), how much coarse resource it may consume. By itself this
//! does NOT contain what the child can DO to the filesystem or network: an
//! explicit working directory is a controlled *starting* directory, not a
//! sandbox — the inner server can still `chdir` elsewhere and open any path its
//! OS credentials permit. A configured behavior is never silently dropped: a
//! setting that cannot be applied is a loud, fail-closed error.
//!
//! fs/network containment (#3865 + #4039): the [`SandboxProfile`] field below is
//! the seam for REAL kernel-mediated fs/network containment, with a FAIL-CLOSED
//! platform gate. On a capable Linux kernel, requesting
//! [`crate::sandbox::SandboxMode::Enforce`] installs a Landlock fs ruleset +
//! seccomp-bpf egress filter on the inner-server child before `exec` (implemented
//! in [`crate::sandbox_linux`], #4039). On a Linux kernel too old to enforce, or on
//! any non-Linux platform, [`SandboxProfile::backend_can_enforce`] is `false` and
//! `Enforce` refuses to start (fail closed). With the default
//! [`crate::sandbox::SandboxMode::Off`] the profile is inert and the
//! "no containment / starting-dir-not-a-sandbox" disclaimers above still hold
//! exactly. See [`InnerLaunchConfig::apply_sandbox`] for the pre-`exec` seam.

use std::process::Command;
use std::time::Duration;

use crate::rlimits::RLimits;
use crate::sandbox::SandboxProfile;

/// A structured inner-server lifecycle / hygiene event (MCPS-036).
///
/// The proxy emits these to its OWN diagnostic channel (never onto the inner
/// server's stdout protocol stream and never as MCP content). Each event is
/// tagged with the inner process / session identity so emissions from concurrent
/// or successive inner launches stay attributable. Captured stderr is BOUNDED
/// and structured, not safe-from-secrets: an inner server can write a secret to
/// its own stderr, so the capture is bounded blast-radius, not redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerLogEvent {
    /// The inner subprocess was spawned successfully (`pid` of the child).
    Spawned { pid: u32 },
    /// Spawning the inner subprocess failed (reason names no secret value).
    SpawnFailed { reason: String },
    /// The inner subprocess exited; `code` is the OS exit status code if known.
    Exited { code: Option<i32> },
    /// The proxy actively killed the inner subprocess.
    Killed { reason: String },
    /// Captured inner stderr hit the configured byte/line bound and was
    /// truncated; the dropped tail is NOT retained.
    StderrTruncated { captured_bytes: usize, cap_bytes: usize },
    /// The inner server's stdout could not be parsed as a JSON-RPC frame the
    /// proxy expects (the protocol stream was dirty).
    ProtocolError { detail: String },
    /// A verified request was forwarded to the inner server.
    RequestForwarded,
    /// A signed response was produced for the caller from an inner result.
    ResponseSigned,
}

impl InnerLogEvent {
    /// The stable event tag (the `inner_*` names from the issue / brief §13).
    pub fn tag(&self) -> &'static str {
        match self {
            InnerLogEvent::Spawned { .. } => "inner_spawned",
            InnerLogEvent::SpawnFailed { .. } => "inner_spawn_failed",
            InnerLogEvent::Exited { .. } => "inner_exited",
            InnerLogEvent::Killed { .. } => "inner_killed",
            InnerLogEvent::StderrTruncated { .. } => "inner_stderr_truncated",
            InnerLogEvent::ProtocolError { .. } => "inner_protocol_error",
            InnerLogEvent::RequestForwarded => "inner_request_forwarded",
            InnerLogEvent::ResponseSigned => "inner_response_signed",
        }
    }
}

/// A sink for [`InnerLogEvent`]s, tagged with the inner identity.
///
/// Injected so the lifecycle emissions are deterministically testable without
/// scraping the proxy's real stderr. The proxy's production sink writes a single
/// structured line per event to the proxy's OWN stderr (see
/// [`StderrLogSink`]) — this is the proxy's diagnostic channel, entirely
/// separate from the inner server's stdout protocol stream.
pub trait InnerLogSink {
    /// Record one lifecycle event for the inner identified by `inner_identity`.
    fn log(&self, inner_identity: &str, event: &InnerLogEvent);

    /// Record the BOUNDED captured stderr of one inner invocation. This is the
    /// destination for the inner server's stderr — it goes ONLY here (the proxy's
    /// structured log), never onto stdout (the protocol stream) and never into
    /// MCP content. The default writes one line to the proxy's stderr. Bounded is
    /// not secrets-safe: an inner server may write a secret here.
    fn log_stderr(&self, inner_identity: &str, captured: &[u8]) {
        eprintln!(
            "mcps-proxy: inner-stderr inner={inner_identity} {:?}",
            String::from_utf8_lossy(captured)
        );
    }
}

/// The production sink: one structured line per event on the PROXY's stderr.
///
/// This is the proxy's own diagnostic channel. It is intentionally distinct from
/// the inner server's stdout (the MCP protocol stream) and from the inner
/// server's captured stderr (the bounded log), so a lifecycle event can never be
/// mistaken for MCP content.
#[derive(Debug, Clone, Default)]
pub struct StderrLogSink;

impl InnerLogSink for StderrLogSink {
    fn log(&self, inner_identity: &str, event: &InnerLogEvent) {
        eprintln!("mcps-proxy: inner-event {} inner={inner_identity} {:?}", event.tag(), event);
    }
}

/// A bounded, structured capture of an inner server's stderr.
///
/// stderr is captured SEPARATELY from stdout (which carries only the MCP
/// protocol stream) and is NEVER forwarded as MCP content. The capture is
/// bounded on BOTH bytes and lines so a noisy or hostile inner server cannot
/// exhaust proxy memory: writes past either cap are dropped and the capture is
/// marked truncated (the proxy emits [`InnerLogEvent::StderrTruncated`]). A
/// bounded log is not a secrets-safe log — an inner server may write a secret to
/// its own stderr; the bound limits blast radius, it does not redact.
#[derive(Debug, Clone)]
pub struct BoundedStderr {
    cap_bytes: usize,
    cap_lines: usize,
    bytes: Vec<u8>,
    lines: usize,
    truncated: bool,
}

impl BoundedStderr {
    /// A capture bounded to at most `cap_bytes` bytes and `cap_lines` lines.
    /// Both must be > 0 (a zero bound is a misconfiguration, not "capture
    /// nothing"); callers parsing CLI flags reject 0 explicitly.
    pub fn new(cap_bytes: usize, cap_lines: usize) -> Self {
        BoundedStderr {
            cap_bytes,
            cap_lines,
            bytes: Vec::new(),
            lines: 0,
            truncated: false,
        }
    }

    /// Append a chunk of inner stderr, respecting both bounds. Once either cap is
    /// reached the capture is marked truncated and further bytes are dropped.
    pub fn push(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if self.bytes.len() >= self.cap_bytes || self.lines >= self.cap_lines {
                self.truncated = true;
                return;
            }
            self.bytes.push(byte);
            if byte == b'\n' {
                self.lines += 1;
                if self.lines >= self.cap_lines {
                    self.truncated = true;
                    return;
                }
            }
        }
    }

    /// Whether the capture hit a bound and dropped trailing stderr.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The captured bytes (at most `cap_bytes`).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The captured stderr as a lossy UTF-8 string (for structured logging).
    pub fn as_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The configured byte cap (for the truncation event).
    pub fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }
}

/// Default stderr capture bound: 64 KiB, 1024 lines. Generous enough for real
/// inner-server diagnostics, small enough that a hostile inner server cannot
/// exhaust proxy memory.
pub const DEFAULT_STDERR_CAP_BYTES: usize = 64 * 1024;
pub const DEFAULT_STDERR_CAP_LINES: usize = 1024;

/// Default per-read timeout on the persistent-inner stdout pipe (MCPS-074, audit
/// §3 H-3). Mirrors the [`crate::tls::ServerLimits`] socket `read_timeout`
/// default of 30s. The timeout is ALWAYS bounded — there is NO disable: a
/// hung/silent/unterminated-line inner can never block the single-threaded serve
/// loop forever (the module's "never hang" P179 claim).
pub const DEFAULT_INNER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How the inner subprocess's launch is constructed.
///
/// The proxy always builds a child environment from a clean slate plus an
/// explicit allowlist (MCPS-035); launches it in a CONTROLLED working directory
/// rather than silently inheriting the proxy's cwd (MCPS-036); and captures its
/// stderr into a bounded structured log while keeping its stdout reserved for the
/// MCP protocol stream (MCPS-036). This is the extensible inner-launch policy,
/// with room for the Unix `setrlimit` slice (#3857) to be added as a further
/// field without disturbing the contracts here.
#[derive(Debug, Clone)]
pub struct InnerLaunchConfig {
    /// Inherit the proxy's entire environment instead of clearing it. `false`
    /// (the secure default) means the child starts from an empty environment and
    /// receives ONLY the explicit pairs and allowlisted pass-throughs below.
    /// `true` re-opens the full-inheritance leak and MUST be accompanied by a
    /// strong operator warning.
    pub inherit_env: bool,
    /// Explicit `KEY=VALUE` pairs to set in the child environment, regardless of
    /// the proxy's own environment (`--inner-env KEY=VALUE`).
    pub explicit_env: Vec<(String, String)>,
    /// Names of variables to pass through from the proxy's OWN environment by
    /// name (`--inner-env-allow KEY`). A name that is not present in the proxy's
    /// environment is a fail-closed error — never silently dropped.
    pub allow_env_names: Vec<String>,
    /// The explicit working directory the inner server is launched in
    /// (`--inner-working-dir`). `None` selects the CONTROLLED default
    /// ([`InnerLaunchConfig::default_working_dir`]) rather than silently
    /// inheriting the proxy's cwd. This is NOT a filesystem sandbox — see the
    /// module docs.
    pub working_dir: Option<String>,
    /// Byte cap for the bounded inner-stderr capture (MCPS-036).
    pub stderr_cap_bytes: usize,
    /// Line cap for the bounded inner-stderr capture (MCPS-036).
    pub stderr_cap_lines: usize,
    /// Unix `setrlimit` resource ceilings applied to the inner subprocess before
    /// `exec` (MCPS-037). This is **resource hardening, NOT sandboxing** — it
    /// bounds resource abuse (fds, CPU, memory, core/file size), not access. A
    /// configured limit is never silently dropped: see [`RLimits`].
    pub rlimits: RLimits,
    /// Per-read timeout on the persistent-inner stdout pipe (MCPS-074, audit §3
    /// H-3). Every read of an inner response line is bounded by this deadline so a
    /// hung/silent inner — or one that emits an unterminated line then goes quiet
    /// — can never block the single-threaded serve loop forever. This is a plain
    /// `Duration`, NOT an `Option`: the timeout is ALWAYS bounded, there is NO
    /// disable (CLI `--inner-read-timeout-secs` rejects 0). Defaults to
    /// [`DEFAULT_INNER_READ_TIMEOUT`] (30s), mirroring the socket read timeout.
    pub inner_read_timeout: Duration,
    /// OS sandbox profile for inner-server fs/network containment (#3865 +
    /// #4039). With the default [`crate::sandbox::SandboxMode::Off`] it is inert
    /// (no containment, existing disclaimers apply). Under
    /// [`crate::sandbox::SandboxMode::Enforce`], on a capable Linux kernel the
    /// Landlock fs ruleset + seccomp-bpf egress filter are installed on the inner
    /// child before `exec` ([`crate::sandbox_linux`]); on a too-old kernel or any
    /// non-Linux platform it fails closed at startup. See [`SandboxProfile`] and
    /// [`InnerLaunchConfig::apply_sandbox`].
    pub sandbox: SandboxProfile,
}

impl Default for InnerLaunchConfig {
    /// The secure default config (see [`InnerLaunchConfig::new`]).
    fn default() -> Self {
        InnerLaunchConfig::new()
    }
}

impl InnerLaunchConfig {
    /// A secure-default config: no env inheritance, no explicit pairs, no
    /// pass-throughs (empty child environment), the controlled default working
    /// directory, and the default bounded-stderr caps.
    pub fn new() -> Self {
        InnerLaunchConfig {
            inherit_env: false,
            explicit_env: Vec::new(),
            allow_env_names: Vec::new(),
            working_dir: None,
            stderr_cap_bytes: DEFAULT_STDERR_CAP_BYTES,
            stderr_cap_lines: DEFAULT_STDERR_CAP_LINES,
            rlimits: RLimits::new(),
            inner_read_timeout: DEFAULT_INNER_READ_TIMEOUT,
            sandbox: SandboxProfile::new(),
        }
    }

    /// The CONTROLLED default working directory used when `working_dir` is unset:
    /// a PRIVATE per-proxy subdirectory of the system temp dir, NOT the proxy's own
    /// current directory and NOT the world-writable temp dir itself (issue #25).
    ///
    /// Two deliberate properties: (1) it is not the proxy's cwd — silently
    /// inheriting that would expose whatever the operator launched from (config,
    /// keys, source tree); (2) it is not bare `$TMPDIR`, which is world-writable.
    /// This returns the intended PATH only; [`InnerLaunchConfig::apply_working_dir`]
    /// creates it `0700` and validates ownership/permissions before use.
    pub fn default_working_dir() -> String {
        std::env::temp_dir()
            .join(format!("mcps-inner-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    /// Create (or validate) the private default inner working directory, returning
    /// its path or a fail-closed error (issue #25). Unlike bare `$TMPDIR`
    /// (world-writable), this is a per-proxy `0700` directory owned by the proxy,
    /// so the inner server's default cwd is never a world-writable starting point.
    ///
    /// A pre-existing path at this name is accepted ONLY if it is a real directory
    /// (not a symlink), owned by the current uid, with no group/other access — so a
    /// predictable-name squat (an attacker-planted symlink or loose-perms dir)
    /// fails closed rather than being adopted as the inner's cwd.
    #[cfg(unix)]
    fn ensure_private_default_working_dir() -> Result<String, String> {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::MetadataExt;

        let path = std::env::temp_dir().join(format!("mcps-inner-{}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            // Freshly created: 0700 and owned by us by construction.
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Validate the pre-existing path WITHOUT following symlinks.
                let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                    format!("inner working dir {}: cannot stat ({e})", path.display())
                })?;
                if !meta.file_type().is_dir() {
                    return Err(format!(
                        "inner working dir {}: exists but is not a directory \
                         (symlink/file squat?) — refusing",
                        path.display()
                    ));
                }
                // SAFETY: `getuid` reads the caller's real uid; it has no
                // preconditions and cannot fail or cause UB.
                let our_uid = unsafe { libc::getuid() };
                if meta.uid() != our_uid {
                    return Err(format!(
                        "inner working dir {}: not owned by this process — refusing",
                        path.display()
                    ));
                }
                if meta.mode() & 0o077 != 0 {
                    return Err(format!(
                        "inner working dir {}: permissions are not private (0700 required) — refusing",
                        path.display()
                    ));
                }
            }
            Err(e) => {
                return Err(format!(
                    "inner working dir {}: cannot create ({e})",
                    path.display()
                ));
            }
        }
        Ok(path.to_string_lossy().into_owned())
    }

    /// Non-Unix fallback: create the private default working dir best-effort
    /// (per-platform permission models differ; the Unix path enforces `0700`).
    #[cfg(not(unix))]
    fn ensure_private_default_working_dir() -> Result<String, String> {
        let path = std::env::temp_dir().join(format!("mcps-inner-{}", std::process::id()));
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("inner working dir {}: cannot create ({e})", path.display()))?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// The effective working directory: the explicit one if set, else the
    /// controlled default.
    pub fn effective_working_dir(&self) -> String {
        self.working_dir
            .clone()
            .unwrap_or_else(InnerLaunchConfig::default_working_dir)
    }

    /// Resolve the allowlisted pass-through names against the supplied
    /// environment view (`getter`, normally `std::env::var`), returning the
    /// concrete `KEY=VALUE` pairs the child should receive from inheritance.
    ///
    /// Fails closed (`Err`) if any requested name is absent: a configured
    /// pass-through that cannot be satisfied is an error, not a silent drop.
    /// The error names ONLY the missing variable name (never any value), so it
    /// is safe to log.
    fn resolve_allowlist<F>(&self, getter: F) -> Result<Vec<(String, String)>, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut resolved = Vec::with_capacity(self.allow_env_names.len());
        for name in &self.allow_env_names {
            match getter(name) {
                Some(value) => resolved.push((name.clone(), value)),
                None => {
                    return Err(format!(
                        "--inner-env-allow {name}: variable not present in the proxy's \
                         environment (a configured pass-through must be satisfiable; \
                         set the variable or drop the flag)"
                    ))
                }
            }
        }
        Ok(resolved)
    }

    /// Apply the environment policy to a child `Command`, reading the proxy's
    /// own environment through `getter` for allowlisted pass-throughs.
    ///
    /// Order of operations (fail-closed, no silent drops):
    ///   1. unless `inherit_env`, CLEAR the inherited environment;
    ///   2. apply allowlisted pass-throughs resolved from the proxy's env
    ///      (erroring if any requested name is absent);
    ///   3. apply explicit `KEY=VALUE` pairs (these win over pass-throughs).
    ///
    /// `getter` is injected so this is deterministically testable without
    /// touching the real process environment.
    pub fn apply_env<F>(&self, command: &mut Command, getter: F) -> Result<(), String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let pass_through = self.resolve_allowlist(&getter)?;

        if !self.inherit_env {
            command.env_clear();
        }
        for (key, value) in &pass_through {
            command.env(key, value);
        }
        for (key, value) in &self.explicit_env {
            command.env(key, value);
        }
        Ok(())
    }

    /// Apply the working-directory policy to a child `Command`: always set an
    /// EXPLICIT current directory, so the inner server never silently inherits the
    /// proxy's cwd.
    ///
    /// * An EXPLICITLY configured `working_dir` must already exist as a directory —
    ///   it is validated and used as-is, never created here (fails closed if it
    ///   cannot be honored, rather than silently falling back to the proxy's cwd).
    /// * With NO configured `working_dir`, the private per-proxy default is created
    ///   `0700` and ownership/permission-validated (issue #25) — never the
    ///   world-writable bare temp dir.
    pub fn apply_working_dir(&self, command: &mut Command) -> Result<(), String> {
        let dir = match &self.working_dir {
            Some(explicit) => {
                let meta = std::fs::metadata(explicit)
                    .map_err(|e| format!("--inner-working-dir {explicit}: cannot stat ({e})"))?;
                if !meta.is_dir() {
                    return Err(format!("--inner-working-dir {explicit}: not a directory"));
                }
                explicit.clone()
            }
            None => Self::ensure_private_default_working_dir()?,
        };
        command.current_dir(&dir);
        Ok(())
    }

    /// A fresh bounded-stderr capture sized to this config's caps.
    pub fn new_stderr_capture(&self) -> BoundedStderr {
        BoundedStderr::new(self.stderr_cap_bytes, self.stderr_cap_lines)
    }

    /// Apply the Unix `setrlimit` resource ceilings (MCPS-037) to a child
    /// `Command`, fail-closed.
    ///
    /// Two-stage, mirroring the env/working-dir validation: first a startup
    /// platform check ([`RLimits::validate_platform`]) so a configured limit on a
    /// non-Unix platform is refused up front (strict mode) rather than silently
    /// dropped; then the per-limit `setrlimit` calls are installed as a
    /// `pre_exec` hook that runs in the forked child before `exec`. A `setrlimit`
    /// the kernel refuses makes the parent's `spawn` fail (strict mode), so the
    /// inner server is never `exec`'d without its required ceilings.
    ///
    /// This is resource hardening, NOT sandboxing — it bounds resource abuse, not
    /// access. See [`RLimits`].
    pub fn apply_rlimits(&self, command: &mut Command) -> Result<(), String> {
        self.rlimits.validate_platform()?;
        self.rlimits.apply_to_command(command);
        Ok(())
    }

    /// Apply the OS sandbox profile (#3865 + #4039) to a child `Command` — the
    /// seam for REAL kernel-mediated fs/network containment of the inner server.
    ///
    /// Structured exactly like [`InnerLaunchConfig::apply_rlimits`]: a startup
    /// platform/capability check ([`SandboxProfile::validate_platform`]) that
    /// fails CLOSED first, then the platform-specific enforcement install. With
    /// the default [`crate::sandbox::SandboxMode::Off`] the gate is a no-op and
    /// nothing is installed (behavior unchanged). Under
    /// [`crate::sandbox::SandboxMode::Enforce`] the gate REFUSES to start unless a
    /// kernel backend can actually enforce containment; on a capable Linux kernel
    /// it passes and the Linux install arm below installs the Landlock + seccomp
    /// `pre_exec` hook.
    ///
    /// The Linux enforcement is `#[cfg(target_os = "linux")]` ([`install_sandbox_backend`]):
    /// it installs the Landlock fs ruleset + seccomp-bpf egress filter as a
    /// `pre_exec` hook here. The non-Linux arm is a defense-in-depth backstop that
    /// errors (the gate already refuses Enforce there).
    ///
    /// [`install_sandbox_backend`]: InnerLaunchConfig::install_sandbox_backend
    pub fn apply_sandbox(&self, command: &mut Command) -> Result<(), String> {
        // Fail-closed platform/capability gate (the load-bearing honesty
        // property): if `Enforce` is requested but containment cannot be enforced
        // here, refuse BEFORE any spawn. On darwin this always fires for
        // `Enforce`; on a too-old Linux kernel too. `Off` passes through inertly.
        self.sandbox.validate_platform()?;
        if !self.sandbox.is_enforced() {
            // Off (default): no containment is installed — existing behavior.
            return Ok(());
        }
        self.install_sandbox_backend(command)
    }

    /// Close every inherited file descriptor ABOVE stdio (fd >= 3) in the child
    /// before `exec`, as a `pre_exec` hook (M15, audit 0.2 / #4080).
    ///
    /// # Why this is required (not merely belt-and-suspenders)
    ///
    /// The inner-server containment story (the [`crate::sandbox`] seccomp egress
    /// filter) denies the inner the ability to CREATE new sockets. But seccomp
    /// filters SYSCALLS, not existing kernel objects: a connected socket the inner
    /// INHERITS across `exec` is already open, so denying `socket`/`connect` does
    /// nothing to revoke it — the inner could read/write the proxy's own client or
    /// listener sockets. Rust's `std` sets `O_CLOEXEC` on the sockets IT creates,
    /// but that is not a guarantee for the whole process: a descriptor opened by a
    /// C library, by `libc::dup`/`fcntl` (which do NOT set close-on-exec), or
    /// inherited from the proxy's own parent can lack `O_CLOEXEC` and would survive
    /// `exec` into the inner. This hook is the authoritative close: regardless of
    /// each fd's `O_CLOEXEC` flag, every descriptor at or above fd 3 is closed in
    /// the forked child just before `exec`, so the inner inherits ONLY its own
    /// stdin/stdout/stderr pipes (fds 0/1/2, which `Command` sets up).
    ///
    /// # Async-signal-safety
    ///
    /// The hook runs post-`fork`/pre-`exec`, where only async-signal-safe
    /// operations are permitted. It issues ONLY `close(2)` syscalls over a numeric
    /// fd range (no allocation, no locks, no Rust runtime) — `close` is on the
    /// POSIX async-signal-safe list. An `EBADF` from closing an unopened fd is
    /// expected and ignored; any other error is surfaced as an `io::Error` so the
    /// `spawn()` fails closed rather than `exec`ing with descriptors still open.
    ///
    /// Ordering: registered LAST in the pre-`exec` chain (after `setrlimit` and the
    /// sandbox enforce hook) so it does not close any fd those hooks needed.
    /// Always applied (no config flag): leaking the proxy's sockets into the inner
    /// is never desirable.
    pub fn apply_close_extra_fds(&self, command: &mut Command) -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure performs ONLY async-signal-safe `close(2)` syscalls
        // over a fixed numeric fd range; it allocates nothing, takes no locks, and
        // touches no Rust runtime state. It is the last pre_exec hook so it never
        // closes an fd an earlier hook (setrlimit/sandbox) still needed.
        unsafe {
            command.pre_exec(close_fds_above_stdio);
        }
        Ok(())
    }

    /// Linux kernel-enforcement install point for the sandbox profile (#4039).
    /// Reached ONLY after [`SandboxProfile::validate_platform`] has confirmed
    /// enforcement is possible — which requires
    /// [`SandboxProfile::backend_can_enforce`] to return `true` (a runtime
    /// Landlock-ABI probe). It builds the Landlock ruleset and seccomp egress
    /// filter in the PARENT (opening allowlist paths, creating the ruleset fd,
    /// compiling the BPF), then registers an async-signal-safe `pre_exec` hook on
    /// the `Command` that issues only the enforce syscalls in the forked child.
    ///
    /// Ordering: this runs AFTER [`InnerLaunchConfig::apply_rlimits`] in the
    /// pre-`exec` chain, so the `setrlimit` hook is installed first and the sandbox
    /// enforce hook second (Rust runs `pre_exec` hooks in registration order). The
    /// enforce hook sets `PR_SET_NO_NEW_PRIVS`, then Landlock `restrict_self`, then
    /// the seccomp filter.
    ///
    /// Fail-closed: any parent-side build failure is returned here as `Err` (no
    /// spawn). Any child-side enforce failure returns an `io::Error` from
    /// `pre_exec`, which makes `spawn()` fail — so the inner server is never
    /// `exec`'d unsandboxed.
    #[cfg(target_os = "linux")]
    fn install_sandbox_backend(&self, command: &mut Command) -> Result<(), String> {
        use std::os::unix::process::CommandExt;

        // Build everything in the PARENT (allocations, path opens, BPF compile).
        let mut artifacts = crate::sandbox_linux::build_sandbox(&self.sandbox)?;
        // Register the enforce closure to run post-fork/pre-exec. It performs ONLY
        // the async-signal-safe enforce syscalls on the already-built artifacts:
        // no path resolution, no ruleset construction, no filter compilation.
        // SAFETY: the closure touches only state moved into it by value and issues
        // prctl / landlock_restrict_self / seccomp syscalls (see
        // `SandboxArtifacts::enforce`).
        unsafe {
            command.pre_exec(move || artifacts.enforce());
        }
        Ok(())
    }

    /// Non-Linux sandbox install point (#3865 / #4039): there is no
    /// kernel-enforcement backend on these platforms (Landlock/seccomp are
    /// Linux-only, and [`crate::sandbox_linux`] does not exist here). This is
    /// unreachable in practice because [`SandboxProfile::validate_platform`]
    /// already fails closed for `Enforce` here; it returns the same fail-closed
    /// error as a defense-in-depth backstop so the inner server is never spawned
    /// unsandboxed under `Enforce`.
    #[cfg(not(target_os = "linux"))]
    fn install_sandbox_backend(&self, _command: &mut Command) -> Result<(), String> {
        Err(
            "sandbox mode 'enforce' requested but this non-Linux platform cannot enforce kernel \
             containment (Landlock/seccomp are Linux-only); refusing to start the inner server \
             unsandboxed — see #3865 / #4039"
                .to_string(),
        )
    }
}

/// The pre-`exec` hook body that closes every inherited descriptor at or above
/// fd 3 in the forked child (M15, #4080). Separated out as a plain `fn` so the
/// `pre_exec` closure is a single function pointer with no captured state.
///
/// Primary mechanism (issue #25): the Linux `close_range(2)` syscall closes EVERY
/// descriptor from fd 3 up in one call, regardless of `RLIMIT_NOFILE`. This is
/// robust against a lowered soft limit (the `setrlimit` hook runs first in the
/// chain) and against descriptors above any numeric cap — both of which the old
/// `getrlimit`-bounded loop could miss. We invoke it via `syscall(2)` rather than
/// the glibc `close_range` wrapper to avoid a glibc-version symbol dependency; the
/// kernel returns `ENOSYS` on <5.9, in which case we fall back to the bounded
/// loop. Any OTHER `close_range` error means descriptors may still be open, so the
/// spawn FAILS (the inner is never `exec`'d leaking fds).
///
/// Async-signal-safe: only `syscall`/`getrlimit`/`close(2)` — no allocation,
/// locks, or Rust runtime. Returns `io::Result<()>` as `pre_exec` requires.
fn close_fds_above_stdio() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `SYS_close_range` is a single syscall taking three integer
        // arguments; it reads no userspace memory and touches no Rust state, so it
        // is async-signal-safe and valid in the post-fork/pre-exec child. Closing
        // the full [3, u32::MAX] range is exactly the documented "close everything
        // past stderr" idiom.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // ENOSYS (kernel < 5.9): close_range is unavailable — fall through to the
        // bounded loop. Any other error means fds may still be open: fail closed.
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }
    }
    close_fds_above_stdio_loop()
}

/// Bounded `close(2)` loop fallback for [`close_fds_above_stdio`] — used on Linux
/// kernels without `close_range` (<5.9) and on non-Linux platforms.
///
/// Upper bound: the process's HARD `RLIMIT_NOFILE` (`rlim_max`), NOT the soft
/// limit — the `setrlimit` hook lowers the SOFT limit earlier in the pre-`exec`
/// chain, and bounding on the lowered soft value could skip a higher-numbered
/// inherited descriptor (issue #25). The hard limit is clamped to `HARD_CAP_FD` so
/// a pathological "infinity" hard limit cannot make the loop run unreasonably long;
/// this residual cap is the justified bound for the fallback path only (the
/// primary `close_range` path has no such cap). `EBADF` (an unopened fd in the
/// range) is expected and ignored; any other error fails the spawn.
fn close_fds_above_stdio_loop() -> std::io::Result<()> {
    const FALLBACK_MAX_FD: libc::c_int = 1024;
    const HARD_CAP_FD: libc::c_int = 65_536;

    // SAFETY: `getrlimit` writes a single `rlimit` struct we provide; reading the
    // hard limit has no other effect.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let max_fd: libc::c_int = unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_max > 0 {
            // Use the HARD limit (rlim_max): the soft limit may have been lowered
            // by the setrlimit hook, so bounding on it could skip a high inherited
            // fd. Clamp so an "infinity" hard limit cannot run the loop forever.
            limit.rlim_max.min(HARD_CAP_FD as u64) as libc::c_int
        } else {
            FALLBACK_MAX_FD
        }
    };

    // Close fd 3..=max_fd. fds 0/1/2 (the inner's stdio pipes) are preserved.
    let mut fd: libc::c_int = 3;
    while fd <= max_fd {
        // SAFETY: `close` on a single integer fd; closing an unopened fd returns
        // EBADF, which we ignore. No other state is touched.
        let rc = unsafe { libc::close(fd) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // EBADF: this fd was not open — expected for the gaps in the range.
            // EINTR: retry the same fd. Anything else is a real failure → fail
            // closed (the spawn aborts) rather than exec with an fd still open.
            match err.raw_os_error() {
                Some(code) if code == libc::EBADF => {}
                Some(code) if code == libc::EINTR => continue,
                _ => return Err(err),
            }
        }
        fd += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::BoundedStderr;
    use super::InnerLaunchConfig;
    use super::InnerLogEvent;
    use super::DEFAULT_STDERR_CAP_BYTES;
    use super::DEFAULT_STDERR_CAP_LINES;
    use std::collections::HashMap;

    fn env_view(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn default_is_no_inheritance_empty_allowlist() {
        let config = InnerLaunchConfig::new();
        assert!(!config.inherit_env);
        assert!(config.explicit_env.is_empty());
        assert!(config.allow_env_names.is_empty());
    }

    #[test]
    fn default_working_dir_is_not_the_proxy_cwd() {
        // MCPS-036: the controlled default must NOT be the proxy's own cwd.
        let config = InnerLaunchConfig::new();
        assert!(config.working_dir.is_none());
        let effective = config.effective_working_dir();
        let proxy_cwd = std::env::current_dir().expect("cwd").to_string_lossy().into_owned();
        assert_ne!(
            effective, proxy_cwd,
            "the controlled default working dir must not silently be the proxy's cwd"
        );
        assert_eq!(effective, InnerLaunchConfig::default_working_dir());
    }

    #[test]
    fn explicit_working_dir_is_used_when_set() {
        let config = InnerLaunchConfig {
            working_dir: Some("/some/explicit/dir".to_string()),
            ..InnerLaunchConfig::new()
        };
        assert_eq!(config.effective_working_dir(), "/some/explicit/dir");
    }

    #[test]
    fn apply_working_dir_fails_closed_on_missing_dir() {
        let config = InnerLaunchConfig {
            working_dir: Some("/definitely/not/a/real/dir/MCPS036".to_string()),
            ..InnerLaunchConfig::new()
        };
        let mut command = std::process::Command::new("/bin/true");
        let err = config
            .apply_working_dir(&mut command)
            .expect_err("a configured working dir that cannot be honored must fail closed");
        assert!(err.contains("MCPS036"), "got: {err}");
    }

    /// Issue #25: with NO configured working dir, `apply_working_dir` must create
    /// the private default as a `0700` directory (not the world-writable bare temp
    /// dir), so the inner server's default cwd is non-world-writable.
    #[cfg(unix)]
    #[test]
    fn default_working_dir_is_created_private_0700() {
        use std::os::unix::fs::PermissionsExt;
        let config = InnerLaunchConfig::new(); // working_dir is None
        let mut command = std::process::Command::new("/bin/true");
        config
            .apply_working_dir(&mut command)
            .expect("default working dir must be created and applied");

        let dir = InnerLaunchConfig::default_working_dir();
        let meta = std::fs::metadata(&dir).expect("default working dir exists after apply");
        assert!(meta.is_dir(), "default working dir must be a directory");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "default inner working dir must be private 0700, not world-writable"
        );
        // It is also NOT the bare (world-writable) temp dir itself.
        assert_ne!(
            dir,
            std::env::temp_dir().to_string_lossy(),
            "default must be a private subdir, not bare $TMPDIR"
        );
    }

    #[test]
    fn default_stderr_caps_are_set() {
        let config = InnerLaunchConfig::new();
        assert_eq!(config.stderr_cap_bytes, DEFAULT_STDERR_CAP_BYTES);
        assert_eq!(config.stderr_cap_lines, DEFAULT_STDERR_CAP_LINES);
    }

    #[test]
    fn bounded_stderr_respects_byte_cap_and_marks_truncated() {
        let mut cap = BoundedStderr::new(4, 100);
        cap.push(b"abcdef");
        assert_eq!(cap.bytes(), b"abcd");
        assert!(cap.truncated(), "exceeding the byte cap must mark truncated");
    }

    #[test]
    fn bounded_stderr_respects_line_cap_and_marks_truncated() {
        let mut cap = BoundedStderr::new(1000, 2);
        cap.push(b"line1\nline2\nline3\n");
        assert!(cap.truncated(), "exceeding the line cap must mark truncated");
        // At most 2 newlines retained.
        assert!(cap.as_lossy().matches('\n').count() <= 2);
    }

    #[test]
    fn bounded_stderr_under_cap_is_not_truncated() {
        let mut cap = BoundedStderr::new(1000, 100);
        cap.push(b"hello\n");
        assert!(!cap.truncated());
        assert_eq!(cap.as_lossy(), "hello\n");
    }

    #[test]
    fn log_event_tags_match_the_brief() {
        assert_eq!(InnerLogEvent::Spawned { pid: 1 }.tag(), "inner_spawned");
        assert_eq!(
            InnerLogEvent::SpawnFailed { reason: "x".into() }.tag(),
            "inner_spawn_failed"
        );
        assert_eq!(InnerLogEvent::Exited { code: Some(0) }.tag(), "inner_exited");
        assert_eq!(InnerLogEvent::Killed { reason: "x".into() }.tag(), "inner_killed");
        assert_eq!(
            InnerLogEvent::StderrTruncated { captured_bytes: 4, cap_bytes: 4 }.tag(),
            "inner_stderr_truncated"
        );
        assert_eq!(
            InnerLogEvent::ProtocolError { detail: "x".into() }.tag(),
            "inner_protocol_error"
        );
        assert_eq!(InnerLogEvent::RequestForwarded.tag(), "inner_request_forwarded");
        assert_eq!(InnerLogEvent::ResponseSigned.tag(), "inner_response_signed");
    }

    #[test]
    fn allowlisted_present_var_resolves() {
        let config = InnerLaunchConfig {
            allow_env_names: vec!["FOO".to_string()],
            ..InnerLaunchConfig::new()
        };
        let resolved = config
            .resolve_allowlist(&env_view(&[("FOO", "bar")]))
            .expect("present var resolves");
        assert_eq!(resolved, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn allowlisted_absent_var_fails_closed() {
        let config = InnerLaunchConfig {
            allow_env_names: vec!["SECRET_THAT_IS_UNSET".to_string()],
            ..InnerLaunchConfig::new()
        };
        let err = config
            .resolve_allowlist(&env_view(&[]))
            .expect_err("absent allowlisted var must fail closed, not silently drop");
        assert!(err.contains("SECRET_THAT_IS_UNSET"), "got: {err}");
        assert!(err.contains("not present"), "got: {err}");
    }

    #[test]
    fn allowlist_error_names_only_the_var_not_its_value() {
        // The proxy env holds a secret under a DIFFERENT name than the one
        // requested; the error must not surface any environment value.
        let config = InnerLaunchConfig {
            allow_env_names: vec!["WANTED".to_string()],
            ..InnerLaunchConfig::new()
        };
        let err = config
            .resolve_allowlist(&env_view(&[("MCPS_SIGNING_SEED", "TOP-SECRET-SEED-VALUE")]))
            .expect_err("absent var fails");
        assert!(!err.contains("TOP-SECRET-SEED-VALUE"), "error leaked a value: {err}");
    }
}
