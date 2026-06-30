//! Resolve child-process binaries and data fixtures for integration tests
//! whether they run under Bazel runfiles or a plain Cargo build.
//!
//! Each known env-var name (Bazel injects these as `$(rlocationpath ...)`)
//! maps to a workspace-relative cargo path. The resolver tries the Bazel env
//! var first; if absent, it falls back to `<workspace-root>/target/<profile>/<bin>`
//! (or, for the few data fixtures we ship, a fixed source-tree path).
//!
//! New env keys must be added to [`cargo_fallback`] — the resolver fails loudly
//! on unknown keys rather than silently returning an empty path.

use std::path::Path;
use std::path::PathBuf;

/// Resolve a runfile-style path. Under Bazel `env_key` is set; under Cargo we
/// fall back to the canonical workspace layout.
///
/// Panics on an unresolvable lookup with a message that points at the most
/// likely cause: missing `cargo build --workspace --bins` for a cross-crate
/// binary, or an unknown env key that needs adding to [`cargo_fallback`].
pub fn resolve_runfile(env_key: &str) -> PathBuf {
    if let Ok(rel) = std::env::var(env_key) {
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
        if let Some(found) = candidates.into_iter().find(|c| c.exists()) {
            return found;
        }
        // `env_key` was set but the runfile root resolution failed — fall
        // through to the cargo fallback rather than panicking immediately.
    }
    cargo_fallback(env_key)
}

/// Cargo-mode fallback. Each Bazel env key maps to either:
///
/// * a workspace-relative bin (looked up at `target/<profile>/<bin>`), or
/// * a workspace-relative source-tree file (data fixtures).
fn cargo_fallback(env_key: &str) -> PathBuf {
    let workspace_root = workspace_root();
    match env_key {
        // Same-crate bins
        "MCPS_PROXY_CLI" => find_bin(&workspace_root, "mcps-proxy"),
        "MCPS_CLIENT_PROXY_CLI" => find_bin(&workspace_root, "mcps-client-proxy-cli"),
        "MCPS_STDIO_SERVER" => find_bin(&workspace_root, "mcps-stdio-server"),
        "DEMO_SERVER_BIN" => find_bin(&workspace_root, "mcps-demo-server"),
        "INNER_FILESERVER_BIN" | "DEMO_FILESERVER_BIN" => {
            find_bin(&workspace_root, "mcps-demo-fileserver")
        }
        "MCPS_ECHO_INNER" => find_bin(&workspace_root, "echo-inner"),
        // Data fixtures
        "DEMO_ROOT_README" => workspace_root.join("mcps-demo-fileserver/demo_root/readme.txt"),
        // Conformance + traceability manifests
        "MCPS_MANIFEST" => workspace_root.join("mcps-conformance/conformance_manifest.json"),
        "MCPS_SECURITY_MANIFEST" => {
            workspace_root.join("mcps-conformance/security_traceability_manifest.json")
        }
        "MCPS_CORE_MANIFEST" => workspace_root.join("mcps-core/tests/vectors/manifest.json"),
        // ADR-MCPS-034: Core src sentinel (method-name drift guard scans its dir).
        "MCPS_CORE_SRC_LIB" => workspace_root.join("mcps-core/src/lib.rs"),
        // ADR-MCPS-035: frozen error taxonomy + audit vocabulary (the audit drift
        // guard asserts every audit rejection reason ∈ McpsError::wire_code()).
        "MCPS_CORE_SRC_ERROR" => workspace_root.join("mcps-core/src/error.rs"),
        "MCPS_CORE_SRC_AUDIT" => workspace_root.join("mcps-core/src/audit.rs"),
        "MCPS_PHASE5" => workspace_root.join("mcps-policy/tests/vectors/phase5_vectors.json"),
        // Per-crate BUILD.bazel (read by drift / traceability guards)
        "MCPS_BUILD_CONFORMANCE" => workspace_root.join("mcps-conformance/BUILD.bazel"),
        "MCPS_BUILD_CORE" => workspace_root.join("mcps-core/BUILD.bazel"),
        "MCPS_BUILD_DEMO" => workspace_root.join("mcps-demo/BUILD.bazel"),
        "MCPS_BUILD_DEMO_SERVER" => workspace_root.join("mcps-demo-server/BUILD.bazel"),
        "MCPS_BUILD_FILESERVER" => workspace_root.join("mcps-demo-fileserver/BUILD.bazel"),
        "MCPS_BUILD_HOST" => workspace_root.join("mcps-host/BUILD.bazel"),
        "MCPS_BUILD_POLICY" => workspace_root.join("mcps-policy/BUILD.bazel"),
        "MCPS_BUILD_PROXY" => workspace_root.join("mcps-proxy/BUILD.bazel"),
        "MCPS_BUILD_TRANSPORT" => workspace_root.join("mcps-transport/BUILD.bazel"),
        // Per-test source files (read by the security-traceability guard)
        "MCPS_SRC_OBJECT_SUITE" => {
            workspace_root.join("mcps-conformance/tests/object_suite_test.rs")
        }
        // MCPS-50 (#197): the discovery/enforcement conformance corpus source.
        "MCPS_SRC_DISCOVERY_ENFORCEMENT_CONFORMANCE" => {
            workspace_root.join("mcps-conformance/tests/discovery_enforcement_conformance_test.rs")
        }
        // ADR-MCPS-034: the two method-transparency proof artifacts.
        "MCPS_SRC_METHOD_TRANSPARENCY" => {
            workspace_root.join("mcps-conformance/tests/method_transparency_test.rs")
        }
        "MCPS_SRC_METHOD_NAME_DRIFT_GUARD" => {
            workspace_root.join("mcps-conformance/tests/method_name_drift_guard_test.rs")
        }
        "MCPS_SRC_HOST_SESSION" => workspace_root.join("mcps-host/tests/host_session_test.rs"),
        "MCPS_SRC_PERSISTENT_SCOPE" => {
            workspace_root.join("mcps-proxy/tests/persistent_scope_test.rs")
        }
        "MCPS_SRC_PERSISTENT_INNER" => {
            workspace_root.join("mcps-proxy/tests/persistent_inner_test.rs")
        }
        "MCPS_SRC_PERSISTENT_SESSION" => {
            workspace_root.join("mcps-proxy/tests/persistent_session_test.rs")
        }
        "MCPS_SRC_PROXY" => workspace_root.join("mcps-proxy/tests/proxy_test.rs"),
        "MCPS_SRC_KEY_SOURCE" => workspace_root.join("mcps-proxy/tests/key_source_test.rs"),
        "MCPS_SRC_DEV_ENV_KEY_SOURCE" => {
            workspace_root.join("mcps-proxy/tests/dev_env_key_source_test.rs")
        }
        "MCPS_SRC_DEMO_NEGATIVE_E2E" => {
            workspace_root.join("mcps-demo/tests/demo_negative_e2e_test.rs")
        }
        "MCPS_SRC_DEMO_TRANSPORT_E2E" => {
            workspace_root.join("mcps-demo/tests/demo_transport_e2e_test.rs")
        }
        "MCPS_SRC_DEMO_E2E_PERSISTENT" => {
            workspace_root.join("mcps-demo/tests/demo_e2e_persistent_test.rs")
        }
        "MCPS_SRC_DEMO_POSTURE_E2E" => {
            workspace_root.join("mcps-demo/tests/demo_posture_e2e_test.rs")
        }
        "MCPS_SRC_RECEIVED_LOG" => {
            workspace_root.join("mcps-demo-server/tests/received_log_test.rs")
        }
        "MCPS_SRC_MTLS_CLIENT" => workspace_root.join("mcps-transport/tests/mtls_client_test.rs"),
        "MCPS_SRC_KEYSET_ADMISSION" => {
            workspace_root.join("mcps-proxy/tests/keyset_admission_test.rs")
        }
        // ADR-MCPS-036 gate spine: the conformance-guard test sources the
        // traceability manifest maps for the audit (#151) and forbidden-claim
        // (#155) guards, plus the §A claim matrix read by the §A-coverage check.
        "MCPS_SRC_AUDIT_VOCABULARY_GUARD" => {
            workspace_root.join("mcps-conformance/tests/audit_vocabulary_guard_test.rs")
        }
        "MCPS_SRC_FORBIDDEN_CLAIM_GUARD" => {
            workspace_root.join("mcps-conformance/tests/forbidden_claim_guard_test.rs")
        }
        "MCPS_CLAIM_MATRIX" => workspace_root.join("docs/spec/v0.5-claim-matrix.md"),
        // ADR-MCPS-036: proposal-facing docs scanned by the forbidden-claim guard.
        "MCPS_DOC_SECURITY_BOUNDARY" => workspace_root.join("docs/spec/security-boundary.md"),
        "MCPS_DOC_CLAIM_MATRIX" => workspace_root.join("docs/spec/v0.5-claim-matrix.md"),
        "MCPS_DOC_THREAT_COVERAGE" => workspace_root.join("docs/spec/threat-coverage-matrix.md"),
        "MCPS_DOC_COMPOSABILITY" => workspace_root.join("docs/spec/composability.md"),
        "MCPS_DOC_PROPOSAL_SCOPE" => workspace_root.join("docs/spec/proposal-scope.md"),
        "MCPS_DOC_SECURITY_BOUNDARY_STUB" => workspace_root.join("docs/SECURITY_BOUNDARY.md"),
        other => panic!(
            "mcps_test_paths: unknown runfile env key '{other}' — add it to \
             cargo_fallback in mcps-test-paths/src/lib.rs"
        ),
    }
}

/// Locate the workspace root by walking up from the test crate's manifest dir
/// until a `Cargo.toml` containing `[workspace]` is found. Each integration
/// test compiles with `CARGO_MANIFEST_DIR` pointing at its own crate dir.
fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set when compiling Cargo integration tests");
    let mut dir: &Path = Path::new(&manifest);
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if text.contains("[workspace]") {
                    return dir.to_path_buf();
                }
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => panic!(
                "mcps_test_paths: walked past the filesystem root without finding a Cargo.toml \
                 that contains [workspace] (started from '{manifest}')"
            ),
        }
    }
}

/// Map a workspace-root path + bin name to the canonical `target/<profile>/<bin>`
/// location. Tries the current profile first (debug under `cargo test`), then
/// the opposite as a courtesy. Panics with a precise remediation message if
/// neither exists, since Cargo does NOT auto-build cross-crate bins for
/// integration tests.
fn find_bin(workspace_root: &Path, bin_name: &str) -> PathBuf {
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let bin_file = format!("{bin_name}{exe_suffix}");
    // CARGO_TARGET_DIR honors user overrides; default is <workspace-root>/target.
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    let primary_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let other_profile = if primary_profile == "debug" {
        "release"
    } else {
        "debug"
    };
    for profile in [primary_profile, other_profile] {
        let candidate = target_dir.join(profile).join(&bin_file);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "mcps_test_paths: cargo binary '{bin_name}' not found under {}/{{debug,release}}/ \
         — run `cargo build --workspace --bins` first (cargo does not auto-build cross-crate \
         binaries for integration tests).",
        target_dir.display()
    );
}
