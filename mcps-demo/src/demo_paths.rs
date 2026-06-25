//! Shared demo path resolution for the runnable demo binaries.
//!
//! The runnable demos (`demo_positive`, `demo_negative`) need two things on disk:
//! the inner `mcps-demo-fileserver` binary, and the committed `demo_root/` fixture
//! directory. Under Bazel these are delivered through runfiles and their paths are
//! stamped into the `INNER_FILESERVER_BIN` / `DEMO_ROOT_README` env vars by the
//! BUILD target. Under plain Cargo there is no runfiles tree and no stamped env
//! var, so a public user running `cargo run -p mcps-demo --bin demo_positive`
//! would otherwise have nothing to resolve against.
//!
//! These helpers resolve both inputs with a four-tier fallback so the SAME bins
//! run identically under Bazel and under Cargo, with no env setup required for the
//! Cargo quickstart:
//!
//! 1. **Explicit env vars** (`INNER_FILESERVER_BIN` / `DEMO_ROOT_README`) — the
//!    Bazel-stamped path; always wins when set, so `bazel run`/`bazel test` keep
//!    their existing behavior untouched.
//! 2. **Cargo-built binary** — `target/{debug,release}/mcps-demo-fileserver`
//!    relative to the workspace, for the public `cargo build --workspace --bins`
//!    quickstart.
//! 3. **Workspace-relative fixture** — `mcps-demo-fileserver/demo_root/` for the
//!    committed demo fixtures.
//! 4. **Bazel runfiles fallback** — the historical cwd/`TEST_SRCDIR`/`RUNFILES_DIR`
//!    resolution, kept so any runfiles-style layout still resolves.
//!
//! This intentionally does NOT reuse [`mcps_test_paths::resolve_runfile`]: that
//! resolver locates the workspace via `CARGO_MANIFEST_DIR`, which Cargo sets only
//! when it *launches* a process (`cargo run`/`cargo test`) — not when a built
//! binary is executed directly (`./target/debug/demo_positive`). These helpers
//! resolve via `current_exe()` and the cwd so the runnable demos work under
//! `cargo run`, direct execution, AND Bazel.

use std::path::PathBuf;

const INNER_BIN_ENV: &str = "INNER_FILESERVER_BIN";
const DEMO_ROOT_ENV: &str = "DEMO_ROOT_README";
const INNER_BIN_NAME: &str = "mcps-demo-fileserver";
const FIXTURE_README_REL: &str = "mcps-demo-fileserver/demo_root/readme.txt";

/// The directory holding the running binary's Cargo `target/<profile>/` output,
/// derived from the current executable. Returns the `<profile>` dir (e.g.
/// `target/debug`) the demo bin itself was built into, so the sibling
/// `mcps-demo-fileserver` built by the same `cargo build` is found next to it.
fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
}

/// Candidate workspace roots to resolve workspace-relative paths against: the cwd
/// and its parent (covers running from the workspace root or a crate subdir), plus
/// the runfiles roots for the Bazel fallback.
fn workspace_candidates() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for root_key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
        if let Ok(root) = std::env::var(root_key) {
            roots.push(PathBuf::from(root));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(parent) = cwd.parent() {
            roots.push(parent.to_path_buf());
        }
        roots.push(cwd);
    }
    roots
}

/// Resolve a Bazel-stamped `$(rlocationpath ...)` env var against the runfiles
/// roots and the cwd, returning the first candidate that exists. This is the
/// historical (tier-4) resolution, preserved verbatim in behavior.
fn resolve_runfile(env_key: &str) -> Option<PathBuf> {
    let rel = std::env::var(env_key).ok()?;
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
    candidates.into_iter().find(|c| c.exists())
}

/// Resolve the inner `mcps-demo-fileserver` binary, in fallback order:
/// env var → Cargo `target/{debug,release}` → runfiles.
pub fn demo_inner_binary() -> Result<PathBuf, String> {
    // Tier 1: explicit Bazel-stamped env var (wins when set).
    if let Some(p) = resolve_runfile(INNER_BIN_ENV) {
        return Ok(p);
    }

    // Tier 2: the Cargo-built binary, next to the demo bin itself, then under the
    // conventional target/{debug,release} dirs relative to the workspace.
    let exe_name = if cfg!(windows) {
        format!("{INNER_BIN_NAME}.exe")
    } else {
        INNER_BIN_NAME.to_string()
    };
    let mut cargo_candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = current_exe_dir() {
        cargo_candidates.push(dir.join(&exe_name));
    }
    for root in workspace_candidates() {
        cargo_candidates.push(root.join("target").join("debug").join(&exe_name));
        cargo_candidates.push(root.join("target").join("release").join(&exe_name));
    }
    if let Some(p) = cargo_candidates.into_iter().find(|c| c.exists()) {
        return Ok(p);
    }

    Err(format!(
        "cannot locate the inner '{INNER_BIN_NAME}' binary. Set {INNER_BIN_ENV}, \
         or build it with `cargo build -p mcps-demo-fileserver --bin {INNER_BIN_NAME}` \
         (or run via `bazel run //mcps-demo:demo_positive`)."
    ))
}

/// Resolve the `demo_root/` fixture directory, in fallback order:
/// env var (`DEMO_ROOT_README`, whose parent is the dir) → workspace-relative
/// `mcps-demo-fileserver/demo_root/` → runfiles.
pub fn demo_root_dir() -> Result<PathBuf, String> {
    // Tier 1: explicit Bazel-stamped env var points at readme.txt; its parent is
    // the demo_root dir.
    if let Some(readme) = resolve_runfile(DEMO_ROOT_ENV) {
        if let Some(parent) = readme.parent() {
            return Ok(parent.to_path_buf());
        }
    }

    // Tier 2/3: workspace-relative committed fixture.
    for root in workspace_candidates() {
        let readme = root.join(FIXTURE_README_REL);
        if readme.exists() {
            if let Some(parent) = readme.parent() {
                return Ok(parent.to_path_buf());
            }
        }
    }

    Err(format!(
        "cannot locate the demo_root fixture. Set {DEMO_ROOT_ENV}, or run from the \
         workspace root where '{FIXTURE_README_REL}' is committed \
         (or run via `bazel run //mcps-demo:demo_positive`)."
    ))
}
