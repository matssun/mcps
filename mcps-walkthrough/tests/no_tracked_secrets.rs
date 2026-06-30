//! Phase 5 tracked-file leak guard (ADR-MCPS-045).
//!
//! The live-cloud script (`work/test-gcp-cloud.sh`) holds real personal GCP
//! identifiers and is gitignored; a sanitized placeholder
//! (`scripts/test-gcp-cloud.sh.example`) is committed in its place. This test is
//! the backstop: it asserts that NONE of the real identifiers ever appear in a
//! TRACKED file. `git grep` only searches tracked files, so the gitignored real
//! script is excluded by construction; a copy accidentally `git add`ed, or a
//! secret pasted into source/docs, fails this test loudly.
//!
//! The forbidden identifiers are assembled from fragments at runtime so the
//! literal secrets never appear in THIS (tracked) source file — otherwise the
//! guard would itself be the leak it is meant to catch.

use std::process::Command;

/// Reconstruct the real identifiers from fragments (so this file stays clean).
fn forbidden_needles() -> Vec<String> {
    vec![
        // Personal account domain (also covers the full email address).
        format!("{}{}", "rudbeck", "skliniken.se"),
        // GCP project id.
        format!("{}{}", "project-b19bbb5e", "-9be8-4fcb-a2f"),
        // GCP project number.
        format!("{}{}", "4708", "85495385"),
    ]
}

fn repo_root() -> String {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("run git rev-parse");
    assert!(out.status.success(), "not in a git repo (this guard requires git)");
    String::from_utf8(out.stdout).expect("utf-8 toplevel").trim().to_string()
}

#[test]
fn no_real_gcp_identifiers_in_tracked_files() {
    let root = repo_root();
    let mut leaks = Vec::new();
    for needle in forbidden_needles() {
        // `git grep -I -nF <needle> -- :/` over all tracked files from the repo
        // root. Exit 0 = match found (a leak), 1 = no match (clean), >1 = error.
        let out = Command::new("git")
            .args(["-C", &root, "grep", "-I", "-nF", &needle, "--", ":/"])
            .output()
            .expect("run git grep");
        match out.status.code() {
            Some(1) => {} // clean: no tracked file contains this identifier
            Some(0) => leaks.push(format!(
                "leaked identifier in tracked files:\n{}",
                String::from_utf8_lossy(&out.stdout)
            )),
            other => panic!("git grep failed (status {other:?}) for a leak-guard needle"),
        }
    }
    assert!(
        leaks.is_empty(),
        "tracked-file leak guard tripped — real personal/GCP identifiers must never \
         be committed (keep them only in the gitignored work/ script):\n{}",
        leaks.join("\n")
    );
}
