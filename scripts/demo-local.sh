#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-S — local single-node demo (no cloud credentials required).
#
# Builds the workspace and runs the two runnable demos against the in-process
# sidecar path:
#   * demo_positive  — one authorized call round-trips client -> proxy -> inner.
#   * demo_negative  — ten fail-closed cases, each rejected with its frozen
#                      mcps.* reason code (the binary exits non-zero if any case
#                      is NOT rejected as expected).
#
# This is the real v0.5.1 behavior, not a mock-up. For the live Google Cloud KMS
# key-custody proof, run ./scripts/demo-gcp-kms.sh after this.

set -euo pipefail

# Run from the repository root regardless of where the script is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "== Building workspace binaries (cargo build --workspace --bins) =="
cargo build --workspace --bins

echo
echo "== MCP-S local positive path =="
cargo run --quiet -p mcps-demo --bin demo_positive

echo
echo "== MCP-S local fail-closed paths =="
cargo run --quiet -p mcps-demo --bin demo_negative

echo
echo "OK: MCP-S local demo completed"
