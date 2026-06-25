#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-S — smoke test for the evaluator demo scripts.
#
# Proves the public demo entry points actually work, end to end, on a clean
# checkout — so a stale binary, a moved fixture, or a broken path-resolution
# fallback is caught here rather than by an evaluator. It asserts:
#
#   1. ./scripts/demo-local.sh exits 0 and prints the completion line;
#   2. demo_positive's authorized call round-trips and the response verifies;
#   3. demo_negative surfaces ALL ten fail-closed cases, each with its frozen
#      mcps.* reason code (and the caller-verified strip/replace case);
#   4. ./scripts/demo-gcp-kms.sh fails closed (exit 2) when PROJECT_ID is unset,
#      WITHOUT contacting any cloud — the guard is testable offline.
#
# No cloud credentials are required. Run from anywhere:
#   ./scripts/test-demos.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

# The frozen mcps.* reason codes the negative demo must surface, plus the
# non-denial strip/replace marker. Kept in sync with demo_negative.rs by this
# test failing loudly if any goes missing.
EXPECT=(
  "mcps.invalid_signature"
  "mcps.replay_detected"
  "mcps.expired_request"
  "mcps.invalid_audience"
  "mcps.missing_envelope"
  "stripped+replaced"
  "mcps.authorization_scope_denied"
  "mcps.response_hash_mismatch"
  "mcps.response_sig_invalid"
)

echo "== 1. ./scripts/demo-local.sh (build + positive + negative) =="
# Capture combined output; -e would abort on the script's exit code, so guard it.
set +e
LOCAL_OUT="$(./scripts/demo-local.sh 2>&1)"
LOCAL_RC=$?
set -e
if [[ $LOCAL_RC -ne 0 ]]; then
  echo "$LOCAL_OUT" >&2
  fail "demo-local.sh exited $LOCAL_RC (expected 0)"
fi
pass "demo-local.sh exited 0"

grep -q "OK: MCP-S local demo completed" <<<"$LOCAL_OUT" \
  || fail "missing final completion line"
pass "completion line present"

# Positive path must round-trip and verify.
grep -q "OK: authorized list_files round-tripped" <<<"$LOCAL_OUT" \
  || fail "positive path did not round-trip"
grep -q "response-verified server_signer=" <<<"$LOCAL_OUT" \
  || fail "positive response was not verified"
pass "positive path round-tripped and response verified"

# Negative path must surface every expected security property.
grep -q "OK: all 10 fail-closed cases rejected" <<<"$LOCAL_OUT" \
  || fail "negative path did not confirm all 10 cases"
for code in "${EXPECT[@]}"; do
  grep -qF "$code" <<<"$LOCAL_OUT" || fail "negative output missing: $code"
done
PASS_COUNT="$(grep -c '  PASS ' <<<"$LOCAL_OUT" || true)"
[[ "$PASS_COUNT" -eq 10 ]] || fail "expected 10 PASS lines, saw $PASS_COUNT"
pass "all 10 fail-closed cases surfaced with frozen reason codes"

echo
echo "== 2. ./scripts/demo-gcp-kms.sh guard (offline) =="
set +e
GCP_OUT="$(./scripts/demo-gcp-kms.sh 2>&1)"
GCP_RC=$?
set -e
[[ $GCP_RC -eq 2 ]] || fail "demo-gcp-kms.sh without PROJECT_ID exited $GCP_RC (expected 2)"
grep -q "PROJECT_ID is required" <<<"$GCP_OUT" || fail "guard message missing"
pass "demo-gcp-kms.sh fails closed without PROJECT_ID (no cloud contacted)"

echo
echo "OK: demo scripts verified"
