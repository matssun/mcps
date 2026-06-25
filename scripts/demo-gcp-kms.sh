#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-S — optional live Google Cloud KMS demo (thin wrapper).
#
# Cloud KMS validation is OPTIONAL and is NOT a dependency of the local demo
# (./scripts/demo-local.sh). Run this only if you want to prove the live,
# non-exporting GCP key-custody path: object signing and delegated-TLS server
# signing performed INSIDE Cloud KMS, plus the fail-closed negative lanes.
#
# This is a thin wrapper over the committed harness
# docs/security/gcloud-kms-validation.sh — see docs/quickstart-gcp-kms.md for what
# it proves and docs/security/google-validation-plan.md for first-time setup.
#
# Usage:
#   PROJECT_ID=my-gcp-project ./scripts/demo-gcp-kms.sh

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "error: PROJECT_ID is required." >&2
  echo "usage: PROJECT_ID=my-gcp-project ./scripts/demo-gcp-kms.sh" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

exec env PROJECT_ID="$PROJECT_ID" ./docs/security/gcloud-kms-validation.sh
