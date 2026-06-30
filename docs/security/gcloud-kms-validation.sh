#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-S — Google Cloud KMS validation harness (Stage 1 of the Google Validation
# Plan, see docs/security/google-validation-plan.md).
#
# WHAT THIS PROVES, against a LIVE Google Cloud KMS, with the private keys never
# leaving the cloud:
#   1. Response signing  — a real EC_SIGN_ED25519 asymmetricSign verifies under
#      the unmodified mcps-core verifier (+ wrong-identity, bad-token, and
#      non-Ed25519 negatives).
#   2. Delegated TLS     — the proxy's TLS server key lives in KMS; a real mTLS
#      handshake completes only because the cloud signed it (+ wrong-key-binding
#      and untrusted-client negatives).
#
# This is a TEMPLATE. It contains no secrets. Fill in PROJECT_ID below (or export
# it in your shell) and authenticate with `gcloud auth login` first. Everything
# else (key ring / key names) is non-sensitive and safe to keep as-is.
#
# Cost note: Cloud KMS crypto ops are ~$0.03 / 10,000 ops plus a small
# per-active-key-version charge; this harness creates 3 key versions and performs
# a handful of ops per run. Billing must be enabled on the project.
#
# Prerequisites (first-time Google Cloud setup is documented in
# docs/security/google-validation-plan.md -> "Reproducing Stage 1 locally"):
#   * a Google Cloud project with billing enabled
#   * gcloud CLI, authenticated:            gcloud auth login
#   * Rust toolchain (cargo) to run the tests
#
# Usage:
#   PROJECT_ID="my-project-123" ./docs/security/gcloud-kms-validation.sh
#   # or edit the PROJECT_ID default below.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — EDIT PROJECT_ID (or pass it in the environment).
# ---------------------------------------------------------------------------
export PROJECT_ID="${PROJECT_ID:-REPLACE_WITH_YOUR_PROJECT_ID}"
export LOCATION="${LOCATION:-global}"
export KEY_RING="${KEY_RING:-mcps-test-ring}"

# Three keys: object-signing (Ed25519), a NON-Ed25519 key to prove rejection,
# and a SECOND, DISTINCT Ed25519 key for delegated TLS (ADR-MCPS-028 §G).
export KEY_NAME="${KEY_NAME:-mcps-ed25519-object}"
export RSA_KEY_NAME="${RSA_KEY_NAME:-mcps-rsa-object}"
export TLS_KEY_NAME="${TLS_KEY_NAME:-mcps-ed25519-tls}"

# ---------------------------------------------------------------------------
# Preflight — fail loudly on an unconfigured or unauthenticated environment.
# ---------------------------------------------------------------------------
if [[ "$PROJECT_ID" == "REPLACE_WITH_YOUR_PROJECT_ID" ]]; then
  echo "ERROR: set PROJECT_ID (edit this script or run: PROJECT_ID=... $0)" >&2
  exit 1
fi
if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud CLI not found on PATH." >&2
  exit 1
fi
if ! gcloud auth print-access-token >/dev/null 2>&1; then
  echo "ERROR: not authenticated — run 'gcloud auth login' first." >&2
  exit 1
fi

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"
gcloud services enable cloudkms.googleapis.com --project "$PROJECT_ID"

# ---------------------------------------------------------------------------
# Idempotent provisioning. KMS key rings and keys CANNOT be deleted, so each
# resource is created once and reused on later runs (describe-or-create).
# ---------------------------------------------------------------------------
if gcloud kms keyrings describe "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1; then
  echo "keyring $KEY_RING already exists, skipping"
else
  gcloud kms keyrings create "$KEY_RING" --location "$LOCATION"
fi

# Object-signing Ed25519 key.
if gcloud kms keys describe "$KEY_NAME" \
     --keyring "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1; then
  echo "key $KEY_NAME already exists, skipping"
else
  gcloud kms keys create "$KEY_NAME" \
    --keyring "$KEY_RING" --location "$LOCATION" \
    --purpose "asymmetric-signing" \
    --default-algorithm "ec-sign-ed25519" \
    --protection-level "software"
fi

# NON-Ed25519 (RSA) key — proves a disallowed algorithm is rejected at construction.
if gcloud kms keys describe "$RSA_KEY_NAME" \
     --keyring "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1; then
  echo "key $RSA_KEY_NAME already exists, skipping"
else
  gcloud kms keys create "$RSA_KEY_NAME" \
    --keyring "$KEY_RING" --location "$LOCATION" \
    --purpose "asymmetric-signing" \
    --default-algorithm "rsa-sign-pkcs1-2048-sha256" \
    --protection-level "software"
fi

# Delegated-TLS Ed25519 key — a DISTINCT key from the object-signing key. Its
# private key never leaves KMS; the TLS handshake is signed via asymmetricSign.
if gcloud kms keys describe "$TLS_KEY_NAME" \
     --keyring "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1; then
  echo "key $TLS_KEY_NAME already exists, skipping"
else
  gcloud kms keys create "$TLS_KEY_NAME" \
    --keyring "$KEY_RING" --location "$LOCATION" \
    --purpose "asymmetric-signing" \
    --default-algorithm "ec-sign-ed25519" \
    --protection-level "software"
fi

# ---------------------------------------------------------------------------
# Credentials + key-version resource paths the tests read from the environment.
# An operator OAuth2 token is used here; on a GCE/GKE host you can instead set
# MCPS_GCP_USE_METADATA=1 and drop MCPS_GCP_ACCESS_TOKEN.
# ---------------------------------------------------------------------------
KV_BASE="projects/$PROJECT_ID/locations/$LOCATION/keyRings/$KEY_RING/cryptoKeys"
export MCPS_GCP_KEY_VERSION="$KV_BASE/$KEY_NAME/cryptoKeyVersions/1"
export MCPS_GCP_KEY_VERSION_RSA="$KV_BASE/$RSA_KEY_NAME/cryptoKeyVersions/1"
export MCPS_GCP_KEY_VERSION_TLS="$KV_BASE/$TLS_KEY_NAME/cryptoKeyVersions/1"
export MCPS_GCP_ACCESS_TOKEN="$(gcloud auth print-access-token)"

# ---------------------------------------------------------------------------
# Run ONLY the live GCP test targets (the `#[ignore]` lanes) so the output is
# just the lanes that matter, not the whole workspace.
# ---------------------------------------------------------------------------
cd "$REPO_ROOT"

# 1. Object-signing lane: positive verify + wrong-identity + bad-token + non-Ed25519.
cargo test -p mcps-proxy --features gcp_kms_keysource \
  --test gcp_kms_live_test -- --ignored --nocapture --test-threads=1

# 2. Delegated-TLS lane: real mTLS handshake signed by KMS + wrong-key-binding +
#    untrusted-client negatives.
cargo test -p mcps-proxy --features gcp_kms_keysource \
  --test gcp_kms_delegated_tls_live_test -- --ignored --nocapture --test-threads=1

# 3. Draft-02 (v0.6) envelope lane: Cloud KMS signs a COMPLETE draft-02 request
#    and response — over the protected version + canonicalization_id +
#    authorization_binding preimage — that the unmodified draft-02 verifier
#    (verify_request_draft02 / verify_response_draft02) accepts, with tamper and
#    wrong-key negatives.
cargo test -p mcps-proxy --features gcp_kms_keysource \
  --test gcp_kms_draft02_live_test -- --ignored --nocapture --test-threads=1

echo
echo "OK — live GCP KMS validation passed (object signing + delegated TLS +"
echo "draft-02 envelope round-trip, with negatives). The private keys never left"
echo "Cloud KMS."
