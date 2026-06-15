//! Live AWS KMS verification lane (ADR-MCPS-028 §B, guardrail #7).
//!
//! This is the lane that lets MCP-S CLAIM AWS KMS support: a signature produced by
//! a REAL KMS `Sign` (against a real AWS endpoint or a LocalStack/internal-platform
//! emulator) MUST verify under the UNMODIFIED `mcps-core` Ed25519 verifier, using
//! the public key the same KMS reports via `GetPublicKey`. Compiling is NOT
//! support; this assertion against live infrastructure is.
//!
//! It is `#[ignore]` by default (it needs network + a configured KMS key) and is
//! run explicitly in the live-infra lane with `cargo test --features
//! aws_kms_keysource -- --ignored`. When run, it FAILS LOUDLY if its required
//! configuration is absent — it never silently "passes" without verifying.
//!
//! Required environment:
//!   * `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN` if
//!     temporary) — the static credentials (ADR-MCPS-028 credential scope).
//!   * `MCPS_AWS_KMS_KEY_ID`   — an `ECC_NIST_EDWARDS25519` KMS key id/ARN/alias.
//!   * `MCPS_AWS_KMS_REGION`   — the region.
//!   * `MCPS_AWS_KMS_ENDPOINT` — OPTIONAL endpoint override (e.g. LocalStack
//!     `http://localhost:4566`); default AWS endpoint when unset.
#![cfg(feature = "aws_kms_keysource")]

use mcps_core::verify_ed25519;
use mcps_proxy::AwsKmsConfig;
use mcps_proxy::AwsKmsEd25519Backend;
use mcps_proxy::KmsResponseSigner;
use mcps_proxy::ResponseSigner;

/// Read a REQUIRED env var or fail the lane with a clear message — a missing
/// configuration is a lane FAILURE, not a silent skip (anti-gaming).
fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "aws-kms live lane: required env var {name} is not set — this lane must run against a \
             real/emulated KMS; it does not pass without verifying"
        ),
    }
}

#[test]
#[ignore = "requires a live or emulated AWS KMS (run with --ignored and MCPS_AWS_KMS_* + AWS creds set)"]
fn aws_kms_signature_verifies_under_mcps_core() {
    let config = AwsKmsConfig {
        region: require_env("MCPS_AWS_KMS_REGION"),
        key_id: require_env("MCPS_AWS_KMS_KEY_ID"),
        endpoint: std::env::var("MCPS_AWS_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    // `from_env` reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
    // and performs GetPublicKey (which fails closed unless the key is Ed25519).
    let backend = AwsKmsEd25519Backend::from_env(&config)
        .expect("construct AWS KMS backend (GetPublicKey must succeed and be Ed25519)");
    let signer = KmsResponseSigner::new(Box::new(backend));

    let preimage = b"mcps canonical response preimage (live KMS lane)";
    let sig = signer.sign_response(preimage).expect("KMS Sign");
    let pubkey = signer.response_public_key().expect("KMS public key");

    // THE load-bearing assertion: real KMS signature verifies under mcps-core.
    verify_ed25519(preimage, &sig, &pubkey)
        .expect("a live KMS Ed25519 signature MUST verify under the mcps-core verifier");
    // And a tampered preimage must NOT verify.
    assert!(
        verify_ed25519(b"tampered", &sig, &pubkey).is_err(),
        "signature must not verify over a different preimage"
    );
}
