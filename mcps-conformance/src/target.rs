//! Conformance targets (MCPS-010).
//!
//! A [`ConformanceTarget`] submits a single vector and reports the resulting
//! verification outcome as a wire token. MCPS-010 ships the in-process
//! [`ObjectTarget`], which runs each vector directly through
//! `mcps_core::verify_request` / `verify_response`. Later phases (MCPS-012 stdio,
//! MCPS-013 Streamable HTTP) implement the same trait over a transport, so the
//! runner is transport-agnostic.

use mcps_core::b64url_decode;
use mcps_core::canonicalize;
use mcps_core::parse_rfc3339_utc;
use mcps_core::request_hash;
use mcps_core::verify_request;
use mcps_core::verify_response;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::VerificationConfig;
use mcps_core::VerificationKey;
use serde_json::Value;

use crate::vector::Expected;
use crate::vector::VectorCase;

/// The documented test audience (signer/server seed scheme, MCPS_SPEC §10).
pub const TEST_AUDIENCE: &str = "did:example:server-1";
/// The symmetric clock-skew allowance used for the object suite.
pub const TEST_MAX_CLOCK_SKEW_SECS: i64 = 300;

/// A runner-facing outcome: the verification result reduced to a wire token,
/// using the SAME mapping the report compares against (Ok ⇒ `"verify_ok"`,
/// `Err(e)` ⇒ `e.wire_code()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetOutcome {
    pub token: String,
}

impl TargetOutcome {
    fn ok() -> Self {
        TargetOutcome {
            token: "verify_ok".to_string(),
        }
    }
    fn err(code: &str) -> Self {
        TargetOutcome {
            token: code.to_string(),
        }
    }

    /// The wire token this outcome produced.
    pub fn as_token(&self) -> &str {
        &self.token
    }

    /// Whether this outcome satisfies an expected result.
    pub fn matches(&self, expected: &Expected) -> bool {
        self.token == expected.as_token()
    }
}

/// Context a target may need to evaluate a vector that is not self-contained.
///
/// Response vectors verify against the `request_hash` of their matching request;
/// in the committed suite every response binds to the canonical v1 request, so
/// the runner supplies that request's locally computed hash here.
#[derive(Debug, Clone)]
pub struct RunContext {
    /// The locally computed `request_hash` of the canonical valid request,
    /// used as `expected_request_hash` for response verification.
    pub canonical_request_hash: Option<String>,
}

/// A conformance target: submit one vector, get back its verification outcome.
pub trait ConformanceTarget {
    /// Run `case` and return the outcome as a wire token, or a descriptive
    /// error string if the case itself is malformed (e.g. a raw fixture with no
    /// bytes). The latter is a harness bug, not a verification verdict.
    fn run_case(&self, case: &VectorCase, ctx: &RunContext) -> Result<TargetOutcome, String>;
}

/// In-process target: runs vectors directly against `mcps-core` (MCPS-010).
#[derive(Debug, Default)]
pub struct ObjectTarget;

impl ObjectTarget {
    /// Construct a fresh object target.
    pub fn new() -> Self {
        ObjectTarget
    }

    /// Verification config with the documented audience + skew.
    fn config() -> VerificationConfig {
        VerificationConfig {
            expected_audience: TEST_AUDIENCE.to_string(),
            max_clock_skew_secs: TEST_MAX_CLOCK_SKEW_SECS,
        }
    }

    /// Build an in-memory resolver seeded from the vector's committed resolver
    /// entry (the documented test public key). Returns an empty resolver when
    /// the vector carries none (such vectors fail before key resolution).
    fn resolver_for(case: &VectorCase) -> Result<InMemoryTrustResolver, String> {
        let mut resolver = InMemoryTrustResolver::new();
        if let Some(entry) = &case.resolver {
            let (signer, key_id) = entry
                .signer_key
                .split_once('#')
                .ok_or_else(|| format!("resolver signer_key missing '#': {}", entry.signer_key))?;
            let key = VerificationKey::from_b64url(&entry.public_key_b64url)
                .map_err(|e| format!("resolver public key decode failed: {e}"))?;
            resolver.insert(signer, key_id, key);
        }
        Ok(resolver)
    }

    /// The raw wire bytes for a vector: the serialized `message` for
    /// request/response kinds, or the `raw_text`/`raw_bytes_b64url` for raw
    /// kinds (the latter preserving non-UTF-8 bytes verbatim).
    fn wire_bytes(case: &VectorCase) -> Result<Vec<u8>, String> {
        if let Some(text) = &case.raw_text {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(b64) = &case.raw_bytes_b64url {
            return b64url_decode(b64).map_err(|e| format!("raw_bytes_b64url decode failed: {e}"));
        }
        match &case.message {
            Some(message) => serde_json::to_vec(message)
                .map_err(|e| format!("serialize message failed: {e}")),
            None => Err(format!(
                "vector '{}' has neither message nor raw bytes",
                case.name
            )),
        }
    }

    /// Choose `now_unix` for a request vector so freshness is exercised
    /// realistically: issued_at + 60s normally, but for an expired vector
    /// (where now must fall outside the window) use expires_at + skew + 1.
    fn now_unix_for(case: &VectorCase) -> Result<i64, String> {
        now_unix_for_case(case)
    }

    fn map_result(result: Result<impl Sized, McpsError>) -> TargetOutcome {
        match result {
            Ok(_) => TargetOutcome::ok(),
            Err(err) => TargetOutcome::err(err.wire_code()),
        }
    }

    /// Run a `raw`-kind vector. `verify_ok` for raw means canonicalization
    /// succeeds (raw fixtures have no envelope, so the pipeline is not invoked);
    /// any failure maps to its wire code.
    fn run_raw(bytes: &[u8]) -> TargetOutcome {
        Self::map_result(canonicalize(bytes))
    }

    fn run_request(&self, case: &VectorCase, bytes: &[u8]) -> Result<TargetOutcome, String> {
        let resolver = Self::resolver_for(case)?;
        let now = Self::now_unix_for(case)?;
        let config = Self::config();

        // For the replay vector, the verdict only manifests on the SECOND
        // submission against the same cache; run it twice and report the second.
        if case.expected == "mcps.replay_detected" {
            let mut replay = InMemoryReplayCache::new(TEST_MAX_CLOCK_SKEW_SECS);
            let _first = verify_request(bytes, &resolver, &mut replay, &config, now);
            let second = verify_request(bytes, &resolver, &mut replay, &config, now);
            return Ok(Self::map_result(second));
        }

        let mut replay = InMemoryReplayCache::new(TEST_MAX_CLOCK_SKEW_SECS);
        Ok(Self::map_result(verify_request(
            bytes, &resolver, &mut replay, &config, now,
        )))
    }

    fn run_response(
        &self,
        case: &VectorCase,
        bytes: &[u8],
        ctx: &RunContext,
    ) -> Result<TargetOutcome, String> {
        let resolver = Self::resolver_for(case)?;
        let expected_hash = ctx
            .canonical_request_hash
            .as_deref()
            .ok_or_else(|| "response vector needs canonical_request_hash in RunContext".to_string())?;
        Ok(Self::map_result(verify_response(bytes, &resolver, expected_hash)))
    }
}

/// Choose `now_unix` for a request vector so freshness is exercised
/// realistically: issued_at + 60s normally, but for an expired vector (where
/// now must fall outside the window) use expires_at + skew + 1. Shared by the
/// object target and the transport harnesses (MCPS-012/013) so a vector
/// produces the same verdict on every transport.
pub fn now_unix_for_case(case: &VectorCase) -> Result<i64, String> {
    let Some(message) = &case.message else {
        // No message (cannot happen for request kinds); evaluate at epoch.
        return Ok(0);
    };
    let envelope = &message["params"]["_meta"]["se.syncom/mcps.request"];
    let issued_at = envelope["issued_at"].as_str();
    let expires_at = envelope["expires_at"].as_str();

    // A request expected to fail as expired: place `now` past expiry + skew.
    if case.expected == "mcps.expired_request" {
        if let Some(exp) = expires_at {
            let exp_unix =
                parse_rfc3339_utc(exp).map_err(|e| format!("parse expires_at failed: {e}"))?;
            return Ok(exp_unix + TEST_MAX_CLOCK_SKEW_SECS + 1);
        }
    }

    // Default: just after issued_at (well within the window).
    if let Some(iss) = issued_at {
        let iss_unix =
            parse_rfc3339_utc(iss).map_err(|e| format!("parse issued_at failed: {e}"))?;
        return Ok(iss_unix + 60);
    }

    // Structural-failure vectors (batch / notification / missing envelope) have
    // no parseable issued_at; they fail before freshness anyway.
    Ok(0)
}

/// Compute the canonical request's `request_hash` from a request vector's
/// message, for use as `expected_request_hash` when verifying responses.
pub fn canonical_request_hash(case: &VectorCase) -> Result<String, String> {
    let message: &Value = case
        .message
        .as_ref()
        .ok_or_else(|| format!("vector '{}' has no message", case.name))?;
    request_hash(message).map_err(|e| format!("request_hash failed: {}", e.wire_code()))
}

impl ConformanceTarget for ObjectTarget {
    fn run_case(&self, case: &VectorCase, ctx: &RunContext) -> Result<TargetOutcome, String> {
        let bytes = Self::wire_bytes(case)?;
        match case.kind.as_str() {
            "raw" => Ok(Self::run_raw(&bytes)),
            "request" => self.run_request(case, &bytes),
            "response" => self.run_response(case, &bytes, ctx),
            other => Err(format!("unknown vector kind '{other}' for '{}'", case.name)),
        }
    }
}
