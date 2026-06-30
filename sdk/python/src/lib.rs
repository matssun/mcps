//! `mcps_sdk._core` — the PyO3 native extension for the MCP-S Python SDK.
//!
//! Issue #199, ADR-MCPS-044. The transport-adapter verdict means the Python SDK
//! owns serialization at the byte boundary and delegates ALL security logic here,
//! to the audited `mcps-client-core`.
//!
//! Bound so far:
//!   - [`sign_request`] — sign via `build_signed_request` over a raw seed key
//!     (dev/test; no custody gate). Lowest-level entry point.
//!   - [`sign_request_with_signer`] + [`Signer`] + [`SignerPolicy`] — the CUSTODY
//!     seam: `build_signed_request_with_signer` authorizes the signer against the
//!     policy (identity match, revocation, hardening profile, and the production
//!     dev-file rule) BEFORE signing, and binds the evidence to the signer's
//!     actual identity. This is the path the Rust proxy uses.
//!
//! # Still to bind (the proxy `handle` pipeline — `mcps-client-proxy/src/proxy.rs`)
//!   - `resolve_authorization_binding` (this slice takes a pre-resolved opaque
//!     binding directly)
//!   - `verify_signed_response` / `classify_response_result` / `decide` /
//!     `audit_for_decision` / `CorrelationStore`

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcps_client_core::{
    audit_for_decision, build_signed_request, build_signed_request_with_signer,
    classify_response_result, decide, verify_signed_response, AbsenceReason, ClientOutcome,
    ClientPath, ClientSigner, CorrelationError, CorrelationStore, CustodyClass, DevFileSigner,
    EnforcementDecision, EnforcementMode, Environment, PendingRequest, RequestSigningInputs,
    ResponseExpectation, SignerPolicy, SoftwareSigner,
};
use mcps_core::{AuthorizationBinding, InMemoryTrustResolver, McpsError, SigningKey, VerificationKey};
use serde_json::{Map, Value};

// --- shared helpers --------------------------------------------------------

/// Map a core error to a Python exception (kept inside the frozen wire taxonomy).
fn to_py_err(e: McpsError) -> PyErr {
    PyValueError::new_err(format!("mcps-client-core: {e:?}"))
}

fn parse_id(id_json: &str) -> PyResult<Value> {
    serde_json::from_str(id_json).map_err(|e| PyValueError::new_err(format!("invalid id_json: {e}")))
}

fn parse_params(params_json: &str) -> PyResult<Map<String, Value>> {
    serde_json::from_str(params_json)
        .map_err(|e| PyValueError::new_err(format!("params_json must be a JSON object: {e}")))
}

fn seed_to_key(seed: &[u8]) -> PyResult<SigningKey> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        PyValueError::new_err(format!("seed must be exactly 32 bytes, got {}", seed.len()))
    })?;
    Ok(SigningKey::from_seed_bytes(&seed))
}

fn opaque_binding(digest_alg: &str, digest_value: &str) -> AuthorizationBinding {
    AuthorizationBinding::OpaqueBytes {
        digest_alg: digest_alg.to_string(),
        digest_value: digest_value.to_string(),
    }
}

fn parse_env(s: &str) -> PyResult<Environment> {
    match s {
        "production" => Ok(Environment::Production),
        "dev-test" | "dev_test" | "devtest" => Ok(Environment::DevTest),
        other => Err(PyValueError::new_err(format!(
            "environment must be 'production' or 'dev-test', got {other:?}"
        ))),
    }
}

fn parse_mode(s: &str) -> PyResult<EnforcementMode> {
    match s {
        "require_mcps" => Ok(EnforcementMode::RequireMcps),
        "allow_legacy_explicit" => Ok(EnforcementMode::AllowLegacyExplicit),
        other => Err(PyValueError::new_err(format!(
            "enforcement_mode must be 'require_mcps' or 'allow_legacy_explicit', got {other:?}"
        ))),
    }
}

fn absence_str(reason: AbsenceReason) -> &'static str {
    match reason {
        AbsenceReason::TransportFailurePreEvidence => "transport-failure-pre-evidence",
        AbsenceReason::PlainUnsigned => "plain-unsigned",
        AbsenceReason::ExplicitUnsupportedHint => "explicit-unsupported-hint",
    }
}

/// Map a correlation failure to a Python exception carrying its frozen wire code
/// (no parallel taxonomy: dup/nonce → replay, uncorrelatable → response-hash
/// mismatch, expired → expired request).
fn corr_err(e: CorrelationError) -> PyErr {
    PyValueError::new_err(format!(
        "mcps-client-core correlation: {}",
        e.to_mcps_error().wire_code()
    ))
}

// --- protocol constants ----------------------------------------------------

/// The MCP-S protocol version this core verifies/signs against (draft-02).
#[pyfunction]
fn core_version() -> &'static str {
    mcps_core::VERSION_DRAFT_02
}

/// The canonicalization id of the signed preimage the SDK reproduces exactly.
#[pyfunction]
fn canonicalization_id() -> &'static str {
    mcps_core::CANONICALIZATION_ID_INT53_V1
}

/// The `params._meta` / `result._meta` key under which the MCP-S response envelope
/// lives — the adapter strips it before handing a plain response up to the app.
#[pyfunction]
fn response_meta_key() -> &'static str {
    mcps_core::RESPONSE_META_KEY
}

// --- signed request --------------------------------------------------------

/// A signed draft-02 request crossing the binding: the exact wire bytes plus the
/// `request_hash` that binds the eventual response. Mirrors the Rust `SignedRequest`.
#[pyclass(name = "SignedRequest", frozen)]
struct PySignedRequest {
    wire: Vec<u8>,
    /// `sha256:<b64url-no-pad>` of the signed preimage — hold it to bind the response.
    #[pyo3(get)]
    request_hash: String,
}

impl PySignedRequest {
    fn from_signed(signed: mcps_client_core::SignedRequest) -> Self {
        PySignedRequest {
            wire: signed.wire_bytes().to_vec(),
            request_hash: signed.request_hash().to_string(),
        }
    }
}

#[pymethods]
impl PySignedRequest {
    /// The exact JSON-RPC wire bytes to send (canonical signed preimage + signature).
    #[getter]
    fn wire_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.wire)
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedRequest(request_hash={:?}, wire_bytes=<{} bytes>)",
            self.request_hash,
            self.wire.len()
        )
    }
}

// --- custody: signer + policy ----------------------------------------------

enum SignerKind {
    Software(SoftwareSigner),
    DevFile(DevFileSigner),
}

/// A client signing identity (the custody seam). Construct via [`Signer::software`]
/// (a held-private software key — acceptable in production) or [`Signer::dev_file`]
/// (an unprotected dev/test key — rejected under production `require_mcps`).
#[pyclass(name = "Signer", frozen)]
struct PySigner {
    kind: SignerKind,
}

impl PySigner {
    fn as_dyn(&self) -> &dyn ClientSigner {
        match &self.kind {
            SignerKind::Software(s) => s,
            SignerKind::DevFile(s) => s,
        }
    }
}

#[pymethods]
impl PySigner {
    /// In-process software signer (custody class software-held-private).
    #[staticmethod]
    #[pyo3(signature = (seed, *, signer_id, key_id))]
    fn software(seed: &[u8], signer_id: &str, key_id: &str) -> PyResult<Self> {
        Ok(PySigner {
            kind: SignerKind::Software(SoftwareSigner::new(seed_to_key(seed)?, signer_id, key_id)),
        })
    }

    /// Unprotected dev/test file signer (rejected under production `require_mcps`).
    #[staticmethod]
    #[pyo3(signature = (seed, *, signer_id, key_id))]
    fn dev_file(seed: &[u8], signer_id: &str, key_id: &str) -> PyResult<Self> {
        Ok(PySigner {
            kind: SignerKind::DevFile(DevFileSigner::new(seed_to_key(seed)?, signer_id, key_id)),
        })
    }

    #[getter]
    fn signer_id(&self) -> String {
        self.as_dyn().signer_id().to_string()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.as_dyn().key_id().to_string()
    }

    #[getter]
    fn custody(&self) -> &'static str {
        match self.as_dyn().custody() {
            CustodyClass::NonExporting => "non-exporting",
            CustodyClass::SoftwareHeldPrivate => "software-held-private",
            CustodyClass::DevFileUnprotected => "dev-file-unprotected",
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Signer(signer_id={:?}, key_id={:?}, custody={:?})",
            self.as_dyn().signer_id(),
            self.as_dyn().key_id(),
            self.custody(),
        )
    }
}

/// The signer-custody policy for a route/identity (resolved from explicit config).
/// Builder methods return a new policy: ``SignerPolicy(...).revoke_key_id(...)``.
#[pyclass(name = "SignerPolicy", frozen)]
struct PySignerPolicy {
    inner: SignerPolicy,
}

#[pymethods]
impl PySignerPolicy {
    /// Bind `expected_signer` for `environment` ("production" | "dev-test") and mode.
    #[new]
    #[pyo3(signature = (expected_signer, *, environment, require_mcps))]
    fn new(expected_signer: &str, environment: &str, require_mcps: bool) -> PyResult<Self> {
        Ok(PySignerPolicy {
            inner: SignerPolicy::new(expected_signer, parse_env(environment)?, require_mcps),
        })
    }

    /// A copy with `key_id` marked revoked (signing through it fails closed).
    fn revoke_key_id(&self, key_id: &str) -> PySignerPolicy {
        PySignerPolicy {
            inner: self.inner.clone().revoke_key_id(key_id),
        }
    }

    /// A copy requiring the hardening profile (only non-exporting custody accepted).
    fn require_non_exporting(&self) -> PySignerPolicy {
        PySignerPolicy {
            inner: self.inner.clone().require_non_exporting(),
        }
    }
}

// --- signing entry points --------------------------------------------------

/// Sign an ordinary MCP request into a draft-02 MCP-S request via the audited
/// `mcps-client-core`, using a raw 32-byte Ed25519 seed (DEV/TEST custody only —
/// no policy gate). For the production custody gate use [`sign_request_with_signer`].
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    id_json, method, params_json, *,
    signer, key_id, on_behalf_of, audience,
    binding_digest_alg, binding_digest_value,
    nonce, issued_at, expires_at, seed,
))]
fn sign_request(
    id_json: &str,
    method: &str,
    params_json: &str,
    signer: &str,
    key_id: &str,
    on_behalf_of: &str,
    audience: &str,
    binding_digest_alg: &str,
    binding_digest_value: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    seed: &[u8],
) -> PyResult<PySignedRequest> {
    let id = parse_id(id_json)?;
    let params = parse_params(params_json)?;
    let key = seed_to_key(seed)?;
    let inputs = RequestSigningInputs::with_default_canonicalization(
        signer,
        key_id,
        on_behalf_of,
        audience,
        opaque_binding(binding_digest_alg, binding_digest_value),
        nonce,
        issued_at,
        expires_at,
    );
    let signed = build_signed_request(&id, method, params, &inputs, &key).map_err(to_py_err)?;
    Ok(PySignedRequest::from_signed(signed))
}

/// Sign through a [`Signer`] gated by a [`SignerPolicy`] — the production custody
/// path (`build_signed_request_with_signer`). Authorizes the signer (identity,
/// revocation, hardening, dev-file-in-production) BEFORE signing and binds the
/// evidence to the signer's actual identity; a custody failure raises `ValueError`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    id_json, method, params_json, *,
    on_behalf_of, audience,
    binding_digest_alg, binding_digest_value,
    nonce, issued_at, expires_at, signer, policy,
))]
fn sign_request_with_signer(
    id_json: &str,
    method: &str,
    params_json: &str,
    on_behalf_of: &str,
    audience: &str,
    binding_digest_alg: &str,
    binding_digest_value: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    signer: PyRef<'_, PySigner>,
    policy: PyRef<'_, PySignerPolicy>,
) -> PyResult<PySignedRequest> {
    let id = parse_id(id_json)?;
    let params = parse_params(params_json)?;
    let s = signer.as_dyn();
    // signer/key_id here are overridden from the signer by the core; pass the
    // signer's identity for a faithful (non-misleading) inputs value.
    let inputs = RequestSigningInputs::with_default_canonicalization(
        s.signer_id(),
        s.key_id(),
        on_behalf_of,
        audience,
        opaque_binding(binding_digest_alg, binding_digest_value),
        nonce,
        issued_at,
        expires_at,
    );
    let signed = build_signed_request_with_signer(&id, method, params, &inputs, s, &policy.inner)
        .map_err(to_py_err)?;
    Ok(PySignedRequest::from_signed(signed))
}

// --- response verification: trust resolver ---------------------------------

/// The client's trust anchor set for response verification — maps a verified
/// `(server_signer, key_id)` to the PUBLIC verifying key. Response verification
/// consumes public keys only; a verifier never needs private signing material.
#[pyclass(name = "TrustResolver")]
struct PyTrustResolver {
    inner: InMemoryTrustResolver,
}

#[pymethods]
impl PyTrustResolver {
    #[new]
    fn new() -> Self {
        PyTrustResolver {
            inner: InMemoryTrustResolver::new(),
        }
    }

    /// Register a server signer by its raw 32-byte Ed25519 PUBLIC key. This is the
    /// real verifier input.
    fn insert_public_key(&mut self, signer_id: &str, key_id: &str, public_key: &[u8]) -> PyResult<()> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "public_key must be exactly 32 bytes, got {}",
                public_key.len()
            ))
        })?;
        self.inner
            .insert(signer_id, key_id, VerificationKey::from_bytes(&pk).map_err(to_py_err)?);
        Ok(())
    }

    /// DEV/TEST ONLY: register a server signer from a 32-byte SEED, deriving the
    /// public key. This exists solely to make parity vectors byte-identical with
    /// the signing side — verifiers NEVER need private material; production trust
    /// config uses `insert_public_key`.
    fn insert_dev_seed(&mut self, signer_id: &str, key_id: &str, seed: &[u8]) -> PyResult<()> {
        self.inner
            .insert(signer_id, key_id, seed_to_key(seed)?.public_key());
        Ok(())
    }
}

/// The structured outcome of [`verify_response`]: the enforcement decision plus the
/// audit-facing path/outcome/reason and (on a verified exchange) the server identity
/// and bound request_hash. A fail-closed verification is a RESULT here (with the
/// frozen `mcps.*` wire reason), not a Python exception.
#[pyclass(name = "VerifyResult", frozen)]
struct PyVerifyResult {
    /// "accept" | "fallback" | "fail-closed".
    #[pyo3(get)]
    decision: &'static str,
    /// "mcps-verified" | "legacy-explicit".
    #[pyo3(get)]
    path: &'static str,
    /// "accepted" | "fell-back" | "rejected".
    #[pyo3(get)]
    outcome: &'static str,
    /// Frozen `McpsError::wire_code()` token on a fail-closed rejection; else `None`.
    #[pyo3(get)]
    reason: Option<String>,
    /// The absence reason that made a legacy fallback eligible (local); else `None`.
    #[pyo3(get)]
    legacy_reason: Option<String>,
    /// The verified server signer (on a verified exchange); else `None`.
    #[pyo3(get)]
    server_signer: Option<String>,
    /// The key id that verified the response (on a verified exchange); else `None`.
    #[pyo3(get)]
    key_id: Option<String>,
    /// The bound `request_hash` (on a verified exchange); else `None`.
    #[pyo3(get)]
    request_hash: Option<String>,
    /// Convenience: true iff the decision was AcceptMcps.
    #[pyo3(get)]
    accepted: bool,
}

#[pymethods]
impl PyVerifyResult {
    fn __repr__(&self) -> String {
        format!(
            "VerifyResult(decision={:?}, path={:?}, reason={:?})",
            self.decision, self.path, self.reason
        )
    }
}

/// Verify a signed draft-02 response and apply the enforcement decision — the
/// proxy's return-leg pipeline (`verify_signed_response` → `classify_response_result`
/// → `decide` → `audit_for_decision`). Returns a [`VerifyResult`]; a fail-closed
/// verification is reported there (not raised). Malformed arguments raise `ValueError`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    raw_bytes, *,
    resolver, expected_request_hash,
    expected_canonicalization_id=None, expected_server_signer=None,
    enforcement_mode="require_mcps", legacy_allowed=false,
))]
fn verify_response(
    raw_bytes: &[u8],
    resolver: PyRef<'_, PyTrustResolver>,
    expected_request_hash: &str,
    expected_canonicalization_id: Option<&str>,
    expected_server_signer: Option<&str>,
    enforcement_mode: &str,
    legacy_allowed: bool,
) -> PyResult<PyVerifyResult> {
    let canon = expected_canonicalization_id.unwrap_or(mcps_core::CANONICALIZATION_ID_INT53_V1);
    let mut expectation = ResponseExpectation::new(expected_request_hash, canon);
    if let Some(signer) = expected_server_signer {
        expectation = expectation.with_expected_server_signer(signer);
    }
    let mode = parse_mode(enforcement_mode)?;

    let result = verify_signed_response(raw_bytes, &resolver.inner, &expectation);
    // Capture the verified identity before the value is moved into the outcome.
    let verified = result
        .as_ref()
        .ok()
        .map(|v| (v.server_signer().to_string(), v.key_id().to_string(), v.request_hash().to_string()));

    let outcome = classify_response_result(result);
    let decision = decide(mode, legacy_allowed, &outcome);
    let audit = audit_for_decision(&decision);

    let (decision_str, accepted) = match &decision {
        EnforcementDecision::AcceptMcps => ("accept", true),
        EnforcementDecision::FallBackToLegacy { .. } => ("fallback", false),
        EnforcementDecision::FailClosed(_) => ("fail-closed", false),
    };
    let path = match audit.path {
        ClientPath::McpsVerified => "mcps-verified",
        ClientPath::LegacyExplicit => "legacy-explicit",
    };
    let outcome_str = match audit.outcome {
        ClientOutcome::Accepted => "accepted",
        ClientOutcome::FellBackToLegacy => "fell-back",
        ClientOutcome::Rejected => "rejected",
    };
    let (server_signer, key_id, request_hash) = match verified {
        Some((s, k, h)) => (Some(s), Some(k), Some(h)),
        None => (None, None, None),
    };

    Ok(PyVerifyResult {
        decision: decision_str,
        path,
        outcome: outcome_str,
        reason: audit.reason.map(|s| s.to_string()),
        legacy_reason: audit.legacy_reason.map(|r| absence_str(r).to_string()),
        server_signer,
        key_id,
        request_hash,
        accepted,
    })
}

// --- in-flight correlation -------------------------------------------------

/// One outstanding request's retained state, returned by
/// [`CorrelationStore::take_for_response`].
#[pyclass(name = "PendingRequest", frozen)]
struct PyPendingEntry {
    #[pyo3(get)]
    correlation_id: String,
    #[pyo3(get)]
    request_hash: String,
    #[pyo3(get)]
    nonce: String,
    #[pyo3(get)]
    issued_at_unix: i64,
    #[pyo3(get)]
    deadline_unix: i64,
    #[pyo3(get)]
    route_id: String,
    #[pyo3(get)]
    audience: String,
    #[pyo3(get)]
    expected_server_signers: Vec<String>,
    #[pyo3(get)]
    version: String,
    #[pyo3(get)]
    canonicalization_id: String,
    #[pyo3(get)]
    authz_digest: String,
}

impl PyPendingEntry {
    fn from_pending(p: PendingRequest) -> Self {
        PyPendingEntry {
            correlation_id: p.correlation_id,
            request_hash: p.request_hash,
            nonce: p.nonce,
            issued_at_unix: p.issued_at_unix,
            deadline_unix: p.deadline_unix,
            route_id: p.route_id,
            audience: p.audience,
            expected_server_signers: p.expected_server_signers,
            version: p.version,
            canonicalization_id: p.canonicalization_id,
            authz_digest: p.authz_digest,
        }
    }
}

/// Per-outstanding-request correlation store: binds an outgoing signed request to
/// exactly one acceptable returning response, with nonce-reuse prevention and an
/// expiry sweep. The clock is the caller's: every method takes `now_unix`.
/// Failures (duplicate id, nonce reuse, late/uncorrelatable, expired) raise
/// `ValueError` carrying the frozen `mcps.*` wire code.
#[pyclass(name = "CorrelationStore")]
struct PyCorrelationStore {
    inner: CorrelationStore,
}

#[pymethods]
impl PyCorrelationStore {
    #[new]
    fn new() -> Self {
        PyCorrelationStore {
            inner: CorrelationStore::new(),
        }
    }

    /// The number of currently-outstanding requests.
    #[getter]
    fn outstanding(&self) -> usize {
        self.inner.outstanding()
    }

    /// Register an outstanding request at `now_unix`. Fails closed on a duplicate
    /// correlation id or a nonce still within a prior use's window.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        *, correlation_id, request_hash, nonce, deadline_unix, now_unix,
        issued_at_unix=0, route_id="", audience="", expected_server_signers=Vec::new(),
        version=None, canonicalization_id=None, authz_digest="",
    ))]
    fn register(
        &mut self,
        correlation_id: &str,
        request_hash: &str,
        nonce: &str,
        deadline_unix: i64,
        now_unix: i64,
        issued_at_unix: i64,
        route_id: &str,
        audience: &str,
        expected_server_signers: Vec<String>,
        version: Option<&str>,
        canonicalization_id: Option<&str>,
        authz_digest: &str,
    ) -> PyResult<()> {
        let pending = PendingRequest {
            correlation_id: correlation_id.to_string(),
            request_hash: request_hash.to_string(),
            nonce: nonce.to_string(),
            issued_at_unix,
            deadline_unix,
            route_id: route_id.to_string(),
            audience: audience.to_string(),
            expected_server_signers,
            version: version.unwrap_or(mcps_core::VERSION_DRAFT_02).to_string(),
            canonicalization_id: canonicalization_id
                .unwrap_or(mcps_core::CANONICALIZATION_ID_INT53_V1)
                .to_string(),
            authz_digest: authz_digest.to_string(),
        };
        self.inner.register(pending, now_unix).map_err(corr_err)
    }

    /// Correlate an incoming response by `correlation_id` at `now_unix`, removing and
    /// returning the pending entry (cleanup-on-completion). A late/uncorrelatable or
    /// past-deadline response fails closed.
    fn take_for_response(&mut self, correlation_id: &str, now_unix: i64) -> PyResult<PyPendingEntry> {
        self.inner
            .take_for_response(correlation_id, now_unix)
            .map(PyPendingEntry::from_pending)
            .map_err(corr_err)
    }

    /// Cancel an outstanding request; returns whether an entry was present.
    fn cancel(&mut self, correlation_id: &str) -> bool {
        self.inner.cancel(correlation_id).is_some()
    }

    /// Periodic expiry sweep at `now_unix`; returns how many pending entries were dropped.
    fn sweep_expired(&mut self, now_unix: i64) -> usize {
        self.inner.sweep_expired(now_unix)
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(canonicalization_id, m)?)?;
    m.add_function(wrap_pyfunction!(response_meta_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PySigner>()?;
    m.add_class::<PySignerPolicy>()?;
    m.add_class::<PyTrustResolver>()?;
    m.add_class::<PyVerifyResult>()?;
    m.add_class::<PyCorrelationStore>()?;
    m.add_class::<PyPendingEntry>()?;
    Ok(())
}
