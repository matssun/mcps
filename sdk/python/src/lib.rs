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

use mcps_client_core::authz::{
    binding_tag, AuthorizationBindingPolicy, AuthorizationBindingProvider, BindingRequestContext,
    BindingTypeTag, OpaqueBytesProvider,
};
use mcps_client_core::{
    audit_for_decision, build_signed_request, build_signed_request_with_signer,
    classify_response_result, decide, verify_and_classify_response, AbsenceReason, ClientOutcome,
    ClientPath, ClientSigner, CorrelationError, CorrelationStore, CustodyClass, DevFileSigner,
    EnforcementDecision, EnforcementMode, Environment, PendingRequest, RequestSigningInputs,
    ResponseExpectation, SignerPolicy, SoftwareSigner,
};
use mcps_core::ids::{
    BINDING_TYPE_AUTHZ_SYSTEM_REFERENCE, BINDING_TYPE_OPAQUE_BYTES, DIGEST_ALG_SHA256,
};
use mcps_core::{
    build_mcp_mrt_continuation, AuthorizationBinding, InMemoryTrustResolver, McpsError,
    ResultClass, SigningKey, VerificationKey,
};
use serde_json::{Map, Value};

// --- shared helpers --------------------------------------------------------

/// Map a core error to a Python exception (kept inside the frozen wire taxonomy).
fn to_py_err(e: McpsError) -> PyErr {
    PyValueError::new_err(format!("mcps-client-core: {e:?}"))
}

fn parse_id(id_json: &str) -> PyResult<Value> {
    serde_json::from_str(id_json)
        .map_err(|e| PyValueError::new_err(format!("invalid id_json: {e}")))
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

/// Attach an ADR-MCPS-047 continuation binding to signing inputs when both hashes
/// are supplied (the answer leg of a multi-round-trip). Supplying exactly one is a
/// caller error — a continuation binds BOTH the previous request and the verified
/// `InputRequiredResult`.
fn apply_continuation(
    inputs: RequestSigningInputs,
    previous_request_hash: Option<&str>,
    input_required_response_hash: Option<&str>,
) -> PyResult<RequestSigningInputs> {
    match (previous_request_hash, input_required_response_hash) {
        (Some(prev), Some(resp)) => {
            Ok(inputs.with_continuation(build_mcp_mrt_continuation(prev, resp)))
        }
        (None, None) => Ok(inputs),
        _ => Err(PyValueError::new_err(
            "continuation requires BOTH continuation_previous_request_hash and \
             continuation_input_required_response_hash",
        )),
    }
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
    Delegated(DelegatedSigner),
}

/// A NON-EXPORTING signer (custody class `NonExporting`): the private key lives in
/// an external device (HSM / KMS / remote signer) and NEVER enters the SDK. Signing
/// is delegated to a Python callback `preimage_bytes -> base64url_no_pad_signature`;
/// this struct holds only that callback, so there is nothing to export. A callback
/// that raises or returns a non-string fails closed (`mcps.actor_binding_failed`) —
/// a signer that cannot sign never yields a placeholder.
struct DelegatedSigner {
    signer_id: String,
    key_id: String,
    sign_cb: Py<PyAny>,
}

impl ClientSigner for DelegatedSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn custody(&self) -> CustodyClass {
        CustodyClass::NonExporting
    }
    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
        Python::with_gil(|py| {
            let arg = PyBytes::new(py, preimage);
            let out = self
                .sign_cb
                .call1(py, (arg,))
                .map_err(|_| McpsError::ActorBindingFailed)?;
            out.extract::<String>(py)
                .map_err(|_| McpsError::ActorBindingFailed)
        })
    }
}

/// A client signing identity (the custody seam). Construct via [`Signer::software`]
/// (a held-private software key — acceptable in production), [`Signer::dev_file`]
/// (an unprotected dev/test key — rejected under production `require_mcps`), or
/// [`Signer::non_exporting`] (custody `NonExporting`, the hardening profile — signs
/// via an external device, the only class [`SignerPolicy::require_non_exporting`]
/// accepts).
#[pyclass(name = "Signer", frozen)]
struct PySigner {
    kind: SignerKind,
}

impl PySigner {
    fn as_dyn(&self) -> &dyn ClientSigner {
        match &self.kind {
            SignerKind::Software(s) => s,
            SignerKind::DevFile(s) => s,
            SignerKind::Delegated(s) => s,
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

    /// NON-EXPORTING signer (custody class `NonExporting`, the hardening profile):
    /// the key lives in an external device and never enters the SDK. `sign_callback`
    /// is a callable `preimage_bytes -> base64url-no-pad signature str` (e.g. a
    /// `SigningDevice.sign` bound method, or a KMS/HSM client call). This is the only
    /// custody class a `require_non_exporting()` policy accepts.
    #[staticmethod]
    #[pyo3(signature = (*, signer_id, key_id, sign_callback))]
    fn non_exporting(signer_id: &str, key_id: &str, sign_callback: Py<PyAny>) -> Self {
        PySigner {
            kind: SignerKind::Delegated(DelegatedSigner {
                signer_id: signer_id.to_string(),
                key_id: key_id.to_string(),
                sign_cb: sign_callback,
            }),
        }
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

/// A signing device that ENCAPSULATES a key: it holds the private key internally
/// and exposes ONLY a sign operation — there is no getter, so the key can never be
/// read back out. This is the HSM/KMS stand-in for the non-exporting custody path:
/// provision it (here from a seed; in production it wraps a device/KMS handle) and
/// hand its [`sign`](Self::sign) to [`Signer::non_exporting`]. The Ed25519 signing is
/// the audited core path (a `SoftwareSigner` held privately, scrubbed on drop).
#[pyclass(name = "SigningDevice", frozen)]
struct PySigningDevice {
    inner: SoftwareSigner,
}

#[pymethods]
impl PySigningDevice {
    /// Provision a device holding the key derived from `seed` (32 bytes). The seed is
    /// consumed into the device and never exposed again — modelling key provisioning
    /// into hardware. A real deployment constructs the device from a KMS/HSM handle
    /// instead of a seed.
    #[staticmethod]
    #[pyo3(signature = (seed, *, signer_id, key_id))]
    fn from_seed(seed: &[u8], signer_id: &str, key_id: &str) -> PyResult<Self> {
        Ok(PySigningDevice {
            inner: SoftwareSigner::new(seed_to_key(seed)?, signer_id, key_id),
        })
    }

    /// The device signing operation: Ed25519-sign `preimage` with the device-held
    /// key, returning the base64url-no-pad signature. The key never leaves the device.
    fn sign(&self, preimage: &[u8]) -> PyResult<String> {
        self.inner.sign_preimage(preimage).map_err(to_py_err)
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
    nonce, issued_at, expires_at, seed,
    authorization_binding=None, binding_digest_alg=None, binding_digest_value=None,
    continuation_previous_request_hash=None, continuation_input_required_response_hash=None,
))]
fn sign_request(
    id_json: &str,
    method: &str,
    params_json: &str,
    signer: &str,
    key_id: &str,
    on_behalf_of: &str,
    audience: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    seed: &[u8],
    authorization_binding: Option<PyRef<'_, PyAuthorizationBinding>>,
    binding_digest_alg: Option<&str>,
    binding_digest_value: Option<&str>,
    continuation_previous_request_hash: Option<&str>,
    continuation_input_required_response_hash: Option<&str>,
) -> PyResult<PySignedRequest> {
    let id = parse_id(id_json)?;
    let params = parse_params(params_json)?;
    let key = seed_to_key(seed)?;
    let binding = resolve_binding(
        authorization_binding,
        binding_digest_alg,
        binding_digest_value,
    )?;
    let inputs = RequestSigningInputs::with_default_canonicalization(
        signer,
        key_id,
        on_behalf_of,
        audience,
        binding,
        nonce,
        issued_at,
        expires_at,
    );
    let inputs = apply_continuation(
        inputs,
        continuation_previous_request_hash,
        continuation_input_required_response_hash,
    )?;
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
    nonce, issued_at, expires_at, signer, policy,
    authorization_binding=None, binding_digest_alg=None, binding_digest_value=None,
    continuation_previous_request_hash=None, continuation_input_required_response_hash=None,
))]
fn sign_request_with_signer(
    id_json: &str,
    method: &str,
    params_json: &str,
    on_behalf_of: &str,
    audience: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    signer: PyRef<'_, PySigner>,
    policy: PyRef<'_, PySignerPolicy>,
    authorization_binding: Option<PyRef<'_, PyAuthorizationBinding>>,
    binding_digest_alg: Option<&str>,
    binding_digest_value: Option<&str>,
    continuation_previous_request_hash: Option<&str>,
    continuation_input_required_response_hash: Option<&str>,
) -> PyResult<PySignedRequest> {
    let id = parse_id(id_json)?;
    let params = parse_params(params_json)?;
    let binding = resolve_binding(
        authorization_binding,
        binding_digest_alg,
        binding_digest_value,
    )?;
    let s = signer.as_dyn();
    // signer/key_id here are overridden from the signer by the core; pass the
    // signer's identity for a faithful (non-misleading) inputs value.
    let inputs = RequestSigningInputs::with_default_canonicalization(
        s.signer_id(),
        s.key_id(),
        on_behalf_of,
        audience,
        binding,
        nonce,
        issued_at,
        expires_at,
    );
    let inputs = apply_continuation(
        inputs,
        continuation_previous_request_hash,
        continuation_input_required_response_hash,
    )?;
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
    fn insert_public_key(
        &mut self,
        signer_id: &str,
        key_id: &str,
        public_key: &[u8],
    ) -> PyResult<()> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "public_key must be exactly 32 bytes, got {}",
                public_key.len()
            ))
        })?;
        self.inner.insert(
            signer_id,
            key_id,
            VerificationKey::from_bytes(&pk).map_err(to_py_err)?,
        );
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
    /// ADR-MCPS-047 classification of the SIGNED result body: "terminal" or
    /// "input_required". Read only from verified bytes; "terminal" when unverified.
    #[pyo3(get)]
    result_class: &'static str,
    /// The verified response preimage hash (`sha256:<b64url>`) on a verified
    /// exchange; else `None`. When `result_class == "input_required"` this is the
    /// `continuation_input_required_response_hash` to pass to `sign_request` for the
    /// answer leg (with the original `request_hash` as the previous hash).
    #[pyo3(get)]
    response_hash: Option<String>,
    /// Convenience: true iff `result_class == "input_required"`.
    #[pyo3(get)]
    input_required: bool,
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

    let classified = verify_and_classify_response(raw_bytes, &resolver.inner, &expectation);
    // Capture the verified identity + multi-round-trip classification before the
    // value is moved into the outcome.
    let verified = classified.as_ref().ok().map(|c| {
        (
            c.verified.server_signer().to_string(),
            c.verified.key_id().to_string(),
            c.verified.request_hash().to_string(),
        )
    });
    let (result_class, response_hash) = match classified.as_ref().ok() {
        Some(c) => (
            match c.class {
                ResultClass::Terminal => "terminal",
                ResultClass::InputRequired => "input_required",
            },
            Some(c.response_hash.clone()),
        ),
        None => ("terminal", None),
    };

    let outcome = classify_response_result(classified.map(|c| c.verified));
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
        result_class,
        response_hash,
        input_required: result_class == "input_required",
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
    fn take_for_response(
        &mut self,
        correlation_id: &str,
        now_unix: i64,
    ) -> PyResult<PyPendingEntry> {
        self.inner
            .take_for_response(correlation_id, now_unix)
            .map(PyPendingEntry::from_pending)
            .map_err(corr_err)
    }

    /// Read an outstanding request's state WITHOUT consuming it (same existence +
    /// deadline gate as `take_for_response`). The multi-round-trip flow peeks the
    /// expected `request_hash` before classifying a response as terminal vs
    /// `InputRequiredResult`, then consumes via `take_for_response` (terminal) or
    /// `record_input_required` (non-terminal).
    fn peek_for_response(
        &mut self,
        correlation_id: &str,
        now_unix: i64,
    ) -> PyResult<PyPendingEntry> {
        self.inner
            .peek_for_response(correlation_id, now_unix)
            .map(PyPendingEntry::from_pending)
            .map_err(corr_err)
    }

    /// Correlate a verified, NON-TERMINAL `InputRequiredResult` (ADR-MCPS-047 / D7 —
    /// associate-without-consume). Consumes the original response slot but retains
    /// the exchange, and returns the continuation binding as a
    /// `(previous_request_hash, input_required_response_hash)` tuple — pass these to
    /// `sign_request(..., continuation_previous_request_hash=...,
    /// continuation_input_required_response_hash=...)` to sign the answer leg.
    /// `input_required_response_hash` is `VerifyResult.response_hash` from the
    /// verified elicitation. Fails closed exactly like `take_for_response`.
    fn record_input_required(
        &mut self,
        correlation_id: &str,
        input_required_response_hash: &str,
        now_unix: i64,
    ) -> PyResult<(String, String)> {
        let continuation = self
            .inner
            .record_input_required(correlation_id, input_required_response_hash, now_unix)
            .map_err(corr_err)?;
        match continuation {
            mcps_core::Continuation::McpMrt {
                previous_request_hash,
                input_required_response_hash,
            } => Ok((previous_request_hash, input_required_response_hash)),
        }
    }

    /// The number of non-terminal multi-round-trip records awaiting a continuation.
    #[getter]
    fn non_terminal_outstanding(&self) -> usize {
        self.inner.non_terminal_outstanding()
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

// --- authorization binding (MCPS-45) ---------------------------------------

/// A typed authorization-evidence binding bound into the signed request preimage
/// (bind-not-interpret). Built through the AUDITED `mcps-client-core` providers so
/// the digest is computed in one place — never a caller-supplied magic constant.
#[pyclass(name = "AuthorizationBinding")]
#[derive(Clone)]
struct PyAuthorizationBinding {
    inner: AuthorizationBinding,
}

#[pymethods]
impl PyAuthorizationBinding {
    /// `opaque-bytes`: bind the EXACT decoded authorization-artifact bytes (e.g. a
    /// bearer token / capability already base64url-decoded off the transport). The
    /// digest is `base64url-no-pad(SHA-256(bytes))`, computed by the audited
    /// `OpaqueBytesProvider` — not passed in.
    #[staticmethod]
    fn opaque_bytes(artifact_bytes: &[u8]) -> PyResult<Self> {
        // The opaque form's digest is over the bytes alone; the request context is
        // not consulted, so a zeroed context is faithful here.
        let ctx = BindingRequestContext {
            audience: "",
            route_id: "",
            method: None,
            tool_id: None,
            deadline_unix: 0,
        };
        let inner = OpaqueBytesProvider::new(artifact_bytes.to_vec())
            .provide(&ctx)
            .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// `authz-system-reference`: bind an external authorization system's
    /// self-contained `digest_value` plus its cross-audit reference. The digest is
    /// produced by the authz system (the SDK binds, never interprets it).
    #[staticmethod]
    fn authz_system_reference(
        authorization_system_id: &str,
        reference_scheme_id: &str,
        reference_value: &str,
        digest_value: &str,
    ) -> Self {
        Self {
            inner: AuthorizationBinding::AuthzSystemReference {
                authorization_system_id: authorization_system_id.to_string(),
                reference_scheme_id: reference_scheme_id.to_string(),
                reference_value: reference_value.to_string(),
                digest_alg: DIGEST_ALG_SHA256.to_string(),
                digest_value: digest_value.to_string(),
            },
        }
    }

    /// The base-form tag (`opaque-bytes` / `authz-system-reference`).
    #[getter]
    fn binding_type(&self) -> &'static str {
        match &self.inner {
            AuthorizationBinding::OpaqueBytes { .. } => BINDING_TYPE_OPAQUE_BYTES,
            AuthorizationBinding::AuthzSystemReference { .. } => {
                BINDING_TYPE_AUTHZ_SYSTEM_REFERENCE
            }
        }
    }

    #[getter]
    fn digest_alg(&self) -> String {
        match &self.inner {
            AuthorizationBinding::OpaqueBytes { digest_alg, .. }
            | AuthorizationBinding::AuthzSystemReference { digest_alg, .. } => digest_alg.clone(),
        }
    }

    #[getter]
    fn digest_value(&self) -> String {
        match &self.inner {
            AuthorizationBinding::OpaqueBytes { digest_value, .. }
            | AuthorizationBinding::AuthzSystemReference { digest_value, .. } => {
                digest_value.clone()
            }
        }
    }

    /// The authz-system namespace (reference form only; `None` for opaque-bytes).
    #[getter]
    fn authorization_system_id(&self) -> Option<String> {
        match &self.inner {
            AuthorizationBinding::AuthzSystemReference {
                authorization_system_id,
                ..
            } => Some(authorization_system_id.clone()),
            _ => None,
        }
    }

    /// The authz-system reference handle (reference form only).
    #[getter]
    fn reference_value(&self) -> Option<String> {
        match &self.inner {
            AuthorizationBinding::AuthzSystemReference {
                reference_value, ..
            } => Some(reference_value.clone()),
            _ => None,
        }
    }
}

/// Per-route policy: which authorization-binding base forms a route permits
/// (mirrors `mcps-client-core::authz::AuthorizationBindingPolicy`). A binding of a
/// non-permitted type fails closed with `mcps.authorization_binding_type_unsupported`.
#[pyclass(name = "AuthorizationBindingPolicy")]
#[derive(Clone)]
struct PyAuthorizationBindingPolicy {
    inner: AuthorizationBindingPolicy,
}

#[pymethods]
impl PyAuthorizationBindingPolicy {
    /// Permit both base forms (the common v0.6 default).
    #[staticmethod]
    fn both_base_forms() -> Self {
        Self {
            inner: AuthorizationBindingPolicy::both_base_forms(),
        }
    }

    /// Permit only `opaque-bytes`.
    #[staticmethod]
    fn opaque_only() -> Self {
        Self {
            inner: AuthorizationBindingPolicy::new([BindingTypeTag::OpaqueBytes]),
        }
    }

    /// Permit only `authz-system-reference`.
    #[staticmethod]
    fn reference_only() -> Self {
        Self {
            inner: AuthorizationBindingPolicy::new([BindingTypeTag::AuthzSystemReference]),
        }
    }

    /// A deliberately closed route: permit nothing (every binding is rejected).
    #[staticmethod]
    fn closed() -> Self {
        Self {
            inner: AuthorizationBindingPolicy::new([]),
        }
    }

    /// Whether this policy permits `binding`'s base form.
    fn permits(&self, binding: &PyAuthorizationBinding) -> bool {
        self.inner.permits(binding_tag(&binding.inner))
    }

    /// Fail closed (`mcps.authorization_binding_type_unsupported`) if `binding`'s
    /// base form is not permitted on this route; otherwise return `None`.
    fn enforce(&self, binding: &PyAuthorizationBinding) -> PyResult<()> {
        if self.inner.permits(binding_tag(&binding.inner)) {
            Ok(())
        } else {
            Err(PyValueError::new_err(
                McpsError::AuthorizationBindingTypeUnsupported
                    .wire_code()
                    .to_string(),
            ))
        }
    }
}

/// Resolve the binding to embed: EITHER a provider-built [`PyAuthorizationBinding`]
/// (the real path) OR the raw `digest_alg`/`digest_value` opaque shortcut (dev/test
/// — kept so existing golden vectors stay byte-identical). Exactly one must be given.
fn resolve_binding(
    binding: Option<PyRef<'_, PyAuthorizationBinding>>,
    digest_alg: Option<&str>,
    digest_value: Option<&str>,
) -> PyResult<AuthorizationBinding> {
    match (binding, digest_alg, digest_value) {
        (Some(b), None, None) => Ok(b.inner.clone()),
        (None, Some(alg), Some(value)) => Ok(opaque_binding(alg, value)),
        (None, None, None) => Err(PyValueError::new_err(
            "an authorization binding is required: pass authorization_binding= (a \
             provider-built AuthorizationBinding) or binding_digest_alg=/binding_digest_value= \
             (the dev/test opaque shortcut)",
        )),
        _ => Err(PyValueError::new_err(
            "pass EITHER authorization_binding= OR binding_digest_alg=/binding_digest_value=, \
             not both",
        )),
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
    m.add_class::<PySigningDevice>()?;
    m.add_class::<PySignerPolicy>()?;
    m.add_class::<PyTrustResolver>()?;
    m.add_class::<PyVerifyResult>()?;
    m.add_class::<PyCorrelationStore>()?;
    m.add_class::<PyPendingEntry>()?;
    m.add_class::<PyAuthorizationBinding>()?;
    m.add_class::<PyAuthorizationBindingPolicy>()?;
    Ok(())
}
