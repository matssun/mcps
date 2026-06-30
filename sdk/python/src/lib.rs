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
    build_signed_request, build_signed_request_with_signer, ClientSigner, CustodyClass,
    DevFileSigner, Environment, RequestSigningInputs, SignerPolicy, SoftwareSigner,
};
use mcps_core::{AuthorizationBinding, McpsError, SigningKey};
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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(canonicalization_id, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request_with_signer, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PySigner>()?;
    m.add_class::<PySignerPolicy>()?;
    Ok(())
}
