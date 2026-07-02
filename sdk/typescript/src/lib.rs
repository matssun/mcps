//! `mcps-sdk-core` — the napi-rs native addon for the MCP-S TypeScript SDK.
//!
//! ADR-MCPS-044 (SDK wrap-or-fork rule) + ADR-MCPS-047 (v0.8 continuation). The
//! transport-adapter verdict means the TypeScript SDK owns serialization at the byte
//! boundary and delegates ALL security logic here, to the audited `mcps-client-core`.
//! This is the exact analog of the Python SDK's PyO3 binding (`sdk/python/src/lib.rs`)
//! — same audited core, same canonical signed preimage, byte-identical wire.
//!
//! napi maps snake_case Rust to camelCase JS (`core_version` -> `coreVersion`,
//! `sign_request` -> `signRequest`); option structs (`#[napi(object)]`) mirror
//! Python's keyword-only arguments. A fail-closed *verification* is a RESULT
//! (`VerifyResult`), never a thrown error; malformed *inputs* and custody/correlation
//! failures throw an `Error` whose message carries the frozen `mcps.*` wire code.

#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::{Buffer, Function, FunctionRef};
use napi::{Env, Error, Result, Status};

use mcps_client_core::authz::{
    binding_tag, AuthorizationBindingPolicy as CoreBindingPolicy, AuthorizationBindingProvider,
    BindingRequestContext, BindingTypeTag, OpaqueBytesProvider,
};
use mcps_client_core::{
    audit_for_decision, build_signed_request, build_signed_request_with_signer,
    classify_response_result, decide, verify_and_classify_response, AbsenceReason, ClientOutcome,
    ClientPath, ClientSigner, CorrelationError, CorrelationStore as CoreCorrelationStore,
    CustodyClass, DevFileSigner, EnforcementDecision, EnforcementMode, Environment,
    PendingRequest as CorePendingRequest, RequestSigningInputs, ResponseExpectation,
    SignerPolicy as CoreSignerPolicy, SoftwareSigner,
};
use mcps_core::ids::{
    BINDING_TYPE_AUTHZ_SYSTEM_REFERENCE, BINDING_TYPE_OPAQUE_BYTES, DIGEST_ALG_SHA256,
};
use mcps_core::{
    build_mcp_mrt_continuation, AuthorizationBinding as CoreAuthorizationBinding,
    Continuation as CoreContinuation, InMemoryTrustResolver, McpsError, ResultClass, SigningKey,
    VerificationKey,
};
use serde_json::{Map, Value};

// --- shared helpers --------------------------------------------------------

/// Map a core error to a JS `Error` (kept inside the frozen wire taxonomy — the
/// `{:?}` form carries the variant name, e.g. `ActorBindingFailed`).
fn to_js_err(e: McpsError) -> Error {
    Error::new(Status::GenericFailure, format!("mcps-client-core: {e:?}"))
}

/// A JS `Error` with a plain message (invalid-argument style, mirrors PyValueError).
fn value_err(msg: impl Into<String>) -> Error {
    Error::new(Status::InvalidArg, msg.into())
}

fn parse_id(id_json: &str) -> Result<Value> {
    serde_json::from_str(id_json).map_err(|e| value_err(format!("invalid id_json: {e}")))
}

fn parse_params(params_json: &str) -> Result<Map<String, Value>> {
    serde_json::from_str(params_json)
        .map_err(|e| value_err(format!("params_json must be a JSON object: {e}")))
}

fn seed_to_key(seed: &[u8]) -> Result<SigningKey> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| value_err(format!("seed must be exactly 32 bytes, got {}", seed.len())))?;
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
) -> Result<RequestSigningInputs> {
    match (previous_request_hash, input_required_response_hash) {
        (Some(prev), Some(resp)) => {
            Ok(inputs.with_continuation(build_mcp_mrt_continuation(prev, resp)))
        }
        (None, None) => Ok(inputs),
        _ => Err(value_err(
            "continuation requires BOTH continuationPreviousRequestHash and \
             continuationInputRequiredResponseHash",
        )),
    }
}

fn opaque_binding(digest_alg: &str, digest_value: &str) -> CoreAuthorizationBinding {
    CoreAuthorizationBinding::OpaqueBytes {
        digest_alg: digest_alg.to_string(),
        digest_value: digest_value.to_string(),
    }
}

fn parse_env(s: &str) -> Result<Environment> {
    match s {
        "production" => Ok(Environment::Production),
        "dev-test" | "dev_test" | "devtest" => Ok(Environment::DevTest),
        other => Err(value_err(format!(
            "environment must be 'production' or 'dev-test', got {other:?}"
        ))),
    }
}

fn parse_mode(s: &str) -> Result<EnforcementMode> {
    match s {
        "require_mcps" => Ok(EnforcementMode::RequireMcps),
        "allow_legacy_explicit" => Ok(EnforcementMode::AllowLegacyExplicit),
        other => Err(value_err(format!(
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

/// Map a correlation failure to a JS `Error` carrying its frozen wire code (no
/// parallel taxonomy: dup/nonce -> replay, uncorrelatable -> response-hash mismatch,
/// expired -> expired request).
fn corr_err(e: CorrelationError) -> Error {
    value_err(format!(
        "mcps-client-core correlation: {}",
        e.to_mcps_error().wire_code()
    ))
}

// --- protocol constants ----------------------------------------------------

/// The MCP-S protocol version this core verifies/signs against (draft-02).
#[napi]
pub fn core_version() -> &'static str {
    mcps_core::VERSION_DRAFT_02
}

/// The canonicalization id of the signed preimage the SDK reproduces exactly.
#[napi]
pub fn canonicalization_id() -> &'static str {
    mcps_core::CANONICALIZATION_ID_INT53_V1
}

/// The `params._meta` / `result._meta` key under which the MCP-S response envelope
/// lives — the adapter strips it before handing a plain response up to the app.
#[napi]
pub fn response_meta_key() -> &'static str {
    mcps_core::RESPONSE_META_KEY
}

// --- signed request --------------------------------------------------------

/// A signed draft-02 request crossing the binding: the exact wire bytes plus the
/// `request_hash` that binds the eventual response. Mirrors the Rust `SignedRequest`.
#[napi(object)]
pub struct SignedRequest {
    /// The exact JSON-RPC wire bytes to send (canonical signed preimage + signature).
    pub wire_bytes: Buffer,
    /// `sha256:<b64url-no-pad>` of the signed preimage — hold it to bind the response.
    pub request_hash: String,
}

impl SignedRequest {
    fn from_core(signed: mcps_client_core::SignedRequest) -> Self {
        SignedRequest {
            wire_bytes: signed.wire_bytes().to_vec().into(),
            request_hash: signed.request_hash().to_string(),
        }
    }
}

// --- custody: signer + policy ----------------------------------------------

enum SignerKind {
    Software(SoftwareSigner),
    DevFile(DevFileSigner),
    Delegated {
        signer_id: String,
        key_id: String,
        cb: FunctionRef<Buffer, String>,
    },
}

/// A transient non-exporting signer, live only for the duration of one signing call.
/// The private key lives in an external device (HSM / KMS / remote signer) and NEVER
/// enters the SDK; signing is delegated to the JS callback borrowed back with the
/// call's `Env`. A callback that throws or returns a non-string fails closed
/// (`mcps.actor_binding_failed`) — a signer that cannot sign never yields a
/// placeholder.
struct DelegatedCall<'a> {
    signer_id: &'a str,
    key_id: &'a str,
    func: Function<'a, Buffer, String>,
}

impl ClientSigner for DelegatedCall<'_> {
    fn signer_id(&self) -> &str {
        self.signer_id
    }
    fn key_id(&self) -> &str {
        self.key_id
    }
    fn custody(&self) -> CustodyClass {
        CustodyClass::NonExporting
    }
    fn sign_preimage(&self, preimage: &[u8]) -> std::result::Result<String, McpsError> {
        self.func
            .call(preimage.to_vec().into())
            .map_err(|_| McpsError::ActorBindingFailed)
    }
}

/// A client signing identity (the custody seam). Construct via `Signer.software`
/// (a held-private software key — acceptable in production), `Signer.devFile` (an
/// unprotected dev/test key — rejected under production `require_mcps`), or
/// `Signer.nonExporting` (custody `NonExporting`, the hardening profile — signs via
/// an external device, the only class `SignerPolicy.requireNonExporting` accepts).
#[napi]
pub struct Signer {
    kind: SignerKind,
}

impl Signer {
    fn identity(&self) -> (&str, &str) {
        match &self.kind {
            SignerKind::Software(s) => (s.signer_id(), s.key_id()),
            SignerKind::DevFile(s) => (s.signer_id(), s.key_id()),
            SignerKind::Delegated {
                signer_id, key_id, ..
            } => (signer_id, key_id),
        }
    }
}

#[napi]
impl Signer {
    /// In-process software signer (custody class software-held-private).
    #[napi(factory)]
    pub fn software(seed: Buffer, signer_id: String, key_id: String) -> Result<Self> {
        Ok(Signer {
            kind: SignerKind::Software(SoftwareSigner::new(
                seed_to_key(&seed)?,
                &signer_id,
                &key_id,
            )),
        })
    }

    /// Unprotected dev/test file signer (rejected under production `require_mcps`).
    #[napi(factory)]
    pub fn dev_file(seed: Buffer, signer_id: String, key_id: String) -> Result<Self> {
        Ok(Signer {
            kind: SignerKind::DevFile(DevFileSigner::new(seed_to_key(&seed)?, &signer_id, &key_id)),
        })
    }

    /// NON-EXPORTING signer (custody class `NonExporting`, the hardening profile): the
    /// key lives in an external device and never enters the SDK. `signCallback` is a
    /// callable `(preimage: Buffer) -> base64url-no-pad signature string` (e.g. a
    /// `SigningDevice.sign` bound method, or a KMS/HSM client call). This is the only
    /// custody class a `requireNonExporting()` policy accepts. Called SYNCHRONOUSLY on
    /// the Node main thread during signing.
    #[napi(factory)]
    pub fn non_exporting(
        signer_id: String,
        key_id: String,
        sign_callback: Function<Buffer, String>,
    ) -> Result<Self> {
        Ok(Signer {
            kind: SignerKind::Delegated {
                signer_id,
                key_id,
                cb: sign_callback.create_ref()?,
            },
        })
    }

    #[napi(getter)]
    pub fn signer_id(&self) -> String {
        self.identity().0.to_string()
    }

    #[napi(getter)]
    pub fn key_id(&self) -> String {
        self.identity().1.to_string()
    }

    #[napi(getter)]
    pub fn custody(&self) -> &'static str {
        let class = match &self.kind {
            SignerKind::Software(_) => CustodyClass::SoftwareHeldPrivate,
            SignerKind::DevFile(_) => CustodyClass::DevFileUnprotected,
            SignerKind::Delegated { .. } => CustodyClass::NonExporting,
        };
        match class {
            CustodyClass::NonExporting => "non-exporting",
            CustodyClass::SoftwareHeldPrivate => "software-held-private",
            CustodyClass::DevFileUnprotected => "dev-file-unprotected",
        }
    }
}

/// A signing device that ENCAPSULATES a key: it holds the private key internally and
/// exposes ONLY a sign operation — there is no getter, so the key can never be read
/// back out. This is the HSM/KMS stand-in for the non-exporting custody path:
/// provision it (here from a seed; in production it wraps a device/KMS handle) and
/// hand its `sign` to `Signer.nonExporting`. The Ed25519 signing is the audited core
/// path (a `SoftwareSigner` held privately, scrubbed on drop).
#[napi]
pub struct SigningDevice {
    inner: SoftwareSigner,
}

#[napi]
impl SigningDevice {
    /// Provision a device holding the key derived from `seed` (32 bytes). The seed is
    /// consumed into the device and never exposed again — modelling key provisioning
    /// into hardware. A real deployment constructs the device from a KMS/HSM handle.
    #[napi(factory)]
    pub fn from_seed(seed: Buffer, signer_id: String, key_id: String) -> Result<Self> {
        Ok(SigningDevice {
            inner: SoftwareSigner::new(seed_to_key(&seed)?, &signer_id, &key_id),
        })
    }

    /// The device signing operation: Ed25519-sign `preimage` with the device-held key,
    /// returning the base64url-no-pad signature. The key never leaves the device.
    #[napi]
    pub fn sign(&self, preimage: Buffer) -> Result<String> {
        self.inner.sign_preimage(&preimage).map_err(to_js_err)
    }
}

/// The signer-custody policy for a route/identity (resolved from explicit config).
/// Builder methods return a NEW policy: `new SignerPolicy(...).revokeKeyId(...)`.
#[napi]
pub struct SignerPolicy {
    inner: CoreSignerPolicy,
}

#[napi]
impl SignerPolicy {
    /// Bind `expectedSigner` for `environment` ("production" | "dev-test") and mode.
    #[napi(constructor)]
    pub fn new(expected_signer: String, environment: String, require_mcps: bool) -> Result<Self> {
        Ok(SignerPolicy {
            inner: CoreSignerPolicy::new(&expected_signer, parse_env(&environment)?, require_mcps),
        })
    }

    /// A copy with `keyId` marked revoked (signing through it fails closed).
    #[napi]
    pub fn revoke_key_id(&self, key_id: String) -> SignerPolicy {
        SignerPolicy {
            inner: self.inner.clone().revoke_key_id(&key_id),
        }
    }

    /// A copy requiring the hardening profile (only non-exporting custody accepted).
    #[napi]
    pub fn require_non_exporting(&self) -> SignerPolicy {
        SignerPolicy {
            inner: self.inner.clone().require_non_exporting(),
        }
    }
}

// --- signing entry points --------------------------------------------------

/// The named (keyword-style) options for `signRequest` — mirrors the Python binding's
/// keyword-only arguments. Exactly one authorization form must be supplied: either
/// `authorizationBinding` (a provider-built `AuthorizationBinding`, the real path) or
/// the raw `bindingDigestAlg`/`bindingDigestValue` opaque shortcut (dev/test).
#[napi(object)]
pub struct SignRequestOptions {
    pub signer: String,
    pub key_id: String,
    pub on_behalf_of: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub seed: Buffer,
    pub binding_digest_alg: Option<String>,
    pub binding_digest_value: Option<String>,
    pub continuation_previous_request_hash: Option<String>,
    pub continuation_input_required_response_hash: Option<String>,
}

/// The named options for `signRequestWithSigner` (signer + policy are passed as class
/// arguments; identity comes from the signer, not these options).
#[napi(object)]
pub struct SignWithSignerOptions {
    pub on_behalf_of: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub binding_digest_alg: Option<String>,
    pub binding_digest_value: Option<String>,
    pub continuation_previous_request_hash: Option<String>,
    pub continuation_input_required_response_hash: Option<String>,
}

/// Sign an ordinary MCP request into a draft-02 MCP-S request via the audited
/// `mcps-client-core`, using a raw 32-byte Ed25519 seed (DEV/TEST custody only — no
/// policy gate). For the production custody gate use `signRequestWithSigner`.
#[napi]
pub fn sign_request(
    id_json: String,
    method: String,
    params_json: String,
    options: SignRequestOptions,
    authorization_binding: Option<&AuthorizationBinding>,
) -> Result<SignedRequest> {
    let id = parse_id(&id_json)?;
    let params = parse_params(&params_json)?;
    let key = seed_to_key(&options.seed)?;
    let binding = resolve_binding(
        authorization_binding,
        options.binding_digest_alg.as_deref(),
        options.binding_digest_value.as_deref(),
    )?;
    let inputs = RequestSigningInputs::with_default_canonicalization(
        &options.signer,
        &options.key_id,
        &options.on_behalf_of,
        &options.audience,
        binding,
        &options.nonce,
        &options.issued_at,
        &options.expires_at,
    );
    let inputs = apply_continuation(
        inputs,
        options.continuation_previous_request_hash.as_deref(),
        options.continuation_input_required_response_hash.as_deref(),
    )?;
    let signed = build_signed_request(&id, &method, params, &inputs, &key).map_err(to_js_err)?;
    Ok(SignedRequest::from_core(signed))
}

/// Sign through a `Signer` gated by a `SignerPolicy` — the production custody path
/// (`build_signed_request_with_signer`). Authorizes the signer (identity, revocation,
/// hardening, dev-file-in-production) BEFORE signing and binds the evidence to the
/// signer's actual identity; a custody failure throws.
#[napi]
pub fn sign_request_with_signer(
    env: Env,
    id_json: String,
    method: String,
    params_json: String,
    options: SignWithSignerOptions,
    signer: &Signer,
    policy: &SignerPolicy,
    authorization_binding: Option<&AuthorizationBinding>,
) -> Result<SignedRequest> {
    let id = parse_id(&id_json)?;
    let params = parse_params(&params_json)?;
    let binding = resolve_binding(
        authorization_binding,
        options.binding_digest_alg.as_deref(),
        options.binding_digest_value.as_deref(),
    )?;
    let (sid, kid) = signer.identity();
    // signer/key_id here are overridden from the signer by the core; pass the signer's
    // identity for a faithful (non-misleading) inputs value.
    let inputs = RequestSigningInputs::with_default_canonicalization(
        sid,
        kid,
        &options.on_behalf_of,
        &options.audience,
        binding,
        &options.nonce,
        &options.issued_at,
        &options.expires_at,
    );
    let inputs = apply_continuation(
        inputs,
        options.continuation_previous_request_hash.as_deref(),
        options.continuation_input_required_response_hash.as_deref(),
    )?;
    let signed = match &signer.kind {
        SignerKind::Software(s) => {
            build_signed_request_with_signer(&id, &method, params, &inputs, s, &policy.inner)
        }
        SignerKind::DevFile(s) => {
            build_signed_request_with_signer(&id, &method, params, &inputs, s, &policy.inner)
        }
        SignerKind::Delegated {
            signer_id,
            key_id,
            cb,
        } => {
            let func = cb.borrow_back(&env)?;
            let call = DelegatedCall {
                signer_id,
                key_id,
                func,
            };
            build_signed_request_with_signer(&id, &method, params, &inputs, &call, &policy.inner)
        }
    }
    .map_err(to_js_err)?;
    Ok(SignedRequest::from_core(signed))
}

// --- response verification: trust resolver ---------------------------------

/// The client's trust anchor set for response verification — maps a verified
/// `(server_signer, key_id)` to the PUBLIC verifying key. Response verification
/// consumes public keys only; a verifier never needs private signing material.
#[napi]
pub struct TrustResolver {
    inner: InMemoryTrustResolver,
}

#[napi]
impl TrustResolver {
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        TrustResolver {
            inner: InMemoryTrustResolver::new(),
        }
    }

    /// Register a server signer by its raw 32-byte Ed25519 PUBLIC key. This is the real
    /// verifier input.
    #[napi]
    pub fn insert_public_key(
        &mut self,
        signer_id: String,
        key_id: String,
        public_key: Buffer,
    ) -> Result<()> {
        let pk: [u8; 32] = public_key.as_ref().try_into().map_err(|_| {
            value_err(format!(
                "public_key must be exactly 32 bytes, got {}",
                public_key.len()
            ))
        })?;
        self.inner.insert(
            &signer_id,
            &key_id,
            VerificationKey::from_bytes(&pk).map_err(to_js_err)?,
        );
        Ok(())
    }

    /// DEV/TEST ONLY: register a server signer from a 32-byte SEED, deriving the public
    /// key. This exists solely to make parity vectors byte-identical with the signing
    /// side — verifiers NEVER need private material; production trust config uses
    /// `insertPublicKey`.
    #[napi]
    pub fn insert_dev_seed(
        &mut self,
        signer_id: String,
        key_id: String,
        seed: Buffer,
    ) -> Result<()> {
        self.inner
            .insert(&signer_id, &key_id, seed_to_key(&seed)?.public_key());
        Ok(())
    }
}

/// The structured outcome of `verifyResponse`: the enforcement decision plus the
/// audit-facing path/outcome/reason and (on a verified exchange) the server identity
/// and bound `requestHash`. A fail-closed verification is a RESULT here (with the
/// frozen `mcps.*` wire reason), not a thrown error.
#[napi(object)]
pub struct VerifyResult {
    /// "accept" | "fallback" | "fail-closed".
    pub decision: String,
    /// "mcps-verified" | "legacy-explicit".
    pub path: String,
    /// "accepted" | "fell-back" | "rejected".
    pub outcome: String,
    /// Frozen `McpsError::wire_code()` token on a fail-closed rejection; else null.
    pub reason: Option<String>,
    /// The absence reason that made a legacy fallback eligible (local); else null.
    pub legacy_reason: Option<String>,
    /// The verified server signer (on a verified exchange); else null.
    pub server_signer: Option<String>,
    /// The key id that verified the response (on a verified exchange); else null.
    pub key_id: Option<String>,
    /// The bound `request_hash` (on a verified exchange); else null.
    pub request_hash: Option<String>,
    /// Convenience: true iff the decision was AcceptMcps.
    pub accepted: bool,
    /// ADR-MCPS-047 classification of the SIGNED result body: "terminal" or
    /// "input_required". Read only from verified bytes; "terminal" when unverified.
    pub result_class: String,
    /// The verified response preimage hash (`sha256:<b64url>`) on a verified exchange;
    /// else null. When `resultClass === "input_required"` this is the
    /// `continuationInputRequiredResponseHash` to pass to `signRequest` for the answer
    /// leg (with the original `requestHash` as the previous hash).
    pub response_hash: Option<String>,
    /// Convenience: true iff `resultClass === "input_required"`.
    pub input_required: bool,
}

/// The named options for `verifyResponse` (mirrors Python's keyword arguments).
#[napi(object)]
pub struct VerifyResponseOptions {
    pub expected_request_hash: String,
    pub expected_canonicalization_id: Option<String>,
    pub expected_server_signer: Option<String>,
    /// "require_mcps" (default) | "allow_legacy_explicit".
    pub enforcement_mode: Option<String>,
    pub legacy_allowed: Option<bool>,
}

/// Verify a signed draft-02 response and apply the enforcement decision — the proxy's
/// return-leg pipeline (`verify_signed_response` -> `classify_response_result` ->
/// `decide` -> `audit_for_decision`). Returns a `VerifyResult`; a fail-closed
/// verification is reported there (not thrown). Malformed arguments throw.
#[napi]
pub fn verify_response(
    raw_bytes: Buffer,
    resolver: &TrustResolver,
    options: VerifyResponseOptions,
) -> Result<VerifyResult> {
    let canon = options
        .expected_canonicalization_id
        .as_deref()
        .unwrap_or(mcps_core::CANONICALIZATION_ID_INT53_V1);
    let mut expectation = ResponseExpectation::new(&options.expected_request_hash, canon);
    if let Some(signer) = options.expected_server_signer.as_deref() {
        expectation = expectation.with_expected_server_signer(signer);
    }
    let mode = parse_mode(options.enforcement_mode.as_deref().unwrap_or("require_mcps"))?;
    let legacy_allowed = options.legacy_allowed.unwrap_or(false);

    let classified = verify_and_classify_response(&raw_bytes, &resolver.inner, &expectation);
    // Capture the verified identity + multi-round-trip classification before the value
    // is moved into the outcome.
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

    Ok(VerifyResult {
        decision: decision_str.to_string(),
        path: path.to_string(),
        outcome: outcome_str.to_string(),
        reason: audit.reason.map(|s| s.to_string()),
        legacy_reason: audit.legacy_reason.map(|r| absence_str(r).to_string()),
        server_signer,
        key_id,
        request_hash,
        accepted,
        result_class: result_class.to_string(),
        response_hash,
        input_required: result_class == "input_required",
    })
}

// --- in-flight correlation -------------------------------------------------

/// One outstanding request's retained state, returned by
/// `CorrelationStore.takeForResponse` / `peekForResponse`.
#[napi(object)]
pub struct PendingRequest {
    pub correlation_id: String,
    pub request_hash: String,
    pub nonce: String,
    pub issued_at_unix: i64,
    pub deadline_unix: i64,
    pub route_id: String,
    pub audience: String,
    pub expected_server_signers: Vec<String>,
    pub version: String,
    pub canonicalization_id: String,
    pub authz_digest: String,
}

impl PendingRequest {
    fn from_core(p: CorePendingRequest) -> Self {
        PendingRequest {
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

/// The continuation binding returned by `recordInputRequired` — feed both hashes to
/// `signRequest` (`continuationPreviousRequestHash` / `continuationInputRequiredResponseHash`)
/// to sign the answer leg (ADR-MCPS-047).
#[napi(object)]
pub struct ContinuationBinding {
    pub previous_request_hash: String,
    pub input_required_response_hash: String,
}

/// The named (keyword-style) options for `CorrelationStore.register`.
#[napi(object)]
pub struct RegisterOptions {
    pub correlation_id: String,
    pub request_hash: String,
    pub nonce: String,
    pub deadline_unix: i64,
    pub now_unix: i64,
    pub issued_at_unix: Option<i64>,
    pub route_id: Option<String>,
    pub audience: Option<String>,
    pub expected_server_signers: Option<Vec<String>>,
    pub version: Option<String>,
    pub canonicalization_id: Option<String>,
    pub authz_digest: Option<String>,
}

/// Per-outstanding-request correlation store: binds an outgoing signed request to
/// exactly one acceptable returning response, with nonce-reuse prevention and an
/// expiry sweep. The clock is the caller's: every method takes `nowUnix`. Failures
/// (duplicate id, nonce reuse, late/uncorrelatable, expired) throw an `Error` carrying
/// the frozen `mcps.*` wire code.
#[napi]
pub struct CorrelationStore {
    inner: CoreCorrelationStore,
}

#[napi]
impl CorrelationStore {
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        CorrelationStore {
            inner: CoreCorrelationStore::new(),
        }
    }

    /// The number of currently-outstanding requests.
    #[napi(getter)]
    pub fn outstanding(&self) -> u32 {
        self.inner.outstanding() as u32
    }

    /// Register an outstanding request at `nowUnix`. Fails closed on a duplicate
    /// correlation id or a nonce still within a prior use's window.
    #[napi]
    pub fn register(&mut self, options: RegisterOptions) -> Result<()> {
        let pending = CorePendingRequest {
            correlation_id: options.correlation_id,
            request_hash: options.request_hash,
            nonce: options.nonce,
            issued_at_unix: options.issued_at_unix.unwrap_or(0),
            deadline_unix: options.deadline_unix,
            route_id: options.route_id.unwrap_or_default(),
            audience: options.audience.unwrap_or_default(),
            expected_server_signers: options.expected_server_signers.unwrap_or_default(),
            version: options
                .version
                .unwrap_or_else(|| mcps_core::VERSION_DRAFT_02.to_string()),
            canonicalization_id: options
                .canonicalization_id
                .unwrap_or_else(|| mcps_core::CANONICALIZATION_ID_INT53_V1.to_string()),
            authz_digest: options.authz_digest.unwrap_or_default(),
        };
        self.inner
            .register(pending, options.now_unix)
            .map_err(corr_err)
    }

    /// Correlate an incoming response by `correlationId` at `nowUnix`, removing and
    /// returning the pending entry (cleanup-on-completion). A late/uncorrelatable or
    /// past-deadline response fails closed.
    #[napi]
    pub fn take_for_response(
        &mut self,
        correlation_id: String,
        now_unix: i64,
    ) -> Result<PendingRequest> {
        self.inner
            .take_for_response(&correlation_id, now_unix)
            .map(PendingRequest::from_core)
            .map_err(corr_err)
    }

    /// Read an outstanding request's state WITHOUT consuming it (same existence +
    /// deadline gate as `takeForResponse`). The multi-round-trip flow peeks the
    /// expected `requestHash` before classifying a response as terminal vs
    /// `InputRequiredResult`, then consumes via `takeForResponse` (terminal) or
    /// `recordInputRequired` (non-terminal).
    #[napi]
    pub fn peek_for_response(
        &mut self,
        correlation_id: String,
        now_unix: i64,
    ) -> Result<PendingRequest> {
        self.inner
            .peek_for_response(&correlation_id, now_unix)
            .map(PendingRequest::from_core)
            .map_err(corr_err)
    }

    /// Correlate a verified, NON-TERMINAL `InputRequiredResult` (ADR-MCPS-047 / D7 —
    /// associate-without-consume). Consumes the original response slot but retains the
    /// exchange, and returns the continuation binding — pass its two hashes to
    /// `signRequest` (`continuationPreviousRequestHash` /
    /// `continuationInputRequiredResponseHash`) to sign the answer leg.
    /// `inputRequiredResponseHash` is `VerifyResult.responseHash` from the verified
    /// elicitation. Fails closed exactly like `takeForResponse`.
    #[napi]
    pub fn record_input_required(
        &mut self,
        correlation_id: String,
        input_required_response_hash: String,
        now_unix: i64,
    ) -> Result<ContinuationBinding> {
        let continuation = self
            .inner
            .record_input_required(&correlation_id, &input_required_response_hash, now_unix)
            .map_err(corr_err)?;
        match continuation {
            CoreContinuation::McpMrt {
                previous_request_hash,
                input_required_response_hash,
            } => Ok(ContinuationBinding {
                previous_request_hash,
                input_required_response_hash,
            }),
        }
    }

    /// The number of non-terminal multi-round-trip records awaiting a continuation.
    #[napi(getter)]
    pub fn non_terminal_outstanding(&self) -> u32 {
        self.inner.non_terminal_outstanding() as u32
    }

    /// Cancel an outstanding request; returns whether an entry was present.
    #[napi]
    pub fn cancel(&mut self, correlation_id: String) -> bool {
        self.inner.cancel(&correlation_id).is_some()
    }

    /// Periodic expiry sweep at `nowUnix`; returns how many pending entries were dropped.
    #[napi]
    pub fn sweep_expired(&mut self, now_unix: i64) -> u32 {
        self.inner.sweep_expired(now_unix) as u32
    }
}

// --- authorization binding (MCPS-45) ---------------------------------------

/// A typed authorization-evidence binding bound into the signed request preimage
/// (bind-not-interpret). Built through the AUDITED `mcps-client-core` providers so the
/// digest is computed in one place — never a caller-supplied magic constant.
#[napi]
#[derive(Clone)]
pub struct AuthorizationBinding {
    inner: CoreAuthorizationBinding,
}

#[napi]
impl AuthorizationBinding {
    /// `opaque-bytes`: bind the EXACT decoded authorization-artifact bytes (e.g. a
    /// bearer token / capability already base64url-decoded off the transport). The
    /// digest is `base64url-no-pad(SHA-256(bytes))`, computed by the audited
    /// `OpaqueBytesProvider` — not passed in.
    #[napi(factory)]
    pub fn opaque_bytes(artifact_bytes: Buffer) -> Result<Self> {
        // The opaque form's digest is over the bytes alone; the request context is not
        // consulted, so a zeroed context is faithful here.
        let ctx = BindingRequestContext {
            audience: "",
            route_id: "",
            method: None,
            tool_id: None,
            deadline_unix: 0,
        };
        let inner = OpaqueBytesProvider::new(artifact_bytes.to_vec())
            .provide(&ctx)
            .map_err(to_js_err)?;
        Ok(Self { inner })
    }

    /// `authz-system-reference`: bind an external authorization system's self-contained
    /// `digestValue` plus its cross-audit reference. The digest is produced by the
    /// authz system (the SDK binds, never interprets it).
    #[napi(factory)]
    pub fn authz_system_reference(
        authorization_system_id: String,
        reference_scheme_id: String,
        reference_value: String,
        digest_value: String,
    ) -> Self {
        Self {
            inner: CoreAuthorizationBinding::AuthzSystemReference {
                authorization_system_id,
                reference_scheme_id,
                reference_value,
                digest_alg: DIGEST_ALG_SHA256.to_string(),
                digest_value,
            },
        }
    }

    /// The base-form tag (`opaque-bytes` / `authz-system-reference`).
    #[napi(getter)]
    pub fn binding_type(&self) -> &'static str {
        match &self.inner {
            CoreAuthorizationBinding::OpaqueBytes { .. } => BINDING_TYPE_OPAQUE_BYTES,
            CoreAuthorizationBinding::AuthzSystemReference { .. } => {
                BINDING_TYPE_AUTHZ_SYSTEM_REFERENCE
            }
        }
    }

    #[napi(getter)]
    pub fn digest_alg(&self) -> String {
        match &self.inner {
            CoreAuthorizationBinding::OpaqueBytes { digest_alg, .. }
            | CoreAuthorizationBinding::AuthzSystemReference { digest_alg, .. } => {
                digest_alg.clone()
            }
        }
    }

    #[napi(getter)]
    pub fn digest_value(&self) -> String {
        match &self.inner {
            CoreAuthorizationBinding::OpaqueBytes { digest_value, .. }
            | CoreAuthorizationBinding::AuthzSystemReference { digest_value, .. } => {
                digest_value.clone()
            }
        }
    }

    /// The authz-system namespace (reference form only; null for opaque-bytes).
    #[napi(getter)]
    pub fn authorization_system_id(&self) -> Option<String> {
        match &self.inner {
            CoreAuthorizationBinding::AuthzSystemReference {
                authorization_system_id,
                ..
            } => Some(authorization_system_id.clone()),
            _ => None,
        }
    }

    /// The authz-system reference handle (reference form only).
    #[napi(getter)]
    pub fn reference_value(&self) -> Option<String> {
        match &self.inner {
            CoreAuthorizationBinding::AuthzSystemReference {
                reference_value, ..
            } => Some(reference_value.clone()),
            _ => None,
        }
    }
}

/// Per-route policy: which authorization-binding base forms a route permits (mirrors
/// `mcps-client-core::authz::AuthorizationBindingPolicy`). A binding of a non-permitted
/// type fails closed with `mcps.authorization_binding_type_unsupported`.
#[napi]
#[derive(Clone)]
pub struct AuthorizationBindingPolicy {
    inner: CoreBindingPolicy,
}

#[napi]
impl AuthorizationBindingPolicy {
    /// Permit both base forms (the common v0.6 default).
    #[napi(factory)]
    pub fn both_base_forms() -> Self {
        Self {
            inner: CoreBindingPolicy::both_base_forms(),
        }
    }

    /// Permit only `opaque-bytes`.
    #[napi(factory)]
    pub fn opaque_only() -> Self {
        Self {
            inner: CoreBindingPolicy::new([BindingTypeTag::OpaqueBytes]),
        }
    }

    /// Permit only `authz-system-reference`.
    #[napi(factory)]
    pub fn reference_only() -> Self {
        Self {
            inner: CoreBindingPolicy::new([BindingTypeTag::AuthzSystemReference]),
        }
    }

    /// A deliberately closed route: permit nothing (every binding is rejected).
    #[napi(factory)]
    pub fn closed() -> Self {
        Self {
            inner: CoreBindingPolicy::new([]),
        }
    }

    /// Whether this policy permits `binding`'s base form.
    #[napi]
    pub fn permits(&self, binding: &AuthorizationBinding) -> bool {
        self.inner.permits(binding_tag(&binding.inner))
    }

    /// Fail closed (`mcps.authorization_binding_type_unsupported`) if `binding`'s base
    /// form is not permitted on this route; otherwise return.
    #[napi]
    pub fn enforce(&self, binding: &AuthorizationBinding) -> Result<()> {
        if self.inner.permits(binding_tag(&binding.inner)) {
            Ok(())
        } else {
            Err(value_err(
                McpsError::AuthorizationBindingTypeUnsupported
                    .wire_code()
                    .to_string(),
            ))
        }
    }
}

/// Resolve the binding to embed: EITHER a provider-built `AuthorizationBinding` (the
/// real path) OR the raw `bindingDigestAlg`/`bindingDigestValue` opaque shortcut
/// (dev/test — kept so existing golden vectors stay byte-identical). Exactly one must
/// be given.
fn resolve_binding(
    binding: Option<&AuthorizationBinding>,
    digest_alg: Option<&str>,
    digest_value: Option<&str>,
) -> Result<CoreAuthorizationBinding> {
    match (binding, digest_alg, digest_value) {
        (Some(b), None, None) => Ok(b.inner.clone()),
        (None, Some(alg), Some(value)) => Ok(opaque_binding(alg, value)),
        (None, None, None) => Err(value_err(
            "an authorization binding is required: pass authorizationBinding (a \
             provider-built AuthorizationBinding) or bindingDigestAlg/bindingDigestValue \
             (the dev/test opaque shortcut)",
        )),
        _ => Err(value_err(
            "pass EITHER authorizationBinding OR bindingDigestAlg/bindingDigestValue, not both",
        )),
    }
}
