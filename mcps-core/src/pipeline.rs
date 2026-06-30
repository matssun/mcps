//! Full verification pipeline (MCPS_SPEC §9 / ADR-004/005/006/007/009).
//!
//! This module composes every Phase-1/2 primitive into the two end-to-end
//! verification entry points: [`verify_request`] and [`verify_response`]. The
//! step ordering is NORMATIVE (MCPS_SPEC §9) — each function fails closed at the
//! FIRST failing step and returns the listed [`McpsError`].
//!
//! The pipeline stays pure: it takes the wire bytes, a caller-injected
//! [`TrustResolver`] and [`ReplayCache`], a [`VerificationConfig`], and a
//! caller-supplied `now_unix` (Core never reads the system clock). No
//! networking, async, or filesystem; no `unwrap`/`expect`/`panic!`.
//!
//! ## verify_request order (MCPS_SPEC §9, steps 1-12)
//! 1. Parse JSON; reject a top-level array (batch) -> [`McpsError::BatchForbidden`].
//! 2. Reject a notification (no `id`) -> [`McpsError::NotificationForbidden`].
//! 3. JCS-safe domain on the ORIGINAL raw bytes (duplicate keys, unsafe integers,
//!    invalid UTF-8, ...) -> [`McpsError::CanonicalizationFailed`].
//! 4. (steps 4-6) Locate / deny-unknown-fields / version-check the request
//!    envelope (-> [`McpsError::MissingEnvelope`] /
//!    [`McpsError::UnknownEnvelopeField`] / [`McpsError::UnsupportedVersion`],
//!    mapped inside `extract_request_envelope`).
//! 7. Required-field presence/format on the envelope:
//!    - `authorization_hash` non-empty AND `sha256:`-prefixed
//!      -> else [`McpsError::AuthorizationHashMissing`] (present-but-empty OR
//!      malformed; a STRUCTURALLY absent value already yielded the same token at
//!      step 5 — see the documented choice below).
//!    - `on_behalf_of` non-empty -> else [`McpsError::OnBehalfOfInvalidFormat`]
//!      (this is the present-but-empty case; a STRUCTURALLY absent `on_behalf_of`
//!      already yielded [`McpsError::OnBehalfOfMissing`] at step 5).
//!    - `signature.alg == "Ed25519"` -> else [`McpsError::InvalidSignature`];
//!      `signature.value` present -> else [`McpsError::InvalidSignature`].
//! 8. `audience == config.expected_audience` -> else [`McpsError::InvalidAudience`].
//! 9. Freshness window -> else [`McpsError::ExpiredRequest`].
//! 10. Resolve `(signer, key_id)` -> [`McpsError::ActorBindingFailed`] /
//!     [`McpsError::TrustResolverUnavailable`].
//! 11. Build the request signing preimage (`signature.value` removed) and verify
//!     Ed25519 -> [`McpsError::InvalidSignature`].
//! 12. Parse `expires_at`, then replay-cache check-and-insert ->
//!     [`McpsError::ReplayCacheUnavailable`] / [`McpsError::ReplayDetected`].
//!
//! ## Documented step-7 error choice (per MCPS_SPEC §9 step 7's request)
//! - `authorization_hash`: a structurally absent value maps to
//!   [`McpsError::AuthorizationHashMissing`] at step 5 (deserialization); a
//!   present-but-empty or wrong-format (non-`sha256:`) value maps to the SAME
//!   token at step 7. We do not add a separate format error; "missing" subsumes
//!   "malformed" here, which fails closed and keeps the surface minimal (the spec
//!   explicitly permits this).
//! - `on_behalf_of`: a structurally absent value maps to
//!   [`McpsError::OnBehalfOfMissing`] (P005) at step 5 (deserialization); a
//!   present-but-empty value maps to [`McpsError::OnBehalfOfInvalidFormat`] at
//!   step 7. Both tokens are reachable and exercised by the constraints
//!   deserialization tests (absent) and the pipeline tests (present-but-empty).
//!
//! ## verify_response order (MCPS_SPEC §9 verify_response, with the structural
//! batch/notification rejects mirrored up front from `verify_request`)
//! 1. Parse JSON; reject a top-level array (batch) -> [`McpsError::BatchForbidden`].
//! 2. Reject a notification (no `id`) -> [`McpsError::NotificationForbidden`].
//! 3. JCS-safe domain on the ORIGINAL raw bytes ->
//!    [`McpsError::CanonicalizationFailed`].
//! 4-5. Locate / deny-unknown-fields the response envelope ->
//!    [`McpsError::MissingEnvelope`] / [`McpsError::UnknownEnvelopeField`].
//! 6. `signature.alg == "Ed25519"` -> else [`McpsError::ResponseSigInvalid`].
//! 7. Resolve `(server_signer, key_id)` -> [`McpsError::ActorBindingFailed`] /
//!    [`McpsError::TrustResolverUnavailable`].
//! 8. Build the response preimage and verify Ed25519 ->
//!    [`McpsError::ResponseSigInvalid`].
//! 9. `response.request_hash == expected_request_hash` -> else
//!    [`McpsError::ResponseHashMismatch`]. Vector 4B proves this fires even when
//!    the signature (step 8) is valid over a wrong `request_hash`.

use serde_json::Value;

use crate::canonical::canonicalize;
use crate::constraints::extract_draft02_request_envelope;
use crate::constraints::extract_draft02_response_envelope;
use crate::constraints::extract_request_envelope;
use crate::envelope::AuthorizationBinding;
use crate::constraints::extract_response_envelope;
use crate::constraints::reject_batch;
use crate::constraints::reject_notification;
use crate::crypto::ensure_ed25519_alg;
use crate::crypto::verify_ed25519;
use crate::crypto::verify_ed25519_with;
use crate::error::McpsError;
use crate::ids::REQUEST_META_KEY;
use crate::ids::VERSION_DRAFT_01;
use crate::ids::VERSION_DRAFT_02;
use crate::replay::ReplayCache;
use crate::replay::ReplayDecision;
use crate::resolver::TrustResolver;
use crate::signing::request_hash;
use crate::signing::request_signing_preimage;
use crate::signing::response_signing_preimage;
use crate::time::check_freshness;
use crate::time::parse_rfc3339_utc;

/// The `sha256:` prefix required of a well-formed `authorization_hash` (step 7).
const SHA256_PREFIX: &str = "sha256:";

/// Verifier-side configuration for [`verify_request`] (MCPS_SPEC §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationConfig {
    /// The verifier's own identity; an envelope's `audience` must equal this
    /// (step 8) or the request is rejected with [`McpsError::InvalidAudience`].
    pub expected_audience: String,
    /// Symmetric clock-skew tolerance (seconds) for the freshness window
    /// (step 9) and for replay-entry retention.
    pub max_clock_skew_secs: i64,
}

/// The verified authorization evidence, **versioned and explicit** so the policy
/// layer matches it exhaustively — no sentinel/empty-field placeholders for the
/// inactive profile (ADR-MCPS-039). draft-01 carries a bare hash; draft-02
/// carries the typed [`AuthorizationBinding`]. Core BINDS this evidence; the
/// `mcps-policy` profile interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedAuthorization {
    /// draft-01: the bare `authorization_hash` (`"sha256:<b64url-no-pad>"`).
    Draft01Hash {
        /// The authorization-artifact binding hash from the verified envelope.
        authorization_hash: String,
    },
    /// draft-02: the typed `authorization_binding` object from the verified
    /// envelope (opaque-bytes or authz-system-reference).
    Draft02Binding {
        /// The verified, structurally-validated authorization binding.
        authorization_binding: AuthorizationBinding,
    },
}

impl VerifiedAuthorization {
    /// The draft-01 `authorization_hash`, if this is a draft-01 verdict; `None`
    /// for a draft-02 binding. Lets a draft-01-only consumer read the hash
    /// without assuming the profile.
    pub fn draft01_hash(&self) -> Option<&str> {
        match self {
            VerifiedAuthorization::Draft01Hash { authorization_hash } => Some(authorization_hash),
            VerifiedAuthorization::Draft02Binding { .. } => None,
        }
    }

    /// The draft-02 [`AuthorizationBinding`], if this is a draft-02 verdict;
    /// `None` for a draft-01 hash.
    pub fn draft02_binding(&self) -> Option<&AuthorizationBinding> {
        match self {
            VerifiedAuthorization::Draft02Binding { authorization_binding } => {
                Some(authorization_binding)
            }
            VerifiedAuthorization::Draft01Hash { .. } => None,
        }
    }
}

/// The successful outcome of [`verify_request`] (MCPS_SPEC §9).
///
/// Every field is copied from the cryptographically verified request envelope;
/// `request_hash` is recomputed locally from the verified preimage so it binds a
/// later response (compare against [`verify_response`]'s `expected_request_hash`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    /// The signer identity whose key verified the signature.
    pub verified_signer: String,
    /// The key id used to verify the signature.
    pub key_id: String,
    /// The asserted principal (`on_behalf_of`) from the verified envelope.
    pub on_behalf_of: String,
    /// The audience from the verified envelope (equals the expected audience).
    pub audience: String,
    /// The verified authorization evidence, versioned by profile.
    pub authorization: VerifiedAuthorization,
    /// `sha256:<b64url-no-pad>` of the verified request signing preimage.
    pub request_hash: String,
    /// The anti-replay nonce from the verified envelope.
    pub nonce: String,
    /// The envelope `issued_at` (RFC 3339 UTC).
    pub issued_at: String,
    /// The envelope `expires_at` (RFC 3339 UTC).
    pub expires_at: String,
    /// The protected `canonicalization_id` from the verified envelope —
    /// `Some(..)` for draft-02 (it binds the later response's scheme), `None`
    /// for draft-01 (which carries no canonicalization id). ADR-MCPS-038.
    pub canonicalization_id: Option<String>,
}

/// The successful outcome of [`verify_response`] (MCPS_SPEC §9).
///
/// This is a PROOF token: per ADR-MCPS-003 the `server_signer` is evidence of key
/// control, only legitimately produced by the verifier ([`verify_response`]). To
/// keep the type as evidence, the fields are PRIVATE and the only constructor is
/// `pub(crate)` — reachable solely from inside this crate's verify path. Downstream
/// crates can READ the verdict through the accessors but can NOT fabricate a
/// "verified" verdict by struct-literal construction (issue #83). `#[non_exhaustive]`
/// additionally blocks any future field from being set by an external literal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedResponse {
    /// The server signer identity whose key verified the response signature.
    server_signer: String,
    /// The key id used to verify the response signature.
    key_id: String,
    /// The `request_hash` the response carried (equals the expected hash).
    request_hash: String,
}

impl VerifiedResponse {
    /// Mint a verified verdict. `pub(crate)` ON PURPOSE: the ONLY legitimate
    /// producer is [`verify_response`] in this crate, so a "verified" token cannot
    /// be forged from outside `mcps-core` (issue #83 / ADR-MCPS-003 type-as-evidence).
    pub(crate) fn new(server_signer: String, key_id: String, request_hash: String) -> Self {
        Self {
            server_signer,
            key_id,
            request_hash,
        }
    }

    /// The server signer identity whose key verified the response signature.
    pub fn server_signer(&self) -> &str {
        &self.server_signer
    }

    /// The key id used to verify the response signature.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The `request_hash` the response carried (equals the expected hash).
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }
}

/// Verify a signed MCP-S request end-to-end (MCPS_SPEC §9 steps 1-12).
///
/// Fails closed at the first failing step. See the module docs for the full
/// step-by-step error mapping. On success returns a [`VerifiedRequest`] whose
/// `request_hash` binds a later response.
pub fn verify_request(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    replay: &mut dyn ReplayCache,
    config: &VerificationConfig,
    now_unix: i64,
) -> Result<VerifiedRequest, McpsError> {
    // The JSON value model used for envelope extraction and preimage building.
    // A parse failure here is a malformed message: fail closed as a JCS-domain
    // violation (the dedicated raw-bytes domain check at step 3 also rejects it,
    // but serde may reject inputs serde_json cannot model at all).
    let value: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

    // Step 1 — reject a top-level array (batch).
    reject_batch(&value)?;

    // Step 2 — reject a notification (no id).
    reject_notification(&value)?;

    // Step 3 — JCS-safe domain on the ORIGINAL raw bytes (duplicate keys etc.).
    canonicalize(raw_bytes)?;

    // Steps 4-6 — locate / deny-unknown-fields / version-check the envelope.
    let envelope = extract_request_envelope(&value)?;

    // Step 7 — required-field presence / format.
    check_authorization_hash(&envelope.authorization_hash)?;
    check_on_behalf_of(&envelope.on_behalf_of)?;
    check_signature_block(&envelope.signature.alg, envelope.signature.value.as_deref())?;

    // Step 8 — audience match.
    if envelope.audience != config.expected_audience {
        return Err(McpsError::InvalidAudience);
    }

    // Step 9 — freshness window.
    check_freshness(
        &envelope.issued_at,
        &envelope.expires_at,
        now_unix,
        config.max_clock_skew_secs,
    )?;

    // Step 10 — resolve (signer, key_id) -> key.
    let key = resolver
        .resolve(&envelope.signer, &envelope.signature.key_id)
        .map_err(McpsError::from)?;

    // Step 11 — canonicalize (signature.value removed) and verify Ed25519.
    // The preimage is built from `value` (a serde_json::Value, which cannot
    // represent duplicate members); duplicate-key rejection is guaranteed by the
    // raw-bytes `canonicalize(raw_bytes)` at step 3 ABOVE, which fails closed
    // before we reach here. That ordering is locked by
    // `duplicate_key_wins_over_envelope_extraction` (issue #20, cluster 1).
    let preimage = request_signing_preimage(&value)?;
    let signature_value = envelope
        .signature
        .value
        .as_deref()
        .ok_or(McpsError::InvalidSignature)?;
    verify_ed25519(&preimage, signature_value, &key)?;

    // Step 12 — replay check-and-insert (LAST, after a valid signature).
    let expires_at_unix = parse_rfc3339_utc(&envelope.expires_at)?;
    match replay.check_and_insert(
        &envelope.signer,
        &envelope.audience,
        &envelope.nonce,
        expires_at_unix,
    ) {
        Ok(ReplayDecision::Fresh) => {}
        Ok(ReplayDecision::Replay) => return Err(McpsError::ReplayDetected),
        Err(err) => return Err(McpsError::from(err)),
    }

    // Success — recompute request_hash from the verified preimage.
    let computed_request_hash = request_hash(&value)?;
    Ok(VerifiedRequest {
        verified_signer: envelope.signer,
        key_id: envelope.signature.key_id,
        on_behalf_of: envelope.on_behalf_of,
        audience: envelope.audience,
        authorization: VerifiedAuthorization::Draft01Hash {
            authorization_hash: envelope.authorization_hash,
        },
        request_hash: computed_request_hash,
        nonce: envelope.nonce,
        issued_at: envelope.issued_at,
        expires_at: envelope.expires_at,
        // draft-01 carries no canonicalization id.
        canonicalization_id: None,
    })
}

/// Verify a signed MCP-S response end-to-end (MCPS_SPEC §9 verify_response
/// steps 1-7).
///
/// `expected_request_hash` is the `request_hash` from the locally verified
/// [`VerifiedRequest`]. Fails closed at the first failing step. Vector 4B proves
/// step 7 ([`McpsError::ResponseHashMismatch`]) fires even when the signature
/// (step 6) is valid over a wrong `request_hash`.
pub fn verify_response(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    expected_request_hash: &str,
) -> Result<VerifiedResponse, McpsError> {
    let value: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

    // Explicit structural rejects FIRST, mirroring `verify_request`. An array/batch
    // or notification-shaped response already fails closed at envelope location
    // (`locate_envelope` returns MissingEnvelope), but rejecting them up front —
    // before the raw-bytes JCS pass — surfaces the precise wire token
    // (BatchForbidden / NotificationForbidden) instead of an incidental
    // CanonicalizationFailed / MissingEnvelope, keeping the request/response
    // taxonomy symmetric.

    // Step 1 — reject a top-level array (batch).
    reject_batch(&value)?;

    // Step 2 — reject a notification (no id).
    reject_notification(&value)?;

    // Step 3 — JCS-safe domain on the ORIGINAL raw bytes (duplicate keys etc.).
    canonicalize(raw_bytes)?;

    // Steps 4-5 — locate / deny-unknown-fields the response envelope.
    let envelope = extract_response_envelope(&value)?;

    // Step 6 — signature.alg == Ed25519 (else ResponseSigInvalid).
    ensure_ed25519_alg(&envelope.signature.alg, McpsError::ResponseSigInvalid)?;

    // Step 7 — resolve (server_signer, key_id) -> key.
    let key = resolver
        .resolve(&envelope.server_signer, &envelope.signature.key_id)
        .map_err(McpsError::from)?;

    // Step 8 — build the response preimage (signature.value removed) and verify Ed25519.
    let preimage = response_signing_preimage(&value)?;
    let signature_value = envelope
        .signature
        .value
        .as_deref()
        .ok_or(McpsError::ResponseSigInvalid)?;
    verify_ed25519_with(
        &preimage,
        signature_value,
        &key,
        McpsError::ResponseSigInvalid,
    )?;

    // Step 9 — request_hash binding (fires even with a valid signature).
    if envelope.request_hash != expected_request_hash {
        return Err(McpsError::ResponseHashMismatch);
    }

    Ok(VerifiedResponse::new(
        envelope.server_signer,
        envelope.signature.key_id,
        envelope.request_hash,
    ))
}

// ---------------------------------------------------------------------------
// Draft-02 (v0.6) verify paths — ADR-MCPS-038/041 / decision B.2, G.1.
// ---------------------------------------------------------------------------
//
// These are strictly separate from the draft-01 verify functions: profile
// semantics are never merged (decision G.1). They share only the below-profile
// primitives (raw-bytes JCS domain check, the preimage builder, Ed25519 verify,
// freshness, replay) — the same functions the draft-01 path calls. The policy-
// gated dispatcher that selects between the draft-01 and draft-02 paths by the
// untrusted `version` selector, with the required expected-version policy and
// no cross-accept, lands in MCPS-37 (#183); here each path enforces its own
// exact signed `version`.

/// Verify a signed MCP-S **draft-02** request end-to-end. Mirrors
/// [`verify_request`] but extracts the draft-02 envelope, which enforces
/// `version == "draft-02"` and a profile-allowlisted `canonicalization_id`
/// (read as untrusted selectors before the signature verifies — ADR-MCPS-038).
/// The returned [`VerifiedRequest`] carries `canonicalization_id: Some(..)` so a
/// later [`verify_response_draft02`] can bind the same scheme.
///
/// Mutating `version` or `canonicalization_id` on the wire changes the signing
/// preimage (both are protected, inside it), so tampering them fails at the
/// Ed25519 check even past the structural selector validation.
pub fn verify_request_draft02(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    replay: &mut dyn ReplayCache,
    config: &VerificationConfig,
    now_unix: i64,
) -> Result<VerifiedRequest, McpsError> {
    let value: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

    // Steps 1-3 — structural rejects + raw-bytes JCS-safe domain (shared).
    reject_batch(&value)?;
    reject_notification(&value)?;
    canonicalize(raw_bytes)?;

    // Steps 4-6 (draft-02) — locate / deny-unknown-fields / version=="draft-02" /
    // canonicalization_id ∈ allowlist / authorization_binding structurally valid,
    // all read as untrusted selectors (the binding shape is validated inside
    // extraction — ADR-MCPS-039).
    let envelope = extract_draft02_request_envelope(&value)?;

    // Step 7 — required-field presence / format.
    check_on_behalf_of(&envelope.on_behalf_of)?;
    check_signature_block(&envelope.signature.alg, envelope.signature.value.as_deref())?;

    // Step 8 — audience match.
    if envelope.audience != config.expected_audience {
        return Err(McpsError::InvalidAudience);
    }

    // Step 9 — freshness window.
    check_freshness(
        &envelope.issued_at,
        &envelope.expires_at,
        now_unix,
        config.max_clock_skew_secs,
    )?;

    // Step 10 — resolve (signer, key_id) -> key.
    let key = resolver
        .resolve(&envelope.signer, &envelope.signature.key_id)
        .map_err(McpsError::from)?;

    // Step 11 — canonicalize (signature.value removed) and verify Ed25519. The
    // preimage retains the protected version + canonicalization_id, so tampering
    // either fails here.
    let preimage = request_signing_preimage(&value)?;
    let signature_value = envelope
        .signature
        .value
        .as_deref()
        .ok_or(McpsError::InvalidSignature)?;
    verify_ed25519(&preimage, signature_value, &key)?;

    // Step 12 — replay check-and-insert (LAST, after a valid signature).
    let expires_at_unix = parse_rfc3339_utc(&envelope.expires_at)?;
    match replay.check_and_insert(
        &envelope.signer,
        &envelope.audience,
        &envelope.nonce,
        expires_at_unix,
    ) {
        Ok(ReplayDecision::Fresh) => {}
        Ok(ReplayDecision::Replay) => return Err(McpsError::ReplayDetected),
        Err(err) => return Err(McpsError::from(err)),
    }

    let computed_request_hash = request_hash(&value)?;
    Ok(VerifiedRequest {
        verified_signer: envelope.signer,
        key_id: envelope.signature.key_id,
        on_behalf_of: envelope.on_behalf_of,
        audience: envelope.audience,
        authorization: VerifiedAuthorization::Draft02Binding {
            authorization_binding: envelope.authorization_binding,
        },
        request_hash: computed_request_hash,
        nonce: envelope.nonce,
        issued_at: envelope.issued_at,
        expires_at: envelope.expires_at,
        canonicalization_id: Some(envelope.canonicalization_id),
    })
}

/// Verify a signed MCP-S **draft-02** response end-to-end. Mirrors
/// [`verify_response`] but extracts the draft-02 response envelope (which now
/// carries `version` + `canonicalization_id`) and adds the scheme-binding check.
///
/// `expected_request_hash` and `expected_canonicalization_id` both come from the
/// locally verified [`VerifiedRequest`] (use its `request_hash` and the inner
/// value of its `canonicalization_id`). Both binding checks run AFTER the
/// signature verifies: a response signed over a different request hash →
/// [`McpsError::ResponseHashMismatch`]; a response declaring a different scheme
/// than the bound request → [`McpsError::CanonicalizationIdMismatch`] (decision
/// B.2 — request and response share the same canonicalization_id).
pub fn verify_response_draft02(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    expected_request_hash: &str,
    expected_canonicalization_id: &str,
) -> Result<VerifiedResponse, McpsError> {
    let value: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

    // Steps 1-3 — structural rejects + raw-bytes JCS-safe domain (shared).
    reject_batch(&value)?;
    reject_notification(&value)?;
    canonicalize(raw_bytes)?;

    // Steps 4-5 (draft-02) — locate / deny-unknown / version=="draft-02" /
    // canonicalization_id ∈ allowlist.
    let envelope = extract_draft02_response_envelope(&value)?;

    // Step 6 — signature.alg == Ed25519 (else ResponseSigInvalid).
    ensure_ed25519_alg(&envelope.signature.alg, McpsError::ResponseSigInvalid)?;

    // Step 7 — resolve (server_signer, key_id) -> key.
    let key = resolver
        .resolve(&envelope.server_signer, &envelope.signature.key_id)
        .map_err(McpsError::from)?;

    // Step 8 — build the response preimage (signature.value removed) and verify.
    let preimage = response_signing_preimage(&value)?;
    let signature_value = envelope
        .signature
        .value
        .as_deref()
        .ok_or(McpsError::ResponseSigInvalid)?;
    verify_ed25519_with(
        &preimage,
        signature_value,
        &key,
        McpsError::ResponseSigInvalid,
    )?;

    // Step 9 — binding checks (post-signature): same scheme AND same request hash
    // as the verified request. Both fire even with a valid signature.
    if envelope.canonicalization_id != expected_canonicalization_id {
        return Err(McpsError::CanonicalizationIdMismatch);
    }
    if envelope.request_hash != expected_request_hash {
        return Err(McpsError::ResponseHashMismatch);
    }

    Ok(VerifiedResponse::new(
        envelope.server_signer,
        envelope.signature.key_id,
        envelope.request_hash,
    ))
}

// ---------------------------------------------------------------------------
// Dual verifier — strict version dispatch + required expected-version policy.
// ADR-MCPS-041 / decision G.1.
// ---------------------------------------------------------------------------

/// The operator's expected-version security posture — a **required, explicit**
/// input (ADR-MCPS-041 / decision G.1). There is deliberately **no `Default`**:
/// a deployment must declare its posture, because defaulting either way is the
/// implicit fallback the project rejects (draft-02-only would silently break
/// deployed draft-01 clients; dual-accept would silently open a downgrade-
/// acceptance hole). A service that has not configured this must fail closed at
/// startup — see [`ExpectedVersionPolicy::from_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedVersionPolicy {
    /// The **recommended** production posture: only `draft-02` evidence is
    /// accepted; a `draft-01` envelope is refused as a downgrade.
    Draft02Only,
    /// An explicit **migration** posture: both `draft-01` and `draft-02` are
    /// accepted, each verified strictly by its own profile (never cross-accepted).
    Draft01AndDraft02,
}

impl ExpectedVersionPolicy {
    /// Resolve the policy from an operator-supplied configuration value, failing
    /// closed at startup when it is **unset** or unrecognized (decision G.1). The
    /// accepted tokens are `"draft-02-only"` and `"draft-01-and-draft-02"`.
    pub fn from_config(value: Option<&str>) -> Result<Self, VersionPolicyError> {
        match value {
            None => Err(VersionPolicyError::Unset),
            Some("draft-02-only") => Ok(ExpectedVersionPolicy::Draft02Only),
            Some("draft-01-and-draft-02") => Ok(ExpectedVersionPolicy::Draft01AndDraft02),
            Some(other) => Err(VersionPolicyError::Unrecognized(other.to_string())),
        }
    }

    /// Whether this posture admits the given (recognized) wire `version`.
    fn admits(self, version: &str) -> bool {
        match self {
            ExpectedVersionPolicy::Draft02Only => version == VERSION_DRAFT_02,
            ExpectedVersionPolicy::Draft01AndDraft02 => {
                version == VERSION_DRAFT_01 || version == VERSION_DRAFT_02
            }
        }
    }
}

/// A configuration-time failure resolving the [`ExpectedVersionPolicy`]. This is
/// a STARTUP error, distinct from the wire [`McpsError`] taxonomy: the service
/// must not start (fail closed) rather than infer a posture.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionPolicyError {
    /// No expected-version policy was configured. The service must fail closed
    /// at startup rather than choose a posture for the operator.
    #[error("expected-version policy is required but was not configured")]
    Unset,
    /// The configured value is not a recognized policy token.
    #[error("unrecognized expected-version policy: {0}")]
    Unrecognized(String),
}

/// Verify a signed MCP-S request through the **dual verifier** with strict
/// version dispatch (ADR-MCPS-041 / decision G.1). `envelope.version` is the
/// SOLE profile selector, read as an untrusted selector and then enforced
/// exactly by the chosen profile:
///
/// - unknown/unrecognized version → [`McpsError::UnsupportedVersion`]
///   ("cannot select a known profile");
/// - a recognized version the `policy` forbids (e.g. `draft-01` under
///   [`ExpectedVersionPolicy::Draft02Only`]) → [`McpsError::DowngradeForbidden`]
///   ("recognized the lower profile, policy forbids it");
/// - `draft-01` → the draft-01 verifier ONLY; `draft-02` → the draft-02 verifier
///   ONLY. **No fallback-retry, no cross-acceptance** — each profile rejects the
///   other's evidence.
///
/// The `policy` argument is required by the type system, so there is no way to
/// dispatch without an explicit posture (the startup fail-closed of
/// [`ExpectedVersionPolicy::from_config`] handles the operator-config side).
pub fn verify_request_dispatch(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    replay: &mut dyn ReplayCache,
    config: &VerificationConfig,
    now_unix: i64,
    policy: ExpectedVersionPolicy,
) -> Result<VerifiedRequest, McpsError> {
    let value: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

    // Structural rejects first (version-agnostic), so a batch/notification
    // surfaces its precise token rather than a missing-envelope incidental.
    reject_batch(&value)?;
    reject_notification(&value)?;

    // Read the untrusted version selector from the located request envelope.
    let version = read_request_envelope_version(&value)?;

    // Recognized profile? (downgrade defense distinguishes the two outcomes.)
    let recognized = version == VERSION_DRAFT_01 || version == VERSION_DRAFT_02;
    if !recognized {
        return Err(McpsError::UnsupportedVersion);
    }
    if !policy.admits(&version) {
        // Recognized the (lower) profile, policy forbids it.
        return Err(McpsError::DowngradeForbidden);
    }

    // Dispatch to exactly one profile; no fallback. The chosen verifier re-reads
    // and enforces the exact signed version.
    if version == VERSION_DRAFT_01 {
        verify_request(raw_bytes, resolver, replay, config, now_unix)
    } else {
        verify_request_draft02(raw_bytes, resolver, replay, config, now_unix)
    }
}

/// Read the request envelope's `version` as an untrusted selector. Missing
/// envelope → [`McpsError::MissingEnvelope`]; absent/non-string version →
/// [`McpsError::UnsupportedVersion`] (no profile can be selected).
fn read_request_envelope_version(value: &Value) -> Result<String, McpsError> {
    let envelope = value
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(REQUEST_META_KEY))
        .ok_or(McpsError::MissingEnvelope)?;
    envelope
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(McpsError::UnsupportedVersion)
}

/// Step 7 — `authorization_hash` must be present, non-empty, and `sha256:`-
/// prefixed. Absent/empty/malformed all -> [`McpsError::AuthorizationHashMissing`]
/// (documented choice; fails closed without a separate format error).
fn check_authorization_hash(authorization_hash: &str) -> Result<(), McpsError> {
    if authorization_hash.is_empty() || !authorization_hash.starts_with(SHA256_PREFIX) {
        return Err(McpsError::AuthorizationHashMissing);
    }
    Ok(())
}

/// Step 7 — `on_behalf_of` well-formedness. The envelope struct makes the field
/// required, so a present-but-empty value is the reachable malformed case ->
/// [`McpsError::OnBehalfOfInvalidFormat`]. True absence is rejected earlier as
/// [`McpsError::CanonicalizationFailed`] at extraction (see module docs).
fn check_on_behalf_of(on_behalf_of: &str) -> Result<(), McpsError> {
    if on_behalf_of.is_empty() {
        return Err(McpsError::OnBehalfOfInvalidFormat);
    }
    Ok(())
}

/// Step 7 — `signature.alg == "Ed25519"` and `signature.value` present. Any
/// other alg, or an absent value, -> [`McpsError::InvalidSignature`] (unknown alg
/// is treated as a signature failure in v1, MCPS_SPEC §3).
fn check_signature_block(alg: &str, value: Option<&str>) -> Result<(), McpsError> {
    ensure_ed25519_alg(alg, McpsError::InvalidSignature)?;
    if value.is_none() {
        return Err(McpsError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_authorization_hash;
    use super::check_on_behalf_of;
    use super::check_signature_block;
    use super::verify_request;
    use super::verify_request_dispatch;
    use super::verify_request_draft02;
    use super::verify_response;
    use super::verify_response_draft02;
    use super::ExpectedVersionPolicy;
    use super::VerificationConfig;
    use super::VerifiedAuthorization;
    use super::VersionPolicyError;
    use crate::crypto::SigningKey;
    use crate::error::McpsError;
    use crate::ids::REQUEST_META_KEY;
    use crate::ids::RESPONSE_META_KEY;
    use crate::replay::InMemoryReplayCache;
    use crate::replay::ReplayCache;
    use crate::replay::ReplayCacheError;
    use crate::replay::ReplayDecision;
    use crate::resolver::InMemoryTrustResolver;
    use crate::resolver::TrustResolver;
    use crate::resolver::TrustResolverError;
    use crate::signing::request_hash;
    use crate::signing::request_signing_preimage;
    use crate::signing::response_signing_preimage;
    use crate::crypto::VerificationKey;
    use serde_json::json;
    use serde_json::Value;

    // Fixed, documented seeds (mirror tests/vectors/README.md).
    const SIGNER_SEED: [u8; 32] = [1u8; 32];
    const SERVER_SEED: [u8; 32] = [2u8; 32];

    const SIGNER_ID: &str = "did:example:agent-1";
    const SIGNER_KEY_ID: &str = "key-1";
    const SERVER_SIGNER_ID: &str = "did:example:server-1";
    const SERVER_KEY_ID: &str = "server-key-1";
    const AUDIENCE: &str = "did:example:server-1";
    const ON_BEHALF_OF: &str = "did:example:user-1";

    const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
    const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
    const ISSUED_EPOCH: i64 = 1_779_998_400;
    const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
    const AUTHORIZATION_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

    const SKEW: i64 = 30;

    fn signer_key() -> SigningKey {
        SigningKey::from_seed_bytes(&SIGNER_SEED)
    }
    fn server_key() -> SigningKey {
        SigningKey::from_seed_bytes(&SERVER_SEED)
    }

    fn config() -> VerificationConfig {
        VerificationConfig {
            expected_audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        }
    }

    fn signer_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SIGNER_ID, SIGNER_KEY_ID, signer_key().public_key());
        r
    }
    fn server_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SERVER_SIGNER_ID, SERVER_KEY_ID, server_key().public_key());
        r
    }

    /// An always-unavailable resolver to exercise TrustResolverUnavailable.
    struct UnavailableResolver;
    impl TrustResolver for UnavailableResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            Err(TrustResolverError::Unavailable {
                details: "down".to_string(),
            })
        }
    }

    /// An always-unavailable replay cache to exercise ReplayCacheUnavailable.
    struct UnavailableReplayCache;
    impl ReplayCache for UnavailableReplayCache {
        fn check_and_insert(
            &mut self,
            _signer: &str,
            _audience: &str,
            _nonce: &str,
            _expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayCacheError> {
            Err(ReplayCacheError::Unavailable {
                details: "down".to_string(),
            })
        }
    }

    fn request_unsigned(id: &str, arg_text: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": arg_text },
                "_meta": {
                    REQUEST_META_KEY: {
                        "version": "draft-01",
                        "signer": SIGNER_ID,
                        "on_behalf_of": ON_BEHALF_OF,
                        "audience": AUDIENCE,
                        "authorization_hash": AUTHORIZATION_HASH,
                        "nonce": NONCE,
                        "issued_at": ISSUED_AT,
                        "expires_at": EXPIRES_AT,
                        "signature": { "alg": "Ed25519", "key_id": SIGNER_KEY_ID, "value": null }
                    }
                }
            }
        })
    }

    fn sign_request_value(object: &mut Value) {
        object["params"]["_meta"][REQUEST_META_KEY]["signature"]
            .as_object_mut()
            .expect("sig obj")
            .remove("value");
        let preimage = request_signing_preimage(object).expect("preimage");
        let sig = signer_key().sign(&preimage);
        object["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(sig);
    }

    fn signed_request(id: &str, arg_text: &str) -> Vec<u8> {
        let mut obj = request_unsigned(id, arg_text);
        sign_request_value(&mut obj);
        serde_json::to_vec(&obj).expect("serialize")
    }

    fn response_unsigned(request_hash_value: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "content": [{ "type": "text", "text": "hello" }],
                "_meta": {
                    RESPONSE_META_KEY: {
                        "request_hash": request_hash_value,
                        "server_signer": SERVER_SIGNER_ID,
                        "issued_at": "2026-05-28T20:00:01Z",
                        "signature": { "alg": "Ed25519", "key_id": SERVER_KEY_ID, "value": null }
                    }
                }
            }
        })
    }

    fn sign_response_value(object: &mut Value) {
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]
            .as_object_mut()
            .expect("sig obj")
            .remove("value");
        let preimage = response_signing_preimage(object).expect("preimage");
        let sig = server_key().sign(&preimage);
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
    }

    fn signed_response(request_hash_value: &str) -> Vec<u8> {
        let mut obj = response_unsigned(request_hash_value);
        sign_response_value(&mut obj);
        serde_json::to_vec(&obj).expect("serialize")
    }

    // ---- field-check helpers --------------------------------------------------

    #[test]
    fn authorization_hash_absent_or_malformed_is_missing() {
        assert_eq!(
            check_authorization_hash(""),
            Err(McpsError::AuthorizationHashMissing)
        );
        assert_eq!(
            check_authorization_hash("not-a-hash"),
            Err(McpsError::AuthorizationHashMissing)
        );
        assert_eq!(check_authorization_hash(AUTHORIZATION_HASH), Ok(()));
    }

    #[test]
    fn on_behalf_of_empty_is_invalid_format() {
        assert_eq!(
            check_on_behalf_of(""),
            Err(McpsError::OnBehalfOfInvalidFormat)
        );
        assert_eq!(check_on_behalf_of(ON_BEHALF_OF), Ok(()));
    }

    #[test]
    fn signature_block_rejects_bad_alg_and_absent_value() {
        assert_eq!(
            check_signature_block("RS256", Some("x")),
            Err(McpsError::InvalidSignature)
        );
        assert_eq!(
            check_signature_block("Ed25519", None),
            Err(McpsError::InvalidSignature)
        );
        assert_eq!(check_signature_block("Ed25519", Some("x")), Ok(()));
    }

    // ---- Draft-02 (v0.6) verify path — ADR-MCPS-038 / decision B.2 -----------

    /// An unsigned draft-02 request: draft-01 shape + the two protected
    /// identifiers (version="draft-02", canonicalization_id="mcps-jcs-int53-json-v1").
    fn request_unsigned_draft02(id: &str, arg_text: &str) -> Value {
        let mut obj = request_unsigned(id, arg_text);
        let env = obj["params"]["_meta"][REQUEST_META_KEY]
            .as_object_mut()
            .expect("request envelope object");
        env.insert("version".into(), json!("draft-02"));
        env.insert(
            "canonicalization_id".into(),
            json!("mcps-jcs-int53-json-v1"),
        );
        // draft-02 replaces authorization_hash with the typed binding.
        env.remove("authorization_hash");
        env.insert(
            "authorization_binding".into(),
            json!({
                "binding_type": "opaque-bytes",
                "digest_alg": "sha256",
                "digest_value": "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
            }),
        );
        obj
    }

    fn signed_request_draft02(id: &str, arg_text: &str) -> Vec<u8> {
        let mut obj = request_unsigned_draft02(id, arg_text);
        sign_request_value(&mut obj);
        serde_json::to_vec(&obj).expect("serialize")
    }

    fn response_unsigned_draft02(request_hash_value: &str) -> Value {
        let mut obj = response_unsigned(request_hash_value);
        let env = obj["result"]["_meta"][RESPONSE_META_KEY]
            .as_object_mut()
            .expect("response envelope object");
        env.insert("version".into(), json!("draft-02"));
        env.insert(
            "canonicalization_id".into(),
            json!("mcps-jcs-int53-json-v1"),
        );
        obj
    }

    fn signed_response_draft02(request_hash_value: &str) -> Vec<u8> {
        let mut obj = response_unsigned_draft02(request_hash_value);
        sign_response_value(&mut obj);
        serde_json::to_vec(&obj).expect("serialize")
    }

    #[test]
    fn draft02_request_verifies_and_carries_canonicalization_id() {
        let raw = signed_request_draft02("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let verified = verify_request_draft02(
            &raw,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
        )
        .expect("valid draft-02 request verifies");
        assert_eq!(verified.verified_signer, SIGNER_ID);
        assert_eq!(
            verified.canonicalization_id.as_deref(),
            Some("mcps-jcs-int53-json-v1")
        );
    }

    #[test]
    fn draft02_full_round_trip_request_then_response() {
        let raw_req = signed_request_draft02("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let verified_req = verify_request_draft02(
            &raw_req,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
        )
        .expect("request verifies");

        let raw_resp = signed_response_draft02(&verified_req.request_hash);
        let verified_resp = verify_response_draft02(
            &raw_resp,
            &server_resolver(),
            &verified_req.request_hash,
            verified_req.canonicalization_id.as_deref().unwrap(),
        )
        .expect("response verifies and binds");
        assert_eq!(verified_resp.server_signer(), SERVER_SIGNER_ID);
        assert_eq!(verified_resp.request_hash(), verified_req.request_hash);
    }

    #[test]
    fn draft02_mutating_canonicalization_id_breaks_the_signature() {
        // canonicalization_id is protected (inside the preimage). Sign a valid
        // request, then swap the id to a still-allowlisted-shaped but different
        // value: it is no longer in the allowlist, so extraction rejects it BEFORE
        // crypto — and even an allowlisted swap would break the signature.
        let mut obj = request_unsigned_draft02("req-1", "hello");
        sign_request_value(&mut obj);
        obj["params"]["_meta"][REQUEST_META_KEY]["canonicalization_id"] =
            json!("mcps-jcs-int53-json-v1-TAMPERED");
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::CanonicalizationIdUnknown)
        );
    }

    #[test]
    fn draft02_mutating_version_after_signing_fails_closed() {
        // version is protected too; flipping it to draft-01 makes the draft-02
        // verifier reject it as unsupported (it is not the draft-02 selector).
        let mut obj = request_unsigned_draft02("req-1", "hello");
        sign_request_value(&mut obj);
        obj["params"]["_meta"][REQUEST_META_KEY]["version"] = json!("draft-01");
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::UnsupportedVersion)
        );
    }

    #[test]
    fn draft02_response_scheme_mismatch_is_rejected() {
        // A correctly signed draft-02 response whose scheme does not match the
        // bound request's scheme fails the post-signature binding check (decision
        // B.2: request and response share canonicalization_id).
        let raw_req = signed_request_draft02("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let verified_req = verify_request_draft02(
            &raw_req,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
        )
        .expect("request verifies");

        let raw_resp = signed_response_draft02(&verified_req.request_hash);
        // The verified request used the int53 scheme; assert the response is bound
        // to a DIFFERENT expected scheme -> mismatch (forward-compat path).
        assert_eq!(
            verify_response_draft02(
                &raw_resp,
                &server_resolver(),
                &verified_req.request_hash,
                "mcps-jcs-future-floats-v2",
            ),
            Err(McpsError::CanonicalizationIdMismatch)
        );
    }

    #[test]
    fn draft02_float_bearing_payload_fails_closed_int53_honesty_vector() {
        // ADR-MCPS-037 / decision B.1: the v0.6 int53 scheme does NOT protect a
        // signed payload carrying JSON fractional numbers. A float in the signed
        // arguments fails closed at the raw-bytes JCS domain check (step 3),
        // before the signature — machine-checking the documented limitation
        // end-to-end through the draft-02 verifier.
        let mut obj = request_unsigned_draft02("req-1", "hello");
        obj["params"]["arguments"] = json!({ "temperature": 0.7, "price": 19.99 });
        // The float cannot even be signed (the preimage canonicalizer rejects it),
        // so a placeholder signature suffices: verification rejects at step 3.
        obj["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!("AA");
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::CanonicalizationFailed)
        );
    }

    #[test]
    fn draft02_max_safe_integer_payload_verifies() {
        // The int53 boundary (±(2^53−1)) IS in domain: a max-safe-int argument
        // signs and verifies, confirming the limitation is floats-only, not
        // integers-near-the-edge.
        let mut obj = request_unsigned_draft02("req-1", "hello");
        obj["params"]["arguments"] = json!({ "count": 9_007_199_254_740_991i64 });
        sign_request_value(&mut obj);
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert!(
            verify_request_draft02(&raw, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60)
                .is_ok(),
            "a max-safe-integer payload must verify under the int53 scheme"
        );
    }

    #[test]
    fn draft02_missing_canonicalization_id_fails_before_crypto() {
        let mut obj = request_unsigned_draft02("req-1", "hello");
        sign_request_value(&mut obj);
        obj["params"]["_meta"][REQUEST_META_KEY]
            .as_object_mut()
            .unwrap()
            .remove("canonicalization_id");
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::CanonicalizationIdMissing)
        );
    }

    // ---- Dual verifier: dispatch + policy (ADR-MCPS-041 / decision G.1) ------

    #[test]
    fn expected_version_policy_unset_fails_closed_at_config() {
        // The startup fail-closed: no policy configured => the service must not
        // start (decision G.1 — no default posture).
        assert_eq!(
            ExpectedVersionPolicy::from_config(None),
            Err(VersionPolicyError::Unset)
        );
        assert_eq!(
            ExpectedVersionPolicy::from_config(Some("draft-02-only")),
            Ok(ExpectedVersionPolicy::Draft02Only)
        );
        assert_eq!(
            ExpectedVersionPolicy::from_config(Some("draft-01-and-draft-02")),
            Ok(ExpectedVersionPolicy::Draft01AndDraft02)
        );
        assert!(matches!(
            ExpectedVersionPolicy::from_config(Some("loose")),
            Err(VersionPolicyError::Unrecognized(_))
        ));
    }

    #[test]
    fn dispatch_routes_draft01_and_draft02_by_version() {
        // draft-02 under the recommended draft-02-only posture verifies.
        let raw2 = signed_request_draft02("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let v2 = verify_request_dispatch(
            &raw2,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
            ExpectedVersionPolicy::Draft02Only,
        )
        .expect("draft-02 dispatches");
        assert!(v2.canonicalization_id.is_some());

        // draft-01 under the migration posture verifies (its own profile).
        let raw1 = signed_request("req-2", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let v1 = verify_request_dispatch(
            &raw1,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
            ExpectedVersionPolicy::Draft01AndDraft02,
        )
        .expect("draft-01 dispatches");
        assert!(v1.canonicalization_id.is_none());
        assert!(matches!(
            v1.authorization,
            VerifiedAuthorization::Draft01Hash { .. }
        ));
    }

    #[test]
    fn dispatch_draft01_under_draft02_only_is_downgrade_forbidden() {
        // Recognized lower profile, policy forbids it -> downgrade_forbidden
        // (NOT unsupported_version).
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_dispatch(
                &raw,
                &signer_resolver(),
                &mut replay,
                &config(),
                ISSUED_EPOCH + 60,
                ExpectedVersionPolicy::Draft02Only,
            ),
            Err(McpsError::DowngradeForbidden)
        );
    }

    #[test]
    fn dispatch_unknown_version_is_unsupported_not_downgrade() {
        // A version that names no known profile -> unsupported_version under any
        // policy (cannot select a profile at all).
        let mut obj = request_unsigned("req-1", "hello");
        obj["params"]["_meta"][REQUEST_META_KEY]["version"] = json!("draft-99");
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        for policy in [
            ExpectedVersionPolicy::Draft02Only,
            ExpectedVersionPolicy::Draft01AndDraft02,
        ] {
            assert_eq!(
                verify_request_dispatch(
                    &raw,
                    &signer_resolver(),
                    &mut replay,
                    &config(),
                    ISSUED_EPOCH + 60,
                    policy,
                ),
                Err(McpsError::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn no_cross_acceptance_between_profiles() {
        // Each verifier rejects the other's evidence — no fallback. The draft-01
        // verifier rejects the draft-02 envelope via deny_unknown_fields (the
        // draft-02-only fields are unknown to it); the draft-02 verifier rejects
        // the draft-01 envelope at the version selector.
        let raw2 = signed_request_draft02("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request(&raw2, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::UnknownEnvelopeField),
            "the draft-01 verifier must reject draft-02 evidence"
        );
        let raw1 = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_draft02(&raw1, &signer_resolver(), &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::UnsupportedVersion),
            "the draft-02 verifier must reject draft-01 evidence"
        );
    }

    #[test]
    fn draft01_no_leak_rejects_draft02_only_field() {
        // A draft-01 envelope carrying a draft-02-only field (canonicalization_id)
        // is rejected by deny_unknown_fields — the draft-02 surface never leaks
        // into the draft-01 profile.
        let mut obj = request_unsigned("req-1", "hello");
        obj["params"]["_meta"][REQUEST_META_KEY]
            .as_object_mut()
            .unwrap()
            .insert("canonicalization_id".into(), json!("mcps-jcs-int53-json-v1"));
        let raw = serde_json::to_vec(&obj).expect("serialize");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request_dispatch(
                &raw,
                &signer_resolver(),
                &mut replay,
                &config(),
                ISSUED_EPOCH + 60,
                ExpectedVersionPolicy::Draft01AndDraft02,
            ),
            Err(McpsError::UnknownEnvelopeField)
        );
    }

    // ---- verify_request happy path -------------------------------------------

    #[test]
    fn valid_request_verifies_and_fields_match() {
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let verified = verify_request(
            &raw,
            &signer_resolver(),
            &mut replay,
            &config(),
            ISSUED_EPOCH + 60,
        )
        .expect("valid request verifies");

        assert_eq!(verified.verified_signer, SIGNER_ID);
        assert_eq!(verified.key_id, SIGNER_KEY_ID);
        assert_eq!(verified.on_behalf_of, ON_BEHALF_OF);
        assert_eq!(verified.audience, AUDIENCE);
        assert_eq!(
            verified.authorization,
            VerifiedAuthorization::Draft01Hash {
                authorization_hash: AUTHORIZATION_HASH.to_string()
            }
        );
        assert_eq!(verified.nonce, NONCE);
        assert_eq!(verified.issued_at, ISSUED_AT);
        assert_eq!(verified.expires_at, EXPIRES_AT);
        assert!(verified.request_hash.starts_with("sha256:"));

        // The reported request_hash equals the canonical request_hash.
        let parsed: Value = serde_json::from_slice(&raw).expect("parse");
        assert_eq!(verified.request_hash, request_hash(&parsed).expect("hash"));
    }

    // ---- step-order: batch wins over everything (step 1) ----------------------

    #[test]
    fn batch_wins_over_other_problems() {
        // A top-level array that ALSO has unsafe integers etc. Step 1 fires first.
        let raw = br#"[{"id":9007199254740993}]"#;
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request(raw, &signer_resolver(), &mut replay, &config(), 0),
            Err(McpsError::BatchForbidden)
        );
    }

    #[test]
    fn notification_wins_over_envelope_problems() {
        // No id, and no envelope either: step 2 (notification) precedes step 4.
        let raw = br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#;
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request(raw, &signer_resolver(), &mut replay, &config(), 0),
            Err(McpsError::NotificationForbidden)
        );
    }

    #[test]
    fn duplicate_key_wins_over_envelope_extraction() {
        // id present (passes step 2), but a duplicate key -> step 3 canon fail.
        let raw = br#"{"id":"x","id":"y","jsonrpc":"2.0"}"#;
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request(raw, &signer_resolver(), &mut replay, &config(), 0),
            Err(McpsError::CanonicalizationFailed)
        );
    }

    // ---- step-order: expired (step 9) precedes signature (step 11) ------------

    #[test]
    fn expired_precedes_bad_signature() {
        // Sign a valid request, then TAMPER the argument (breaks the signature),
        // and evaluate at a time past expiry+skew. Step 9 must fire before step 11.
        let mut obj = request_unsigned("req-1", "hello");
        sign_request_value(&mut obj);
        obj["params"]["arguments"]["text"] = Value::String("tampered".to_string());
        let raw = serde_json::to_vec(&obj).expect("serialize");

        let mut replay = InMemoryReplayCache::new(SKEW);
        // expires_at = 2026-05-28T20:05:00Z -> ISSUED_EPOCH + 300; +skew+1 is past.
        let now = ISSUED_EPOCH + 300 + SKEW + 1;
        assert_eq!(
            verify_request(&raw, &signer_resolver(), &mut replay, &config(), now),
            Err(McpsError::ExpiredRequest)
        );
    }

    // ---- step-order: signature (step 11) precedes replay insert (step 12) -----

    #[test]
    fn bad_signature_precedes_replay_and_does_not_burn_nonce() {
        // Tampered argument (bad sig) within the freshness window. Step 11 fires;
        // the replay cache must NOT have been touched, so a later VALID request
        // with the same nonce is Fresh, not Replay.
        let mut obj = request_unsigned("req-1", "hello");
        sign_request_value(&mut obj);
        obj["params"]["arguments"]["text"] = Value::String("tampered".to_string());
        let raw_bad = serde_json::to_vec(&obj).expect("serialize");

        let mut replay = InMemoryReplayCache::new(SKEW);
        let now = ISSUED_EPOCH + 60;
        assert_eq!(
            verify_request(&raw_bad, &signer_resolver(), &mut replay, &config(), now),
            Err(McpsError::InvalidSignature)
        );

        // Same nonce, valid signature -> Fresh (nonce was not burned by the bad one).
        let raw_good = signed_request("req-1", "hello");
        assert!(verify_request(&raw_good, &signer_resolver(), &mut replay, &config(), now).is_ok());
    }

    // ---- replay detection -----------------------------------------------------

    #[test]
    fn second_identical_request_is_replay() {
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let now = ISSUED_EPOCH + 60;
        assert!(verify_request(&raw, &signer_resolver(), &mut replay, &config(), now).is_ok());
        assert_eq!(
            verify_request(&raw, &signer_resolver(), &mut replay, &config(), now),
            Err(McpsError::ReplayDetected)
        );
    }

    // ---- audience (step 8) ----------------------------------------------------

    #[test]
    fn audience_mismatch_is_invalid_audience() {
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let cfg = VerificationConfig {
            expected_audience: "did:example:someone-else".to_string(),
            max_clock_skew_secs: SKEW,
        };
        assert_eq!(
            verify_request(&raw, &signer_resolver(), &mut replay, &cfg, ISSUED_EPOCH + 60),
            Err(McpsError::InvalidAudience)
        );
    }

    // ---- resolver outcomes ----------------------------------------------------

    #[test]
    fn unknown_binding_is_actor_binding_failed() {
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        let empty = InMemoryTrustResolver::new();
        assert_eq!(
            verify_request(&raw, &empty, &mut replay, &config(), ISSUED_EPOCH + 60),
            Err(McpsError::ActorBindingFailed)
        );
    }

    #[test]
    fn unavailable_resolver_is_trust_resolver_unavailable() {
        let raw = signed_request("req-1", "hello");
        let mut replay = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            verify_request(
                &raw,
                &UnavailableResolver,
                &mut replay,
                &config(),
                ISSUED_EPOCH + 60
            ),
            Err(McpsError::TrustResolverUnavailable)
        );
    }

    #[test]
    fn unavailable_replay_cache_is_replay_cache_unavailable() {
        let raw = signed_request("req-1", "hello");
        let mut replay = UnavailableReplayCache;
        assert_eq!(
            verify_request(
                &raw,
                &signer_resolver(),
                &mut replay,
                &config(),
                ISSUED_EPOCH + 60
            ),
            Err(McpsError::ReplayCacheUnavailable)
        );
    }

    // ---- verify_response ------------------------------------------------------

    #[test]
    fn valid_response_verifies() {
        // Compute the true request_hash from a valid signed request.
        let req_raw = signed_request("req-1", "hello");
        let req_value: Value = serde_json::from_slice(&req_raw).expect("parse");
        let true_hash = request_hash(&req_value).expect("hash");

        let resp_raw = signed_response(&true_hash);
        let verified = verify_response(&resp_raw, &server_resolver(), &true_hash)
            .expect("valid response verifies");
        assert_eq!(verified.server_signer(), SERVER_SIGNER_ID);
        assert_eq!(verified.key_id(), SERVER_KEY_ID);
        assert_eq!(verified.request_hash(), true_hash);
    }

    #[test]
    fn response_hash_mismatch_with_valid_signature() {
        // Sign a response over a WRONG hash; the signature is valid, but step 7
        // mismatch must fire (Vector 4B semantics) — NOT ResponseSigInvalid.
        let wrong = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let resp_raw = signed_response(wrong);
        let expected = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
        let result = verify_response(&resp_raw, &server_resolver(), expected);
        assert_eq!(result, Err(McpsError::ResponseHashMismatch));
        assert_ne!(result, Err(McpsError::ResponseSigInvalid));
    }

    #[test]
    fn response_bad_signature_is_response_sig_invalid() {
        let true_hash = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
        let mut obj = response_unsigned(true_hash);
        sign_response_value(&mut obj);
        // Tamper the server_signer AFTER signing -> signature no longer valid.
        obj["result"]["_meta"][RESPONSE_META_KEY]["server_signer"] =
            Value::String(SERVER_SIGNER_ID.to_string());
        obj["result"]["content"] = json!([{ "type": "text", "text": "tampered" }]);
        let raw = serde_json::to_vec(&obj).expect("serialize");
        assert_eq!(
            verify_response(&raw, &server_resolver(), true_hash),
            Err(McpsError::ResponseSigInvalid)
        );
    }

    #[test]
    fn response_non_ed25519_alg_is_response_sig_invalid() {
        // Step 6 gates signature.alg through `ensure_ed25519_alg`; a non-Ed25519
        // alg must fail closed to ResponseSigInvalid.
        //
        // Isolation (anti false-pass): set alg to a non-Ed25519 value BEFORE
        // signing, so the Ed25519 signature is cryptographically VALID over the
        // alg-bearing preimage (signing.rs retains signature.alg in the preimage).
        // Therefore ONLY the Step-6 alg gate can reject this response: if the gate
        // were removed, Step-8 signature verification would PASS and Step-9 hash
        // would match, so verify_response would return Ok. This assertion thus
        // fails-on-gate-removal — it pins the gate rather than an incidental
        // signature mismatch.
        let true_hash = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
        let mut obj = response_unsigned(true_hash);
        obj["result"]["_meta"][RESPONSE_META_KEY]["signature"]["alg"] =
            Value::String("RS256".to_string());
        sign_response_value(&mut obj);
        let raw = serde_json::to_vec(&obj).expect("serialize");
        assert_eq!(
            verify_response(&raw, &server_resolver(), true_hash),
            Err(McpsError::ResponseSigInvalid)
        );
    }

    #[test]
    fn response_missing_envelope_is_missing_envelope() {
        let raw = br#"{"jsonrpc":"2.0","id":"req-1","result":{"content":[]}}"#;
        assert_eq!(
            verify_response(raw, &server_resolver(), "sha256:x"),
            Err(McpsError::MissingEnvelope)
        );
    }

    #[test]
    fn response_batch_array_is_batch_forbidden() {
        // A top-level array (JSON-RPC batch) response must reject with the
        // precise BatchForbidden token, mirroring verify_request, rather than the
        // incidental MissingEnvelope it would surface without the explicit
        // reject_batch guard at the top of verify_response.
        let raw = br#"[{"jsonrpc":"2.0","id":"req-1","result":{"content":[]}}]"#;
        assert_eq!(
            verify_response(raw, &server_resolver(), "sha256:x"),
            Err(McpsError::BatchForbidden)
        );
    }

    #[test]
    fn response_notification_no_id_is_notification_forbidden() {
        // An id-less (notification-shaped) response rejects with the precise
        // NotificationForbidden token instead of the incidental MissingEnvelope.
        let raw = br#"{"jsonrpc":"2.0","result":{"content":[]}}"#;
        assert_eq!(
            verify_response(raw, &server_resolver(), "sha256:x"),
            Err(McpsError::NotificationForbidden)
        );
    }
}
