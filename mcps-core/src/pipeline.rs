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
use crate::constraints::extract_request_envelope;
use crate::constraints::extract_response_envelope;
use crate::constraints::reject_batch;
use crate::constraints::reject_notification;
use crate::crypto::verify_ed25519;
use crate::crypto::verify_ed25519_with;
use crate::error::McpsError;
use crate::ids::SIG_ALG_ED25519;
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
    /// The authorization-artifact binding from the verified envelope.
    pub authorization_hash: String,
    /// `sha256:<b64url-no-pad>` of the verified request signing preimage.
    pub request_hash: String,
    /// The anti-replay nonce from the verified envelope.
    pub nonce: String,
    /// The envelope `issued_at` (RFC 3339 UTC).
    pub issued_at: String,
    /// The envelope `expires_at` (RFC 3339 UTC).
    pub expires_at: String,
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
        authorization_hash: envelope.authorization_hash,
        request_hash: computed_request_hash,
        nonce: envelope.nonce,
        issued_at: envelope.issued_at,
        expires_at: envelope.expires_at,
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
    if envelope.signature.alg != SIG_ALG_ED25519 {
        return Err(McpsError::ResponseSigInvalid);
    }

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
    if alg != SIG_ALG_ED25519 {
        return Err(McpsError::InvalidSignature);
    }
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
    use super::verify_response;
    use super::VerificationConfig;
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
        assert_eq!(verified.authorization_hash, AUTHORIZATION_HASH);
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
