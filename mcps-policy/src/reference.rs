//! The Reference Signed Authorization Profile (MCPS-020, ADR-MCPS-013).
//!
//! Profile id `se.syncom/mcps-authz-reference-v1`. This is a native,
//! in-house, deterministic profile whose ONLY purpose is to prove the
//! [`AuthorizationProfile`] interface and produce reproducible conformance
//! vectors. It is explicitly NOT the long-term recommendation — Biscuit is the
//! intended first serious external profile (ADR-MCPS-013).
//!
//! ## Artifact
//!
//! A single JSON object, canonicalized with the same RFC 8785/JCS rule as Core
//! and signed by an issuer with the same Ed25519 rule (signature over the
//! canonical bytes with the top-level `signature.value` removed):
//!
//! ```text
//! profile, issuer, grantee, subject, audience,
//! grants: [ { method, tool, arguments? } ],
//! not_before, expires_at, revocation_id,
//! signature: { alg: "Ed25519", key_id, value }
//! ```
//!
//! The bytes carried in the `.authorization` block are the canonical bytes of the
//! complete signed artifact; `authorization_hash == sha256(those bytes)`.

use mcps_core::canonicalize;
use mcps_core::canonicalize_json_value;
use mcps_core::parse_rfc3339_utc;
use mcps_core::sha256_hash_id;
use mcps_core::verify_ed25519_with;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::TrustResolver;
use mcps_core::VerifiedRequest;
use mcps_core::SIG_ALG_ED25519;
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;

use crate::decision::AuthorizationDecision;
use crate::error::PolicyError;
use crate::profile::AuthorizationProfile;
use crate::revocation::RevocationSource;
use crate::revocation::RevocationStatus;

/// The Reference Signed Authorization Profile identifier.
pub const REFERENCE_PROFILE_ID: &str = "se.syncom/mcps-authz-reference-v1";

/// One granted operation: a method + tool/resource name, with optional argument
/// constraints (each constrained key must equal the request's argument value).
#[derive(Debug, Clone, Deserialize)]
struct Grant {
    method: String,
    tool: String,
    #[serde(default)]
    arguments: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct GrantSignature {
    alg: String,
    key_id: String,
    value: String,
}

/// The typed view of a reference artifact (evaluation fields). Unknown fields are
/// ignored — the canonical hash binding already pins the exact bytes.
#[derive(Debug, Clone, Deserialize)]
struct ReferenceGrant {
    issuer: String,
    grantee: String,
    subject: String,
    audience: String,
    grants: Vec<Grant>,
    not_before: String,
    expires_at: String,
    revocation_id: String,
    signature: GrantSignature,
}

/// The Reference Signed Authorization Profile.
#[derive(Debug, Clone, Default)]
pub struct ReferenceProfile;

impl ReferenceProfile {
    /// Construct the profile.
    pub fn new() -> Self {
        ReferenceProfile
    }
}

impl AuthorizationProfile for ReferenceProfile {
    fn profile_id(&self) -> &str {
        REFERENCE_PROFILE_ID
    }

    fn expected_authorization_hash(&self, artifact_bytes: &[u8]) -> Result<String, PolicyError> {
        // Canonicalize via the raw-bytes path (JCS-safe domain + duplicate-key
        // detection), then hash the canonical bytes. Bytes the host already
        // canonicalized are idempotent here.
        let canon = canonicalize(artifact_bytes).map_err(|_| PolicyError::AuthorizationMalformed)?;
        Ok(sha256_hash_id(&canon))
    }

    fn authorize(
        &self,
        artifact_bytes: &[u8],
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> AuthorizationDecision {
        match self.evaluate_inner(artifact_bytes, verified, request, resolver, revocation, now_unix)
        {
            Ok(()) => AuthorizationDecision::Allow,
            Err(err) => AuthorizationDecision::Deny(err),
        }
    }
}

impl ReferenceProfile {
    /// `Ok(())` iff the request is authorized; otherwise the precise denial error.
    fn evaluate_inner(
        &self,
        artifact_bytes: &[u8],
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> Result<(), PolicyError> {
        // Enforce the JCS-safe domain on the RAW artifact bytes FIRST — in
        // particular duplicate-member rejection, which the `serde_json::Value`
        // path below cannot detect (its `Map` silently keeps the last duplicate).
        // The issuer signature is then verified over a preimage derived from these
        // validated, canonical bytes — never from a duplicate-collapsed `Value`.
        // This makes `authorize` self-protecting: the `PolicyEvaluator` already
        // runs the same raw `canonicalize` in its hash-binding step, but the
        // public `AuthorizationProfile` trait does not guarantee that ordering, so
        // a direct caller must not be able to get a signature verified over bytes
        // that differ from the wire bytes (cluster 1, issue #20).
        let canonical_artifact =
            canonicalize(artifact_bytes).map_err(|_| PolicyError::AuthorizationMalformed)?;
        let artifact: Value = serde_json::from_slice(&canonical_artifact)
            .map_err(|_| PolicyError::AuthorizationMalformed)?;
        let grant: ReferenceGrant = serde_json::from_value(artifact.clone())
            .map_err(|_| PolicyError::AuthorizationMalformed)?;

        // validate_signature_or_chain: issuer Ed25519 signature over the canonical
        // artifact with the top-level signature.value removed.
        verify_issuer_signature(&artifact, &grant, resolver)?;

        // Bindings to the Core-verified request.
        if grant.grantee != verified.verified_signer {
            return Err(PolicyError::AuthorizationSignerMismatch);
        }
        if grant.subject != verified.on_behalf_of {
            return Err(PolicyError::AuthorizationSubjectMismatch);
        }
        if grant.audience != verified.audience {
            return Err(PolicyError::AuthorizationAudienceMismatch);
        }

        // Validity window (strict [not_before, expires_at]; malformed fails closed).
        check_window(&grant, now_unix)?;

        // Revocation. M-10: map the three outcomes to two DISTINCT denial tokens
        // (revoked vs unavailable) while failing closed on both — only an
        // affirmative NotRevoked lets evaluation continue.
        match revocation.revocation_status(&grant.revocation_id) {
            Ok(RevocationStatus::NotRevoked) => {}
            Ok(RevocationStatus::Revoked) => return Err(PolicyError::AuthorizationRevoked),
            Err(_unavailable) => return Err(PolicyError::AuthorizationRevocationUnavailable),
        }

        // Scope: the requested method/tool/arguments must match a granted op.
        check_scope(&grant, request)?;

        Ok(())
    }
}

/// Verify the issuer signature over the artifact (same Ed25519/JCS rule as Core).
/// Any failure — unsupported alg, unresolvable issuer key, or a cryptographic
/// mismatch — is [`PolicyError::AuthorizationSignatureInvalid`] (fail closed).
fn verify_issuer_signature(
    artifact: &Value,
    grant: &ReferenceGrant,
    resolver: &dyn TrustResolver,
) -> Result<(), PolicyError> {
    if grant.signature.alg != SIG_ALG_ED25519 {
        return Err(PolicyError::AuthorizationSignatureInvalid);
    }
    let mut preimage_value = artifact.clone();
    if let Some(sig) = preimage_value
        .get_mut("signature")
        .and_then(Value::as_object_mut)
    {
        sig.remove("value");
    } else {
        return Err(PolicyError::AuthorizationMalformed);
    }
    let preimage =
        canonicalize_json_value(&preimage_value).map_err(|_| PolicyError::AuthorizationMalformed)?;

    let key = resolver
        .resolve(&grant.issuer, &grant.signature.key_id)
        .map_err(|_| PolicyError::AuthorizationSignatureInvalid)?;

    // `verify_ed25519_with` returns its own McpsError sentinel on any failure;
    // we discard it and surface the policy-layer code.
    verify_ed25519_with(
        &preimage,
        &grant.signature.value,
        &key,
        McpsError::InvalidSignature,
    )
    .map_err(|_| PolicyError::AuthorizationSignatureInvalid)
}

/// Strict `[not_before, expires_at]` window check. An UNPARSEABLE timestamp is a
/// structural/malformedness defect, not a freshness verdict, so it fails closed
/// as [`PolicyError::AuthorizationMalformed`] (the taxonomy's token for "artifact
/// bytes do not parse into the profile's expected shape"); only a well-formed
/// timestamp that places `now` outside the window yields
/// [`PolicyError::AuthorizationExpired`].
fn check_window(grant: &ReferenceGrant, now_unix: i64) -> Result<(), PolicyError> {
    let not_before =
        parse_rfc3339_utc(&grant.not_before).map_err(|_| PolicyError::AuthorizationMalformed)?;
    let expires_at =
        parse_rfc3339_utc(&grant.expires_at).map_err(|_| PolicyError::AuthorizationMalformed)?;
    if now_unix < not_before || now_unix > expires_at {
        return Err(PolicyError::AuthorizationExpired);
    }
    Ok(())
}

/// The requested method / tool / arguments must match at least one granted op.
fn check_scope(grant: &ReferenceGrant, request: &Value) -> Result<(), PolicyError> {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let tool = request
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = request.get("params").and_then(|p| p.get("arguments"));

    let permitted = grant.grants.iter().any(|g| {
        g.method == method && g.tool == tool && arguments_satisfied(g.arguments.as_ref(), arguments)
    });
    if permitted {
        Ok(())
    } else {
        Err(PolicyError::AuthorizationScopeDenied)
    }
}

/// Argument constraints: when a grant specifies `arguments`, every constrained
/// key must equal the request's corresponding argument value. No constraint
/// (`None`) permits any arguments for that operation.
fn arguments_satisfied(constraint: Option<&Value>, actual: Option<&Value>) -> bool {
    let Some(constraint) = constraint else {
        return true;
    };
    let Some(constraint) = constraint.as_object() else {
        // A non-object constraint is unsatisfiable (deny — fail closed).
        return false;
    };
    let actual = match actual.and_then(Value::as_object) {
        Some(obj) => obj,
        None => return constraint.is_empty(),
    };
    constraint
        .iter()
        .all(|(key, value)| actual.get(key) == Some(value))
}

/// One granted operation, for minting (test/host support).
#[derive(Debug, Clone)]
pub struct GrantedOperation {
    /// JSON-RPC method (e.g. `tools/call`).
    pub method: String,
    /// Tool or resource name (e.g. `echo`).
    pub tool: String,
    /// Optional argument-equality constraints.
    pub arguments: Option<Value>,
}

/// The claims for a reference grant, for minting (test/host support).
#[derive(Debug, Clone)]
pub struct ReferenceGrantSpec {
    /// The granting authority identity.
    pub issuer: String,
    /// The agent identity allowed to wield the grant (== request signer).
    pub grantee: String,
    /// The party acted for (== request `on_behalf_of`).
    pub subject: String,
    /// The intended server (== request `audience`).
    pub audience: String,
    /// The granted operations.
    pub operations: Vec<GrantedOperation>,
    /// Validity-window start (RFC 3339 UTC).
    pub not_before: String,
    /// Validity-window end (RFC 3339 UTC).
    pub expires_at: String,
    /// Opaque revocation identifier.
    pub revocation_id: String,
}

/// Mint a signed reference grant and return its CANONICAL artifact bytes (ready to
/// Base64URL-encode into the `.authorization` block; `authorization_hash` is
/// `sha256(these bytes)`). Pure — signing has no side effects. Used by tests and
/// the host grant helper (MCPS-022).
pub fn mint_reference_grant(
    spec: &ReferenceGrantSpec,
    issuer_key: &SigningKey,
    key_id: &str,
) -> Result<Vec<u8>, PolicyError> {
    let grants: Vec<Value> = spec
        .operations
        .iter()
        .map(|op| {
            let mut entry = serde_json::Map::new();
            entry.insert("method".to_string(), json!(op.method));
            entry.insert("tool".to_string(), json!(op.tool));
            if let Some(arguments) = &op.arguments {
                entry.insert("arguments".to_string(), arguments.clone());
            }
            Value::Object(entry)
        })
        .collect();

    let mut artifact = json!({
        "profile": REFERENCE_PROFILE_ID,
        "issuer": spec.issuer,
        "grantee": spec.grantee,
        "subject": spec.subject,
        "audience": spec.audience,
        "grants": grants,
        "not_before": spec.not_before,
        "expires_at": spec.expires_at,
        "revocation_id": spec.revocation_id,
        "signature": { "alg": SIG_ALG_ED25519, "key_id": key_id },
    });

    let preimage =
        canonicalize_json_value(&artifact).map_err(|_| PolicyError::AuthorizationMalformed)?;
    let value = issuer_key.sign(&preimage);
    artifact["signature"]["value"] = Value::String(value);

    canonicalize_json_value(&artifact).map_err(|_| PolicyError::AuthorizationMalformed)
}

#[cfg(test)]
mod tests {
    use super::mint_reference_grant;
    use super::GrantedOperation;
    use super::ReferenceGrantSpec;
    use super::ReferenceProfile;
    use super::REFERENCE_PROFILE_ID;
    use crate::decision::AuthorizationDecision;
    use crate::error::PolicyError;
    use crate::profile::AuthorizationProfile;
    use crate::revocation::InMemoryRevocationSource;
    use crate::revocation::RevocationSource;
    use mcps_core::sha256_hash_id;
    use mcps_core::InMemoryTrustResolver;
    use mcps_core::SigningKey;
    use mcps_core::VerifiedRequest;
    use serde_json::json;
    use serde_json::Value;

    const ISSUER: &str = "did:example:authority-1";
    const ISSUER_KEY_ID: &str = "authority-key-1";
    const AGENT: &str = "did:example:agent-1";
    const USER: &str = "did:example:user-1";
    const SERVER: &str = "did:example:server-1";
    const NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
    const EXPIRES_AT: &str = "2026-05-28T21:00:00Z";

    /// 30 minutes after `not_before` — comfortably inside the window.
    fn now() -> i64 {
        mcps_core::parse_rfc3339_utc(NOT_BEFORE).expect("parse not_before") + 1_800
    }

    fn issuer_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[42u8; 32])
    }

    fn issuer_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
        r
    }

    fn default_spec() -> ReferenceGrantSpec {
        ReferenceGrantSpec {
            issuer: ISSUER.to_string(),
            grantee: AGENT.to_string(),
            subject: USER.to_string(),
            audience: SERVER.to_string(),
            operations: vec![GrantedOperation {
                method: "tools/call".to_string(),
                tool: "echo".to_string(),
                arguments: None,
            }],
            not_before: NOT_BEFORE.to_string(),
            expires_at: EXPIRES_AT.to_string(),
            revocation_id: "rev-1".to_string(),
        }
    }

    /// A VerifiedRequest whose authorization_hash binds the given artifact bytes.
    fn verified_for(artifact: &[u8]) -> VerifiedRequest {
        VerifiedRequest {
            verified_signer: AGENT.to_string(),
            key_id: "key-1".to_string(),
            on_behalf_of: USER.to_string(),
            audience: SERVER.to_string(),
            authorization_hash: sha256_hash_id(artifact),
            request_hash: "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            nonce: "nonce-1".to_string(),
            issued_at: NOT_BEFORE.to_string(),
            expires_at: EXPIRES_AT.to_string(),
        }
    }

    fn echo_request() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hello" } }
        })
    }

    fn authorize(
        artifact: &[u8],
        verified: &VerifiedRequest,
        request: &Value,
        revocation: &dyn RevocationSource,
    ) -> AuthorizationDecision {
        ReferenceProfile::new().authorize(
            artifact,
            verified,
            request,
            &issuer_resolver(),
            revocation,
            now(),
        )
    }

    #[test]
    fn profile_id_is_the_reference_identifier() {
        assert_eq!(ReferenceProfile::new().profile_id(), REFERENCE_PROFILE_ID);
    }

    #[test]
    fn expected_hash_matches_sha256_of_canonical_bytes() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        assert_eq!(
            ReferenceProfile::new()
                .expected_authorization_hash(&artifact)
                .unwrap(),
            sha256_hash_id(&artifact)
        );
    }

    #[test]
    fn fully_valid_grant_is_allowed() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(decision, AuthorizationDecision::Allow);
    }

    #[test]
    fn tampered_artifact_fails_signature() {
        let mut artifact =
            mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        // Flip a byte inside the signed content (not the signature value).
        let mut value: Value = serde_json::from_slice(&artifact).unwrap();
        value["subject"] = json!("did:evil:impostor");
        artifact = serde_json::to_vec(&value).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationSignatureInvalid)
        );
    }

    #[test]
    fn wrong_grantee_is_signer_mismatch() {
        let mut spec = default_spec();
        spec.grantee = "did:example:other-agent".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact); // verified_signer is still AGENT
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationSignerMismatch)
        );
    }

    #[test]
    fn wrong_subject_is_subject_mismatch() {
        let mut spec = default_spec();
        spec.subject = "did:example:other-user".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationSubjectMismatch)
        );
    }

    #[test]
    fn wrong_audience_is_audience_mismatch() {
        let mut spec = default_spec();
        spec.audience = "did:example:other-server".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationAudienceMismatch)
        );
    }

    #[test]
    fn outside_window_is_expired() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        // now after expires_at.
        let decision = ReferenceProfile::new().authorize(
            &artifact,
            &verified,
            &echo_request(),
            &issuer_resolver(),
            &InMemoryRevocationSource::new(),
            now() + 100_000,
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationExpired)
        );
    }

    /// A grant whose timestamp is well-formed JSON but NOT a parseable RFC 3339
    /// instant is a structural malformedness defect, not a freshness verdict: it
    /// must deny with `authorization_malformed`, never `authorization_expired`
    /// (which is reserved for `now` outside a well-formed window). The timestamp
    /// is inside the signed preimage, so the signature still verifies and
    /// evaluation reaches `check_window`.
    #[test]
    fn unparseable_timestamp_is_malformed_not_expired() {
        let mut spec = default_spec();
        spec.expires_at = "not-a-timestamp".to_string();
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(
            &artifact,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationMalformed)
        );
    }

    #[test]
    fn revoked_grant_is_revoked() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let mut revocation = InMemoryRevocationSource::new();
        revocation.revoke("rev-1");
        let decision = authorize(&artifact, &verified, &echo_request(), &revocation);
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationRevoked)
        );
    }

    /// M-10: a revocation backend that cannot determine status must deny with the
    /// DISTINCT `authorization_revocation_unavailable` token — never silently
    /// allow, and never be confused with an actual revocation. Fail closed.
    #[test]
    fn unavailable_revocation_source_denies_with_distinct_token() {
        use crate::revocation::RevocationStatus;
        use crate::revocation::RevocationUnavailable;

        /// A source that is always indeterminate (models a down backend).
        struct AlwaysUnavailable;
        impl RevocationSource for AlwaysUnavailable {
            fn revocation_status(
                &self,
                _revocation_id: &str,
            ) -> Result<RevocationStatus, RevocationUnavailable> {
                Err(RevocationUnavailable::new("test backend down"))
            }
        }

        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        let decision = authorize(&artifact, &verified, &echo_request(), &AlwaysUnavailable);
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationRevocationUnavailable),
            "an unavailable revocation backend must fail closed with its own distinct token"
        );
    }

    #[test]
    fn out_of_scope_tool_is_scope_denied() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);
        // Request a DIFFERENT tool than the one granted (echo).
        let request = json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": { "name": "delete_everything", "arguments": {} }
        });
        let decision = authorize(&artifact, &verified, &request, &InMemoryRevocationSource::new());
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationScopeDenied)
        );
    }

    #[test]
    fn argument_constraint_is_enforced() {
        let mut spec = default_spec();
        spec.operations = vec![GrantedOperation {
            method: "tools/call".to_string(),
            tool: "echo".to_string(),
            arguments: Some(json!({ "text": "hello" })),
        }];
        let artifact = mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).unwrap();
        let verified = verified_for(&artifact);

        // Matching argument → allowed.
        assert_eq!(
            authorize(
                &artifact,
                &verified,
                &echo_request(),
                &InMemoryRevocationSource::new()
            ),
            AuthorizationDecision::Allow
        );

        // Different argument value → scope denied.
        let other = json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "goodbye" } }
        });
        assert_eq!(
            authorize(&artifact, &verified, &other, &InMemoryRevocationSource::new()),
            AuthorizationDecision::Deny(PolicyError::AuthorizationScopeDenied)
        );
    }

    /// Issue #20 (cluster 1) — defense-in-depth: `authorize` must reject an
    /// artifact carrying a DUPLICATE object member on its own, never verify the
    /// issuer signature over duplicate-collapsed (last-wins) bytes. The
    /// `PolicyEvaluator` already rejects this at its hash-binding step, but the
    /// public `AuthorizationProfile` trait does not promise that ordering, so a
    /// direct `authorize` caller must still be protected. We call `authorize`
    /// DIRECTLY (bypassing the evaluator's hash check) to pin the profile-level
    /// guarantee.
    #[test]
    fn duplicate_key_artifact_is_malformed_not_signature_verified() {
        let artifact = mint_reference_grant(&default_spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        // Inject a second top-level `subject` member right after the opening brace.
        // serde_json::Value cannot represent this, so it is built textually; the
        // bytes are otherwise well-formed JSON whose ONLY defect is the duplicate.
        let text = String::from_utf8(artifact).unwrap();
        let dup = format!("{{\"subject\":\"did:example:user-1\",{}", &text[1..]);
        let dup_bytes = dup.into_bytes();
        let verified = verified_for(&dup_bytes);
        let decision = authorize(
            &dup_bytes,
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationMalformed),
            "a duplicate-member artifact must fail closed as malformed, never be \
             signature-verified over last-wins deduplicated bytes"
        );
    }

    #[test]
    fn malformed_artifact_bytes_are_malformed() {
        let verified = verified_for(b"not json");
        let decision = authorize(
            b"not json at all",
            &verified,
            &echo_request(),
            &InMemoryRevocationSource::new(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationMalformed)
        );
    }
}
