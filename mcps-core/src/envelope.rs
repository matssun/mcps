//! MCP-S envelope data structures (MCPS_SPEC §2 / ADR-002, ADR-008).
//!
//! These structs mirror the FROZEN wire vocabulary exactly. The signed
//! envelopes use `#[serde(deny_unknown_fields)]` so that any field other than
//! those listed in §2 is rejected at deserialization time — this is the
//! type-level enforcement of the fail-closed `mcps.unknown_envelope_field` rule
//! (the reserved `extensions` growth point is intentionally NOT a known key in
//! v1, so it too is rejected).
//!
//! Field names here are authoritative wire names; do NOT copy the stale planning
//! brief's `actor` / `capability_hash` / `server_actor` / `trust_label` names.

use serde::Deserialize;
use serde::Serialize;

/// Signature block carried inside both request and response envelopes
/// (MCPS_SPEC §2/§3).
///
/// `value` is `None` on the signing *preimage* (it is removed before
/// canonicalization, while `alg` and `key_id` are retained) and `Some(..)` on
/// the wire. Serializing with `value: None` omits the `value` key entirely so
/// the preimage is exactly "the object with `signature.value` removed".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBlock {
    /// Signature algorithm. Only `"Ed25519"` is supported in v1.
    pub alg: String,
    /// Identifier of the key whose private half produced `value`.
    pub key_id: String,
    /// Base64URL-no-pad signature bytes. `None` on the preimage, `Some` on wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// The request envelope (value carried under the request `_meta` key).
///
/// All frozen request fields in their exact wire order/names (MCPS_SPEC §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Envelope version; must be `"draft-01"`.
    pub version: String,
    /// Identity controlling `signature.key_id`'s private key.
    pub signer: String,
    /// Signed assertion of the principal on whose behalf the request is made.
    /// REQUIRED-present in Core; not independently verified.
    pub on_behalf_of: String,
    /// Intended verifier identity.
    pub audience: String,
    /// Authorization-artifact binding: `"sha256:<b64url-no-pad>"`. Core does not
    /// interpret the underlying artifact.
    pub authorization_hash: String,
    /// Opaque anti-replay nonce (>= 128 bits entropy).
    pub nonce: String,
    /// Issue time, RFC 3339 UTC.
    pub issued_at: String,
    /// Expiry time, RFC 3339 UTC.
    pub expires_at: String,
    /// Detached-in-line signature over the canonical preimage.
    pub signature: SignatureBlock,
}

/// The response envelope (value carried under the response `_meta` key).
///
/// `trust_label` is REMOVED from Core (MCPS_SPEC §2); response envelopes MUST
/// NOT carry it, and `deny_unknown_fields` enforces that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    /// Hash of the verified request signing preimage: `"sha256:<b64url-no-pad>"`.
    pub request_hash: String,
    /// Identity controlling the server signing key.
    pub server_signer: String,
    /// Issue time, RFC 3339 UTC.
    pub issued_at: String,
    /// Detached-in-line signature over the canonical response preimage.
    pub signature: SignatureBlock,
}

// ---------------------------------------------------------------------------
// Draft-02 (v0.6) envelopes — ADR-MCPS-038 / decision B.2, D.1.
// ---------------------------------------------------------------------------
//
// Draft-02 carries two non-overloaded PROTECTED identifiers inside the signing
// preimage on BOTH envelopes:
//   * `version: "draft-02"`            — the profile-version authority (DIRECTS
//      the verifier's allowlist/rules/algorithms/structure/error behavior);
//   * `canonicalization_id: "mcps-jcs-int53-json-v1"` — the audit-facing record
//      of the byte scheme used (DESCRIBES/binds; never directs verification).
//
// Both are mandatory even though v0.6 admits exactly one scheme: behavior-
// redundant but not EVIDENCE-redundant — a signed record must state its byte
// scheme under signature (the "describes and binds; does not direct" principle).
// These structs are strictly separate from the draft-01 ones: the verifier
// never merges profile semantics across versions (ADR-MCPS-041 / decision G.1).
//
// NOTE: the draft-02 request envelope still carries `authorization_hash` here;
// MCPS-35 (#181) replaces it with the typed `authorization_binding` object.

/// The draft-02 typed authorization-evidence binding (ADR-MCPS-039 / decision
/// E.1, E.2). Replaces draft-01's bare `authorization_hash` string: the envelope
/// carries the **binding contract** (typed, inside the signing preimage), while
/// the sibling `se.syncom/mcps.authorization` `_meta` block continues to carry
/// the profile-specific evidence (`{ profile, artifact }`). Two base forms in
/// v0.6; structured authorization-object hashing (case 3) stays OUT of the base
/// profile (allowed only via an explicit authorization-binding profile).
///
/// MCP-S **binds and never interprets**: Core validates structure (`binding_type`
/// ∈ base set, mandatory fields, `digest_alg` shape); the `mcps-policy` profile
/// reproduces/compares (opaque) or hands a reference off to a configured
/// authorization-reference resolver. The digest representation is the SPLIT form
/// (`digest_alg` + bare `digest_value`, no `sha256:` prefix) — security
/// parameters are explicit protected fields, matching `canonicalization_id`.
///
/// `#[serde(tag = "binding_type")]` makes it internally tagged; the exact field
/// set (and the oneof — no mixing forms) is enforced by Core's explicit
/// structural validator, which maps violations to the precise MCPS-31 codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "binding_type")]
pub enum AuthorizationBinding {
    /// Opaque-bytes: the digest is SHA-256 over the transport-decoded artifact
    /// bytes (base64url-no-pad decode → SHA-256 → base64url-no-pad), never the
    /// base64 text or UTF-8 JSON string bytes.
    #[serde(rename = "opaque-bytes")]
    OpaqueBytes {
        /// Digest algorithm token; `"sha256"` in v0.6.
        digest_alg: String,
        /// `base64url-no-pad(SHA-256(decoded artifact bytes))` — bare, no prefix.
        digest_value: String,
    },
    /// Authz-system-reference: an external authorization system's self-contained
    /// digest plus cross-audit reference metadata. All fields mandatory; the
    /// digest (not the reference) is the cryptographic binding, so the record
    /// stays historically verifiable independent of the external system's live
    /// state. MCP-S binds it; a configured reference profile/resolver validates.
    #[serde(rename = "authz-system-reference")]
    AuthzSystemReference {
        /// Namespace of the external authorization system.
        authorization_system_id: String,
        /// The authz system's scheme: what `reference_value` means and how the
        /// digest was produced.
        reference_scheme_id: String,
        /// Decision id / grant id / reference handle (cross-audit metadata).
        reference_value: String,
        /// Digest algorithm token; `"sha256"` in v0.6.
        digest_alg: String,
        /// `base64url-no-pad` digest produced by the authz system under
        /// `reference_scheme_id` — bare, no prefix.
        digest_value: String,
    },
}

/// Multi-round-trip continuation binding (ADR-MCPS-047 / decision D4).
///
/// Present ONLY on a continuation request — the fresh signed client request that
/// answers a verified `InputRequiredResult`. Ordinary first-round requests omit
/// it entirely. It cryptographically ties the continuation to the exact signed
/// `InputRequiredResult` it answers, so a continuation cannot be detached from the
/// prompt it responds to; missing/malformed/mismatched fails closed.
///
/// Like [`AuthorizationBinding`] it is internally tagged (`#[serde(tag = "type")]`)
/// and Core validates STRUCTURE only — it BINDS, never interprets. Unlike the
/// authz digests (split `digest_alg`/bare `digest_value`), the two hashes here use
/// the combined `"sha256:<b64url-no-pad>"` form, matching the response envelope's
/// `request_hash`, because they ARE request/response preimage hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Continuation {
    /// Stateless MCP multi-round-trip continuation (SEP-2260/2322 elicitation).
    #[serde(rename = "mcp-mrt")]
    McpMrt {
        /// `request_hash` of the client request that produced the
        /// `InputRequiredResult` being answered. Combined `"sha256:<b64url>"` form.
        previous_request_hash: String,
        /// Hash of the signed `InputRequiredResult` response preimage the client
        /// verified before continuing. Combined `"sha256:<b64url>"` form.
        input_required_response_hash: String,
    },
}

/// The draft-02 request envelope (value under the request `_meta` key).
///
/// Mirrors [`RequestEnvelope`] plus the two protected draft-02 identifiers, with
/// the bare `authorization_hash` string **replaced** by the typed
/// [`AuthorizationBinding`] object (ADR-MCPS-039 — no compat alias).
/// `#[serde(deny_unknown_fields)]` keeps the fail-closed
/// `mcps.unknown_envelope_field` rule; a stray draft-01-shaped (e.g.
/// `authorization_hash`) or unknown field is rejected at deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft02RequestEnvelope {
    /// Envelope version; must be `"draft-02"` (profile-version authority).
    pub version: String,
    /// Protected canonicalization-scheme id; must be `"mcps-jcs-int53-json-v1"`
    /// for v0.6. Recorded under signature for audit self-description; the
    /// verifier selects the canonicalizer from the profile, never from this field.
    pub canonicalization_id: String,
    /// Identity controlling `signature.key_id`'s private key.
    pub signer: String,
    /// Signed assertion of the principal on whose behalf the request is made.
    pub on_behalf_of: String,
    /// Intended verifier identity.
    pub audience: String,
    /// Typed authorization-evidence binding (replaces draft-01's
    /// `authorization_hash`). Core validates structure only; the policy profile
    /// reproduces/compares or hands a reference off — never interpreted in Core.
    pub authorization_binding: AuthorizationBinding,
    /// Multi-round-trip continuation binding (ADR-MCPS-047 / D4). Present ONLY on a
    /// continuation request answering a verified `InputRequiredResult`; ordinary
    /// requests omit it (`skip_serializing_if` keeps existing wire byte-identical).
    /// When present it is INSIDE the signed preimage (not an exclusion path), so
    /// the round-trip linkage is cryptographic evidence. Core validates structure
    /// only; the policy/server layer checks the hashes against the verified prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<Continuation>,
    /// Opaque anti-replay nonce (>= 128 bits entropy).
    pub nonce: String,
    /// Issue time, RFC 3339 UTC.
    pub issued_at: String,
    /// Expiry time, RFC 3339 UTC.
    pub expires_at: String,
    /// Detached-in-line signature over the canonical preimage.
    pub signature: SignatureBlock,
}

/// The draft-02 response envelope (value under the response `_meta` key).
///
/// Unlike draft-01, the draft-02 response carries **both** `version` and
/// `canonicalization_id`: it is an independently signed server-evidence record
/// that must be self-describing standalone, not dependent on the bound request
/// to recover its profile/scheme context (ADR-MCPS-038 / decision B.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft02ResponseEnvelope {
    /// Envelope version; must be `"draft-02"`.
    pub version: String,
    /// Protected canonicalization-scheme id; must be `"mcps-jcs-int53-json-v1"`.
    pub canonicalization_id: String,
    /// Hash of the verified request signing preimage: `"sha256:<b64url-no-pad>"`.
    pub request_hash: String,
    /// Identity controlling the server signing key.
    pub server_signer: String,
    /// Issue time, RFC 3339 UTC.
    pub issued_at: String,
    /// Detached-in-line signature over the canonical response preimage.
    pub signature: SignatureBlock,
}

/// The verified-context sidecar block (MCPS_SPEC §2 / ADR-008).
///
/// Emitted locally by a verifier into the verified `_meta` key after a request
/// verifies. It is UNSIGNED and never part of any preimage, so it deliberately
/// does NOT use `deny_unknown_fields` — it is a local, additively-extensible
/// block rather than a protected wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedContext {
    /// The signer identity that was cryptographically verified.
    pub verified_signer: String,
    /// The key id used to verify the signature.
    pub key_id: String,
    /// The asserted principal copied from the verified request.
    pub on_behalf_of: String,
    /// The audience copied from the verified request.
    pub audience: String,
    /// The authorization-artifact binding copied from the verified request.
    pub authorization_hash: String,
    /// Hash of the verified request signing preimage: `"sha256:<b64url-no-pad>"`.
    pub request_hash: String,
    /// Identity of the verifier that produced this context.
    pub verifier: String,
    /// Time the verification completed, RFC 3339 UTC.
    pub verified_at: String,
}

#[cfg(test)]
mod tests {
    use super::RequestEnvelope;
    use super::ResponseEnvelope;
    use super::SignatureBlock;
    use super::VerifiedContext;

    // A frozen-vocabulary request envelope, constructed from MCPS_SPEC §2.
    const REQUEST_JSON: &str = r#"{
        "version": "draft-01",
        "signer": "did:example:host",
        "on_behalf_of": "user:alice",
        "audience": "did:example:server",
        "authorization_hash": "sha256:AAAA",
        "nonce": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "issued_at": "2026-05-28T20:00:00Z",
        "expires_at": "2026-05-28T20:05:00Z",
        "signature": {
            "alg": "Ed25519",
            "key_id": "key-1",
            "value": "c2lnbmF0dXJl"
        }
    }"#;

    const RESPONSE_JSON: &str = r#"{
        "request_hash": "sha256:BBBB",
        "server_signer": "did:example:server",
        "issued_at": "2026-05-28T20:00:01Z",
        "signature": {
            "alg": "Ed25519",
            "key_id": "srv-key-1",
            "value": "cmVzcG9uc2VzaWc"
        }
    }"#;

    const VERIFIED_JSON: &str = r#"{
        "verified_signer": "did:example:host",
        "key_id": "key-1",
        "on_behalf_of": "user:alice",
        "audience": "did:example:server",
        "authorization_hash": "sha256:AAAA",
        "request_hash": "sha256:BBBB",
        "verifier": "did:example:server",
        "verified_at": "2026-05-28T20:00:01Z"
    }"#;

    #[test]
    fn request_envelope_round_trips() {
        let parsed: RequestEnvelope =
            serde_json::from_str(REQUEST_JSON).expect("request must deserialize");
        assert_eq!(parsed.version, "draft-01");
        assert_eq!(parsed.signer, "did:example:host");
        assert_eq!(parsed.on_behalf_of, "user:alice");
        assert_eq!(parsed.authorization_hash, "sha256:AAAA");
        assert_eq!(parsed.signature.alg, "Ed25519");
        assert_eq!(parsed.signature.value.as_deref(), Some("c2lnbmF0dXJl"));

        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: RequestEnvelope = serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn response_envelope_round_trips() {
        let parsed: ResponseEnvelope =
            serde_json::from_str(RESPONSE_JSON).expect("response must deserialize");
        assert_eq!(parsed.request_hash, "sha256:BBBB");
        assert_eq!(parsed.server_signer, "did:example:server");

        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: ResponseEnvelope = serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn verified_context_round_trips() {
        let parsed: VerifiedContext =
            serde_json::from_str(VERIFIED_JSON).expect("verified must deserialize");
        assert_eq!(parsed.verified_signer, "did:example:host");
        assert_eq!(parsed.request_hash, "sha256:BBBB");

        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: VerifiedContext = serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn request_envelope_rejects_unknown_field() {
        let bogus = REQUEST_JSON.replace(
            "\"version\": \"draft-01\",",
            "\"version\": \"draft-01\",\n        \"bogus\": true,",
        );
        let result: Result<RequestEnvelope, _> = serde_json::from_str(&bogus);
        assert!(
            result.is_err(),
            "unknown field must be rejected (fail closed)"
        );
    }

    #[test]
    fn response_envelope_rejects_trust_label() {
        // trust_label is REMOVED from Core; it must be rejected as unknown.
        let bogus = RESPONSE_JSON.replace(
            "\"server_signer\": \"did:example:server\",",
            "\"server_signer\": \"did:example:server\",\n        \"trust_label\": \"high\",",
        );
        let result: Result<ResponseEnvelope, _> = serde_json::from_str(&bogus);
        assert!(result.is_err(), "trust_label must be rejected");
    }

    // ---- Draft-02 (v0.6) envelopes — ADR-MCPS-038 / decision B.2 ------------

    const DRAFT02_REQUEST_JSON: &str = r#"{
        "version": "draft-02",
        "canonicalization_id": "mcps-jcs-int53-json-v1",
        "signer": "did:example:host",
        "on_behalf_of": "user:alice",
        "audience": "did:example:server",
        "authorization_binding": {
            "binding_type": "opaque-bytes",
            "digest_alg": "sha256",
            "digest_value": "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        },
        "nonce": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "issued_at": "2026-05-28T20:00:00Z",
        "expires_at": "2026-05-28T20:05:00Z",
        "signature": {
            "alg": "Ed25519",
            "key_id": "key-1",
            "value": "c2lnbmF0dXJl"
        }
    }"#;

    const DRAFT02_RESPONSE_JSON: &str = r#"{
        "version": "draft-02",
        "canonicalization_id": "mcps-jcs-int53-json-v1",
        "request_hash": "sha256:BBBB",
        "server_signer": "did:example:server",
        "issued_at": "2026-05-28T20:00:01Z",
        "signature": {
            "alg": "Ed25519",
            "key_id": "srv-key-1",
            "value": "cmVzcG9uc2VzaWc"
        }
    }"#;

    #[test]
    fn draft02_request_envelope_carries_both_protected_identifiers() {
        let parsed: super::Draft02RequestEnvelope =
            serde_json::from_str(DRAFT02_REQUEST_JSON).expect("draft-02 request must deserialize");
        assert_eq!(parsed.version, "draft-02");
        assert_eq!(parsed.canonicalization_id, "mcps-jcs-int53-json-v1");
        assert_eq!(parsed.signer, "did:example:host");
        assert!(matches!(
            parsed.authorization_binding,
            super::AuthorizationBinding::OpaqueBytes { .. }
        ));

        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: super::Draft02RequestEnvelope =
            serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn draft02_request_rejects_draft01_authorization_hash_field() {
        // No compat alias: a draft-01-shaped authorization_hash is an unknown
        // field on the draft-02 envelope (ADR-MCPS-039).
        let bogus = DRAFT02_REQUEST_JSON.replace(
            "\"signer\": \"did:example:host\",",
            "\"signer\": \"did:example:host\",\n        \"authorization_hash\": \"sha256:AAAA\",",
        );
        let result: Result<super::Draft02RequestEnvelope, _> = serde_json::from_str(&bogus);
        assert!(
            result.is_err(),
            "authorization_hash must be rejected in draft-02"
        );
    }

    #[test]
    fn authorization_binding_both_forms_round_trip() {
        use super::AuthorizationBinding;
        let opaque = AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "abc".to_string(),
        };
        let reference = AuthorizationBinding::AuthzSystemReference {
            authorization_system_id: "sys-1".to_string(),
            reference_scheme_id: "scheme-1".to_string(),
            reference_value: "grant-1".to_string(),
            digest_alg: "sha256".to_string(),
            digest_value: "def".to_string(),
        };
        for binding in [opaque, reference] {
            let json = serde_json::to_string(&binding).expect("serialize");
            // The discriminator is the wire field `binding_type`.
            assert!(json.contains("\"binding_type\""));
            let reparsed: AuthorizationBinding = serde_json::from_str(&json).expect("reparse");
            assert_eq!(binding, reparsed);
        }
    }

    #[test]
    fn draft02_response_envelope_carries_both_protected_identifiers() {
        // The draft-01 response carries NEITHER identifier; draft-02 gains both so
        // a stored response is self-describing standalone (decision B.2).
        let parsed: super::Draft02ResponseEnvelope = serde_json::from_str(DRAFT02_RESPONSE_JSON)
            .expect("draft-02 response must deserialize");
        assert_eq!(parsed.version, "draft-02");
        assert_eq!(parsed.canonicalization_id, "mcps-jcs-int53-json-v1");
        assert_eq!(parsed.request_hash, "sha256:BBBB");

        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: super::Draft02ResponseEnvelope =
            serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn draft02_request_rejects_unknown_field() {
        let bogus = DRAFT02_REQUEST_JSON.replace(
            "\"version\": \"draft-02\",",
            "\"version\": \"draft-02\",\n        \"bogus\": true,",
        );
        let result: Result<super::Draft02RequestEnvelope, _> = serde_json::from_str(&bogus);
        assert!(
            result.is_err(),
            "unknown field must be rejected (fail closed)"
        );
    }

    #[test]
    fn draft02_request_rejects_missing_canonicalization_id() {
        // A draft-02 envelope lacking the protected canonicalization_id is
        // structurally invalid (the pipeline maps this to
        // mcps.canonicalization_id_missing).
        let missing = DRAFT02_REQUEST_JSON.replace(
            "\"canonicalization_id\": \"mcps-jcs-int53-json-v1\",\n        ",
            "",
        );
        let result: Result<super::Draft02RequestEnvelope, _> = serde_json::from_str(&missing);
        assert!(
            result.is_err(),
            "missing canonicalization_id must fail closed"
        );
    }

    #[test]
    fn signature_block_omits_value_when_none() {
        let preimage = SignatureBlock {
            alg: "Ed25519".to_string(),
            key_id: "key-1".to_string(),
            value: None,
        };
        let serialized = serde_json::to_string(&preimage).expect("serialize");
        assert!(
            !serialized.contains("value"),
            "value key must be omitted on the preimage, got {serialized}"
        );
        assert!(serialized.contains("\"alg\""));
        assert!(serialized.contains("\"key_id\""));
    }

    #[test]
    fn signature_block_round_trips_with_value_present() {
        let wire = SignatureBlock {
            alg: "Ed25519".to_string(),
            key_id: "key-1".to_string(),
            value: Some("c2ln".to_string()),
        };
        let serialized = serde_json::to_string(&wire).expect("serialize");
        assert!(serialized.contains("\"value\":\"c2ln\""));
        let reparsed: SignatureBlock = serde_json::from_str(&serialized).expect("reparse");
        assert_eq!(wire, reparsed);
    }

    #[test]
    fn signature_block_deserializes_without_value_key() {
        let no_value = r#"{"alg":"Ed25519","key_id":"key-1"}"#;
        let parsed: SignatureBlock = serde_json::from_str(no_value).expect("missing value -> None");
        assert_eq!(parsed.value, None);
    }
}
