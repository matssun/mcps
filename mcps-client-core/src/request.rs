//! Signed draft-02 request construction (MCPS-40, ADR-MCPS-044 §Minimum
//! responsibilities; ADR-MCPS-038 draft-02 envelope).
//!
//! This is the client-side mirror of `mcps-core`'s server-side
//! [`mcps_core::verify_request_draft02`]: given an ordinary MCP request (a
//! method + a params object) plus the signing inputs (signer/audience/freshness/
//! authorization binding), it injects the draft-02 request envelope under
//! `params._meta["se.syncom/mcps.request"]`, computes the canonical signing
//! preimage with `mcps-core` (so signer and verifier share ONE preimage rule),
//! signs it directly with Ed25519, and grafts the signature value back in.
//!
//! Two protected identifiers are bound INSIDE the preimage on every request
//! (ADR-MCPS-038 / decision B.2): `version` = `"draft-02"` (the profile-version
//! authority) and `canonicalization_id` (the byte-scheme record, audit-facing).
//! The builder rejects any `canonicalization_id` outside the draft-02 allowlist
//! BEFORE signing (fail closed): the client never emits evidence under a scheme
//! the profile does not admit, mirroring the verifier's selector validation.
//!
//! The returned [`SignedRequest`] exposes `request_hash` — `sha256:<b64url-no-pad>`
//! of the signed preimage — so the caller can correlate and later bind the signed
//! response (`response.request_hash == request.request_hash`, MCPS-41 / #188).
//!
//! Purity: this module builds and signs JSON in-process only. Nonce generation,
//! clock reads, key custody, and transport all live in the mode-specific layers
//! above this seam (ADR-MCPS-044); the inputs here are already-resolved values.

use mcps_core::request_hash;
use mcps_core::request_signing_preimage;
use mcps_core::AuthorizationBinding;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::DRAFT_02_CANONICALIZATION_ALLOWLIST;
use mcps_core::REQUEST_META_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_core::VERSION_DRAFT_02;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

/// The already-resolved inputs for one signed draft-02 request.
///
/// Every field is a value the mode-specific layer has already produced: the
/// signer identity and key id (from the key-custody layer, MCPS-46), the
/// `audience` (the resolved expected verifier identity, MCPS-43), the typed
/// `authorization_binding` (from an `AuthorizationBindingProvider`, MCPS-45), and
/// the freshness triple `nonce`/`issued_at`/`expires_at` (from the nonce + clock
/// sources). `canonicalization_id` defaults to the single v0.6 scheme via
/// [`RequestSigningInputs::with_default_canonicalization`]; an explicit value is
/// validated against the draft-02 allowlist.
#[derive(Debug, Clone)]
pub struct RequestSigningInputs {
    /// Identity controlling `signature.key_id`'s private key.
    pub signer: String,
    /// Identifier of the signing key (named in evidence; never the key itself).
    pub key_id: String,
    /// Signed assertion of the principal on whose behalf the request is made.
    pub on_behalf_of: String,
    /// Intended verifier identity (the resolved audience — MCPS-43).
    pub audience: String,
    /// Typed authorization-evidence binding bound into the signed preimage. Core
    /// binds it; it is never interpreted on the client (bind-not-interpret).
    pub authorization_binding: AuthorizationBinding,
    /// Opaque anti-replay nonce (>= 128 bits entropy), already drawn.
    pub nonce: String,
    /// Issue time, RFC 3339 UTC.
    pub issued_at: String,
    /// Expiry time, RFC 3339 UTC.
    pub expires_at: String,
    /// Protected canonicalization-scheme id; must be in the draft-02 allowlist.
    pub canonicalization_id: String,
}

impl RequestSigningInputs {
    /// Build inputs using the single v0.6 draft-02 canonicalization scheme
    /// (`mcps-jcs-int53-json-v1`). This is the normal constructor — a caller only
    /// sets `canonicalization_id` explicitly to exercise the fail-closed reject
    /// path or to opt into a future allowlisted scheme.
    #[allow(clippy::too_many_arguments)]
    pub fn with_default_canonicalization(
        signer: impl Into<String>,
        key_id: impl Into<String>,
        on_behalf_of: impl Into<String>,
        audience: impl Into<String>,
        authorization_binding: AuthorizationBinding,
        nonce: impl Into<String>,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        RequestSigningInputs {
            signer: signer.into(),
            key_id: key_id.into(),
            on_behalf_of: on_behalf_of.into(),
            audience: audience.into(),
            authorization_binding,
            nonce: nonce.into(),
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
            canonicalization_id: DRAFT_02_CANONICALIZATION_ALLOWLIST[0].to_string(),
        }
    }
}

/// A fully signed draft-02 request: the wire bytes plus the `request_hash` that
/// binds a later response.
///
/// `request_hash` is recomputed from the signed object's preimage (which excludes
/// `signature.value`), so it equals what a server-side verifier recomputes and
/// echoes into the signed response envelope. Hold it in the correlation store
/// (MCPS-47) and compare against `response.request_hash` on the way back.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// The serialized JSON-RPC request, ready to send on the remote leg.
    wire_bytes: Vec<u8>,
    /// `sha256:<b64url-no-pad>` of the signed request preimage (response binding).
    request_hash: String,
    /// The signed request object (kept for callers that prefer a `Value`).
    object: Value,
}

impl SignedRequest {
    /// The serialized JSON-RPC request bytes to forward to the remote endpoint.
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// The `request_hash` (`sha256:<b64url-no-pad>`) binding a later response.
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    /// The signed request as a `serde_json::Value`.
    pub fn object(&self) -> &Value {
        &self.object
    }

    /// Consume the signed request, returning the owned wire bytes.
    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.wire_bytes
    }
}

/// Reject a `canonicalization_id` outside the draft-02 profile allowlist BEFORE
/// any signing happens (fail closed). With exactly one v0.6 scheme, an absent id
/// maps to [`McpsError::CanonicalizationIdMissing`] and any non-allowlisted token
/// to [`McpsError::CanonicalizationIdNotAllowed`] — the client never emits
/// evidence under a scheme the profile does not admit.
fn check_canonicalization_id(id: &str) -> Result<(), McpsError> {
    if id.is_empty() {
        return Err(McpsError::CanonicalizationIdMissing);
    }
    if DRAFT_02_CANONICALIZATION_ALLOWLIST.contains(&id) {
        Ok(())
    } else {
        Err(McpsError::CanonicalizationIdNotAllowed)
    }
}

/// Construct and sign a draft-02 MCP-S request.
///
/// `id`/`method`/`params` are the ordinary MCP request fields (the params object
/// for `tools/call` is typically `{"name","arguments"}`). Any caller-supplied
/// `_meta` request envelope is OVERWRITTEN — the client core is the sole author of
/// the `*.request` block, exactly like the server is the sole author of the
/// response block.
///
/// Steps:
/// 1. reject an unsupported `canonicalization_id` (fail closed, no signing);
/// 2. build the draft-02 envelope (with `signature.value` omitted) and merge it
///    into `params._meta[REQUEST_META_KEY]`;
/// 3. compute the canonical preimage via `mcps-core` and sign it with `signing_key`;
/// 4. graft the signature value back in and compute `request_hash`.
///
/// The `signing_key` is taken by reference and never retained — the key-custody
/// abstraction (MCPS-46) owns its lifetime. On success the request is one a
/// server-side [`mcps_core::verify_request_draft02`] accepts.
pub fn build_signed_request(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, McpsError> {
    // The in-process software signer signs infallibly; wrap it as the closure the
    // shared core expects. The key-custody abstraction (MCPS-46) uses the same core
    // with a delegated/non-exporting signer via [`build_signed_request_with`].
    build_signed_request_with(id, method, params, inputs, |preimage| {
        Ok(signing_key.sign(preimage))
    })
}

/// The shared request-construction core, generic over HOW the canonical preimage
/// is signed. `sign` receives the exact preimage bytes and returns the
/// Base64URL-no-pad signature value (or a typed failure — e.g. a delegated signer
/// that is unavailable/revoked fails closed here). This is the single seam every
/// signing mechanism (in-process software key, KMS/HSM, delegated service) flows
/// through, so the envelope shape and preimage rule are authored in exactly one
/// place. `inputs.signer` / `inputs.key_id` identify the signer in the evidence.
pub(crate) fn build_signed_request_with(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    inputs: &RequestSigningInputs,
    sign: impl FnOnce(&[u8]) -> Result<String, McpsError>,
) -> Result<SignedRequest, McpsError> {
    // Step 1 — fail closed on an unsupported scheme before constructing evidence.
    check_canonicalization_id(&inputs.canonicalization_id)?;

    // Step 2 — author the draft-02 request envelope (no signature.value yet). The
    // protected `version` and `canonicalization_id` are the first two members so
    // they are clearly part of the signed evidence; JCS reorders them canonically
    // regardless.
    let envelope = json!({
        "version": VERSION_DRAFT_02,
        "canonicalization_id": inputs.canonicalization_id,
        "signer": inputs.signer,
        "on_behalf_of": inputs.on_behalf_of,
        "audience": inputs.audience,
        "authorization_binding": inputs.authorization_binding,
        "nonce": inputs.nonce,
        "issued_at": inputs.issued_at,
        "expires_at": inputs.expires_at,
        "signature": { "alg": SIG_ALG_ED25519, "key_id": inputs.key_id },
    });

    // Merge the envelope into params._meta, overwriting any caller-supplied copy.
    let mut params = params;
    let mut meta = params
        .remove("_meta")
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    meta.insert(REQUEST_META_KEY.to_string(), envelope);
    params.insert("_meta".to_string(), Value::Object(meta));

    let mut request = json!({
        "id": id.clone(),
        "jsonrpc": "2.0",
        "method": method,
        "params": Value::Object(params),
    });

    // Step 3 — sign the canonical preimage (signature.value omitted by construction).
    let preimage = request_signing_preimage(&request)?;
    let signature = sign(&preimage)?;

    // Step 4 — graft the signature value and compute the response-binding hash.
    // request_hash recomputes the SAME preimage (it excludes signature.value), so
    // it is independent of the value we just grafted.
    request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(signature);
    let request_hash = request_hash(&request)?;

    let wire_bytes = serde_json::to_vec(&request).map_err(|_| McpsError::CanonicalizationFailed)?;
    Ok(SignedRequest {
        wire_bytes,
        request_hash,
        object: request,
    })
}

/// Convenience for the common `tools/call` case: builds `{"name","arguments"}`
/// params and signs them (mirrors `mcps_host::HostSigner::sign_tool_call` but on
/// the draft-02 wire).
pub fn build_signed_tool_call(
    id: &Value,
    tool_name: &str,
    arguments: Value,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, McpsError> {
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(tool_name.to_string()));
    params.insert("arguments".to_string(), arguments);
    build_signed_request(id, "tools/call", params, inputs, signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcps_core::ids::DIGEST_ALG_SHA256;
    use mcps_core::CANONICALIZATION_ID_INT53_V1;

    const SEED: [u8; 32] = [42u8; 32];

    fn opaque_binding() -> AuthorizationBinding {
        AuthorizationBinding::OpaqueBytes {
            digest_alg: DIGEST_ALG_SHA256.to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        }
    }

    fn default_inputs() -> RequestSigningInputs {
        RequestSigningInputs::with_default_canonicalization(
            "did:example:client",
            "client-key-1",
            "user:alice",
            "did:example:server",
            opaque_binding(),
            "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
            "2026-06-30T20:00:00Z",
            "2026-06-30T20:05:00Z",
        )
    }

    fn sign() -> (SignedRequest, SigningKey) {
        let key = SigningKey::from_seed_bytes(&SEED);
        let signed = build_signed_tool_call(
            &json!("req-1"),
            "echo",
            json!({ "text": "hello" }),
            &default_inputs(),
            &key,
        )
        .expect("sign");
        (signed, key)
    }

    #[test]
    fn signed_request_carries_both_protected_identifiers() {
        let (signed, _) = sign();
        let env = &signed.object()["params"]["_meta"][REQUEST_META_KEY];
        assert_eq!(env["version"], json!("draft-02"));
        assert_eq!(
            env["canonicalization_id"],
            json!(CANONICALIZATION_ID_INT53_V1)
        );
        assert_eq!(env["audience"], json!("did:example:server"));
        assert_eq!(env["nonce"], json!("Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA"));
        assert_eq!(env["issued_at"], json!("2026-06-30T20:00:00Z"));
        assert_eq!(env["expires_at"], json!("2026-06-30T20:05:00Z"));
        assert_eq!(env["signature"]["alg"], json!("Ed25519"));
        assert_eq!(env["signature"]["key_id"], json!("client-key-1"));
        assert!(
            env["signature"]["value"].is_string(),
            "signature value grafted"
        );
    }

    #[test]
    fn request_hash_is_well_formed_and_value_independent() {
        let (signed, _) = sign();
        assert!(signed.request_hash().starts_with("sha256:"));
        assert!(!signed.request_hash().contains('='));
        // Mutating signature.value must NOT change request_hash (it is excluded
        // from the preimage).
        let mut other = signed.object().clone();
        other["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = json!("ZGlmZmVyZW50");
        assert_eq!(signed.request_hash(), request_hash(&other).unwrap());
    }

    #[test]
    fn empty_canonicalization_id_fails_closed_before_signing() {
        let mut inputs = default_inputs();
        inputs.canonicalization_id = String::new();
        let key = SigningKey::from_seed_bytes(&SEED);
        assert_eq!(
            build_signed_tool_call(&json!(1), "echo", json!({}), &inputs, &key).unwrap_err(),
            McpsError::CanonicalizationIdMissing
        );
    }

    #[test]
    fn unsupported_canonicalization_id_fails_closed() {
        let mut inputs = default_inputs();
        inputs.canonicalization_id = "mcps-jcs-floats-v2".to_string();
        let key = SigningKey::from_seed_bytes(&SEED);
        assert_eq!(
            build_signed_tool_call(&json!(1), "echo", json!({}), &inputs, &key).unwrap_err(),
            McpsError::CanonicalizationIdNotAllowed
        );
    }

    #[test]
    fn caller_supplied_request_meta_is_overwritten() {
        // A caller cannot smuggle a forged envelope — the client core authors it.
        let key = SigningKey::from_seed_bytes(&SEED);
        let mut params = Map::new();
        params.insert("name".into(), json!("echo"));
        params.insert("arguments".into(), json!({}));
        params.insert(
            "_meta".into(),
            json!({ REQUEST_META_KEY: { "version": "draft-01", "forged": true } }),
        );
        let signed = build_signed_request(&json!(1), "tools/call", params, &default_inputs(), &key)
            .expect("sign");
        let env = &signed.object()["params"]["_meta"][REQUEST_META_KEY];
        assert_eq!(env["version"], json!("draft-02"));
        assert!(
            env.get("forged").is_none(),
            "forged envelope must be replaced"
        );
    }
}
