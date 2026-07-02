//! Signed draft-02 response verification on the client side (MCPS-41, #188;
//! ADR-MCPS-044 §Minimum responsibilities).
//!
//! This is the return leg of [`crate::request`]. Given the raw response bytes and
//! the expectation drawn from the in-flight correlation entry (MCPS-47) for the
//! request we sent, it confirms the response is genuine MCP-S evidence bound to
//! THIS request. `mcps-core`'s [`verify_response_draft02`] (one shared verifier
//! with the server side) performs the structural + protected
//! `version`/`canonicalization_id` validation, the `signature.alg == Ed25519` gate
//! and present-value check (an unsigned / value-less response is rejected — under
//! `require_mcps` there is no fallback), `server_signer` resolution through the
//! injected [`TrustResolver`], the Ed25519 signature check over the canonical
//! response preimage, and the request binding (same `canonicalization_id` AND
//! `request_hash == expected_request_hash`, mismatch fails closed).
//!
//! This module adds one client-policy guard on top: the verified `server_signer`
//! must equal the signer policy binds to this route/audience when one is pinned
//! (an *unexpected* — even if independently resolvable — signer fails closed). The
//! full `(server_signer, audience)` tuple resolution is MCPS-43 (#190); here the
//! expected signer is an optional caller-supplied value.
//!
//! `server_signer` resolution stays behind the [`TrustResolver`] trait, so the
//! proxy/SDK injects the live-trust / OCSP-backed resolver and this seam never
//! reaches the network itself. The returned [`VerifiedResponse`] is `mcps-core`'s
//! unforgeable proof token (its `server_signer` constructor is crate-private), so
//! a "verified" verdict can only originate from real verification.

use mcps_core::classify_result;
use mcps_core::response_hash;
use mcps_core::verify_response_draft02;
use mcps_core::McpsError;
use mcps_core::ResultClass;
use mcps_core::TrustResolver;
use mcps_core::VerifiedResponse;
use serde_json::Value;

/// What the client expects of the bound response for one outstanding request.
///
/// `expected_request_hash` and `expected_canonicalization_id` come from the
/// locally verified request we sent (the correlation entry, MCPS-47):
/// `SignedRequest::request_hash` and the bound `canonicalization_id`.
/// `expected_server_signer` is the signer policy binds to this route/audience
/// (MCPS-43); leave it `None` to defer the identity check to the resolver's own
/// scope (a resolver that only knows the legitimate anchor already rejects an
/// unknown signer with [`McpsError::ActorBindingFailed`]).
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The `request_hash` of the verified request this response must bind.
    pub expected_request_hash: String,
    /// The `canonicalization_id` bound by the request (request and response share
    /// one scheme — ADR-MCPS-038 decision B.2).
    pub expected_canonicalization_id: String,
    /// The server signer policy expects for this route/audience, if bound. When
    /// `Some`, the verified `server_signer` MUST equal it (unexpected → fail
    /// closed) even if some other signer would independently resolve.
    pub expected_server_signer: Option<String>,
}

impl ResponseExpectation {
    /// Build an expectation from a verified request's `request_hash` and bound
    /// `canonicalization_id`, with no pinned signer (resolver scope governs).
    pub fn new(
        expected_request_hash: impl Into<String>,
        expected_canonicalization_id: impl Into<String>,
    ) -> Self {
        ResponseExpectation {
            expected_request_hash: expected_request_hash.into(),
            expected_canonicalization_id: expected_canonicalization_id.into(),
            expected_server_signer: None,
        }
    }

    /// Pin the expected server signer (MCPS-43 signer→audience binding). A
    /// verified-but-unexpected signer then fails closed.
    pub fn with_expected_server_signer(mut self, signer: impl Into<String>) -> Self {
        self.expected_server_signer = Some(signer.into());
        self
    }
}

/// Verify a signed draft-02 response and confirm it binds the expected request.
///
/// `resolver` is the client's trust resolver (injected by the proxy/SDK — live
/// trust + OCSP live behind the `mcps-core` [`TrustResolver`] trait, so this pure
/// seam never performs I/O). On success returns the unforgeable
/// [`VerifiedResponse`]; on any failure returns the precise frozen
/// [`McpsError`] (→ `wire_code()`), fail-closed.
pub fn verify_signed_response(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    expectation: &ResponseExpectation,
) -> Result<VerifiedResponse, McpsError> {
    // Steps 1-5 — the shared server/client draft-02 response verifier: structure,
    // protected identifiers, alg gate, signer key resolution, signature, and the
    // request_hash + canonicalization_id binding checks.
    let verified = verify_response_draft02(
        raw_bytes,
        resolver,
        &expectation.expected_request_hash,
        &expectation.expected_canonicalization_id,
    )?;

    // Step 6 — unexpected-signer guard (client policy). A signer that verifies but
    // is not the one policy bound to this route/audience is a trust-binding
    // failure, not a valid response (CONTEXT.md §Fallback failure taxonomy:
    // "unexpected server_signer" MUST fail closed). MCPS-43 (#190) resolves the
    // expected signer from the audience tuple; here it is supplied by the caller.
    if let Some(expected) = &expectation.expected_server_signer {
        if verified.server_signer() != expected {
            return Err(McpsError::ActorBindingFailed);
        }
    }

    Ok(verified)
}

/// A verified response plus its multi-round-trip classification (ADR-MCPS-047).
///
/// Produced by [`verify_and_classify_response`] AFTER the signature and request
/// binding verify, so `class` is read from trusted (signed) bytes — never a forged
/// `resultType`. `response_hash` is the hash of the signed response preimage; when
/// `class == ResultClass::InputRequired` it is the `input_required_response_hash`
/// the client binds into its continuation (feed it to
/// [`crate::CorrelationStore::record_input_required`]).
#[derive(Debug, Clone)]
pub struct ClassifiedResponse {
    /// The unforgeable verification verdict.
    pub verified: VerifiedResponse,
    /// Terminal vs non-terminal `InputRequiredResult`.
    pub class: ResultClass,
    /// `sha256:<b64url>` of the verified response preimage.
    pub response_hash: String,
}

/// Verify a signed draft-02 response AND classify its result body for the
/// multi-round-trip flow (ADR-MCPS-047 / D2 + D7).
///
/// Verifies exactly as [`verify_signed_response`] (fail-closed on any evidence
/// failure), then — only on success — classifies the signed `result` body as
/// terminal or `InputRequiredResult` and computes the response preimage hash. The
/// classification is therefore never trusted from unverified bytes: an unsigned or
/// tampered response fails at verification and never reaches classification.
pub fn verify_and_classify_response(
    raw_bytes: &[u8],
    resolver: &dyn TrustResolver,
    expectation: &ResponseExpectation,
) -> Result<ClassifiedResponse, McpsError> {
    let verified = verify_signed_response(raw_bytes, resolver, expectation)?;
    // Verification already parsed and validated these bytes; re-model them to read
    // the (now trusted) result body and compute the preimage hash.
    let object: Value =
        serde_json::from_slice(raw_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;
    let class = match object.get("result") {
        Some(result) => classify_result(result),
        None => ResultClass::Terminal,
    };
    let response_hash = response_hash(&object)?;
    Ok(ClassifiedResponse {
        verified,
        class,
        response_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_signed_tool_call;
    use crate::RequestSigningInputs;
    use mcps_core::ids::DIGEST_ALG_SHA256;
    use mcps_core::AuthorizationBinding;
    use mcps_core::InMemoryTrustResolver;
    use mcps_core::SigningKey;
    use mcps_core::CANONICALIZATION_ID_INT53_V1;
    use mcps_core::RESPONSE_META_KEY;
    use mcps_core::SIG_ALG_ED25519;
    use mcps_core::VERSION_DRAFT_02;
    use serde_json::json;
    use serde_json::Value;

    const CLIENT_SEED: [u8; 32] = [42u8; 32];
    const SERVER_SEED: [u8; 32] = [99u8; 32];
    const CLIENT_SIGNER: &str = "did:example:client";
    const CLIENT_KEY_ID: &str = "client-key-1";
    const SERVER_SIGNER: &str = "did:example:server";
    const SERVER_KEY_ID: &str = "server-key-1";
    const AUDIENCE: &str = "did:example:server";

    /// The request_hash a real client would hold after signing (the correlation
    /// handle the response must bind).
    fn expected_request_hash() -> String {
        let key = SigningKey::from_seed_bytes(&CLIENT_SEED);
        let inputs = RequestSigningInputs::with_default_canonicalization(
            CLIENT_SIGNER,
            CLIENT_KEY_ID,
            "user:alice",
            AUDIENCE,
            AuthorizationBinding::OpaqueBytes {
                digest_alg: DIGEST_ALG_SHA256.to_string(),
                digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            },
            "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
            "2026-06-30T20:00:00Z",
            "2026-06-30T20:05:00Z",
        );
        build_signed_tool_call(
            &json!("req-1"),
            "echo",
            json!({ "text": "hi" }),
            &inputs,
            &key,
        )
        .unwrap()
        .request_hash()
        .to_string()
    }

    /// Build a server-signed draft-02 response object binding `request_hash`,
    /// signed by `server_seed` under `server_signer`/`server_key_id`.
    fn signed_response(
        request_hash: &str,
        server_seed: &[u8; 32],
        server_signer: &str,
        server_key_id: &str,
    ) -> Vec<u8> {
        let key = SigningKey::from_seed_bytes(server_seed);
        let mut object = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "content": [{ "type": "text", "text": "hi" }],
                "_meta": {
                    RESPONSE_META_KEY: {
                        "version": VERSION_DRAFT_02,
                        "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                        "request_hash": request_hash,
                        "server_signer": server_signer,
                        "issued_at": "2026-06-30T20:00:01Z",
                        "signature": { "alg": SIG_ALG_ED25519, "key_id": server_key_id },
                    }
                }
            }
        });
        let preimage = mcps_core::response_signing_preimage(&object).unwrap();
        let sig = key.sign(&preimage);
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
        serde_json::to_vec(&object).unwrap()
    }

    fn resolver_with_server() -> InMemoryTrustResolver {
        let key = SigningKey::from_seed_bytes(&SERVER_SEED);
        let mut r = InMemoryTrustResolver::new();
        r.insert(SERVER_SIGNER, SERVER_KEY_ID, key.public_key());
        r
    }

    fn expectation(request_hash: &str) -> ResponseExpectation {
        ResponseExpectation::new(request_hash, CANONICALIZATION_ID_INT53_V1)
    }

    #[test]
    fn valid_response_is_accepted_and_binds_the_request() {
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);
        let verified =
            verify_signed_response(&bytes, &resolver_with_server(), &expectation(&rh)).unwrap();
        assert_eq!(verified.server_signer(), SERVER_SIGNER);
        assert_eq!(verified.request_hash(), rh);
    }

    #[test]
    fn pinned_expected_signer_accepts_the_match() {
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);
        let exp = expectation(&rh).with_expected_server_signer(SERVER_SIGNER);
        assert!(verify_signed_response(&bytes, &resolver_with_server(), &exp).is_ok());
    }

    #[test]
    fn unsigned_response_is_rejected() {
        // A plain MCP response with no MCP-S envelope: no fallback under require_mcps.
        let rh = expected_request_hash();
        let plain = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": "req-1",
            "result": { "content": [{ "type": "text", "text": "hi" }] }
        }))
        .unwrap();
        assert_eq!(
            verify_signed_response(&plain, &resolver_with_server(), &expectation(&rh)).unwrap_err(),
            McpsError::MissingEnvelope
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let rh = expected_request_hash();
        let mut object: Value = serde_json::from_slice(&signed_response(
            &rh,
            &SERVER_SEED,
            SERVER_SIGNER,
            SERVER_KEY_ID,
        ))
        .unwrap();
        // Flip a result byte AFTER signing.
        object["result"]["content"][0]["text"] = json!("tampered");
        let bytes = serde_json::to_vec(&object).unwrap();
        assert_eq!(
            verify_signed_response(&bytes, &resolver_with_server(), &expectation(&rh)).unwrap_err(),
            McpsError::ResponseSigInvalid
        );
    }

    #[test]
    fn unexpected_signer_unknown_to_resolver_fails_closed() {
        // The response is signed by a different server identity the resolver does
        // not know — resolution fails (ActorBindingFailed).
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &[7u8; 32], "did:example:evil", "evil-key");
        assert_eq!(
            verify_signed_response(&bytes, &resolver_with_server(), &expectation(&rh)).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn resolvable_but_unexpected_pinned_signer_fails_closed() {
        // The signer IS resolvable, but policy pinned a different expected signer:
        // a verified-but-unexpected signer must still fail closed (step 6 guard).
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);
        let exp = expectation(&rh).with_expected_server_signer("did:example:other-tenant");
        assert_eq!(
            verify_signed_response(&bytes, &resolver_with_server(), &exp).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn request_hash_mismatch_fails_closed() {
        let rh = expected_request_hash();
        // Server validly signs a response binding a DIFFERENT request hash than the
        // one we sent. The signature is valid; only the binding check fires.
        let bytes = signed_response(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &SERVER_SEED,
            SERVER_SIGNER,
            SERVER_KEY_ID,
        );
        assert_eq!(
            verify_signed_response(&bytes, &resolver_with_server(), &expectation(&rh)).unwrap_err(),
            McpsError::ResponseHashMismatch
        );
    }

    /// Build a server-signed response whose `result` body is arbitrary (used for
    /// the InputRequiredResult classification tests).
    fn signed_response_with_result(request_hash: &str, result: Value) -> Vec<u8> {
        let key = SigningKey::from_seed_bytes(&SERVER_SEED);
        let mut result = result;
        result["_meta"] = json!({
            RESPONSE_META_KEY: {
                "version": VERSION_DRAFT_02,
                "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                "request_hash": request_hash,
                "server_signer": SERVER_SIGNER,
                "issued_at": "2026-06-30T20:00:01Z",
                "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
            }
        });
        let mut object = json!({ "jsonrpc": "2.0", "id": "req-1", "result": result });
        let preimage = mcps_core::response_signing_preimage(&object).unwrap();
        let sig = key.sign(&preimage);
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(sig);
        serde_json::to_vec(&object).unwrap()
    }

    #[test]
    fn terminal_response_classifies_terminal() {
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);
        let c = verify_and_classify_response(&bytes, &resolver_with_server(), &expectation(&rh))
            .unwrap();
        assert_eq!(c.class, ResultClass::Terminal);
        assert!(c.response_hash.starts_with("sha256:"));
    }

    #[test]
    fn input_required_response_classifies_non_terminal_with_hash() {
        let rh = expected_request_hash();
        let bytes = signed_response_with_result(
            &rh,
            json!({
                "resultType": "inputRequired",
                "inputRequests": { "confirm": { "type": "elicitation" } },
                "requestState": "eyJzdGVwIjoxfQ"
            }),
        );
        let c = verify_and_classify_response(&bytes, &resolver_with_server(), &expectation(&rh))
            .unwrap();
        assert_eq!(c.class, ResultClass::InputRequired);
        // The response hash equals mcps-core's response_hash over the same bytes.
        let object: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(c.response_hash, mcps_core::response_hash(&object).unwrap());
    }

    #[test]
    fn tampered_input_requests_fails_response_verification() {
        // The elicitation prompt fields are INSIDE the signed response preimage
        // (ADR-MCPS-047 / D2): a server prompt cannot be forged. Flip inputRequests
        // AFTER signing -> the signature no longer matches -> fail closed before the
        // prompt is ever classified or shown.
        let rh = expected_request_hash();
        let bytes = signed_response_with_result(
            &rh,
            json!({
                "resultType": "inputRequired",
                "inputRequests": { "confirm": { "type": "elicitation", "message": "Delete 3 files?" } },
                "requestState": "eyJzdGVwIjoxfQ"
            }),
        );
        let mut object: Value = serde_json::from_slice(&bytes).unwrap();
        // A middlebox rewrites the prompt to coerce a different answer.
        object["result"]["inputRequests"]["confirm"]["message"] = json!("Keep all files?");
        let tampered = serde_json::to_vec(&object).unwrap();
        assert_eq!(
            verify_and_classify_response(&tampered, &resolver_with_server(), &expectation(&rh))
                .unwrap_err(),
            McpsError::ResponseSigInvalid
        );
    }

    #[test]
    fn tampered_request_state_fails_response_verification() {
        // requestState is opaque server continuation state, also inside the signed
        // preimage (D2/D5). Tampering it AFTER signing breaks the signature — a
        // continuation can never be steered onto a forged server state.
        let rh = expected_request_hash();
        let bytes = signed_response_with_result(
            &rh,
            json!({
                "resultType": "inputRequired",
                "inputRequests": { "confirm": { "type": "elicitation" } },
                "requestState": "eyJzdGVwIjoxfQ"
            }),
        );
        let mut object: Value = serde_json::from_slice(&bytes).unwrap();
        object["result"]["requestState"] = json!("dGFtcGVyZWQtc3RhdGU");
        let tampered = serde_json::to_vec(&object).unwrap();
        assert_eq!(
            verify_and_classify_response(&tampered, &resolver_with_server(), &expectation(&rh))
                .unwrap_err(),
            McpsError::ResponseSigInvalid
        );
    }

    #[test]
    fn input_required_but_tampered_fails_before_classification() {
        // A forged resultType on an unsigned body must never be classified.
        let rh = expected_request_hash();
        let plain = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": "req-1",
            "result": { "resultType": "inputRequired", "inputRequests": {} }
        }))
        .unwrap();
        assert_eq!(
            verify_and_classify_response(&plain, &resolver_with_server(), &expectation(&rh))
                .unwrap_err(),
            McpsError::MissingEnvelope
        );
    }

    #[test]
    fn canonicalization_id_mismatch_fails_closed() {
        // The response carries the real allowlisted scheme, but the expectation was
        // bound to a different scheme — decision B.2 requires request and response
        // agree, so the post-signature binding check fails closed.
        let rh = expected_request_hash();
        let bytes = signed_response(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID);
        let exp = ResponseExpectation::new(&rh, "mcps-jcs-int53-json-v9-mismatch");
        assert_eq!(
            verify_signed_response(&bytes, &resolver_with_server(), &exp).unwrap_err(),
            McpsError::CanonicalizationIdMismatch
        );
    }
}
