//! Signing-preimage and `request_hash` construction (MCPS_SPEC §3 / ADR-004).
//!
//! The MCP-S signing rule signs the COMPLETE JSON-RPC object, not just the
//! envelope. The preimage is the object with two explicitly-excluded sets removed
//! (ADR-MCPS-026 signed/unsigned `_meta` partition), canonicalized with RFC 8785
//! (JCS):
//!
//! 1. the envelope's `signature.value` (but `signature.alg` and `signature.key_id`
//!    are RETAINED); and
//! 2. the W3C Trace Context observability keys
//!    ([`crate::ids::OBSERVABILITY_META_KEYS`]) under the located container's
//!    `_meta` — mutated by tracing middle boxes, so out of signing scope.
//!
//! Everything else — including a per-request `protocolVersion` and any unknown
//! `_meta` key — is IN scope and integrity-protected. We operate on a
//! `serde_json::Value` here and reuse
//! [`crate::canonical::canonicalize_json_value`] for the canonical bytes.
//!
//! Envelope placement (frozen, from §2 / the brief's unchanged JSON shape):
//! - request envelope: `object["params"]["_meta"][REQUEST_META_KEY]`
//! - response envelope: `object["result"]["_meta"][RESPONSE_META_KEY]`
//!
//! If the envelope (or its `signature` block) is absent →
//! [`McpsError::MissingEnvelope`].
//!
//! NOTE: this layer does NOT perform duplicate-key detection — that belongs to
//! the raw-bytes [`crate::canonical::canonicalize`] path run by the pipeline
//! (MCPS-008) on the original wire bytes. Here we assume a `serde_json::Value`
//! already derived from validated wire bytes.

use serde_json::Value;

use crate::canonical::canonicalize_json_value;
use crate::error::McpsError;
use crate::hash::sha256_hash_id;
use crate::ids::OBSERVABILITY_META_KEYS;
use crate::ids::REQUEST_META_KEY;
use crate::ids::RESPONSE_META_KEY;

/// Build the canonical signing preimage for a REQUEST object: clone, locate the
/// request envelope under `params._meta[REQUEST_META_KEY]`, remove
/// `signature.value`, canonicalize.
pub fn request_signing_preimage(object: &Value) -> Result<Vec<u8>, McpsError> {
    signing_preimage(object, EnvelopeLocation::Request)
}

/// Build the canonical signing preimage for a RESPONSE object: clone, locate the
/// response envelope under `result._meta[RESPONSE_META_KEY]`, remove
/// `signature.value`, canonicalize.
pub fn response_signing_preimage(object: &Value) -> Result<Vec<u8>, McpsError> {
    signing_preimage(object, EnvelopeLocation::Response)
}

/// Which envelope (and therefore which `_meta` key + container) to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeLocation {
    /// `params._meta[REQUEST_META_KEY]`.
    Request,
    /// `result._meta[RESPONSE_META_KEY]`.
    Response,
}

impl EnvelopeLocation {
    fn container_key(self) -> &'static str {
        match self {
            EnvelopeLocation::Request => "params",
            EnvelopeLocation::Response => "result",
        }
    }

    fn meta_key(self) -> &'static str {
        match self {
            EnvelopeLocation::Request => REQUEST_META_KEY,
            EnvelopeLocation::Response => RESPONSE_META_KEY,
        }
    }
}

/// Produce the canonical signing preimage for the given envelope location.
///
/// The MCP-S signed region is the COMPLETE JSON-RPC object MINUS exactly two
/// explicitly-excluded sets (ADR-MCPS-026, the signed/unsigned `_meta`
/// partition):
///
/// 1. `signature.value` of the located envelope (always — a signature cannot
///    cover itself), with `signature.alg`/`signature.key_id` retained; and
/// 2. the W3C Trace Context observability keys ([`OBSERVABILITY_META_KEYS`]) under
///    the located container's `_meta` — they are rewritten by legitimate tracing
///    middle boxes and MUST NOT be in scope or influence any security decision.
///
/// EVERYTHING ELSE is in scope and therefore integrity-protected: a per-request
/// `protocolVersion` (rule 2) and any unknown `_meta` key (rule 6) are signed, so
/// tampering them fails verification. The exclusion is applied identically here
/// for both signing and verification (one shared function), so a middle box that
/// mutates only a trace field cannot break the signature. Missing envelope or
/// signature block → [`McpsError::MissingEnvelope`].
pub fn signing_preimage(
    object: &Value,
    location: EnvelopeLocation,
) -> Result<Vec<u8>, McpsError> {
    let mut cloned = object.clone();
    strip_signature_value(&mut cloned, location)?;
    strip_observability_meta(&mut cloned, location);
    canonicalize_json_value(&cloned)
}

/// `request_hash` (MCPS_SPEC §3.6): SHA-256 of the REQUEST signing preimage,
/// formatted `sha256:<b64url-no-pad>`.
pub fn request_hash(request_object: &Value) -> Result<String, McpsError> {
    let preimage = request_signing_preimage(request_object)?;
    Ok(sha256_hash_id(&preimage))
}

/// Remove `signature.value` from the envelope at `location`, in place. Returns
/// [`McpsError::MissingEnvelope`] if the container, `_meta`, the envelope, or its
/// `signature` block is absent.
fn strip_signature_value(
    object: &mut Value,
    location: EnvelopeLocation,
) -> Result<(), McpsError> {
    let container = object
        .get_mut(location.container_key())
        .ok_or(McpsError::MissingEnvelope)?;
    let meta = container
        .get_mut("_meta")
        .ok_or(McpsError::MissingEnvelope)?;
    let envelope = meta
        .get_mut(location.meta_key())
        .ok_or(McpsError::MissingEnvelope)?;
    let signature = envelope
        .get_mut("signature")
        .ok_or(McpsError::MissingEnvelope)?;
    let signature_obj = signature
        .as_object_mut()
        .ok_or(McpsError::MissingEnvelope)?;
    // Removing a possibly-absent key is fine; the preimage is "the object with
    // signature.value removed", whether or not it was present.
    signature_obj.remove("value");
    Ok(())
}

/// Remove the excluded W3C Trace Context observability keys
/// ([`OBSERVABILITY_META_KEYS`]) from the located container's `_meta`, in place
/// (ADR-MCPS-026 rule 5). Best-effort and infallible: any absent segment (or a
/// `_meta` that is not an object) simply means there is nothing to exclude — the
/// caller has already validated envelope presence via [`strip_signature_value`].
/// Stripping an absent key is a no-op, so an object with no trace fields produces
/// exactly the same preimage as before this rule existed.
///
/// # Scope is container-level ONLY — by design (issue #22, cluster 3)
///
/// The exclusion targets EXACTLY the located container's `_meta`
/// (`params._meta` for a request, `result._meta` for a response) and is NOT
/// recursive. A trace-context key in a NESTED `_meta` (e.g.
/// `params.arguments._meta.traceparent`) is deliberately LEFT IN signing scope and
/// is therefore integrity-protected like any other application payload (ADR-026
/// rule 6). The rationale: the W3C Trace Context exclusion exists solely because
/// legitimate tracing middle boxes rewrite the request/response's OWN trace context
/// (at the container `_meta`) in flight; a `traceparent` buried inside the
/// application's `arguments` is not that transport-level field — it is data the
/// caller chose to send, so signing it is correct. Broadening the exclusion to
/// nested `_meta` would let an attacker move security-relevant bytes out of signing
/// scope simply by nesting them under a reserved name. The boundary is pinned by
/// `nested_trace_key_is_in_signing_scope`.
fn strip_observability_meta(object: &mut Value, location: EnvelopeLocation) {
    if let Some(meta) = object
        .get_mut(location.container_key())
        .and_then(|container| container.get_mut("_meta"))
        .and_then(|meta| meta.as_object_mut())
    {
        for key in OBSERVABILITY_META_KEYS {
            meta.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::request_hash;
    use super::request_signing_preimage;
    use super::response_signing_preimage;
    use crate::canonical::canonicalize_json_value;
    use crate::error::McpsError;
    use serde_json::json;
    use serde_json::Value;

    fn request_object() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello" },
                "_meta": {
                    "se.syncom/mcps.request": {
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
                    }
                }
            }
        })
    }

    fn response_object() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "content": [{ "type": "text", "text": "hello" }],
                "_meta": {
                    "se.syncom/mcps.response": {
                        "request_hash": "sha256:BBBB",
                        "server_signer": "did:example:server",
                        "issued_at": "2026-05-28T20:00:01Z",
                        "signature": {
                            "alg": "Ed25519",
                            "key_id": "srv-key-1",
                            "value": "cmVzcG9uc2VzaWc"
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn preimage_excludes_value_but_keeps_alg_and_key_id() {
        let preimage = request_signing_preimage(&request_object()).expect("preimage");
        let text = String::from_utf8(preimage).expect("utf8");
        assert!(!text.contains("c2lnbmF0dXJl"), "signature value must be removed");
        assert!(text.contains("\"alg\":\"Ed25519\""), "alg must be retained");
        assert!(text.contains("\"key_id\":\"key-1\""), "key_id must be retained");
    }

    #[test]
    fn preimage_equals_canonicalize_of_object_with_value_removed() {
        // Independently build the expected: same object, signature.value removed.
        let mut expected_obj = request_object();
        expected_obj["params"]["_meta"]["se.syncom/mcps.request"]["signature"]
            .as_object_mut()
            .unwrap()
            .remove("value");
        let expected = canonicalize_json_value(&expected_obj).expect("canon");

        let actual = request_signing_preimage(&request_object()).expect("preimage");
        assert_eq!(actual, expected);
    }

    #[test]
    fn response_preimage_targets_result_meta() {
        let preimage = response_signing_preimage(&response_object()).expect("preimage");
        let text = String::from_utf8(preimage).expect("utf8");
        assert!(!text.contains("cmVzcG9uc2VzaWc"), "response sig value removed");
        assert!(text.contains("server_signer"));
    }

    #[test]
    fn missing_request_envelope_errors() {
        let obj = json!({ "jsonrpc": "2.0", "id": 1, "params": { "name": "x" } });
        assert_eq!(
            request_signing_preimage(&obj).unwrap_err(),
            McpsError::MissingEnvelope
        );
    }

    #[test]
    fn missing_signature_block_errors() {
        let mut obj = request_object();
        obj["params"]["_meta"]["se.syncom/mcps.request"]
            .as_object_mut()
            .unwrap()
            .remove("signature");
        assert_eq!(
            request_signing_preimage(&obj).unwrap_err(),
            McpsError::MissingEnvelope
        );
    }

    #[test]
    fn request_hash_is_deterministic_and_well_formed() {
        let h1 = request_hash(&request_object()).expect("hash");
        let h2 = request_hash(&request_object()).expect("hash");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert!(!h1.contains('='));
    }

    #[test]
    fn request_hash_changes_when_argument_changes() {
        let baseline = request_hash(&request_object()).expect("hash");
        let mut mutated = request_object();
        mutated["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
        let changed = request_hash(&mutated).expect("hash");
        assert_ne!(baseline, changed);
    }

    #[test]
    fn request_hash_independent_of_signature_value() {
        // Because the preimage removes signature.value, changing only the value
        // must NOT change the request_hash.
        let baseline = request_hash(&request_object()).expect("hash");
        let mut other_value = request_object();
        other_value["params"]["_meta"]["se.syncom/mcps.request"]["signature"]
            ["value"] = Value::String("ZGlmZmVyZW50".to_string());
        assert_eq!(baseline, request_hash(&other_value).expect("hash"));
    }

    // ---- ADR-MCPS-026 signed/unsigned `_meta` partition -----------------------

    /// Add a string-valued peer `_meta` member alongside the request envelope.
    fn add_peer(object: &mut Value, key: &str, value: &str) {
        object["params"]["_meta"]
            .as_object_mut()
            .expect("params._meta object")
            .insert(key.to_string(), Value::String(value.to_string()));
    }

    #[test]
    fn trace_context_keys_are_excluded_from_the_preimage() {
        // A request WITHOUT trace fields and one WITH them (any values) must
        // produce the SAME preimage — trace context is out of signing scope.
        let baseline = request_signing_preimage(&request_object()).expect("preimage");

        let mut traced = request_object();
        add_peer(&mut traced, "traceparent", "00-abc-def-01");
        add_peer(&mut traced, "tracestate", "vendor=xyz");
        add_peer(&mut traced, "baggage", "k=v");
        let with_trace = request_signing_preimage(&traced).expect("preimage");

        assert_eq!(
            baseline, with_trace,
            "trace-context _meta keys must not affect the signing preimage"
        );
    }

    #[test]
    fn mutating_a_trace_field_does_not_change_the_preimage() {
        let mut a = request_object();
        add_peer(&mut a, "traceparent", "00-aaaa-1");
        let mut b = request_object();
        add_peer(&mut b, "traceparent", "00-bbbb-2");
        assert_eq!(
            request_signing_preimage(&a).expect("preimage"),
            request_signing_preimage(&b).expect("preimage"),
            "rewriting traceparent (as a middle box would) must not change the preimage"
        );
    }

    #[test]
    fn nested_trace_key_is_in_signing_scope() {
        // Issue #22 (cluster 3): the trace-context exclusion is container-`_meta`-
        // level ONLY. A `traceparent` nested under `params.arguments._meta` is NOT
        // the request's transport-level trace context — it is application payload
        // and stays IN signing scope, so mutating it MUST change the preimage.
        // This pins the boundary against an accidental broadening of the exclusion
        // (which would let an attacker exclude bytes from signing by nesting them
        // under a reserved name).
        let mut base = request_object();
        base["params"]["arguments"]["_meta"] = json!({ "traceparent": "00-aaaa-1" });
        let mut altered = request_object();
        altered["params"]["arguments"]["_meta"] = json!({ "traceparent": "00-bbbb-2" });
        assert_ne!(
            request_signing_preimage(&base).expect("preimage"),
            request_signing_preimage(&altered).expect("preimage"),
            "a NESTED _meta.traceparent is integrity-protected; only the container \
             _meta trace context is excluded from the preimage"
        );
    }

    #[test]
    fn protocol_version_is_in_signing_scope() {
        // A per-request protocolVersion peer key is NOT excluded, so changing it
        // MUST change the preimage (it is integrity-protected, ADR-026 rule 2).
        let mut base = request_object();
        add_peer(&mut base, "protocolVersion", "2026-07-28");
        let mut altered = request_object();
        add_peer(&mut altered, "protocolVersion", "2025-06-18");
        assert_ne!(
            request_signing_preimage(&base).expect("preimage"),
            request_signing_preimage(&altered).expect("preimage"),
            "protocolVersion is in signing scope; altering it must change the preimage"
        );
    }

    #[test]
    fn unknown_signed_region_key_is_integrity_protected() {
        // Any unknown _meta peer key (not a trace key) is in scope, so tampering
        // it changes the preimage (rule 6: it cannot be silently altered).
        let mut base = request_object();
        add_peer(&mut base, "io.example/capability", "a");
        let mut altered = request_object();
        add_peer(&mut altered, "io.example/capability", "b");
        assert_ne!(
            request_signing_preimage(&base).expect("preimage"),
            request_signing_preimage(&altered).expect("preimage"),
        );
    }
}
