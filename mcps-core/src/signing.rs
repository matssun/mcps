//! Signing-preimage and `request_hash` construction (MCPS_SPEC §3 / ADR-004).
//!
//! The MCP-S signing rule signs the COMPLETE JSON-RPC object, not just the
//! envelope. The preimage is the object with the envelope's `signature.value`
//! REMOVED (but `signature.alg` and `signature.key_id` RETAINED), canonicalized
//! with RFC 8785 (JCS). We operate on a `serde_json::Value` here and reuse
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
/// Clones the object, removes `signature.value` from the located envelope while
/// retaining `signature.alg`/`signature.key_id`, and canonicalizes via RFC 8785.
/// Missing envelope or signature block → [`McpsError::MissingEnvelope`].
pub fn signing_preimage(
    object: &Value,
    location: EnvelopeLocation,
) -> Result<Vec<u8>, McpsError> {
    let mut cloned = object.clone();
    strip_signature_value(&mut cloned, location)?;
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
}
