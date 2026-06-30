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

/// The canonical preimage EXCLUSION PREDICATE (ADR-MCPS-038 / decision C.1),
/// made explicit as an enumerable set of JSON paths. The signed preimage is the
/// complete JSON-RPC object MINUS exactly these paths — **nothing recursive,
/// nothing by key-name alone**:
///
/// 1. the located envelope's `signature.value`
///    (req `params._meta["se.syncom/mcps.request"].signature.value`;
///     resp `result._meta["se.syncom/mcps.response"].signature.value`); and
/// 2. the three W3C Trace Context keys ([`OBSERVABILITY_META_KEYS`]) at
///    **container-level** `_meta` only
///    (req `params._meta.{traceparent,tracestate,baggage}`;
///     resp `result._meta.{...}`).
///
/// A `traceparent` under `params.arguments._meta` or `result.content[*]._meta`
/// is application payload and stays SIGNED — recursive name-based exclusion would
/// let an attacker relocate security bytes under a reserved observability name to
/// strip them from integrity coverage (decision C.1). This is the SAME predicate
/// draft-01 and draft-02 both obey ([`signing_preimage`] is version-agnostic);
/// exposing it as data lets an independent verifier recompute the preimage by
/// deleting exactly these paths — the C.1 byte-equality oracle.
///
/// Each path is a sequence of object-key segments from the document root. Array
/// indices are intentionally absent: the predicate never excludes anything inside
/// an array (`result.content[*]`), by design.
pub fn preimage_exclusion_paths(location: EnvelopeLocation) -> Vec<Vec<String>> {
    let container = location.container_key().to_string();
    let meta_key = location.meta_key().to_string();
    let mut paths = Vec::with_capacity(1 + OBSERVABILITY_META_KEYS.len());
    // (1) the located envelope's signature.value.
    paths.push(vec![
        container.clone(),
        "_meta".to_string(),
        meta_key,
        "signature".to_string(),
        "value".to_string(),
    ]);
    // (2) container-level W3C trace keys only.
    for key in OBSERVABILITY_META_KEYS {
        paths.push(vec![container.clone(), "_meta".to_string(), key.to_string()]);
    }
    paths
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
    use super::preimage_exclusion_paths;
    use super::request_hash;
    use super::request_signing_preimage;
    use super::response_signing_preimage;
    use super::EnvelopeLocation;
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

    // ---- ADR-MCPS-038 / decision C.1 — explicit exclusion predicate ----------

    /// Delete an object-key path (the predicate's representation) from a value;
    /// independent of the production builder's `strip_*` functions.
    fn remove_path(value: &mut Value, path: &[String]) {
        let Some((last, parents)) = path.split_last() else {
            return;
        };
        let mut cur = value;
        for seg in parents {
            match cur.get_mut(seg) {
                Some(next) => cur = next,
                None => return,
            }
        }
        if let Some(obj) = cur.as_object_mut() {
            obj.remove(last);
        }
    }

    /// A draft-02 request object with BOTH protected identifiers, a container-level
    /// trace key (excluded) AND a nested `arguments._meta` trace key (signed).
    fn draft02_request_object() -> Value {
        let mut obj = request_object();
        let env = obj["params"]["_meta"]["se.syncom/mcps.request"]
            .as_object_mut()
            .unwrap();
        env.insert("version".into(), json!("draft-02"));
        env.insert("canonicalization_id".into(), json!("mcps-jcs-int53-json-v1"));
        // container-level trace key — EXCLUDED by the predicate.
        obj["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .insert("traceparent".into(), json!("00-aaaa-1"));
        // nested trace key — application payload, SIGNED.
        obj["params"]["arguments"]
            .as_object_mut()
            .unwrap()
            .insert("_meta".into(), json!({ "traceparent": "00-bbbb-2" }));
        obj
    }

    #[test]
    fn draft02_preimage_equals_independent_predicate_deletion() {
        // C.1 byte-equality oracle: the production preimage must equal the object
        // with EXACTLY the predicate paths deleted by independent code.
        let obj = draft02_request_object();
        let actual = request_signing_preimage(&obj).expect("preimage");

        let mut expected_obj = obj.clone();
        for path in preimage_exclusion_paths(EnvelopeLocation::Request) {
            remove_path(&mut expected_obj, &path);
        }
        let expected = canonicalize_json_value(&expected_obj).expect("canon");
        assert_eq!(actual, expected, "preimage excludes exactly the predicate");
    }

    #[test]
    fn draft02_predicate_excludes_container_trace_but_keeps_protected_and_nested() {
        let preimage = request_signing_preimage(&draft02_request_object()).expect("preimage");
        let text = String::from_utf8(preimage).expect("utf8");
        // signature.value excluded.
        assert!(!text.contains("c2lnbmF0dXJl"));
        // container-level traceparent excluded.
        assert!(!text.contains("00-aaaa-1"));
        // nested arguments._meta.traceparent RETAINED (signed).
        assert!(text.contains("00-bbbb-2"));
        // protected identifiers RETAINED.
        assert!(text.contains("draft-02"));
        assert!(text.contains("mcps-jcs-int53-json-v1"));
        assert!(text.contains("\"alg\":\"Ed25519\""));
        assert!(text.contains("\"key_id\":\"key-1\""));
    }

    #[test]
    fn draft02_preimage_is_byte_identical_across_key_order_whitespace_escapes() {
        // Determinism: three raw encodings that differ only in member order,
        // whitespace, and escape spelling (e == 'e') must canonicalize to a
        // byte-identical preimage.
        let pretty = r#"{
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello" },
                "_meta": {
                    "se.syncom/mcps.request": {
                        "version": "draft-02",
                        "canonicalization_id": "mcps-jcs-int53-json-v1",
                        "signer": "did:example:host",
                        "on_behalf_of": "user:alice",
                        "audience": "did:example:server",
                        "authorization_hash": "sha256:AAAA",
                        "nonce": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
                        "issued_at": "2026-05-28T20:00:00Z",
                        "expires_at": "2026-05-28T20:05:00Z",
                        "signature": { "alg": "Ed25519", "key_id": "key-1", "value": "c2lnbmF0dXJl" }
                    }
                }
            }
        }"#;
        // Reordered members, collapsed whitespace, and an escaped 'e' in "echo".
        let reordered = r#"{"method":"tools/call","params":{"_meta":{"se.syncom/mcps.request":{"signature":{"value":"c2lnbmF0dXJl","key_id":"key-1","alg":"Ed25519"},"expires_at":"2026-05-28T20:05:00Z","issued_at":"2026-05-28T20:00:00Z","nonce":"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA","authorization_hash":"sha256:AAAA","audience":"did:example:server","on_behalf_of":"user:alice","signer":"did:example:host","canonicalization_id":"mcps-jcs-int53-json-v1","version":"draft-02"}},"arguments":{"text":"hello"},"name":"echo"},"id":"req-1","jsonrpc":"2.0"}"#;

        let a: Value = serde_json::from_str(pretty).expect("parse pretty");
        let b: Value = serde_json::from_str(reordered).expect("parse reordered");
        assert_eq!(
            request_signing_preimage(&a).expect("preimage a"),
            request_signing_preimage(&b).expect("preimage b"),
            "key order / whitespace / escape spelling must not change the preimage"
        );
    }

    /// Mutating any protected draft-02 field — version, canonicalization_id, alg,
    /// key_id — changes the preimage (none are excluded), so the signature breaks.
    #[test]
    fn draft02_mutating_protected_fields_changes_the_preimage() {
        let baseline = request_signing_preimage(&draft02_request_object()).expect("preimage");
        for (field, value) in [
            ("version", json!("draft-99")),
            ("canonicalization_id", json!("mcps-jcs-other-v1")),
        ] {
            let mut m = draft02_request_object();
            m["params"]["_meta"]["se.syncom/mcps.request"][field] = value;
            assert_ne!(
                baseline,
                request_signing_preimage(&m).expect("preimage"),
                "mutating protected field {field} must change the preimage"
            );
        }
        for (field, value) in [("alg", json!("RS256")), ("key_id", json!("key-2"))] {
            let mut m = draft02_request_object();
            m["params"]["_meta"]["se.syncom/mcps.request"]["signature"][field] = value;
            assert_ne!(
                baseline,
                request_signing_preimage(&m).expect("preimage"),
                "mutating signature.{field} must change the preimage"
            );
        }
    }

    #[test]
    fn exclusion_predicate_enumerates_exactly_the_documented_paths() {
        let req = preimage_exclusion_paths(EnvelopeLocation::Request);
        assert_eq!(
            req,
            vec![
                vec![
                    "params".to_string(),
                    "_meta".to_string(),
                    "se.syncom/mcps.request".to_string(),
                    "signature".to_string(),
                    "value".to_string()
                ],
                vec!["params".to_string(), "_meta".to_string(), "traceparent".to_string()],
                vec!["params".to_string(), "_meta".to_string(), "tracestate".to_string()],
                vec!["params".to_string(), "_meta".to_string(), "baggage".to_string()],
            ]
        );
        let resp = preimage_exclusion_paths(EnvelopeLocation::Response);
        assert_eq!(resp[0][0], "result");
        assert_eq!(resp[0][2], "se.syncom/mcps.response");
        assert_eq!(resp.len(), 4);
    }
}
