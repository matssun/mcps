//! Client-side inverse of the proxy's `build_signed_response` reshape
//! (issue #4077 / MCPS-MED-4).
//!
//! The proxy signs EVERY inner result by normalizing it into a signed `result`
//! OBJECT so the signature can never be suppressed by a hostile inner that
//! returns a non-object or an error (see `mcps-proxy` `build_signed_response`):
//!
//! * an OBJECT inner `result` is signed in place;
//! * a NON-OBJECT inner `result` (number/string/bool/array/null) is preserved
//!   under `result.value` and signed;
//! * an inner ERROR (no `result`) is preserved under `result.inner_error` and
//!   signed.
//!
//! Verification ([`crate::verify_response`]) only proves the signature + request
//! binding; it deliberately does not touch the payload. Without a matching
//! client-side unwrap the reshape would leak to the MCP consumer — a scalar `42`
//! would arrive as `{"value":42}`, and an inner error would arrive as a JSON-RPC
//! SUCCESS whose `result` is `{"inner_error":…}` (an error masquerading as
//! success). [`unwrap_verified_result`] restores the ORIGINAL MCP shape AFTER
//! verification has succeeded.
//!
//! The wrapper key names are the shared constants [`RESPONSE_WRAP_VALUE_KEY`] and
//! [`RESPONSE_WRAP_INNER_ERROR_KEY`]; the proxy uses the same constants, so the
//! two sides stay in lockstep.

use serde_json::Map;
use serde_json::Value;

use crate::error::McpsError;
use crate::ids::RESPONSE_WRAP_INNER_ERROR_KEY;
use crate::ids::RESPONSE_WRAP_VALUE_KEY;

/// The `_meta` field carrying the (now-verified) response signature envelope.
/// Stripped before the payload is handed back to the consumer.
const META_FIELD: &str = "_meta";

/// The original MCP shape recovered from a verified, signed `result` object.
///
/// Exactly mirrors the three branches of the proxy's `build_signed_response`:
/// * [`UnwrappedResult::Object`] — a normal object result that was signed in
///   place; the payload is the object with `_meta` removed.
/// * [`UnwrappedResult::Scalar`] — a non-object inner result that the proxy
///   wrapped under `value`; the payload is the original scalar/array/null/object.
/// * [`UnwrappedResult::InnerError`] — an inner ERROR the proxy wrapped under
///   `inner_error`; the caller MUST surface this as a JSON-RPC error (top-level
///   `error`, no `result`), NOT as a success.
#[derive(Debug, Clone, PartialEq)]
pub enum UnwrappedResult {
    /// A normal object result, `_meta` stripped.
    Object(Value),
    /// A scalar/array/null/object that the proxy wrapped under `value`.
    Scalar(Value),
    /// An inner error the proxy wrapped under `inner_error`; surface as an error.
    InnerError(Value),
}

impl UnwrappedResult {
    /// `true` only for the [`UnwrappedResult::InnerError`] case — the consumer
    /// must render a JSON-RPC error rather than a success.
    pub fn is_inner_error(&self) -> bool {
        matches!(self, UnwrappedResult::InnerError(_))
    }

    /// The recovered payload for the non-error cases (the original `result`),
    /// or the inner-error payload for the error case. The variant carries the
    /// error/non-error discrimination; this is the value either way.
    pub fn into_value(self) -> Value {
        match self {
            UnwrappedResult::Object(value)
            | UnwrappedResult::Scalar(value)
            | UnwrappedResult::InnerError(value) => value,
        }
    }
}

/// Recover the original MCP `result` shape from a verified, signed `result`
/// object — the client-side inverse of the proxy's `build_signed_response`.
///
/// MUST be called only on a `result` value whose signature already verified
/// (the proxy guarantees that value is an object carrying `_meta`). The match is
/// EXACT-KEY: the `value` / `inner_error` wrapper is recognized ONLY when it is
/// the SOLE non-`_meta` key, so a legitimate inner object that merely contains a
/// `value` (or `inner_error`) field among others is returned untouched as
/// [`UnwrappedResult::Object`].
///
/// Returns [`McpsError::CanonicalizationFailed`] only for the structurally
/// impossible-post-verification case where `result` is not a JSON object.
pub fn unwrap_verified_result(result_value: &Value) -> Result<UnwrappedResult, McpsError> {
    let object = result_value
        .as_object()
        .ok_or(McpsError::CanonicalizationFailed)?;

    // Strip the signature envelope: everything except `_meta`.
    let mut payload: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| key.as_str() != META_FIELD)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    // A wrapper is recognized ONLY when it is the SOLE non-`_meta` key.
    if payload.len() == 1 {
        if let Some(value) = payload.remove(RESPONSE_WRAP_VALUE_KEY) {
            return Ok(UnwrappedResult::Scalar(value));
        }
        if let Some(inner_error) = payload.remove(RESPONSE_WRAP_INNER_ERROR_KEY) {
            return Ok(UnwrappedResult::InnerError(inner_error));
        }
        // Sole key, but not a wrapper — fall through; re-insert is not needed
        // because we matched by name and only `remove`d on a hit.
    }

    Ok(UnwrappedResult::Object(Value::Object(payload)))
}

#[cfg(test)]
mod tests {
    use super::unwrap_verified_result;
    use super::UnwrappedResult;
    use crate::error::McpsError;
    use serde_json::json;

    fn signed_meta() -> serde_json::Value {
        json!({ "se.syncom/mcps.response": { "signature": { "alg": "Ed25519" } } })
    }

    #[test]
    fn object_result_signed_in_place_strips_only_meta() {
        let result = json!({
            "content": [ { "type": "text", "text": "hi" } ],
            "_meta": signed_meta(),
        });
        let unwrapped = unwrap_verified_result(&result).expect("object unwraps");
        assert_eq!(
            unwrapped,
            UnwrappedResult::Object(json!({ "content": [ { "type": "text", "text": "hi" } ] }))
        );
        assert!(!unwrapped.is_inner_error());
    }

    #[test]
    fn scalar_wrapped_under_value_recovers_the_scalar() {
        let result = json!({ "value": 42, "_meta": signed_meta() });
        let unwrapped = unwrap_verified_result(&result).expect("scalar unwraps");
        assert_eq!(unwrapped, UnwrappedResult::Scalar(json!(42)));
        assert_eq!(unwrapped.into_value(), json!(42));
    }

    #[test]
    fn array_wrapped_under_value_recovers_the_array() {
        let result = json!({ "value": [1, 2, 3], "_meta": signed_meta() });
        let unwrapped = unwrap_verified_result(&result).expect("array unwraps");
        assert_eq!(unwrapped, UnwrappedResult::Scalar(json!([1, 2, 3])));
    }

    #[test]
    fn null_wrapped_under_value_recovers_null() {
        let result = json!({ "value": null, "_meta": signed_meta() });
        let unwrapped = unwrap_verified_result(&result).expect("null unwraps");
        assert_eq!(unwrapped, UnwrappedResult::Scalar(json!(null)));
    }

    #[test]
    fn inner_error_is_signalled_as_an_error() {
        let inner = json!({ "jsonrpc": "2.0", "id": "req-1", "error": { "code": -32000 } });
        let result = json!({ "inner_error": inner.clone(), "_meta": signed_meta() });
        let unwrapped = unwrap_verified_result(&result).expect("inner_error unwraps");
        assert!(unwrapped.is_inner_error());
        assert_eq!(unwrapped, UnwrappedResult::InnerError(inner));
    }

    #[test]
    fn legitimate_object_with_a_value_field_among_others_is_not_a_wrapper() {
        // EXACT-KEY-MATCH: `value` is present but NOT the sole non-_meta key.
        let result = json!({ "value": 7, "unit": "kg", "_meta": signed_meta() });
        let unwrapped = unwrap_verified_result(&result).expect("object unwraps");
        assert_eq!(
            unwrapped,
            UnwrappedResult::Object(json!({ "value": 7, "unit": "kg" }))
        );
    }

    #[test]
    fn object_whose_sole_key_is_named_value_is_a_wrapper_by_construction() {
        // This is the proxy's own scalar wrapping shape; sole non-_meta key.
        let result = json!({ "value": "hello", "_meta": signed_meta() });
        assert_eq!(
            unwrap_verified_result(&result).expect("unwraps"),
            UnwrappedResult::Scalar(json!("hello"))
        );
    }

    #[test]
    fn non_object_result_is_rejected() {
        // Post-verification this cannot occur, but guard it explicitly.
        let err = unwrap_verified_result(&json!(42)).expect_err("non-object rejected");
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }
}
