//! ADR-MCPS-047 stateless multi-round-trip (MRT) continuation helpers.
//!
//! MCP-S secures a stateless elicitation flow as two ordinary signed legs plus a
//! cryptographic linkage between them:
//!
//! ```text
//! client signed request
//!   -> server signed InputRequiredResult   (non-terminal, verified as an ordinary response)
//!   -> client signed continuation request  (bound to the verified InputRequiredResult, D4)
//!   -> server signed terminal response
//! ```
//!
//! This module holds the pure, `no_std`-friendly leaf helpers shared by the proxy,
//! `mcps-client-core`, and the SDK: classifying a verified response's result body,
//! and constructing the typed [`Continuation`] binding. It BINDS, never interprets
//! `inputRequests` / `requestState`.

use serde_json::Value;

use crate::envelope::Continuation;
use crate::ids::RESULT_TYPE_INPUT_REQUIRED;

/// Classification of a verified response's application `result` body.
///
/// The distinction drives correlation lifetime (ADR-MCPS-047 / D7): a terminal
/// result consumes the pending correlation entry, whereas an `InputRequiredResult`
/// is non-terminal — the client keeps the entry (associate-without-consume) and
/// answers with a signed continuation request bound to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    /// A terminal result — the exchange completes; consume the correlation entry.
    Terminal,
    /// An `InputRequiredResult` (SEP-2322). Non-terminal: verify it, RETAIN the
    /// correlation entry, and continue with a signed request bound to it (D3/D4).
    InputRequired,
}

/// Classify a JSON-RPC response `result` body by its `resultType` discriminator.
///
/// `resultType == "inputRequired"` → [`ResultClass::InputRequired`]; anything else,
/// including an absent `resultType`, is [`ResultClass::Terminal`]. Structural only:
/// Core does not read `inputRequests` or `requestState`. This must run on a result
/// body whose response signature has ALREADY verified — an unsigned/forged
/// `resultType` must never reach a trust decision.
pub fn classify_result(result: &Value) -> ResultClass {
    match result.get("resultType").and_then(Value::as_str) {
        Some(RESULT_TYPE_INPUT_REQUIRED) => ResultClass::InputRequired,
        _ => ResultClass::Terminal,
    }
}

/// Build the typed multi-round-trip [`Continuation`] binding (ADR-MCPS-047 / D4)
/// from the two hashes the client holds after verifying an `InputRequiredResult`:
///
/// - `previous_request_hash` — the `request_hash` of the client request that
///   produced the `InputRequiredResult` (see [`crate::request_hash`]);
/// - `input_required_response_hash` — the hash of the verified `InputRequiredResult`
///   response preimage (see [`crate::response_hash`]).
///
/// Both must already be `sha256:<base64url>` identifiers; the structural validator
/// [`crate::constraints`] re-checks their form on the verify side.
pub fn build_mcp_mrt_continuation(
    previous_request_hash: impl Into<String>,
    input_required_response_hash: impl Into<String>,
) -> Continuation {
    Continuation::McpMrt {
        previous_request_hash: previous_request_hash.into(),
        input_required_response_hash: input_required_response_hash.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn input_required_result_is_classified_non_terminal() {
        let result = json!({
            "resultType": "inputRequired",
            "inputRequests": { "confirm": { "type": "elicitation" } },
            "requestState": "eyJzdGVwIjoxfQ"
        });
        assert_eq!(classify_result(&result), ResultClass::InputRequired);
    }

    #[test]
    fn ordinary_result_is_terminal() {
        assert_eq!(
            classify_result(&json!({ "content": [] })),
            ResultClass::Terminal
        );
        assert_eq!(classify_result(&json!({})), ResultClass::Terminal);
    }

    #[test]
    fn unknown_result_type_is_terminal_not_input_required() {
        // Only the exact token is non-terminal; a look-alike stays terminal.
        assert_eq!(
            classify_result(&json!({ "resultType": "somethingElse" })),
            ResultClass::Terminal
        );
    }

    #[test]
    fn builds_the_typed_mcp_mrt_binding() {
        let c = build_mcp_mrt_continuation("sha256:AAAA", "sha256:BBBB");
        assert_eq!(
            c,
            Continuation::McpMrt {
                previous_request_hash: "sha256:AAAA".to_string(),
                input_required_response_hash: "sha256:BBBB".to_string(),
            }
        );
    }
}
