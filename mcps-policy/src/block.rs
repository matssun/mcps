//! The `se.syncom/mcps.authorization` sibling `_meta` block
//! (ADR-MCPS-013).
//!
//! The block travels alongside the Core request envelope under
//! `params._meta`. It is NOT part of the Core signed preimage; it is bound to
//! the request transitively because Core signs `authorization_hash`, which
//! equals `sha256(decoded artifact bytes)`. The block carries a profile
//! identifier (which profile interprets the artifact) and the artifact itself as
//! Base64URL-no-pad bytes.

use mcps_core::b64url_decode;
use serde_json::Value;

use crate::error::PolicyError;

/// `_meta` key under which the authorization block is carried. Defined here (not
/// in `mcps-core`) so Core stays byte-for-byte unchanged; it is never part of any
/// signed preimage. Kept consistent with the Core extension identifier — see the
/// test asserting `AUTHORIZATION_META_KEY == "{EXTENSION_ID}.authorization"`.
pub const AUTHORIZATION_META_KEY: &str = "se.syncom/mcps.authorization";

/// The parsed authorization block: a profile selector plus the raw artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationBlock {
    /// The profile identifier that interprets `artifact` (e.g.
    /// `se.syncom/mcps-authz-reference-v1`).
    pub profile: String,
    /// The artifact as a Base64URL-no-pad string (decode via
    /// [`AuthorizationBlock::decoded_artifact`]).
    pub artifact_b64url: String,
}

impl AuthorizationBlock {
    /// Decode the artifact to raw bytes. A bad Base64URL body is a malformed
    /// artifact ([`PolicyError::AuthorizationMalformed`]).
    pub fn decoded_artifact(&self) -> Result<Vec<u8>, PolicyError> {
        b64url_decode(&self.artifact_b64url).map_err(|_| PolicyError::AuthorizationMalformed)
    }
}

/// Extract the authorization block from a JSON-RPC request object.
///
/// Looks under `params._meta[AUTHORIZATION_META_KEY]`. Absence (no `params`, no
/// `_meta`, or no authorization key) is [`PolicyError::AuthorizationBlockMissing`].
/// A present-but-misshapen block (not an object, or missing/non-string `profile`
/// or `artifact`) is [`PolicyError::AuthorizationMalformed`].
pub fn extract_authorization_block(request: &Value) -> Result<AuthorizationBlock, PolicyError> {
    let block = request
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(AUTHORIZATION_META_KEY))
        .ok_or(PolicyError::AuthorizationBlockMissing)?;

    let object = block
        .as_object()
        .ok_or(PolicyError::AuthorizationMalformed)?;

    let profile = object
        .get("profile")
        .and_then(Value::as_str)
        .ok_or(PolicyError::AuthorizationMalformed)?
        .to_string();
    let artifact_b64url = object
        .get("artifact")
        .and_then(Value::as_str)
        .ok_or(PolicyError::AuthorizationMalformed)?
        .to_string();

    Ok(AuthorizationBlock {
        profile,
        artifact_b64url,
    })
}

#[cfg(test)]
mod tests {
    use super::extract_authorization_block;
    use super::AuthorizationBlock;
    use super::AUTHORIZATION_META_KEY;
    use crate::error::PolicyError;
    use mcps_core::b64url_encode;
    use mcps_core::EXTENSION_ID;
    use serde_json::json;

    #[test]
    fn meta_key_is_namespaced_under_the_extension_id() {
        assert_eq!(
            AUTHORIZATION_META_KEY,
            format!("{EXTENSION_ID}.authorization")
        );
        assert!(AUTHORIZATION_META_KEY.starts_with(EXTENSION_ID));
    }

    fn request_with_block(block: serde_json::Value) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": { "name": "echo", "_meta": { AUTHORIZATION_META_KEY: block } }
        })
    }

    #[test]
    fn extracts_a_well_formed_block_and_decodes_the_artifact() {
        let bytes = b"the-artifact-bytes";
        let req = request_with_block(json!({
            "profile": "se.syncom/mcps-authz-reference-v1",
            "artifact": b64url_encode(bytes),
        }));
        let block = extract_authorization_block(&req).expect("extract");
        assert_eq!(block.profile, "se.syncom/mcps-authz-reference-v1");
        assert_eq!(block.decoded_artifact().expect("decode"), bytes);
    }

    #[test]
    fn absent_block_is_block_missing() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": { "name": "echo", "_meta": {} }
        });
        assert_eq!(
            extract_authorization_block(&req).unwrap_err(),
            PolicyError::AuthorizationBlockMissing
        );
    }

    #[test]
    fn no_params_or_meta_is_block_missing() {
        assert_eq!(
            extract_authorization_block(&json!({ "id": "x" })).unwrap_err(),
            PolicyError::AuthorizationBlockMissing
        );
        assert_eq!(
            extract_authorization_block(&json!({ "params": { "name": "echo" } })).unwrap_err(),
            PolicyError::AuthorizationBlockMissing
        );
    }

    #[test]
    fn misshapen_block_is_malformed() {
        // Block present but not an object.
        assert_eq!(
            extract_authorization_block(&request_with_block(json!("nope"))).unwrap_err(),
            PolicyError::AuthorizationMalformed
        );
        // Missing artifact.
        assert_eq!(
            extract_authorization_block(&request_with_block(json!({ "profile": "p" })))
                .unwrap_err(),
            PolicyError::AuthorizationMalformed
        );
        // Non-string profile.
        assert_eq!(
            extract_authorization_block(&request_with_block(
                json!({ "profile": 1, "artifact": "AAAA" })
            ))
            .unwrap_err(),
            PolicyError::AuthorizationMalformed
        );
    }

    #[test]
    fn bad_base64_artifact_is_malformed_on_decode() {
        let block = AuthorizationBlock {
            profile: "p".to_string(),
            artifact_b64url: "!!!! not base64".to_string(),
        };
        assert_eq!(
            block.decoded_artifact().unwrap_err(),
            PolicyError::AuthorizationMalformed
        );
    }
}
