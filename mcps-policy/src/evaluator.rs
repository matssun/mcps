//! The policy evaluator (MCPS-021, ADR-MCPS-013).
//!
//! [`PolicyEvaluator`] ties Core's verification output to a profile decision. It
//! is profile-agnostic: it extracts the `.authorization` block, selects the
//! registered profile by id, checks the hash binding
//! (`sha256(artifact) == verified.authorization_hash`) BEFORE trusting the
//! artifact's claims, and then dispatches to the profile.
//!
//! Evaluation order (fail closed at the first failing step):
//! 1. extract the `.authorization` block         -> authorization_block_missing / _malformed
//! 2. select profile by id                        -> authorization_profile_unsupported
//! 3. decode artifact bytes                       -> authorization_malformed
//! 4. hash binding == verified authorization_hash -> authorization_hash_mismatch
//! 5. profile.authorize(...)                      -> Allow | Deny(authorization_*)

use std::collections::BTreeMap;

use mcps_core::TrustResolver;
use mcps_core::VerifiedRequest;
use serde_json::Value;

use crate::block::extract_authorization_block;
use crate::decision::AuthorizationDecision;
use crate::error::PolicyError;
use crate::profile::AuthorizationProfile;
use crate::revocation::RevocationSource;

/// A registry of [`AuthorizationProfile`]s that evaluates a verified request
/// against the authorization artifact it carries.
#[derive(Default)]
pub struct PolicyEvaluator {
    profiles: BTreeMap<String, Box<dyn AuthorizationProfile>>,
}

impl PolicyEvaluator {
    /// An evaluator with no profiles registered.
    pub fn new() -> Self {
        PolicyEvaluator {
            profiles: BTreeMap::new(),
        }
    }

    /// Register a profile, keyed by its [`AuthorizationProfile::profile_id`]. A
    /// later registration with the same id replaces the earlier one.
    pub fn register(&mut self, profile: Box<dyn AuthorizationProfile>) {
        self.profiles
            .insert(profile.profile_id().to_string(), profile);
    }

    /// Evaluate a verified request. Always returns a decision (never errors): any
    /// structural problem becomes a [`AuthorizationDecision::Deny`] with the
    /// precise [`PolicyError`].
    ///
    /// `request` is the ORIGINAL JSON-RPC request object (carrying the
    /// `.authorization` block and the method/tool/arguments for scope).
    pub fn evaluate(
        &self,
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> AuthorizationDecision {
        match self.evaluate_inner(verified, request, resolver, revocation, now_unix) {
            Ok(decision) => decision,
            Err(err) => AuthorizationDecision::Deny(err),
        }
    }

    fn evaluate_inner(
        &self,
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> Result<AuthorizationDecision, PolicyError> {
        let block = extract_authorization_block(request)?;
        let profile = self
            .profiles
            .get(&block.profile)
            .ok_or(PolicyError::AuthorizationProfileUnsupported)?;
        let artifact_bytes = block.decoded_artifact()?;

        // Hash binding precedes any interpretation of the artifact's claims.
        let expected = profile.expected_authorization_hash(&artifact_bytes)?;
        if expected != verified.authorization_hash {
            return Err(PolicyError::AuthorizationHashMismatch);
        }

        Ok(profile.authorize(&artifact_bytes, verified, request, resolver, revocation, now_unix))
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyEvaluator;
    use crate::block::AUTHORIZATION_META_KEY;
    use crate::decision::AuthorizationDecision;
    use crate::error::PolicyError;
    use crate::profile::AuthorizationProfile;
    use crate::reference::mint_reference_grant;
    use crate::reference::GrantedOperation;
    use crate::reference::ReferenceGrantSpec;
    use crate::reference::ReferenceProfile;
    use crate::reference::REFERENCE_PROFILE_ID;
    use crate::revocation::InMemoryRevocationSource;
    use mcps_core::b64url_encode;
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

    fn issuer_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[42u8; 32])
    }
    fn resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
        r
    }
    fn now() -> i64 {
        mcps_core::parse_rfc3339_utc(NOT_BEFORE).expect("parse") + 1_800
    }

    fn spec() -> ReferenceGrantSpec {
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

    fn evaluator() -> PolicyEvaluator {
        let mut e = PolicyEvaluator::new();
        e.register(Box::new(ReferenceProfile::new()));
        e
    }

    /// Build the request with the .authorization block + a VerifiedRequest whose
    /// authorization_hash binds the minted artifact.
    fn request_and_verified(
        artifact: &[u8],
        profile_id: &str,
    ) -> (Value, VerifiedRequest) {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello" },
                "_meta": {
                    AUTHORIZATION_META_KEY: {
                        "profile": profile_id,
                        "artifact": b64url_encode(artifact),
                    }
                }
            }
        });
        let authorization_hash = ReferenceProfile::new()
            .expected_authorization_hash(artifact)
            .expect("hash");
        let verified = VerifiedRequest {
            verified_signer: AGENT.to_string(),
            key_id: "key-1".to_string(),
            on_behalf_of: USER.to_string(),
            audience: SERVER.to_string(),
            authorization_hash,
            request_hash: "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            nonce: "nonce-1".to_string(),
            issued_at: NOT_BEFORE.to_string(),
            expires_at: EXPIRES_AT.to_string(),
        };
        (request, verified)
    }

    #[test]
    fn end_to_end_allow() {
        let artifact = mint_reference_grant(&spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let (request, verified) = request_and_verified(&artifact, REFERENCE_PROFILE_ID);
        let decision = evaluator().evaluate(
            &verified,
            &request,
            &resolver(),
            &InMemoryRevocationSource::new(),
            now(),
        );
        assert_eq!(decision, AuthorizationDecision::Allow);
    }

    #[test]
    fn missing_block_is_block_missing() {
        let plain = json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hello" } }
        });
        let (_, verified) = request_and_verified(
            &mint_reference_grant(&spec(), &issuer_key(), ISSUER_KEY_ID).unwrap(),
            REFERENCE_PROFILE_ID,
        );
        let decision = evaluator().evaluate(
            &verified,
            &plain,
            &resolver(),
            &InMemoryRevocationSource::new(),
            now(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationBlockMissing)
        );
    }

    #[test]
    fn unknown_profile_is_unsupported() {
        let artifact = mint_reference_grant(&spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let (request, verified) = request_and_verified(&artifact, "se.syncom/mcps-authz-biscuit-v1");
        let decision = evaluator().evaluate(
            &verified,
            &request,
            &resolver(),
            &InMemoryRevocationSource::new(),
            now(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationProfileUnsupported)
        );
    }

    #[test]
    fn hash_mismatch_fails_before_artifact_interpretation() {
        // A perfectly valid grant, but the verified authorization_hash does NOT
        // bind it (it binds different bytes). Must deny with hash_mismatch — not
        // any artifact-interpretation error.
        let artifact = mint_reference_grant(&spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let (request, mut verified) = request_and_verified(&artifact, REFERENCE_PROFILE_ID);
        verified.authorization_hash =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let decision = evaluator().evaluate(
            &verified,
            &request,
            &resolver(),
            &InMemoryRevocationSource::new(),
            now(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationHashMismatch)
        );
    }

    #[test]
    fn profile_denial_propagates() {
        // Grant only `echo`, but request a different tool → scope denied, surfaced
        // through the evaluator.
        let artifact = mint_reference_grant(&spec(), &issuer_key(), ISSUER_KEY_ID).unwrap();
        let (mut request, verified) = request_and_verified(&artifact, REFERENCE_PROFILE_ID);
        request["params"]["name"] = json!("delete_everything");
        let decision = evaluator().evaluate(
            &verified,
            &request,
            &resolver(),
            &InMemoryRevocationSource::new(),
            now(),
        );
        assert_eq!(
            decision,
            AuthorizationDecision::Deny(PolicyError::AuthorizationScopeDenied)
        );
    }
}
