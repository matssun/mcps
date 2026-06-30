//! Demo delegated-authorization wiring (MCPS-048, MCPS-EPIC-P6 Child Issue 4).
//!
//! This is the demo-specific glue that turns on the EXISTING Phase 5
//! (ADR-MCPS-013) authorization layer for the demo proxy. It reinvents nothing:
//! the [`AuthorizationProfile`](mcps_policy::AuthorizationProfile) abstraction,
//! the Reference Signed Authorization Profile, the
//! [`PolicyEvaluator`](mcps_policy::PolicyEvaluator) (hash-binding check +
//! profile dispatch over a `VerifiedRequest`), and the proxy's opt-in
//! deny-before-dispatch enforcement path all live in `mcps-policy` /
//! `mcps-proxy`. This module only assembles them for the demo:
//!
//! * it MINTS a single reference grant that ALLOWS `list_files` on ONE specific
//!   allowed path inside the demo root (the issuer signs it);
//! * it exposes the canonical artifact bytes so the caller can both attach the
//!   `.authorization` block to a request AND bind it to the request's
//!   `authorization_hash` (= `sha256(canonical artifact bytes)`);
//! * it builds a [`PolicyEvaluator`](mcps_policy::PolicyEvaluator) with the
//!   reference profile registered and hands it to the EXISTING
//!   [`build_demo_proxy`](crate::build_demo_proxy) wiring via
//!   [`Proxy::with_policy_enforcement`](mcps_proxy::Proxy::with_policy_enforcement).
//!
//! The grant binds, through the reference profile, every Phase 5 dimension:
//! `signer` (grantee == verified signer), `on_behalf_of` (subject == verified
//! `on_behalf_of`), `audience`, the method (`tools/call`) + tool name
//! (`list_files`), the `path` argument (argument-equality constraint), and the
//! `[not_before, expires_at]` validity window (expiry). The hash binding
//! (`authorization_hash`) is checked by the evaluator BEFORE the artifact's
//! claims are trusted.

use std::sync::Arc;

use mcps_core::b64url_encode;
use mcps_core::SigningKey;
use mcps_core::TrustResolver;
use mcps_policy::mint_reference_grant;
use mcps_policy::AuthorizationProfile;
use mcps_policy::GrantedOperation;
use mcps_policy::InMemoryRevocationSource;
use mcps_policy::PolicyError;
use mcps_policy::PolicyEvaluator;
use mcps_policy::ReferenceGrantSpec;
use mcps_policy::ReferenceProfile;
use mcps_policy::RevocationSource;
use mcps_policy::AUTHORIZATION_META_KEY;
use mcps_policy::REFERENCE_PROFILE_ID;
use mcps_proxy::InnerLogSink;
use mcps_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

use crate::demo_proxy::build_demo_proxy;
use crate::demo_proxy::DemoProxyConfig;

/// The single tool the demo grant authorizes.
pub const DEMO_TOOL_NAME: &str = "list_files";
/// The JSON-RPC method the demo grant authorizes.
pub const DEMO_METHOD: &str = "tools/call";

/// The inputs that pin a demo authorization grant to a concrete request shape.
///
/// Every field is a binding the reference profile checks against the
/// Core-verified request: a grant minted from this spec is allowed ONLY for a
/// `list_files` call by `grantee`, on behalf of `subject`, targeting `audience`,
/// with the `path` argument exactly equal to `allowed_path`, inside the
/// `[not_before, expires_at]` window.
pub struct DemoGrantSpec {
    /// The granting authority identity (the grant issuer).
    pub issuer: String,
    /// The agent identity allowed to wield the grant (must equal the verified
    /// request signer).
    pub grantee: String,
    /// The party acted for (must equal the verified `on_behalf_of`).
    pub subject: String,
    /// The intended server (must equal the verified `audience`).
    pub audience: String,
    /// The ONE `list_files` path the grant authorizes (e.g. `"reports"`). The
    /// grant constrains the `path` argument to exactly this value; any other
    /// path — including one escaping the demo root — falls outside the grant.
    pub allowed_path: String,
    /// Validity-window start (RFC 3339 UTC).
    pub not_before: String,
    /// Validity-window end (RFC 3339 UTC).
    pub expires_at: String,
    /// Opaque revocation identifier.
    pub revocation_id: String,
}

impl DemoGrantSpec {
    /// The `ReferenceGrantSpec` minted from this demo spec: a single
    /// `tools/call`/`list_files` operation whose `path` argument is constrained
    /// to [`Self::allowed_path`].
    fn reference_spec(&self) -> ReferenceGrantSpec {
        ReferenceGrantSpec {
            issuer: self.issuer.clone(),
            grantee: self.grantee.clone(),
            subject: self.subject.clone(),
            audience: self.audience.clone(),
            operations: vec![GrantedOperation {
                method: DEMO_METHOD.to_string(),
                tool: DEMO_TOOL_NAME.to_string(),
                arguments: Some(json!({ "path": self.allowed_path })),
            }],
            not_before: self.not_before.clone(),
            expires_at: self.expires_at.clone(),
            revocation_id: self.revocation_id.clone(),
        }
    }
}

/// A minted demo grant: the canonical signed artifact bytes plus the derived
/// pieces the caller needs to attach and bind it.
pub struct DemoGrant {
    /// The canonical bytes of the complete signed reference artifact. The
    /// request's `authorization_hash` must equal `sha256(these bytes)`; obtain it
    /// via [`DemoGrant::authorization_hash`].
    pub artifact: Vec<u8>,
}

impl DemoGrant {
    /// The `authorization_hash` that binds a request to this grant
    /// (`sha256(canonical artifact bytes)`, rendered as the Core hash id). The
    /// host signs this value into the request envelope; the evaluator checks it
    /// before trusting the artifact.
    pub fn authorization_hash(&self) -> Result<String, PolicyError> {
        ReferenceProfile::new().expected_authorization_hash(&self.artifact)
    }

    /// The `.authorization` sibling `_meta` block value carrying this grant:
    /// `{ "profile": <reference profile id>, "artifact": <base64url bytes> }`.
    /// Insert it under `params._meta[AUTHORIZATION_META_KEY]` of a request.
    pub fn authorization_block(&self) -> Value {
        json!({
            "profile": REFERENCE_PROFILE_ID,
            "artifact": b64url_encode(&self.artifact),
        })
    }

    /// The `_meta` key under which [`DemoGrant::authorization_block`] is carried.
    pub fn meta_key() -> &'static str {
        AUTHORIZATION_META_KEY
    }
}

/// Mint the demo authorization grant from `spec`, signed by `issuer_key` /
/// `issuer_key_id`. Pure — signing has no side effects.
///
/// Fails closed (`Err`) only if the artifact cannot be canonicalized (it always
/// can for a well-formed spec); the demo spec is well-formed by construction.
pub fn mint_demo_grant(
    spec: &DemoGrantSpec,
    issuer_key: &SigningKey,
    issuer_key_id: &str,
) -> Result<DemoGrant, PolicyError> {
    let artifact = mint_reference_grant(&spec.reference_spec(), issuer_key, issuer_key_id)?;
    Ok(DemoGrant { artifact })
}

// --- Scoped role grants (Tier T2: reader vs admin) --------------------------
//
// The fileserver tool names the role grants enumerate, kept as local string
// literals like [`DEMO_TOOL_NAME`] so this crate stays self-contained (it never
// depends on `mcps-demo-fileserver`; it launches its binary as a subprocess).
const TOOL_READ_FILE: &str = "read_file";
const TOOL_STAT: &str = "stat";
const TOOL_WRITE_FILE: &str = "write_file";

/// A demo authorization role: the set of fileserver tools an identity may call.
///
/// This mirrors the fileserver's INERT `net.mcps.intendedScope` tags. `Reader`
/// covers the read-only `protected` tools (`list_files`, `read_file`, `stat`);
/// `Admin` additionally covers the `admin`-tagged `write_file`. The reference
/// profile knows nothing about the scope-tag strings — a role is realized, per
/// its "enumerate the allowed operations" convention, as the SET of `tools/call`
/// operations the grant lists. The role demo deliberately puts NO argument
/// (path) constraint on the operations: the demonstration is about ROLE, not
/// path — the fileserver still physically confines every call to the demo root.
pub enum DemoRole {
    /// Read-only: `list_files`, `read_file`, `stat`.
    Reader,
    /// Read-write: the reader tools plus `write_file`.
    Admin,
}

impl DemoRole {
    /// The tool names this role authorizes, in advertised order.
    pub fn tools(&self) -> &'static [&'static str] {
        match self {
            DemoRole::Reader => &[DEMO_TOOL_NAME, TOOL_READ_FILE, TOOL_STAT],
            DemoRole::Admin => &[DEMO_TOOL_NAME, TOOL_READ_FILE, TOOL_STAT, TOOL_WRITE_FILE],
        }
    }
}

/// The identity + window inputs that pin a demo ROLE grant.
///
/// The bindings are exactly those of [`DemoGrantSpec`] (grantee == verified
/// signer, subject == verified `on_behalf_of`, audience, `[not_before,
/// expires_at]` window), but the authorized operations come from [`DemoRole`]
/// instead of a single `list_files` path — so one grant can cover a whole role's
/// toolset.
pub struct DemoRoleGrantSpec {
    /// The granting authority identity (the grant issuer).
    pub issuer: String,
    /// The agent identity allowed to wield the grant (must equal the verified
    /// request signer).
    pub grantee: String,
    /// The party acted for (must equal the verified `on_behalf_of`).
    pub subject: String,
    /// The intended server (must equal the verified `audience`).
    pub audience: String,
    /// The role whose toolset this grant authorizes.
    pub role: DemoRole,
    /// Validity-window start (RFC 3339 UTC).
    pub not_before: String,
    /// Validity-window end (RFC 3339 UTC).
    pub expires_at: String,
    /// Opaque revocation identifier.
    pub revocation_id: String,
}

impl DemoRoleGrantSpec {
    /// The `ReferenceGrantSpec` minted from this role spec: one unconstrained
    /// `tools/call` operation per tool the role covers ([`DemoRole::tools`]).
    fn reference_spec(&self) -> ReferenceGrantSpec {
        ReferenceGrantSpec {
            issuer: self.issuer.clone(),
            grantee: self.grantee.clone(),
            subject: self.subject.clone(),
            audience: self.audience.clone(),
            operations: self
                .role
                .tools()
                .iter()
                .map(|tool| GrantedOperation {
                    method: DEMO_METHOD.to_string(),
                    tool: (*tool).to_string(),
                    // No argument constraint: any path inside the demo root.
                    arguments: None,
                })
                .collect(),
            not_before: self.not_before.clone(),
            expires_at: self.expires_at.clone(),
            revocation_id: self.revocation_id.clone(),
        }
    }
}

/// Mint a demo ROLE grant from `spec`, signed by `issuer_key` / `issuer_key_id`.
/// Pure — signing has no side effects. Reuses [`DemoGrant`], so the minted grant
/// attaches and binds exactly like a single-operation [`mint_demo_grant`] grant.
pub fn mint_demo_role_grant(
    spec: &DemoRoleGrantSpec,
    issuer_key: &SigningKey,
    issuer_key_id: &str,
) -> Result<DemoGrant, PolicyError> {
    let artifact = mint_reference_grant(&spec.reference_spec(), issuer_key, issuer_key_id)?;
    Ok(DemoGrant { artifact })
}

/// Build a [`PolicyEvaluator`](mcps_policy::PolicyEvaluator) with the Reference
/// Signed Authorization Profile registered — the evaluator the demo proxy uses
/// to render allow/deny over the demo grant. Issuer keys are resolved through the
/// proxy's existing `TrustResolver`, so the caller must register the issuer key
/// in that resolver.
pub fn demo_policy_evaluator() -> PolicyEvaluator {
    let mut evaluator = PolicyEvaluator::new();
    evaluator.register(Box::new(ReferenceProfile::new()));
    evaluator
}

/// The default (empty) revocation source the demo enforcement uses: nothing is
/// revoked, so the demo's allow/deny outcomes turn purely on signer / subject /
/// audience / scope / expiry. A caller wanting to demonstrate revocation can
/// supply its own [`InMemoryRevocationSource`](mcps_policy::InMemoryRevocationSource).
pub fn demo_revocation_source() -> InMemoryRevocationSource {
    InMemoryRevocationSource::new()
}

/// Assemble a demo [`Proxy`](mcps_proxy::Proxy) that launches the real
/// `mcps-demo-fileserver` AND enforces Phase 5 authorization before dispatch.
///
/// This is exactly [`build_demo_proxy`](crate::build_demo_proxy) with the
/// EXISTING [`Proxy::with_policy_enforcement`](mcps_proxy::Proxy::with_policy_enforcement)
/// builder applied: the supplied `evaluator` (build via
/// [`demo_policy_evaluator`]) and `revocation` source are wired so that, after a
/// request verifies at the Core layer and BEFORE the inner subprocess is
/// launched/written to, the authorization artifact is evaluated; a denial fails
/// closed with the matching `mcps.authorization_*` error and the inner fileserver
/// is never reached.
///
/// The proxy's `resolver` must hold BOTH the inbound request-signer key (Core
/// verification) AND the grant-issuer key (policy signature check) — the proxy
/// reuses one resolver for both.
///
/// Fails closed (`Err`) if the launch policy cannot be honored against the real
/// process environment / filesystem (surfaced at construction).
pub fn build_demo_proxy_with_policy(
    config: DemoProxyConfig,
    resolver: Box<dyn TrustResolver>,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    evaluator: PolicyEvaluator,
    revocation: Box<dyn RevocationSource>,
) -> Result<Proxy, String> {
    let proxy = build_demo_proxy(config, resolver, log_sink)?;
    Ok(proxy.with_policy_enforcement(evaluator, revocation))
}
