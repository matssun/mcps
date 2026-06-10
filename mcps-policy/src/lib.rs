//! MCP-S delegated authorization (Phase 5 — ADR-MCPS-013).
//!
//! Core (`mcps-core`) proves a request is authentic, fresh, non-replayed, and
//! audience-correct, and carries an OPAQUE `authorization_hash`. This crate
//! interprets the authorization artifact behind that hash and renders an
//! allow/deny decision, WITHOUT reopening the frozen Core vocabulary or extending
//! the Core error taxonomy.
//!
//! The artifact travels in a sibling `_meta` block,
//! `se.syncom/mcps.authorization = { profile, artifact }`, bound to
//! the request because `authorization_hash == sha256(decoded artifact bytes)`.
//!
//! MCPS-019 lands the abstraction: the [`AuthorizationProfile`] trait, the
//! [`AuthorizationDecision`] / [`PolicyError`] types, the authorization-block
//! types, and the injected [`RevocationSource`]. The Reference Signed
//! Authorization Profile (MCPS-020) and the policy evaluator (MCPS-021) build on
//! it; Biscuit / UCAN / OAuth-bound are later pluggable profiles.
//!
//! Firewall (ADR-MCPS-011/012): this crate depends only on `mcps-core` plus
//! `serde`/`serde_json`. No networking, async runtime, or filesystem access.

pub mod block;
pub mod decision;
pub mod error;
pub mod evaluator;
pub mod manifest;
pub mod manifest_error;
pub mod manifest_pin;
pub mod manifest_verifier;
pub mod profile;
pub mod reference;
pub mod revocation;
pub mod wire;

pub use block::extract_authorization_block;
pub use block::AuthorizationBlock;
pub use block::AUTHORIZATION_META_KEY;
pub use decision::AuthorizationDecision;
pub use error::PolicyError;
pub use error::PolicyResult;
pub use evaluator::PolicyEvaluator;
pub use manifest::compute_schema_hash;
pub use manifest::manifest_signing_preimage;
pub use manifest::mint_signed_manifest;
pub use manifest::ManifestSignature;
pub use manifest::ManifestSpec;
pub use manifest::ToolEntry;
pub use manifest::ToolManifest;
pub use manifest::ToolSpec;
pub use manifest_error::ManifestError;
pub use manifest_error::ManifestResult;
pub use manifest_pin::InMemoryManifestPinStore;
pub use manifest_pin::ManifestPinStore;
pub use manifest_verifier::ManifestVerifier;
pub use manifest_verifier::VerifiedTool;
pub use profile::AuthorizationProfile;
pub use reference::mint_reference_grant;
pub use reference::GrantedOperation;
pub use reference::ReferenceGrantSpec;
pub use reference::ReferenceProfile;
pub use reference::REFERENCE_PROFILE_ID;
pub use revocation::InMemoryRevocationSource;
pub use revocation::RevocationSource;
pub use revocation::RevocationStatus;
pub use revocation::RevocationUnavailable;
pub use wire::json_rpc_authorization_error;
