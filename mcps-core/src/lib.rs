//! MCP-S Core — pure, dependency-free cryptographic verification crate for the
//! MCP-S security profile (a clean-room Zero Trust profile for MCP).
//!
//! Scope and invariants are fixed by the MCP-S ADRs:
//! - ADR-MCPS-001: clean-room; no monorepo trust concepts.
//! - ADR-MCPS-011 / ADR-MCPS-012: no networking, async runtime, or filesystem
//!   access. Callers inject `TrustResolver` and `ReplayCache` implementations.
//!
//! MCPS-003 lands the envelope data structures, the frozen string-constant
//! vocabulary (`ids`), and the frozen error taxonomy (`error`). MCPS-004 lands
//! JCS canonicalization (`canonical`). MCPS-005 lands the cryptographic
//! primitives: Base64URL encoding (`encoding`), SHA-256 hash identifiers
//! (`hash`), Ed25519 sign/verify (`crypto`), and signing-preimage / `request_hash`
//! construction (`signing`). MCPS-006/007 add trust resolution (`resolver`),
//! replay detection (`replay`), and freshness (`time`); MCPS-009 adds the
//! fail-closed message constraints (`constraints`). MCPS-008 composes them all
//! into the full verification pipeline (`pipeline`): `verify_request` and
//! `verify_response`.

pub mod audit;
pub mod canonical;
pub mod constraints;
pub mod crypto;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod ids;
pub mod mrt;
pub mod pipeline;
pub mod replay;
pub mod resolver;
pub mod signing;
pub mod time;
pub mod unwrap;
pub mod wire;

// Re-export the public surface at the crate root for ergonomic use.
pub use canonical::canonicalize;
pub use canonical::canonicalize_json_value;
pub use canonical::canonicalize_value;
pub use canonical::parse;
pub use canonical::JcsValue;
pub use constraints::extract_draft02_request_envelope;
pub use constraints::extract_draft02_response_envelope;
pub use constraints::extract_request_envelope;
pub use constraints::extract_response_envelope;
pub use constraints::reject_batch;
pub use constraints::reject_notification;
pub use constraints::KNOWN_CANONICALIZATION_SCHEMES;
pub use crypto::ensure_ed25519_alg;
pub use crypto::verify_ed25519;
pub use crypto::verify_ed25519_with;
pub use crypto::SigningKey;
pub use crypto::VerificationKey;
pub use encoding::b64url_decode;
pub use encoding::b64url_encode;
pub use envelope::AuthorizationBinding;
pub use envelope::Continuation;
pub use envelope::Draft02RequestEnvelope;
pub use envelope::Draft02ResponseEnvelope;
pub use envelope::RequestEnvelope;
pub use envelope::ResponseEnvelope;
pub use envelope::SignatureBlock;
pub use envelope::VerifiedContext;
pub use error::McpsError;
pub use error::McpsResult;
pub use hash::parse_hash_id;
pub use hash::sha256_hash_id;
pub use ids::CANONICALIZATION_ID_INT53_V1;
pub use ids::DRAFT_02_CANONICALIZATION_ALLOWLIST;
pub use ids::EXTENSION_ID;
pub use ids::REQUEST_META_KEY;
pub use ids::RESPONSE_META_KEY;
pub use ids::RESPONSE_WRAP_INNER_ERROR_KEY;
pub use ids::RESPONSE_WRAP_VALUE_KEY;
pub use ids::SIG_ALG_ED25519;
pub use ids::VERIFIED_META_KEY;
pub use ids::VERSION_DRAFT_01;
pub use ids::VERSION_DRAFT_02;
pub use mrt::build_mcp_mrt_continuation;
pub use mrt::classify_result;
pub use mrt::ResultClass;
pub use pipeline::verify_request;
pub use pipeline::verify_request_dispatch;
pub use pipeline::verify_request_draft02;
pub use pipeline::verify_response;
pub use pipeline::verify_response_draft02;
pub use pipeline::ExpectedVersionPolicy;
pub use pipeline::VerificationConfig;
pub use pipeline::VerifiedAuthorization;
pub use pipeline::VerifiedRequest;
pub use pipeline::VerifiedResponse;
pub use pipeline::VersionPolicyError;
pub use replay::InMemoryReplayCache;
pub use replay::ReplayCache;
pub use replay::ReplayCacheError;
pub use replay::ReplayDecision;
pub use replay::ReplayDurabilityClass;
pub use resolver::InMemoryTrustResolver;
pub use resolver::TrustResolver;
pub use resolver::TrustResolverError;
pub use signing::preimage_exclusion_paths;
pub use signing::request_hash;
pub use signing::request_signing_preimage;
pub use signing::response_hash;
pub use signing::response_signing_preimage;
pub use signing::signing_preimage;
pub use signing::EnvelopeLocation;
pub use time::check_freshness;
pub use time::parse_rfc3339_utc;
pub use time::unix_to_rfc3339_utc;
pub use unwrap::unwrap_verified_result;
pub use unwrap::UnwrappedResult;
pub use wire::json_rpc_error_object;
pub use wire::MCPS_JSON_RPC_ERROR_CODE;
