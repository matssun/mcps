//! MCP-S client-side core — the shared seam consumed by BOTH the local client
//! proxy and the SDK (ADR-MCPS-044 §`mcps-client-core`).
//!
//! This crate is the client-side mirror of `mcps-core`'s server-side verifier.
//! It owns the version-neutral, mode-neutral evidence work: constructing a signed
//! draft-02 request, computing the `request_hash`, and (in later slices)
//! verifying the bound signed response, evaluating enforcement mode, the
//! authorization-binding hook, key-custody signer abstraction, in-flight
//! correlation, discovery, and the error→`wire_code()` mapping.
//!
//! # Why a separate crate (NOT in `mcps-core`)
//! `mcps-core` is the pure-crypto, method-transparent verification layer; pushing
//! client construction/policy into it would break that boundary (ADR-MCPS-044,
//! CONTEXT.md §`mcps-client-core`). Equally, the MODE-specific layers — the local
//! listener, config/lifecycle, language bindings, key providers, and transports —
//! stay OUT of this crate: they live in the proxy/SDK above this seam. This crate
//! therefore depends only on `mcps-core` (pure primitives) and `serde_json`; it
//! pulls in NO networking/async/fs crate.
//!
//! # Slice status
//! Landed:
//! - MCPS-40 (#187): signed draft-02 request construction + `request_hash`
//!   ([`build_signed_request`] / [`build_signed_tool_call`]) with fail-closed
//!   rejection of an unsupported `canonicalization_id`.
//! - MCPS-41 (#188): signed-response verification + request binding
//!   ([`verify_signed_response`] / [`ResponseExpectation`]) — server_signer via
//!   the injected `TrustResolver`, `request_hash`/`canonicalization_id` binding,
//!   unsigned + unexpected-signer fail-closed.
//!
//! - MCPS-42 (#189): the enforcement-mode engine ([`decide`] /
//!   [`EnforcementMode`] / [`classify_response_result`]) — the two normative modes
//!   plus the bright-line fallback taxonomy (absence may fall back only under
//!   `allow_legacy_explicit` + an allowlisted route; bad/downgrade-shaped evidence
//!   always fails closed).
//!
//! - MCPS-45 (#192): the [`AuthorizationBindingProvider`] hook +
//!   [`resolve_authorization_binding`] — opaque-bytes / authz-system-reference base
//!   forms, route type-policy enforcement, structured-hashing rejected in base
//!   (bind-not-interpret; the binding is placed in the signed preimage).
//!
//! - MCPS-46 (#193): the [`ClientSigner`] custody abstraction + [`SignerPolicy`]
//!   gate ([`authorize_signer`] / [`build_signed_request_with_signer`]) —
//!   mechanism-neutral signing, signer identified in evidence, dev-file keys
//!   rejected under production `require_mcps`, rotation/revocation by config,
//!   hardware/KMS-only as an opt-in hardening profile.
//!
//! - MCPS-47 (#194): the in-flight [`CorrelationStore`] — per-outstanding-request
//!   [`PendingRequest`] state, cleanup-on-completion + expiry sweep, late-response
//!   fail-closed ([`CorrelationError::Uncorrelatable`]), nonce-reuse prevention.
//!
//! - MCPS-43 (#190): the signer→audience binding ([`AudienceTuple`] /
//!   [`resolve_signer_audience`] / [`SignerAudiencePolicy`]) — the expected
//!   `(server_signer, audience)` resolved from local policy + verified transport
//!   pre-discovery; mandatory tenant/route discriminators; discovery can never
//!   choose/widen/rewrite the audience.
//!
//! - MCPS-48 (#195): the client error→`wire_code()` mapping + audit events
//!   ([`ClientAuditEvent`] / [`audit_for_decision`] /
//!   [`correlation::CorrelationError::to_mcps_error`]) — no parallel wire taxonomy;
//!   audit events distinguish verified vs legacy-explicit paths.
//!
//! Stateless-primary discovery lands in the following sprint slice on top of this
//! seam.

pub mod audience;
pub mod audit;
pub mod authz;
pub mod correlation;
pub mod enforcement;
pub mod request;
pub mod response;
pub mod signer;

pub use audience::enforce_request_audience;
pub use audience::resolve_signer_audience;
pub use audience::AudienceTuple;
pub use audience::SignerAudienceBinding;
pub use audience::SignerAudiencePolicy;
pub use audience::TransportIdentity;
pub use audit::audit_for_decision;
pub use audit::ClientAuditEvent;
pub use audit::ClientOutcome;
pub use audit::ClientPath;
pub use authz::binding_tag;
pub use authz::resolve_authorization_binding;
pub use authz::AuthorizationBindingPolicy;
pub use authz::AuthorizationBindingProvider;
pub use authz::AuthorizationReferenceResolver;
pub use authz::AuthzReference;
pub use authz::AuthzSystemReferenceProvider;
pub use authz::BindingRequestContext;
pub use authz::BindingTypeTag;
pub use authz::OpaqueBytesProvider;
pub use authz::StructuredObjectHashingProvider;
pub use correlation::CorrelationError;
pub use correlation::CorrelationStore;
pub use correlation::PendingRequest;
pub use enforcement::classify_response_result;
pub use enforcement::decide;
pub use enforcement::AbsenceReason;
pub use enforcement::EnforcementDecision;
pub use enforcement::EnforcementMode;
pub use enforcement::EvidenceOutcome;
pub use request::build_signed_request;
pub use request::build_signed_tool_call;
pub use request::RequestSigningInputs;
pub use request::SignedRequest;
pub use response::verify_signed_response;
pub use response::ResponseExpectation;
pub use signer::authorize_signer;
pub use signer::build_signed_request_with_signer;
pub use signer::ClientSigner;
pub use signer::CustodyClass;
pub use signer::DevFileSigner;
pub use signer::Environment;
pub use signer::SignerPolicy;
pub use signer::SoftwareSigner;
