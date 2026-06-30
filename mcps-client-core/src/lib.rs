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
//! # Slice status (MCPS-40, #187)
//! Landed: signed draft-02 request construction + `request_hash`
//! ([`build_signed_request`] / [`build_signed_tool_call`]) with fail-closed
//! rejection of an unsupported `canonicalization_id`. The response verifier,
//! enforcement engine, authz-binding hook, signer custody, correlation store,
//! discovery, and audit/error mapping land in the following sprint slices
//! (#188–#200) on top of this seam.

pub mod request;

pub use request::build_signed_request;
pub use request::build_signed_tool_call;
pub use request::RequestSigningInputs;
pub use request::SignedRequest;
