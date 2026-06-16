//! MCP-S server-side sidecar (MCPS-015 + MCPS-016).
//!
//! [`Proxy`] wraps an unmodified inner MCP server ([`InnerServer`]): it verifies
//! every inbound MCP-S request before dispatch, fails closed on any verification
//! failure (the inner server is never reached), strips the external transport
//! envelope, injects a fresh verified-context block as the sole writer, forwards
//! only verified requests, and signs the inner server's result on the way back.
//!
//! MCPS-023 adds opt-in Phase 5 policy enforcement; MCPS-024 (ADR-MCPS-014) adds
//! the Phase 6 transport-binding abstraction (`transport`): identity types, the
//! provider seam, and the binding policy that ties the verified `signer` to the
//! mTLS channel identity.
//!
//! # Security posture (v1, Phase 6.1)
//!
//! What this supports: **single-node production hardening** with Rust-native
//! mTLS, file-backed *single-node* durable replay protection, an explicit
//! client-cert identity policy (no implicit fallback), and a **short-lived
//! client-certificate revocation posture** — there is NO online CRL/OCSP, so the
//! proxy ENFORCES a maximum client-cert lifetime (CLI default 1h) and a
//! compromised credential is bounded by that lifetime.
//!
//! What v1 does NOT support (and must not be claimed) until the corresponding
//! work lands: **horizontally-scaled production** replay protection, **enterprise
//! key custody** (needs an HSM/KMS `KeySource`), and **full revocation** (needs
//! CRL/OCSP or equivalent). Issue #3837 adds the SHARED-cache machinery for
//! horizontal scale — [`SharedReplayCache`] over an [`AtomicReplayStore`], with an
//! in-memory reference store proving cross-node rejection — but the only in-tree
//! [`AtomicReplayStore`] today is that in-memory reference store; no production
//! shared backend ships in this build. A real shared backend (the Redis adapter
//! plus the `crates_mcps` repin and a live-backend black-box test) is tracked as a
//! separate follow-up. Until it lands, the file cache remains single-node only and
//! multi-node replay safety MUST NOT be claimed in a real deployment.

// ADR-MCPS-022: explicit authorized server key set + per-audience response-signing
// identity mode (per_node_keyset default | shared_remote_signer). The verifier-side
// admission anchor; composes with `trust_cache::BoundedTrustCache` (ADR-MCPS-021).
pub mod authorized_keyset;
// ADR-MCPS-028 §B: native AWS KMS Ed25519 response signer over blocking HTTPS
// (ureq) + a minimal audited SigV4 signer — NO async `aws-sdk-kms`/tokio/Smithy
// (ADR-MCPS-018 lean-sync firewall). Compiled ONLY under the non-default
// `aws_kms_keysource` feature so the default build links no HTTPS/SigV4 code.
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_kms_keysource;
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_sigv4;
pub mod cli;
// Issue #3838 (ADR-MCPS-014): a non-exporting reference `ResponseSigner` proving the
// response-signing delegation seam — a backend whose key never leaves it can drive
// the proxy's full signing path.
pub mod delegated_response_signer;
// ADR-MCPS-028 §G: delegated TLS handshake signing — a rustls SigningKey that
// forwards the handshake transcript to a non-exporting device/KMS so the TLS
// server key never leaves it. Generic mechanism (always compiled); the per-backend
// raw signers are wired under their own feature gates.
pub mod delegated_tls;
pub mod durable_replay;
// ADR-MCPS-028 §C: native GCP Cloud KMS Ed25519 response signer over blocking HTTPS
// (ureq) + OAuth2 bearer — NO async google-cloud SDK. Compiled ONLY under the
// non-default `gcp_kms_keysource` feature.
#[cfg(feature = "gcp_kms_keysource")]
pub mod gcp_kms_keysource;
pub mod inner_launch;
pub mod key_source;
// ADR-MCPS-028: provider-agnostic cloud-KMS response signer (the shared protocol
// mapping behind the #3838 delegation seam). Dependency-free — the per-provider
// network backends (AWS KMS / GCP Cloud KMS) are the feature-gated follow-ups.
pub mod kms_keysource;
// Issue #4030: ONLINE client-cert revocation via OCSP (RFC 6960) checked at
// connection time, the online sibling of #3839's offline CRL revocation.
// Compiled ONLY under the non-default `online_ocsp` feature so the default build
// links no HTTP client and stays byte-for-byte unchanged.
#[cfg(feature = "online_ocsp")]
pub mod ocsp;
pub mod persistent_inner;
// Issue #4034: the PKCS#11-backed response-signing key source (the real,
// non-exporting backend behind the #3838 delegation seam — the response-signing
// key never leaves the token). Compiled ONLY under the non-default
// `pkcs11_keysource` feature so the default build is unchanged.
#[cfg(feature = "pkcs11_keysource")]
pub mod pkcs11_keysource;
// Issue #4034 supply-chain follow-up: a small, OWNED safe wrapper over the raw
// `cryptoki-sys` FFI bindings, replacing the high-level `cryptoki` crate (which
// transitively pulled the unmaintained `paste`, RUSTSEC-2024-0436). Compiled ONLY
// under the same non-default `pkcs11_keysource` feature.
#[cfg(feature = "pkcs11_keysource")]
pub mod pkcs11_native;
pub mod proxy;
// Issue #4028: the Redis-backed shared replay backend that makes
// `--replay-cache shared` give real horizontally-scaled replay safety. Compiled
// ONLY under the non-default `redis_replay` feature so the default build is
// unchanged.
#[cfg(feature = "redis_replay")]
pub mod redis_store;
// ADR-MCPS-020: the declared replay-store durability tier (deployment assertion,
// semantic names, honest per-tier guarantee, tier-claim ceiling). Pure type — in
// the default build.
pub mod replay_tier;
pub mod rlimits;
// Issue #3865: OS sandbox PROFILE + fail-closed platform gate for inner-server
// fs/network containment (the config, CLI, seam, and fail-closed gate).
pub mod sandbox;
// Issue #4039: the LINUX kernel-enforcement backend behind the #3865 seam —
// Landlock fs ruleset + seccomp-bpf egress filter installed on the inner-server
// child before exec. Linux-only: a non-Linux build excludes this module entirely
// and never links landlock/seccompiler.
#[cfg(target_os = "linux")]
pub mod sandbox_linux;
// Issue #3837: shared, server-side-atomic replay cache for horizontally-scaled
// replay safety (the backend-agnostic core + the in-memory reference store).
pub mod shared_replay;
pub mod tls;
pub mod transport;
// ADR-MCPS-021: bounded trust-propagation cache (Tier 1). Caching is a caller
// concern (mcps-core does not cache); this wraps the injected TrustResolver with
// the bounded-`T` window + negative-cache classification + fail-closed rules.
pub mod trust_cache;

pub use authorized_keyset::AuthorizedKeyEntry;
pub use authorized_keyset::AuthorizedKeySet;
pub use authorized_keyset::KeySetError;
pub use authorized_keyset::KeySetTrustResolver;
pub use authorized_keyset::KeyStatus;
pub use authorized_keyset::ResponseSigningIdentityMode;
// ADR-MCPS-028 §B: the AWS KMS Ed25519 backend (feature-gated). Drives the
// `KmsResponseSigner` core via the `KmsEd25519Backend` seam.
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsConfig;
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsEd25519Backend;
pub use delegated_response_signer::DelegatedResponseSigner;
// ADR-MCPS-028 §G: delegated TLS signing (generic mechanism).
pub use delegated_tls::DelegatedCertResolver;
pub use delegated_tls::DelegatedEd25519SigningKey;
pub use delegated_tls::RawEd25519TlsSigner;
// ADR-MCPS-028 §C: the GCP Cloud KMS Ed25519 backend (feature-gated).
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsConfig;
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsEd25519Backend;
pub use durable_replay::DurableReplayCache;
pub use inner_launch::BoundedStderr;
pub use inner_launch::InnerLaunchConfig;
pub use inner_launch::InnerLogEvent;
pub use inner_launch::InnerLogSink;
pub use inner_launch::StderrLogSink;
// MCPS-076 (audit gap G-3): EnvKeySource is dev/CI-only and exists only when the
// non-default `dev_env_key_source` feature is enabled.
#[cfg(feature = "dev_env_key_source")]
pub use key_source::EnvKeySource;
pub use key_source::FileKeySource;
pub use key_source::KeyError;
pub use key_source::KeySource;
// Issue #3838: the response-signing delegation seam (a non-exporting HSM/KMS can
// implement this without surrendering its private key).
pub use key_source::ResponseSigner;
pub use kms_keysource::KmsEd25519Backend;
pub use kms_keysource::KmsKeySource;
pub use kms_keysource::KmsResponseSigner;
// Issue #4030: the online OCSP revocation checker (feature-gated).
#[cfg(feature = "online_ocsp")]
pub use ocsp::CertRevocationStatus;
#[cfg(feature = "online_ocsp")]
pub use ocsp::OcspChecker;
#[cfg(feature = "online_ocsp")]
pub use ocsp::OcspError;
pub use persistent_inner::PersistentSubprocessInner;
// Issue #4034: the PKCS#11 key source (feature-gated).
#[cfg(feature = "pkcs11_keysource")]
pub use pkcs11_keysource::Pkcs11KeySource;
pub use proxy::InnerServer;
pub use proxy::Proxy;
// Issue #4028: the Redis shared replay backend (feature-gated).
#[cfg(feature = "redis_replay")]
pub use redis_store::RedisAtomicReplayStore;
pub use replay_tier::ReplayDurabilityTier;
pub use rlimits::RLimits;
pub use sandbox::NetworkPolicy;
pub use sandbox::SandboxMode;
pub use sandbox::SandboxProfile;
pub use shared_replay::AtomicReplayStore;
pub use shared_replay::InMemoryAtomicReplayStore;
pub use shared_replay::ReplayStoreError;
pub use shared_replay::SharedReplayCache;
pub use tls::build_server_config_delegated_with_crls;
pub use tls::extract_identity;
pub use tls::IdentityStrategy;
pub use tls::serve;
pub use tls::serve_once;
pub use tls::RustlsDirectProvider;
pub use tls::ServerLimits;
pub use tls::ServerOptions;
pub use tls::TlsError;
pub use transport::validate_asserted_identity_value;
pub use transport::validate_routing_headers;
pub use transport::AssertedIdentityRejection;
pub use transport::RoutingHeaderRejection;
pub use transport::MCP_METHOD_HEADER;
pub use transport::MCP_NAME_HEADER;
pub use transport::ExactMatchBinding;
pub use transport::IdentityPolicy;
pub use transport::IdentitySource;
pub use transport::MappedBinding;
pub use transport::RequestHeaders;
pub use transport::ReverseProxyHeaderFormat;
pub use transport::ReverseProxyMtlsProvider;
pub use trust_cache::BoundedTrustCache;
pub use transport::StaticIdentityProvider;
pub use transport::TransportBindingPolicy;
pub use transport::TransportBindingProvider;
pub use transport::TransportIdentity;
