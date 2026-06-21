//! The runnable mTLS client orchestration (MCPS-054, Phase 6.6, epic #3948).
//!
//! [`MtlsClientRunner`] is the host/LLM-caller side of the multi-process demo. It
//! is a thin ORCHESTRATOR that stitches together two crates and re-implements
//! NOTHING they already own:
//!
//! - signing, nonce, freshness, and request/response correlation stay in
//!   `mcps-host`'s [`HostSession`](mcps_host::HostSession) (which builds on
//!   `mcps-core`). The runner drives the session; it never touches the bare
//!   signer, computes a hash by hand, or supplies a caller-chosen expected hash;
//! - the mTLS connection, server-certificate + server-identity verification,
//!   client-certificate presentation, and HTTP wire framing stay in
//!   `mcps-transport`'s [`MtlsClient`](mcps_transport::MtlsClient). The runner
//!   never opens a socket or speaks `rustls` directly.
//!
//! The flow per call is: the session SIGNS the request (storing its
//! `request_hash` by JSON-RPC id) → the transport PRESENTS the client cert,
//! VERIFIES the server cert against the configured server CA, and round-trips the
//! signed bytes over mTLS → the session VERIFIES the signed response against the
//! STORED hash. The runner exposes the signer identity but NO private-key
//! accessor (the language model never holds keys, ADR-MCPS-003).
//!
//! The full multi-process wiring against `mcps_proxy_cli` is #3943; this module
//! is validated in-process against the real `mcps_proxy::serve_once` server, so
//! the client path is proven end to end without prematurely doing #3943's job.

use std::net::SocketAddr;

use mcps_core::McpsError;
use mcps_core::TrustResolver;
use mcps_host::Clock;
use mcps_host::HostSession;
use mcps_host::HostSigner;
use mcps_host::NonceSource;
use mcps_transport::MtlsClient;
use mcps_transport::TransportError;
use serde_json::Value;

/// An error orchestrating one signed mTLS round trip. Each variant names the
/// boundary that failed so the runnable bin can surface it loudly but correctly
/// (no panics on bad input).
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// Signing the request via the [`HostSession`] failed (e.g. a duplicate
    /// in-flight id, [`McpsError::ReplayDetected`]).
    #[error("signing failed: {0:?}")]
    Sign(McpsError),
    /// The transport (mTLS handshake, server-auth rejection, or IO) failed — the
    /// signed body may never have reached the wire (see [`TransportError`]).
    #[error("transport failed: {0}")]
    Transport(#[from] TransportError),
    /// The proxy returned a JSON-RPC error response (carried verbatim).
    #[error("proxy returned an error response: {0}")]
    ProxyError(String),
    /// The response bytes were not parseable JSON.
    #[error("response is not valid JSON: {0}")]
    BadResponse(String),
    /// The session refused to bind the response to the stored request hash (e.g.
    /// [`McpsError::ResponseHashMismatch`], [`McpsError::ResponseSigInvalid`], or
    /// [`McpsError::MissingEnvelope`] for an unknown id).
    #[error("response verification failed: {0:?}")]
    Verify(McpsError),
    /// Internal invariant: no stored request hash after a successful sign.
    #[error("no stored request hash after signing")]
    NoStoredHash,
}

/// The outcome of one verified round trip — the data the runnable bin prints as
/// its structured result line. It carries identities and the correlated hash, not
/// secrets.
#[derive(Debug, Clone)]
pub struct RoundTripOutcome {
    /// The request signer identity (the LLM caller).
    pub signer: String,
    /// The audience the request was signed for (the target server).
    pub audience: String,
    /// The Core-computed request hash the session stored at sign time and bound
    /// the response against.
    pub request_hash: String,
    /// The tool invoked (`tools/call` name).
    pub tool: String,
    /// The path argument passed to the tool.
    pub path: String,
    /// The server signer identity that signed the verified response.
    pub server_signer: String,
}

/// Orchestrates ONE signed-request → mTLS POST → verified-response round trip
/// over an injected [`HostSession`] (signing) and [`MtlsClient`] (transport).
///
/// Generic over the session's injected [`Clock`] and [`NonceSource`] so a test
/// can drive it deterministically (fixed clock + seeded RNG) exactly as the rest
/// of the demo does.
pub struct MtlsClientRunner<C, N> {
    session: HostSession<C, N>,
    client: MtlsClient,
}

impl<C: Clock, N: NonceSource> MtlsClientRunner<C, N> {
    /// Build a runner from an already-constructed [`HostSession`] (the bin builds
    /// it from the signing-seed flag) and an already-built verifying
    /// [`MtlsClient`] (the bin builds it from the client cert/key + server-CA +
    /// expected-server-name flags). Keeping construction in the bin means the
    /// runner re-implements neither signing setup nor TLS setup.
    pub fn new(signer: HostSigner, clock: C, nonce_source: N, client: MtlsClient) -> Self {
        MtlsClientRunner {
            session: HostSession::with_defaults(signer, clock, nonce_source),
            client,
        }
    }

    /// The signer identity (public — an identity, not a secret). There is
    /// deliberately NO accessor for the signing key.
    pub fn signer(&self) -> &str {
        self.session.signer()
    }

    /// Sign a `tools/call` for `tool`/`path` via the session, POST the signed
    /// bytes to `addr` over mTLS via the transport, and verify the signed
    /// response against the STORED request hash using `resolver` (the server's
    /// trust anchor).
    ///
    /// Returns the [`RoundTripOutcome`] on a fully verified round trip. Every
    /// failure surfaces as a [`RunnerError`] naming its boundary — the runner
    /// never panics on bad input.
    pub fn run_tool_call<R: TrustResolver>(
        &mut self,
        addr: SocketAddr,
        id: &Value,
        tool: &str,
        arguments: Value,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
        path: &str,
        resolver: &R,
    ) -> Result<RoundTripOutcome, RunnerError> {
        // 1. SIGN via the session (nonce + freshness + hash storage are its job).
        let request = self
            .session
            .sign_tool_call(id, tool, arguments, on_behalf_of, audience, authorization_hash)
            .map_err(RunnerError::Sign)?;
        let stored_hash = self
            .session
            .stored_request_hash(id)
            .ok_or(RunnerError::NoStoredHash)?
            .to_string();

        // 2. POST over mTLS via the transport (server-auth happens in the
        //    handshake; the body never reaches an unauthenticated peer).
        let response = self.client.round_trip(addr, &request)?;

        // 3. Surface a JSON-RPC error response before attempting to bind it.
        let parsed: Value = serde_json::from_slice(&response)
            .map_err(|e| RunnerError::BadResponse(e.to_string()))?;
        if let Some(error) = parsed.get("error") {
            return Err(RunnerError::ProxyError(error.to_string()));
        }

        // 4. VERIFY via the session against the STORED hash (never a caller value).
        let verified = self
            .session
            .verify_response(&response, resolver)
            .map_err(RunnerError::Verify)?;

        Ok(RoundTripOutcome {
            signer: self.session.signer().to_string(),
            audience: audience.to_string(),
            request_hash: stored_hash,
            tool: tool.to_string(),
            path: path.to_string(),
            server_signer: verified.server_signer().to_string(),
        })
    }

    /// The number of outstanding (unverified) requests — `0` after a verified
    /// round trip. Exposed for the bin's post-condition check.
    pub fn pending_count(&self) -> usize {
        self.session.pending_count()
    }
}
