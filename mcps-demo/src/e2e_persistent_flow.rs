//! The multi-process mTLS flow against the LONG-LIVED `mcps-demo-server`
//! (MCPS-066, MCPS-EPIC-P6.6B).
//!
//! This is the persistent counterpart of [`crate::e2e_flow`]: where that flow
//! drives ONE authorized `list_files` against a one-shot inner fileserver, this
//! one drives **several** authorized `tools/call`s plus **one** authorization-
//! denied call over the SAME verifying mTLS client and the SAME persistent inner
//! session, across the real multi-process topology:
//!
//! ```text
//! this process: DemoHostClient (HostSession) signs + mcps-transport mTLS POST
//!    │  real mTLS socket (127.0.0.1:<ephemeral>)
//!    ▼
//! mcps_proxy_cli --inner-mode persistent  (SEPARATE OS process: mTLS terminate +
//!    │             verify, Core verify, freshness, durable replay, transport-
//!    │             binding EXACT, Phase-5 authz=reference, strip/inject, sign
//!    │             response)
//!    │  ONE persistent stdio child, spawned + initialized ONCE
//!    ▼
//! mcps_demo_server_bin  (the long-lived MCP server; echo / list_items / reset_items)
//! ```
//!
//! It reinvents NOTHING: signing, nonce, freshness, and `request_hash`
//! correlation stay in `mcps-host`'s [`HostSession`](mcps_host::HostSession)
//! (driven through [`DemoHostClient`](crate::DemoHostClient)); the mTLS
//! connection + server-cert/identity verification + client-cert presentation
//! stay in `mcps-transport`'s [`MtlsClient`](mcps_transport::MtlsClient); the
//! per-scope reference grants are minted by `mcps-policy`; response verification
//! (bind to the STORED request hash) is the session's own job.
//!
//! ## The scopes, realized as reference grants
//!   * `echo`        — **public**:    a grant covering exactly `echo`.
//!   * `list_items`  — **protected**: a grant covering exactly `list_items`.
//!   * `reset_items` — **admin**:     NO grant is minted, so the call is denied
//!                                    (`authorization_scope_denied`) before dispatch.
//!
//! Each grant is SELF-ISSUED by the request signer (issuer == grantee == the
//! fixture signer), so the single fixture `trust.json` entry already carries the
//! issuer key the proxy resolves for the policy-signature check — exactly as
//! [`crate::e2e_flow`] does.
//!
//! Boundary (LOCKED): this module holds NO transport, signing, or policy logic —
//! it stitches the proven crates together. It does not open a socket or speak
//! `rustls`/`jwt` directly; it does not compute a hash by hand.

use std::net::SocketAddr;

use mcps_core::b64url_encode;
use mcps_core::extract_response_envelope;
use mcps_core::response_signing_preimage;
use mcps_core::verify_ed25519_with;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationKey;
use mcps_host::HostSigner;
use mcps_host::SystemClock;
use mcps_host::SystemNonceSource;
use mcps_host::UnwrappedResult;
use mcps_policy::mint_reference_grant;
use mcps_policy::AuthorizationProfile;
use mcps_policy::GrantedOperation;
use mcps_policy::ReferenceGrantSpec;
use mcps_policy::ReferenceProfile;
use mcps_policy::AUTHORIZATION_META_KEY;
use mcps_policy::REFERENCE_PROFILE_ID;
use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

use crate::client::DemoHostClient;
use crate::demo_fixtures::DemoFixtures;

/// The JSON-RPC method every demo `tools/call` carries.
pub const PERSISTENT_METHOD: &str = "tools/call";
/// The public demo tool (no special scope) — echoes its `message`.
pub const TOOL_ECHO: &str = "echo";
/// The protected demo tool — lists the in-memory item set.
pub const TOOL_LIST_ITEMS: &str = "list_items";
/// The admin demo tool — restores the seed set (never granted in this flow).
pub const TOOL_RESET_ITEMS: &str = "reset_items";
/// The party every request is signed on behalf of (the human/user identity).
pub const PERSISTENT_ON_BEHALF_OF: &str = "did:example:user-1";

/// The JSON-RPC id of the FIRST authorized call (`echo`). Stable so the test can
/// assert this id is PRESENT in the inner server's received-log (#3965).
pub const PERSISTENT_ECHO_1_ID: &str = "persist-echo-1";
/// The JSON-RPC id of the authorized `list_items` call. Asserted PRESENT in the
/// inner's received-log.
pub const PERSISTENT_LIST_ID: &str = "persist-list-1";
/// The JSON-RPC id of the SECOND authorized `echo` call (proves the persistent
/// session survives after the denial). Asserted PRESENT in the received-log.
pub const PERSISTENT_ECHO_2_ID: &str = "persist-echo-2";
/// The JSON-RPC id of the authorization-DENIED admin `reset_items` call. This id
/// must be ABSENT from the inner's received-log: the proxy rejects it BEFORE
/// dispatch, so the long-lived inner server never sees it (the anti-gaming
/// oracle — the inner's own record, not the proxy's claim).
pub const PERSISTENT_DENIED_ID: &str = "persist-admin-deny";

/// One authorized round trip's verified facts. Carries identities + the
/// correlated hash and the returned tool payload, never a secret.
#[derive(Debug, Clone)]
pub struct PersistentCallOutcome {
    /// The JSON-RPC id this call carried (also its received-log discriminator).
    pub id: String,
    /// The tool invoked.
    pub tool: String,
    /// The request signer identity (== the mTLS client cert URI SAN, so the
    /// proxy's `exact` transport binding is satisfied — not bypassed).
    pub signer: String,
    /// The request hash the session stored at sign time and the signed response
    /// bound back to.
    pub request_hash: String,
    /// The server signer identity that signed the verified response.
    pub server_signer: String,
    /// The full parsed `result` object the inner returned (e.g. echo text,
    /// the listed items) — proof the persistent inner actually executed.
    pub result: Value,
    /// The RAW signed response bytes off the wire. Retained so a harness can
    /// verify the proxy's response signature INDEPENDENTLY — recomputing the
    /// response signing preimage and checking it against the server public key
    /// directly, not only via [`HostSession`](mcps_host::HostSession).
    pub response_bytes: Vec<u8>,
}

/// The full multi-call outcome: the verified authorized calls (in order) plus
/// the captured denial. The test asserts on the counts, the bound hashes, and
/// the denial reason.
#[derive(Debug, Clone)]
pub struct PersistentE2eOutcome {
    /// One entry per authorized call that round-tripped + verified, in order.
    pub authorized: Vec<PersistentCallOutcome>,
    /// The frozen `mcps.*` reason the denied admin call was rejected with
    /// (rendered by the proxy BEFORE dispatch).
    pub denied_reason: String,
}

/// An error driving the persistent flow. Each variant names the boundary that
/// failed so the test and the bin can surface it precisely.
#[derive(Debug, thiserror::Error)]
pub enum PersistentE2eError {
    /// Building the verifying mTLS client (TLS material) failed.
    #[error("building mTLS client: {0}")]
    Client(String),
    /// Minting or hashing a reference grant failed.
    #[error("authorization grant: {0}")]
    Grant(String),
    /// Signing a request via the [`HostSession`](mcps_host::HostSession) failed.
    #[error("signing failed: {0}")]
    Sign(String),
    /// The mTLS round trip (handshake / IO) failed.
    #[error("mTLS transport failed: {0}")]
    Transport(String),
    /// An authorized call unexpectedly returned a JSON-RPC error response.
    #[error("authorized call returned an error response: {0}")]
    AuthorizedError(String),
    /// A response could not be parsed / lacked the expected shape.
    #[error("malformed response: {0}")]
    BadResponse(String),
    /// The session refused to bind the signed response to the stored request
    /// hash, or a post-condition failed.
    #[error("response verification failed: {0}")]
    Verify(String),
    /// The denied call was NOT rejected with the expected reason (it either
    /// succeeded or was rejected for the wrong reason).
    #[error("denial expectation failed: {0}")]
    Denial(String),
}

/// One authorized `tools/call` to issue over the persistent session.
struct AuthorizedCall {
    /// Stable JSON-RPC id (also the grant revocation id discriminator).
    id: String,
    tool: &'static str,
    arguments: Value,
}

fn signer_key(fixtures: &DemoFixtures) -> SigningKey {
    SigningKey::from_seed_bytes(&fixtures.signer_seed())
}

fn server_public_key(fixtures: &DemoFixtures) -> VerificationKey {
    SigningKey::from_seed_bytes(&fixtures.server_seed()).public_key()
}

/// The trust anchor for verifying the SIGNED RESPONSE: the proxy's server signer.
fn response_resolver(fixtures: &DemoFixtures) -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(
        fixtures.server_signer(),
        fixtures.server_key_id(),
        server_public_key(fixtures),
    );
    resolver
}

/// Mint a reference grant covering exactly `tools` (one [`GrantedOperation`] per
/// tool name, no argument constraint), SELF-ISSUED by the fixture signer and
/// valid around the real clock `now_unix` so a system-clock request signed now
/// falls inside the window. Returns the canonical artifact bytes.
fn grant_artifact(
    fixtures: &DemoFixtures,
    tools: &[&str],
    revocation_id: &str,
    now_unix: i64,
    skew_secs: i64,
    lifetime_secs: i64,
) -> Result<Vec<u8>, PersistentE2eError> {
    let operations = tools
        .iter()
        .map(|tool| GrantedOperation {
            method: PERSISTENT_METHOD.to_string(),
            tool: (*tool).to_string(),
            arguments: None,
        })
        .collect();
    let spec = ReferenceGrantSpec {
        issuer: fixtures.signer().to_string(),
        grantee: fixtures.signer().to_string(),
        subject: PERSISTENT_ON_BEHALF_OF.to_string(),
        audience: fixtures.audience().to_string(),
        operations,
        not_before: mcps_core::unix_to_rfc3339_utc(now_unix - skew_secs),
        expires_at: mcps_core::unix_to_rfc3339_utc(now_unix + lifetime_secs),
        revocation_id: revocation_id.to_string(),
    };
    mint_reference_grant(&spec, &signer_key(fixtures), fixtures.signer_key_id())
        .map_err(|e| PersistentE2eError::Grant(format!("{e:?}")))
}

/// The `authorization_hash` binding a request to `artifact`.
fn authorization_hash(artifact: &[u8]) -> Result<String, PersistentE2eError> {
    ReferenceProfile::new()
        .expected_authorization_hash(artifact)
        .map_err(|e| PersistentE2eError::Grant(format!("authorization_hash: {e:?}")))
}

/// The `_meta` `.authorization` block carrying `artifact`.
fn authorization_block(artifact: &[u8]) -> Value {
    json!({
        "profile": REFERENCE_PROFILE_ID,
        "artifact": b64url_encode(artifact),
    })
}

/// Build the `tools/call` params (`{name, arguments, _meta.authorization}`).
fn call_params(tool: &str, arguments: Value, artifact: &[u8]) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(tool.to_string()));
    params.insert("arguments".to_string(), arguments);
    let mut meta = serde_json::Map::new();
    meta.insert(AUTHORIZATION_META_KEY.to_string(), authorization_block(artifact));
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// Sign one authorized `tools/call`, POST it over mTLS to the persistent proxy,
/// and verify the signed response against the STORED request hash. Returns the
/// verified outcome (the inner's `result`).
#[allow(clippy::too_many_arguments)]
fn run_authorized_call(
    session: &mut DemoHostClient<SystemClock, SystemNonceSource>,
    client: &MtlsClient,
    proxy_addr: SocketAddr,
    fixtures: &DemoFixtures,
    call: &AuthorizedCall,
    artifact: &[u8],
) -> Result<PersistentCallOutcome, PersistentE2eError> {
    let auth_hash = authorization_hash(artifact)?;
    let id = Value::String(call.id.clone());
    let params = call_params(call.tool, call.arguments.clone(), artifact);

    let request = session
        .sign_request(
            &id,
            PERSISTENT_METHOD,
            params,
            PERSISTENT_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .map_err(|e| PersistentE2eError::Sign(format!("{e:?}")))?;
    let stored_hash = session
        .stored_request_hash(&id)
        .ok_or_else(|| PersistentE2eError::Sign("no stored request hash after signing".to_string()))?
        .to_string();

    let response = client
        .round_trip(proxy_addr, &request)
        .map_err(|e| PersistentE2eError::Transport(format!("{e}")))?;

    let parsed: Value = serde_json::from_slice(&response)
        .map_err(|e| PersistentE2eError::BadResponse(format!("response is not JSON: {e}")))?;
    if let Some(error) = parsed.get("error") {
        return Err(PersistentE2eError::AuthorizedError(error.to_string()));
    }

    // VERIFY + UNWRAP (issue #4077): restore the ORIGINAL MCP `result` shape the
    // proxy reshaped before signing; an inner ERROR surfaces as an error here.
    let verified_result = session
        .verify_and_unwrap_response(&response, &response_resolver(fixtures))
        .map_err(|e| PersistentE2eError::Verify(format!("{e:?}")))?;
    let (verified, unwrapped) = verified_result.into_parts();
    if verified.request_hash() != stored_hash {
        return Err(PersistentE2eError::Verify(
            "verified response did not bind to the stored request hash".to_string(),
        ));
    }

    let result = match unwrapped {
        UnwrappedResult::Object(value) | UnwrappedResult::Scalar(value) => value,
        UnwrappedResult::InnerError(inner) => {
            return Err(PersistentE2eError::AuthorizedError(inner.to_string()));
        }
    };

    Ok(PersistentCallOutcome {
        id: call.id.clone(),
        tool: call.tool.to_string(),
        signer: fixtures.signer().to_string(),
        request_hash: stored_hash,
        server_signer: verified.server_signer().to_string(),
        result,
        response_bytes: response,
    })
}

/// Drive the persistent multi-process flow against an ALREADY-LISTENING proxy at
/// `proxy_addr` (a separate `mcps_proxy_cli --inner-mode persistent` OS process
/// fronting `mcps-demo-server`), using `fixtures` for all security material and
/// `now_unix` (the real clock) to size the grant windows.
///
/// Issues, over ONE verifying mTLS client and ONE `HostSession`:
///   1. authorized `echo` (public grant),
///   2. authorized `list_items` (protected grant),
///   3. authorized `echo` again (proving the persistent session keeps serving),
/// then one authorization-DENIED admin `reset_items` (covered by no grant),
/// asserting it is rejected with `mcps.authorization_scope_denied`.
///
/// `skew_secs` / `lifetime_secs` size the grant windows; pass the proxy's
/// `--max-clock-skew` (default 300) and a comfortable request lifetime.
pub fn run_persistent_e2e(
    fixtures: &DemoFixtures,
    proxy_addr: SocketAddr,
    now_unix: i64,
    skew_secs: i64,
    lifetime_secs: i64,
) -> Result<PersistentE2eOutcome, PersistentE2eError> {
    // ONE verifying mTLS client (present the client cert; verify the proxy's
    // server cert + identity against the fixture server CA).
    let tls = ClientTlsConfig::from_pem(
        fixtures.client_cert_pem().as_bytes(),
        fixtures.client_key_pem().as_bytes(),
        fixtures.server_ca_pem().as_bytes(),
    )
    .map_err(|e| PersistentE2eError::Client(format!("{e}")))?;
    let client =
        MtlsClient::new(tls, fixtures.server_name()).map_err(|e| PersistentE2eError::Client(format!("{e}")))?;

    // ONE session: real clock + real RNG, authoring every nonce/issued_at/
    // expires_at and storing each request hash by id.
    let mut session = DemoHostClient::with_defaults(
        HostSigner::new(signer_key(fixtures), fixtures.signer(), fixtures.signer_key_id()),
        SystemClock,
        SystemNonceSource,
    );

    // Per-scope grants. The admin tool is covered by NONE.
    let public_grant = grant_artifact(fixtures, &[TOOL_ECHO], "persist-public", now_unix, skew_secs, lifetime_secs)?;
    let protected_grant =
        grant_artifact(fixtures, &[TOOL_LIST_ITEMS], "persist-protected", now_unix, skew_secs, lifetime_secs)?;

    // The three authorized calls (>= 3), each paired with its covering grant.
    let calls = [
        (
            AuthorizedCall {
                id: PERSISTENT_ECHO_1_ID.to_string(),
                tool: TOOL_ECHO,
                arguments: json!({ "message": "hello-persistent" }),
            },
            &public_grant,
        ),
        (
            AuthorizedCall {
                id: PERSISTENT_LIST_ID.to_string(),
                tool: TOOL_LIST_ITEMS,
                arguments: json!({}),
            },
            &protected_grant,
        ),
        (
            AuthorizedCall {
                id: PERSISTENT_ECHO_2_ID.to_string(),
                tool: TOOL_ECHO,
                arguments: json!({ "message": "still-alive" }),
            },
            &public_grant,
        ),
    ];

    let mut authorized = Vec::with_capacity(calls.len());
    for (call, artifact) in &calls {
        authorized.push(run_authorized_call(
            &mut session,
            &client,
            proxy_addr,
            fixtures,
            call,
            artifact,
        )?);
    }

    // The pending set must drain after the authorized calls all verified.
    if session.pending_count() != 0 {
        return Err(PersistentE2eError::Verify(
            "pending count did not return to 0 after the authorized calls".to_string(),
        ));
    }

    // The DENIED admin call: `reset_items` is covered by NO grant. Present the
    // protected (list_items) grant — it does not cover reset_items, so the proxy
    // denies BEFORE dispatch with `authorization_scope_denied`. The persistent
    // inner is never forwarded the request.
    let denied_id = Value::String(PERSISTENT_DENIED_ID.to_string());
    let denied_hash = authorization_hash(&protected_grant)?;
    let denied_params = call_params(TOOL_RESET_ITEMS, json!({}), &protected_grant);
    let denied_request = session
        .sign_request(
            &denied_id,
            PERSISTENT_METHOD,
            denied_params,
            PERSISTENT_ON_BEHALF_OF,
            fixtures.audience(),
            &denied_hash,
        )
        .map_err(|e| PersistentE2eError::Sign(format!("{e:?}")))?;
    let denied_response = client
        .round_trip(proxy_addr, &denied_request)
        .map_err(|e| PersistentE2eError::Transport(format!("{e}")))?;
    let denied_parsed: Value = serde_json::from_slice(&denied_response)
        .map_err(|e| PersistentE2eError::BadResponse(format!("denied response is not JSON: {e}")))?;
    let denied_reason = denied_parsed
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PersistentE2eError::Denial(format!(
                "admin reset_items must be DENIED, but got: {denied_parsed}"
            ))
        })?
        .to_string();
    if denied_reason != "mcps.authorization_scope_denied" {
        return Err(PersistentE2eError::Denial(format!(
            "expected mcps.authorization_scope_denied, got: {denied_reason}"
        )));
    }
    // The denied request was rejected; the session must not have a verified
    // pending entry for it left dangling that we forgot to clean. Cancel it so
    // the session is left clean (the proxy never produced a bindable response).
    session.cancel_request(&denied_id);

    Ok(PersistentE2eOutcome {
        authorized,
        denied_reason,
    })
}

/// The server's response-signing PUBLIC key, derived from the fixture server
/// seed. The harness uses this to verify the proxy's response signature
/// INDEPENDENTLY of the producing component (the proxy) and of the consuming
/// session ([`HostSession`](mcps_host::HostSession)).
pub fn server_response_public_key(fixtures: &DemoFixtures) -> VerificationKey {
    server_public_key(fixtures)
}

/// INDEPENDENTLY verify one signed response off the wire (anti-gaming oracle for
/// `response_hash_verified`).
///
/// This does NOT go through [`HostSession`](mcps_host::HostSession) or a
/// [`TrustResolver`](mcps_core::TrustResolver): it recomputes the canonical
/// response signing preimage from the RAW bytes, verifies the Ed25519 signature
/// against `server_pubkey` DIRECTLY, and asserts the response's `request_hash`
/// binds to `expected_request_hash` (the hash the session actually stored for the
/// request it sent). A future change that re-signs a response without binding the
/// right request, or signs with the wrong key, makes this return `false`.
pub fn independently_verify_response(
    response_bytes: &[u8],
    server_pubkey: &VerificationKey,
    expected_request_hash: &str,
) -> bool {
    let value: Value = match serde_json::from_slice(response_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let envelope = match extract_response_envelope(&value) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Bind the response to the request actually sent.
    if envelope.request_hash != expected_request_hash {
        return false;
    }
    let signature_value = match envelope.signature.value.as_deref() {
        Some(v) => v,
        None => return false,
    };
    let preimage = match response_signing_preimage(&value) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Direct Ed25519 check against the server public key — no resolver, no session.
    verify_ed25519_with(
        &preimage,
        signature_value,
        server_pubkey,
        McpsError::ResponseSigInvalid,
    )
    .is_ok()
}

/// The externally-observable, MACHINE-CHECKED facts about one persistent-demo run
/// (#3966). Every field is sourced from a signal INDEPENDENT of the bin's own
/// printed "OK": the proxy's spawn lifecycle, the inner server's received-log,
/// and a direct public-key signature check. Serialized via [`Self::to_json`] as
/// the demo's evidence object; asserted field-by-field by the hermetic test.
#[derive(Debug, Clone)]
pub struct PersistentE2eAssertions {
    /// The proxy emitted its post-bind startup marker on its lifecycle stderr
    /// (`mcps-proxy: listening on …`) — an independent signal that the proxy
    /// process started and bound, NOT a restatement of the app-layer outcome.
    pub proxy_process_started: bool,
    /// At least one round trip returned over the verifying mTLS client
    /// (`WebPkiServerVerifier`). Because that verifier rejects an untrusted,
    /// wrong-identity, or expired server certificate AT THE HANDSHAKE, a returned
    /// response witnesses a verified server cert + identity. The load-bearing
    /// proof that this control is real (the tests fail if it is neutered) lives in
    /// `//mcps-transport:fault_injection_test`, not in this evidence object.
    pub mtls_verified: bool,
    /// How many times the proxy launched the persistent inner (from its spawn
    /// lifecycle stderr — `inner_spawned`). Exactly 1 for a persistent inner.
    pub inner_spawn_count: usize,
    /// How many authorized calls round-tripped AND verified.
    pub authorized_calls: usize,
    /// How many calls were denied BEFORE dispatch (the admin reset_items).
    pub denied_before_dispatch: usize,
    /// Whether the DENIED request's id appears in the inner's received-log. MUST
    /// be false: the proxy rejected it before forwarding, so the inner never saw
    /// it (sourced from the inner's OWN record, #3965 — not the proxy's claim).
    pub denied_reached_inner: bool,
    /// Whether every authorized response's signature verified via the INDEPENDENT
    /// public-key check AND its request_hash bound to the request actually sent.
    pub response_hash_verified: bool,
    /// Whether an authorized call AFTER the denied one still succeeded on the same
    /// persistent inner.
    pub session_survived_after_denial: bool,
}

impl PersistentE2eAssertions {
    /// All facts hold to the values a healthy run must produce.
    pub fn all_pass(&self) -> bool {
        self.proxy_process_started
            && self.mtls_verified
            && self.inner_spawn_count == 1
            && self.authorized_calls == 3
            && self.denied_before_dispatch == 1
            && !self.denied_reached_inner
            && self.response_hash_verified
            && self.session_survived_after_denial
    }

    /// The `assertions` JSON sub-object.
    pub fn to_json(&self) -> Value {
        json!({
            "proxy_process_started": self.proxy_process_started,
            "mtls_verified": self.mtls_verified,
            "inner_spawn_count": self.inner_spawn_count,
            "authorized_calls": self.authorized_calls,
            "denied_before_dispatch": self.denied_before_dispatch,
            "denied_reached_inner": self.denied_reached_inner,
            "response_hash_verified": self.response_hash_verified,
            "session_survived_after_denial": self.session_survived_after_denial,
        })
    }
}

/// Count `inner_spawned` lifecycle lines in the proxy's captured stderr. In
/// `--inner-mode persistent` the proxy spawns the inner ONCE, so a healthy run
/// yields exactly 1. This reads the proxy's OWN lifecycle channel — independent
/// of the flow's printed claims.
pub fn count_inner_spawns(proxy_stderr: &str) -> usize {
    proxy_stderr.matches("inner_spawned").count()
}

/// Whether a JSON-RPC `id` appears in the inner server's received-log content
/// (#3965). Each served `tools/call` appends one line `{"id":<id>,"tool":...}`,
/// so an id is "received by the inner" iff a line carries `"id":<id>` as parsed
/// JSON. The DENIED id must be ABSENT (the proxy rejected it before dispatch);
/// the authorized ids must be PRESENT. This is the INNER's own record — the
/// anti-gaming oracle, not the proxy's `inner_request_forwarded` claim.
pub fn inner_received_id(received_log: &str, id: &str) -> bool {
    received_log.lines().any(|line| {
        serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| v.get("id").and_then(Value::as_str).map(|s| s == id))
            .unwrap_or(false)
    })
}

/// Assemble the externally-observable assertions (#3966) for a persistent run
/// from the harness-gathered independent signals:
///   * `outcome` — the authorized/denied result of [`run_persistent_e2e`];
///   * `proxy_stderr` — the proxy's captured lifecycle stderr (spawn count);
///   * `inner_received_log` — the inner server's received-log content (#3965);
///   * `server_pubkey` — the server response public key (independent sig check).
///
/// Every fact is sourced from a signal the flow itself does not author, so a
/// silently-broken control surfaces as a false fact (and a failing assertion in
/// the test), not merely a changed printed line.
pub fn assemble_assertions(
    outcome: &PersistentE2eOutcome,
    proxy_stderr: &str,
    inner_received_log: &str,
    server_pubkey: &VerificationKey,
) -> PersistentE2eAssertions {
    let authorized_calls = outcome.authorized.len();
    // Independent crypto: verify EVERY authorized response's signature with the
    // server public key directly, binding to the request hash actually stored.
    let response_hash_verified = !outcome.authorized.is_empty()
        && outcome.authorized.iter().all(|call| {
            independently_verify_response(&call.response_bytes, server_pubkey, &call.request_hash)
        });
    // authorized ids MUST. The final echo (echo-2) proves the session survived.
    let denied_reached_inner = inner_received_id(inner_received_log, PERSISTENT_DENIED_ID);
    let echo_1_received = inner_received_id(inner_received_log, PERSISTENT_ECHO_1_ID);
    let list_received = inner_received_id(inner_received_log, PERSISTENT_LIST_ID);
    let echo_2_received = inner_received_id(inner_received_log, PERSISTENT_ECHO_2_ID);
    let session_survived_after_denial = echo_2_received;

    PersistentE2eAssertions {
        // Independent of the bin's printed OK: the proxy's own startup marker.
        proxy_process_started: proxy_stderr.contains("mcps-proxy: listening on"),
        // A returned round trip over the verifying client (authorized OR the
        // denial) witnesses a verified server cert at the handshake.
        mtls_verified: authorized_calls > 0 || !outcome.denied_reason.is_empty(),
        inner_spawn_count: count_inner_spawns(proxy_stderr),
        authorized_calls,
        denied_before_dispatch: usize::from(
            outcome.denied_reason == "mcps.authorization_scope_denied",
        ),
        denied_reached_inner,
        response_hash_verified,
        session_survived_after_denial: session_survived_after_denial
            && echo_1_received
            && list_received,
    }
}

/// The full machine-readable evidence object for `demo_e2e_persistent` (#3966).
/// `commit` is left for CI to fill (the bin does NOT shell out to git); when
/// absent it is omitted from the JSON.
#[derive(Debug, Clone)]
pub struct PersistentE2eEvidence {
    /// The demo name (`demo_e2e_persistent`).
    pub demo: String,
    /// `"pass"` iff every assertion holds, else `"fail"`.
    pub result: String,
    /// The externally-observable assertions.
    pub assertions: PersistentE2eAssertions,
}

impl PersistentE2eEvidence {
    /// Build the evidence from the externally-sourced assertions, deriving
    /// `result` from whether they all pass.
    pub fn from_assertions(assertions: PersistentE2eAssertions) -> Self {
        let result = if assertions.all_pass() { "pass" } else { "fail" };
        PersistentE2eEvidence {
            demo: "demo_e2e_persistent".to_string(),
            result: result.to_string(),
            assertions,
        }
    }

    /// The full evidence JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "demo": self.demo,
            "result": self.result,
            "assertions": self.assertions.to_json(),
        })
    }
}
