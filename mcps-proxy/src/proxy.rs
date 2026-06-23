//! The server-side sidecar (MCPS-015 + MCPS-016).
//!
//! [`Proxy`] sits in front of an UNMODIFIED inner MCP server. It verifies every
//! inbound MCP-S request BEFORE dispatch and fails closed: unsigned, tampered,
//! expired, replayed, or wrong-audience requests are answered with a JSON-RPC
//! error object and NEVER reach the inner server. Only verified requests are
//! forwarded — with the MCP-S transport envelope stripped and a fresh
//! verified-context block injected (MCPS-016) — and the inner server's result is
//! signed on the way back (response bound to the verified `request_hash`).
//!
//! Verified-context rules (ADR-MCPS-008): the proxy is the SOLE writer of the
//! `*.verified` block. Any caller-supplied `*.verified` is stripped regardless
//! of signature; the external `*.request` envelope is stripped by default; the
//! injected block derives ONLY from the verification result and is a
//! local-boundary artifact, never a portable credential.
//!
//! The clock is injected (`now_unix`); the proxy never reads the system clock,
//! so its behavior is deterministic and testable.

use std::cell::RefCell;
use std::sync::Arc;

use mcps_core::json_rpc_error_object;
use mcps_core::response_signing_preimage;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::McpsError;
use mcps_core::ReplayCache;
use mcps_core::TrustResolver;
use mcps_core::VerificationConfig;
use mcps_core::VerifiedContext;
use mcps_core::VerifiedRequest;
use mcps_core::REQUEST_META_KEY;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::RESPONSE_WRAP_INNER_ERROR_KEY;
use mcps_core::RESPONSE_WRAP_VALUE_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_core::VERIFIED_META_KEY;
use mcps_policy::json_rpc_authorization_error;
use mcps_policy::AuthorizationDecision;
use mcps_policy::PolicyEvaluator;
use mcps_policy::RevocationSource;
use mcps_policy::AUTHORIZATION_META_KEY;
use serde_json::json;
use serde_json::Value;

use crate::inner_launch::InnerLogEvent;
use crate::inner_launch::InnerLogSink;
use crate::key_source::ResponseSigner;
use crate::transport::LbAssertionBinding;
use crate::transport::TransportBindingPolicy;
use crate::transport::TransportIdentity;

/// An unmodified inner MCP server: plain JSON-RPC request bytes in, plain
/// JSON-RPC response bytes out. The proxy is the only MCP-S-aware component;
/// the inner server speaks ordinary MCP.
pub trait InnerServer {
    /// Dispatch one (already verified + stripped) request to the inner server.
    fn dispatch(&self, request: &[u8]) -> Vec<u8>;
}

/// Any `Fn(&[u8]) -> Vec<u8>` is an inner server (ergonomic for tests / closures
/// wrapping a real subprocess).
impl<F> InnerServer for F
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        self(request)
    }
}

/// Optional Phase 5 (ADR-MCPS-013) policy enforcement: after a request verifies
/// and BEFORE it is dispatched, evaluate the authorization artifact and deny
/// out-of-scope/expired/revoked requests. Issuer keys are resolved through the
/// proxy's existing `TrustResolver`.
struct PolicyEnforcement {
    evaluator: PolicyEvaluator,
    revocation: Box<dyn RevocationSource>,
}

/// A verify-before-dispatch MCP-S sidecar wrapping an inner server.
pub struct Proxy {
    /// Issue #3838 (ADR-MCPS-014): the response-signing key is reached ONLY through
    /// the [`ResponseSigner`] delegation seam — the proxy holds a "sign these bytes"
    /// capability, never the raw private key. An in-memory `SigningKey` satisfies
    /// `ResponseSigner` (so existing call sites are unchanged), and a non-exporting
    /// HSM/KMS-backed signer satisfies it without ever surrendering its key.
    signer: Box<dyn ResponseSigner>,
    server_signer: String,
    key_id: String,
    resolver: Box<dyn TrustResolver>,
    config: VerificationConfig,
    inner: Box<dyn InnerServer>,
    replay: RefCell<Box<dyn ReplayCache>>,
    policy: Option<PolicyEnforcement>,
    transport_binding: Option<Box<dyn TransportBindingPolicy>>,
    /// Optional ADR-MCPS-023 Tier 3 (issue #71) LB-signed, request-bound ingress
    /// assertion verifier. Unlike `transport_binding` — whose identity is resolved
    /// from the connection BEFORE verification — an LB assertion binds
    /// `verified.request_hash`, so it can only be checked AFTER object verification.
    /// When set, the post-verification path REQUIRES a presented assertion header,
    /// cryptographically verifies it against the in-hand request hash, and feeds the
    /// resulting verified [`TransportIdentity`] into `transport_binding` so the
    /// signer↔identity binding still applies. A `Proxy` built without this ignores
    /// the assertion header entirely.
    lb_assertion: Option<LbAssertionBinding>,
    /// Optional MCPS-036 lifecycle-event sink for the two proxy-level events
    /// (`inner_request_forwarded`, `inner_response_signed`). Inner-process-level
    /// events (spawn/exit/stderr) are emitted by the `SubprocessInner` itself.
    log_sink: Option<Arc<dyn InnerLogSink + Send + Sync>>,
}

impl Proxy {
    /// Construct a sidecar.
    ///
    /// * `signer` / `server_signer` / `key_id` — the response-signing capability
    ///   (issue #3838 delegation seam) and its advertised identity / key id. Any
    ///   [`ResponseSigner`] is accepted: an in-memory [`mcps_core::SigningKey`]
    ///   (which impls `ResponseSigner`) — so existing call sites pass a key
    ///   unchanged — or a non-exporting HSM/KMS-backed signer that never surrenders
    ///   its private key. The signer is boxed internally.
    /// * `resolver` — resolves inbound request signers.
    /// * `expected_audience` / `max_clock_skew_secs` — verification policy.
    /// * `inner` — the unmodified MCP server to protect.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: impl ResponseSigner + 'static,
        server_signer: impl Into<String>,
        key_id: impl Into<String>,
        resolver: Box<dyn TrustResolver>,
        expected_audience: impl Into<String>,
        max_clock_skew_secs: i64,
        inner: Box<dyn InnerServer>,
    ) -> Self {
        Proxy {
            signer: Box::new(signer),
            server_signer: server_signer.into(),
            key_id: key_id.into(),
            resolver,
            config: VerificationConfig {
                expected_audience: expected_audience.into(),
                max_clock_skew_secs,
            },
            inner,
            replay: RefCell::new(Box::new(InMemoryReplayCache::new(max_clock_skew_secs))),
            policy: None,
            transport_binding: None,
            lb_assertion: None,
            log_sink: None,
        }
    }

    /// Attach an MCPS-036 lifecycle-event sink for the proxy-level events
    /// (`inner_request_forwarded` when a verified request is forwarded to the
    /// inner server, `inner_response_signed` when a signed response is produced).
    /// `inner_identity` tags the emissions. A `Proxy` built without this emits no
    /// proxy-level lifecycle events.
    pub fn with_log_sink(
        mut self,
        log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    ) -> Self {
        self.log_sink = Some(log_sink);
        self
    }

    /// Replace the default in-memory replay cache with an injected one (e.g. the
    /// durable file-backed cache). The cache is consulted only after signature
    /// verification; a cache failure fails closed.
    pub fn with_replay_cache(mut self, cache: Box<dyn ReplayCache>) -> Self {
        self.replay = RefCell::new(cache);
        self
    }

    /// The self-declared [`mcps_core::ReplayDurabilityClass`] of the replay cache
    /// this proxy actually holds (issue #78, ADR-MCPS-020). Lets the wiring layer
    /// MACHINE-CHECK the cache OBJECT — including a caller-injected one — rather than
    /// inferring durability from the selected `ReplayKind`. A strict/production
    /// startup rejects a [`mcps_core::ReplayDurabilityClass::SingleProcessReference`]
    /// cache, closing the gap at the object level (defense in depth beneath the
    /// CLI-flag rejection of `--replay-cache memory`).
    pub fn replay_durability_class(&self) -> mcps_core::ReplayDurabilityClass {
        self.replay.borrow().durability_class()
    }

    /// Enable opt-in Phase 5 policy enforcement (ADR-MCPS-013). After a request
    /// verifies and before it is dispatched, `evaluator` evaluates the
    /// authorization artifact (issuer keys resolved through this proxy's
    /// `TrustResolver`); a denial fails closed with the matching
    /// `mcps.authorization_*` error and the inner server is never reached. A
    /// `Proxy` built without this is behaviorally identical to a pre-Phase-5
    /// sidecar.
    pub fn with_policy_enforcement(
        mut self,
        evaluator: PolicyEvaluator,
        revocation: Box<dyn RevocationSource>,
    ) -> Self {
        self.policy = Some(PolicyEnforcement {
            evaluator,
            revocation,
        });
        self
    }

    /// Enable opt-in Phase 6 transport binding (ADR-MCPS-014). After verification
    /// (and any authorization policy) and before dispatch, the verified request
    /// `signer` is checked against the connection's verified transport identity;
    /// a mismatch (or a required-but-absent identity) fails closed with
    /// `mcps.transport_binding_failed`. A `Proxy` built without this ignores the
    /// transport identity entirely.
    pub fn with_transport_binding(mut self, policy: Box<dyn TransportBindingPolicy>) -> Self {
        self.transport_binding = Some(policy);
        self
    }

    /// Enable opt-in ADR-MCPS-023 Tier 3 (issue #71) LB-signed, request-bound
    /// ingress assertion verification. After object verification (and any
    /// authorization policy) and BEFORE dispatch, the presented assertion header
    /// (passed to [`Proxy::handle_with_transport`]) is cryptographically verified
    /// against the in-hand `verified.request_hash`: a missing-but-required header,
    /// an unknown LB key, a bad signature, a cross-request hash, or a stale
    /// assertion ALL fail closed with `mcps.transport_binding_failed` and the inner
    /// server is never reached. On success the verifier yields a verified
    /// [`TransportIdentity`] which is fed into the configured transport-binding
    /// policy so the request signer↔identity binding still applies (the LB binding
    /// does not replace it — it SUPPLIES the identity the policy then checks). This
    /// is honestly downgraded — request-bound ingress assertion, NOT end-to-end
    /// client↔node mTLS (see [`LbAssertionBinding::GUARANTEE`]). A `Proxy` built
    /// without this ignores the assertion header entirely.
    pub fn with_lb_assertion(mut self, lb_assertion: LbAssertionBinding) -> Self {
        self.lb_assertion = Some(lb_assertion);
        self
    }

    /// Handle one inbound request without a transport identity (stdio / no mTLS).
    /// Equivalent to [`Proxy::handle_with_transport`] with `identity = None` and no
    /// LB-assertion header. When an LB-assertion verifier is configured this fails
    /// closed (a required assertion header is absent).
    pub fn handle(&self, request_bytes: &[u8], now_unix: i64) -> Vec<u8> {
        self.handle_with_transport(request_bytes, now_unix, None, None)
    }

    /// Handle one inbound request carrying the connection's verified transport
    /// identity (mTLS): verify, then (on success) authorization policy, then
    /// transport binding, then strip + forward + sign — or, on any failure, an
    /// unsigned JSON-RPC error WITHOUT touching the inner server. Never panics.
    ///
    /// `lb_assertion_header` carries the raw presented Tier-3 ingress-assertion
    /// header value (issue #71), if any. It is consulted ONLY when an
    /// [`LbAssertionBinding`] is configured (via [`Proxy::with_lb_assertion`]): the
    /// assertion can only be checked AFTER verification (it binds
    /// `verified.request_hash`), so it cannot flow through the pre-resolved
    /// `transport_identity` seam. When the LB verifier is configured the header is
    /// REQUIRED — its absence, or any assertion rejection, fails closed before
    /// dispatch.
    pub fn handle_with_transport(
        &self,
        request_bytes: &[u8],
        now_unix: i64,
        transport_identity: Option<&TransportIdentity>,
        lb_assertion_header: Option<&str>,
    ) -> Vec<u8> {
        let parsed: Option<Value> = serde_json::from_slice(request_bytes).ok();
        let id_value = parsed
            .as_ref()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);

        let verify_result = match self.replay.try_borrow_mut() {
            Ok(mut replay) => verify_request(
                request_bytes,
                self.resolver.as_ref(),
                &mut **replay,
                &self.config,
                now_unix,
            ),
            Err(_) => Err(McpsError::ReplayCacheUnavailable),
        };

        match verify_result {
            // Fail closed: the inner server is never reached.
            Err(err) => json_rpc_error_object(&err, &id_value),
            Ok(verified) => {
                // Phase 5 (ADR-MCPS-013): when policy enforcement is enabled,
                // evaluate authorization BEFORE dispatch and fail closed on deny.
                if let Some(policy) = &self.policy {
                    let request_value: Value = match parsed {
                        Some(value) => value,
                        None => return json_rpc_error_object(&McpsError::CanonicalizationFailed, &id_value),
                    };
                    let decision = policy.evaluator.evaluate(
                        &verified,
                        &request_value,
                        self.resolver.as_ref(),
                        policy.revocation.as_ref(),
                        now_unix,
                    );
                    if let AuthorizationDecision::Deny(err) = decision {
                        return json_rpc_authorization_error(&err, &id_value);
                    }
                }
                // ADR-MCPS-023 Tier 3 (issue #71): when an LB-signed, request-bound
                // ingress assertion verifier is configured, the verified transport
                // identity comes from a CRYPTOGRAPHICALLY-VERIFIED assertion bound to
                // THIS request's hash — not from the pre-resolved `transport_identity`
                // seam (that identity is resolved before verification, so it cannot
                // carry the request-hash binding). Require the header, verify it, and
                // on success substitute the verified identity for the binding check
                // below; any rejection (missing header, unknown key, bad signature,
                // cross-request hash, stale) fails closed before dispatch. Object
                // verification has ALREADY run above and is independent of this — a
                // tampered object signature never reaches here regardless of a valid
                // assertion.
                let lb_verified_identity: Option<TransportIdentity> = match &self.lb_assertion {
                    None => None,
                    Some(lb) => {
                        // Builder-composition guard (issue #135): the LB assertion
                        // exists ONLY to SUPPLY the request-bound verified identity
                        // that `transport_binding` then ties to `verified_signer`. If
                        // no transport-binding policy is configured, the verified
                        // identity below would be consumed by nothing — the
                        // signer↔identity binding the assertion is verified to enforce
                        // would be silently dropped. That is a misconfiguration, not a
                        // weaker-but-valid mode: fail closed rather than admit a
                        // request whose asserted identity is never bound. (The shipped
                        // CLI always pairs the two; this closes the gap for any other
                        // embedder/test that wires only the LB assertion.)
                        if self.transport_binding.is_none() {
                            return json_rpc_error_object(
                                &McpsError::TransportBindingFailed,
                                &id_value,
                            );
                        }
                        let header = match lb_assertion_header {
                            Some(value) => value,
                            // Required-but-absent assertion header → fail closed.
                            None => {
                                return json_rpc_error_object(
                                    &McpsError::TransportBindingFailed,
                                    &id_value,
                                )
                            }
                        };
                        match lb.verify(header, &verified.request_hash, now_unix) {
                            Ok(identity) => Some(identity),
                            // Any LbAssertionRejection maps to the transport-boundary
                            // wire token; the inner server is never reached.
                            Err(_rejection) => {
                                return json_rpc_error_object(
                                    &McpsError::TransportBindingFailed,
                                    &id_value,
                                )
                            }
                        }
                    }
                };
                // Phase 6 (ADR-MCPS-014): bind the verified signer to the channel
                // identity. With an LB assertion configured, the identity is the one
                // the assertion just verified (request-bound); otherwise it is the
                // pre-resolved `transport_identity`. Fail closed before dispatch.
                if let Some(binding) = &self.transport_binding {
                    let identity = lb_verified_identity.as_ref().or(transport_identity);
                    if let Err(err) = binding.check(&verified.verified_signer, identity) {
                        return json_rpc_error_object(&err, &id_value);
                    }
                }
                // Response `id` provenance (issue #24): on THIS branch the request
                // has been cryptographically verified, and the JSON-RPC top-level
                // `id` is inside the signing preimage (the preimage canonicalizes
                // the whole object minus `signature.value` and the container trace
                // keys), so the request signature COVERS `id` — a tampered `id`
                // fails verification and never reaches here. A duplicate top-level
                // `id` is likewise rejected at verify step 3 (raw-bytes JCS
                // duplicate-key check). `id_value` is parsed from the same bytes
                // `verify_request` validated, so on success it IS the verified
                // request's id — not unchecked inbound data. (The error branches
                // above use `id_value` only for best-effort correlation, where no
                // verified request exists.) Pinned by the #24 tests.
                match self.dispatch_and_sign(request_bytes, &verified, now_unix, &id_value) {
                    Ok(bytes) => bytes,
                    Err(err) => json_rpc_error_object(&err, &id_value),
                }
            }
        }
    }

    /// Strip + inject verified context, forward to the inner server, then sign
    /// its result.
    fn dispatch_and_sign(
        &self,
        request_bytes: &[u8],
        verified: &VerifiedRequest,
        now_unix: i64,
        id_value: &Value,
    ) -> Result<Vec<u8>, McpsError> {
        let forwarded = self.build_forwarded_request(request_bytes, verified, now_unix)?;
        if let Some(sink) = &self.log_sink {
            sink.log(&verified.verified_signer, &InnerLogEvent::RequestForwarded);
        }
        let inner_response = self.inner.dispatch(&forwarded);
        let signed = self.build_signed_response(&inner_response, verified, now_unix, id_value)?;
        if let Some(sink) = &self.log_sink {
            sink.log(&verified.verified_signer, &InnerLogEvent::ResponseSigned);
        }
        Ok(signed)
    }

    /// Build the request forwarded to the inner server (MCPS-016): strip the
    /// external `*.request` envelope, strip ANY caller-supplied `*.verified`
    /// block, and inject a fresh `*.verified` derived only from `verified`.
    fn build_forwarded_request(
        &self,
        request_bytes: &[u8],
        verified: &VerifiedRequest,
        now_unix: i64,
    ) -> Result<Vec<u8>, McpsError> {
        let mut request: Value =
            serde_json::from_slice(request_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;

        // Scrub ANY caller-supplied proxy-owned MCP-S `_meta` keys from EVERY
        // `_meta` location (the container `params._meta` AND any nested `_meta`,
        // e.g. under `params.arguments`) BEFORE injecting the proxy-authored
        // block. This is what makes the proxy the sole writer: a caller cannot
        // pre-seed a forged `*.verified`/`*.request`/`*.authorization` anywhere in
        // the request and have it reach the inner server as proxy-authored.
        scrub_proxy_owned_meta(&mut request);

        let context = VerifiedContext {
            verified_signer: verified.verified_signer.clone(),
            key_id: verified.key_id.clone(),
            on_behalf_of: verified.on_behalf_of.clone(),
            audience: verified.audience.clone(),
            authorization_hash: verified.authorization_hash.clone(),
            request_hash: verified.request_hash.clone(),
            verifier: self.server_signer.clone(),
            verified_at: unix_to_rfc3339_utc(now_unix),
        };
        let context_value =
            serde_json::to_value(&context).map_err(|_| McpsError::CanonicalizationFailed)?;

        // Inject the SINGLE canonical `verified` block the proxy authors. The
        // recursive scrub above already removed every proxy-owned key (the external
        // `*.request` transport envelope, the `*.authorization` artifact not meant
        // for the inner server, and any caller `*.verified` copy) from this and
        // every nested `_meta`, so this is the only proxy-owned block forwarded.
        match request["params"]["_meta"].as_object_mut() {
            Some(meta) => {
                meta.insert(VERIFIED_META_KEY.to_string(), context_value);
            }
            None => {
                // A verified request always had a params._meta object, but stay
                // defensive: synthesize a _meta carrying only the fresh context.
                request["params"]["_meta"] = json!({ VERIFIED_META_KEY: context_value });
            }
        }

        serde_json::to_vec(&request).map_err(|_| McpsError::CanonicalizationFailed)
    }

    /// Wrap the inner server's response in a SIGNED envelope bound to the verified
    /// `request_hash` and the request `id`, covering EVERY inner shape (issue
    /// #4077, findings M17/M18/M25/M26/M27).
    ///
    /// The client's integrity guarantee — "every response I receive is signed by
    /// the server and bound to MY request" — must not depend on what the inner
    /// server chooses to return. A hostile inner could otherwise suppress the
    /// signature simply by returning a non-object result or an error. So all four
    /// inner shapes are normalized into a signed `result` object:
    ///
    /// * an OBJECT `result` is signed in place (unchanged behavior);
    /// * a NON-OBJECT `result` (number/string/bool/array/null) is preserved under
    ///   `result.value` and signed (wrap-and-sign — M17/M18/M25);
    /// * an inner ERROR (or any response carrying no `result`) is preserved under
    ///   `result.inner_error` and signed, with the OUTGOING `id` taken from the
    ///   verified request — never from a hostile inner-controlled (possibly null)
    ///   `id` (wrap-and-sign — M26/M27).
    ///
    /// In every case the outgoing object is a signed, request-hash-bound,
    /// id-correlated envelope the client verifies through the SAME
    /// `verify_response` path; the inner-controlled payload can no longer suppress
    /// the signature.
    fn build_signed_response(
        &self,
        inner_response: &[u8],
        verified: &VerifiedRequest,
        now_unix: i64,
        id_value: &Value,
    ) -> Result<Vec<u8>, McpsError> {
        let inner: Value =
            serde_json::from_slice(inner_response).map_err(|_| McpsError::CanonicalizationFailed)?;

        let mut result = match inner.get("result") {
            // OBJECT result — sign the inner result object in place.
            Some(result) if result.is_object() => result.clone(),
            // NON-OBJECT result (scalar/array/null) — preserve under `value` and
            // sign, so the same signed+bound guarantee applies (M17/M18/M25). The
            // client-side `mcps_core::unwrap_verified_result` strips this wrapper
            // back to the scalar (issue #4077); both sides share the key constant.
            Some(result) => json!({ RESPONSE_WRAP_VALUE_KEY: result.clone() }),
            // No `result` at all — this is an inner error (or a malformed inner
            // response). Preserve the inner object under `inner_error` and sign,
            // so the client still gets a signed, request-bound, id-correlated
            // envelope rather than an unsigned verbatim pass-through (M26/M27). The
            // client-side `mcps_core::unwrap_verified_result` surfaces this as a
            // real error to the caller (issue #4077); both sides share the key.
            None => json!({ RESPONSE_WRAP_INNER_ERROR_KEY: inner.clone() }),
        };

        // Scrub any inner-server-forged proxy-owned MCP-S `_meta` keys from EVERY
        // `_meta` location in the result (including nested ones, e.g. under
        // `result.content[].metadata._meta`) BEFORE the proxy adds its canonical
        // `result._meta.response` and signs. A hostile inner therefore cannot
        // smuggle a forged `*.response`/`*.verified`/`*.request`/`*.authorization`
        // block into a response that then carries the proxy's signature.
        scrub_proxy_owned_meta(&mut result);

        let mut response = json!({
            "jsonrpc": "2.0",
            "id": id_value.clone(),
            "result": result,
        });
        response["result"]["_meta"][RESPONSE_META_KEY] = json!({
            "request_hash": verified.request_hash,
            "server_signer": self.server_signer,
            "issued_at": unix_to_rfc3339_utc(now_unix),
            "signature": { "alg": SIG_ALG_ED25519, "key_id": self.key_id },
        });

        let preimage = response_signing_preimage(&response)?;
        // Issue #3838: sign through the delegation seam. The key never leaves the
        // signer. A signing failure (e.g. a non-exporting device that is offline)
        // FAILS CLOSED: it maps to `ResponseSigInvalid` — the response-signature
        // failure wire token — which `dispatch_and_sign`'s caller turns into a
        // JSON-RPC error object, exactly as any other response-path failure here.
        let signature = self
            .signer
            .sign_response(&preimage)
            .map_err(|_| McpsError::ResponseSigInvalid)?;
        response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(signature);

        serde_json::to_vec(&response).map_err(|_| McpsError::CanonicalizationFailed)
    }
}

/// The four MCP-S `_meta` keys the proxy EXCLUSIVELY owns at the trust boundary
/// (ADR-MCPS-014 / ADR-MCPS-026). The proxy is the sole writer of each; any
/// caller- or inner-server-supplied copy is scrubbed before the proxy forwards a
/// request or signs a response. This is the explicit protocol-owned key set — NOT
/// a `se.syncom/mcps.*` prefix scrub — so unrelated `_meta` keys are untouched.
const PROXY_OWNED_META_KEYS: [&str; 4] = [
    REQUEST_META_KEY,
    RESPONSE_META_KEY,
    VERIFIED_META_KEY,
    AUTHORIZATION_META_KEY,
];

/// Recursively remove the four [`PROXY_OWNED_META_KEYS`] from EVERY `_meta` object
/// anywhere in `value` (issue #22, cluster 3): the container `_meta`, and any
/// `_meta` nested arbitrarily deep under `params`/`arguments`/`result`/`content`
/// — including through arrays. Only these protocol-owned keys are removed; all
/// other `_meta` content is preserved. The proxy writes its single canonical block
/// AFTER this scrub, so the authoritative block is never the one removed.
///
/// This enforces the trust-boundary invariant that MCP-S metadata is proxy-owned:
/// a caller cannot smuggle a forged nested `*.verified` to the inner server, and a
/// hostile inner cannot smuggle a forged nested `*.response`/`*.request`/
/// `*.authorization` into a response the proxy then signs.
fn scrub_proxy_owned_meta(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // Strip the proxy-owned keys from this object's own `_meta`, if any.
            if let Some(meta) = map.get_mut("_meta").and_then(Value::as_object_mut) {
                for key in PROXY_OWNED_META_KEYS {
                    meta.remove(key);
                }
            }
            // Recurse into every member to reach nested `_meta` objects (and the
            // just-scrubbed `_meta` itself, harmlessly).
            for child in map.values_mut() {
                scrub_proxy_owned_meta(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_proxy_owned_meta(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::scrub_proxy_owned_meta;
    use super::Proxy;
    use mcps_core::request_hash;
    use mcps_core::request_signing_preimage;
    use mcps_core::verify_response;
    use mcps_core::InMemoryTrustResolver;
    use mcps_core::SigningKey;
    use mcps_core::REQUEST_META_KEY;
    use mcps_core::RESPONSE_META_KEY;
    use mcps_core::SIG_ALG_ED25519;
    use mcps_core::VERIFIED_META_KEY;
    use mcps_core::VERSION_DRAFT_01;
    use mcps_policy::AUTHORIZATION_META_KEY;
    use serde_json::json;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::Mutex;

    const SIGNER: &str = "did:example:agent-1";
    const SIGNER_KEY_ID: &str = "key-1";
    const SERVER: &str = "did:example:server-1";
    const SERVER_KEY_ID: &str = "server-key-1";
    const AUDIENCE: &str = "did:example:server-1";
    const ON_BEHALF_OF: &str = "did:example:user-1";
    const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
    const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
    const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
    const SKEW: i64 = 300;
    const REQUEST_ID: &str = "req-unsigned-coverage-1";

    fn signer_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[1u8; 32])
    }
    fn server_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[2u8; 32])
    }
    fn now() -> i64 {
        mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
    }
    fn inbound_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
        r
    }
    fn server_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
        r
    }

    /// Build a valid signed inbound `tools/call` request using ONLY `mcps_core`
    /// primitives (the unit-test target does not depend on `mcps_host`).
    fn signed_request(nonce: &str) -> Vec<u8> {
        let mut request = json!({
            "id": REQUEST_ID,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello" },
                "_meta": {
                    REQUEST_META_KEY: {
                        "version": VERSION_DRAFT_01,
                        "signer": SIGNER,
                        "on_behalf_of": ON_BEHALF_OF,
                        "audience": AUDIENCE,
                        "authorization_hash": AUTH_HASH,
                        "nonce": nonce,
                        "issued_at": ISSUED_AT,
                        "expires_at": EXPIRES_AT,
                        "signature": { "alg": SIG_ALG_ED25519, "key_id": SIGNER_KEY_ID },
                    }
                }
            }
        });
        let preimage = request_signing_preimage(&request).expect("request preimage");
        let signature = signer_key().sign(&preimage);
        request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] =
            Value::String(signature);
        serde_json::to_vec(&request).expect("serialize signed request")
    }

    /// The `request_hash` the client will bind the response against — derived
    /// from the SAME canonical request the proxy verified (signature.value is
    /// excluded from the preimage, so signing does not perturb it).
    fn expected_request_hash(nonce: &str) -> String {
        let bytes = signed_request(nonce);
        let value: Value = serde_json::from_slice(&bytes).expect("parse signed request");
        request_hash(&value).expect("request_hash")
    }

    /// A `Proxy` whose inner server always returns `inner_response` verbatim.
    fn proxy_returning(inner_response: Value) -> Proxy {
        let bytes = serde_json::to_vec(&inner_response).expect("serialize inner response");
        let inner = move |_request: &[u8]| -> Vec<u8> { bytes.clone() };
        Proxy::new(
            server_key(),
            SERVER,
            SERVER_KEY_ID,
            Box::new(inbound_resolver()),
            AUDIENCE,
            SKEW,
            Box::new(inner),
        )
    }

    fn out_value(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("parse outgoing response")
    }

    // ---- M17/M18/M25: non-object inner results must be signed + request-bound ----

    #[test]
    fn scalar_number_result_is_signed_and_request_bound() {
        let nonce = "nonce-cov-number-1";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": 42,
        }));
        let out = proxy.handle(&signed_request(nonce), now());

        // The client MUST be able to verify the response against its request_hash.
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("scalar-number result must be a signed, request-bound envelope");
    }

    #[test]
    fn array_result_is_signed_and_request_bound() {
        let nonce = "nonce-cov-array-1";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": [1, 2, 3],
        }));
        let out = proxy.handle(&signed_request(nonce), now());
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("array result must be a signed, request-bound envelope");
    }

    #[test]
    fn null_result_is_signed_and_request_bound() {
        let nonce = "nonce-cov-null-1";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": Value::Null,
        }));
        let out = proxy.handle(&signed_request(nonce), now());
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("null result must be a signed, request-bound envelope");
    }

    #[test]
    fn scalar_result_payload_is_preserved_under_value() {
        let nonce = "nonce-cov-preserve-1";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": "scalar-string",
        }));
        let out = proxy.handle(&signed_request(nonce), now());
        let value = out_value(&out);
        // The inner scalar is preserved so it is not silently dropped by wrapping.
        assert_eq!(
            value["result"]["value"],
            Value::String("scalar-string".to_string()),
            "inner scalar must be preserved under result.value"
        );
    }

    // ---- M26/M27: inner ERROR responses must be signed, request-bound, id-correlated ----

    #[test]
    fn inner_error_is_signed_request_bound_and_id_correlated() {
        let nonce = "nonce-cov-error-1";
        // A hostile inner returns an error with a NULL id and an attacker body —
        // the proxy must NOT forward it verbatim and unsigned.
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32000, "message": "inner boom" },
        }));
        let out = proxy.handle(&signed_request(nonce), now());

        // (1) The outgoing envelope must be signed + bound to the request_hash.
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("inner error must be wrapped in a signed, request-bound envelope");

        // (2) The id must correlate to the REQUEST, not the hostile inner null.
        let value = out_value(&out);
        assert_eq!(
            value["id"],
            Value::String(REQUEST_ID.to_string()),
            "outgoing id must correlate to the request, not the inner null id"
        );
        // (3) The outgoing object must NOT be a bare unsigned pass-through error.
        assert!(
            value.get("error").is_none(),
            "inner error must not be passed through as a top-level unsigned error"
        );
    }

    #[test]
    fn inner_error_does_not_pass_through_verbatim() {
        let nonce = "nonce-cov-error-2";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32000, "message": "inner boom", "data": "attacker" },
        }));
        let out = proxy.handle(&signed_request(nonce), now());
        let value = out_value(&out);
        // The exact hostile inner object (null id + top-level error) must not be
        // what the client receives.
        let is_verbatim = value.get("error").is_some() && value["id"] == Value::Null;
        assert!(!is_verbatim, "hostile inner error must not be forwarded verbatim");
    }

    // ---- Issue #22 (cluster 3): proxy-owned `_meta` scrub at EVERY location ----

    /// A `Proxy` whose inner records the forwarded request bytes (so a test can
    /// inspect exactly what crossed the trust boundary) and returns a minimal
    /// valid object result.
    fn proxy_capturing(captured: Arc<Mutex<Vec<u8>>>) -> Proxy {
        let inner = move |request: &[u8]| -> Vec<u8> {
            *captured.lock().expect("capture lock") = request.to_vec();
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "result": {} }))
                .expect("serialize inner result")
        };
        Proxy::new(
            server_key(),
            SERVER,
            SERVER_KEY_ID,
            Box::new(inbound_resolver()),
            AUDIENCE,
            SKEW,
            Box::new(inner),
        )
    }

    /// A signed inbound request that ALSO carries attacker-planted proxy-owned
    /// `_meta` blocks nested under `params.arguments._meta` (a forged `*.verified`
    /// the caller hopes the inner will trust) plus an unrelated nested `_meta` key.
    /// Signed AFTER planting, so the nested blocks are within the (legitimately
    /// signed) request — exactly the hostile case the scrub must defeat.
    fn signed_request_with_forged_nested(nonce: &str) -> Vec<u8> {
        let mut request = json!({
            "id": REQUEST_ID,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {
                    "text": "hello",
                    "_meta": {
                        VERIFIED_META_KEY: { "verified_signer": "did:evil:impostor" },
                        AUTHORIZATION_META_KEY: { "forged": true },
                        "io.example/keep": "unrelated-nested-meta"
                    }
                },
                "_meta": {
                    REQUEST_META_KEY: {
                        "version": VERSION_DRAFT_01,
                        "signer": SIGNER,
                        "on_behalf_of": ON_BEHALF_OF,
                        "audience": AUDIENCE,
                        "authorization_hash": AUTH_HASH,
                        "nonce": nonce,
                        "issued_at": ISSUED_AT,
                        "expires_at": EXPIRES_AT,
                        "signature": { "alg": SIG_ALG_ED25519, "key_id": SIGNER_KEY_ID },
                    }
                }
            }
        });
        let preimage = request_signing_preimage(&request).expect("request preimage");
        let signature = signer_key().sign(&preimage);
        request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] =
            Value::String(signature);
        serde_json::to_vec(&request).expect("serialize signed request")
    }

    #[test]
    fn forged_nested_verified_is_scrubbed_from_forwarded_request() {
        let nonce = "nonce-scrub-req-1";
        let captured = Arc::new(Mutex::new(Vec::new()));
        let proxy = proxy_capturing(Arc::clone(&captured));
        let _ = proxy.handle(&signed_request_with_forged_nested(nonce), now());

        let forwarded: Value =
            serde_json::from_slice(&captured.lock().expect("lock")).expect("parse forwarded");

        // The forged nested `*.verified` / `*.authorization` are gone from the
        // nested `arguments._meta`...
        let nested = &forwarded["params"]["arguments"]["_meta"];
        assert!(
            nested.get(VERIFIED_META_KEY).is_none(),
            "a forged nested *.verified must be scrubbed before forwarding"
        );
        assert!(
            nested.get(AUTHORIZATION_META_KEY).is_none(),
            "a forged nested *.authorization must be scrubbed before forwarding"
        );
        // ...while an unrelated nested `_meta` key survives.
        assert_eq!(
            nested["io.example/keep"],
            Value::String("unrelated-nested-meta".to_string()),
            "unrelated nested _meta keys must be preserved"
        );
        // The proxy authors EXACTLY ONE canonical verified block, at params._meta,
        // and it reflects the verified signer (not the attacker's forged value).
        assert_eq!(
            forwarded["params"]["_meta"][VERIFIED_META_KEY]["verified_signer"],
            Value::String(SIGNER.to_string()),
            "the canonical verified block is the proxy-authored one"
        );
    }

    #[test]
    fn forged_nested_mcps_blocks_scrubbed_from_signed_response() {
        let nonce = "nonce-scrub-resp-1";
        // A hostile inner returns an object result with forged proxy-owned blocks
        // nested deep under result.content[].metadata._meta, plus an unrelated key.
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": {
                "content": [{
                    "type": "text",
                    "text": "hello",
                    "metadata": {
                        "_meta": {
                            RESPONSE_META_KEY: { "server_signer": "did:evil:impostor" },
                            VERIFIED_META_KEY: { "forged": true },
                            REQUEST_META_KEY: { "forged": true },
                            AUTHORIZATION_META_KEY: { "forged": true },
                            "io.example/keep": "unrelated-nested-meta"
                        }
                    }
                }]
            }
        }));
        let out = proxy.handle(&signed_request(nonce), now());

        // The outgoing envelope still verifies (the canonical response block the
        // proxy wrote is intact and signs the scrubbed result).
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("scrubbed response must still be a signed, request-bound envelope");

        let value = out_value(&out);
        let nested = &value["result"]["content"][0]["metadata"]["_meta"];
        for key in [
            RESPONSE_META_KEY,
            VERIFIED_META_KEY,
            REQUEST_META_KEY,
            AUTHORIZATION_META_KEY,
        ] {
            assert!(
                nested.get(key).is_none(),
                "forged nested proxy-owned key {key} must be scrubbed before signing"
            );
        }
        assert_eq!(
            nested["io.example/keep"],
            Value::String("unrelated-nested-meta".to_string()),
            "unrelated nested _meta keys must survive the response scrub"
        );
        // The proxy's own canonical response block is present and authoritative.
        assert_eq!(
            value["result"]["_meta"][RESPONSE_META_KEY]["server_signer"],
            Value::String(SERVER.to_string()),
            "the canonical response block is the proxy-authored one"
        );
    }

    // ---- Issue #24: response `id` provenance — only a verified id is signed ----

    #[test]
    fn signed_response_id_is_the_verified_request_id() {
        let nonce = "nonce-id-happy-1";
        let proxy = proxy_returning(json!({
            "jsonrpc": "2.0",
            "id": REQUEST_ID,
            "result": { "ok": true },
        }));
        let out = proxy.handle(&signed_request(nonce), now());
        // The response verifies AND its correlation id is exactly the request id.
        verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
            .expect("happy-path response must be signed and request-bound");
        assert_eq!(
            out_value(&out)["id"],
            Value::String(REQUEST_ID.to_string()),
            "the signed response id must echo the verified request id"
        );
    }

    #[test]
    fn tampered_top_level_id_fails_verification_and_is_not_signed() {
        let nonce = "nonce-id-tamper-1";
        // Take a validly signed request and change ONLY the top-level id, WITHOUT
        // re-signing. The id is inside the signing preimage, so the request
        // signature no longer matches → verification fails → no signed response.
        let mut request: Value =
            serde_json::from_slice(&signed_request(nonce)).expect("parse signed request");
        request["id"] = Value::String("did:evil:swapped-id".to_string());
        let tampered = serde_json::to_vec(&request).expect("serialize");

        let proxy = proxy_returning(json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "result": {} }));
        let out = proxy.handle(&tampered, now());

        // It is an unsigned JSON-RPC error, NOT a verifiable signed response.
        assert!(
            verify_response(&out, &server_resolver(), &expected_request_hash(nonce)).is_err(),
            "a tampered-id request must never yield a verifiable signed response"
        );
        assert!(
            out_value(&out).get("error").is_some(),
            "a tampered-id request must fail closed with a JSON-RPC error"
        );
    }

    #[test]
    fn duplicate_top_level_id_is_rejected_and_is_not_signed() {
        let nonce = "nonce-id-dup-1";
        // Inject a DUPLICATE top-level `id` member into otherwise-signed bytes. The
        // raw-bytes JCS duplicate-key check (verify step 3) rejects it before any
        // signed response can be produced, so a last-wins duplicate id can never
        // propagate to a signed response.
        let signed = signed_request(nonce);
        let text = String::from_utf8(signed).expect("utf8");
        // Serialized object begins with `{` then the first member; inject a second
        // `id` right after the opening brace to create a duplicate key.
        let duped = format!("{{\"id\":\"did:evil:dup\",{}", &text[1..]);

        let proxy = proxy_returning(json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "result": {} }));
        let out = proxy.handle(duped.as_bytes(), now());

        assert!(
            verify_response(&out, &server_resolver(), &expected_request_hash(nonce)).is_err(),
            "a duplicate-id request must never yield a verifiable signed response"
        );
        assert!(
            out_value(&out).get("error").is_some(),
            "a duplicate-id request must fail closed with a JSON-RPC error"
        );
    }

    // ---- Issue #135: an LB assertion without a transport binding fails closed ----

    /// Mint a wire-form Tier-3 LB ingress assertion bound to `request_hash`,
    /// signed by `lb` under `key_id` at `validation_time` — the same five
    /// `.`-separated base64url fields the transport-module verifier accepts.
    fn mint_lb_assertion(
        lb: &SigningKey,
        key_id: &str,
        identity: &str,
        request_hash: &str,
        validation_time: i64,
    ) -> String {
        let assertion = crate::transport::LbAssertion {
            key_id: key_id.to_string(),
            asserted_client_identity: identity.to_string(),
            request_hash: request_hash.to_string(),
            validation_time,
        };
        let signature = lb.sign(&assertion.signing_preimage());
        format!(
            "{}.{}.{}.{}.{}",
            mcps_core::b64url_encode(key_id.as_bytes()),
            mcps_core::b64url_encode(identity.as_bytes()),
            mcps_core::b64url_encode(request_hash.as_bytes()),
            mcps_core::b64url_encode(&validation_time.to_be_bytes()),
            signature,
        )
    }

    /// A `Proxy` configured with an LB-assertion verifier but NO transport-binding
    /// policy must fail closed: the assertion exists ONLY to supply the verified
    /// identity that the binding then ties to the request signer, so without a
    /// binding the signer↔identity binding would be silently dropped. A VALID,
    /// request-bound, in-window assertion (one that would otherwise verify) must
    /// therefore still be rejected and never reach the inner server — proving the
    /// guard, not merely some other rejection. (Production wiring always pairs the
    /// two; this pins the builder-composition footgun closed for any embedder/test
    /// that wires only the LB assertion.)
    #[test]
    fn lb_assertion_without_transport_binding_fails_closed() {
        use crate::transport::IdentitySource;
        use crate::transport::LbAssertionBinding;

        let nonce = "nonce-lb-no-binding-1";
        let lb_seed = [42u8; 32];
        let lb = SigningKey::from_seed_bytes(&lb_seed);

        // A verifier that DOES trust the LB key, so the assertion below would
        // pass every cryptographic check — only the missing binding fails it.
        let mut lb_binding = LbAssertionBinding::new(IdentitySource::UriSan);
        lb_binding.add_key("lb-1", lb.public_key());

        // The inner must NOT be reached; flag it if it ever is.
        let reached = Arc::new(Mutex::new(false));
        let reached_inner = Arc::clone(&reached);
        let inner = move |_request: &[u8]| -> Vec<u8> {
            *reached_inner.lock().expect("lock") = true;
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "result": {} }))
                .expect("serialize inner result")
        };
        // Built WITH the LB assertion but WITHOUT a transport binding.
        let proxy = Proxy::new(
            server_key(),
            SERVER,
            SERVER_KEY_ID,
            Box::new(inbound_resolver()),
            AUDIENCE,
            SKEW,
            Box::new(inner),
        )
        .with_lb_assertion(lb_binding);

        // A genuinely valid assertion bound to THIS request's hash, in-window.
        let request_hash = expected_request_hash(nonce);
        let assertion = mint_lb_assertion(
            &lb,
            "lb-1",
            "spiffe://example.org/agent-1",
            &request_hash,
            now(),
        );

        // Prove the minted assertion is itself cryptographically VALID: a
        // standalone binding over the same trusted key accepts it (signature, key,
        // request-hash binding, and freshness all pass). The builder-composition
        // guard in handle_with_transport fails closed BEFORE lb.verify runs, so
        // without this check the test would also pass for a malformed assertion.
        // This pins that the rejection below is caused SOLELY by the missing
        // transport binding, not by an invalid header.
        let mut lb_verifier = LbAssertionBinding::new(IdentitySource::UriSan);
        lb_verifier.add_key("lb-1", lb.public_key());
        assert!(
            lb_verifier.verify(&assertion, &request_hash, now()).is_ok(),
            "the minted LB assertion must be cryptographically valid on its own"
        );

        let out = proxy.handle_with_transport(
            &signed_request(nonce),
            now(),
            None,
            Some(&assertion),
        );

        // Fail closed: the inner server is never reached...
        assert!(
            !*reached.lock().expect("lock"),
            "a valid LB assertion with no transport binding must not reach the inner server"
        );
        // ...the client gets an unsigned JSON-RPC error, NOT a signed response...
        assert!(
            verify_response(&out, &server_resolver(), &request_hash).is_err(),
            "an unbound LB assertion must never yield a verifiable signed response"
        );
        let value = out_value(&out);
        assert!(
            value.get("error").is_some(),
            "an unbound LB assertion must fail closed with a JSON-RPC error"
        );
        // ...and the failure is the transport-boundary token, not some unrelated one.
        assert_eq!(
            value["error"]["data"]["mcps_error"],
            json!(mcps_core::McpsError::TransportBindingFailed.wire_code()),
            "the rejection must be mcps.transport_binding_failed"
        );
    }

    #[test]
    fn scrub_removes_only_proxy_owned_keys_through_objects_and_arrays() {
        // Proxy-owned keys planted in _meta at top level, in a nested object, and
        // inside an array element; plus unrelated _meta keys at each location.
        let mut value = json!({
            "_meta": {
                REQUEST_META_KEY: { "x": 1 },
                "io.example/top": "keep"
            },
            "nested": {
                "_meta": {
                    VERIFIED_META_KEY: { "x": 2 },
                    "io.example/nested": "keep"
                }
            },
            "items": [
                { "_meta": { RESPONSE_META_KEY: { "x": 3 }, AUTHORIZATION_META_KEY: { "x": 4 }, "io.example/arr": "keep" } }
            ]
        });
        scrub_proxy_owned_meta(&mut value);

        // Every proxy-owned key removed at every depth (object + array).
        assert!(value["_meta"].get(REQUEST_META_KEY).is_none());
        assert!(value["nested"]["_meta"].get(VERIFIED_META_KEY).is_none());
        assert!(value["items"][0]["_meta"].get(RESPONSE_META_KEY).is_none());
        assert!(value["items"][0]["_meta"]
            .get(AUTHORIZATION_META_KEY)
            .is_none());
        // Every unrelated _meta key preserved at every depth.
        assert_eq!(value["_meta"]["io.example/top"], json!("keep"));
        assert_eq!(value["nested"]["_meta"]["io.example/nested"], json!("keep"));
        assert_eq!(value["items"][0]["_meta"]["io.example/arr"], json!("keep"));
    }
}
