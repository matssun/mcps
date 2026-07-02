//! The local client-side MCP-S proxy pipeline (MCPS-49, #196; ADR-MCPS-044
//! §Proxy transparency / §Security adapter scope).
//!
//! The local client speaks PLAIN MCP to this proxy; the proxy signs the outbound
//! request via `mcps-client-core`, forwards it to the remote MCP-S endpoint,
//! verifies the signed response, applies the enforcement decision, and returns
//! PLAIN MCP back. The local client never emits, parses, or negotiates any MCP-S
//! field — only the route name + surfaced security errors leak.
//!
//! Adapter scope: route resolution is STATIC (by configured route id), and the
//! proxy performs NO tool choice, planning, or intent routing — it is a security
//! adapter, not an orchestrator.

use mcps_client_core::audit_for_decision;
use mcps_client_core::build_signed_request_with_signer;
use mcps_client_core::classify_response_result;
use mcps_client_core::decide;
use mcps_client_core::resolve_authorization_binding;
use mcps_client_core::verify_and_classify_response;
use mcps_client_core::AbsenceReason;
use mcps_client_core::BindingRequestContext;
use mcps_client_core::ClientAuditEvent;
use mcps_client_core::ClientPath;
use mcps_client_core::ClientSigner;
use mcps_client_core::CorrelationStore;
use mcps_client_core::EnforcementDecision;
use mcps_client_core::EvidenceOutcome;
use mcps_client_core::PendingRequest;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::ResponseExpectation;
use mcps_client_core::SignerPolicy;
use mcps_core::unwrap_verified_result;
use mcps_core::Continuation;
use mcps_core::McpsError;
use mcps_core::ResultClass;
use mcps_core::TrustResolver;
use mcps_core::CANONICALIZATION_ID_INT53_V1;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;
use std::collections::HashMap;

use crate::route::RouteRegistry;
use crate::transport::ProxyError;
use crate::transport::RemoteTransport;

/// Per-call parameters the mode-specific layer supplies (freshness + identity).
/// Kept explicit so the pipeline stays deterministic and testable; the binary
/// fills these from its nonce source and clock.
#[derive(Debug, Clone)]
pub struct CallParams {
    /// The asserted principal (`on_behalf_of`).
    pub on_behalf_of: String,
    /// A fresh anti-replay nonce.
    pub nonce: String,
    /// Issue time (RFC 3339 UTC).
    pub issued_at: String,
    /// Expiry time (RFC 3339 UTC).
    pub expires_at: String,
    /// Current time (unix seconds) for correlation registration/cleanup.
    pub now_unix: i64,
    /// Deadline (unix seconds) for the correlation entry.
    pub deadline_unix: i64,
}

/// The proxy's response to the local client: plain MCP plus the audit record and
/// which path produced it (verified vs explicit legacy).
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The plain MCP JSON-RPC response to return to the local client.
    pub plain_response: Value,
    /// The audit event for this exchange (verified vs legacy_explicit + reason).
    pub audit: ClientAuditEvent,
    /// Which path produced the response.
    pub path: ClientPath,
}

/// The local client-side MCP-S proxy. Holds the static route registry, the client
/// signing identity + custody policy, the trust resolver for response verification,
/// the in-flight correlation store, and the remote transport.
pub struct ClientProxy {
    registry: RouteRegistry,
    signer: Box<dyn ClientSigner>,
    signer_policy: SignerPolicy,
    trust_resolver: Box<dyn TrustResolver>,
    transport: Box<dyn RemoteTransport>,
    correlation: CorrelationStore,
    /// Pending multi-round-trip continuations (ADR-MCPS-047): server `requestState`
    /// -> the signed [`Continuation`] binding to attach when the local client
    /// re-issues the call with its `inputResponses`. Keyed by `requestState` because
    /// the continuation call carries a FRESH JSON-RPC id, and the echoed opaque
    /// `requestState` is the only stable handle linking the two legs.
    continuations: HashMap<String, Continuation>,
}

impl ClientProxy {
    /// Construct a proxy from its wired pieces.
    pub fn new(
        registry: RouteRegistry,
        signer: Box<dyn ClientSigner>,
        signer_policy: SignerPolicy,
        trust_resolver: Box<dyn TrustResolver>,
        transport: Box<dyn RemoteTransport>,
    ) -> Self {
        ClientProxy {
            registry,
            signer,
            signer_policy,
            trust_resolver,
            transport,
            correlation: CorrelationStore::new(),
            continuations: HashMap::new(),
        }
    }

    /// Handle one plain-MCP request on `route_id`: sign → forward → verify → return
    /// plain MCP. Fails closed on any bad-evidence verdict; falls back to legacy ONLY
    /// when policy permits and the remote returned a plain/unsigned response.
    pub fn handle(
        &mut self,
        route_id: &str,
        plain_request: &Value,
        params: &CallParams,
    ) -> Result<ProxyResponse, ProxyError> {
        let route = self
            .registry
            .get(route_id)
            .ok_or_else(|| ProxyError::UnknownRoute(route_id.to_string()))?;

        // Parse the ordinary MCP request (transparency: it carries no MCP-S fields).
        let id = plain_request.get("id").cloned().unwrap_or(Value::Null);
        let method = plain_request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProxyError::MalformedRequest)?
            .to_string();
        let req_params: Map<String, Value> = plain_request
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let tool_id = req_params.get("name").and_then(Value::as_str);

        // Resolve the authorization binding for this request (bind-not-interpret).
        let audience = route.signer_audience.audience_string();
        let ctx = BindingRequestContext {
            audience: &audience,
            route_id,
            method: Some(&method),
            tool_id,
            deadline_unix: params.deadline_unix,
        };
        let binding = resolve_authorization_binding(
            route.authz_provider.as_ref(),
            &route.authz_policy,
            &ctx,
        )?;

        // Continuation answer leg (ADR-MCPS-047 / D3+D4): an answer carries BOTH
        // `inputResponses` and the echoed `requestState` (SEP-2322) — the same gate the
        // SDK drivers apply. Only then do we bind the stored continuation we retained
        // from the prior InputRequiredResult. `remove` consumes it — a continuation is
        // single-use; a replayed answer finds nothing and is signed as an ordinary
        // (unbound) request, which the server rejects on its own requestState rules.
        // Gating on `inputResponses` too avoids burning the single-use state on a
        // malformed/partial follow-up that echoes `requestState` without answering.
        let continuation = match (req_params.get("inputResponses"), req_params.get("requestState")) {
            (Some(_), Some(state)) => state.as_str().and_then(|s| self.continuations.remove(s)),
            _ => None,
        };

        // Build + sign the draft-02 request through the custody seam.
        let mut inputs = RequestSigningInputs::with_default_canonicalization(
            self.signer.signer_id(),
            self.signer.key_id(),
            &params.on_behalf_of,
            &audience,
            binding.clone(),
            &params.nonce,
            &params.issued_at,
            &params.expires_at,
        );
        if let Some(continuation) = continuation {
            inputs = inputs.with_continuation(continuation);
        }
        let signed = build_signed_request_with_signer(
            &id,
            &method,
            req_params,
            &inputs,
            self.signer.as_ref(),
            &self.signer_policy,
        )?;

        // Register the outstanding request (in-flight correlation, MCPS-47).
        let correlation_id = id.to_string();
        let authz_digest = binding_digest(&binding);
        self.correlation.register(
            PendingRequest {
                correlation_id: correlation_id.clone(),
                request_hash: signed.request_hash().to_string(),
                nonce: params.nonce.clone(),
                issued_at_unix: params.now_unix,
                deadline_unix: params.deadline_unix,
                route_id: route_id.to_string(),
                audience: audience.clone(),
                expected_server_signers: vec![route.signer_audience.expected_server_signer.clone()],
                version: mcps_core::VERSION_DRAFT_02.to_string(),
                canonicalization_id: CANONICALIZATION_ID_INT53_V1.to_string(),
                authz_digest,
            },
            params.now_unix,
        )?;

        // Forward to the remote MCP-S endpoint.
        let response_bytes = match self.transport.round_trip(signed.wire_bytes()) {
            Ok(bytes) => bytes,
            Err(transport_err) => {
                // Transport failure before any evidence: classify as absence and let
                // the enforcement engine decide. A proxy cannot synthesize a response,
                // so even a fallback-eligible verdict surfaces as a transport error.
                self.correlation.cancel(&correlation_id);
                let outcome = EvidenceOutcome::Absent(AbsenceReason::TransportFailurePreEvidence);
                return match decide(route.enforcement_mode, route.legacy_allowed, &outcome) {
                    EnforcementDecision::FailClosed(err) => Err(ProxyError::FailedClosed(err)),
                    _ => Err(ProxyError::Transport(transport_err)),
                };
            }
        };

        // Verify the signed response AND classify it for the multi-round-trip flow
        // (ADR-MCPS-047 / D2). Classification reads only the SIGNED result body.
        let expectation =
            ResponseExpectation::new(signed.request_hash(), CANONICALIZATION_ID_INT53_V1)
                .with_expected_server_signer(&route.signer_audience.expected_server_signer);
        let classified = verify_and_classify_response(
            &response_bytes,
            self.trust_resolver.as_ref(),
            &expectation,
        );

        // A verified, NON-TERMINAL InputRequiredResult (D2/D7): retain the exchange
        // (associate-without-consume) instead of completing it, stash the continuation
        // binding keyed by the server's `requestState`, and return the elicitation as
        // PLAIN MCP so the unmodified client can answer. The answer leg (above) attaches
        // the stored continuation, transparently completing the round trip.
        if let Ok(c) = &classified {
            if c.class == ResultClass::InputRequired {
                let outcome = classify_response_result(Ok(c.verified.clone()));
                let decision = decide(route.enforcement_mode, route.legacy_allowed, &outcome);
                let audit = audit_for_decision(&decision);
                let continuation = self.correlation.record_input_required(
                    &correlation_id,
                    &c.response_hash,
                    params.now_unix,
                )?;
                let plain = plain_response_from_verified(&id, &response_bytes)?;
                if let Some(state) = plain
                    .get("result")
                    .and_then(|r| r.get("requestState"))
                    .and_then(Value::as_str)
                {
                    self.continuations.insert(state.to_string(), continuation);
                }
                return Ok(ProxyResponse {
                    plain_response: plain,
                    audit,
                    path: ClientPath::McpsVerified,
                });
            }
        }

        let outcome = classify_response_result(classified.map(|c| c.verified));

        // Correlate (cleanup-on-completion). A late/uncorrelatable response fails closed.
        self.correlation
            .take_for_response(&correlation_id, params.now_unix)?;

        let decision = decide(route.enforcement_mode, route.legacy_allowed, &outcome);
        let audit = audit_for_decision(&decision);
        match decision {
            EnforcementDecision::AcceptMcps => {
                let plain = plain_response_from_verified(&id, &response_bytes)?;
                Ok(ProxyResponse {
                    plain_response: plain,
                    audit,
                    path: ClientPath::McpsVerified,
                })
            }
            EnforcementDecision::FallBackToLegacy { .. } => {
                // The remote returned plain/unsigned MCP; under an explicit legacy
                // route we pass it through, audited as the legacy/no-evidence path.
                let plain: Value = serde_json::from_slice(&response_bytes)
                    .map_err(|_| ProxyError::MalformedRequest)?;
                Ok(ProxyResponse {
                    plain_response: plain,
                    audit,
                    path: ClientPath::LegacyExplicit,
                })
            }
            EnforcementDecision::FailClosed(err) => Err(ProxyError::FailedClosed(err)),
        }
    }
}

/// Extract the authorization digest value from a binding (for correlation state).
fn binding_digest(binding: &mcps_core::AuthorizationBinding) -> String {
    match binding {
        mcps_core::AuthorizationBinding::OpaqueBytes { digest_value, .. } => digest_value.clone(),
        mcps_core::AuthorizationBinding::AuthzSystemReference { digest_value, .. } => {
            digest_value.clone()
        }
    }
}

/// Rebuild a PLAIN MCP response from a verified signed response: strip the MCP-S
/// response envelope from `result` (and any wrapper), returning ordinary JSON-RPC.
fn plain_response_from_verified(id: &Value, response_bytes: &[u8]) -> Result<Value, ProxyError> {
    let object: Value =
        serde_json::from_slice(response_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;
    let result = object
        .get("result")
        .ok_or(McpsError::CanonicalizationFailed)?;
    let unwrapped = unwrap_verified_result(result)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "result": unwrapped.into_value(),
    }))
}
