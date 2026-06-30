"""MCP-S transport adapter — the heart of the SDK.

It implements the MCP Python SDK's public ``Transport`` protocol
(``mcp/client/_transport.py``) so it OWNS the socket/pipe I/O and the JSON-RPC
(de)serialization. That is the only seam with exact-byte control: the anyio
stream between ``ClientSession`` and the transport carries already-parsed
pydantic ``SessionMessage`` objects, not bytes (spike #199).

The pipeline mirrors ``mcps-client-proxy/src/proxy.rs::ClientProxy::handle``
one-to-one. For every outbound MCP request:

    1. resolve_authorization_binding(provider, policy, ctx)     # bind-not-interpret
    2. RequestSigningInputs::with_default_canonicalization(...)
       build_signed_request_with_signer(id, method, params, .)  -> SignedRequest
          .wire_bytes()    = canonical signed preimage put on the wire
          .request_hash()  = binds the eventual response
    3. correlation.register(PendingRequest{...})                # in-flight tracking
    4. round_trip(signed.wire_bytes()) -> response_bytes        # the I/O WE own
    5. ResponseExpectation::new(request_hash, canonicalization_id)
          .with_expected_server_signer(...)
       verify_signed_response(response_bytes, trust_resolver, expectation)
    6. classify_response_result(...) -> outcome
    7. correlation.take_for_response(...)                       # late -> fail closed
    8. decide(enforcement_mode, legacy_allowed, outcome) -> decision
       audit_for_decision(decision)
    9. on AcceptMcps -> hand the plain (verified) response up to ClientSession

Steps 1, 2, 5, 6, 8 are calls into ``mcps_sdk._core`` (audited Rust). Steps 3, 4,
7, 9 are the adapter's job: own the transport, wire the correlation store, and
keep the plain<->signed boundary so ClientSession only ever sees plain MCP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class McpsPolicy:
    """Per-route MCP-S policy (mirror of the proxy's route config).

    TODO(#199): fields for enforcement mode (require_mcps / opportunistic),
    audience, accepted versions/canonicalization ids, expected server signers,
    legacy-allowed flag — passed through to the core's ``decide`` / expectation.
    """

    audience: str
    enforcement: str = "require_mcps"
    legacy_allowed: bool = False
    expected_server_signers: tuple[str, ...] = ()


class McpsTransport:
    """Implements the upstream ``Transport`` protocol; signs/verifies at the byte
    boundary and exposes plain MCP read/write streams to ``ClientSession``.

    SCAFFOLD: the structure and the pipeline contract are fixed; the bodies are
    filled in once the core bindings (``mcps_sdk._core``) and the upstream
    ``Transport`` seam are pinned. The upstream seam is mid-refactor (spike:
    "transport-as-dispatcher rework"), so the exact stream signature is left
    abstract here on purpose.
    """

    def __init__(
        self,
        inner_transport,  # the plain transport we wrap (stdio / streamable-http)
        policy: McpsPolicy,
        signer,           # mcps_sdk._core signer handle (concrete Rust impl)
        trust_resolver,   # mcps_sdk._core trust-resolver handle
        binding_provider=None,
    ) -> None:
        self._inner = inner_transport
        self._policy = policy
        self._signer = signer
        self._trust_resolver = trust_resolver
        self._binding_provider = binding_provider
        # TODO(#199): construct the core CorrelationStore handle here.

    async def __aenter__(self):
        # TODO(#199): open `self._inner`, then return a (read_stream, write_stream)
        # pair of MEMORY streams that ClientSession talks plain MCP over, while two
        # pump tasks run the sign-on-write / verify-on-read pipeline above against
        # the real bytes of `self._inner`.
        raise NotImplementedError("McpsTransport: scaffold (#199)")

    async def __aexit__(self, *exc) -> None:
        raise NotImplementedError("McpsTransport: scaffold (#199)")

    # --- the two pumps that own the byte boundary ---------------------------

    async def _sign_and_send(self, plain_session_message) -> None:
        """Steps 1-4: turn a plain outbound JSON-RPC message into the signed
        preimage and write it to the real transport."""
        raise NotImplementedError("McpsTransport._sign_and_send: scaffold (#199)")

    async def _recv_and_verify(self, raw_bytes: bytes) -> Optional[object]:
        """Steps 5-9: verify raw inbound bytes, apply the enforcement decision,
        and (on accept) return the plain message to hand up to ClientSession.

        Open gaps from the spike, to resolve here:
          - streamable-HTTP has THREE inbound decode sites (direct JSON, POST-SSE,
            standalone-GET SSE) that must all route through verification;
          - server-initiated messages (sampling/roots/notifications) are NOT
            responses to a correlated request, so the request_hash binding in
            `ResponseExpectation` does not cover them — needs an inbound policy.
        """
        raise NotImplementedError("McpsTransport._recv_and_verify: scaffold (#199)")
