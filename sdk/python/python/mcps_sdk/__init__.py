"""MCP-S Python SDK — runtime-evidence security for the MCP Python SDK.

Architecture (issue #199, ADR-MCPS-044 §SDK wrap-or-fork rule; Python first)::

    application code
      -> mcp.ClientSession           (plain MCP; unaware of MCP-S)
      -> McpsTransport  (THIS SDK)   (signs outbound bytes, verifies inbound bytes)
      -> mcps_sdk._core (PyO3)       (the AUDITED mcps-client-core logic, in Rust)
      -> remote MCP-S server / proxy

The spike verdict was **transport adapter**, not a transparent wrapper: the MCP
Python SDK serializes JSON-RPC *inside* each transport, so the only place with
exact-byte control is the transport itself. We therefore ship our own
implementation of the SDK's public ``Transport`` protocol and delegate every
security decision to the Rust core — one implementation of the signed preimage,
shared with ``mcps-client-proxy``. See ``README.md``.
"""

from . import _core  # native extension, built by maturin (mcps_sdk._core)

__version__ = "0.1.0"
__all__ = [
    "core_version",
    "canonicalization_id",
    "sign_request",
    "sign_request_with_signer",
    "verify_response",
    "SignedRequest",
    "Signer",
    "SignerPolicy",
    "TrustResolver",
    "VerifyResult",
    "CorrelationStore",
    "PendingRequest",
    "McpsConfig",
    "McpsTransport",
    "McpsVerificationError",
    "connect",
    "connect_stdio",
]

#: MCP-S protocol version the bound core verifies/signs against (e.g. "draft-02").
core_version = _core.core_version
#: Canonicalization id of the signed preimage the SDK reproduces exactly.
canonicalization_id = _core.canonicalization_id
#: Sign an MCP request via a raw seed key (dev/test; no custody gate).
sign_request = _core.sign_request
#: Sign through a Signer gated by a SignerPolicy (production custody path).
sign_request_with_signer = _core.sign_request_with_signer
#: A signed draft-02 request: ``.wire_bytes`` (bytes) + ``.request_hash`` (str).
SignedRequest = _core.SignedRequest
#: A client signing identity: ``Signer.software(...)`` / ``Signer.dev_file(...)``.
Signer = _core.Signer
#: The signer-custody policy gating which signers may sign under a route/mode.
SignerPolicy = _core.SignerPolicy
#: Verify a signed response + apply the enforcement decision (return-leg chain).
verify_response = _core.verify_response
#: Trust anchors for response verification: ``.insert_public_key`` / ``.insert_dev_seed``.
TrustResolver = _core.TrustResolver
#: Structured verification outcome: ``.decision`` / ``.path`` / ``.reason`` / ``.server_signer``.
VerifyResult = _core.VerifyResult
#: In-flight correlation: binds a signed request to one acceptable returning response.
CorrelationStore = _core.CorrelationStore
#: One outstanding request's retained state (returned by ``take_for_response``).
PendingRequest = _core.PendingRequest

# The adapter: imports `mcp` lazily (inside functions), so this is import-safe even
# where `mcp` is not installed.
from .transport import McpsConfig, McpsTransport, McpsVerificationError  # noqa: E402
from .client import connect, connect_stdio  # noqa: E402

#: Response-envelope key the adapter strips before handing a plain response to the app.
response_meta_key = _core.response_meta_key
