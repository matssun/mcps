<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-023: Ingress and Reverse-Proxy mTLS — End-to-End Binding vs. Trusted-Ingress Re-Assertion

## Status

Proposed (v0.3 sketch — under review)

## Context

ADR-MCPS-014 binds the verified request to the mTLS client-cert identity via the
opt-in, pluggable `TransportBindingPolicy` (`Box<dyn TransportBindingPolicy>`),
applied after verification, failing with `mcps.transport_binding_failed`. Client
certs are verified against client-CA anchors with short-lived-cert enforcement +
OCSP, no implicit fallback. The binding ties the application-layer signature to
the transport-layer client identity.

A TLS-terminating reverse proxy (Envoy, NGINX, HAProxy, a cloud LB, a service
mesh) breaks that binding: the proxy node's mTLS peer becomes the load balancer,
not the client. ADR-MCPS-017 deferred "reverse-proxy mTLS." This ADR decides the
ingress model. The pluggable `TransportBindingPolicy` is the seam.

## Definitions

- **`authenticated LB↔node channel`** — mTLS, or an equivalent mutually
  authenticated private channel, in which the **node authenticates the ingress
  identity against a configured trusted-ingress allowlist**. Network location, a
  private IP range, a Kubernetes namespace, or the mere presence of a header is
  **not** sufficient.
- **`transport_binding_mode`** — the declared ingress posture: `end_to_end_mtls`
  or `trusted_ingress_asserted`. The bare label `mtls` is forbidden.

## Decision

Support two ingress modes; **Tier 2 is supported but explicitly downgraded** and
MUST NOT be presented as equivalent to end-to-end mTLS.

| Tier | Ingress | Channel binding | LB in identity path? |
|---|---|---|---|
| **1 — `end_to_end_mtls`** *(default, strongest)* | L4 / TLS pass-through; client↔node mTLS end-to-end | Cryptographically bound to the client↔node TLS session | **No** |
| **2 — `trusted_ingress_asserted`** *(optional, weakened)* | L7 ingress terminates client mTLS, re-asserts verified client identity to the node over an authenticated LB↔node channel | Bound to the **LB↔node** hop; client identity is *asserted by trusted ingress*, not end-to-end | **Yes — ingress is in the TCB** |

### Tier 2 is explicit opt-in

Tier 2 MUST be explicitly configured (`transport_binding_mode =
trusted_ingress_asserted`, `trusted_ingress_identity = …`, `asserted_identity_header
= …`). **The presence of asserted-identity headers MUST NOT cause the proxy to
enter Tier 2.** A proxy running in `end_to_end_mtls` mode MUST ignore or reject
Tier-2 asserted-identity metadata even if such headers are present.

### Node-side trusted-ingress authentication is the security gate

The node MUST treat **all** asserted-identity metadata as attacker-controlled
unless the immediate peer is authenticated as a configured trusted ingress over
an authenticated LB↔node channel. Public-side header stripping is required, but
**node-side trusted-ingress authentication is the gate** — the node stays robust
even if a misconfigured ingress fails to strip a spoofed header. If the peer is
not a configured trusted ingress, asserted-identity metadata MUST be ignored or
rejected.

### Asserted-identity header rules

Tier-2 asserted-identity metadata MUST be:

- **single-valued** — duplicate or conflicting asserted-identity headers MUST
  fail closed;
- **well-formed** — malformed metadata MUST fail closed;
- **length-bounded** — oversized values MUST fail closed;
- carried under **explicitly configured** header names;
- treated as **opaque** identity strings unless the configured identity policy
  defines a parser.

This defeats ambiguous inputs (`X-MCPS-Verified-Client-Identity: attacker` +
`: real-client`, or comma-merged variants parsed differently across HTTP stacks).

### Minimum Tier-2 assertion metadata

Required: `asserted_client_identity`, `identity_source`, `ingress_identity`,
`validation_time`, and `client_cert_fingerprint` (if client-cert based).
Optional: `client_cert_issuer`, `client_cert_not_before`, `client_cert_not_after`,
`client_cert_trust_anchor`. The node need not re-validate the client certificate
in Tier 2, but MUST log enough to prove *what* the ingress asserted and *when*.

### Mode naming and audit taxonomy

`transport_binding_mode` MUST be `end_to_end_mtls` or `trusted_ingress_asserted`
— never bare `mtls`, which hides the distinction. Audit events MUST include, at
minimum: `transport_binding_mode`, `node_peer_identity`, `trusted_ingress_identity`
(Tier 2), `asserted_client_identity` (Tier 2), `client_cert_fingerprint` (if
present), `binding_policy_result`, and a `reason_code` on failure. Because Tier 2
carries a downgraded claim, reviewers and incident responders MUST be able to see
which mode was used per request.

### Certificate revocation/lifetime enforcement shift

In Tier 2 the ingress enforces client-cert validation, identity extraction, max
lifetime, and any CRL/OCSP posture. The node enforces the LB↔node channel
identity, that the ingress is trusted, that asserted-identity metadata is present
and well-formed, and the transport-binding policy against the asserted identity.
Audit MUST record the certificate enforcement point as the ingress in Tier 2.
This shift MUST be stated in `security-boundary.md`.

### Not in v0.3 — future Tier 3 boundary

An LB-signed, request-bound assertion (the LB signing a statement tying client
identity to the specific request hash) is tracked as a future **Tier 3**. Tier 3
is required if a deployment wants the node to **cryptographically verify that the
ingress assertion was bound to a specific MCP-S request**, rather than relying
only on the authenticated LB↔node channel. v0.3 accepts authenticated LB↔node
mTLS plus strict header handling inside one trust domain.

## Threat Model

- **Trust boundary:** one operator; in Tier 2 the ingress is part of the TCB.
- **Primary threat (Tier 2):** an attacker forges client identity by supplying a
  `X-MCPS-Verified-*` header directly, hoping the node trusts it. Defeated by the
  explicit-opt-in, node-side-trusted-ingress-auth, and header rules above.
- **Private network location is not authentication:** a request arriving from an
  internal IP, service-network address, or Kubernetes namespace is **not**
  sufficient to enter Tier 2 unless the LB↔node channel authenticates the ingress
  identity.
- **Residual (Tier 2):** a compromised trusted ingress can assert arbitrary
  client identities — accepted as a consequence of placing ingress in the TCB;
  the claim is downgraded accordingly and never described as end-to-end binding.
- **Tier 1:** no LB in the identity path; the ADR-014 binding is intact.

## Conformance Vectors (ADR-MCPS-011)

- Trusted ingress over an authenticated LB↔node channel → accepted.
- Untrusted ingress identity → rejected.
- Missing LB↔node authentication → fail closed.
- **Header-presence-not-enough:** Tier 2 is not activated by header presence
  alone; in `end_to_end_mtls` mode asserted headers are ignored/rejected.
- **Spoof test (non-negotiable):** a client sends `X-MCPS-Verified-Client-Identity`
  directly, without trusted-ingress authentication → rejected/ignored.
- **Duplicate headers** fail closed; **malformed or oversized** metadata fails
  closed.
- **Internal network source** without an authenticated trusted-ingress identity
  → fails closed.
- Public caller-supplied identity header → stripped before the node.
- Wrong asserted identity → transport-binding failure.
- **Cert-enforcement shift:** Tier 2 accepts only when trusted ingress asserts;
  records that client-cert validation was performed by the ingress; rejects if
  required validation metadata fields are absent; audit states cert enforcement
  point = ingress.
- Tier-2 audit includes `transport_binding_mode`, `trusted_ingress_identity`,
  `asserted_client_identity`, and the binding result; distinguishable from Tier 1.
- Tier 2 does **not** bypass MCP-S object signature verification.
- Tier 2 does **not** bypass Phase 5 (ADR-MCPS-013) authorization.

## Rationale

TLS termination at an L7 ingress is common in real deployments; deferring it
entirely would make the multi-node story much less useful. But it genuinely
weakens the transport guarantee, so it must be supported *and* honestly
downgraded — in docs, config names, audit logs, and policy outputs — never
marketed as equal to end-to-end mTLS. The one-trust-domain claim is what makes
placing the ingress in the TCB acceptable at all; making Tier 2 impossible to
enable accidentally or to spoof with headers is what keeps it safe.

## Alternatives Considered

- **Defer Tier 2 entirely** — rejected: too common a deployment shape to omit.
- **Require an LB-signed request-bound assertion in v0.3** — rejected as scope:
  assertion format, LB signing key, expiry, request-hash binding, assertion
  replay handling, rotation, and audit semantics are a separate profile (future
  Tier 3).
- **Allow a plain trusted header / trust by network location** — rejected: the
  classic `X-Client-Cert` spoofing bug; forbidden normatively.

## Consequences

### Positive
- Real-world L7-termination deployments are supported, with an honest, visible
  downgrade, a mandatory anti-spoof posture, and explicit opt-in.

### Negative
- Two transport postures to document, name, and test distinctly; Tier 2 puts the
  ingress in the TCB.

### Neutral
- The pluggable `TransportBindingPolicy` already provides the seam; Tier 2 is a
  new policy, not a core change.

## Compliance and Enforcement

`security-boundary.md`: *"The strongest transport-binding claim requires
end-to-end client↔node mTLS using L4/TLS pass-through ingress. MCP-S also
supports a trusted-ingress mode in which an ingress terminates client mTLS and
re-asserts the verified client identity to the node over an authenticated LB↔node
channel; in this mode the ingress is part of the trusted computing base and the
node relies on the ingress's assertion. This is not cryptographic end-to-end
client↔node channel binding. Tier 2 is explicit opt-in; unauthenticated
client-identity headers and trust-by-network-location are forbidden."*

## Related

- ADR-MCPS-014 (Phase 6 transport hardening, `TransportBindingPolicy`)
- ADR-MCPS-013 (Phase 5 authorization — not bypassed by Tier 2)
- ADR-MCPS-017 (deferred reverse-proxy mTLS)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- The exact authenticated LB↔node assertion envelope (namespaced headers over
  LB↔node mTLS vs. a structured metadata block).
- Whether the migration to Tier 2 needs its own strict-mode guard so it cannot be
  enabled silently in a hardened deployment.
- Future Tier 3 (LB-signed request-bound assertion) — its own ADR when scoped.
