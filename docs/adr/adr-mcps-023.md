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

## Decision

Support two ingress modes; **Tier 2 is supported but explicitly downgraded** and
MUST NOT be presented as equivalent to end-to-end mTLS.

| Tier | Ingress | Channel binding | LB in identity path? |
|---|---|---|---|
| **1 — `end_to_end_mtls`** *(default, strongest)* | L4 / TLS pass-through; client↔node mTLS end-to-end | Cryptographically bound to the client↔node TLS session | **No** |
| **2 — `trusted_ingress_asserted`** *(optional, weakened)* | L7 ingress terminates client mTLS, re-asserts verified client identity to the node over an authenticated LB↔node channel | Bound to the **LB↔node** hop; client identity is *asserted by trusted ingress*, not end-to-end | **Yes — ingress is in the TCB** |

**Normative rules (the safety core):**

- The proxy **MUST NOT** trust client identity from an **unauthenticated**
  request header.
- If ingress terminates client TLS, the asserted client identity **MUST** arrive
  over an authenticated LB↔node channel (LB↔node mTLS) from a **configured
  trusted-ingress identity**.
- Any caller-supplied identity header on the public/client side **MUST** be
  stripped or ignored before reaching the node.
- If the trusted-ingress identity cannot be authenticated, the request **MUST**
  fail closed.

**Mode naming MUST be explicit** — `transport_binding_mode = end_to_end_mtls`
vs. `trusted_ingress_asserted`. The bare label `mtls` is forbidden because it
hides the distinction. Audit logs MUST record the mode, the
`trusted_ingress_identity`, and the `asserted_client_identity` so consumers can
distinguish Tier 1 from Tier 2.

**Tier-2 asserted-identity metadata**, when carried as headers, MUST be
explicitly namespaced, e.g. `X-MCPS-Verified-Client-Identity`,
`X-MCPS-Verified-Client-Cert-Fingerprint`, `X-MCPS-Verified-Client-Identity-Source`
— trusted only when the source peer equals the configured trusted ingress, the
LB↔node channel is authenticated, and public-side headers were stripped.

**Certificate revocation/lifetime enforcement shifts in Tier 2:** the ingress
enforces client-cert validation, identity extraction, max lifetime, and any
CRL/OCSP posture. The node enforces the LB↔node channel identity, that the
ingress is trusted, that asserted-identity metadata is present and well-formed,
and the transport-binding policy against the asserted identity. This shift MUST
be stated in `security-boundary.md`.

**Not in v0.3:** an LB-signed, request-bound assertion (the LB signing a
statement tying client identity to the specific request hash) is stronger and is
tracked as a future **Tier 3**; v0.3 accepts authenticated LB↔node mTLS plus
strict header stripping inside one trust domain.

## Threat Model

- **Trust boundary:** one operator; in Tier 2 the ingress is part of the TCB.
- **Primary threat (Tier 2):** an attacker forges client identity by supplying a
  `X-MCPS-Verified-*` header directly, hoping the node trusts it. Defeated by the
  normative header-stripping + authenticated-ingress rules.
- **Residual (Tier 2):** a compromised ingress can assert arbitrary client
  identities — accepted as a consequence of placing ingress in the TCB; the
  claim is downgraded accordingly and never described as end-to-end binding.
- **Tier 1:** no LB in the identity path; the ADR-014 binding is intact.

## Conformance Vectors (ADR-MCPS-011)

- Trusted ingress over an authenticated LB↔node channel → accepted.
- Untrusted ingress identity → rejected.
- Missing LB↔node authentication → fail closed.
- **Spoof test (non-negotiable):** a client sends `X-MCPS-Verified-Client-Identity`
  directly, without trusted-ingress authentication → rejected/ignored.
- Public caller-supplied identity header → stripped before the node.
- Wrong asserted identity → transport-binding failure.
- Tier-2 audit log is distinguishable from Tier 1
  (`transport_binding_mode = trusted_ingress_asserted`).
- Tier 2 does **not** bypass MCP-S object signature verification.
- Tier 2 does **not** bypass Phase 5 (ADR-MCPS-013) authorization.

## Rationale

TLS termination at an L7 ingress is common in real deployments; deferring it
entirely would make the multi-node story much less useful. But it genuinely
weakens the transport guarantee, so it must be supported *and* honestly
downgraded — in docs, config names, audit logs, and policy outputs — never
marketed as equal to end-to-end mTLS. The one-trust-domain claim (Q1) is what
makes placing the ingress in the TCB acceptable at all.

## Alternatives Considered

- **Defer Tier 2 entirely** — rejected: too common a deployment shape to omit.
- **Require an LB-signed request-bound assertion in v0.3** — rejected as scope:
  assertion format, LB signing key, expiry, request-hash binding, assertion
  replay handling, rotation, and audit semantics are a separate profile (future
  Tier 3).
- **Allow a plain trusted header** — rejected: the classic `X-Client-Cert`
  spoofing bug; forbidden normatively.

## Consequences

### Positive
- Real-world L7-termination deployments are supported, with an honest,
  visible downgrade and a mandatory anti-spoof posture.

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
client↔node channel binding. Unauthenticated client-identity headers are
forbidden and MUST NOT be trusted."*

## Related

- ADR-MCPS-014 (Phase 6 transport hardening, `TransportBindingPolicy`)
- ADR-MCPS-013 (Phase 5 authorization — not bypassed by Tier 2)
- ADR-MCPS-017 (deferred reverse-proxy mTLS)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- The exact authenticated LB↔node assertion envelope (headers over LB↔node mTLS
  vs. a structured metadata block).
- Whether Tier 2 requires a strict-mode opt-in flag so it cannot be enabled
  silently.
- Future Tier 3 (LB-signed request-bound assertion) — its own ADR when scoped.
