<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-025: Untrusted Transport Routing Headers — MCP-S Composition with SEP-2243

## Status

Proposed — **conditional on the MCP 2026-07-28 release candidate**; revisit if
the referenced SEP schema changes materially (v0.3 delta sketch). SEP-2243 is
marked Final upstream; this ADR composes MCP-S verification on top of it.

## Context

ADR-MCPS-023 decides the ingress model and treats all caller-supplied identity
metadata as attacker-controlled unless the immediate peer is an authenticated
trusted ingress. ADR-MCPS-014 binds the verified request to the transport
identity through the pluggable `TransportBindingPolicy`.

The MCP 2026-07-28 release standardizes HTTP transport for middle boxes
(SEP-2243). It introduces routing headers — **`Mcp-Method`** and **`Mcp-Name`** —
so load balancers and gateways can route, trace, and rate-limit **without
inspecting the body**, plus an **`x-mcp-header`** tool-schema annotation that
maps selected request-body arguments onto HTTP headers. SEP-2243 requires the
server to **match header values against the corresponding body values and reject
with `400 Bad Request` on any mismatch.**

These headers are **routing signals, not authenticated identity.** They sit in
front of MCP-S nodes and are writable by any middle box. This ADR states how
MCP-S composes its signature verification on top of SEP-2243 without ever
trusting a header for a security decision.

## Definitions

- **SEP-2243 routing headers** — `Mcp-Method`, `Mcp-Name`, and any
  `x-mcp-header`-promoted argument header. Untrusted transport metadata.
- **Security-relevant promoted argument** — an `x-mcp-header`-promoted body
  argument whose value influences an MCP-S verification, authorization, or
  audit decision.

## Decision

MCP-S treats SEP-2243 routing headers as **untrusted transport metadata** and
layers its own check above the SEP's body-match rule:

1. **Routing only, never authorization.** `Mcp-Method` / `Mcp-Name` and any
   promoted header are inputs to routing/observability only. They MUST NOT
   influence identity, trust, freshness, or authorization decisions.
2. **The signature covers the body, not the header.** The MCP-S signature is over
   the canonical JSON-RPC object (ADR-MCPS-004/005). A header is never part of
   the signed preimage.
3. **Security-relevant promoted arguments MUST be re-validated at the node.** For
   any `x-mcp-header`-promoted argument that is security-relevant, the node MUST
   verify the **signed body value** and re-check the header against it, **failing
   closed on mismatch** — composing MCP-S verification on top of SEP-2243's
   `400`. The body value, being signed, is authoritative; the header is a hint.
4. **Routing headers are orthogonal to ingress identity.** A SEP-2243 routing
   header MUST NOT carry, assert, or influence the Tier-2 asserted client
   identity of ADR-MCPS-023. The strict header rules of ADR-MCPS-023
   (single-valued, length-bounded, well-formed, duplicates fail closed) apply to
   SEP-2243 headers as well.
5. **Header-only requests are rejected.** A protected request that arrives with
   routing headers but **no verifiable signed body** is rejected; MCP-S never
   reconstructs a request from headers alone.

## Threat Model

- **Trust boundary:** one operator; middle boxes between client and node may
  rewrite headers (that is their job).
- **Primary threat:** an attacker (or a buggy/over-trusted middle box) sets
  `Mcp-Name`, `Mcp-Method`, or a promoted header to a value that disagrees with
  the signed body, hoping the node honors the header — escalating method,
  retargeting a tool, or spoofing an identity-bearing argument.
- **Defeated by:** the signed body being authoritative + node-side
  re-validation + fail-closed on mismatch + routing headers being barred from the
  identity path.
- **Private network location is not authentication** (carried from
  ADR-MCPS-023): a header arriving over an internal hop is still untrusted.
- **Deferred:** signed/authenticated routing metadata (a middle box that signs
  its routing assertions) — not required in v0.3.

## Conformance Vectors (ADR-MCPS-011)

- **Header/body agreement:** a request whose `Mcp-Method`/`Mcp-Name` matches the
  signed body is routed and verified normally.
- **Header/body mismatch:** a security-relevant promoted header that disagrees
  with the signed body is rejected (fail closed), independent of SEP-2243's own
  `400`.
- **Header cannot escalate:** a `Mcp-Method` header naming a different method
  than the signed body does not cause the node to execute the header's method.
- **Routing header not identity:** a routing header attempting to assert client
  identity is ignored; only the ADR-MCPS-023 trusted-ingress path can assert
  identity.
- **Strict-header rules:** duplicate / malformed / oversized SEP-2243 headers
  fail closed.
- **Header-only request:** routing headers with no verifiable signed body →
  rejected.

## Rationale

SEP-2243 is genuinely useful — body-free routing is what makes the stateless,
horizontally-scaled deployment efficient — but it widens the set of
attacker-writable inputs in front of the node. The safe composition is to keep
the signed body as the single source of truth and make every header a hint that
must agree with it. This reuses the exact posture ADR-MCPS-023 already takes
toward asserted-identity headers, extended to routing headers, so there is one
consistent rule: **no header is trusted; the signature decides.**

## Alternatives Considered

- **Honor `Mcp-Method`/`Mcp-Name` as authoritative for dispatch** — rejected: a
  header-controlled method dispatch is a classic confused-deputy/escalation bug.
- **Rely solely on SEP-2243's `400` body-match** — rejected: that is an
  application-server check; MCP-S must enforce its own fail-closed at the
  verification layer, where the signed value is authoritative.
- **Add routing headers to the signed preimage** — rejected: headers are mutated
  by legitimate middle boxes; signing them would break routing.

## Consequences

### Positive
- MCP-S works cleanly behind SEP-2243 middle boxes; routing/observability gains
  the stateless model intends, with no new trust placed in headers.

### Negative
- The node must re-validate security-relevant promoted arguments against the
  signed body — a small per-request check; integrators must mark which promoted
  arguments are security-relevant.

### Neutral
- `Mcp-Method`/`Mcp-Name` remain fully usable for routing, tracing, and
  rate-limiting.

## Compliance and Enforcement

`security-boundary.md` addition: *"MCP-S operates behind SEP-2243 HTTP routing
middle boxes. `Mcp-Method`, `Mcp-Name`, and `x-mcp-header`-promoted headers are
untrusted routing metadata; they never influence identity, trust, or
authorization. The signed request body is authoritative, and the node fails
closed when a security-relevant header disagrees with it. Routing headers cannot
assert client identity."*

## Related

- ADR-MCPS-023 (Ingress and Reverse-Proxy mTLS — strict header rules extended here)
- ADR-MCPS-014 (Transport hardening, `TransportBindingPolicy`)
- ADR-MCPS-004 / ADR-MCPS-005 (what is signed: the canonical body, not headers)
- ADR-MCPS-013 (authorization — not influenced by headers)
- ADR-MCPS-011 (conformance-as-specification)
- SEP-2243 (HTTP transport standardization / routing headers)

## Open Questions for Review

- Whether MCP-S should publish guidance on which tool arguments may be marked
  `x-mcp-header` (a deny-list for identity/authorization-bearing arguments).
- Whether a future profile accepts a signed routing assertion from a trusted
  middle box (the SEP-2243 analogue of ADR-MCPS-023 Tier 3).
