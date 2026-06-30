<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-044: Client-Side MCP-S Integration Model

## Status

Proposed — targets v0.7/v0.8 (post-v0.6). Resolved in the discovery/client-
integration grill (2026-06-30, Codex + Judge supported). Sibling of
[043](adr-mcps-043.md) (Discovery & Enforcement), whose decisions are binding
constraints here. Depends on [026](adr-mcps-026.md) (signing scope vs stateless
`_meta`), the frozen `mcps-core` error taxonomy, and the existing
`TrustResolver` / OCSP / WebPKI-mTLS machinery ([028](adr-mcps-028.md),
[021](adr-mcps-021.md)).

> Numbering note: the grill-input doc proposed `ADR-MCPS-021`, which is already
> taken (Shared Trust State). Renumbered to 044.

## Context

MCP-S is a two-sided runtime-evidence protocol: a server-side wrapper can verify
signed requests and sign responses, but it cannot construct client request
signatures, generate nonces, bind client-side authorization evidence, track request
hashes, or verify responses at the receiving end. If MCP-S is only a server wrapper,
ordinary MCP clients cannot produce MCP-S evidence and adoption stalls. The MCP
ecosystem has many hosts/clients and cannot be assumed to add native support soon, so
a practical adoption path is needed before native support arrives.

The grill (seed §9, Q1–Q9, plus eight adversarial rulings) had to fix which client-
side components are valid MCP-S implementations and which is built first, how an
ordinary client uses MCP-S unmodified, the security-adapter scope boundary, the
shared-logic seam, key custody, the authorization-binding hook, in-flight correlation
state under the stateless model, the error taxonomy, and SDK feasibility.

## Decision

**MCP-S is two-sided.** It defines three client integration modes — **native client
support**, **local client-side proxy**, and **SDK wrapper** — with this priority:

```text
1. Local client-side proxy   (first practical adoption bridge)
2. SDK wrapper               (TypeScript first)
3. Native client/host        (future ecosystem adoption)
```

Native support is the long-term ideal but not the initial adoption dependency. The
proxy and SDK MAY support legacy MCP only under explicit policy and MUST never
silently downgrade. Shared signing/verification/enforcement logic lives in one crate,
**`mcps-client-core`**, consumed by both the proxy and SDK.

## Rationale

### Proxy is fully transparent and is a security adapter, not an orchestrator

The ordinary client speaks plain MCP to a local endpoint and never emits, parses, or
negotiates MCP-S. Because the stateless model ([043](adr-mcps-043.md),
[026](adr-mcps-026.md)) has no `initialize` to hide behind, **all** signing,
verification, discovery, downgrade enforcement, and error mapping happen inside the
proxy on the remote leg. The only permitted leakage is out-of-band config (local
endpoint URL, route name) and surfaced security errors.

Scope boundary — **IN:** local MCP listener, configured route resolution, policy
enforcement (`require_mcps` / `allow_legacy_explicit`), request signing, nonce/
freshness, authorization-binding attachment, request-hash correlation, response
verification, trust resolution, transport adaptation, audit events, error mapping.
**OUT:** tool choice, planning, *intent* routing, consent UX beyond security errors,
authorization semantics, policy authoring, workflow state, result caching, general
API-gateway behavior. Static route resolution is IN; intent-based routing is OUT —
that line is what keeps it an adapter.

### Shared seam: `mcps-client-core`

A single new crate owns: client evidence construction, nonce/freshness generation +
validation helpers, request-hash calculation, response verification, `server_signer`
validation via `TrustResolver`, enforcement-mode evaluation, authorization-binding
trait types, pending-correlation primitives, audit event types, and error mapping to
frozen `mcps-core` wire codes. It is **not** placed in `mcps-core` (that would breach
the pure-crypto/method-transparent boundary). Mode-specific code stays out of it:
local listener, route-config loading, process lifecycle, SDK language bindings,
host-specific key providers, UI/error presentation, concrete transports.

### Minimum client-side responsibilities

Any conforming component MUST: sign the exact request preimage (protected `version`,
`canonicalization_id`, security-relevant `_meta` in scope; reject unsupported
canonicalization); generate nonce/issued-at/expiry with no reuse in window; set and
sign the audience; attach `authorization_binding` when required; track/recompute
request hashes and correlate responses; verify response signature, protected response
`version`/`canonicalization_id`, `server_signer` via trust resolver, and
`request_hash`; reject unsigned responses under `require_mcps`; enforce downgrade
policy with no silent fallback.

### Authorization-binding hook (bind-not-interpret)

The component exposes an **`AuthorizationBindingProvider`**: given (request context,
route policy, audience, optional method/tool id, deadline) it returns
`{ binding_type, binding_id?, bytes_or_digest, protected_fields }` or a typed
missing/unsupported error. The core includes the returned binding in the signed
preimage and enforces presence/type by policy, but never interprets opaque bytes,
dereferences `authz-system-reference`s, evaluates permissions, or parses structured
authorization semantics. Base forms: `opaque-bytes`, `authz-system-reference`;
structured authorization-object hashing remains deferred.

### In-flight correlation state

Stateless means no discovery-session state — **not** no in-flight state. The component
keeps, per outstanding request: local correlation id, request hash, nonce/request id,
issued-at, expiry/deadline, route, audience, expected signer set, version/
canonicalization, and authz-binding digest/reference for audit. State is retained
until the matching response verifies, the call is cancelled, or the deadline expires;
cleanup happens on completion and via periodic expiry sweep; a **late response after
cleanup fails closed as uncorrelatable** (never retroactively trusted).

### Error taxonomy reuses `wire_code()`

All client-side protocol/security failures map to the frozen `mcps-core`
`wire_code()` taxonomy — no parallel client wire taxonomy. Implementations may add
local exception classes, logs, and remediation hints, but each MUST map to a stable
wire code for interop, proxy/SDK parity, conformance, and the audit drift guard.

### Key custody — mechanism-neutral, strict properties

Under `require_mcps` a client signing identity is mandatory; missing, revoked,
unknown, or policy-mismatched signer fails closed. The ADR mandates **properties, not
a product**: the client signer MUST be identified in MCP-S evidence and bound to the
configured route/audience/client-identity policy; private signing material MUST be
non-exportable or delegated to a non-exporting signer where the platform/deployment
supports it; production `require_mcps` MUST NOT use unprotected file keys; rotation and
revocation MUST be controlled by explicit configuration/trust policy. Acceptable
implementations include OS keychain / Secure Enclave, hardware-backed keys, HSM/KMS,
workload identity, mTLS-bound signing identity, or a delegated enterprise signing
service. Hardware/KMS-only is a valid **hardening profile**, never the base rule
(MCP-S must not depend on one custody product class). Dev file keys MAY exist only in
explicitly-labelled development/test mode and are never accepted as production
`require_mcps` custody. TOFU stays forbidden under `require_mcps`
([043](adr-mcps-043.md)).

### SDK wrap-or-fork rule; TypeScript first

An SDK wrapper is permitted only when the underlying MCP SDK exposes hooks to **sign
the exact outbound bytes / canonical preimage before send** and **verify the exact
inbound response bytes/evidence before application parsing.** If an SDK cannot provide
that without semantic drift, the project MUST NOT claim a transparent wrapper for it;
the fallback is a small transport adapter or a minimal/forked client layer that owns
serialization boundaries explicitly. **TypeScript is the first SDK** (highest MCP
client/host adoption leverage); other languages follow by demand.

## Alternatives Considered

- **Native client support first.** Rejected as the initial dependency: it relies on
  third-party vendors and likely standardization; it remains the long-term ideal.
- **SDK wrapper first.** Rejected: helps developers building custom clients but not
  ordinary existing clients; the proxy delivers value with zero client modification.
- **Put shared logic in `mcps-core`.** Rejected: breaks the pure-crypto/method-
  transparent boundary; client orchestration is method-aware.
- **A parallel client-side error taxonomy.** Rejected: fragments interop/audit; reuse
  `wire_code()`.
- **Hardware/KMS-only custody as the base rule.** Rejected: ties MCP-S to one product
  class; kept as an optional hardening profile.
- **Claim transparent SDK wrappers regardless of hook availability.** Rejected:
  without byte/preimage control the wrapper cannot guarantee the signed preimage.

## Consequences

### Positive
- Ordinary MCP clients use MCP-S-protected servers with **no modification** via the
  proxy; proxy and SDK share one audited core.
- The adapter boundary prevents the proxy from sprawling into an orchestrator.
- Fail-closed custody and correlation rules leave no retroactive-trust gaps.

### Negative
- A new local deployment component (the proxy) and per-route configuration to manage.
- SDK wrappers depend on upstream SDK hooks; some ecosystems may need an adapter/fork.

### Neutral
- Native host support remains future ecosystem work, tracked separately.

## Compliance and Enforcement

Conformance tests (seed §10) a conforming component must pass: signs an ordinary MCP
request into MCP-S draft-02 with protected `version` / `canonicalization_id` / nonce /
audience / `authorization_binding`; rejects unsupported canonicalization; tracks
request hash; verifies a valid signed response; rejects unsigned response under
`require_mcps`; rejects invalid response signature, unexpected `server_signer`, and
`request_hash` mismatch; allows a legacy route only under explicit policy and rejects
it under `require_mcps`; does not silently downgrade when discovery is absent; audits
legacy distinctly from MCP-S-verified; handles timeout / pending-hash cleanup and
repeated-nonce prevention; handles `authz-system-reference` via a configured resolver
and rejects it without one; rejects structured authorization-object hashing in the
base profile. End-to-end test topology: ordinary MCP client → local MCP-S proxy →
remote MCP-S server/proxy → ordinary MCP server.

## Related

- Grill input: [`mcps-client-integration-grill-input.md`](../grilling-seed/mcps-client-integration-grill-input.md).
- Sibling (binding constraints): [043](adr-mcps-043.md) (Discovery & Enforcement).
- Depends on: [026](adr-mcps-026.md), [028](adr-mcps-028.md), [021](adr-mcps-021.md).
- Roadmap: post-v0.6 — proxy → TypeScript SDK → end-to-end demo.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
