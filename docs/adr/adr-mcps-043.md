<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-043: MCP-S Discovery, Capability Advertisement, and Enforcement Policy

## Status

Proposed — targets v0.7 (post-v0.6). Resolved in the discovery/client-integration
grill (2026-06-30, Codex + Judge supported). Sibling of
[044](adr-mcps-044.md) (Client-Side Integration Model). Depends on
[026](adr-mcps-026.md) (signing scope vs stateless `_meta`),
[028](adr-mcps-028.md) (WebPKI/mTLS KMS signers), and
[021](adr-mcps-021.md) (shared trust state / revocation window).

> Numbering note: the grill-input doc proposed `ADR-MCPS-020`, which is already
> taken (Distributed Atomic Replay Store). Renumbered to 043.

## Context

MCP-S to date is runtime evidence: signed request/response, freshness, replay,
audience binding, authorization-evidence binding, canonical preimage, response-to-
request binding. Adoption needs more: an MCP-S-capable client or client-side proxy
must decide how to behave when contacting a server — whether MCP-S is required,
allowed alongside legacy MCP, or refused — without letting a *discovery result*
become a downgrade lever.

The crux: a discovery result is a **claim**, not a **proof**. The grill (seed §8,
Q1–Q8, plus ten adversarial challenges) had to fix the authoritative source of
truth for enforcement, the discovery surface under the MCP 2026-07-28 *stateless*
model that [026](adr-mcps-026.md) tracks (which removes the `initialize`/`initialized`
handshake), the trust-anchor bootstrap, signer→audience binding, the legacy-fallback
failure taxonomy, and the enforcement-mode set.

## Decision

**MCP-S discovery is advisory; enforcement is local-policy-driven; verification is
cryptographic — and the model is stateless-primary.** The authoritative source of
truth is, in order: **local client/operator policy first, capability advertisement
second, cryptographic proof third.** A client MUST NOT silently downgrade from MCP-S
to legacy MCP.

The canonical discovery model is:

```text
local client policy → signed MCP-S request → verified signed response
```

The **first verified signed exchange is both the proof of MCP-S support and the
effective discovery result.** There is no trusted pre-flight "ask the server" step.

## Rationale

### Discovery is not a security boundary

A route is "MCP-S trusted" only after **all** of: signed request/response evidence
verifies, `server_signer` validates against a configured trust anchor, audience
matches, freshness/replay pass, and response-to-request (`request_hash`) binds.
Discovery is an ALPN-like hint about *whether to attempt* MCP-S; it never grants
trust. Under `require_mcps`, discovery is **irrelevant** — the client demands MCP-S
regardless of what any advert says; stripping the advert changes nothing.

### Stateless-primary surface

Because [026](adr-mcps-026.md) commits to the MCP 2026-07-28 stateless model that
removes `initialize`, there is no connection-time `capabilities` object to carry a
canonical advert. Security-relevant profile context therefore travels in **signed
per-message evidence / signed security-relevant `_meta`** (in signing scope per
[026](adr-mcps-026.md), else ignored). For session transports that still run
`initialize`, a server **MAY** advertise MCP-S under
`capabilities.experimental["se.syncom/mcps"]` — **non-canonical, advisory, never
required, never proof.** No new `server/discover` method and no `.well-known`
endpoint are defined (the former is not real MCP; the latter excludes stdio and
splits the surface).

### Trust bootstrap — MCP-S consumes anchors, it does not create them

Under `require_mcps`, `server_signer` MUST resolve to an **already-trusted** anchor
via (1) OOB operator configuration / enterprise trust bundle (`expected_server_signers`)
or (2) authenticated transport identity **verifiably bound** to the route/audience
(config host→signer map, cert SAN/SPIFFE→signer, or a cert-bound/signed assertion of
the object-signing key). A `server_signer_hint` is a lookup hint only — it can never
*introduce* a trusted signer. **TOFU is forbidden under `require_mcps`**; with no
anchor, strict MCP-S is unavailable for that route and the client fails closed rather
than discover-and-trust. A public signer registry, transparency log, or first-contact
bootstrap rooted in a new MCP-S trust authority is a **non-goal** — that would make
MCP-S a PKI/CA/transparency-log standard, far beyond runtime evidence. This reuses the
existing `TrustResolver` (`mcps-proxy/src/live_trust.rs`), OCSP
(`mcps-proxy/src/ocsp.rs`), WebPKI/mTLS ([028](adr-mcps-028.md)), and the revocation/
rotation window ([021](adr-mcps-021.md)).

### Signer→audience binding

The `TrustResolver` resolves an expected `(server_signer, audience)` pair from local
policy + verified transport **before** discovery is consulted. `audience` is a
concrete tuple `{scheme, host, port, tenant_id, route_id, realm}`; tenant/route
discriminators are mandatory wherever one signer serves multiple audiences (hostname
alone is insufficient for shared-SaaS/wildcard signers). The signed request carries
the intended audience; the signed response MUST echo the same audience plus
`request_hash`; mismatch fails closed. Discovery MAY describe but never choose, widen,
or rewrite audience.

### Enforcement modes (two normative)

Client modes: **`require_mcps`** (strict, fail-closed) and **`allow_legacy_explicit`**
(migration; legacy only where route/audience is explicitly allowlisted).
`opportunistic_mcps` is **cut** from the normative matrix and survives only as a
non-normative dev/test *probe* that records support but never changes a trust decision
or production routing. Server modes mirror these: `mcps_required`, `mixed_explicit`,
`legacy_only`. An MCP-S endpoint rejects unsigned runtime calls; a separate legacy
endpoint may exist, but the *same* endpoint must not silently downgrade. There is no
implicit default — policy must be chosen explicitly; enterprise posture is
`require_mcps`.

### Fallback failure taxonomy (`allow_legacy_explicit` only)

Bright line: **absence of MCP-S evidence MAY fall back; bad, inconsistent, or
downgrade-shaped evidence MUST fail closed.**

- **MAY fall back** (absence): transport/connection failure before any MCP-S evidence
  exists; plain-MCP / unsigned response; explicit "MCP-S unsupported" with no signed
  evidence — and only when the route/audience carries an explicit legacy allowlist.
- **MUST fail closed** (presence of bad evidence): invalid request signature; invalid
  response signature; unexpected `server_signer`; missing or mismatched
  `authorization_binding`; replay/freshness failure; `request_hash` mismatch;
  **unsupported or mismatched `version`; unsupported or mismatched `canonicalization_id`.**

Unsupported/mismatched version and canonicalization are **downgrade-sensitive**, not
neutral absence — they are exactly the lever an attacker or broken intermediary would
use to push a client onto a weaker path. An unsigned advert that says "I only support
vX" is not trusted evidence: it may guide what the client tries but must never trigger
silent fallback or weaken policy.

### Capability-advert semantics

Discovery adverts need no security freshness; they MAY be cached with conservative TTL
and eviction on connection/policy change, but are always non-authoritative. A stale
advert can never grant trust, select signer/audience, relax policy, or override the
signed exchange. On mismatch between advert and the verified exchange: if the exchange
satisfies policy → advisory inconsistency is logged, not security-relevant; if the
exchange is **weaker** than policy → fail closed (downgrade); if **stronger** than
advertised → accept if locally supported; if the verified exchange is internally
self-contradictory → protocol error, fail closed.

## Alternatives Considered

- **Static config is the only baseline; discovery has real enforcement weight.**
  Rejected: discovery cannot be authoritative without becoming a downgrade lever; it
  is advisory or it is a vulnerability.
- **Ride the `initialize` capabilities exchange as the canonical surface.** Rejected:
  [026](adr-mcps-026.md) removes `initialize` in the target stateless model;
  enshrining it would canonicalize a handshake being removed upstream. Kept only as a
  legacy-transport convenience.
- **A new `server/discover` method or `.well-known` endpoint.** Rejected: not real
  MCP / excludes stdio and splits the surface.
- **Define a first-contact trust bootstrap (registry / transparency log / signed
  advert chained to a new MCP-S root).** Rejected as a non-goal — pulls MCP-S into
  public PKI / CA / supply-chain trust governance.
- **TOFU-with-pinning as an enterprise path.** Rejected for `require_mcps`; allowed
  only in explicitly-labelled dev/permissive modes, never called enterprise security.
- **Treat unsupported version/canonicalization as ordinary "MCP-S unavailable"
  fallback.** Rejected: it is the canonical downgrade attack.

## Consequences

### Positive
- "Discovery is not a security boundary" is structurally true, not aspirational:
  discovery cannot even *name* a trustable signer that policy did not already know.
- Downgrade is blocked by construction; the strict path never asks, it demands.
- No new trust infrastructure; reuses existing resolver/OCSP/mTLS/revocation.

### Negative
- `require_mcps` is unavailable for any route without a pre-provisioned anchor — more
  operator configuration, accepted as the price of fail-closed strictness.

### Neutral
- Discovery work is explicitly **not** in the v0.6 server-completion gate; it is v0.7.

## Compliance and Enforcement

Conformance vectors (seed §7) required before implementation is complete: MCP-S
advertised + valid → accepted under `require_mcps`; MCP-S absent under `require_mcps`
→ rejected; absent under explicit legacy policy → accepted-and-audited; advertised but
response unsigned → rejected; invalid `server_signer` → rejected; unsupported version
→ rejected (downgrade-shaped, not fallback); unsupported `canonicalization_id` →
rejected; advertised values vs different signed message values → rejected; discovery
stripped → no silent downgrade; discovery tampered → no policy weakening; unknown keys
in signed security region → fail closed; observability metadata changed → no decision
change; legacy explicitly allowed → succeeds, visibly marked legacy/no-runtime-evidence.
Audit events use the frozen `wire_code()` reason vocabulary (per the audit-evidence
ADR / CONTEXT glossary).

## Related

- Grill input: [`mcps-discovery-enforcement-grill-input.md`](../grilling-seed/mcps-discovery-enforcement-grill-input.md).
- Sibling: [044](adr-mcps-044.md) (Client-Side Integration Model).
- Depends on: [026](adr-mcps-026.md), [028](adr-mcps-028.md), [021](adr-mcps-021.md).
- Code (reused): `mcps-proxy/src/live_trust.rs`, `mcps-proxy/src/ocsp.rs`,
  `mcps-core/src/error.rs`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
