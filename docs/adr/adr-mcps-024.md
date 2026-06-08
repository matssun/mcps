<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-024: Replay Safety Under MCP Multi Round-Trip Requests (SEP-2322)

## Status

Proposed — **conditional on the MCP 2026-07-28 release candidate**; revisit if
the referenced SEP schema changes materially (v0.3 delta sketch). SEP-2322's
schema is marked "proposed but not locked" upstream; this ADR therefore binds to
the SEP's *mechanism* and states MCP-S requirements that hold regardless of the
final field names.

## Context

ADR-MCPS-006 and ADR-MCPS-020 define replay protection as an atomic
`(signer, audience, nonce)` insert-if-absent, consulted after signature
verification, failing closed. Both assume a request is a single signed
JSON-RPC object verified once.

The MCP 2026-07-28 stateless release introduces **Multi Round-Trip Requests**
(SEP-2322): a server may return an `InputRequiredResult` / incomplete response
carrying a `requestState` payload; the client gathers the required input and
resumes, and — because protocol-level sessions are removed (SEP-2567) — **any
server instance may continue the exchange**. The exchange is now several legs,
each potentially landing on a different node, with `requestState` as the resume
context.

This collides with the replay store in two directions:

- a legitimate continuation leg must **not** be discarded as a duplicate of an
  earlier leg; and
- a forged or replayed `requestState` must **not** purchase freshness or
  authorization.

SEP-2322 does not specify whether `requestState` is signed, opaque, or
client-held. MCP-S therefore cannot rely on it for any security decision.

## Definitions

- **Leg** — one signed MCP-S request/response round trip within a multi
  round-trip exchange.
- **`requestState`** — the SEP-2322 resume payload returned to the client and
  echoed back to continue an exchange. Treated by MCP-S as opaque,
  client-held, **untrusted** data.

## Decision

A multi round-trip exchange is modelled as **a sequence of independent signed
MCP-S legs**, not as one long-lived authenticated request. The replay contract
of ADR-MCPS-020 is preserved unchanged at the per-leg granularity, with these
explicit rules:

1. **Every leg is its own signed object** carrying its own nonce and freshness,
   verified independently per ADR-MCPS-004/006. A continuation leg is a new
   request, not a replay of a prior leg.
2. **`requestState` is untrusted.** It confers neither freshness nor
   authorization on its own. MCP-S MUST NOT derive a trust, identity, or
   replay-exemption decision from `requestState` unless that state is covered by
   a signature whose signer resolves in the trust set (ADR-MCPS-007). Absent such
   a covering signature, `requestState` is opaque transport data only.
3. **No nonce reuse across legs or retries.** Replay keying stays
   `(signer, audience, nonce)`. A leg that reuses a nonce already accepted is a
   replay *by definition* and MUST fail closed. Clients MUST mint a **fresh nonce
   per leg and per retry**. Idempotency lives in fresh-nonce-per-attempt — never
   in nonce reuse.
4. **Continuation does not bypass authorization.** Each leg is independently
   subject to Phase 5 authorization (ADR-MCPS-013). A later leg MUST NOT inherit
   an authorization decision from an earlier leg via `requestState`.

If a future MCP-S profile wants cross-leg correlation (e.g. binding leg *n* to
leg *1*), it MUST be expressed as a signed field inside each leg's canonical
object, never as trust placed in the unsigned `requestState`.

## Threat Model

- **Trust boundary:** one operator (v0.3 claim unit); the replay store is inside
  the boundary, per ADR-MCPS-020.
- **Primary threat:** an attacker replays a captured leg — or fabricates a
  `requestState` — to a node that has no record of that leg's nonce, hoping to
  resume or short-circuit an exchange with stolen context.
- **Defeated by:** per-leg signature verification + fresh-nonce-per-leg replay
  rejection + the rule that `requestState` is never trusted unsigned.
- **Availability note:** because legs are independent and nonces are fresh per
  attempt, a dropped leg is safely retried with a new nonce; the framework retry
  is not mistaken for a replay, and a replay is not mistaken for a retry.
- **Deferred:** signed cross-leg binding (a hardened multi-leg profile) is named
  here but not specified in v0.3.

## Conformance Vectors (ADR-MCPS-011)

- **Continuation accepted:** leg 2 of an exchange, signed with a fresh nonce on a
  different node, is accepted.
- **Leg replay rejected:** re-sending leg 1 with its original nonce is rejected
  as replay (`mcps.replay_*`), even mid-exchange.
- **Unsigned `requestState` not trusted:** a `requestState` presented without a
  covering signature yields no freshness, identity, or authorization decision.
- **Forged `requestState`:** a mutated `requestState` does not resume an exchange
  on any node absent a valid covering signature.
- **No authorization inheritance:** a later leg is independently authorized;
  revoking authorization between legs causes the next leg to fail closed.
- **Retry safety:** a legitimately retried leg with a new nonce is accepted; the
  same leg with a reused nonce is rejected.

## Rationale

The cleanest reconciliation of SEP-2322 with ADR-MCPS-020 is to refuse to make
the exchange a security unit at all: keep the *leg* as the unit MCP-S already
knows how to verify, and treat `requestState` exactly as hostile as any other
client-supplied bytes. This preserves the existing replay guarantee without a new
store mode and avoids the trap of granting replay exemptions to a payload whose
integrity the protocol does not define.

## Alternatives Considered

- **Treat `requestState` as a trusted resume token** — rejected: SEP-2322 does
  not define its integrity; trusting it would let an attacker forge resume
  context.
- **Add a replay-cache exemption for retried legs** — rejected: a fresh nonce per
  attempt already distinguishes retry from replay without weakening the store.
- **Make the whole exchange one long-lived authenticated request** — rejected:
  incompatible with the stateless, any-instance model of SEP-2567/2322.

## Consequences

### Positive
- No new replay-store mode; the ADR-MCPS-020 contract carries over verbatim at
  per-leg granularity; multi round-trip works across instances without trusting
  resume state.

### Negative
- Clients MUST mint a fresh nonce per leg/retry; integrators reusing nonces will
  see fail-closed rejections (the intended behavior).

### Neutral
- Cross-leg correlation remains possible later as a signed field, not as trust in
  `requestState`.

## Compliance and Enforcement

`security-boundary.md` addition: *"Under MCP multi round-trip requests, each leg
is an independent signed MCP-S request with its own nonce and freshness. MCP-S
does not trust the SEP-2322 `requestState` payload for any security decision
unless it is covered by a resolvable signature. Replay protection applies per
leg; nonces are not reused across legs or retries."*

## Related

- ADR-MCPS-006 (Freshness and Replay Model)
- ADR-MCPS-020 (Distributed Atomic Replay Store — the per-leg contract preserved)
- ADR-MCPS-013 (Phase 5 authorization — applied per leg)
- ADR-MCPS-007 (Trust Resolution — the only basis for trusting any resume state)
- ADR-MCPS-011 (conformance-as-specification)
- SEP-2322 (Multi Round-Trip Requests), SEP-2567 (stateless sessions removed)

## Open Questions for Review

- Whether v0.3 ships a signed cross-leg binding field now or names it as a later
  hardened multi-leg profile.
- Whether `requestState`, when MCP-S itself generates it, should be signed by the
  proxy so a node can cheaply detect tampering even before full verification.
