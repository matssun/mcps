<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-021: Cluster Trust State — Revocation and Rotation Propagation Across Nodes

## Status

Proposed (v0.3 sketch — under review)

## Context

ADR-MCPS-007 defines trust resolution as a caller-injected `TrustResolver`:
`resolve(signer, key_id) -> VerificationKey | TrustResolverError`, authoritative
at verify time, fail-closed. Revocation is already first-class —
`TrustResolverError::Revoked` → `mcps.actor_binding_failed`, `Unavailable` →
`mcps.trust_resolver_unavailable` — and `InMemoryTrustResolver` already supports
rotation (multiple `key_id`s per signer) and `revoke()`.

In a multi-node fleet the same distribution problem as replay (ADR-MCPS-020)
reappears one layer up: **revocation and key-status state must be consistent
across nodes.** Revoke signer X on node A and node B keeps trusting X until B's
resolver reflects it. This ADR reuses ADR-MCPS-020's store-tier vocabulary but
is a **separate** decision because its failure direction is mirrored and its
operational consequence is a *security exposure*, not a DoS.

## Decision

ADR-MCPS-021 governs shared **trust / key-status / revocation / rotation**
state. It reuses ADR-MCPS-020's storage-tier framework applied to the
`TrustResolver`, and introduces a **bounded trust-propagation window `T`**.

**The failure asymmetry (why this is its own ADR):**

| | Dangerous failure | Safe direction | Stale state causes |
|---|---|---|---|
| Replay (020) | forgetting a nonce | over-remember | DoS |
| **Revocation (021)** | continuing to trust a revoked key | propagate fast | **security exposure** |
| **Rotation (021)** | using a new key before verifiers know it | publish-before-use | availability failure |

**Bounded propagation window `T`:**

- A resolver MAY cache *active* key state for at most `T`.
- A revocation is guaranteed fleet-wide within `T`, given every node obeys the
  cache TTL and fails closed after expiry.
- `T` is the documented revocation exposure window.
- **Defaults:** `T = 60s` default; **warn above 5 min**; max recommended 5 min;
  high-risk admin/mutation paths `T ≤ 60s` or live check. A strict/production
  mode MAY cap `T` unless explicitly overridden.

**Normative fail-closed rule:** if the trust store is unavailable, a node MAY
use cached *active* state only until `T` expires; after `T`, trust resolution
MUST fail closed (`mcps.trust_resolver_unavailable`). A node MUST NEVER serve
indefinitely from stale "active" trust state.

**Normative rotation pattern:** publish new key → wait ≥ `T` for propagation →
begin signing with the new key → retain the prior key and drain ≥
`max_request_lifetime + max_clock_skew` → revoke/disable the prior key.

**Tiers (reusing 020's vocabulary):**

| Tier | Posture | Window |
|---|---|---|
| **1** | Bounded-cache eventual: shared trust store, cache TTL = `T` | revocation within `T`; outage → cached until `T` then fail closed |
| **2** | Live strong check: resolve against the shared store on each verification, or a linearizable read | near-zero |
| **3** | Push invalidation: cache allowed, a revocation event invalidates affected keys immediately; on channel failure, fall back to bounded `T` or fail closed | near-zero **with bounded fallback** |

Tier 3 is **not** described as "zero window" unless the push mechanism has
reliable ordering, delivery, and failure handling — otherwise it is "near-zero
with bounded fallback."

## Threat Model

- **Trust boundary:** one operator; the trust store is inside the TCB. Nodes
  share one trust/policy authority.
- **Primary threat:** a revoked or compromised signing key continues to be
  accepted on a node that has not yet learned of the revocation.
- **Exposure window:** bounded by `T` (and by the store outage rule above — a
  node cannot serve stale "active" beyond `T` even during a store outage).
- **Rotation hazard:** a signer that begins using a new key before `T` elapses
  causes valid requests to be rejected on lagging nodes — an availability
  failure, not a security bypass, but it MUST be documented.

## Conformance Vectors (ADR-MCPS-011)

- **Revocation propagation:** revoke on node A → node B rejects within `T`.
- **Fail-closed at `T` under outage:** trust store unreachable → node serves
  cached active until `T`, then `mcps.trust_resolver_unavailable`.
- **No indefinite stale-active:** a node cannot accept a revoked key past `T`
  even with the store down.
- **Rotation overlap:** new key accepted on all nodes only after ≥ `T`; the
  prior key still accepted through the drain window; rejected after revoke.
- **`T` ceiling warning:** configuring `T` above the recommended max emits a
  warning (and is capped in strict mode if overridden).

## Rationale

Revocation's safe direction is the opposite of replay's, so it needs its own
threat model even though it shares the storage tiers. A bounded `T` is honest
and practical: requiring a live CP check on every request would be stronger but
imposes latency/availability costs many deployments will not accept. The
existing fail-closed semantics (`trust_resolver_unavailable`) already give the
safe direction; `T` simply bounds how long cached-active may survive.

## Alternatives Considered

- **Mandatory live check (zero window) by default** — rejected: latency and
  store-availability cost; offered as Tier 2 for high-risk deployments.
- **Fold into ADR-MCPS-020** — rejected: mirrored failure direction and
  different operational consequence warrant a separate, separately-reviewable
  decision.
- **Leave `T` unspecified** — rejected: an unbounded or vague `T` is an
  invisible exposure; defaults must be short and explicit.

## Consequences

### Positive
- Revocation has a stated, bounded, fail-closed exposure window; rotation is
  safe by construction.

### Negative
- Operators must reason about `T` vs. their revocation-urgency needs;
  high-risk paths need tighter `T` or live checks.

### Neutral
- Reuses 020's store tiers; a CP/push backend upgrades the window without an
  architectural change.

## Compliance and Enforcement

`security-boundary.md`: *"Within one trust domain, key revocation is enforced
fleet-wide within the configured trust-propagation window `T`. A node may use
cached active trust state only until `T` expires; after that, trust-store
unavailability fails closed. An unconditional near-zero-window revocation claim
requires a live/linearizable lookup or reliable push invalidation."*

## Related

- ADR-MCPS-007 (Trust Resolution, Key Rotation, Revocation Model)
- ADR-MCPS-020 (storage-tier vocabulary reused here)
- ADR-MCPS-022 (per-node key anchor governed by this ADR's propagation window)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- Whether `T` is global or per-signer / per-sensitivity.
- Push-invalidation transport (Tier 3) — reuse the replay store's pub/sub, or a
  dedicated channel.
- Interaction with online OCSP (ADR-MCPS issue #4030): is OCSP a Tier-2 live
  check, or an orthogonal cert-layer revocation that composes with `T`.
