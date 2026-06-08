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

## Definitions

- **`T`** — the maximum time a verifier may rely on cached *active* trust state
  before revalidating with the shared trust source or failing closed.
- **"Active key state"** — the resolver's complete *positive* trust result for
  `(signer, key_id)`: the verification key, the active status, the validity
  interval if present, and any trust-store generation or policy version used to
  derive the result. A node MUST NOT cache a verification key independently of
  its active/revoked/disabled status. Cached active state is valid only together
  with the status and generation under which it was resolved.
- **`Unavailable`** — an operational failure, never a trust decision. `T` does
  not apply to it; it MUST NOT be cached as active, revoked, or not-found, and
  MUST fail closed as `mcps.trust_resolver_unavailable`.

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

### Bounded propagation window `T`

- A resolver MAY cache *active key state* for at most `T`.
- A revocation is enforced fleet-wide within `T` **provided** all verifier nodes
  use the configured shared trust source, enforce the cache TTL, and fail closed
  after cache expiry. The phrase "fleet-wide within `T`" always carries those
  assumptions.
- `T` is the documented revocation exposure window.

**`T` scope — global default, stricter per sensitivity class.** `T` has a
deployment-wide default of **60s**. Deployments MAY define stricter `T` for
configured sensitivity classes (admin, financial mutation, production
infrastructure, high-risk tools). A request MUST use the **strictest applicable**
`T`. The proxy **warns above 5 min** (max recommended); strict/production mode
MAY cap `T` unless explicitly overridden. Per-request arbitrary `T` is not
introduced in v0.3.

### Negative caching

Negative trust results MUST be classified — they are not cached uniformly:

- **`Revoked` / `Disabled`** — safe-deny; MAY be cached according to policy
  (potentially longer than `T`, since caching a deny is never a security risk).
- **`NotFound`** — SHOULD use a *short* bounded TTL, so a newly published
  rotation key is not suppressed (an availability hazard, not a security one).
- **`Unavailable`** — MUST NOT be cached as a trust decision; fail closed.

### Fail-closed and restart semantics

If the trust store is unavailable, a node MAY use cached *active* state **only**
if it was obtained before the outage and remains within `T`; after `T`, trust
resolution MUST fail closed (`mcps.trust_resolver_unavailable`). A node MUST
NEVER serve indefinitely from stale active trust.

A verifier process that **starts without a valid unexpired local cache and
cannot reach the trust store MUST fail closed** — a restart MUST NOT resurrect
stale trust.

### Rotation pattern (tier-aware)

For **Tier 1**, a signer MUST wait at least `T` after publishing a new key
before using it. For **Tier 2/3**, the signer MAY begin using the new key once
the configured live-check or invalidation mechanism confirms visibility across
the verifier fleet, or after `T` as a conservative fallback.

Full sequence: publish new key → wait per the tier rule above → begin signing →
retain the prior key and drain ≥ `max_request_lifetime + max_clock_skew` →
revoke/disable the prior key.

### Tiers (reusing 020's vocabulary)

| Tier | Posture | Window |
|---|---|---|
| **1** | Bounded-cache eventual: shared trust store, cache TTL = `T` | revocation within `T`; outage → cached until `T` then fail closed |
| **2** | Live strong check: resolve against the shared store on each verification, or a linearizable read | near-zero |
| **3** | Push invalidation: cache allowed, a revocation event invalidates affected keys immediately; on channel failure, fall back to bounded `T` or fail closed | near-zero **with bounded fallback** |

Tier 3 is **not** described as "zero window" unless the push mechanism has
reliable ordering, delivery, and failure handling — otherwise it is "near-zero
with bounded fallback." Invalidation MUST be **monotonic**: a stale "active"
update MUST NOT undo a revocation.

### Relationship to OCSP/CRL

OCSP/CRL revocation for mTLS client **certificates** is orthogonal to this ADR.
ADR-MCPS-021 governs MCP-S **signer/key status** resolved by `TrustResolver`. A
deployment MAY use OCSP as a live certificate-validity check, but that does NOT
replace MCP-S key revocation unless the `TrustResolver` explicitly derives
signer/key status from that certificate layer. The two compose; neither replaces
the other.

### Audit and telemetry

At startup the proxy MUST log the configured trust-resolution tier and `T`.
During operation it MUST emit structured logs for: trust-store unavailability,
cached-active fallback, cache-expiry fail-closed, revoked/disabled key rejection,
and rotation-related `NotFound`. Logs MUST include `signer` and `key_id` (or a
stable redacted hash thereof).

## Threat Model

- **Trust boundary:** one operator; the trust store is inside the TCB. Nodes
  share one trust/policy authority.
- **Primary threat:** a revoked or compromised signing key continues to be
  accepted on a node that has not yet learned of the revocation.
- **Exposure window:** bounded by `T` (and by the outage/restart rules above — a
  node cannot serve stale "active" beyond `T`, and cannot resurrect it on
  restart).
- **Rotation hazard:** a signer that begins using a new key before propagation
  completes causes valid requests to be rejected on lagging nodes — an
  availability failure, not a security bypass, amplified if `NotFound` is cached
  too long. Documented, not security-critical.

## Conformance Vectors (ADR-MCPS-011)

- **Revocation propagation:** revoke on node A → node B rejects within `T`.
- **Fail-closed at `T` under outage:** trust store unreachable → node serves
  cached active until `T`, then `mcps.trust_resolver_unavailable`.
- **Restart fail-closed:** a verifier starting with no valid cache and an
  unreachable store rejects all protected requests.
- **No indefinite stale-active:** a node cannot accept a revoked key past `T`
  even with the store down.
- **Negative-cache classification:** `Revoked`/`Disabled` deny stably;
  `NotFound` expires on a short TTL so a freshly published key is accepted
  promptly; `Unavailable` is never cached and always fails closed.
- **Strictest-`T` selection:** a request in a stricter sensitivity class uses its
  stricter `T`, not the global default.
- **Rotation overlap:** new key accepted fleet-wide only after the tier's
  publish rule; the prior key accepted through the drain window; rejected after
  revoke.
- **Tier 3 channel failure:** push-invalidation channel down → fall back to `T`
  or fail closed, never indefinite cache.
- **Tier 3 monotonicity:** an out-of-order/duplicate "active" update does NOT
  re-enable a revoked key.
- **`T` ceiling warning:** configuring `T` above the recommended max emits a
  warning (capped in strict mode if overridden).

## Rationale

Revocation's safe direction is the opposite of replay's, so it needs its own
threat model even though it shares the storage tiers. A bounded `T` is honest
and practical: requiring a live CP check on every request would be stronger but
imposes latency/availability costs many deployments will not accept. The
sensitivity-class override lets admin/mutation paths buy a tighter window or live
checks without taxing every low-risk tool. The existing fail-closed semantics
(`trust_resolver_unavailable`) already give the safe direction; `T`, the negative
caching rules, and the restart rule bound how long any stale belief can survive.

## Alternatives Considered

- **Mandatory live check (zero window) by default** — rejected: latency and
  store-availability cost; offered as Tier 2 for high-risk classes.
- **Single global `T` with no overrides** — rejected: forces low-risk and
  high-risk paths to the same window.
- **Fold into ADR-MCPS-020** — rejected: mirrored failure direction and
  different operational consequence warrant a separate decision.
- **Uniform negative caching** — rejected: caching `NotFound` like `Revoked`
  suppresses rotation keys; caching `Unavailable` at all breaks fail-closed.

## Consequences

### Positive
- Revocation has a stated, bounded, fail-closed exposure window; rotation is
  safe by construction; high-risk paths can tighten independently.

### Negative
- Operators must reason about `T`, sensitivity classes, and negative-cache TTLs.

### Neutral
- Reuses 020's store tiers; a CP/push backend upgrades the window without an
  architectural change.

## Compliance and Enforcement

`security-boundary.md`: *"Within one trust domain, key revocation is enforced
fleet-wide within the configured trust-propagation window `T`, provided all
nodes use the shared trust source and fail closed after cache expiry. A node may
use cached active trust state only until `T`; a restart without a valid cache and
a reachable store fails closed. An unconditional near-zero-window revocation
claim requires a live/linearizable lookup or reliable monotonic push
invalidation."*

Normative requirements: classify negative results as above; never cache
`Unavailable`; fail closed on restart without cache+store; log tier + `T` at
startup and the enumerated trust events; use the strictest applicable `T`.

## Related

- ADR-MCPS-007 (Trust Resolution, Key Rotation, Revocation Model)
- ADR-MCPS-020 (storage-tier vocabulary reused here)
- ADR-MCPS-022 (per-node key anchor governed by this ADR's propagation window)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- Push-invalidation transport (Tier 3) — reuse the replay store's pub/sub, or a
  dedicated channel with its own ordering/delivery guarantees.
- The concrete set of named sensitivity classes and how a request is mapped to
  one (policy-driven, per ADR-MCPS-013).
