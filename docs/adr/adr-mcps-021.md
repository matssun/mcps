<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-021: Shared Trust State — Bounded Trust-Propagation Window for Revocation and Rotation

## Status

Accepted (targets v0.3). Sibling of ADR-MCPS-020 (shared replay state); both
reuse one storage-tier framework. Partially lifts the multi-node limitation
recorded in ADR-MCPS-017 for trust/key-status state only.

## Context

ADR-MCPS-007 makes the `TrustResolver` authoritative at verification time,
represents rotation as multiple `key_id`s per signer and revocation as
removing/disabling a mapping, permits **only bounded-TTL caching** of resolver
results, and bounds the revocation exposure window at `resolver_cache_ttl +
max_request_lifetime + max_clock_skew`. ADR-MCPS-006 makes the analogous
statement for replay: horizontally-scaled verifiers **MUST share replay state**.
ADR-MCPS-019 then shipped the multi-node backends (shared atomic `ReplayCache`
over Redis; online OCSP/CRL revocation) — but as feature-gated mechanisms, not
as a normative cross-node propagation model.

ADR-MCPS-020 supplies that model for **replay state**. This ADR supplies it for
**shared trust state**: key status, revocation, and rotation across a fleet of
verifiers in one trust domain. It is deliberately a **distinct** ADR rather than
a clause of ADR-MCPS-020, because the failure direction and operational
consequences of stale trust state are not the same as those of stale replay
state (see Rationale).

The gap ADR-MCPS-007 leaves open and this ADR closes: the *multi-node*
propagation guarantee, the default and ceiling for the cache TTL, the behavior
of a node whose trust store is unreachable, and the timing rule for rotation so
a new key is never used before the fleet can verify it.

## Decision

ADR-MCPS-021 is a separate ADR that reuses ADR-MCPS-020's storage-tier
framework and defines a **bounded trust-propagation window `T`** for shared
trust state. `T` is ADR-MCPS-007's `resolver_cache_ttl`, named here as the
**documented revocation exposure window**. The window is bounded and short by
default; it is **not** a mandatory zero-window, and it is never marketed as
zero-window revocation.

### Normative claim (v0.3)

> Within one trust domain, key revocation is enforced fleet-wide within the
> configured trust-propagation window `T`. A node may use cached active trust
> state only until `T` expires; after that, trust-store unavailability fails
> closed.

An unconditional near-zero-window revocation claim is **not** made by Tier 1 and
requires a linearizable trust store, a live check, or a push-invalidation
mechanism (Tier 2 / Tier 3 below).

### Fail-closed rule (normative)

- A trust resolver MAY cache active key state for at most `T`.
- If the trust store is unavailable, a node MAY use cached active state **only
  until `T` expires**.
- After `T`, trust resolution MUST fail closed with
  `mcps.trust_resolver_unavailable` (the resolver-operational-failure error from
  ADR-MCPS-007), distinct from the `mcps.actor_binding_failed` key-invalid
  verdict.
- A node MUST NEVER serve indefinitely from stale "active" trust state.

### Default and ceiling for `T`

- **default `T` = 60 seconds**;
- **maximum recommended `T` = 5 minutes**;
- **high-risk admin / mutation paths: `T` ≤ 60 seconds, or a live check**.

If an operator configures `T` above 5 minutes, the proxy SHOULD warn. A
strict/production mode MAY cap `T` at the recommended maximum unless explicitly
overridden. Live CP (control-plane) checks on every request are **not** required
by default — that strengthens the window to near-zero but imposes latency and a
trust-store availability dependency many deployments will not accept.

### Rotation rule (normative)

A signer rotates keys publish-before-use:

1. **Publish** the new key (a new `(signer, key_id)` mapping in the trust
   store) first.
2. **Wait ≥ `T`** so the new key propagates to all verifiers' caches.
3. **Only then begin signing** with the new key.
4. **Keep the old key active** until in-flight requests drain — at least
   `max_request_lifetime + max_clock_skew`.
5. **Revoke/disable the old key** (drop the mapping).

Beginning to sign with a new key before `T` elapses causes some verifiers to
reject valid requests. That is an **availability** failure, not a security
bypass — but it is a real operational fault and the rule exists to prevent it.

### Storage tiers (trust state)

The same tier framework as ADR-MCPS-020, applied to trust/key-status state:

- **Tier 1 — bounded-cache eventual trust.** Shared trust store; resolver cache
  TTL = `T`; revocation enforced fleet-wide within `T`; on store outage, cached
  state is usable **only until `T`**, then fail closed. This is the default
  posture and the one the v0.3 claim describes.
- **Tier 2 — live strong trust check.** The resolver consults the shared store
  on every verification (or uses a linearizable read). Near-zero propagation
  window, at the cost of higher per-request latency and a hard dependency on
  trust-store availability.
- **Tier 3 — push invalidation.** Resolver caching is allowed, but a revocation
  event invalidates affected keys immediately. Requires reliable ordering and
  delivery; if the invalidation channel fails, it MUST fall back to the bounded
  `T` (or fail closed). Tier 3 is **not** called "zero window" unless its push
  mechanism has reliable ordering/delivery and explicit failure handling —
  otherwise it is "near-zero with bounded fallback."

## Rationale

Replay state and trust state fail in opposite directions, which is why they are
separate ADRs even though they share storage tiers:

| State | Dangerous failure | Safe direction | Effect of stale state |
|---|---|---|---|
| **Replay** | forgetting a nonce | over-remembering | usually DoS |
| **Revocation** | continuing to trust a revoked key | removing trust quickly | security exposure |
| **Rotation** | using a new key before all verifiers know it | publish-before-use | availability failure |

Over-remembering replay state is safe; over-remembering trust state is a
security exposure. A single ADR would force one threat model onto two problems
with inverted risk. Hence ADR-MCPS-021 carries its own threat model while
inheriting ADR-MCPS-020's storage mechanics.

Bounded `T` (rather than a mandatory live check) is the honest and practical
boundary: it states the revocation exposure window explicitly, keeps it short
and visible, and fails closed once it elapses — without imposing per-request
control-plane latency and availability coupling on deployments that cannot
accept it. Deployments that need a stronger guarantee opt into Tier 2 or Tier 3.

## Alternatives Considered

- **Fold the decision into ADR-MCPS-020 (one shared-state ADR).** Rejected —
  replay and revocation have inverted failure directions; conflating them hides
  the asymmetry and the distinct fail-closed obligations.
- **Mandate a live/linearizable trust check on every request (zero-window by
  default).** Rejected as the default — stronger, but adds latency and a
  trust-store availability dependency many deployments will not accept. Retained
  as opt-in Tier 2.
- **Leave `T` unspecified, as in ADR-MCPS-007.** Rejected — an unbounded or
  undocumented TTL silently extends the revocation exposure window; v0.3 fixes a
  short default and a recommended ceiling with an operator warning.
- **Market Tier 3 as zero-window revocation.** Rejected — without reliable
  ordering/delivery and failure handling, push invalidation is near-zero with a
  bounded-`T` fallback, and must be described as such.

## Consequences

### Positive
- Revocation exposure is bounded, short, explicit, and fleet-wide-enforced
  within `T`; fails closed after `T`; rotation can never use a key the fleet
  cannot yet verify.

### Negative
- Tier 1 does not provide zero-window revocation; the exposure window is `T`
  (within the broader `T + max_request_lifetime + max_clock_skew` envelope from
  ADR-MCPS-007). Stronger guarantees require Tier 2/Tier 3 and their costs.

### Neutral
- Reuses ADR-MCPS-007's error taxonomy (`mcps.trust_resolver_unavailable`,
  `mcps.actor_binding_failed`) unchanged; the trust store may be backed by a
  shared snapshot, a live service, or a push-fed cache per tier.

## Compliance and Enforcement

- Config validation: reject `T` ≤ 0; warn when `T` > 5 minutes; in
  strict/production mode, cap `T` at the recommended maximum unless explicitly
  overridden; flag admin/mutation routes configured with `T` > 60 s and no live
  check.
- Conformance vectors: (a) a revoked key is rejected fleet-wide within `T`;
  (b) a trust-store outage past `T` yields `mcps.trust_resolver_unavailable`
  (fail closed), never a stale "active" allow; (c) publish-before-use rotation —
  a key used before `T` produces verifier rejections, and a key used after the
  `T`-wait verifies fleet-wide.
- Tier 3 deployments MUST demonstrate the bounded-`T` (or fail-closed) fallback
  when the invalidation channel is interrupted.

## Related

- Depends on / refines: ADR-MCPS-007 (Trust Resolution, Key Rotation, and
  Revocation Model) — `T` is its `resolver_cache_ttl`; this ADR adds the
  cross-node propagation guarantee, default/ceiling, post-outage fail-closed
  rule, and rotation timing.
- Sibling: ADR-MCPS-020 (shared replay state) — same storage-tier framework,
  inverted failure direction (see Rationale).
- Parent of the replay analogue: ADR-MCPS-006 (Freshness and Replay Model).
- Implements over: ADR-MCPS-019 (Phase 7 external backends — shared atomic
  ReplayCache, online OCSP/CRL revocation).
- Lifts (for trust state only): ADR-MCPS-017 (single-node production claim
  ceiling).
