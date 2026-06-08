<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-020: Distributed Atomic Replay Store — Durability Contract for Horizontally-Scaled Replay Safety

## Status

Proposed (v0.3 sketch — under review)

## Context

ADR-MCPS-006 defines replay protection as a caller-injected `ReplayCache`
keyed by `(signer, audience, nonce)`, consulted after signature verification,
failing closed (`mcps.replay_cache_unavailable`) on any operational error. The
v0.2 codebase already carries the horizontally-scaled mechanism:

- `mcps_core::ReplayCache` — the trait, whose doc already states "in a
  distributed deployment the verifiers MUST share replay state."
- `mcps_proxy::AtomicReplayStore` — the backend-agnostic shared primitive: a
  single server-side-atomic *insert-if-absent-with-TTL*.
- `SharedReplayCache` — `ReplayCache` over a `Box<dyn AtomicReplayStore>`, with
  a collision-safe length-prefixed composite key, identical clock-skew folding,
  fail-closed on store error.
- `RedisAtomicReplayStore` — the `redis_replay`-gated Redis adapter (`SET key 1
  NX PX <ttl>`), with bounded connect/handshake watchdog, single-reconnect
  resilience, and the H-8/H-9 TTL-window fix.
- `cross_instance_insert_via_a_is_replay_via_b` — the load-bearing test proving
  cross-node rejection over one shared store.

ADR-MCPS-017 deferred "horizontal-scale replay" as needing its own ADR and
threat model. **This is that ADR.** The mechanism exists; what is missing is the
*durability contract* the shared store must satisfy, and an honest statement of
the guarantee under store failure. `SET NX` is atomic on the Redis primary, but
Redis replication is asynchronous: a nonce acknowledged by a primary that
crashes before replicating, followed by replica promotion, is *forgotten* — and
becomes replayable on the new primary.

## Decision

Specify replay durability as a **contract on the `SharedReplayStore`
abstraction**, not as a Redis property. Redis is the first practical backend; it
does not define correctness.

The required store operation is: *atomically insert `(signer, audience, nonce)`
if absent, with TTL `= expires_at + max_clock_skew`, fail closed on error*, and
**declare a durability tier**. The strength of the v0.3 replay claim is a
function of the declared tier:

| Tier | Store posture | Guarantee | Cost |
|---|---|---|---|
| **A** | Async Redis replication + failover (vanilla Sentinel/Cluster) | Replay-safe in steady state; a failover may reopen a replay window **bounded by `freshness_window`** | Cheap, standard ops |
| **B** | Redis `SET NX` + `WAIT <quorum> <timeout>` | Materially reduces failover replay risk; `WAIT` timeout / insufficient acks **fails closed**. **Not** linearizable / unconditional | Per-call latency |
| **C** | CP / linearizable store (etcd txn put-if-absent-under-lease, Consul, ZK, SQL serializable + unique key, FoundationDB) | **Unconditional** horizontal replay safety under the store's documented linearizable/durable write guarantee | Store availability dependency |
| **D** | Single Redis, no failover | Unconditional **only if** store loss makes the fleet fail closed until all possibly-fresh requests expire | Store is a single point of *availability* failure |

The `AtomicReplayStore` trait gains a way to **declare its durability tier**, so
the proxy knows which claim it is entitled to make and can log/enforce it; the
`security-boundary.md` claim is matched to the *deployed* backend, not assumed.

`WAIT` is **not** described as a full strong-consistency/linearizability
guarantee — Redis documents that `WAIT` improves replication durability but does
not make Redis strongly consistent.

## Threat Model

- **Trust boundary:** one operator (per the v0.3 claim-unit decision); the
  shared store is *inside* the trust boundary. Adversary = external client
  (replay, tamper) and hostile inner server — **not** a hostile peer node or a
  malicious store.
- **Primary threat:** an attacker replays a previously-accepted signed request
  to a node that has no record of its nonce.
- **Failure-induced window (Tier A/B):** a primary failover loses nonces
  acknowledged but unreplicated. Exposure is bounded: only nonces accepted
  within `freshness_window` before the failover, and not yet replicated, are
  replayable — past that window the request is stale and rejected regardless.
- **Excluded from this threat model:** a compromised store that suppresses
  entries (→ enable replay) or forges them (→ DoS). The one-operator claim
  trusts the store for integrity and defends only against its *unavailability*
  (fail closed). A hostile store is deferred to a future hardened-store profile.

## Conformance Vectors (ADR-MCPS-011)

- **Cross-node atomicity:** nonce accepted on node A → rejected as replay on
  node B over one shared store. (Exists for the in-memory store; extend to each
  backend.)
- **Fail-closed on store outage:** store unreachable → `mcps.replay_cache_unavailable`,
  never `Fresh`.
- **TTL is the window, not the epoch:** the H-8/H-9 regression vector.
- **Tier-B `WAIT` fail-closed:** insufficient replica acks within timeout →
  fail closed (requires a live multi-replica backend in the e2e suite).
- **Tier declaration:** a store declaring Tier A must not let the proxy emit a
  Tier-C unconditional claim.

## Rationale

ADR-MCPS-017 demands each enterprise capability name the contract it depends on
rather than over-claim. Pinning durability to the abstraction (not Redis) keeps
the claim honest across backends and lets a future `CPStore` backend deliver the
unconditional claim without a refactor — the `AtomicReplayStore` seam already
exists. The freshness window doubles as the failover blast-radius cap, which is
why short freshness windows are operationally important here.

## Alternatives Considered

- **Mandate a CP store, refuse async Redis** — rejected: most operators run
  Sentinel/Cluster; a bounded, *documented* caveat is more useful than a refusal.
- **Force `WAIT` on by default** — rejected: latency tax most single-region
  operators do not need; offered as the recommended high-assurance Redis mode.
- **Call `WAIT` "unconditional"** — rejected as dishonest; `WAIT` is not
  linearizability.

## Consequences

### Positive
- Honest, tier-explicit replay claim; a future `CPStore` reaches the strongest
  claim with no architectural change.

### Negative
- Operators must understand store durability to know their claim tier; the proxy
  must surface the tier it is running under.

### Neutral
- Redis remains the default practical backend; the contract, not Redis, is
  normative.

## Compliance and Enforcement

`security-boundary.md`: *"Horizontal replay safety is supported within one trust
domain when all proxy instances share an atomic ReplayCache. The strength of the
claim depends on the store durability mode: async Redis failover carries a
bounded replay caveat ≤ freshness window; an unconditional claim requires a
durable linearizable store contract."*

The proxy MUST fail closed on store unavailability and MUST NOT emit a
durability claim stronger than its declared store tier.

## Related

- ADR-MCPS-006 (Freshness and Replay Model)
- ADR-MCPS-017 (deferred this capability)
- ADR-MCPS-021 (reuses this tier vocabulary for trust state)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- Exact form of the tier declaration on `AtomicReplayStore` (enum return vs.
  constructor-time assertion vs. config).
- Whether a first-class `CPStore` (etcd) backend ships in v0.3 or is named as
  the Tier-C reference for a later point release.
