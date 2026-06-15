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
becomes replayable on the new primary. The same loss can occur on a single store
that restarts from a state missing recently-accepted nonces.

## Definitions

`freshness_window` means the maximum interval during which an already-signed
request may still be accepted by an MCP-S verifier: `request_lifetime +
max_clock_skew`, or equivalently the effective interval until `expires_at +
max_clock_skew`. It is the same quantity the in-process caches fold into each
entry's `retain_until`. Operators MUST read every "bounded by `freshness_window`"
statement in this ADR against that definition.

## Decision

Specify replay durability as a **contract on the `SharedReplayStore`
abstraction**, not as a Redis property. Redis is the first practical backend; it
does not define correctness.

The required store operation is: *atomically insert `(signer, audience, nonce)`
if absent, with a TTL derived from `expires_at + max_clock_skew`, fail closed on
error*, and **declare a durability tier**. The strength of the v0.3 replay claim
is a function of the declared tier. Tiers carry **semantic names** (operators
quote these) rather than bare letters:

| Declared tier | Store posture | Guarantee | Cost |
|---|---|---|---|
| `REDIS_ASYNC` | Async Redis replication + failover (vanilla Sentinel/Cluster) | Replay-safe in steady state; a failover or restart-with-state-loss may reopen a replay window **bounded by `freshness_window`** | Cheap, standard ops |
| `REDIS_WAIT_QUORUM { quorum, timeout_ms }` | Redis `SET NX` + `WAIT <quorum> <timeout>` | Materially reduces failover replay risk; `WAIT` timeout / insufficient acks **fail closed**. **Not** linearizable / not unconditional | Per-call latency |
| `LINEARIZABLE` | CP / linearizable store (etcd txn put-if-absent-under-lease, Consul, ZK, SQL serializable + unique key, FoundationDB) | **Strongest** horizontal replay-safety claim, *conditional* on the store's documented durable linearizable write guarantee **and** correct MCP-S freshness enforcement | Store availability dependency |
| `SINGLE_STORE_FAIL_CLOSED` | Single store, no failover | Strong **only** under the fail-closed invariant below | Store is a single point of *availability* failure |

The basis for the strongest claim is `LINEARIZABLE`. No tier is described as
"unconditional": every guarantee is conditional on the declared store contract
and on MCP-S verification being correctly configured.

### `SINGLE_STORE_FAIL_CLOSED` invariant

This tier is valid only if **all** verifier instances reject protected requests
whenever the store is unavailable, **or** has restarted from a state that may
have lost accepted nonces, and continue rejecting until `freshness_window` has
elapsed since the last possible accepted write. "No failover" avoids
replica-promotion loss but not all forms of state loss (persistence disabled,
partial restart): the real invariant is *no acknowledged nonce may be forgotten
while still fresh, or the fleet fails closed until it cannot matter.*

### TTL handling

Backend TTLs MUST be computed from the remaining validity interval and **rounded
up, never down**, when converting from a timestamp/skew duration to backend TTL
units — rounding down can expire an entry while its nonce is still replayable. A
**non-positive** remaining TTL means the request is already stale and MUST be
rejected before the shared store is consulted. (Extends the existing H-8/H-9
window fix.)

### Operational errors

Store timeouts, connection loss, malformed backend replies, insufficient `WAIT`
acknowledgements, and backend permission/authentication errors are **operational
replay-store errors** and MUST fail closed as `mcps.replay_cache_unavailable`. No
backend failure may be treated as "probably `Fresh`."

### Tier declaration is a deployment assertion

A durability tier is a **deployment assertion**, not merely a backend type. The
same backend implementation may support different tiers depending on topology and
configuration — a Redis adapter can be deployed async, `WAIT`-quorum, or
single-store fail-closed. The trait therefore separates **backend-reported
capability** from **declared deployment tier**:

```rust
pub enum ReplayDurabilityTier {
    RedisAsyncBounded,
    RedisWaitQuorum { quorum: u32, timeout_ms: u64 },
    Linearizable,
    SingleStoreFailClosed,
}
```

The proxy surfaces the configured tier, enforces the behavior it controls
(e.g. issuing `WAIT` and failing closed on insufficient acks), and refuses
impossible combinations — but it **cannot independently prove** all external
store topology properties (whether Sentinel/Cluster failover is enabled, whether
ops will fail closed after a restart). The ADR states this honestly: the tier is
verified as far as backend configuration allows and asserted by the operator for
the rest.

### Startup and audit logging

At startup the proxy MUST log the configured replay-store backend and declared
durability tier. On every replay-store operational error it MUST log the backend,
tier, operation, and fail-closed reason. Nonce material MUST NOT be logged in
plaintext unless explicitly configured for debug; the default is to hash or
truncate nonce values (they are sensitive correlation material).

## Threat Model

- **Trust boundary:** one operator (per the v0.3 claim-unit decision); the
  shared store is *inside* the trust boundary. Adversary = external client
  (replay, tamper) and hostile inner server — **not** a hostile peer node or a
  malicious store.
- **Primary threat:** an attacker replays a previously-accepted signed request
  to a node that has no record of its nonce.
- **Failure-induced window (`REDIS_ASYNC` / `REDIS_WAIT_QUORUM`):** a failover —
  or a single-store restart from lost state — drops nonces acknowledged but not
  durably retained. Exposure is bounded: only nonces accepted within
  `freshness_window` before the event, and not yet durably stored, are
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
- **TTL rounds up:** a remaining interval that does not divide evenly into
  backend units yields a TTL ≥ the interval, never `<`.
- **Non-positive TTL rejects pre-store:** an already-stale request is rejected
  before the store is consulted.
- **Operational-error classification:** each of timeout / connection loss /
  malformed reply / insufficient `WAIT` acks / auth error maps to
  `mcps.replay_cache_unavailable`, never `Fresh`.
- **`REDIS_WAIT_QUORUM` fail-closed:** insufficient replica acks within timeout →
  fail closed (requires a live multi-replica backend in the e2e suite).
- **`SINGLE_STORE_FAIL_CLOSED` restart:** a store restart that may have lost
  state → the fleet rejects protected requests until `freshness_window` elapses.
- **Tier-claim ceiling:** a store declaring `REDIS_ASYNC` must not let the proxy
  emit a `LINEARIZABLE` claim.

## Rationale

ADR-MCPS-017 demands each enterprise capability name the contract it depends on
rather than over-claim. Pinning durability to the abstraction (not Redis) keeps
the claim honest across backends and lets a future `CPStore` backend deliver the
strongest claim without a refactor — the `AtomicReplayStore` seam already exists.
The freshness window doubles as the failure blast-radius cap, which is why short
freshness windows are operationally important here. Naming tiers semantically
prevents a reader from misjudging which posture is stronger.

## Alternatives Considered

- **Mandate a CP store, refuse async Redis** — rejected: most operators run
  Sentinel/Cluster; a bounded, *documented* caveat is more useful than a refusal.
- **Force `WAIT` on by default** — rejected: latency tax most single-region
  operators do not need; offered as the recommended high-assurance Redis mode.
- **Call any tier "unconditional"** — rejected as dishonest; every guarantee is
  conditional on the store contract and correct MCP-S freshness enforcement.
- **Bare A/B/C/D tier letters** — rejected: security operators quote these; the
  names must carry their own strength meaning.

## Consequences

### Positive
- Honest, tier-explicit replay claim; a future `CPStore` reaches the strongest
  claim with no architectural change.

### Negative
- Operators must understand store durability to know their claim tier; the proxy
  must surface the tier it is running under and cannot prove all of it.

### Neutral
- Redis remains the default practical backend; the contract, not Redis, is
  normative.

## Compliance and Enforcement

`security-boundary.md`: *"Horizontal replay safety is supported within one trust
domain when all proxy instances share an atomic ReplayCache. The strength of the
claim depends on the store durability mode: async Redis failover carries a
bounded replay caveat ≤ freshness window; the strongest claim requires a durable
linearizable store contract."*

Normative requirements:

- The proxy MUST fail closed on store unavailability and on every operational
  store error enumerated above, with `mcps.replay_cache_unavailable`.
- The proxy MUST surface the configured durability tier and MUST NOT emit a claim
  stronger than that tier.
- Backend TTLs MUST round up; non-positive TTLs MUST reject pre-store.
- The proxy MUST log backend + tier at startup and on every replay-store error,
  without plaintext nonce material by default.

### WAIT-quorum shortfall: retry semantics (Tier `REDIS_WAIT_QUORUM`)

The `REDIS_WAIT_QUORUM` insert is a `SET … NX PX` on the primary **followed by**
`WAIT <quorum> <timeout>`. The `SET NX` lands on the primary *before* `WAIT` runs,
so the two steps are not a single atomic unit. When `WAIT` reports fewer than
`quorum` acknowledgements (or errors), the nonce IS present on the primary but is
NOT durably replicated. The proxy MUST:

- **fail closed** for that request with `mcps.replay_cache_unavailable`
  (`OpAttempt::Fatal` — it MUST NOT be retried internally, because re-running the
  non-idempotent `SET NX` would find the just-written key and wrongly report
  `Replay`); and
- **NOT** issue a compensating `DEL`/`UNLINK` of the primary key. The write may
  already have reached one or more replicas; deleting it under that uncertainty
  could reopen a replay window — which would violate the durability-over-
  availability guarantee this tier exists to provide.

The consequence is a bounded **availability** cost, never a replay-safety hole:
re-submitting the *same signed request / same nonce* may be rejected as `Replay`
until the `PX` window elapses. The **client contract** is therefore that a
`replay_cache_unavailable` outcome is *retryable by re-signing with a FRESH
nonce* — a new nonce is a new key and inserts `Fresh`. Clients MUST NOT replay
the identical envelope after this error.

A compensating cleanup that trades this availability edge for added complexity
(and a carefully-modelled, replica-state-aware delete) is a possible FUTURE
amendment to this ADR; the v0.3 decision is recorded in **Amendment 1** below.

## Amendment 1 (2026-06-15): WAIT-quorum shortfall contract ratified — no compensating `DEL`/`UNLINK` in v0.3

Amendment status: **Accepted (v0.3)** (this ratifies only the v0.3
WAIT-quorum shortfall contract point; the ADR overall remains Proposed / under
review). Supersedes the "possible future / deferred" framing of the preceding
section for the purpose of the v0.3 contract: the keep-the-nonce / fail-closed
behavior is the **ratified v0.3 default**, and a compensating `DEL`/`UNLINK` is
**rejected for v0.3** (not merely deferred). This amendment makes the contract
explicit so its distributed proof (issue #41) tests a settled behavior rather
than an incidental one.

### Ratified contract (Tier `REDIS_WAIT_QUORUM`)

On a Redis WAIT-quorum shortfall (fewer than `quorum` acknowledgements — including due
to timeout — or a `WAIT` error), the durable replication state of the just-written
nonce is **unknown** to the proxy. Under that uncertainty the proxy MUST:

1. **Fail closed** for that request with `mcps.replay_cache_unavailable`
   (`OpAttempt::Fatal`); the outcome is a distinct, *retryable* error, **never** a
   silent admit.
2. **Never report `Fresh`** for the request after a shortfall. A shortfall is not a
   successful insert.
3. **Not** attempt a compensating `DEL`/`UNLINK` of the primary key.
   The nonce **may be burned** on the primary (and may already have reached one or
   more replicas).
4. Accept that the **same signed request with the same nonce is NOT guaranteed
   retryable** — it may be rejected as `Replay` until the `PX` window elapses.
5. Require the **client to re-sign with a FRESH nonce**; a new nonce is a new key
   and inserts `Fresh` once the store is healthy. Clients MUST NOT replay the
   identical envelope after this error.

### Rationale

A WAIT shortfall means the system does **not** know whether the `SET NX` replicated.
A compensating delete is an *availability* improvement, but under unknown
replication state it can delete a nonce that already reached a replica and thereby
**reopen a replay window** — converting an availability nuisance into a replay-safety
defect. The security-honest default is therefore to keep the nonce and surface a
retryable error. The bounded cost is availability (a same-nonce retry may be
refused), never replay safety.

### Conditions to revisit (post-v0.3)

A future amendment MAY introduce a compensating cleanup **only** if it is a
replica-state-aware delete that provably never removes a nonce that reached any
replica, and only after it is verified against a real multi-replica topology under
induced replica lag. Absent that proof, the v0.3 contract above stands.

### Proof obligation (issue #41)

The ratified contract is verified on a real multi-replica Redis in the live-infra
lane: induce a WAIT shortfall / replica lag, then assert (a) the insert fails closed
as `mcps.replay_cache_unavailable`, (b) the request is never treated as `Fresh`
after the shortfall, (c) a same-nonce retry behaves as the contract states (may be
rejected as `Replay`), and (d) a fresh-nonce retry succeeds once the cluster is
healthy.

## Related

- ADR-MCPS-006 (Freshness and Replay Model)
- ADR-MCPS-017 (deferred this capability)
- ADR-MCPS-021 (reuses this tier vocabulary for trust state)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- Whether a first-class `CPStore` (`LINEARIZABLE`, e.g. etcd) backend ships in
  v0.3 or is named as the reference for a later point release.
- Whether the proxy should refuse to start in a strict/production mode unless the
  declared tier is `REDIS_WAIT_QUORUM` or stronger.
