<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-037: Draft-02 Canonical Number Domain — Integer-Only, With a Documented Float Limitation

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([038](adr-mcps-038.md)–[042](adr-mcps-042.md)). Builds on the JCS-safe
canonicalization domain of [ADR-MCPS-005](adr-mcps-005.md).

## Context

MCP-S draft-02 (shipping as v0.6) defines a protected `canonicalization_id` and a
long-lived, allowlisted canonical scheme (see [038](adr-mcps-038.md)). That scheme's
JSON **number domain** must be fixed for the first release. The draft-01 canonicalizer
(`mcps-core/src/canonical.rs`, per [ADR-MCPS-005](adr-mcps-005.md)) is a hand-rolled
RFC 8785 (JCS) implementation with a deliberately strict "JCS-safe domain": numbers are
**integers only**, within ±(2^53 − 1); any fraction (`1.5`), exponent (`1e3`), or
out-of-range integer is rejected with `mcps.canonicalization_failed`. The signing
preimage canonicalizes the **complete** JSON-RPC object, `params`/`arguments` included.

The consequence was not previously stated plainly: an MCP message whose signed payload
contains a fractional number — `{"temperature":0.7}`, `{"price":19.99}`, a latitude, a
sampling parameter — **cannot be signed or verified** today. RFC 8785 itself *does*
define fractional-number serialization (the ECMAScript Number-to-String algorithm), so
draft-01 is a strict subset of JCS. The v0.6 grill forced the choice: keep the strict
domain, or expand the v1 scheme to full RFC 8785 floats.

## Decision

The first v0.6 canonicalization scheme **keeps the integer-only number domain**
(±(2^53 − 1)); fractional numbers, exponent-form numbers, and NaN/Inf are rejected
before signature verification, and the scheme is named **`mcps-jcs-int53-json-v1`** to
make the restriction visible on the wire.

## Rationale

Full RFC 8785 fractional-number serialization is the single highest-risk area for
independent implementations to disagree on byte-for-byte; admitting it into the first
security-critical scheme would widen exactly the cross-implementation divergence surface
that draft-02 exists to eliminate. The strict domain *is* the higher bar, not a
conservative hedge: it makes the preimage trivially reproducible across implementations.
Float support is not abandoned — it is deferred to a later, separately-named,
separately-vector-hardened scheme admitted through the profile-version allowlist
([038](adr-mcps-038.md)), so the migration mechanism, not a risky v1, carries it.

The prior candidate name `jcs-rfc8785-mcp-runtime-evidence-json-v1` was rejected as
misleading: it implies full RFC 8785 while the implementation is an integer-only subset.
`mcps-jcs-int53-json-v1` names the actual restriction.

## Alternatives Considered

- **Expand v1 to full RFC 8785 floats** (the answerer's recommendation). Rejected: it
  reopens the IEEE-754/ES6 number-formatting surface — the worst place to risk
  byte-divergence — on the first release; floats belong to a `…-v2` scheme proven after
  v1 is stable.
- **Keep integer-only but leave the limitation undocumented.** Rejected: a profile that
  silently cannot sign common MCP payloads is a hidden scope hole; the limitation must be
  explicit and machine-checked.
- **Do nothing (no named scheme).** Rejected: draft-02 requires a stable, allowlisted
  scheme id as protected evidence ([038](adr-mcps-038.md)).

## Consequences

### Positive
- The canonical preimage is trivially cross-verifiable; the hardest JCS interop surface
  is excluded from v1.
- The scheme name advertises the restriction; no implementer is surprised.

### Negative
- **MCP-S v0.6 does not protect MCP messages whose signed payload contains JSON
  fractional numbers.** Such messages fail closed with `mcps.canonicalization_failed`
  unless the values are represented outside the JSON number domain (e.g. as strings) or
  handled by a future scheme. This is an accepted, documented limitation, not a defect.

### Neutral
- Float support becomes a future `mcps-jcs-…-v2` scheme added via the allowlist, with its
  own exhaustive IEEE-754 vectors, before any verifier profile accepts it.

## Compliance and Enforcement

A **required** conformance vector proves a float-bearing signed payload (e.g. `0.7`,
`19.99`) is rejected with `mcps.canonicalization_failed` (see [042](adr-mcps-042.md)) —
the limitation is machine-checked, not merely documented. The integer safe-boundary
vectors (`±9007199254740991` accepted; out-of-range rejected) and the
fraction/exponent-rejection vectors (`jcs_04`, `jcs_05`) remain green. The scheme id
literal is pinned by the allowlist in [038](adr-mcps-038.md).

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (B.1), seed [`mcps-v0.6-seed.md`](../grilling-seed/mcps-v0.6-seed.md) §20.
- Builds on: [ADR-MCPS-005](adr-mcps-005.md) (JCS-safe canonicalization domain).
- Sibling v0.6 ADRs: [038](adr-mcps-038.md), [039](adr-mcps-039.md), [040](adr-mcps-040.md), [041](adr-mcps-041.md), [042](adr-mcps-042.md).
- Code: `mcps-core/src/canonical.rs`, `mcps-core/tests/vectors/`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
