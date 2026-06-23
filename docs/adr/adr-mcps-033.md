<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-033: v0.5 Claim Matrix — Two Cross-Linked Sections; NSA Matrix Derived From §A

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Resolved in the v0.5 grill; ratified by the owner HITL
sign-off in [ADR-MCPS-036](adr-mcps-036.md). Derives from PRD
[#148](https://github.com/matssun/mcps/discussions/148).

## Context

The live claim artifact is [`docs/spec/v0.3-claim-matrix.md`](../spec/v0.3-claim-matrix.md):
a **four-axis deployment-tier matrix** (replay durability, trust propagation, key
custody, ingress binding) whose composed claim is the AND of the declared tiers,
bounded by the weakest ([ADR-MCPS-020](adr-mcps-020.md)..[023](adr-mcps-023.md)).
Two problems:

1. **Version-label drift.** The file is named `v0.3-…` but its body already contains
   v0.4 content (epic #68 "v0.4 Axis 1," `LINEARIZABLE` #69, `LIVE`/`PUSH` #70,
   `lb_assertion` Tier 3 #71). The filename lies about its contents.
2. **Shape mismatch with the proposal need.** The v0.5 seed (§5.4) proposed a *flat*
   per-capability claim-wording matrix (Allowed / Forbidden / Required conformance /
   Residual) for external reviewers. A flat list placed next to the tiered matrix
   would drift — e.g. "replay resistance is strong" (flat) vs "replay strength is
   tier-dependent" (tiered).

The seed also wanted a separate NSA/threat-coverage matrix (§5.2). If that carries
its own conformance mapping it becomes a second claim system that drifts from the
first.

## Decision

The v0.5 claim matrix lives in a **single canonical file**
`docs/spec/v0.5-claim-matrix.md` — created during the 0.5 implementation (issue
#152); it does not yet exist on `main`, where only `docs/spec/v0.3-claim-matrix.md`
is present — superseding `v0.3-claim-matrix.md` (which becomes a
redirect/superseded stub), structured as **two cross-linked sections**, and the
**NSA/threat-coverage matrix is derived from §A** rather than carrying an
independent conformance mapping.

Specifically:

1. **§A — Capability-claim matrix (reviewer-facing).** One row per security
   property (message authenticity, integrity, signer identity, audience binding,
   delegation/authorization binding, freshness, replay resistance, response
   binding, verified context, **tool safety = none, by design**). Columns: Allowed
   wording / Forbidden wording / Required conformance test / Residual.
2. **§A classification rule — exactly two categories, no third.** Each capability is
   either **unconditional** (e.g. authenticity, integrity, response binding) and
   stated flat, or **"deployment-dependent; see §B"** (replay resistance,
   revocation/trust, ingress binding, key custody) and must reference §B rather than
   restate a strength.
3. **§B — Deployment-tier matrix.** The existing four-axis composition carried
   forward, with the v0.4 results folded in (correcting the version-label drift).
   Strict multi-node production minimum remains `REDIS_WAIT_QUORUM` or stronger
   ([ADR-MCPS-020](adr-mcps-020.md)); never invent a new threshold.
4. **Replay naming disambiguation.** §A distinguishes the **single-node local replay
   profile** (one proxy, file-backed cache, instance-bounded;
   [ADR-MCPS-017](adr-mcps-017.md)) from the **single shared store fail-closed
   tier** (a multi-node Axis-1 tier). The word "single" is never used loosely for
   both.
5. **NSA/threat-coverage matrix references §A.** Each row points to a §A capability
   claim (Direct / Partial) or to a non-goal + the relevant guard (Out of scope).
   It carries no independent test mapping — one evidence spine
   ([ADR-MCPS-036](adr-mcps-036.md)).
6. **Coverage split.** Audience binding = **Direct**; delegation
   (`on_behalf_of` + `authorization_hash`) = **Partial** — never the fuzzy
   "Partial/Direct" cell. Authorization wording per [ADR-MCPS-013](adr-mcps-013.md):
   Core binds, the AuthorizationProfile interprets.

## Rationale

Reviewers use the capability view and the tier view together, so one file with two
linked sections beats two files that drift. The "unconditional or see §B" rule is
the load-bearing constraint: it makes it impossible for the flat reviewer-facing
claims to silently override the tiered deployment reality. Deriving the NSA matrix
from §A means a change to a claim propagates automatically instead of requiring two
edits.

## Alternatives Considered

- **Two separate files (capability matrix, tier matrix).** Rejected: predictable
  drift between them; reviewers need them together.
- **Replace the tiered matrix with a flat list.** Rejected: discards the
  hard-won, honest tier semantics from ADR-020..023.
- **Independent conformance mapping for the NSA matrix.** Rejected: a second
  evidence spine that will drift from §A.

## Consequences

### Positive
- One claim file; capability and deployment views cannot contradict each other.
- The NSA matrix tracks §A automatically; no parallel claim system.

### Negative
- §A authors must classify every capability as unconditional or deployment-dependent
  — a small upfront discipline cost.

### Neutral
- `v0.3-claim-matrix.md` survives only as a superseded stub for historical links.

## Compliance and Enforcement

The proposal-readiness gate ([ADR-MCPS-036](adr-mcps-036.md)) requires every §A
capability claim to map to a named green test in `security_traceability_manifest.json`;
a §A row with no backing test fails the gate. The forbidden-claim guard checks that
§A's forbidden wording (e.g. "prevents all duplicate business operations,"
"unconditional multi-node replay," "tool safety") does not appear as an asserted
claim. No automated check enforces the "must reference §B" link — code review owns
that, a known residual.

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-020](adr-mcps-020.md)..[023](adr-mcps-023.md) (the four axes), [ADR-MCPS-017](adr-mcps-017.md) (single-node ceiling), [ADR-MCPS-013](adr-mcps-013.md) (authorization profile)
- Sibling v0.5 ADRs: [031](adr-mcps-031.md), [032](adr-mcps-032.md), [035](adr-mcps-035.md), [036](adr-mcps-036.md)
- Code/docs: `docs/spec/v0.3-claim-matrix.md` → `docs/spec/v0.5-claim-matrix.md`
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
