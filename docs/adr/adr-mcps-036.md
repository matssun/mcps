<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-036: Proposal-Readiness Is a Dual Gate — Mechanical CI + Owner HITL — Over One Evidence Spine

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Resolved in the v0.5 grill. This ADR defines the gate
that the other v0.5 ADRs ([031](adr-mcps-031.md)–[035](adr-mcps-035.md)) are checked
against; it is itself ratified when the owner signs the boundary and claim-matrix
updates. Derives from PRD [#148](https://github.com/matssun/mcps/discussions/148).

## Context

PRD #148's success criteria require that an external reviewer can answer "what does
MCP-S secure / not secure / what proves it / how does it compose / why doesn't it
compete with tool-catalog work." "Proposal-ready" must therefore be a concrete,
checkable state, not a judgement call. The repo already has the machinery:
`conformance_manifest.json`, `security_traceability_manifest.json`, the
`mcps-conformance` drift guards ([ADR-MCPS-018](adr-mcps-018.md)),
"conformance-as-specification" ([ADR-MCPS-011](adr-mcps-011.md)), and a worked
HITL release-gate pattern (the owner-signed security-boundary doc, §7/§8.1). 0.5
should reuse that pattern rather than invent a new one.

## Decision

"MCP-S 0.5 proposal-ready" is defined as a **dual gate** — a mechanical CI gate
**and** an owner HITL sign-off — governed by the rule **"no traceability-mapped
green test, no proposal claim,"** with a **single evidence spine** feeding both the
claim matrix and the NSA/threat-coverage matrix.

**Mechanical gate (CI-green, machine-checkable):**

1. **Every §A capability claim** in `docs/spec/v0.5-claim-matrix.md` (the canonical
   claim matrix created during the 0.5 implementation per
   [ADR-MCPS-033](adr-mcps-033.md); not yet present on `main`) maps to at least
   one **named green test** in `security_traceability_manifest.json`.
2. **Method-transparency artifacts green** — behavioral equivalence test + static
   drift guard — mapped to [ADR-MCPS-030](adr-mcps-030.md) (per
   [ADR-MCPS-034](adr-mcps-034.md)).
3. **Audit-taxonomy drift guard green** — every rejection `reason` is a member of
   `McpsError::wire_code()` (per [ADR-MCPS-035](adr-mcps-035.md)).
4. **Forbidden-claim guard green** — forbidden wording from §A does not appear as an
   asserted claim in proposal-facing docs (e.g. "prevents tool poisoning,"
   "provides RBAC," "proves a signer is a safe agent," "proves on_behalf_of
   delegation is legitimate," `authorization_hash_mismatch`, "unconditional
   multi-node replay," "MCP-S secures all MCP," "validates tool descriptors").
   The guard scans proposal-facing docs, not every test fixture or historical ADR.
5. **Conformance and traceability manifests** are drift-guard green.

**HITL gate (owner sign-off):**

6. The **owner signs** the v0.5 security-boundary and claim-matrix updates;
   agent-authored material does **not** self-approve. Proposal-ready is **blocked**
   until signed (same pattern as the existing boundary §7/§8.1).

**Single evidence spine.** One chain: §A claim → `security_traceability_manifest.json`
→ named test → CI green → referenced by the NSA/threat-coverage matrix. The NSA
matrix is **derived from §A** ([ADR-MCPS-033](adr-mcps-033.md)) and carries no
independent conformance mapping.

**Non-gating.** Optional deliverables — proposal deck, external FAQ, NSA alignment
appendix — are useful but do not gate proposal-readiness.

## Rationale

A claim with no backing test is exactly the over-claim risk the release exists to
remove, so the gate's load-bearing rule ties every published claim to a green test.
The HITL sign-off mirrors the repo's proven honesty-gate pattern and prevents
AI-authored proposal drift. One evidence spine (not a second mapping for the NSA
matrix) is what keeps the two matrices from diverging.

## Alternatives Considered

- **Mechanical gate only.** Rejected: the repo's release discipline already requires
  owner sign-off for claim artifacts; dropping it would weaken the honesty gate.
- **HITL only ("owner reads it and approves").** Rejected: not reproducible; the
  whole point is machine-checkable evidence.
- **Independent NSA-matrix conformance mapping.** Rejected: a second evidence spine
  that drifts (see [ADR-MCPS-033](adr-mcps-033.md)).

## Consequences

### Positive
- "Proposal-ready" is a reproducible, CI-observable state plus one signature.
- A claim cannot ship without evidence; the NSA matrix can never out-claim §A.

### Negative
- Authoring a claim now also requires authoring its conformance test before it can
  be published — more upfront work. Accepted as the price of credibility.

### Neutral
- The forbidden-wording list must be maintained alongside §A's forbidden column.

## Compliance and Enforcement

The gate **is** the enforcement: items 1–5 run in CI and block merge of any
proposal artifact that violates them; item 6 blocks the release tag until the owner
signs. The traceability manifest is the single source mapping claims to tests; the
existing `mcps-conformance` drift guards re-derive it ([ADR-MCPS-018](adr-mcps-018.md)).

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-011](adr-mcps-011.md) (conformance-as-specification), [ADR-MCPS-018](adr-mcps-018.md) (manifest authority)
- Sibling v0.5 ADRs: [031](adr-mcps-031.md), [032](adr-mcps-032.md), [033](adr-mcps-033.md), [034](adr-mcps-034.md), [035](adr-mcps-035.md)
- Code: `mcps-conformance/security_traceability_manifest.json`, `mcps-conformance/conformance_manifest.json`
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
