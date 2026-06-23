<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-032: Documentation Consolidation for 0.5 — One Canonical Boundary, One Docs Root, Redirect Stubs

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Resolved in the v0.5 grill; ratified by the owner HITL
sign-off in [ADR-MCPS-036](adr-mcps-036.md). Derives from PRD
[#148](https://github.com/matssun/mcps/discussions/148).

## Context

The 0.5 problem is not missing documents — it is **document drift**. Concretely,
found during the grill:

- **Two competing boundary docs.** [`docs/spec/security-boundary.md`](../spec/security-boundary.md)
  is the canonical, owner-signed honesty gate (signed 2026-05-30 single-node,
  2026-06-15 v0.3 multi-node active). [`docs/SECURITY_BOUNDARY.md`](../SECURITY_BOUNDARY.md)
  still states *"production-hardened for single-node … this is the entire current
  release claim,"* which now **contradicts** the canonical doc's active multi-node
  claim.
- **Path drift inside the canonical doc.** Its §7 cites its own path as
  `documents/mcps/security-boundary.md`, which matches neither its real location
  (`docs/spec/`) nor the v0.5 seed's proposed `components/mcps/docs/`.
- **Three path conventions** in play for one repo: `docs/`, `components/mcps/docs/`,
  `documents/mcps/`. The repo is an isolated `rules_rust` workspace
  ([ADR-MCPS-012](adr-mcps-012.md)), so top-level `docs/` is the only correct root.

The v0.5 seed proposed nine deliverables; several already exist under different
paths. Recreating them would multiply the drift this release is meant to remove.

## Decision

MCP-S 0.5 **consolidates** documentation rather than proliferating it: it keeps a
**single canonical security-boundary document** (`docs/spec/security-boundary.md`),
reduces every other boundary document to a redirect stub, uses **top-level `docs/`
as the sole documentation root**, and adds exactly **three genuinely net-new
proposal documents** under `docs/spec/` — `threat-coverage-matrix.md`,
`composability.md`, `proposal-scope.md` — superseding or pointing to, never
duplicating, existing artifacts.

Specifically:

1. **Canonical boundary** = `docs/spec/security-boundary.md`. No second competing
   boundary document may exist.
2. **`docs/SECURITY_BOUNDARY.md` becomes a one-line redirect stub** pointing to the
   canonical doc (kept only for external/GitHub discoverability; it must carry no
   live release claim).
3. **Fix the §7 path drift** in the canonical doc to `docs/spec/security-boundary.md`.
4. **Docs root is `docs/` only.** `components/mcps/docs/` and `documents/mcps/` are
   forbidden.
5. **Three net-new docs only.** Everything else in the seed is consolidation:
   the claim matrix evolves in place ([ADR-MCPS-033](adr-mcps-033.md)); deployment
   guidance, if added, is a pointer/overview routing to the existing
   `sidecar-deployment-guide.md`, `transport-hardening-guide.md`, and
   `host-integration-guide.md`, not a restatement.
6. **Reference, don't re-decide.** Method-transparency is [ADR-MCPS-030](adr-mcps-030.md);
   authorization is [ADR-MCPS-013](adr-mcps-013.md). 0.5 docs cite them.

## Rationale

The codebase's own honesty-gate pattern already treats the boundary as a single
signed source; the failure mode is a *second* document that ages out of sync. One
canonical source plus redirect stubs is the minimal structure that makes drift
structurally impossible while preserving inbound links. This is not covered by the
Python/Bazel `CLAUDE.md` defaults table (those concern code, not docs), so it is a
repo-specific decision grounded in the existing `docs/spec/` convention.

## Alternatives Considered

- **Create the seed's nine docs as-specified.** Rejected: several already exist;
  recreation adds drift and a third path convention.
- **Hard-delete `docs/SECURITY_BOUNDARY.md`.** Rejected: it may be an external entry
  point; a redirect stub preserves discoverability without allowing drift.
- **Keep both boundary docs and add a "which is canonical" note.** Rejected: two
  live claim docs is exactly the failure being removed.

## Consequences

### Positive
- Exactly one place states what MCP-S claims; external readers cannot land on a
  contradictory page.
- Only three new files to review; the rest is deletion/redirection.

### Negative
- Inbound links to `docs/SECURITY_BOUNDARY.md` now take one redirect hop. Accepted.

### Neutral
- Future docs must be added under `docs/`; contributors used to the seed's
  `components/mcps/docs/` phrasing must adjust.

## Compliance and Enforcement

The forbidden-claim guard ([ADR-MCPS-036](adr-mcps-036.md)) scans proposal-facing
docs and will flag a live release claim appearing in a file that should be a stub.
A lightweight check that `docs/SECURITY_BOUNDARY.md` contains only the redirect
pointer (no claim wording) can be added to the same guard. No automated check
enforces the single-root rule beyond code review — a known, accepted residual.

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-012](adr-mcps-012.md) (isolated workspace / placement), [ADR-MCPS-017](adr-mcps-017.md) (claim ceiling)
- Sibling v0.5 ADRs: [031](adr-mcps-031.md), [033](adr-mcps-033.md), [036](adr-mcps-036.md)
- Code/docs: `docs/spec/security-boundary.md`, `docs/SECURITY_BOUNDARY.md`
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
