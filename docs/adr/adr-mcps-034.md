<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-034: Method-Transparency Is CI-Enforced — Behavioral Equivalence Test + Static Drift Guard

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Resolved in the v0.5 grill; ratified by the owner HITL
sign-off in [ADR-MCPS-036](adr-mcps-036.md). Extends (does not re-decide)
[ADR-MCPS-030](adr-mcps-030.md). Derives from PRD
[#148](https://github.com/matssun/mcps/discussions/148).

## Context

[ADR-MCPS-030](adr-mcps-030.md) decided the *principle* that MCP-S Core is
method-transparent and tool-catalog integrity is excluded. The proposal positions
this as a central claim ("we do not need to understand every MCP method"), so it
must be *provable* and *durable*, not merely documented.

Code verification during the grill confirms transparency holds **today**: every
`tools/call` occurrence in `mcps-core/src` is a `#[cfg(test)]` fixture (there are
no `tools/list` occurrences in Core at all); no non-test path reads the JSON-RPC
`method` field. Notification rejection
keys on the **absence of `id`** (`mcps-core/src/constraints.rs:69`) and batch
rejection on **top-level array shape**, not on method semantics. The remaining risk
is a future contributor adding a well-intentioned `if method == "tools/call"` check
that quietly erodes the boundary.

## Decision

Method-transparency is **enforced in CI** by two artifacts, both mapped to
[ADR-MCPS-030](adr-mcps-030.md) in the security-traceability manifest:

1. **Behavioral equivalence conformance test.** Run the *same* signed envelope, same
   signature, same policy context, varying **only** the JSON-RPC `method` across
   `tools/list`, `tools/call`, `resources/list`, `prompts/list`, and a fabricated
   `x/nonexistent/custom`, and assert **identical verification verdicts**. Run it for
   **both** an accepted envelope and at least one rejected envelope (e.g. bad
   signature or expired), proving the method neither rescues nor worsens the verdict.
   The assertion is *equivalence*, not mere acceptance of known methods.
2. **Static method-name drift guard.** Fail CI if non-test `mcps-core/src` code
   references a concrete MCP method-name literal. The banned set is:
   `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`,
   `prompts/get`, `sampling/createMessage`, `completion/complete`.
   - **Scope narrowly.** Do **not** ban the bare JSON-RPC `"method"` field — Core
     must still preserve/sign/canonicalize the full request object. Exclude
     `#[cfg(test)]` modules, `tests/`, and fixture files (`*_test.rs`). If the
     scanner is file-based, also avoid those literals in non-test Core comments.

Any future method-aware behavior MUST be introduced in a separate layer/profile
(MTCI, an `mcps-policy` extension, an `mcps-proxy` adapter, or the host/application
layer) **with its own ADR** — never inside `mcps-core`.

## Rationale

A one-shot test proves transparency at a point in time; a static guard makes the
boundary *durable* against future drift, which is what "protects the proposal
boundary" actually requires. Equivalence-across-an-unknown-method is a strictly
stronger claim than the seed's "a signed tools/list request is treated as an
ordinary request," because it proves the verdict is a function of the
envelope+signature, not of the method. The rigidity is intentional: if MCP-S Core
is proposal-positioned as method-transparent, method-aware logic should not be able
to slip in as a "small helpful check."

## Alternatives Considered

- **Behavioral test only.** Rejected: weaker; nothing stops a later PR from adding
  method-aware code that still passes the existing test set.
- **Ban the bare `"method"` field too.** Rejected: Core legitimately signs and
  canonicalizes the whole object including `method`.
- **Document-only (no CI).** Rejected: the proposal claims CI enforcement; prose is
  not evidence.

## Consequences

### Positive
- The proposal can state "MCP-S Core method-transparency is CI-enforced," backed by
  two named green artifacts.
- Future method-aware Core code is blocked at build time.

### Negative
- The static guard rejects even well-intentioned future method-aware Core code,
  forcing it into a separate profile + ADR. Accepted — that is the point.

### Neutral
- The banned-literal list must be maintained as MCP adds methods; it lives next to
  the guard.

## Compliance and Enforcement

Both artifacts run in CI and are listed in `security_traceability_manifest.json`
against [ADR-MCPS-030](adr-mcps-030.md); they are re-derived by the existing
`mcps-conformance` drift guards ([ADR-MCPS-018](adr-mcps-018.md)). A red on either
blocks merge. The behavioral test lives under `mcps-conformance`; the static guard
is a workspace test over `mcps-core/src`.

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-030](adr-mcps-030.md) (the principle this enforces), [ADR-MCPS-009](adr-mcps-009.md) (batch/notification constraints), [ADR-MCPS-018](adr-mcps-018.md) (conformance-manifest authority)
- Sibling v0.5 ADRs: [031](adr-mcps-031.md), [035](adr-mcps-035.md), [036](adr-mcps-036.md)
- Code: `mcps-core/src/constraints.rs`, `mcps-core/src/pipeline.rs`, `mcps-conformance/`
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
