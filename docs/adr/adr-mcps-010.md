<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-010: Incubation Strategy, Extension Identifier, and Preimage-Stability Rule

## Status

Superseded by ADR-MCPS-027 — the incubation extension identifier was reassigned
from `name.sundvall/mcps-security` to `se.syncom/mcps` (and the authorization
profile IDs from `name.sundvall/mcps-authz-*` to `se.syncom/mcps-authz-*`). The
original decision is preserved below as the historical record; the reassignment
rationale, full identifier mapping, and the preimage/vector-regeneration
consequence live in ADR-MCPS-027. The incubation strategy and preimage-stability
rule themselves remain in force.

## Context

Derived from PRD. The brief uses `com.example/mcps-security` as a placeholder and lists two coupled open decisions: whether to propose MCP-S upstream immediately or incubate first (#18.8), and which controlled extension identifier replaces the placeholder (#18.1). These are coupled because the extension identifier lives inside the signed `_meta` key, so it is part of the canonical preimage — *who assigns it* and *when it can change* are the same question.

## Decision

MCP-S is incubated independently first under the controlled, explicitly non-official extension identifier `name.sundvall/mcps-security` (keys `.request` / `.response` / `.verified`), and proposed upstream to the MCP community only after the Core profile is implemented and conformance-proven; because the identifier is part of the canonical preimage, it MAY change between draft versions during incubation, MUST freeze at 1.0, and any upstream-assigned official identifier defines a new wire profile with regenerated conformance vectors.

## Rationale

Incubating with a working reference implementation and a passing conformance suite is far stronger upstream leverage than a paper proposal, and avoids design-by-committee churn before the invariants are proven in code (the brief's own §19/§22 say to start with `mcps-core` + vectors). Using a domain already controlled by the initiator has zero registration friction and is clearly non-official; because any later neutral or official identifier is a new profile regardless, there is no lock-in cost. The `io.modelcontextprotocol` prefix is not used unless and until the MCP maintainers assign one.

## Alternatives Considered

- **Propose upstream immediately**: rejected — forces public discussion before invariants are proven, with no code verification in the meantime.
- **Incubate but never upstream**: rejected — abandons the PRD's stated goal of a community-proposable profile.
- **Register a dedicated project domain now**: rejected as unnecessary friction given the new-profile-on-rename rule.

## Consequences

### Positive
- Freedom to evolve the canonical preimage pre-1.0; a credible, code-backed upstream proposal later.

### Negative
- An upstream identifier reassignment forces full vector regeneration — it changes the signed bytes, not just prose.

### Neutral
- The identifier carries a personal-domain name during incubation; a `version` field (e.g. `draft-01`) is pinned and unknown versions are rejected with `mcps.unsupported_version`.

## Compliance and Enforcement

`CONTEXT.md` records the incubator identifier and the preimage-stability rule. Version pinning is enforced in the verification path. Conformance vectors are regenerated whenever a preimage-affecting field (including the identifier) changes.

## Related

- PRD: (author's private monorepo)
- Siblings: ADR-MCPS-002 (vocabulary), ADR-MCPS-008 (verified-context key), ADR-MCPS-011 (delivery)
