<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-031: MCP-S 0.5 Is a Proposal-Readiness Release Over a Frozen draft-01 Envelope

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Decision resolved with the owner in the v0.5 grill
session ([`docs/grilling-seed/mcps-v0.5-seed.md`](../grilling-seed/mcps-v0.5-seed.md));
ratified, with implementation merged and the owner HITL sign-off recorded as defined in
[ADR-MCPS-036](adr-mcps-036.md). Umbrella ADR for the 0.5 release framing.

## Context

PRD [#148](https://github.com/matssun/mcps/discussions/148) calls for making MCP-S
credible and easy to evaluate as the message-security layer of the MCP ecosystem,
explicitly aligned with recent public (NSA) MCP security guidance. The release
numbering already in flight is:

- `0.3.1` — current released baseline;
- `0.4` — in-flight security-hardening release (the v0.4 Axis-1/2/3 results already
  landed in the codebase: `EtcdAtomicReplayStore` #69, `LIVE`/`PUSH` revocation
  tiers #70, `lb_assertion` Tier 3 #71);
- `0.5` — this release: proposal-readiness / NSA alignment.

The **wire/envelope version** (`draft-01`, frozen in `mcps-core/src/envelope.rs`
per [ADR-MCPS-002](adr-mcps-002.md)) is a *separate* namespace from the release
version. Every NSA-mapped capability the proposal needs is already expressible with
the existing request fields (`signer`, `on_behalf_of`, `audience`,
`authorization_hash`, `nonce`, `issued_at`, `expires_at`, `signature`) and response
fields (`request_hash`, `server_signer`, `issued_at`, `signature`) — verified
during the grill. The risk this ADR closes is **scope creep**: the seed's default
"no new fields unless a concrete claim cannot be supported" left an open escape
hatch that could quietly turn a documentation release into a wire revision.

## Decision

MCP-S 0.5 is a **proposal-readiness / NSA-alignment release scoped to
documentation, conformance, claim hardening, and audit evidence over the existing,
frozen `draft-01` envelope**: it adds **no** wire-envelope fields and **no** MCP
method semantics, and any proposal claim that cannot be supported by `draft-01` is
**cut from 0.5** and ejected to a separate `draft-02` ADR rather than patched in.

Specifically:

1. **Release version ≠ wire version.** 0.5 is a release/profile milestone; the wire
   envelope remains `draft-01`. Both envelopes (request and response) are unchanged.
2. **Zero in-release wire-field additions.** There is no "small field," "metadata
   field," or "NSA-alignment field" path inside 0.5.
3. **The only exception path is ejection, not expansion.** If a desired claim cannot
   be supported by `draft-01`: (a) drop the claim from 0.5; (b) open a dedicated
   `draft-02` ADR defining the field and its threat model; (c) implement and test it
   as separate post-0.5 work.
4. **0.5 still contains real engineering work** — conformance evidence, claim-matrix
   reconciliation, security-boundary consolidation, method-transparency proof,
   audit/error taxonomy mapping, NSA alignment — none of which touches the wire.
5. **0.5 must not** reintroduce signed tool manifests, parse `tools/list` /
   `tools/call`, add tool-catalog enforcement, or claim prompt-injection / output /
   sandbox / RBAC / host-UX coverage (these remain governed by
   [ADR-MCPS-030](adr-mcps-030.md) and [ADR-MCPS-017](adr-mcps-017.md)).

Scope-freeze wording for the proposal-scope doc: *"MCP-S 0.5 is proposal-readiness
over draft-01. No wire-envelope changes. Field gaps become draft-02 work."*

## Rationale

A proposal-readiness release whose credibility rests on "narrower, clearer, easier
to accept" cannot simultaneously change the wire format — that would invite the
exact "what is MCP-S really?" ambiguity it is trying to remove. Keeping `draft-01`
frozen also keeps the preimage-stability rule ([ADR-MCPS-010](adr-mcps-010.md))
intact and the conformance vectors stable. The existing fields already cover the
NSA-aligned claims, so adding fields would be scope expansion mislabelled as
alignment.

## Alternatives Considered

- **Label this release 0.4.** Rejected: 0.4 is already reserved for the in-flight
  hardening release whose results are merged.
- **Allow a narrow in-release field-add path.** Rejected: it reopens the wire-scope
  risk this ADR exists to close; the ejection-to-`draft-02` path is strictly safer
  and is mechanically enforced (see Compliance).
- **Do nothing / leave "no new fields unless…" as-is.** Rejected: the conditional is
  unfalsifiable and invites drift.

## Consequences

### Positive
- The proposal story is unambiguous: 0.5 strengthens evidence and boundaries, not
  the protocol.
- `draft-01`, its preimage rule, and the committed conformance vectors stay stable.

### Negative
- If a genuine field gap surfaces mid-cycle, the dependent claim is dropped from 0.5
  and deferred to `draft-02` — slower than an in-place patch. Accepted as the cost
  of scope discipline.

### Neutral
- The release-version vs wire-version distinction must be stated explicitly in
  proposal materials (see [ADR-MCPS-032](adr-mcps-032.md)), since readers conflate
  them.

## Compliance and Enforcement

Enforced mechanically by the proposal-readiness gate ([ADR-MCPS-036](adr-mcps-036.md)):
every §A claim must map to a named green conformance test, so a claim that needs a
nonexistent `draft-01` field has no backing test and **cannot pass the gate**. The
`draft-01` freeze is therefore self-policing — no separate "did we add a field?"
check is required, though the existing `drift_guard_test` over the frozen envelope
vocabulary ([ADR-MCPS-002](adr-mcps-002.md)) also catches any envelope-struct change.

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-002](adr-mcps-002.md) (frozen envelope vocabulary), [ADR-MCPS-010](adr-mcps-010.md) (preimage stability)
- [ADR-MCPS-030](adr-mcps-030.md) (method-transparency / tool-catalog exclusion), [ADR-MCPS-017](adr-mcps-017.md) (deferred capabilities)
- Sibling v0.5 ADRs: [032](adr-mcps-032.md), [033](adr-mcps-033.md), [034](adr-mcps-034.md), [035](adr-mcps-035.md), [036](adr-mcps-036.md)
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
