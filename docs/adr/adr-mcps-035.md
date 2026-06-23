<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-035: MCP-S Audit-Evidence Vocabulary Is Derived From the Frozen Error Taxonomy

## Status

Accepted (v0.5 — 2026-06-23, owner HITL sign-off; see security-boundary.md §10; supersedes the prior Proposed status of 2026-06-22). Resolved in the v0.5 grill; ratified by the owner HITL
sign-off in [ADR-MCPS-036](adr-mcps-036.md). Derives from PRD
[#148](https://github.com/matssun/mcps/discussions/148).

## Context

The v0.5 seed (§5.8) proposed an audit-event vocabulary so MCP-S can emit security
evidence for its own decisions. But `mcps-core/src/error.rs` already defines a
**frozen `mcps.*` error taxonomy** — 20 wire codes, one per `McpsError` variant,
rendered by `McpsError::wire_code()` ([ADR-MCPS-002](adr-mcps-002.md)/
[007](adr-mcps-007.md)/[009](adr-mcps-009.md)). The seed's proposed event names
**collide** with it: they rename frozen outcomes (`rejected.bad_signature` vs the
frozen `mcps.invalid_signature`; `rejected.expired` vs `mcps.expired_request`;
`rejected.replay` vs `mcps.replay_detected`; `rejected.untrusted_signer` vs the
broader `mcps.actor_binding_failed`) and even **invent**
`authorization_hash_mismatch`, which Core can never legitimately emit — Core binds
`authorization_hash` but does **not interpret** the authorization artifact
([ADR-MCPS-013](adr-mcps-013.md); boundary doc §Authorization). Two parallel
vocabularies for the same outcomes guarantee drift.

The frozen taxonomy is also **rejection-only** (it is an error enum); the audit
layer legitimately needs **success/lifecycle** events the enum cannot express.

## Decision

The MCP-S audit-evidence vocabulary **derives its rejection reasons from the frozen
`McpsError::wire_code()` taxonomy** — `error.rs` is the sole authority — and adds
**only** the success events the error enum cannot express. No parallel rejection
vocabulary is minted.

Specifically:

1. **Rejection events** use a small fixed `event_type`
   (`mcps.request.rejected` or `mcps.response.rejected`) with `reason` set to the
   **exact** `McpsError::wire_code()` token. Example:
   `{ "event_type": "mcps.request.rejected", "reason": "mcps.invalid_signature" }`.
2. **No minted rejection sub-names** such as `mcps.request.rejected.bad_signature`,
   `…expired`, `…replay`, `…untrusted_signer`, or `…authorization_hash_mismatch`.
3. **Net-new success/lifecycle events only:** `mcps.request.accepted`,
   `mcps.response.signed`. (Defer `…observed` variants until a concrete consumer
   needs them.)
4. **Drop `authorization_hash_mismatch` entirely** — "mismatch" implies Core
   semantically compared the authorization artifact, which is outside Core.
5. **Optional non-normative display field.** A `reason_label` (e.g. "Invalid
   signature") may accompany an event for SIEM readability, but the stable machine
   token is always `reason`.
6. **Event fields** (per seed §5.8, kept): `event_type`, `timestamp`,
   `request_hash`, `signer`, `key_id`, `audience`, `on_behalf_of`,
   `authorization_hash`, `nonce`, `decision`, `reason`, `trust_tier`, `replay_tier`,
   `transport_binding_mode`.

**Non-goal:** the MCP-S audit vocabulary is not a full SIEM schema and does not
replace deployment audit policy.

## Rationale

One authority for rejection tokens (`error.rs`) means the audit layer cannot drift
from the actual decisions the pipeline makes. Reusing the frozen `wire_code()` also
means existing conformance over the error taxonomy already covers the rejection
side; only the two success events are new surface. Dropping
`authorization_hash_mismatch` keeps the audit layer inside the same bind-not-interpret
boundary as the rest of Core.

## Alternatives Considered

- **Hand-authored parallel SIEM-friendly names with a mapping table.** Rejected:
  needs its own frozen-mapping artifact and a sync guard; `reason_label` gives
  readability without a second vocabulary.
- **Adopt the seed's names verbatim.** Rejected: renames frozen codes and ships
  `authorization_hash_mismatch`, an overclaim.

## Consequences

### Positive
- Rejection evidence is guaranteed consistent with the pipeline's actual verdicts.
- Minimal new surface: two success events plus an event envelope.

### Negative
- SIEM consumers wanting human labels must use the non-normative `reason_label` or
  map tokens themselves. Accepted.

### Neutral
- Adding a new rejection outcome means adding an `McpsError` variant first (the
  frozen-taxonomy process), which the audit layer then inherits automatically.

## Compliance and Enforcement

A drift guard ([ADR-MCPS-036](adr-mcps-036.md) gate) asserts that **every rejection
`reason` the audit layer can emit is a member of `McpsError::wire_code()`** — the
same teeth used for method-name drift in [ADR-MCPS-034](adr-mcps-034.md). The
success-event set (`accepted`, `response.signed`) is a small enumerated allowlist
checked by the same guard.

## Related

- PRD: <https://github.com/matssun/mcps/discussions/148>
- [ADR-MCPS-002](adr-mcps-002.md)/[007](adr-mcps-007.md)/[009](adr-mcps-009.md) (frozen error taxonomy), [ADR-MCPS-013](adr-mcps-013.md) (authorization bind-not-interpret)
- Sibling v0.5 ADRs: [031](adr-mcps-031.md), [034](adr-mcps-034.md), [036](adr-mcps-036.md)
- Code: `mcps-core/src/error.rs` (`McpsError`, `wire_code`)
- Glossary: [`CONTEXT.md`](../../CONTEXT.md)
