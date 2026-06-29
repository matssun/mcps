<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-040: Draft-02 Fail-Closed Error Taxonomy

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([037](adr-mcps-037.md)–[039](adr-mcps-039.md), [041](adr-mcps-041.md),
[042](adr-mcps-042.md)). Extends the frozen audit-taxonomy authority of
[ADR-MCPS-035](adr-mcps-035.md).

## Context

`McpsError::wire_code()` is the sole frozen taxonomy authority; the audit rejection
vocabulary is `error.wire_code()` verbatim, and a CI drift guard asserts every emitted
reason is a member ([ADR-MCPS-035](adr-mcps-035.md)). Draft-02 introduces new protected
fields (`canonicalization_id`, [038](adr-mcps-038.md); `authorization_binding`,
[039](adr-mcps-039.md)) with new failure modes. The grill's open question
(seed §18) was granularity: should canonicalization-id *mismatch* vs *unsupported scheme*
vs *downgrade* be distinct codes or folded, and does the renamed authorization field reuse
`mcps.authorization_hash_missing` (per the [ADR-MCPS-007](adr-mcps-007.md) "stable token
across renames" precedent) or get a clean code?

## Decision

Draft-02 adds **nine** new fail-closed wire codes — granular for protocol/profile-confusion
failures, coarse (`mcps.canonicalization_failed`) for low-level JSON value-domain/parser
failures — with no fallback-to-allow on any path.

The new codes:

```
mcps.canonicalization_id_missing        mcps.authorization_binding_type_unsupported
mcps.canonicalization_id_unknown        mcps.authorization_binding_malformed
mcps.canonicalization_id_not_allowed    mcps.authorization_binding_profile_required
mcps.canonicalization_id_mismatch       mcps.authorization_binding_ambiguous_bytes
mcps.authorization_binding_missing
```

## Rationale

Granularity is right **for confusion/downgrade failures**: the attacker-oracle argument is
weak (the attacker already controls the public profile/canonicalization fields, the allowed
scheme is public conformance data, and rejection is fail-closed regardless), while defender
telemetry is strong — an unknown-id probe, a disallowed-future-scheme probe, and a downgrade
attempt are distinct attack shapes worth distinguishing. Low-level JSON value-domain failures
(duplicate keys, unsafe integers, invalid UTF-8, parser repair) stay coarse under
`mcps.canonicalization_failed`; codes stay broad where granularity would leak internal
trust/key state or parser trivia (`mcps.invalid_signature`, `mcps.actor_binding_failed`).

`mcps.authorization_binding_missing` is **minted** rather than reusing
`mcps.authorization_hash_missing`: draft-02 structurally replaces a bare hash string with a
typed object ([039](adr-mcps-039.md)), so the legacy token would name a field that no longer
exists on the draft-02 wire. The [ADR-MCPS-007](adr-mcps-007.md) "stable token across
renames" precedent covered a pure field rename (`actor`→`signer`); it does not compel reusing
a now-misleading token for a structurally new, strictly-separated draft-02 surface.
`mcps.authorization_hash_missing` remains the **draft-01** code; audit systems can group the
two semantically if needed.

`canonicalization_id` (the domain term, [038](adr-mcps-038.md)) is used in code naming, not
an invented abbreviation.

## Alternatives Considered

- **Fold canon-id failures into `mcps.canonicalization_failed`.** Rejected: a JSON-domain
  failure ("not canonicalizable") and a profile-evidence failure ("canonicalization/profile
  confusion probe") are different events defenders must separate.
- **Reuse `mcps.authorization_hash_missing` in draft-02** (the answerer's recommendation,
  citing [ADR-MCPS-007](adr-mcps-007.md)). Rejected by the owner: the field no longer exists
  in draft-02; a clean native taxonomy beats a misleading legacy token under strict version
  separation.
- **Maximally coarse external codes (hide the reason).** Rejected: removes defender telemetry
  for the exact confusion/downgrade attacks draft-02 hardens against, with negligible oracle
  benefit for integrity failures.

## Consequences

### Positive
- Confusion/downgrade attacks are individually observable in audit; every §12 fail-closed
  case maps to a concrete code with no allow path.
- The draft-02 taxonomy reflects the actual draft-02 wire surface.

### Negative
- The frozen taxonomy authority grows by nine codes; `wire_code()`, display labels, and the
  drift-guard tests must be updated together.

### Neutral
- New codes are draft-02-scoped: draft-01 verification must not emit them unless running the
  draft-02 verifier ([041](adr-mcps-041.md)).

## Compliance and Enforcement

The codes are added to `McpsError` with `Display == wire_code()` asserted as the existing
taxonomy tests do; the [ADR-MCPS-035](adr-mcps-035.md) drift guard and the audit rejection
vocabulary inherit them automatically (reasons are `wire_code()` verbatim — no parallel
list). Conformance vectors ([042](adr-mcps-042.md)) emit each new code on its trigger and
assert the wire code via the black-box public API.

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (F.1), seed §20.
- Extends: [ADR-MCPS-035](adr-mcps-035.md) (audit taxonomy authority); precedent discussed: [ADR-MCPS-007](adr-mcps-007.md).
- Sibling v0.6 ADRs: [037](adr-mcps-037.md), [038](adr-mcps-038.md), [039](adr-mcps-039.md), [041](adr-mcps-041.md), [042](adr-mcps-042.md).
- Code: `mcps-core/src/error.rs`, `mcps-core/src/audit.rs`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
