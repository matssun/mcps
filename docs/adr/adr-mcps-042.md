<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-042: Draft-02 Conformance Corpus and Cross-Implementation Interop Oracle

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([037](adr-mcps-037.md)–[041](adr-mcps-041.md)). Extends the conformance-as-specification
model of [ADR-MCPS-011](adr-mcps-011.md) and the manifest authority of
[ADR-MCPS-018](adr-mcps-018.md).

## Context

Draft-02's purpose is byte-identical, cross-verifiable preimages, so its conformance corpus
must do two things the draft-01 harness does not. First, keep the draft-01 golden set
provably frozen while adding draft-02 (the [041](adr-mcps-041.md) no-leak property). Second,
serve as a real **interoperability oracle**: the existing harness regenerates fixtures with
the project's own Ed25519 and canonicalization code, which proves self-consistency but **not**
cross-implementation agreement — a third-party implementation needs frozen ground-truth
bytes to check itself against, not the project's regenerated opinion. This ADR fixes the
corpus structure, the manifest additions, the oracle requirement, and the required vector
classes.

## Decision

Draft-02 gets a **separate, byte-frozen corpus** (`mcps-core/tests/vectors/draft-02/`) whose
manifest carries an explicit version policy and a **frozen static interop oracle** (committed
canonical preimage bytes, digest, and signature) **in addition to** the regenerated
drift-guard set.

## Rationale

A separate corpus makes "draft-01 unchanged" mechanically obvious rather than a human
promise; mixing draft-02 into the draft-01 manifest would undermine the [041](adr-mcps-041.md)
no-leak proof. The manifest reuses the existing fixture fields and adds: `envelope_version`
(required on every draft-02 fixture); `canonicalization_id` (required when a draft-02 envelope
is present — the domain term, not an abbreviation); `version_policy { accepted_versions,
downgrade }` (required for every migration/downgrade vector, since the outcome depends on the
configured policy); and `oracle { canonical_preimage_b64url, canonical_preimage_sha256,
signature_value, request_hash }` (required for every signed fixture whose canonicalization
succeeds; absent only for malformed-raw vectors that fail before a preimage exists).

Both oracle modes are kept: the regenerated set remains an internal drift guard, and the
frozen static oracle is the cross-implementation ground truth. The harness asserts wire
fixture == committed, computed preimage bytes == `oracle.canonical_preimage_b64url`, digest ==
`oracle.canonical_preimage_sha256`, signature == `oracle.signature_value`, and verification
result == `expected` — asserting bytes and hashes, never a printed "OK".

The **integer-only honesty vector is required**, not optional: a float-bearing signed payload
(e.g. `0.7`, `19.99`) must be rejected with `mcps.canonicalization_failed`, machine-checking
the [037](adr-mcps-037.md) limitation. Beyond the per-branch vectors, the corpus must include:
canonical determinism across raw key reordering / whitespace / escape spelling (byte-identical
preimage); raw duplicate protected fields (`version`, `canonicalization_id`, a binding field)
failing before serde collapse; signed-wrong-profile (signed under one scheme/version, presented
under another) failing as an integrity error; an unknown-but-correctly-signed
`canonicalization_id` emitting the unsupported-canonicalization code (proving policy and
signature failures are distinct); response/request profile mismatch; the authorization-binding
`oneof` violation (both forms present) rejected; and a historical-trust-material vector that
verifies against trust material valid at `issued_at`, not current state.

## Alternatives Considered

- **One shared manifest tagged by version.** Rejected: makes draft-01 immutability a human
  promise instead of a mechanical fact.
- **Regenerated fixtures only.** Rejected: proves self-consistency, not cross-implementation
  agreement — the very thing draft-02 exists to guarantee.
- **Treat the float limitation as prose only.** Rejected: it must be a required, machine-checked
  rejection vector.

## Consequences

### Positive
- A third-party implementation can verify itself against frozen bytes/digests/signatures; the
  draft-01 corpus is provably untouched; the documented float limitation is enforced, not just
  stated.

### Negative
- Two oracle modes (regenerated + frozen static) must be maintained; the static oracle is
  hand-frozen and updated only by deliberate, reviewed change.

### Neutral
- The corpus grows a draft-02 subtree and a richer manifest schema; draft-01 fixtures keep
  their existing shape.

## Compliance and Enforcement

The corpus is the enforcement: the regenerated golden set and the frozen static oracle both
run in CI and fail on drift; the required negative vectors (float rejection, duplicate
protected fields, signed-wrong-profile, unknown canon-id, profile mismatch, binding oneof,
historical trust) gate the release alongside the [041](adr-mcps-041.md) gate. Tests call the
black-box public verifier API and assert wire codes and bytes, not diagnostics. Manifest
authority and drift re-derivation follow [ADR-MCPS-018](adr-mcps-018.md).

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (H.1), seed §20.
- Extends: [ADR-MCPS-011](adr-mcps-011.md) (conformance-as-specification), [ADR-MCPS-018](adr-mcps-018.md) (manifest authority).
- Sibling v0.6 ADRs: [037](adr-mcps-037.md), [038](adr-mcps-038.md), [039](adr-mcps-039.md), [040](adr-mcps-040.md), [041](adr-mcps-041.md).
- Code: `mcps-core/tests/vectors/`, `mcps-core/tests/vectors_test.rs`, `mcps-core/tests/manifest.json`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
