<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-039: Draft-02 Authorization-Evidence Binding

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([037](adr-mcps-037.md), [038](adr-mcps-038.md), [040](adr-mcps-040.md)–[042](adr-mcps-042.md)).
Builds on the bind-not-interpret `AuthorizationProfile` model of
[ADR-MCPS-013](adr-mcps-013.md).

## Context

Draft-01 binds a request to authorization evidence with a single signed envelope field
`authorization_hash: "sha256:<b64url>"`. Core checks only its presence/prefix; the
`mcps-policy` profile re-hashes `sha256(decoded artifact bytes)` and compares before
interpreting claims ([ADR-MCPS-013](adr-mcps-013.md)). The artifact rides in a sibling
signed `_meta` block, `se.syncom/mcps.authorization = { profile, artifact }`. A single
opaque-hash field cannot distinguish "MCP-S/profile hashed opaque artifact bytes" from
"an external authorization system produced a decision digest/reference," and that
ambiguity is security debt in a protected envelope. v0.6 must make the binding **typed**
without making MCP-S responsible for interpreting authorization semantics (the
runtime-evidence ↔ authorization boundary).

## Decision

Draft-02 **replaces** the bare `authorization_hash` field with a signed, typed
`authorization_binding` object carrying a `binding_type` discriminator with two base forms
— `opaque-bytes` and `authz-system-reference` (both implemented in v0.6) — while
MCP-S binds, and never interprets, the authorization evidence.

## Rationale

The envelope carries the **binding contract**; the sibling `_meta` block continues to carry
profile-specific **evidence** (`{ profile, artifact }`). Typing the binding protects the
wire contract — it tells verifier and auditor *what kind* of evidence was signed — which is
not the same as interpreting authorization.

- **`opaque-bytes`**: `{ binding_type, digest_alg: "sha256", digest_value }`. The digest is
  over the **transport-decoded** artifact bytes (base64url-no-pad decode → SHA-256), never
  the base64 text or the UTF-8 JSON string bytes — matching current `mcps-policy` behavior.
- **`authz-system-reference`**: `{ binding_type, authorization_system_id, reference_scheme_id,
  reference_value, digest_alg: "sha256", digest_value }`; **all six fields mandatory**. The
  digest is mandatory and **self-contained** so the record stays historically verifiable
  from the signed record plus archived external evidence, independent of the external
  system's live state; the reference is cross-audit metadata, not the cryptographic binding.
  A reference-only binding would be a live-system dependency that becomes non-reconstructable
  on purge/rotation — a defect, not residual risk. The authorization system computes
  `digest_value` under `reference_scheme_id`; MCP-S binds it and never recomputes it over a
  structured artifact, so the boundary holds.

`binding_type` (how the call is bound) and the block's `profile` (how the artifact is
interpreted) are **separate axes**; the profile must not imply the binding form. The digest
representation is the **split** form (`digest_alg` + bare `digest_value`, no `sha256:`
prefix) for both forms, because security parameters are explicit protected fields — matching
`canonicalization_id` ([038](adr-mcps-038.md)) and `signature.alg`. Required dependencies, no
optional fields: every field of the active `binding_type` is mandatory; there is no compat
alias for the removed `authorization_hash` (draft-02 is a strictly separated profile, so
there is no in-the-wild draft-02 consumer to preserve).

## Alternatives Considered

- **Keep the bare `authorization_hash`, define only its byte representation.** Rejected:
  cannot distinguish opaque-hash from system-produced binding; the ambiguity is signed-in.
- **Add `authz-system-reference` later; ship opaque-only now** (the griller's first
  recommendation). Rejected by the owner: define the stable contract and implement both base
  forms now.
- **Bind to a decision id alone, no digest.** Rejected: a live-system dependency; fails
  historical verification when the external record is purged or rotated.
- **Let MCP-S hash a structured authorization artifact (Case 3).** Rejected for the base
  profile: reopens the canonicalization problem; permitted only via an explicit
  authorization-binding profile that defines artifact schema, canonicalization, hash, and
  vectors.
- **Use the `sha256:<digest>` prefix convention.** Rejected for this object: the split
  `digest_alg` + `digest_value` makes the algorithm an explicit protected field; legacy
  prefixed identifiers (`request_hash`, etc.) are **not** retrofitted in v0.6.

## Consequences

### Positive
- The binding is self-describing and typed; enterprise (authorization-system-produced)
  bindings are first-class; historical verifiability is structural (mandatory self-contained
  digest).
- The runtime-evidence ↔ authorization boundary is preserved: Core validates only structure;
  the profile interprets.

### Negative
- A breaking wire change for the authorization field (no compatibility alias), scoped to
  draft-02; deployments must emit `authorization_binding`.
- Two digest representations now coexist (`authorization_binding` split form vs legacy
  `sha256:<digest>` identifiers) until a future cleanup — a documented wart.

### Neutral
- Structured-artifact hashing remains available only behind an explicit, separately
  specified authorization-binding profile.

## Compliance and Enforcement

Core requires `authorization_binding`, validates `binding_type` ∈ the base set, the
mandatory fields, and the digest shape, then copies it into verified context — it never
hashes/fetches/parses/authorizes. The `mcps-policy` profile reproduces and compares (opaque)
or verifies the system reference. Conformance vectors ([042](adr-mcps-042.md)) pin: opaque
digest reproducibility over transport-decoded bytes; all six `authz-system-reference` fields
required; malformed binding rejected; a structured artifact without an explicit binding
profile rejected; both forms verify on a signed request; the binding `oneof` violation (both
forms present) rejected. New fail-closed codes are in [040](adr-mcps-040.md).

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (E.1, E.2), seed §20.
- Builds on: [ADR-MCPS-013](adr-mcps-013.md) (AuthorizationProfile, bind-not-interpret).
- Sibling v0.6 ADRs: [037](adr-mcps-037.md), [038](adr-mcps-038.md), [040](adr-mcps-040.md), [041](adr-mcps-041.md), [042](adr-mcps-042.md).
- Code: `mcps-core/src/envelope.rs`, `mcps-core/src/pipeline.rs`, `mcps-policy/src/evaluator.rs`, `mcps-policy/src/profile.rs`, `mcps-policy/src/lib.rs`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
