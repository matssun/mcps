<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-038: Draft-02 Envelope Identifiers and Canonical Preimage Field Set

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([037](adr-mcps-037.md), [039](adr-mcps-039.md)–[042](adr-mcps-042.md)). Builds on the
signing-scope rule of [ADR-MCPS-026](adr-mcps-026.md) and the canonicalization domain of
[ADR-MCPS-005](adr-mcps-005.md).

## Context

Draft-02 must make the canonical scheme self-describing as protected evidence so
independent verifiers and auditors can cross-check exactly which bytes were signed, while
avoiding JWT-style `alg`-confusion. The draft-01 envelope carries `version: "draft-01"`
(with serde `deny_unknown_fields`) but **no** canonicalization identifier; the response
envelope carries neither a version nor a canonicalization id. The signing preimage signs
the complete JSON-RPC object minus `signature.value` (retaining `signature.alg`/`key_id`)
and minus container-level W3C trace keys ([ADR-MCPS-026](adr-mcps-026.md)). This ADR fixes
the draft-02 identifier set, their protection, the verification order, and the exact
preimage exclusion predicate. The number domain those bytes obey is
[037](adr-mcps-037.md).

## Decision

Every draft-02 request **and** response envelope carries two non-overloaded **protected**
identifiers inside the signing preimage — `version: "draft-02"` (the profile-version
authority) and `canonicalization_id: "mcps-jcs-int53-json-v1"` (the audit-facing record of
the byte scheme used) — and the preimage excludes **only** `signature.value` plus the
three W3C trace keys at container-level `_meta`, by an explicit JSON-path predicate.

## Rationale

The two identifiers play distinct roles (the "describes and binds; does not direct"
principle): `version` **directs** — it selects the verifier's allowlist, validation rules,
algorithms, envelope structure, and error behavior; `canonicalization_id` **describes** —
it records which allowlisted scheme was used and is self-describing for audit, but can
never introduce verifier behavior. `canonicalization_id` is mandatory **even though v0.6
allows exactly one scheme**: it is behavior-redundant but not *evidence*-redundant — a
signed record must state its byte scheme under signature so a future auditor reads it from
the evidence, not from release folklore.

There is no circularity, because the verifier selects the canonicalizer from the
**profile** (chosen by `version`), never from the field. Verification order: (1) parse raw
JSON and read `version`/`canonicalization_id` as **untrusted** selectors; (2) require
`version == "draft-02"`; (3) load the draft-02 profile whose allowlist is exactly
`{mcps-jcs-int53-json-v1}`; (4) require `canonicalization_id` ∈ allowlist; (5) canonicalize
with the profile-selected scheme; (6) build the preimage removing only `signature.value`,
retaining `alg`/`key_id`/`canonicalization_id`/`version`; (7) verify the signature, then
enforce the rest. The fields are read before verification but trusted only after — the same
pattern `alg`/`key_id` already follow.

The response envelope gains **both** identifiers (it carries neither today) because it is an
independently signed server-evidence record and must be self-describing standalone, not
dependent on the bound request to recover its profile/scheme context.

The preimage exclusion keeps the draft-01 container-vs-nested trace-key asymmetry, written
as an explicit path predicate: exclude `signature.value`, and `traceparent`/`tracestate`/
`baggage` **only** at container-level `params._meta` (request) / `result._meta` (response).
Nothing recursive, nothing by key-name alone — a `traceparent` under `params.arguments._meta`
or `result.content[*]._meta` is payload and stays signed. Recursive name-based exclusion
would let an attacker relocate security bytes under a reserved observability name to strip
them from integrity coverage; the container-only rule is the strictly tighter boundary.

## Alternatives Considered

- **Overload the single `version` field to mean both profile version and byte scheme.**
  Rejected: conflates "directs" with "describes"; loses audit self-description and future
  multi-scheme support.
- **Omit `canonicalization_id` because there is only one scheme.** Rejected: the record
  would not be self-describing for historical verification.
- **Exclude trace keys recursively by name at any depth.** Rejected: opens the
  smuggle-bytes-under-a-reserved-key attack; container-only is stricter.
- **Give the response no identifiers; inherit from the bound request.** Rejected: a stored
  response alone could not prove which profile/scheme verified it.

## Consequences

### Positive
- Evidence is self-describing and cross-verifiable; `alg`/canonicalization-confusion and
  downgrade are structurally prevented (the field never directs the verifier).
- One explicit predicate defines the signed bytes for both envelopes.

### Negative
- Both envelopes grow by two protected fields, and the response envelope changes shape
  (it gains `version` + `canonicalization_id`) — a wire-contract change, scoped to draft-02.

### Neutral
- The single-scheme allowlist makes step (4) trivial in v0.6 but is the seam through which
  future schemes (e.g. a float-capable `…-v2`, [037](adr-mcps-037.md)) are admitted.

## Compliance and Enforcement

Conformance vectors ([042](adr-mcps-042.md)) pin: byte-identical preimage across key
reordering/whitespace/escape spelling; mutation of `version`/`canonicalization_id`/`alg`/
`key_id` fails verification; a container-level trace-key rewrite still verifies while a
nested-`_meta` rewrite fails; an unknown/disallowed/mismatched `canonicalization_id` fails
closed with the [040](adr-mcps-040.md) codes. The exclusion predicate is implemented as the
preimage builder in `mcps-core/src/signing.rs`.

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (B.2, C.1, D.1), seed §20.
- Builds on: [ADR-MCPS-005](adr-mcps-005.md) (canonicalization), [ADR-MCPS-026](adr-mcps-026.md) (signing scope / signature-value exclusion).
- Sibling v0.6 ADRs: [037](adr-mcps-037.md), [039](adr-mcps-039.md), [040](adr-mcps-040.md), [041](adr-mcps-041.md), [042](adr-mcps-042.md).
- Code: `mcps-core/src/envelope.rs`, `mcps-core/src/signing.rs`, `mcps-core/src/canonical.rs`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
