<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-041: Draft-01/Draft-02 Migration and Dual-Verifier Release Posture

## Status

Proposed — resolved in the v0.6 grill (2026-06-29, owner per-branch sign-off);
becomes Accepted on merge to main as v0.6. Sibling of the v0.6 draft-02 set
([037](adr-mcps-037.md)–[040](adr-mcps-040.md), [042](adr-mcps-042.md)).

## Context

Draft-02 (shipping as v0.6) is a wire-envelope change merged to main, while
draft-01 / v0.5.1 is the released baseline still in the field. The two profiles must
coexist at the runtime boundary without a verifier ever silently accepting the other's
evidence, and a deployment must never inherit a security posture by accident. The grill
(seed §13, Q20–Q22) had to fix the dispatch rule, whether v0.6 ships a dual or
draft-02-only verifier, the default version policy, the cross-version downgrade defense,
and the minimum implementation gate for release.

## Decision

v0.6 ships a **dual verifier with strict version dispatch** (not draft-02-only), keyed off
`envelope.version` as the sole profile selector, with **no default expected-version
policy** — the policy is a required explicit input and the service **fails closed at
configuration/startup** if it is unset.

## Rationale

Draft-01 is the released field profile, so coexistence is required; **cross-acceptance is
the bug, coexistence is not**. `envelope.version` is the sole selector: `"draft-01"`
dispatches only to the draft-01 verifier, `"draft-02"` only to the draft-02 verifier; each
verifier must reject the other's evidence; no verifier may "try one profile then fall back
to the other." `version` is read as an untrusted selector (like
`canonicalization_id`, [038](adr-mcps-038.md)), then the selected profile enforces its
exact signed value. Shared code is permitted only **below** the profile boundary (JCS,
hashing, signature primitives); profile semantics are never merged.

The **expected-version policy is a security-policy input, not a compatibility toggle**, so
v0.6 must not silently choose either strictness or compatibility for the operator. A default
in either direction is the kind of implicit fallback the project rejects: defaulting to
draft-02-only would silently break deployed draft-01 clients on upgrade; defaulting to
dual-accept would silently create a downgrade-acceptance posture for deployments that should
be draft-02-only. Therefore the policy is required and unset ⇒ fail closed at startup, with
`draft-02-only` the **recommended** production value and `draft-01-and-draft-02` available
only as an explicit migration posture.

Cross-version downgrade defense distinguishes two outcomes: an unknown/unrecognized version
→ `mcps.unsupported_version` ("cannot select a known profile"); a recognized-but-policy-
forbidden version (e.g. draft-01 under a draft-02-only policy) → `mcps.downgrade_forbidden`
("recognized the lower profile, policy forbids it"). draft-01 / v0.5.1 stays **untouched
except documentation and conformance vectors** — provably byte-for-byte and
verdict-for-verdict compatible with the released baseline.

## Alternatives Considered

- **Draft-02-only runtime.** Rejected: breaks existing draft-01 field traffic at the
  library boundary for no security gain; coexistence is not the vulnerability.
- **Default the expected-version policy to draft-02-only** (the answerer's recommendation).
  Rejected by the owner: silently refuses deployed draft-01 clients on upgrade; the default
  is the operator's security posture to declare.
- **Default to dual-accept.** Rejected: silently opens a downgrade-acceptance hole for
  deployments that should be strict.
- **A dual verifier that falls back from draft-02 to draft-01 on failure.** Rejected:
  fallback is exactly the cross-acceptance/downgrade bug.

## Consequences

### Positive
- Existing draft-01 traffic keeps working; draft-02 is verified strictly; cross-version
  downgrade is structurally blocked and individually auditable.
- No deployment can inherit a version posture by accident.

### Negative
- Every deployment must explicitly configure an expected-version policy or it will not
  start — more operator configuration, accepted as the price of an explicit security posture.

### Neutral
- The dual verifier carries both profiles in one runtime; the profile boundary is the
  enforced separation line.

## Compliance and Enforcement

The v0.6 release gate (irreducible): draft-02 structs (`version: "draft-02"` + protected
`canonicalization_id` + `authorization_binding`); the canonicalization-id allowlist as
explicit constants; fail-closed checks for absent/unknown/ambiguous/mismatched `version`
and `canonicalization_id`; both `authorization_binding` forms implemented and signed; the
nine new codes ([040](adr-mcps-040.md)) with `Display == wire_code()` asserted; the dual
dispatcher with no-fallback/no-cross-accept; draft-02 positive and negative conformance
vectors including draft-01→draft-02 rejection; a draft-01 no-leak proof (existing vectors
pass unchanged and `deny_unknown_fields` rejects draft-02-only fields); black-box wire-code
tests; and downgrade tests. Startup configuration validation fails closed when the
expected-version policy is unset. Vectors and corpus structure are in
[042](adr-mcps-042.md).

## Related

- PRD: none — design resolved directly via the v0.6 grill.
- Decision record: [`mcps-v0.6-grill-decisions.md`](../grilling-seed/mcps-v0.6-grill-decisions.md) (G.1), seed §20.
- Sibling v0.6 ADRs: [037](adr-mcps-037.md), [038](adr-mcps-038.md), [039](adr-mcps-039.md), [040](adr-mcps-040.md), [042](adr-mcps-042.md).
- Code: `mcps-core/src/pipeline.rs`, `mcps-core/src/envelope.rs`, `mcps-core/src/error.rs`.
- Glossary: [`CONTEXT.md`](../../CONTEXT.md).
