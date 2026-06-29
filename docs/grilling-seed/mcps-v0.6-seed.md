# MCP-S v0.6 Grill Seed: Canonical Preimages and Authorization-Evidence Binding

> **Note:** this is the **grill seed**, not a numbered ADR. Its earlier self-title
> "ADR-MCPS-019" collided with an existing ADR (`adr-mcps-019.md`) and was incorrect.
> The resolved decisions (§20) are published as the focused sibling ADRs
> **[ADR-MCPS-037](../adr/adr-mcps-037.md)–[042](../adr/adr-mcps-042.md)**.

**Status:** Grilled — decisions resolved 2026-06-29 (local draft, pre-implementation). See §20.
**Target:** MCP-S draft-02 / v0.6 candidate — to be implemented on a branch and **merged to main as v0.6**.
**Supersedes:** none
**Depends on:** MCP-S draft-01 signing, canonicalization, replay, response-binding, and authorization-hash model
**Decision type:** Security-critical wire/protocol design
**The §15 review questions have been resolved via a Codex-assisted grill (judge-gated, per-branch human sign-off). Resolutions are in §20; full provenance in `mcps-v0.6-grill-decisions.md` + `mcps-v0.6-grill-transcript.md`. Implementation may proceed on the `draft-02/runtime-evidence-preimages` branch against §20; nothing is merged until Mats approves.**

---

## 1. Purpose

This ADR defines how MCP-S should treat canonical byte preimages and authorization-evidence binding in a future draft-02 runtime-evidence profile.

The immediate reason for this ADR is feedback from the MCP runtime-evidence proposal discussion: a runtime-evidence profile cannot safely say only “sign the request” or “bind to an authorization artifact by hash.” It must define the exact bytes that are signed and hashed, and it must do so in a way that is interoperable, auditable, and fail-closed.

This ADR is intentionally written as an input to a security grill. It is not yet a final decision.

---

## 2. Core problem

MCP-S draft-01 already signs and verifies MCP request/response evidence. However, a future standard/profile must be precise enough that independent implementations can cross-verify evidence.

Two implementations can both claim to sign “a canonical representation” of the same request and still produce different byte sequences if they differ on:

* JSON value domain;
* duplicate-key handling;
* number handling;
* Unicode / UTF-8 handling;
* object-key ordering;
* omitted or unsigned fields;
* hash algorithm;
* signature algorithm;
* canonicalization scheme identifier;
* test vectors.

If the signed bytes are not precisely defined, an implementation mismatch becomes indistinguishable from tampering.

The same problem applies to authorization-evidence binding. If a request is bound to an authorization artifact by hash, the verifier and auditor must know what bytes were hashed. Opaque tokens can be hashed as raw bytes. Structured authorization objects require their own canonicalization rules, or the binding cannot be reliably reproduced.

---

## 3. Design goals

This ADR aims to ensure that MCP-S draft-02:

1. makes every security-relevant signed/hash preimage explicit;
2. prevents canonicalization / algorithm confusion;
3. preserves fail-closed behavior;
4. remains auditable after the fact;
5. allows independent implementations to cross-check conformance with test vectors;
6. binds runtime evidence to authorization evidence without turning MCP-S into an authorization system;
7. maintains a clean boundary between runtime evidence and external authorization semantics;
8. avoids breaking draft-01 / v0.5.1 behavior until a draft-02 migration is explicitly chosen.

---

## 4. Non-goals

This ADR does not:

* replace OAuth, OIDC, EMA, or enterprise authorization systems;
* define authorization policy semantics;
* define the meaning of external grants, tokens, or policy decisions;
* require MCP-S to evaluate structured authorization decisions;
* define canonicalization for arbitrary enterprise authorization objects in the base profile;
* change v0.5.1 wire behavior;
* mandate a specific deployment architecture;
* define a full audit receipt format;
* solve prompt injection, tool safety, or tool catalog integrity.

---

## 5. Key distinction

The architecture depends on this separation:

> Authorization decides whether a caller may use a server, tool, or capability.

> Runtime evidence proves what exact MCP call happened under that authorization.

MCP-S should bind a concrete MCP call to selected authorization evidence, but it must not become responsible for interpreting the authorization artifact unless an explicit authorization-binding profile defines that artifact and its canonicalization rules.

---

## 6. Decision summary

For draft-02, MCP-S should treat canonical preimages as first-class protocol artifacts.

There are two preimage categories:

1. **MCP request/response preimages**
   These are the bytes used for runtime-evidence signatures, request hashes, and response binding.

2. **Authorization-evidence binding preimages**
   These are the bytes, digests, or references used to bind a runtime request to external authorization evidence.

The draft-02 profile should define the request/response preimage directly.

The base profile should support two authorization-binding forms:

* opaque artifact byte hashing;
* authorization-system-produced digest/reference binding.

Structured authorization-object hashing should not be part of the base profile. It should require an explicit authorization-binding profile.

---

## 7. Request/response canonical preimage

### 7.1 Decision

MCP-S draft-02 should define the exact byte preimage used for request and response signatures/hashes.

At minimum, the profile must specify:

* JSON value domain;
* duplicate-key handling;
* number handling;
* Unicode / UTF-8 handling;
* object-key ordering;
* omitted, rewritten, or unsigned fields;
* hash algorithm;
* signature algorithm;
* canonicalization identifier;
* conformance test vectors.

### 7.2 Canonicalization identifier

The canonicalization identifier must be protected evidence, not negotiation.

Design principle:

> The canonicalization identifier describes and binds; it does not direct.

The verifier must not read a canonicalization id and then dynamically decide how to verify. That would create an algorithm/canonicalization-confusion risk similar to JWT `alg` confusion.

Instead:

1. the profile version defines the verifier’s allowlist of accepted canonicalization schemes;
2. the protected evidence carries the concrete canonicalization id used;
3. the verifier checks that the protected id matches an allowlisted scheme;
4. unknown, disallowed, mismatched, or downgraded ids fail closed.

### 7.3 Initial candidate scheme

For an initial draft-02 profile, the allowlist should be very small. A single mandatory scheme is preferred unless there is a compelling interoperability reason to support more.

Candidate id:

```text
jcs-rfc8785-mcp-runtime-evidence-json-v1
```

The exact name is not final. The important properties are:

* stable identifier;
* profile-version allowlisted;
* present inside protected evidence;
* covered by the signature/hash preimage;
* tested by conformance vectors.

### 7.4 Required test vectors

Every allowlisted request/response canonicalization scheme must ship test vectors including:

* input JSON;
* validated JSON value domain;
* canonical UTF-8 bytes;
* digest / request hash;
* valid signature;
* valid response binding;
* expected rejection cases.

Rejection cases should include at least:

* duplicate object keys;
* unsafe integer values;
* fractional numbers where not allowed;
* exponent-form numbers if disallowed by the profile;
* invalid UTF-8 or unpaired surrogates;
* parser repair/coercion;
* unknown envelope fields where fail-closed applies;
* mismatched canonicalization id;
* unknown canonicalization id;
* downgrade attempt to another canonicalization id;
* changed signed field;
* changed unsigned/omitted field if the field is not allowed to affect verification;
* modified `signature.value`.

---

## 8. Signature-value exclusion

### 8.1 Decision

The signature value itself must be excluded from the signing preimage.

For a signature-bearing envelope, the preimage construction must remove only the signature value field, not the entire signature object, unless the profile explicitly defines otherwise.

Retaining fields such as `alg`, `key_id`, `canonicalization_id`, and profile version inside the protected bytes prevents confusion and downgrade.

### 8.2 Grill question

Should draft-02 retain the draft-01 rule exactly — removing only `signature.value` while retaining `signature.alg` and `signature.key_id` — and additionally retain `canonicalization_id` in the protected bytes?

Expected answer unless contradicted by review:

> Yes. The signature value cannot sign itself, but all security-control fields that define how the signature is verified should remain protected.

---

## 9. Profile version vs canonicalization id

### 9.1 Decision

The profile version and canonicalization id have separate roles.

**Profile version:**

* defines the verifier’s allowlist;
* defines validation rules;
* defines supported algorithms;
* defines envelope structure;
* defines error behavior.

**Canonicalization id:**

* records which allowlisted scheme was used;
* makes evidence self-describing for auditors;
* is protected by the signature/hash preimage;
* cannot introduce new verifier behavior.

### 9.2 Forbidden behavior

A verifier must not:

* load a canonicalization implementation only because the message names it;
* accept a canonicalization id not allowed by the profile version;
* treat the canonicalization id as negotiation;
* silently fall back to a default if the protected id is unknown or mismatched;
* accept a message where the evidence says one scheme but verification used another.

---

## 10. Authorization-evidence binding

### 10.1 Problem

Authorization-evidence binding also has a preimage problem.

If MCP-S binds a request to an authorization artifact by hash, the profile must define what was hashed or what digest/reference is being bound.

The runtime-evidence profile must not reinterpret authorization semantics. It should only bind the MCP call to selected authorization evidence in a reproducible and auditable way.

### 10.2 Decision

The base runtime-evidence profile should support three conceptual cases, but only the first two should be part of the base profile.

---

### Case 1 — Opaque authorization artifact

If the authorization artifact is opaque, such as an access token, opaque grant, or authorization blob, the binding hashes the exact bytes as received.

No canonicalization claim is needed because the runtime-evidence layer does not parse or reinterpret the artifact.

Required metadata:

* digest algorithm;
* digest value;
* artifact type marker such as `opaque-bytes`, if needed;
* optional source/reference metadata if useful for audit.

The profile must define whether the digest covers:

* raw token bytes;
* transport-decoded bytes;
* base64-decoded bytes;
* UTF-8 string bytes;
* some other exact byte representation.

This must not be left implicit.

---

### Case 2 — Authorization-system-produced digest or reference

If the authorization system already produced a digest, decision id, grant id, or decision reference under its own declared scheme, MCP-S should bind to that value rather than reinterpret the authorization object.

This is the preferred enterprise shape.

The authorization system remains responsible for:

* policy semantics;
* decision semantics;
* artifact schema;
* artifact canonicalization;
* digest construction;
* revocation/lifecycle;
* audit reconstruction of its own decision.

MCP-S remains responsible for:

* binding the MCP call to that digest/reference;
* making the binding visible in runtime evidence;
* ensuring the binding is covered by the MCP-S request preimage;
* making the binding reproducible from the evidence presented.

---

### Case 3 — Structured authorization artifact hashed by MCP-S

If a deployment expects MCP-S itself to hash a structured authorization artifact, then that artifact reopens the canonicalization problem.

This should not be part of the base profile.

It should be allowed only through an explicit authorization-binding profile that defines:

* artifact type;
* artifact schema or value domain;
* duplicate-key handling;
* number handling;
* Unicode / UTF-8 handling;
* object-key ordering;
* omitted, rewritten, or unsigned fields;
* canonicalization id;
* hash algorithm;
* test vectors;
* rejection cases;
* lifecycle expectations;
* audit reconstruction rules.

The authorization-evidence canonicalization id must follow the same principle:

> The authorization-evidence canonicalization id describes and binds; it does not direct.

Unknown, disallowed, mismatched, or downgraded ids fail closed.

---

## 11. Base-profile authorization-binding decision

For draft-02 base profile:

1. support opaque-byte authorization artifact binding;
2. support authorization-system-produced digest/reference binding;
3. do not define canonicalization for arbitrary structured authorization decisions;
4. require structured authorization-object hashing to use an explicit authorization-binding profile.

This keeps the boundary clean:

> Authorization systems decide and define their artifacts.

> Runtime evidence binds the MCP call to selected authorization evidence in a reproducible and auditable way.

---

## 12. Fail-closed requirements

Draft-02 must fail closed for at least the following cases:

* unsupported profile version;
* missing required canonicalization id;
* unknown canonicalization id;
* canonicalization id not allowed by the profile version;
* canonicalization id mismatch;
* downgrade attempt;
* malformed protected evidence;
* duplicate keys in protected JSON domain;
* unsafe numbers in protected JSON domain;
* invalid UTF-8 / invalid Unicode scalar values;
* parser repair/coercion;
* signature verification failure;
* request hash mismatch;
* response hash mismatch;
* replay detected;
* replay cache unavailable, if replay protection is required;
* trust resolver unavailable, if trust resolution is required;
* authorization binding required but missing;
* structured authorization artifact supplied without an explicit binding profile;
* authorization digest/reference malformed;
* opaque artifact digest computed over ambiguous bytes.

No failure in a security-critical verification step may fall back to allow.

---

## 13. Draft-01 compatibility and draft-02 migration

### 13.1 Draft-01 behavior

MCP-S draft-01 / v0.5.1 already defines a concrete signing and canonicalization model. It should remain stable unless a deliberate draft-02 wire migration is approved.

This ADR must not be implemented as an in-place change to the draft-01 wire contract.

### 13.2 Draft-02 candidate change

Adding a protected canonicalization id to the evidence envelope is a wire-contract change.

Therefore, it belongs to:

* draft-02;
* v0.6.0-alpha;
* or another explicitly marked experimental profile.

It should not be backported silently into v0.5.1.

### 13.3 Migration rule

Draft-01 and draft-02 verifiers must not silently accept each other’s evidence unless explicit compatibility rules are defined.

Possible migration approaches:

1. strict separation by profile version;
2. dual verifier that explicitly selects draft-01 or draft-02 by version;
3. compatibility mode only in test/demo tooling, not production;
4. hard rejection of ambiguous or missing profile version.

Preferred initial posture:

> Strict separation by profile version.

---

## 14. Conformance requirements

Before implementation is considered complete, draft-02 must have conformance tests for:

### Request/response preimage

* canonical bytes for representative request;
* canonical bytes for representative response;
* request hash;
* response binding;
* valid request signature;
* valid response signature;
* tampered request rejection;
* tampered response rejection;
* wrong request hash rejection;
* wrong canonicalization id rejection;
* unknown canonicalization id rejection.

### JSON safety

* duplicate keys rejected;
* unsafe integers rejected;
* fractional/exponent numbers rejected if outside profile;
* invalid Unicode rejected;
* parser repair rejected;
* unknown protected fields rejected or explicitly handled.

### Authorization binding

* opaque artifact byte hash reproducibility;
* authorization-system digest/reference binding;
* malformed digest/reference rejection;
* structured authorization object rejected unless explicit binding profile is active;
* structured authorization object accepted only with explicit binding profile and matching canonicalization id.

### Downgrade / confusion

* protected canonicalization id changed after signing;
* profile version changed after signing;
* canonicalization id allowed in another profile but not this one;
* declared canonicalization id differs from verifier-used scheme;
* signature algorithm changed after signing;
* hash algorithm changed after signing.

---

## 15. Security review questions

The ADR is not accepted until these questions have been grilled.

### Canonicalization and preimage

1. Is the proposed “canonicalization id describes and binds; does not direct” rule sufficient to prevent canonicalization confusion?
2. Should the canonicalization id be mandatory in draft-02 evidence?
3. Should the profile support exactly one canonicalization scheme in draft-02?
4. Are there any fields besides `signature.value` that must be excluded from the preimage?
5. Are observability fields excluded, signed, or handled by a separate rule?
6. Does retaining `alg`, `key_id`, and `canonicalization_id` in the protected bytes create any circularity problem?
7. Is the JSON value domain too strict, too loose, or appropriate for security evidence?

### Authorization evidence

8. Is opaque-byte binding sufficiently precise, or must artifact byte representation be further typed?
9. Is authorization-system digest/reference binding the right preferred enterprise shape?
10. Does binding to a decision id create audit reconstruction risk if the external system later loses the decision record?
11. Should the runtime-evidence profile require both a digest and a decision id for enterprise auditability?
12. Should structured authorization-object hashing be excluded from the base profile?
13. What minimum metadata is required for authorization-evidence binding to be auditable?

### Boundary

14. Does this ADR preserve the boundary between runtime evidence and authorization semantics?
15. Is there any hidden place where MCP-S starts interpreting authorization artifacts?
16. Does the verifier need to know the authorization artifact type, or only the binding type?

### Fail-closed behavior

17. Are all canonicalization and authorization-binding failures mapped to fail-closed outcomes?
18. Is there any plausible fallback-to-allow path?
19. Are resolver/cache unavailability cases handled correctly?

### Migration

20. Is strict draft-01/draft-02 separation the right migration posture?
21. Should v0.5.1 remain untouched except for documentation/conformance vectors?
22. What is the minimum draft-02 implementation needed before public release?

---

## 16. Proposed implementation plan

### Phase 0 — No wire changes

* Write this ADR.
* Grill this ADR.
* Update proposal text if needed.
* Inventory current draft-01 canonicalization behavior.
* Add or improve draft-01 conformance vectors.
* Add negative tests for current fail-closed behavior.

### Phase 1 — Draft-02 branch

Create a branch such as:

```text
draft-02/runtime-evidence-preimages
```

On that branch:

* add canonicalization id model;
* add profile-version allowlist;
* add fail-closed mismatch checks;
* add authorization-binding model for opaque bytes and digest/reference;
* reject structured authorization-object hashing unless explicit profile is active;
* add draft-02 conformance vectors.

### Phase 2 — Security review

Before merge:

* run adversarial review against this ADR;
* run test-vector review;
* run compatibility review;
* run downgrade/confusion review;
* compare against JWS/COSE/JWT failure patterns;
* verify no wire change leaks into draft-01/v0.5.1.

### Phase 3 — Release only as draft-02 / v0.6 alpha

If accepted:

* release as draft-02 or v0.6.0-alpha;
* label as wire-contract change;
* document migration from draft-01;
* keep v0.5.1 stable.

---

## 17. Provisional decision

The provisional decision is:

> MCP-S draft-02 will treat canonical preimages as first-class protocol artifacts. The runtime-evidence profile will define exact byte preimages for request/response signatures and hashes, and will define safe authorization-evidence binding forms without making MCP-S responsible for authorization semantics.

More specifically:

1. request/response canonicalization must be explicit and test-vector backed;
2. canonicalization id must be protected evidence, not negotiation;
3. profile version defines the verifier allowlist;
4. unknown, mismatched, or downgraded canonicalization ids fail closed;
5. opaque authorization artifacts are bound by hashing exact bytes as received;
6. authorization-system-produced digests/references are preferred for enterprise authorization binding;
7. structured authorization-object hashing is out of base-profile scope and requires an explicit authorization-binding profile;
8. no draft-02 wire change should be merged until this ADR survives security review.

---

## 18. Open issues

* Exact canonicalization id string.
* Exact envelope field name for protected canonicalization id.
* Whether the request and response use the same canonicalization id or separately declare them.
* Whether authorization-binding metadata belongs in the main request envelope or a nested binding object.
* Exact digest format for opaque authorization artifacts.
* Whether enterprise binding should require decision id, digest, or both.
* Whether test vectors should include detached authorization artifacts.
* Exact error taxonomy for canonicalization-id mismatch vs unsupported scheme vs downgrade.
* Whether draft-02 should support one canonicalization scheme only.
* Whether observability metadata is excluded, signed, or separately constrained.

---

## 19. Grill acceptance criteria

This ADR can move from draft to accepted only when:

* all security review questions have been answered or explicitly deferred;
* all deferrals are marked non-blocking with rationale;
* draft-01 compatibility impact is clear;
* draft-02 wire changes are identified;
* conformance-vector requirements are complete;
* fail-closed behavior is specified for every parsing, canonicalization, digest, resolver, replay, and binding failure;
* the authorization/runtime-evidence boundary remains clean;
* at least one adversarial reviewer has tried to break the design.

---

## 20. Resolved decisions (grill outcome, 2026-06-29)

Resolved via Codex-assisted grill (Claude griller, Codex answerer, judge scored against the decision-stance profile, per-branch human sign-off). Provenance tags and the full transcript live in `mcps-v0.6-grill-decisions.md` / `mcps-v0.6-grill-transcript.md`.

**A. Scope.** The draft-02 wire change is implemented on a branch and **merged to main as release v0.6** — a real wire-envelope change, not a Phase-0 paper design. The §5 bind-not-interpret boundary already holds in code and is preserved.

**B.1. Number domain — integer-only kept (intentional, named, tested limitation).** The first v0.6 canonicalization scheme keeps the draft-01 integer-only JSON number domain (±(2^53−1)). Fractional numbers, exponent-form numbers, NaN/Inf are rejected before signature verification with `mcps.canonicalization_failed`. Rationale: full RFC 8785 fractional-number (ECMAScript number-to-string) serialization is the highest-risk surface for independent implementations to disagree byte-for-byte; the first security-critical scheme chooses the stricter domain. **Consequence (documented, not silent): MCP-S v0.6 does not protect MCP messages whose signed payload contains JSON fractional numbers** (e.g. `{"temperature":0.7}`, `{"price":19.99}`, `{"latitude":55.7047}`); they fail closed unless represented outside the JSON number domain or handled by a later scheme. The scheme id is renamed to make the restriction visible: **`mcps-jcs-int53-json-v1`** (the prior `jcs-rfc8785-…` name misleadingly implied full RFC 8785). Floats are deferred to a later, separately-named, separately-vector-hardened scheme via the profile-version allowlist.

**B.2. Envelope identifiers.** Two non-overloaded **protected** fields in both request and response envelopes, both inside the signing preimage: `version: "draft-02"` (wire-version / profile-version authority) and `canonicalization_id: "mcps-jcs-int53-json-v1"` (records the scheme; self-describing for audit). `canonicalization_id` is mandatory even with one scheme (evidence self-description for historical verification). Verification order: read `version`+`canonicalization_id` as untrusted selectors → require `version=="draft-02"` → select the draft-02 profile whose allowlist is exactly `{mcps-jcs-int53-json-v1}` → require the id ∈ allowlist → canonicalize via the **profile-selected** scheme (never field-directed) → build preimage retaining `alg`/`key_id`/`canonicalization_id` → verify → trust. No circularity; "describes and binds, does not direct."

**C.1. Preimage exclusion set.** Keep the draft-01 container-vs-nested trace-key asymmetry, written as an explicit JSON-path predicate. Exclude only: the envelope `signature.value`, and the three W3C keys `traceparent`/`tracestate`/`baggage` at **container-level** `params._meta` (req) / `result._meta` (resp). Nothing recursive, nothing by key-name alone, nothing in `arguments`/`content`/nested `_meta`/the envelope (recursive name-based exclusion would let an attacker relocate security bytes under a reserved observability name to strip integrity). All other fields signed; unknown fields rejected (`deny_unknown_fields`).

**D.1. Profile-version vs canonicalization-id.** §9 separation upheld (resolved by B.2): `version` directs (allowlist + rules + algorithms + structure + error behavior); `canonicalization_id` describes/binds. All §9.2 forbidden behaviors are prevented by B.2's verification order.

**E.1/E.2. Authorization-evidence binding.** Replace the bare signed envelope field `authorization_hash` with a signed `authorization_binding` object (the envelope carries the binding contract; the `_meta` block `se.syncom/mcps.authorization = {profile, artifact}` carries profile-specific evidence). Two base `binding_type` forms, **both implemented in v0.6**:

* `opaque-bytes` — `{binding_type, digest_alg:"sha256", digest_value}`; the digest is over the **transport-decoded** artifact bytes (base64url-no-pad decode → SHA-256), never the base64 text or UTF-8 JSON string bytes.
* `authz-system-reference` — `{binding_type, authorization_system_id, reference_scheme_id, reference_value, digest_alg:"sha256", digest_value}`; **all six fields mandatory**. The digest is mandatory and self-contained so the record is **historically verifiable** independent of the external system's live state; the reference is cross-audit metadata, not the cryptographic binding (a reference-only binding would be a live-system dependency = defect). The authorization system produces `digest_value` under `reference_scheme_id`; MCP-S binds it, never recomputes/interprets it (§5 intact).

Structured authorization-object hashing stays **out of the base profile** (requires an explicit authorization-binding profile). `binding_type` (how the call is bound) and `profile` (how the artifact is interpreted) are **separate axes**; the profile must not imply the binding form. Digest representation is the **split** form (`digest_alg` + bare `digest_value`, no `sha256:` prefix) for both forms — security parameters are explicit protected fields; legacy `sha256:<digest>` identifiers (`request_hash` etc.) are **not** retrofitted in v0.6 (two-convention wart documented as future cleanup).

**F.1. Fail-closed taxonomy.** Granular wire codes for protocol/profile-confusion failures, coarse (`mcps.canonicalization_failed`) for low-level JSON value-domain/parser failures (attacker-oracle is weak here; defender telemetry is strong). **Nine new draft-02 wire codes:** `mcps.canonicalization_id_missing` / `_unknown` / `_not_allowed` / `_mismatch`; `mcps.authorization_binding_type_unsupported` / `_malformed` / `_profile_required` / `_ambiguous_bytes`; and `mcps.authorization_binding_missing` (minted new — `mcps.authorization_hash_missing` is **not** reused in draft-02; it stays the draft-01 code, since draft-02 structurally replaces the bare hash with a typed object). Reuse `downgrade_forbidden` / `unsupported_version` / `canonicalization_failed` / `unknown_envelope_field` / signature/response/replay/resolver codes. Every §12 case maps to a code; **no fallback-to-allow** anywhere. New codes are draft-02-scoped; the drift guard + audit rejection vocabulary inherit them (`reason == wire_code()` verbatim).

**G.1. Migration & release posture.** Ship a **dual verifier with strict version dispatch** (not draft-02-only): `envelope.version` is the sole profile selector; each verifier rejects the other's evidence; no fallback-retry, no cross-acceptance (cross-acceptance is the bug, coexistence is not). v0.5.1/draft-01 stays **untouched except docs + conformance vectors** (provably byte/verdict compatible). The **expected-version policy is a required explicit input with no default** — if unset, the verifier/service **fails closed at configuration/startup**; `draft-02-only` is the recommended production value, `draft-01-and-draft-02` an explicit migration posture. Downgrade defense: unknown/unrecognized version → `mcps.unsupported_version`; recognized-but-policy-forbidden → `mcps.downgrade_forbidden`. A 10-item release gate (structs, allowlist constants, fail-closed version/canon-id checks, both binding forms, the 9 codes, dual dispatcher, ± conformance vectors, draft-01 no-leak proof, black-box wire-code tests, downgrade tests) is the irreducible bar for v0.6.

**H.1. Conformance corpus.** A **separate, byte-frozen draft-02 corpus** (`tests/vectors/draft-02/manifest.json`); the draft-01 corpus stays frozen so the no-leak property is mechanical. Manifest gains `envelope_version`, `canonicalization_id`, `version_policy{accepted_versions, downgrade}`, and an `oracle{canonical_preimage_b64url, canonical_preimage_sha256, signature_value, request_hash}`. Ship **both** a regenerated drift-guard set **and a frozen static interop oracle** (committed canonical bytes + digest + signature) — regenerating with our own crypto proves self-consistency, not cross-implementation agreement. A float-rejection (int53 honesty) vector is **required**, plus vector classes for canonical determinism, raw duplicate protected fields, signed-wrong-profile, unknown-but-signed canon-id, response/request profile mismatch, authorization-binding oneof violation, and historical-trust-material verification.

**Open (non-blocking) items:** exact `canonicalization_id` literal suffix; whether `-0` is rejected vs normalized in the int53 vector; the two-digest-convention cleanup.
