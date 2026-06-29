# ADR-MCPS-019 (MCP-S v0.6) — Grill Decision Summary

**Status: LOCAL DRAFT — not published to the ADR until Mats approves this summary.**
Mode: Codex-assisted (griller = Claude, answerer = Codex, judge = stance-profile rubric, per-branch sign-off = Mats).
Companion transcript: `mcps-v0.6-grill-transcript.md`.

Provenance tags: `[user]` = Mats decided directly · `[Codex, judge-passed]` = auto-accepted · `[Codex, user-confirmed]` = escalated, Mats agreed · `[user, Codex-overridden]` = Codex answered, Mats overrode.

---

## Branch A — Scope & boundary

- **A.1 — Near-term scope.** `[user]`
  The draft-02 wire change (protected `canonicalization_id` + authorization-binding metadata + profile handling) is **implemented on a branch and merged to main as release v0.6** — a real release carrying a wire-envelope change, not a Phase-0 paper design. The 0.5 draft-01-freeze rule does not bind 0.6; 0.6 is the "dedicated ADR justifies a field change" exception.
  The §5 bind-not-interpret boundary already holds in code (`pipeline.rs:348` opaque-hash-only; `evaluator.rs:85` interprets in the profile layer). Branch closed.

## Branch B — Request/response preimage

- **B.1 — JSON number domain.** `[user, Codex-overridden]`
  **Keep the integer-only domain (±(2^53−1)) for the v0.6 first canonicalization scheme.** Fractional/exponent numbers, NaN/Inf remain rejected before verification with `mcps.canonicalization_failed`. This is an **intentional, named, tested scope boundary**, not a parser accident.
  - **Rationale:** the first scheme optimizes for deterministic cross-implementation preimage agreement; full RFC 8785 fractional-number (ES6 number-to-string) canonicalization is the highest-risk interop surface and is deferred to a later, separately-named, separately-vector-hardened scheme via the allowlist mechanism.
  - **Consequence (must be documented honestly):** MCP-S v0.6 does **not** protect MCP messages whose signed payload contains JSON fractional numbers (`{"temperature":0.7}`, `{"price":19.99}`, `{"latitude":55.7047}`). Such messages fail closed unless the values are represented as strings or a future scheme supports them.
  - **Rename the scheme** so the restriction is visible: `jcs-rfc8785-mcp-runtime-evidence-json-v1` → **`mcps-jcs-int53-json-v1`** (current `…-rfc8785-…` name misleadingly implies full RFC 8785).
  - **Required v0.6 vectors:** integer accepted; max-safe-int accepted; min-safe-int accepted; above-max rejected; below-min rejected; fractional rejected; exponent rejected; `-0` rejected-or-normalized per exact rule; `19.99` rejected; `0.7` rejected.
  - **Doc surfaces to update on approval:** proposal text, ADR §7, conformance guide, release notes. (Draft ADR §B.1 text is staged in the transcript; insert only after summary approval.)
  - **Codex dissent (recorded):** Codex recommended expanding to full RFC 8785 floats in v1 with exhaustive IEEE-754 vectors, arguing integer-only is "deferred failure." Overridden.
  - **Learning-log candidate (confirm at branch sign-off):** for cross-implementation crypto preimages, strictest-deterministic-domain + documented limitation beats widening the highest-risk surface, even against S1's "do the full thing now." → refines S1 vs S10/S14 boundary. Standing or case-specific?

- **B.2 — Envelope identifier design.** substance `[Codex, judge-passed]`; naming `[Codex, user-confirmed]`
  v0.6 carries **two non-overloaded identifiers** in every signed envelope:
  - `version: "draft-02"` — the **wire/envelope version**, profile-version authority (distinct from the `0.6` release number; follows the existing `draft-NN` convention). Defines the verifier's allowlist, validation rules, algorithms, envelope structure, error behavior.
  - `canonicalization_id: "mcps-jcs-int53-json-v1"` — **protected canonicalization evidence**; records which allowlisted byte scheme was used, self-describing for audit. Name confirmed by Mats over `canonicalization_scheme` because the field is a protected identifier checked against the profile-version allowlist — **not negotiation, must not direct verification** (the §7.2 "describes and binds; does not direct" principle).
  - **Mandatory even with one scheme** — behavior-redundant in v0.6 but **not evidence-redundant**: a signed record must be self-describing for historical verification (S16). Missing/different value → fail closed.
  - **Both fields top-level members of BOTH envelopes, inside the signing preimage.** The response envelope (which today carries neither) gains **both** `version` and `canonicalization_id` — the response is an independently signed server-evidence record and must be self-describing standalone (S16), not dependent on the bound request to recover its profile/scheme context. `signature.value` excluded from the preimage as usual.
  - **No circularity — verification order:** (1) parse raw JSON, read `version`+`canonicalization_id` as UNTRUSTED selectors; (2) require `version=="draft-02"`; (3) load draft-02 profile, allowlist = exactly `{mcps-jcs-int53-json-v1}`; (4) require `canonicalization_id` ∈ allowlist; (5) canonicalize via the **profile-selected** scheme (never field-directed); (6) build preimage removing only `signature.value`, retaining `alg`/`key_id`/`canonicalization_id`; (7) verify signature, then enforce rest. Field is read before verification, trusted only after — same pattern as `alg`/`key_id` today.
  - **§9 separation upheld:** profile-version directs, canonicalization-id describes. (ADR Q1 / §7.2 answered: rule is sufficient given profile-allowlist + read-untrusted/trust-after-verify.)

### Branch B cascade (resolved)
- **Exactly one** canonicalization scheme in the v0.6 verifier allowlist (floats = future `…-v2` scheme). → §7.3 / Q3.
- v0.6 scheme id string = `mcps-jcs-int53-json-v1`. → open-issue "exact canonicalization id string."
- Envelope field name for the protected canon id = `canonicalization_id`. → open-issue "exact envelope field name."
- Request and response **share** the same `canonicalization_id` value but each declares its own (both protected). → open-issue "request/response same canon id or separate."

---

## Branch C — preimage exclusion set

- **C.1 — Observability exclusion / full preimage field set.** `[Codex, judge-passed]`
  **Keep the draft-01 container-vs-nested trace-key asymmetry** — it is the stricter, correct boundary, not a smell. Formalize draft-02's exclusion as an **explicit JSON-path predicate**, excluding ONLY:
  1. the envelope signature value — req `/params/_meta/se.syncom~1mcps.request/signature/value`, resp `/result/_meta/se.syncom~1mcps.response/signature/value`;
  2. the three W3C keys `traceparent`/`tracestate`/`baggage` **only at container-level** `params._meta` (req) / `result._meta` (resp).
  **Nothing recursive, nothing by key-name alone, nothing inside `arguments`/`content`/nested `_meta`/the envelope.** Rationale: the same string key is not the same protocol field at every path — container trace keys are mutable-by-design observability (tracing infra rewrites them); a `traceparent` under `params.arguments._meta` or `result.content[*]._meta` is payload, and recursive name-based exclusion would let an attacker relocate security bytes under a reserved observability name to strip integrity (S14/S2/S5).
  - **No other exclusions.** `version`, `canonicalization_id`, `alg`, `key_id`, `authorization_hash`, `request_hash`, signer/audience/on_behalf_of, nonce, timestamps, method, params, arguments, result all stay signed. Unknown fields are **rejected** (`deny_unknown_fields`), never silently excluded.
  - **Vectors (assert bytes/hashes, not print — S8):** container-rewrite-still-verifies (req+resp); nested-rewrite-fails (`params.arguments._meta`, `result.content[0]._meta`); both-present split; mutate `version`/`canonicalization_id`/`alg`/`key_id`/non-trace `_meta` peer → fail; independent byte-equality vector recomputing the preimage by deleting exactly the predicate.

## Branch D — profile-version vs canon-id roles
- **D.1 — Resolved by B.2 (derived).** §9 separation upheld: `version:"draft-02"` directs (verifier allowlist + rules + algorithms + structure + error behavior); `canonicalization_id` describes/binds (records the scheme, cannot introduce verifier behavior). All §9.2 forbidden behaviors are prevented by B.2's verification order (no field-directed canonicalization, no out-of-allowlist id, no negotiation, no silent fallback, no accept-on-mismatch). No separate question needed.

---

## Branch E — authorization-evidence binding

- **E.1 — Auth-binding wire surface.** shape/vocabulary `[Codex, user-confirmed]`; scope `[user]` (Claude rec overridden as too conservative)
  - **Shape:** replace the bare signed envelope field `authorization_hash` with a signed **`authorization_binding` object** in draft-02. The authorization evidence block stays where it is: `se.syncom/mcps.authorization = { profile, artifact }` in the sibling `_meta`. **The envelope carries the binding contract; the `_meta` block carries profile-specific authorization evidence.** (Preserves the existing binding-in-envelope / evidence-in-`_meta` separation; the object is inside the signing preimage, all-string values → clean under int53.)
  - **Scope — both base forms in v0.6:** `opaque-bytes` AND `authz-system-reference`. (Mats overrode Claude's conservative "opaque-only, reserve system" rec — S1.) **Case 3 (structured authorization-object hashing) stays OUT of the base profile** — allowed only via an explicit authorization-binding profile that defines artifact schema, canonicalization, hash algorithm, and vectors.
  - **§5 boundary constraint (Mats):** `authz-system-reference` must NOT make MCP-S responsible for interpreting authorization semantics — it only **binds** the MCP request to an authorization-system-produced digest / decision id / grant id / reference.
  - **Vocabulary (ratified):** object `authorization_binding`; discriminator `binding_type`; values `opaque-bytes` / `authz-system-reference`; digest-algorithm token `sha256` (matches existing `sha256:` convention, not `sha-256`).
  - **Two separate axes (Mats):** `binding_type` = *how the MCP call is bound to* authorization evidence; `profile` = *how the evidence/artifact is interpreted*. The profile must NOT imply the binding form.
  - **Opaque-bytes representation (verified, matches code):** hash the **transport-decoded** artifact bytes — read `_meta["se.syncom/mcps.authorization"].artifact`, base64url-no-pad decode, SHA-256, b64url-no-pad encode; never the base64 text or UTF-8 JSON string bytes (`lib.rs:9-11`, `evaluator.rs:83-87`).
  - **Layer ownership:** Core requires `authorization_binding`, validates `binding_type` ∈ base values + mandatory fields + digest shape, copies into verified context — never hashes/fetches/parses/authorizes. Policy profile reproduces & compares (opaque) or verifies the system reference (system form).
- **E.2 — `authz-system-reference` field schema (Q10/Q11/Q13).** substance `[Codex, judge-passed]`; naming `[Codex, user-confirmed]`
  - **Require BOTH digest and reference — all six fields mandatory, none optional:**
    ```json
    {
      "binding_type": "authz-system-reference",
      "authorization_system_id": "<external authz system namespace>",
      "reference_scheme_id":     "<authz system's scheme: what reference_value means + how digest produced>",
      "reference_value":         "<decision id / grant id / reference handle>",
      "digest_alg":  "sha256",
      "digest_value": "<base64url-no-pad>"
    }
    ```
  - **S16 rationale (Q10/Q11):** digest is mandatory and **self-contained** — historical verification must be possible from the signed MCP-S record + archived external evidence + trust material valid at signature time, **independent of the external system's live DB state**. Reference-only would be a live-system dependency that becomes non-reconstructable on purge/rotation = a **defect** under S16. Digest-only gives no audit route to the decision. So both, always. `reference_value` is cross-reference metadata, not the cryptographic binding.
  - **Min auditable metadata (Q13)** = exactly those fields; do not duplicate envelope-level signer/key_id/issue-time/version/canonicalization_id inside the binding.
  - **§5 preserved:** the authorization system computes `digest_value` under `reference_scheme_id`; MCP-S signs/verifies the *presence* of digest+reference metadata and binds it — never recomputes over a structured artifact, never interprets/decides.
  - **Digest representation — split form, ratified, applied to BOTH binding forms:** `digest_alg:"sha256"` + `digest_value:"<base64url-no-pad>"` (no `sha256:` prefix). Security parameters are explicit protected fields — matches `canonicalization_id` / `binding_type` / `signature.alg`. **Do NOT retrofit** `request_hash` or other legacy `sha256:<digest>` identifiers in v0.6 (out of scope, S10); document the two-convention wart as future cleanup.

### Branch E resolved
ADR auth-evidence questions Q8–Q16 all covered: opaque binding typed (Q8); system reference is the enterprise shape (Q9); audit-reconstruction handled by mandatory self-contained digest (Q10); both digest+reference required (Q11); structured hashing excluded from base (Q12); min metadata fixed (Q13); boundary preserved, no hidden interpretation, verifier needs only `binding_type` not artifact type (Q14/15/16).

**Self-calibration (E.1 scope) — RESOLVED at C+E sign-off:** no new standing stance; bias Claude's own scope-sizing recs more aggressive per S1/S2 (judge escalated correctly; gap was Claude's cautious rec). Profile unchanged. (cf. GL grill A.6.)

**Branches C, D, E signed off by Mats.**

---

## Branch F — fail-closed error taxonomy

- **F.1 — Granularity + new wire codes (§12, §18).** philosophy/mapping `[Codex, judge-passed]`; names `[Codex, user-confirmed]`; `authorization_binding_missing` `[user, Codex-overridden]`
  - **Granularity rule:** GRANULAR for protocol/profile-confusion failures, COARSE for low-level JSON value-domain/parser failures (stay `mcps.canonicalization_failed`). Reasoning: the attacker-oracle argument is weak (attacker controls the public profile/canon fields; the allowed scheme is public conformance data; rejection is still fail-closed), while defender telemetry is strong (unknown-id probe vs disallowed-future-scheme probe vs downgrade are distinct attack shapes — S14). Keep coarse where granularity would leak internal trust/key state or parser trivia (`invalid_signature`, `actor_binding_failed`, `canonicalization_failed` stay broad).
  - **9 new draft-02 wire codes:**
    ```
    mcps.canonicalization_id_missing       mcps.authorization_binding_type_unsupported
    mcps.canonicalization_id_unknown       mcps.authorization_binding_malformed
    mcps.canonicalization_id_not_allowed   mcps.authorization_binding_profile_required
    mcps.canonicalization_id_mismatch      mcps.authorization_binding_ambiguous_bytes
    mcps.authorization_binding_missing     (← minted, NOT reused authorization_hash_missing)
    ```
  - **`authorization_hash_missing` is NOT reused in draft-02** (Mats overrode Codex's ADR-007-reuse): draft-02 structurally *replaces* the bare hash string with a typed `authorization_binding` object, so reusing the old token would name a field that no longer exists on the draft-02 wire. `authorization_hash_missing` stays the **draft-01** code; `authorization_binding_missing` is the **draft-02** code. Strict version separation makes a clean, accurate native taxonomy preferable to cross-version reuse of a misleading legacy token; audit systems can group both semantically if needed.
  - **Reused existing codes:** `downgrade_forbidden` (downgrade attempt), `unsupported_version` (bad/absent profile version), `canonicalization_failed` (JSON value-domain: dup keys / unsafe ints / invalid UTF-8 / parser repair), `unknown_envelope_field`, `invalid_signature`, `response_sig_invalid`, `response_hash_mismatch`, `replay_detected`, `replay_cache_unavailable`, `trust_resolver_unavailable`.
  - **§12 fully mapped, NO fallback-to-allow** anywhere; resolver/cache-unavailable stay fail-closed under existing codes.
  - **Scoping:** new codes are draft-02 profile outcomes; draft-01 verification must not emit them unless running the draft-02 verifier. Drift guard + audit rejection vocabulary inherit them automatically (reasons = `wire_code()` verbatim) — extend `McpsError`/`wire_code()`/labels/tests; no parallel reason list.
  - **Naming self-calibration:** Codex leaned to legacy-token reuse (conservative/precedent-bound); Claude+Mats preferred accurate draft-02-native naming. Consistent with S13 + strict-separation; no new stance.

---

## Branch G — migration & release posture (§13, Q20/Q21/Q22)

- **G.1 — Dual verifier, strict dispatch, required expected-version policy.** substance `[Codex, judge-passed]`; default-policy `[user, Codex-overridden]`
  - **Dual verifier, strict version dispatch (NOT draft-02-only):** draft-01/v0.5.1 is the released field baseline, so coexistence is required; **cross-acceptance is the bug, coexistence is not.** `envelope.version` is the **sole** wire-profile selector: `"draft-01"`→draft-01 verifier only, `"draft-02"`→draft-02 verifier only; each MUST reject the other's evidence; **no fallback-retry, no cross-accept.** `version` is read as an untrusted selector, then the chosen profile enforces its exact signed value. Shared code only *below* the profile boundary (JCS, hashing, signature primitives); profile semantics never merged.
  - **v0.5.1 / draft-01 UNTOUCHED** except documentation + conformance vectors — provably byte-for-byte and verdict-for-verdict compatible with the released baseline.
  - **Expected-version policy — REQUIRED, no default (Mats overrode Codex's default-strict):** the expected-version policy is a security-policy input, not a compatibility toggle; v0.6 must not silently choose strictness or compatibility for the operator. **If unset, the verifier/service fails closed at configuration/startup time.** `draft-02-only` = recommended production value; `draft-01-and-draft-02` = available only as an explicit migration posture. (Direct application of S4 required-deps-no-fallback + S15 fail-closed; a default in either direction is the implicit fallback the stances reject.)
  - **Cross-version downgrade defense:** unknown/unrecognized version → `mcps.unsupported_version` ("cannot select a known profile"); recognized-but-policy-forbidden version (e.g. draft-01 under a draft-02-only policy) → `mcps.downgrade_forbidden` ("recognized the lower profile, policy forbids it").
  - **v0.6 release gate (irreducible, 10 items):** (1) draft-02 structs `version:"draft-02"` + protected `canonicalization_id` + `authorization_binding`; (2) canon-id allowlist as explicit constants, not free strings; (3) fail-closed checks for absent/unknown/ambiguous/mismatched `version` & `canonicalization_id`; (4) both `authorization_binding` forms implemented + signed; (5) 9 new codes in `McpsError` with `Display==wire_code` asserted; (6) dual dispatcher, no-fallback/no-cross-accept; (7) draft-02 +/- conformance vectors (canonical bytes, sig verify, binding mismatch, missing/wrong canon-id, unknown version, draft-01→draft-02 rejection); (8) draft-01 no-leak proof (existing vectors pass unchanged + `deny_unknown_fields` rejects draft-02 fields); (9) black-box public-API tests asserting wire codes, not printed diagnostics (S8); (10) downgrade tests.

## Branch H — conformance-vector corpus (§14, §7.4)

- **H.1 — Corpus structure + interop oracle.** `[Codex, judge-passed]`
  - **Separate draft-02 corpus** (`mcps-core/tests/vectors/draft-02/manifest.json`); the draft-01 corpus stays **byte-frozen**. Mixing into one manifest would make "draft-01 unchanged" a human promise; a separate corpus makes the G.1 no-leak property mechanically obvious.
  - **Manifest additions (test-harness fields, not wire):** `envelope_version` (required on every draft-02 fixture); `canonicalization_id` (required when the fixture has a draft-02 envelope); `version_policy { accepted_versions, downgrade }` (required for every migration/downgrade vector — outcome depends on configured policy, never implicit); `oracle { canonical_preimage_b64url, canonical_preimage_sha256, signature_value, request_hash }` (required for every signed fixture whose canonicalization succeeds, including invalid-signature mutations; absent only for malformed-raw vectors that fail before a preimage exists).
  - **Static interop oracle — need BOTH (S8):** the existing regenerate-with-real-crypto set proves *self-consistency*, NOT cross-implementation agreement (the ADR's core goal). Add a **frozen static oracle** — committed canonical UTF-8 preimage bytes + SHA-256 + signature value — so a third-party implementation checks itself against frozen ground truth, not the project's own regenerated opinion. Harness asserts: wire==committed, computed preimage bytes==oracle bytes, digest==oracle hash, signature==oracle sig, result==expected.
  - **int53 honesty vector REQUIRED** (not optional): a float-bearing signed payload (`0.7`/`19.99`) → `mcps.canonicalization_failed`, so the B.1 documented limitation is machine-checked, not just prose (S8).
  - **7 additional required vector classes:** (1) canonical determinism across raw key-reorder / whitespace / escape spelling → byte-identical preimage; (2) raw duplicate protected fields (duplicate `version`/`canonicalization_id`/binding field — must fail *before* serde collapse); (3) signed-wrong-profile (signed under one canon_id/version, presented under another → integrity failure, not policy passthrough); (4) unknown-but-correctly-signed `canonicalization_id` → the unsupported-canonicalization code (proves policy vs signature failures are distinct); (5) response/request profile mismatch under draft-02 policy; (6) authorization-binding **oneof** violation (both binding forms present → reject); (7) historical-trust-material vector — verify against trust material valid at `issued_at`, not current state (S16).

---

## Status: all eight branches resolved (A–H). Awaiting final summary sign-off before any ADR publication.
