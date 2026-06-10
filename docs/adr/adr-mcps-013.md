<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-013: Delegated Authorization — AuthorizationProfile Abstraction and the Reference Signed Authorization Profile (Phase 5)

## Status

Proposed

## Context

MCP-S Core (ADR-MCPS-001..012) signs the complete MCP JSON-RPC object and carries an **opaque** `authorization_hash` (`sha256:<b64url-no-pad>`) inside the signed request envelope. Core deliberately does **not** interpret the artifact behind that hash — per ADR-MCPS-002 it is "a signed opaque structural binding" only. Phase 5's job, from the planning brief (§14) and PRD-3763, is exactly this open piece:

- bind `authorization_hash` to a **verified authorization artifact**, and
- let a server-side policy **deny** a request based on that artifact's scope.

The brief named Biscuit, UCAN, and OAuth-bound/DPoP as *candidate* delegation profiles. They are **not equivalent**: Biscuit is an offline, attenuable, Datalog-checked bearer token verified locally from a root key; UCAN is a DID-centric, user-originated capability chain; OAuth-bound/DPoP sender-constrains tokens issued by an authorization server, typically with online introspection. Committing to one as the *first* concrete dependency would let that ecosystem's data model define the MCP-S abstraction, and would pull a heavy external dependency through the isolated `crates_mcps` hub before the interface and its conformance vectors are stable.

A design review (recorded in `documents/mcps/MCP-S followup.md`) reached a clear conclusion: build a stable profile **abstraction** plus one **native reference profile** to prove the interface and produce deterministic conformance vectors; add Biscuit as the first serious external profile *after* the abstraction is green; keep OAuth-bound and UCAN as later profiles. Crucially: the **Core vocabulary is frozen and is not reopened** by Phase 5. The only legitimate Phase 5 design choices are (a) what the authorization artifact *is* and (b) how policy evaluates it.

## Decision

Phase 5 introduces an `AuthorizationProfile` abstraction in the existing `mcps-policy` crate, plus exactly **one** native, in-house profile — the **Reference Signed Authorization Profile**, profile identifier `se.syncom/mcps-authz-reference-v1`. No Biscuit/UCAN/OAuth dependency is taken in this phase.

The authorization artifact is carried in a **new sibling `_meta` block** alongside the existing Core envelopes:

```
se.syncom/mcps.authorization = { "profile": "<profile-id>", "artifact": "<base64url-no-pad bytes>" }
```

This block is **not part of the Core signed preimage**. It is bound to the request cryptographically and transitively: Core already signs `authorization_hash`, and Phase 5 defines

```
authorization_hash == sha256:<b64url(  SHA-256( decoded artifact bytes )  )>
```

so tampering with the artifact breaks the Core signature binding. The verifier recomputes the hash over the decoded `artifact` bytes and compares it to the verified `authorization_hash` *before* interpreting the artifact. Core stays byte-for-byte unchanged; `mcps-policy` depends only on `mcps-core` + `serde`/`serde_json`, preserving the ADR-MCPS-011/012 firewall (no networking, no async, no third-party token crate).

### `AuthorizationProfile` trait (abstraction)

```text
trait AuthorizationProfile:
    profile_id() -> &str
    parse_artifact(bytes) -> Result<Artifact, PolicyError>
    expected_authorization_hash(artifact) -> String        # sha256 of canonical artifact bytes
    validate_signature_or_chain(artifact, &dyn TrustResolver) -> Result<(), PolicyError>
    evaluate(artifact, &VerifiedRequest, &dyn RevocationSource, now_unix) -> AuthorizationDecision
```

`evaluate` performs, in order: signer binding (`grantee == verified.verified_signer`), subject binding (`subject == verified.on_behalf_of`), audience binding (`audience == verified.audience`), expiry (`[not_before, expires_at]`), revocation (`RevocationSource`), and scope (method / tool-or-resource / argument constraints). The result is:

```text
AuthorizationDecision = Allow | Deny(PolicyError)
```

### Reference Signed Authorization Profile artifact

A single JSON object, canonicalized with the same RFC 8785/JCS rules and signed with the same Ed25519 rule as Core (signature over the canonical bytes with `signature.value` removed; issuer key resolved via `mcps_core::TrustResolver`):

```text
profile        : "se.syncom/mcps-authz-reference-v1"
issuer         : string   (authority that granted the capability)
grantee        : string   (the agent identity == request signer)
subject        : string   (the party acted for == request on_behalf_of)
audience       : string   (the server == request audience)
grants         : [ { method, tool, arguments? } ]   (allowed operations / scope)
not_before     : RFC3339 UTC
expires_at     : RFC3339 UTC
revocation_id  : string
signature      : { alg: "Ed25519", key_id, value }
```

The profile proves every property the brief requires: the hash binds the artifact bytes; the artifact binds signer, on_behalf_of, and audience; the artifact constrains method/tool/arguments; it has an independent validity window; and it is revocable. It is **a reference, not the final standard** — its name says so.

### Phase 5 error taxonomy (lives in `mcps-policy`, NOT in the frozen Core enum)

```text
mcps.authorization_block_missing       # request verified but no .authorization sibling block
mcps.authorization_hash_mismatch       # sha256(artifact) != signed authorization_hash
mcps.authorization_profile_unsupported # profile id unknown to this verifier
mcps.authorization_malformed           # artifact bytes do not parse to the profile shape
mcps.authorization_signature_invalid   # issuer signature over the artifact failed
mcps.authorization_signer_mismatch     # grantee != verified signer
mcps.authorization_subject_mismatch    # subject != on_behalf_of
mcps.authorization_audience_mismatch   # audience != verified audience
mcps.authorization_expired             # now outside [not_before, expires_at]
mcps.authorization_revoked             # revocation_id present in the deny source
mcps.authorization_scope_denied        # requested method/tool/arguments not granted
```

These supersede the brief's stale `mcps.capability_*` names for the *same* reason Core renamed `capability_hash` → `authorization_hash`: the term "capability" was dropped from the MCP-S vocabulary. They are a **separate** taxonomy in `mcps-policy`; the frozen `mcps-core` `McpsError` enum is not extended.

### Profile build order

1. **Now (Phase 5):** abstraction + Reference Signed Authorization Profile + conformance vectors + optional `mcps-proxy` enforcement.
2. **Next:** Biscuit profile (best match for offline, attenuable, sidecar-local policy).
3. **Later:** OAuth-bound/DPoP profile (enterprise IdP integration); UCAN profile (DID / local-first delegation).

All concrete profiles plug in behind the same trait and the same `.authorization` negotiation block; the recommended default once proven is Biscuit.

## Rationale

This is option 1 of the design review, with the artifact placement and binding rule made concrete. It proves the MCP-S delegated-authorization semantics end-to-end with deterministic, committed vectors and **zero** new external dependency, so the abstraction — not a token vendor's model — defines MCP-S. It follows the codebase's interface-first culture (abstraction + one reference implementation), keeps Core frozen and pure, and leaves a clean seam for Biscuit/UCAN/OAuth as pluggable profiles.

## Alternatives Considered

- **Biscuit first.** Closest single match to the problem, but adopting it before the trait/vectors are stable risks letting Biscuit's Datalog model shape the abstraction, and adds a heavy dependency through `crates_mcps` prematurely. Deferred to "next".
- **UCAN first.** Attractive for decentralized/DID workflows, but less Rust-native attenuation and more ecosystem-specific than a first proof needs. Deferred to "later".
- **OAuth-bound/DPoP first.** Best for shops with a mature authorization server, but introduces a runtime network dependency and AS availability/latency concerns — the opposite of a clean local-first first proof. Deferred to "later".
- **Put the artifact inside the signed Core envelope.** Rejected: would change the Core preimage and reopen frozen vocabulary; the hash-binding sibling block achieves tamper-evidence without touching Core.
- **Do nothing (leave `authorization_hash` opaque forever).** Fails the brief's Phase 5 exit criteria (no server-side scope denial).

## Consequences

### Positive
- MCP-S gains real, testable delegated authorization with no external token dependency and no change to Core.
- The abstraction is frozen and vector-pinned before any ecosystem profile lands, preventing lock-in.
- `mcps-proxy` can deny on scope (brief exit criterion) while remaining a pure verify-before-dispatch sidecar.

### Negative
- A second, in-house artifact format exists that is explicitly *not* the long-term recommendation, creating a (clearly-labelled) interim profile to maintain until Biscuit lands.
- A new `.authorization` `_meta` block is added to the wire shape (additive, profile-namespaced).

### Neutral
- Revocation is modelled as an injected `RevocationSource` trait (mirroring Core's `ReplayCache`/`TrustResolver` injection); Core defines no revocation transport, and neither does this profile.
- Profile negotiation is a single identifier string; richer negotiation is left to later profiles.

## Compliance and Enforcement

- Deterministic conformance vectors (allow + every deny code) committed under the MCP-S vectors tree, generated from the core primitives with fixed seeds — the executable spec, mirroring Phase 1–4 discipline.
- `mcps-policy`'s `BUILD.bazel` deps list must contain only `//components/mcps/mcps-core` + `@crates_mcps//:serde`/`serde_json` — no networking/async/token crate. Checkable.
- `mcps-core`'s frozen `McpsError` enum and envelope vocabulary are unchanged; a test asserts the Core taxonomy is untouched.
- `mcps-proxy` policy enforcement is opt-in; when enabled, a `Deny` fails closed with the matching `mcps.authorization_*` JSON-RPC error and never reaches the inner server.

## Related

- PRD: MCP-S (Discussion #3763)
- Prior ADRs: ADR-MCPS-002 (envelope vocabulary, `authorization_hash` as opaque binding), ADR-MCPS-007 (TrustResolver — reused for issuer keys), ADR-MCPS-010 (extension identifier / preimage stability), ADR-MCPS-011/012 (workspace firewall).
- Brief: `documents/mcps/# MCP-S Project Planning Brief.md` §14 (Phase 5).
- Design review: `documents/mcps/MCP-S followup.md`.
- Code: `components/mcps/mcps-policy/`, consuming `components/mcps/mcps-core/`.
