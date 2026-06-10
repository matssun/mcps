# MCP-S Core Specification

**Status:** Normative for MCP-S Core (`draft-01`)
**Scope:** The frozen wire vocabulary, signing rule, canonicalization domain, freshness/replay model, trust resolution, message constraints, error taxonomy, and verification pipeline of MCP-S Core.

This document **states the current rule**. It does **not** restate the rationale: every major rule cites the ADR that records *why* it is so. Conformance counts (vectors, Bazel test targets) are **not** hardcoded here — they are owned by the drift-guarded conformance manifest (see [§12](#12-conformance-manifest-counts)). The convention is: the spec states the rule, the ADR records why, the guide explains how to use it, and the tests prove it — each fact has one home.

Where this spec and any older planning brief disagree, **this spec and the cited ADRs win**. The original planning brief (`documents/mcps/MCP-S Project Planning Brief.md`) is BACKGROUND ONLY and contains stale field names (`actor`/`capability_hash`/`server_actor`/`trust_label`) that MUST NOT be copied.

## ADR index

The decisions behind this spec are recorded as ADRs:

| ADR | Title | Source |
| --- | --- | --- |
| ADR-MCPS-001 | Clean-Room Public Protocol — Vocabulary Firewall and Public TrustResolver Trait | [view](../adr/adr-mcps-001.md) |
| ADR-MCPS-002 | Frozen Public Envelope Vocabulary | [view](../adr/adr-mcps-002.md) |
| ADR-MCPS-003 | Signing Locus — What `signer` and a Signature Prove | [view](../adr/adr-mcps-003.md) |
| ADR-MCPS-004 | Ed25519-over-JCS Signing Rule for the Whole JSON-RPC Object | [view](../adr/adr-mcps-004.md) |
| ADR-MCPS-005 | JCS-Safe JSON Value Domain with Fail-Closed Canonicalization | [view](../adr/adr-mcps-005.md) |
| ADR-MCPS-006 | Freshness and Replay Model — Injected ReplayCache, No `sequence` in Core v1 | [view](../adr/adr-mcps-006.md) |
| ADR-MCPS-007 | Trust Resolution, Key Rotation, and Revocation Model | [view](../adr/adr-mcps-007.md) |
| ADR-MCPS-008 | Verified-Context Propagation to Inner MCP Servers | [view](../adr/adr-mcps-008.md) |
| ADR-MCPS-009 | Fail-Closed Message Constraints — Batch, Notification, Unknown-Field Rejection | [view](../adr/adr-mcps-009.md) |
| ADR-MCPS-010 | Incubation Strategy, Extension Identifier, and Preimage-Stability Rule | [view](../adr/adr-mcps-010.md) |
| ADR-MCPS-011 | Workspace Structure, Phased Delivery, and Conformance-as-Specification | [view](../adr/adr-mcps-011.md) |
| ADR-MCPS-012 | Project Placement & Build Integration | [view](../adr/adr-mcps-012.md) |
| ADR-MCPS-013 | Delegated Authorization — AuthorizationProfile Abstraction (Phase 5) | [view](../adr/adr-mcps-013.md) |
| ADR-MCPS-014 | Phase 6 — Rust-Native Transport Hardening | [view](../adr/adr-mcps-014.md) |
| ADR-MCPS-015 | Client Host-Session Architecture | [view](../adr/adr-mcps-015.md) |
| ADR-MCPS-016 | Inner-Server Isolation Boundary | [view](../adr/adr-mcps-016.md) |
| ADR-MCPS-017 | Single-Node Production Claim Ceiling and Deferred Enterprise Capabilities | [view](../adr/adr-mcps-017.md) |
| ADR-MCPS-018 | CI Reproducibility Posture and Conformance-Manifest Authority | [view](../adr/adr-mcps-018.md) |

---

## 1. Identifiers and keys

Cites: [ADR-MCPS-002](../adr/adr-mcps-002.md), [ADR-MCPS-010](../adr/adr-mcps-010.md).

These strings are part of the signed preimage; the rationale for treating them as preimage-stable and explicitly non-official lives in ADR-MCPS-010.

- Extension identifier: `se.syncom/mcps` (controlled, explicitly NON-official).
- Request `_meta` key: `se.syncom/mcps.request`
- Response `_meta` key: `se.syncom/mcps.response`
- Verified-context `_meta` key (sidecar→inner only, never signed): `se.syncom/mcps.verified`
- Envelope `version` field value: `"draft-01"`. Any other → `mcps.unsupported_version`.

These strings live inside the signed `_meta` keys, so changing them changes the preimage. They are defined ONCE as constants in `mcps-core` (`mcps_core::ids`) and referenced everywhere. No string literals are scattered in code.

## 2. Frozen wire vocabulary

Cites: [ADR-MCPS-002](../adr/adr-mcps-002.md) (frozen vocabulary), [ADR-MCPS-003](../adr/adr-mcps-003.md) (what `signer`/`on_behalf_of` prove), [ADR-MCPS-008](../adr/adr-mcps-008.md) (verified-context block).

Request envelope object (value under the request key):

```text
version            : string  = "draft-01"
signer             : string  (identity controlling key_id's private key)
on_behalf_of       : string  (signed assertion; REQUIRED-present in Core; not independently verified)
audience           : string  (intended verifier identity)
authorization_hash : string  "sha256:<b64url-no-pad>" (binding only; Core does NOT interpret artifact)
nonce              : string  (opaque, >=128 bits entropy)
issued_at          : string  (RFC 3339 UTC, e.g. "2026-05-28T20:00:00Z")
expires_at         : string  (RFC 3339 UTC)
signature          : { alg: "Ed25519", key_id: string, value: string(b64url-no-pad) }
```

Response envelope object (value under the response key):

```text
request_hash : string "sha256:<b64url-no-pad>"
server_signer: string
issued_at    : string (RFC 3339 UTC)
signature    : { alg: "Ed25519", key_id: string, value: string(b64url-no-pad) }
```

- `trust_label` is REMOVED from Core. Response envelopes MUST NOT carry it.
- Unknown fields inside either envelope → `mcps.unknown_envelope_field` (fail closed). The reserved future growth point is a single `extensions: {}` object (NOT accepted/validated in v1 beyond being a known key — for v1, treat any field other than the ones listed above as unknown, including `extensions`, UNLESS a later task adds it; v1 = reject everything not listed).

## 3. Signing rule

Cites: [ADR-MCPS-004](../adr/adr-mcps-004.md) (Ed25519-over-JCS over the whole JSON-RPC object), [ADR-MCPS-003](../adr/adr-mcps-003.md) (signing locus).

- Sign the COMPLETE JSON-RPC object, not just the envelope.
- Preimage construction: take the full object with `signature.value` REMOVED but `signature.alg` and `signature.key_id` RETAINED; canonicalize with RFC 8785 / JCS to UTF-8 bytes; sign those bytes DIRECTLY with Ed25519 (NO pre-hash — Ed25519ph is forbidden). Insert the Base64URL-no-pad signature into `signature.value`.
- Verification: remove `signature.value`, canonicalize, resolve key, verify Ed25519 over the bytes.
- Response signing is symmetric (response envelope's `signature`).
- Encoding: Base64URL WITHOUT padding for all signature and hash values.
- Hash identifier format: `sha256:<base64url-no-pad>` (the digest is over the relevant canonical bytes).
- `request_hash` = SHA-256 of the verified REQUEST signing preimage (the JCS canonical bytes after `signature.value` removal) — NOT the hash of the transmitted JSON. Format `sha256:<b64url-no-pad>`.
- Only `alg = "Ed25519"` is supported; any other alg → `mcps.invalid_signature` (treat unknown alg as signature failure in v1; a negotiation profile may relax later).

## 4. JCS-safe value domain — fail closed

Cites: [ADR-MCPS-005](../adr/adr-mcps-005.md).

Before signature verification, the protected message MUST be validated against this domain; any violation → `mcps.canonicalization_failed` (NOT `invalid_signature`):

- Object member names unique within each object — DUPLICATE KEYS REJECTED. (The JSON parser MUST detect duplicates; serde_json's default "last wins" is NOT acceptable — use a parse path that surfaces dups.)
- Valid UTF-8, no unpaired surrogates (including via `\uXXXX` escapes).
- Numbers: integers only, within ±(2^53 − 1) inclusive. No fractional, no exponent, no non-finite (NaN/Inf impossible in JSON but reject any non-integer numeric).
- No Unicode normalization, no parser repair/coercion.
- Big IDs, decimals, nanosecond timestamps, monetary amounts → carry as JSON strings. JSON-RPC `id` SHOULD be a string (an integer `id` is allowed only if within the safe-integer range).

Canonicalization (RFC 8785) emitted from the validated value tree:

- Object members sorted by member name, ordered by UTF-16 code unit. (For BMP/ASCII keys used here this is bytewise; implement the UTF-16 rule for correctness.)
- Integers serialized in shortest decimal form, no leading zeros, no `+`, `-0` → `0`.
- Strings: escape only `"` `\` and control chars U+0000–U+001F (use `\b \t \n \f \r` short forms where applicable, else `\u00XX` lowercase hex); all other code points emitted as literal UTF-8.
- No insignificant whitespace.

Canonicalization is implemented IN-HOUSE in `mcps-core` (no external JCS crate) so the preimage is fully auditable; correctness is pinned by the committed vectors.

## 5. Freshness and replay

Cites: [ADR-MCPS-006](../adr/adr-mcps-006.md).

- Freshness: with a configured symmetric `max_clock_skew`, the valid window is `[issued_at − skew, expires_at + skew]`. Outside it (stale OR future-dated beyond skew) → `mcps.expired_request`.
- Replay: caller-injected trait `ReplayCache::check_and_insert(signer, audience, nonce, expires_at) -> Result<ReplayDecision, ReplayCacheError>`, keyed by `(signer, audience, nonce)`, INVOKED ONLY AFTER signature verification succeeds (so invalid-sig garbage can't burn nonces). Retain entries until `expires_at + max_clock_skew`.
  - `ReplayDecision::Fresh` (inserted) | `ReplayDecision::Replay` → `mcps.replay_detected`.
  - `Err(ReplayCacheError)` → FAIL CLOSED, distinct from a replay verdict → `mcps.replay_cache_unavailable` (parallels `trust_resolver_unavailable`).
- Ship `InMemoryReplayCache` reference impl: deterministic, `BTreeMap`-backed, prunes expired entries.
- `nonce` is an opaque string; Core does not generate it (host does) but requires ≥128 bits (≥ ~22 b64url chars / treat as opaque, length-check is advisory not normative in v1).
- NO `sequence`/ordering field in Core v1.

## 6. Trust resolution

Cites: [ADR-MCPS-007](../adr/adr-mcps-007.md), [ADR-MCPS-001](../adr/adr-mcps-001.md) (public `TrustResolver` trait).

- `TrustResolver::resolve(signer, key_id) -> Result<VerificationKey, TrustResolverError>`, authoritative at verify time. Rotation = multiple `key_id`s per signer. Revocation = remove/disable mapping.
- Error mapping: not-found / revoked / disabled / malformed key → `mcps.actor_binding_failed` (KEPT verbatim per ADR-MCPS-007 — this error name retains "actor" even though the field is `signer`). Operational/transient resolver failure → `mcps.trust_resolver_unavailable`.
- Bounded-TTL caching of resolver results is permitted by callers; Core defines no revocation list / OCSP / transparency log / key-validity interval. Resolver failure NEVER falls back to allow.
- Ship a simple in-memory reference resolver (e.g. map of `"signer#key_id" -> public key`) for tests/vectors.

## 7. Message constraints — fail closed

Cites: [ADR-MCPS-009](../adr/adr-mcps-009.md).

- JSON-RPC batch (top-level array) → `mcps.batch_forbidden`.
- Security-relevant notification (no `id`, but is a security-consequential method) → `mcps.notification_forbidden`. Operations with security consequences MUST be id-bearing requests.
- Unknown envelope field → `mcps.unknown_envelope_field`.

## 8. Frozen error taxonomy

Cites: [ADR-MCPS-002](../adr/adr-mcps-002.md), [ADR-MCPS-007](../adr/adr-mcps-007.md), [ADR-MCPS-009](../adr/adr-mcps-009.md).

```text
mcps.missing_envelope
mcps.unsupported_version
mcps.invalid_signature
mcps.canonicalization_failed
mcps.expired_request
mcps.replay_detected
mcps.invalid_audience
mcps.actor_binding_failed          # kept verbatim (ADR-MCPS-007) despite field rename to `signer`
mcps.transport_binding_failed
mcps.authorization_hash_missing    # RENAMED from the brief's capability_hash_missing (field renamed)
mcps.on_behalf_of_missing          # RENAMED from the brief's missing_principal (principal term rejected)
mcps.on_behalf_of_invalid_format   # RENAMED from the brief's invalid_principal_format
mcps.response_sig_invalid
mcps.response_hash_mismatch
mcps.downgrade_forbidden
mcps.batch_forbidden
mcps.notification_forbidden
mcps.unknown_envelope_field
mcps.trust_resolver_unavailable    # ADR-MCPS-007 addition
mcps.replay_cache_unavailable      # ADR-MCPS-006: cache failure fails closed, distinct from replay
```

JSON-RPC error object shape (when surfaced on the wire):

```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32003,
    "message": "mcps.<name>",
    "data": {
      "mcps_error": "mcps.<name>",
      "policy": "core",
      "retryable": false,
      "details": "..."
    }
  }
}
```

Code `-32003` is used for signature/verification failures; other codes follow a small documented map. `id` is `null` when it cannot be determined.

## 9. Verification pipeline — canonical step order

Cites: [ADR-MCPS-004](../adr/adr-mcps-004.md), [ADR-MCPS-005](../adr/adr-mcps-005.md), [ADR-MCPS-006](../adr/adr-mcps-006.md), [ADR-MCPS-007](../adr/adr-mcps-007.md), [ADR-MCPS-009](../adr/adr-mcps-009.md).

### `verify_request`

Fail closed at the FIRST failing step; return the listed error. Replay insert is LAST (after sig verify).

```text
 1. Reject top-level array (batch)                      -> mcps.batch_forbidden
 2. Reject security-relevant notification (no id)       -> mcps.notification_forbidden
 3. Validate JCS-safe domain incl. dup-key detection    -> mcps.canonicalization_failed
 4. Locate request envelope under the request _meta key -> mcps.missing_envelope (if absent)
 5. Reject unknown fields in the envelope               -> mcps.unknown_envelope_field
 6. version == "draft-01"                               -> mcps.unsupported_version
 7. Required-field presence/format:
       authorization_hash present & "sha256:..."        -> mcps.authorization_hash_missing / *_invalid via canon
       on_behalf_of present                             -> mcps.on_behalf_of_missing
       on_behalf_of well-formed (non-empty string)      -> mcps.on_behalf_of_invalid_format
       signature.alg == "Ed25519"                       -> mcps.invalid_signature (unknown alg)
 8. audience == expected verifier audience              -> mcps.invalid_audience
 9. freshness window check (issued_at/expires_at/skew)  -> mcps.expired_request
10. resolve (signer, key_id) -> key                     -> mcps.actor_binding_failed / mcps.trust_resolver_unavailable
11. canonicalize (signature.value removed) & Ed25519 vf -> mcps.invalid_signature
12. ReplayCache.check_and_insert(signer,aud,nonce,exp)  -> mcps.replay_detected / mcps.replay_cache_unavailable
=> success: produce VerifiedRequest { verified_signer, key_id, on_behalf_of, audience,
            authorization_hash, request_hash, nonce, issued_at, expires_at }
```

Steps 1–2 and 4–7 are cheap structural checks before the expensive crypto; this ordering is normative.

### `verify_response`

Cites: [ADR-MCPS-004](../adr/adr-mcps-004.md) §6.7.

```text
 1. JCS-safe domain validation                          -> mcps.canonicalization_failed
 2. Locate response envelope                            -> mcps.missing_envelope
 3. Reject unknown envelope fields                      -> mcps.unknown_envelope_field
 4. signature.alg == "Ed25519"                          -> mcps.response_sig_invalid
 5. resolve (server_signer, key_id) -> key              -> mcps.actor_binding_failed / *_unavailable
 6. canonicalize (signature.value removed) & verify     -> mcps.response_sig_invalid
 7. response.request_hash == locally verified req hash  -> mcps.response_hash_mismatch
```

Vector `v4b_signed_wrong_hash_response` proves step 7 fires even when the signature (step 6) is valid over a wrong `request_hash`.

## 10. Conformance vectors

Cites: [ADR-MCPS-011](../adr/adr-mcps-011.md) (conformance-as-specification), [ADR-MCPS-018](../adr/adr-mcps-018.md) (conformance-manifest authority).

Vectors are the executable spec and are regenerated against the frozen vocabulary/identifier (the brief's are stale). They are committed JSON fixtures under `mcps-core/tests/vectors/` with a generator (a test-only Rust bin/fn using the core primitives) so they are reproducible. They are also re-run, transport-agnostically, over stdio and Streamable HTTP, so they constitute the Core AND transport conformance corpus.

The **authoritative enumeration of every vector** (Core + Phase 5 authorization) lives in the conformance manifest — see [§12](#12-conformance-manifest-counts). Do not maintain a parallel count here.

Each fixture records: name, the message JSON (or raw bytes for the invalid-UTF-8 case), expected outcome (`verify_ok` or an exact `mcps.*` error token), and for OK request/response the resolver entry + test keypair seed. FIXED test keypairs (documented seed) are used so signatures are reproducible — never random in committed vectors.

The vector families cover, at minimum: valid signed request/response; tampered argument and tampered JSON-RPC id; response bound to a wrong `request_hash` (both garbage-signature and signed-but-wrong-hash); replay; expiry; wrong audience; missing envelope; batch; security notification; unknown envelope field; and the JCS domain violations (duplicate key, unsafe integer in id and in arguments, non-integer/exponent number, unpaired surrogate, invalid UTF-8, large id carried as string). The manifest's enumerated file list is the source of truth for the exact present set.

## 11. Crate boundaries

Cites: [ADR-MCPS-011](../adr/adr-mcps-011.md), [ADR-MCPS-012](../adr/adr-mcps-012.md), [ADR-MCPS-013](../adr/adr-mcps-013.md) (`mcps-policy`), [ADR-MCPS-014](../adr/adr-mcps-014.md) (`mcps-proxy` transport), [ADR-MCPS-015](../adr/adr-mcps-015.md) / [ADR-MCPS-016](../adr/adr-mcps-016.md) (`mcps-host` / inner-server isolation).

- `mcps-core`: pure. deps = serde, serde_json (parse only — NOT for canonical output), ed25519-dalek, sha2, base64 (+ thiserror, hex optional). NO networking, async runtime, filesystem, tokio, reqwest, axum. The `BUILD.bazel` deps list must contain none of those. This is checkable.
- `mcps-conformance`: depends on `mcps-core`; runs vectors + stdio/HTTP harnesses.
- `mcps-proxy`: server sidecar; terminates TLS itself (RustlsDirectProvider) and is the policy-enforcement point (ADR-MCPS-014).
- `mcps-host`: client ambassador / host-session (ADR-MCPS-015).
- `mcps-policy`: delegated-authorization profile (ADR-MCPS-013).
- No MCP-S `BUILD.bazel` references any `//components/...` / `//applications/...` Python target or other in-repo crate.

## 12. Conformance manifest (counts)

Cites: [ADR-MCPS-018](../adr/adr-mcps-018.md).

This spec **does not hardcode** vector or test-target counts. The single source of truth is the drift-guarded manifest:

- Manifest: `mcps-conformance/conformance_manifest.json`
- Drift guard: `//mcps-conformance:drift_guard_test` (MCPS-031)

The guard re-derives every count from reality (on-disk fixtures + BUILD files) and FAILS if a vector on disk is missing from the manifest, a manifest entry points at a non-existent vector, a recorded count is stale, or a `rust_test` target is added/removed without updating the manifest. To learn the current vector and test-target counts, read the manifest's `counts` block — never copy a frozen number into this spec.

## 13. Production claim ceiling

Cites: [ADR-MCPS-017](../adr/adr-mcps-017.md).

MCP-S Core's production claim is bounded to a single node. Enterprise capabilities (e.g. distributed/durable replay cache backends, HSM-backed key sources, multi-node trust distribution) are explicitly deferred future seams, not part of the Core v1 claim. See ADR-MCPS-017 for the exact ceiling and the deferred-capability list.

## 14. Conventions

Cites: [ADR-MCPS-011](../adr/adr-mcps-011.md), [ADR-MCPS-012](../adr/adr-mcps-012.md).

- Rust edition 2021. RustCrypto ecosystem (audited; no custom crypto). Match `rust_components` dep style (`[workspace.dependencies]` + `.workspace = true` in members).
- One logical type per file is NOT required for Rust (that is a Python rule); follow idiomatic Rust module layout.
- No `unwrap()` / `expect()` / `panic!` in non-test library code — return `Result` with the error taxonomy.
- Every behavior gets a test (TDD). `bazel test //...` is the gate.
</content>
</invoke>
