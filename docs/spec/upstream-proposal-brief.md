# MCP-S Upstream Proposal Brief

> **STATUS: PREPARED FOR REVIEW — NOT POSTED UPSTREAM.**
> Publication to the Model Context Protocol community is a separate, explicit
> go/no-go decision by the project owner. This document is **reviewable in-repo
> only**. Nothing here instructs anyone to post it, and its presence in the
> repository is not a decision to publish.

**Audience:** Model Context Protocol (MCP) community reviewers and implementers
evaluating a Zero-Trust security profile for MCP tool calls.

This brief is a public-facing explanation of **MCP-S** — what it is, the problem
it addresses, how it is designed, and — equally important — exactly what it does
and does **not** claim. It is deliberately conservative: every positive claim is
bounded by the project's honesty gate, the
[Security Boundary document](./security-boundary.md), and every design rule cites
the ADR that records *why* it is so. Where this brief and any other document
disagree, the [MCP-S Core Specification](./mcps-core-spec.md) and the cited ADRs
win.

Tracking issue: MCPS-041.

---

## 1. What MCP-S is

MCP-S is a **clean-room, public Zero-Trust security profile** for the Model
Context Protocol. It adds, to ordinary MCP tool calls:

- **object-level signing** — the complete JSON-RPC request/response object is
  cryptographically signed, not merely the transport;
- **verification** — a canonical, fail-closed pipeline that proves who signed a
  message, that it is fresh and not replayed or tampered, and that the response
  is bound to the request that produced it;
- **delegated authorization** — a pluggable check of whether the signer is
  authorized to make the call, enforced before the inner server is ever reached.

It is **transport-agnostic** (the same signed object is valid over stdio or
Streamable HTTP) and is implemented as a **sidecar Policy Enforcement Point
(PEP)** that wraps an ordinary MCP server, so existing servers gain these
properties without being rewritten.

MCP-S is built clean-room with a controlled, explicitly **non-official**
vocabulary; it does not claim adoption by or endorsement from the MCP project.
See [Section 5](#5-incubation-status).

---

## 2. The problem it addresses

Today an MCP server effectively **trusts its transport**. If a request arrives,
the server assumes it is legitimate; there is no in-band cryptographic proof of:

- **WHO** issued a given tool call (which identity actually signed *this* exact
  request object);
- that the call is **FRESH** — not a replay of an earlier captured request, and
  not tampered with in flight (a changed argument or a swapped JSON-RPC `id`);
- **WHETHER** that signer is **authorized** to perform the call at all.

A TLS tunnel proves the *peer*, but not the *signer*, and says nothing about
authorization. MCP-S supplies the missing object-level proofs **independent of
transport**, so the guarantee survives proxies, relays, and transport changes.

These are three **separate** proofs and none substitutes for another:

- **mTLS** proves the **transport peer** (who holds the TLS client cert).
- **The object signature** proves the **JSON-RPC signer** (who signed this exact
  object).
- **Delegated authorization** proves **whether the signer may act**.

A valid mTLS peer is not automatically a valid signer; a valid signer is not
automatically authorized.

---

## 3. Design summary

The design rules below are normative in the
[MCP-S Core Specification](./mcps-core-spec.md); each cites the ADR that records
why. The full ADR index lives in that spec.

### 3.1 Metadata-envelope approach

MCP-S rides inside the MCP `_meta` extension space under controlled keys
([ADR-MCPS-002](../adr/adr-mcps-002.md)):

```text
se.syncom/mcps.request     # signed request envelope
se.syncom/mcps.response    # signed response envelope
se.syncom/mcps.verified    # sidecar -> inner server only, NEVER signed
```

The request envelope carries `signer`, `on_behalf_of`, `audience`,
`authorization_hash`, `nonce`, `issued_at`, `expires_at`, and an Ed25519
`signature`; the response envelope binds back to the request via a
`request_hash`.

### 3.2 Signing rule — Ed25519 over JCS, whole object

The **complete JSON-RPC object** is signed, not just the envelope
([ADR-MCPS-004](../adr/adr-mcps-004.md),
[ADR-MCPS-003](../adr/adr-mcps-003.md)). The
preimage is the full object with `signature.value` removed (but `alg` and
`key_id` retained), canonicalized with **RFC 8785 / JCS** to UTF-8 bytes, and
signed **directly** with Ed25519 (no pre-hash). Canonicalization is implemented
in-house in `mcps-core` so the preimage is fully auditable, and its correctness
is pinned by committed conformance vectors. The `request_hash` that binds a
response is the SHA-256 of the verified request signing preimage — not the hash
of the transmitted bytes.

### 3.3 Fail-closed JCS-safe value domain

Before any signature check, the message is validated against a restricted JSON
value domain
([ADR-MCPS-005](../adr/adr-mcps-005.md)):
duplicate object keys are **rejected** (not "last wins"), only safe-range
integers are allowed (big IDs / decimals / nanosecond timestamps must be carried
as strings), and no Unicode normalization or parser repair is permitted. Any
violation fails closed with a distinct error, never silently coerced.

### 3.4 Freshness and single-node replay protection

A freshness window (`issued_at` / `expires_at` ± a configured clock skew) plus a
replay cache keyed by `(signer, audience, nonce)`
([ADR-MCPS-006](../adr/adr-mcps-006.md)). The
replay check runs **only after** signature verification succeeds, so
invalid-signature traffic cannot burn nonces, and cache failure fails closed,
distinct from a replay verdict. The shipped durable cache is **single-node**
(see [Section 6](#6-honest-scope)).

### 3.5 Twelve-step verification pipeline, fail-closed

`verify_request` runs a normative 12-step pipeline that fails closed at the
**first** failing step, with cheap structural checks (batch / notification /
domain / envelope / version / required fields) ordered before the expensive
crypto, and the replay insert last
([Core Spec §9](./mcps-core-spec.md)). `verify_response` symmetrically verifies
the response signature and that its `request_hash` matches the locally verified
request hash. Batches, security-relevant notifications, and unknown envelope
fields are all rejected
([ADR-MCPS-009](../adr/adr-mcps-009.md)).

### 3.6 Trust resolution

Key resolution is an injected, public `TrustResolver` trait
([ADR-MCPS-007](../adr/adr-mcps-007.md),
[ADR-MCPS-001](../adr/adr-mcps-001.md)). Rotation
is expressed as multiple `key_id`s per signer; revocation as removing/disabling a
mapping. Resolver failure **never** falls back to allow; Core defines no built-in
CRL / OCSP / transparency log.

### 3.7 Profile-based delegated authorization

Core **signs and preserves** an `authorization_hash` binding but does **not**
interpret the authorization artifact — interpretation is delegated to a pluggable
**AuthorizationProfile**
([ADR-MCPS-013](../adr/adr-mcps-013.md)). The
**reference signed-authorization profile is delivered** and is enforced by the
proxy **deny-before-dispatch** — an unauthorized request never reaches the inner
server. A **Biscuit** profile is the locked next external profile; it is **not**
yet delivered.

### 3.8 Rust-native transport hardening

`mcps-proxy` terminates TLS itself (`RustlsDirectProvider`, rustls + ring), binds
the verified transport peer to the object signer (**transport binding**), and
enforces a maximum client-cert lifetime as its v1 revocation posture
([ADR-MCPS-014](../adr/adr-mcps-014.md)). This is
**not** online revocation (see [Section 6](#6-honest-scope)).

### 3.9 Transport-free host signing layer

A host / ambassador layer (`HostSession`) signs requests and verifies responses
**without exposing any key accessor** — the model never touches a private key
([ADR-MCPS-015](../adr/adr-mcps-015.md)).

The "how" references for implementers:

- [Conformance Guide](../conformance-guide.md)
- [Host Integration Guide](../host-integration-guide.md)
- [Sidecar Deployment Guide](../sidecar-deployment-guide.md)
- [Transport Hardening Guide](../transport-hardening-guide.md)

---

## 4. Conformance-as-specification

The **executable conformance vectors are the specification**
([ADR-MCPS-011](../adr/adr-mcps-011.md)). They are
committed JSON fixtures generated against the frozen vocabulary using fixed
(documented-seed) keypairs, so signatures are reproducible, and they are re-run
transport-agnostically over stdio and Streamable HTTP — they are the Core **and**
transport conformance corpus. The vector families cover valid signed
request/response, tampered argument and tampered JSON-RPC `id`, response bound to
a wrong `request_hash`, replay, expiry, wrong audience, missing envelope, batch,
security notification, unknown envelope field, and the JCS domain violations.

The **authoritative enumeration and counts** live in a drift-guarded manifest,
not in prose
([ADR-MCPS-018](../adr/adr-mcps-018.md)):

- Manifest: `mcps-conformance/conformance_manifest.json`
- Drift guard: `//mcps-conformance:drift_guard_test`

The guard re-derives every count from the on-disk fixtures and BUILD files and
fails if they drift. This brief therefore **does not hardcode** vector or
test-target counts; read the manifest for the current numbers. See the
[Conformance Guide](../conformance-guide.md) for how to
run it from a fresh clone.

---

## 5. Incubation status

The extension identifier `se.syncom/mcps` is an **INCUBATION
identifier**, not a claim of official MCP adoption or endorsement
([ADR-MCPS-010](../adr/adr-mcps-010.md)). It is a
controlled, explicitly **non-official** namespace chosen so MCP-S can be developed
and reviewed without squatting on an official identifier.

Because these strings live inside the **signed** `_meta` keys, they are part of
the signed preimage: a **preimage-stability rule** applies — changing the
identifier changes every signature and breaks every committed vector, so the
identifier is treated as stable for the lifetime of the `draft-01` envelope
version. If the community were to adopt an official identifier, that would be a
deliberate, versioned migration (a new envelope `version`), not a silent rename.

---

## 6. Honest scope — what is and is not claimed

The single sanctioned positive claim, per the
[Security Boundary document](./security-boundary.md) and
[ADR-MCPS-017](../adr/adr-mcps-017.md), is:

> **"production-hardened for single-node Rust-native deployments."**

That is the **entire** claim. The delivered positive surface (object-signature
verification of every request/response, fail-closed message constraints,
freshness + single-node durable replay, delegated authorization via the
reference signed profile, Rust-native mTLS termination + transport binding + the
v1 max-cert-lifetime revocation posture, and the transport-free key-custody-safe
host layer) is enumerated in
[Security Boundary §4](./security-boundary.md#4-what-is-protected-the-positive-claim-surface).
Nothing outside that surface should be inferred.

### Inner-server non-containment

The proxy controls the inner server's **launch hygiene** (environment
minimization, explicit working directory, stdout/stderr separation,
lifecycle logging, best-effort `setrlimit`, verified-context propagation) but
does **not contain** a malicious or compromised inner server at the kernel,
filesystem, or network level
([ADR-MCPS-016](../adr/adr-mcps-016.md)). Launch
hygiene reduces accidental blast radius; it is not a containment guarantee.

### Named deferred follow-ups (NOT delivered)

The following are explicitly **deferred, named follow-ups**. None is partially
delivered; a "deferred future seam" means an interface may exist to make the
capability addable later, **not** that the capability is present:

| Deferred capability                                                  | Follow-up                                                |
| -------------------------------------------------------------------- | -------------------------------------------------------- |
| Horizontal-scale (multi-node) replay protection                      |     |
| Enterprise HSM / KMS key custody                                     |     |
| Full certificate revocation (online CRL / OCSP)                      |     |
| Reverse-proxy mTLS / enterprise ingress                              |     |
| OS sandbox profile (kernel/filesystem/network containment)           |     |
| Signed-tool-manifest protection (tool identity / rug-pull detection) |     |
| Client-side remote (non-local) transport                             | future seam                                              |
| Offline-hermetic / air-gapped / vendored build reproducibility       |     |

The build is **lockfile-reproducible with crates.io network access**, CI-enforced
on every relevant PR — it is **not** offline-hermetic, and a fully submodule-free
cold clone is not yet achieved (#3852,
blocked on #3841). MCP-S is **not**
a Granian plugin and does not depend on Granian.

---

## 7. Invitation for review

Review of this design is welcome **in-repo**. The feedback most valuable to the
project, roughly in priority order:

1. **Envelope key naming** — the `se.syncom/mcps.{request,response,verified}`
   `_meta` keys and the preimage-stability consequence of changing them
   ([Section 5](#5-incubation-status)). Is the incubation-namespace approach the
   right way to avoid squatting on an official identifier, and is the migration
   story (new envelope `version`) acceptable?
2. **The authorization-profile seam** — Core signs/preserves `authorization_hash`
   but never interprets it; is the AuthorizationProfile abstraction
   ([ADR-MCPS-013](../adr/adr-mcps-013.md)) the
   right boundary, and is Biscuit the right next external profile?
3. **The preimage-stability rule** — signing the **whole** JSON-RPC object over
   in-house JCS canonicalization
   ([ADR-MCPS-004](../adr/adr-mcps-004.md),
   [ADR-MCPS-005](../adr/adr-mcps-005.md)): are
   the fail-closed value-domain restrictions (duplicate-key rejection,
   safe-integer-only, strings-for-big-values) acceptable for real MCP payloads?
4. **The three-separate-checks model** — mTLS peer vs object signer vs
   authorization ([Section 2](#2-the-problem-it-addresses)) — is the separation
   clear and correct?

Reviewers are asked to evaluate the design **against the honest scope in
[Section 6](#6-honest-scope)**: please do not assume any deferred capability is
present, and please flag any wording anywhere that over-claims beyond the
single-node ceiling.

---

> **Reminder:** This brief is **prepared for review, not posted upstream.**
> Whether, when, and how to share it with the MCP community is a separate,
> explicit go/no-go decision reserved to the project owner.
