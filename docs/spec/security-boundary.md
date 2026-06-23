# MCP-S Security Boundary

**Status: SIGNED OFF by the owner — Mats Sundvall, 2026-05-30 (release gate satisfied for the single-node profile). See Section 7.**

**v0.5 proposal-readiness: SIGNED OFF by the owner — Mats Sundvall, 2026-06-23 (mechanical gate #156 green; no wire-envelope change, draft-01 frozen). See Section 10.**

This document is the project's **honesty gate**. It states exactly what MCP-S
protects and — equally important — what it does **not** protect, so that a
security reviewer cannot over-trust the system. It is a **merge/release gate**:
release of any MCP-S production-claim artifact is blocked until this document
exists and has been signed off by the human owner. It is **type:HITL** — it is
authored by an agent but requires the human owner's explicit approval; the
author does **not** self-approve it.

Tracking issue: MCPS-039.

The authorities for the claim boundary are:

- [ADR-MCPS-017 — Single-Node Production Claim Ceiling and Deferred Enterprise
  Capabilities](../adr/adr-mcps-017.md) — the
  authority for the **allowed claim** vs the **forbidden claims** and the
  deferred-capability list.
- [ADR-MCPS-016 — Inner-Server Isolation Boundary
](../adr/adr-mcps-016.md) — the
  **non-containment** boundary between the proxy and the inner MCP server.
- [ADR-MCPS-018 — CI Reproducibility Posture and Conformance-Manifest Authority
](../adr/adr-mcps-018.md) — the
  reproducibility posture.

Where this document and any older planning brief disagree, this document and the
cited ADRs win.

---

## 1. The allowed claim

MCP-S MAY be described as:

> **"production-hardened for single-node Rust-native deployments."**

That is the entire claim. Anything stated beyond this single-node ceiling is a
**forbidden claim** (Section 2) until the named follow-up lands. The claim is
bounded to a single node for exactly **one** reason: the durable replay
protection MCP-S ships is a **local, file-backed** cache, so replay safety holds
only within a single proxy instance — see
[ADR-MCPS-017](../adr/adr-mcps-017.md). Key
custody (file/env vs HSM/KMS) is a **separate, independent** hardening axis and
is **not** a reason for the single-node ceiling — see "Two independent
boundaries" below.

### Two independent hardening boundaries

MCP-S has two distinct hardening axes. They are **orthogonal**: moving along one
does not require moving along the other, and neither is required for MCP-S's core
object-signature verification.

- **Scale boundary — this is what bounds the claim to a single node.** Replay
  protection uses a local, file-backed `ReplayCache`, so it is safe only within
  one proxy instance. A horizontally-scaled / multi-node deployment requires a
  **shared, atomic `ReplayCache`** across proxy instances
. This — and only this —
  is why the production claim is single-node.
- **Key-custody boundary — independent of scale.** Signing keys are loaded from a
  **file/env `KeySource`**. Claiming non-exporting / hardware-backed /
  enterprise-grade signing keys requires an **HSM / KMS / remote-signer
  `KeySource`**. HSM/KMS is
  **not** required for signature verification, and **not** required to move from
  single-node to horizontally-scaled deployment: once the shared `ReplayCache`
  lands, a multi-node deployment using file/env keys is possible. HSM/KMS is a
  separate, additive key-custody hardening, claimed only when hardware-backed key
  custody itself is the requirement.

---

## 2. Forbidden claims (NOT provided)

The system MUST NOT be described as providing any of the following. Each is a
deferred, named follow-up. Asserting any of these as delivered is a release-gate
violation (Section 6).

| Forbidden claim                                                            | Status                | Follow-up                                                       |
| -------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------- |
| Horizontal-scale replay protection (multi-node) — **scale boundary**       | NOT provided — single-node only (local file ReplayCache) | (shared atomic ReplayCache) |
| Full certificate revocation (online CRL / OCSP)                            | NOT provided          |           |
| Hardware-backed / non-exporting signing keys (HSM / KMS) — **key-custody boundary**, independent of scale | NOT provided (file/env KeySource only) |           |
| Reverse-proxy mTLS / enterprise ingress                                    | NOT provided          |           |
| Kernel / filesystem / network containment of the inner server             | NOT provided — OS sandbox profile |           |
| Signed-tool-manifest protection (tool identity / rug-pull detection)       | NOT provided          |           |
| Offline-hermetic / air-gapped / vendored build reproducibility            | NOT provided (network-reproducible only) | future supply-chain item                            |
| Client-side remote (non-local) transport                                   | NOT provided          | future seam                                                    |
| Committed production rollout / SLA / monitoring ownership                  | NOT provided          | future seam                                                    |

None of these is partially delivered. "Deferred future seam" means the interface
may exist to make the capability addable later — it does **not** mean the
capability is present.

---

## 3. Inner-server non-containment boundary

Authority: [ADR-MCPS-016
](../adr/adr-mcps-016.md).

The proxy (`mcps-proxy`) controls the inner MCP server's **launch hygiene** and
propagates verified context. It does **not** contain a malicious or compromised
inner server.

**What the proxy DOES do (launch hygiene + context propagation):**

- environment minimization (the inner server runs with a minimal, explicit
  environment, not the proxy's full environment);
- explicit working directory;
- stdout/stderr separation;
- process-lifecycle logging;
- best-effort resource limits (`setrlimit`);
- verified-context propagation (the proxy strips any caller-supplied verified
  context and injects its own, so the inner server sees only proxy-asserted
  identity).

**What the proxy does NOT do (the boundary):**

- It does **not** contain the inner server at the kernel, filesystem, or network
  level. There is no seccomp / Landlock / container / eBPF enforcement in this
  release.

**Consequence — stated plainly:** a compromised or malicious inner MCP server can
still access whatever its OS user can access (files, network, processes), within
only the best-effort `setrlimit` bounds, until a separate OS sandbox profile
lands. Launch hygiene
reduces accidental blast radius; it is **not** a containment guarantee against a
hostile inner server.

---

## 4. What IS protected (the positive claim surface)

The following are delivered and may be claimed within the single-node ceiling.
This is the complete positive surface; nothing outside it should be implied.

- **Object-signature verification of every JSON-RPC request and response.** Every
  protected message is verified through the canonical 12-step request pipeline
  (and the response pipeline) defined in
  [mcps-core-spec.md §9](./mcps-core-spec.md). Ed25519-over-JCS signs the
  **complete JSON-RPC object**, not just an envelope
  ([ADR-MCPS-004](../adr/adr-mcps-004.md),
  [ADR-MCPS-003](../adr/adr-mcps-003.md)).
- **Fail-closed message constraints.** Batches, security-relevant
  notifications, and unknown envelope fields are rejected; the pipeline fails
  closed at the first failing step
  ([ADR-MCPS-009](../adr/adr-mcps-009.md)).
- **Freshness + single-node durable replay protection.** A freshness window
  (`issued_at`/`expires_at` ± skew) plus a replay cache keyed by
  `(signer, audience, nonce)`, checked only **after** signature verification so
  invalid-signature traffic cannot burn nonces. Cache failure fails closed,
  distinct from a replay verdict
  ([ADR-MCPS-006](../adr/adr-mcps-006.md)). The
  durable replay cache is **single-node** — multi-node replay protection is
  forbidden (Section 2).
- **Delegated authorization** (Phase 5, reference signed-authorization profile).
  The proxy enforces the authorization profile **deny-before-dispatch** — an
  unauthorized request never reaches the inner server
  ([ADR-MCPS-013](../adr/adr-mcps-013.md)).
- **Rust-native mTLS transport termination + transport binding + v1 revocation
  posture** (Phase 6 / 6.1). `mcps-proxy` terminates TLS itself
  (`RustlsDirectProvider`, rustls + ring), binds the verified transport peer to
  the object signer (transport binding), and enforces a maximum client-cert
  lifetime as its v1 revocation posture. This is **not** online revocation —
  full CRL/OCSP is forbidden (Section 2,
  #3839)
  ([ADR-MCPS-014](../adr/adr-mcps-014.md)).
- **Transport-free, key-custody-safe host layer (HostSession).** The host /
  ambassador signs requests and verifies responses without exposing any key
  accessor; the model never touches a private key
  ([ADR-MCPS-015](../adr/adr-mcps-015.md)).
- **Signing-key loading via a file/env `KeySource`.** Signing keys load from a
  file or (hard-guarded) environment `KeySource`; the proxy and host sign without
  exposing private-key material through public APIs. This is the delivered
  key-custody level — hardware-backed / non-exporting keys (HSM/KMS) are a
  **separate, additive** boundary (Section 1,
  #3838) and are **not** required
  for signature verification or for horizontal scale.

### Three separate checks — none replaces another

These are independent proofs and must not be conflated:

- **mTLS** proves the **transport peer** (who holds the TLS client cert).
- **The object signature** proves the **JSON-RPC signer** (who signed this exact
  request/response object).
- **Delegated authorization** proves **whether the signer may act** (is this
  signer authorized for this method/tool/argument scope).

A valid mTLS peer is not automatically a valid signer; a valid signer is not
automatically authorized. All three checks are required and none substitutes for
another.

---

## 5. Reproducibility honesty

Authority: [ADR-MCPS-018
](../adr/adr-mcps-018.md).

- **CI-enforced on every relevant PR.** The Core conformance and transport tests
  run in CI on every PR that touches MCP-S, building the self-contained module
  (`bazel test //...`).
- **Lockfile-reproducible WITH network access — NOT offline-hermetic.** The build
  is reproducible from the committed lockfiles **provided crates.io network
  access is available**. It is **not** offline-hermetic / air-gapped, and vendored
  build reproducibility is **not** claimed (Section 2).
- **Submodule-free cold clone — achieved.** This repository is a self-contained
  Bazel module (`MODULE.bazel`); it builds from a fresh clone with
  **no submodules** and no parent module graph. A scheduled cold-clone
  (no-submodule, cold-cache) CI job validates this. Tracked work is done:
  (no-submodule reproducibility)
  and (module isolation) are
  both closed.
- **Granian is fully removed from the MCP-S build.** MCP-S is not a Granian
  plugin and does not depend on Granian or any Granian ASGI-TLS fork.

---

## 6. How to use this gate

- **Release is blocked until this document is signed off** by the human owner.
  This document existing is not sufficient; owner approval is required because it
  is type:HITL.
- **Reviewers reject deferred-capability claims.** Code review rejects any PR,
  README, marketing line, doc, commit message, or comment that asserts a
  capability listed in Section 2 as delivered, or that describes MCP-S beyond the
  single-node ceiling in Section 1.
- **The only sanctioned positive claim is Section 1's exact wording** plus the
  surface enumerated in Section 4. If a desired claim is not in Section 4, it is
  forbidden until the corresponding follow-up lands and this document is updated
  and re-signed.
- **When in doubt, under-claim.** This document is the honesty artifact; partial
  compliance is not compliance.

---

## 7. Owner sign-off

| Field          | Value                                            |
| -------------- | ------------------------------------------------ |
| Document       | `docs/spec/security-boundary.md`                 |
| Gate type      | HITL release gate (release blocked until signed) |
| Author         | _(agent — does not self-approve)_                |
| Owner sign-off | **Mats Sundvall — 2026-05-30** (signed)          |

**Scope of approval:** Approval of the MCP-S security boundary and claim ceiling
for the current single-node Rust-native deployment profile. This approval does
**not** cover future enterprise / horizontal-scale claims until the named
follow-up issues (Section 2) are implemented and tested.

The single-node release gate is satisfied as of 2026-05-30.

---

## 8. v0.3 multi-node profile — composed claim (SIGNED OFF — ACTIVE)

> **STATUS: SIGNED OFF — ACTIVE as of 2026-06-15.** This section composes
> ADR-MCPS-020 through ADR-MCPS-023 into the v0.3 multi-node claim. The owner
> signed §8.1 below on 2026-06-15 (epic #7 release gate satisfied), so for a
> deployment that declares all four modes the composed multi-node claim is now
> active alongside the single-node ceiling of Section 1; the horizontal-scale row
> of Section 2 is licensed at the declared tier.

When signed, MCP-S MAY additionally be described — for a deployment that declares
all four modes — as:

> **"production-hardened for multi-node deployments within one trust domain / one
> operator, at the security tier composed from the four declared deployment
> modes."**

The claim is **tiered, not unconditional**, and is read off the
[v0.3 security-claim matrix](./v0.3-claim-matrix.md). It is the conjunction of:

- **Replay durability** (ADR-MCPS-020) — the declared `ReplayDurabilityTier`; the
  proxy surfaces that tier's own guarantee and cannot over-claim. Strict
  production requires `REDIS_WAIT_QUORUM` or stronger.
- **Trust propagation** (ADR-MCPS-021) — revocation enforced fleet-wide within the
  bounded window `T` (default 60s); zero-window revocation is **not** claimed.
- **Key custody** (ADR-MCPS-022) — `per_node_keyset` (default; tight blast radius,
  explicit authorized key set) or `shared_remote_signer` (higher custody, not
  smaller blast radius). A copied shared private key is forbidden.
- **Ingress binding** (ADR-MCPS-023) — `end_to_end_mtls` or
  `trusted_ingress_asserted`; SEP-2243 routing headers are never trusted
  (ADR-MCPS-025).

**Still forbidden in v0.3** (unchanged from Section 2 / the epic's "Not in v0.3"):
multi-tenant isolation between mutually distrusting operators; unconditional
replay safety on async failover; zero-window revocation; end-to-end channel
binding under `trusted_ingress_asserted`; a smaller blast radius for shared-KMS
identity than for per-node keys; copied private keys; a hostile shared-store
threat model; cross-operator replay-store isolation.

The RC-conditional delta ADRs (024 multi round-trip, 025 routing headers, 026
signing-scope partition) are **implemented and tested** but remain conditional on
the MCP 2026-07-28 release candidate; they harden the same deployment shape and
do not themselves widen this claim.

### 8.1 v0.3 owner sign-off

| Field          | Value                                                     |
| -------------- | --------------------------------------------------------- |
| Document       | `docs/spec/security-boundary.md` §8 + `v0.3-claim-matrix.md` |
| Gate type      | HITL release gate (multi-node claim blocked until signed) |
| Author         | _(agent — does not self-approve)_                         |
| Owner sign-off | **Mats Sundvall — 2026-06-15** (signed; execution delegated to the agent in-session) |

**Release-gate checklist (epic #7) — all conditions satisfied:** ADRs 020–023
accepted ✅ (020 and 023 moved Proposed→Accepted 2026-06-15; 021/022 already
Accepted); supported tiers implemented ✅; this composition section signed ✅;
conformance manifest lists the tiers + tests ✅ (`drift_guard_test` green); claim
matrix states allowed/forbidden per tier ✅; **CI green** ✅ — `.github/workflows/ci.yml`
(blocking `cargo build`/`cargo test --workspace` + feature-gated backend job) and
the nightly `live-infra-e2e` lane (Redis primary+replica, SoftHSM2 PKCS#11, OpenSSL
OCSP) are green on `main`. The v0.3 multi-node claim is **active** as of 2026-06-15.

---

## 9. Audit-evidence vocabulary (derived from the frozen error taxonomy)

> **Non-goal:** this is **not** a SIEM schema and does not replace deployment
> audit policy. It fixes only the stable machine tokens MCP-S Core emits as
> evidence for its own verdicts; everything else (storage, correlation, retention,
> human dashboards) is the deploying operator's concern.

MCP-S can emit audit evidence for the verdicts it reaches. To keep that evidence
honest, its **rejection reasons are derived from the frozen
`McpsError::wire_code()` taxonomy** — `mcps-core/src/error.rs` is the **sole
authority** (ADR-MCPS-002/007/009, ADR-MCPS-035). The vocabulary lives in one
place, `mcps-core/src/audit.rs`, keyed off `wire_code()`; there is **no parallel
rejection vocabulary**.

- **Rejection events** use a small fixed `event_type` — `mcps.request.rejected`
  or `mcps.response.rejected` — with `reason` set to the **exact**
  `McpsError::wire_code()` token. Example:
  `{ "event_type": "mcps.request.rejected", "reason": "mcps.invalid_signature" }`.
  No minted sub-names (no `…rejected.bad_signature`, `…expired`, `…replay`,
  `…untrusted_signer`).
- **Success events** are the only net-new surface, because the error enum cannot
  express a success/lifecycle outcome. The set is **exactly two**:
  `mcps.request.accepted` and `mcps.response.signed`. No third success event may
  be minted without an ADR.
- **No `authorization_hash_mismatch`.** Core **binds** `authorization_hash` and
  never **interprets** the authorization artifact (ADR-MCPS-013); "mismatch" would
  imply a semantic comparison Core does not perform, so no such audit reason
  exists. (The `mcps.authorization_hash_mismatch` token is a *policy-layer*
  `PolicyError` produced by the configured AuthorizationProfile — outside Core, and
  not an audit reason.)
- **Optional `reason_label`.** A non-normative, human-readable label (e.g.
  "Invalid signature") may accompany an event for readability. It is display-only
  and **must never be parsed**; the stable machine token is always `reason`.

**Adding a rejection outcome** therefore requires adding an `McpsError` variant
first (the frozen-taxonomy process), which the audit layer inherits
automatically — the vocabulary cannot drift from the verdicts the pipeline
actually makes.

**Enforcement.** A CI drift guard
(`//mcps-conformance:audit_vocabulary_guard_test`, ADR-MCPS-035) reads
`error.rs` and `audit.rs` from disk and FAILS if any audit rejection `reason` is
not a member of `McpsError::wire_code()`, if the success set is not exactly the
two-item allowlist, or if an `authorization_hash_mismatch` notion reappears as an
audit reason.

## 10. v0.5 owner sign-off (proposal-readiness)

> **STATUS: SIGNED OFF — Mats Sundvall, 2026-06-23.** MCP-S 0.5 is
> proposal-readiness over the **frozen draft-01** envelope. This sign-off adds
> **no new claim** to Sections 1–9 and **no wire-envelope field**; it attests that
> the 0.5 proposal-facing material is accurate and that the mechanical
> proposal-readiness gate is green. The dual gate of ADR-MCPS-036 (mechanical +
> HITL) is satisfied: the mechanical half below is CI-enforced, and this section is
> the human half.

| Item | Value |
|---|---|
| Scope | MCP-S 0.5 proposal-readiness over frozen draft-01 (no wire change) |
| Boundary + claim matrix | this doc + [`v0.5-claim-matrix.md`](v0.5-claim-matrix.md) (§A capability + §B deployment-tier) |
| Mechanical gate (#156) | **green on `main`** — traceability spine, method-transparency pair, audit drift guard, forbidden-claim guard all passing |
| Owner sign-off | **Mats Sundvall — 2026-06-23** (signed; execution delegated to the agent in-session) |

**Mechanical evidence (CI-enforced).** Every §A claim maps to a named green test
in `security_traceability_manifest.json`
(`//mcps-conformance:security_traceability_guard_test`); the method-transparency
behavioral-equivalence test + static drift guard (ADR-MCPS-030/034), the
audit-vocabulary drift guard (ADR-MCPS-035), and the forbidden-claim guard over
the proposal-facing docs (ADR-MCPS-036) are all green. Rule: **no
traceability-mapped green test, no proposal claim.**

**ADR status.** ADR-MCPS-031 … 036 moved **Proposed → Accepted** on 2026-06-23
with this sign-off. The 0.5 proposal-readiness release gate is satisfied as of
2026-06-23; any wire-envelope field gap is ejected to a separate `draft-02` ADR
as post-0.5 work.
