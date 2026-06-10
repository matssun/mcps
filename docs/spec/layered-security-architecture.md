<!-- SPDX-License-Identifier: Apache-2.0 -->

# Layered Security Architecture for MCP

**Composition contracts across admission, authorization, runtime evidence, enforcement, and audit.**

| Field | Value |
|---|---|
| Status | **Draft v0.1 — for IG review** |
| Author | Mats Sundvall ([github.com/matssun/mcps](https://github.com/matssun/mcps)) |
| Taxonomy contributor | Maaz Khan (Interlock) |
| Created | 2026-06-07 |
| Intended outcome | GitHub Discussion in [modelcontextprotocol/modelcontextprotocol/discussions](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions) → possible Informational SEP |
| Scope | Architectural decomposition only — does NOT propose a single new feature, message format, or wire change |
| License | Apache-2.0 (this document); the proposals it references retain their own licenses |

---

## Abstract

The Model Context Protocol community has several active security proposals — SMCP / SEAL, ATSA (SEP-2809), ACTA signed receipts (IETF Internet-Draft), MCP-S, the Interceptors WG, and continuous schema-drift monitoring — that overlap in surprising ways without obviously colliding. Each proposal carries the implicit risk of "owning the whole stack" because the security domain has no agreed decomposition.

This document proposes a **five-layer decomposition** of the MCP security space, derived from the Security IG conversation on 2026-06-06: **admission / identity**, **caller governance**, **runtime security evidence**, **interception / enforcement**, and **audit / receipts**. For each layer it defines the architectural question that layer answers, the responsibilities it must carry, and the responsibilities it must NOT carry. It then specifies the **composition contracts** between adjacent layers — the data each layer produces for the next and the assumptions each layer is permitted to make about its neighbors.

The document does NOT propose new features for any layer. It is a map of the territory the community is already exploring, intended to make it possible for individual proposals to scope themselves cleanly, reference one another by stable interface, and compose without each having to own everything.

---

## 1. Motivation

### 1.1 What this document is

MCP's security space is currently being filled by multiple incomplete proposals. Each proposal has chosen a sensible scope, but the scopes overlap in ways that are not visible without careful reading. A reader of the Security IG could be forgiven for thinking that SMCP, ATSA, MCP-S, and ACTA are partly competing — they are not, but the absence of an explicit decomposition makes it hard to see why.

This document is a **map**. It says where each layer's responsibility begins and ends, what its outputs look like at a contract level, and what the layer above and below it is permitted to assume. It is intentionally NOT a specification of any individual layer. The specifications of the layers themselves live in their own proposals.

### 1.2 What this document is not

- It is **not** a SEP. It does not propose a protocol change. If accepted, it would be an Informational SEP at most.
- It is **not** a critique of any proposal. The five-layer decomposition is offered as a way to make proposals *compose*, not a way to rank them.
- It is **not** complete. Several of the composition contracts described here are placeholders; they require the active authors of each layer to confirm the interface they actually publish.
- It is **not** the only valid decomposition. Other taxonomies are possible; this one is offered because it has emerged from community conversation and appears to be load-bearing.

### 1.3 Why now

In the last six weeks the Security IG conversation has moved from "do we need security primitives?" to "how do admission, runtime, and audit compose without each absorbing the others?" That shift makes a layered architecture document load-bearing rather than premature: proposals already in flight need to know where to plug in.

---

## 2. The five layers

Each layer answers exactly one architectural question. Adjacent layers communicate only through the contracts in §3 — they do not reach across.

| # | Layer | Question it answers |
|---|---|---|
| 1 | **Admission / identity** | Who is this server, and was it admitted as a tool provider at this sensitivity? |
| 2 | **Caller governance** | Who is invoking this call, for what purpose, under what approval context? |
| 3 | **Runtime security evidence** | Was this individual call authentic, fresh, properly authorized, and was the response really from the admitted server? |
| 4 | **Interception / enforcement** | Where is the decision applied — what mechanism actually withholds or releases the call? |
| 5 | **Audit / receipts** | What portable, verifiable record proves what happened and why? |

The taxonomy was proposed by Maaz Khan (Interlock) in the Security IG Discord thread of 2026-06-06, with the refinement (moving "evidence" from layer 5 to layer 3) on 2026-06-07. The refinement is consequential: it places per-call cryptographic facts at layer 3 (where they are produced) and reserves layer 5 for the portable receipt format (where they are consumed downstream).

---

## 3. Per-layer specifications

### 3.1 Layer 1 — Admission / identity

**Question answered:** Who is this server, and was it admitted as a tool provider at this sensitivity?

**Responsibilities:**

- Resolve a server's claimed identity to an unforgeable cryptographic identifier (e.g., a public key, a certificate fingerprint, an attested workload identity).
- Verify a clearance assertion (or equivalent admission credential) against a locally pinned trust root, BEFORE any tool call is dispatched.
- Bind the admitted identity to a stable anchor that downstream layers can reference.
- Express the **sensitivity** at which the server was admitted — admission is not boolean; some servers are admitted for low-sensitivity work only.
- Refuse, fail-closed, when admission cannot be established.

**Explicitly NOT responsibilities of this layer:**

- Per-call verification of message contents (layer 3).
- Authorization of individual calls (layer 2).
- Detecting that an already-admitted server has changed its tool surface (layer 3 evidence + layer 5 receipts).
- Producing the per-call receipt (layer 5).

**Known work in this layer:**

- **ATSA (SEP-2809)** by Alfredo Metere — Attested Tool-Server Admission. Signed clearance assertion at a well-known URI, verified against a locally pinned trust root before dispatch. Active in review.
- **SEAL / SMCP** by Jeshua ben Joseph — workload identity attestation (container ID / process ID) before JWT issuance. Also covers parts of layers 2-3.
- **mTLS-based identity** as used by MCP-S — pins identity to the transport-layer certificate; light-weight but does not produce an explicit "admitted" assertion.

**Open questions:**

- Is the admitted-identity anchor a public key, a certificate chain, a workload claim, or all of the above?
- How is admission revoked, and how does revocation propagate to downstream layers?
- Can a server be re-admitted at a different sensitivity without restart?

### 3.2 Layer 2 — Caller governance

**Question answered:** Who is invoking this call, for what purpose, under what approval context?

**Responsibilities:**

- Express the caller's identity (which user, agent, or delegating authority).
- Express the authorization grant that permits this specific call — scope, sensitivity, expiry, scope of tools / paths / resources.
- Make the grant verifiable by the enforcement layer (layer 4) without trusting the caller's claim.
- Support multiple authorization styles (signed assertions, OAuth-style tokens, capability-style scopes) behind a common abstraction.
- Fail closed on malformed, missing, expired, or unverifiable grants.

**Explicitly NOT responsibilities of this layer:**

- The per-call authenticity of the message itself (layer 3).
- The mechanism that withholds the call when authorization fails (layer 4).
- The receipt that records what was authorized (layer 5).

**Known work in this layer:**

- **MCP-S** — `mcps-policy` crate, with the `AuthorizationProfile` abstraction. The Reference Signed Authorization Profile is the v1 concrete profile; the abstraction is intended to admit OAuth-style, capability-style, or policy-language profiles (Cedar, OPA, etc.) without changing the evaluator.
- **SEAL / SMCP** — JWT-based 1-hour security tokens, deny-by-default capability model with path/command/domain allowlists.
- **MCP OAuth flows** (existing in the spec) — partially overlapping where the authorization grant is OAuth-style.

**Open questions:**

- Does the layer carry caller identity AND grant in one envelope, or are these two separately-signed artifacts?
- How does the layer compose with admission (layer 1) — is the grant bound to a specific admitted server, to any server in a class, or independent?
- What is the minimum-viable profile language that profile authors can target?

### 3.3 Layer 3 — Runtime security evidence

**Question answered:** Was this individual call authentic, fresh, properly authorized, and was the response really from the admitted server?

**Responsibilities:**

- Produce per-call cryptographic evidence: the request was signed by the claimed caller, the response was signed by the admitted server, both signatures bind to a canonical preimage that includes the message contents.
- Enforce freshness — reject calls outside a configured staleness window.
- Detect and reject replay — the same call cannot be accepted twice.
- Bind the response to the request — a response signature that doesn't carry the request's content hash MUST be rejected.
- Propagate the verified context — downstream consumers (the inner tool server, the receipt layer) MUST receive a structured record of what was verified, not the caller's unverified claims.

**Explicitly NOT responsibilities of this layer:**

- Decisions about whether the caller is allowed to make this call (layer 2 produces the grant; layer 3 only verifies its signature).
- Decisions about which server is acceptable as a counterparty (layer 1 admits it; layer 3 only verifies the response signature against the admitted identity).
- Producing the portable receipt that an auditor consumes (layer 5).
- Detecting that an admitted server's tool schema has changed post-admission — this is *complementary* runtime evidence (see §3.3.1 below).

#### 3.3.1 Schema / capability drift as a complementary evidence stream

A specialized form of runtime evidence answers a different question: *"Has the tool/capability surface of this admitted server changed since it was admitted?"*

This is **complementary** to per-call signature verification. The signature verifies *that the call really was made by who we think made it*. Drift evidence verifies *that what was approved is still what is being executed*. The two compose:

- MCP-S's per-call evidence answers: "was this call authentic and authorized?"
- A drift evidence stream answers: "is the tool/capability surface still the one that was approved?"

Both feed layer 5. Neither replaces the other.

**Known work in this layer:**

- **MCP-S** — `mcps-core` (pure verification) + `mcps-host` (request signing, bound response verification) + `mcps-transport` (verifying mTLS). Per-call freshness, replay, response binding, verified-context propagation.
- **SEAL / SMCP** — JWT-validated request envelopes, 30-second freshness window, audit logging. No response-binding in v1.0 (deferred to Future Work).
- **Continuous drift monitoring** (Maaz Khan / Interlock) — baseline tool schemas at first-observation, diff subsequent declarations against the baseline, anchor baselines to the admitted identity from layer 1.

**Open questions:**

- What is the canonical preimage shape for signing? (JCS-based, as in MCP-S? Something else?)
- How is the verified-context block carried — in the JSON-RPC `_meta` block, in a transport header, both?
- Should drift evidence be carried in the same wire format as per-call evidence, or as a separate channel?

### 3.4 Layer 4 — Interception / enforcement

**Question answered:** Where is the decision applied — what mechanism actually withholds or releases the call?

**Responsibilities:**

- Provide an architectural seam at which evidence (layer 3) and authorization (layer 2) are evaluated before the call reaches the tool server.
- Apply the verification result deterministically — admit, deny, or require additional confirmation.
- Propagate verified context to the inner tool server without trusting the caller's claims.
- Withhold the call from the inner server when verification fails; the inner server MUST NOT see unauthorized traffic.

**Explicitly NOT responsibilities of this layer:**

- Producing the evidence it evaluates (layer 3).
- Producing the authorization grant it evaluates (layer 2).
- The cryptographic primitives themselves.
- The audit receipt (layer 5).

**Known work in this layer:**

- **MCP-S** — `mcps-proxy` is the interceptor: TLS termination → object signature verification → freshness/replay check → authorization evaluation → verified-context propagation → dispatch to an unmodified inner MCP server.
- **SEAL / SMCP** — `aegis-seal-gateway` plays the same architectural role.
- **Interceptors WG** (kicked off 2026-04-22) — formalizing the interceptor architecture as a first-class MCP concept.

**Open questions:**

- Should the interceptor be a separate process, an in-process middleware, or both?
- How does the interceptor compose with reverse proxies that terminate TLS upstream?
- Where does sandbox/isolation of the inner server fit — at this layer (the interceptor enforces it) or below?

### 3.5 Layer 5 — Audit / receipts

**Question answered:** What portable, verifiable record proves what happened and why?

**Responsibilities:**

- Produce a portable, self-contained record of a tool call decision that a third party can verify offline.
- Bind the record cryptographically to the admitted server, the caller, the authorization grant, and the verified-context evidence from layer 3.
- Be signed in a way that allows issuer-blind verification (the verifier can check validity without contacting the issuer).
- Be portable across trust boundaries — no shared database required.
- Support lifecycle events (subagent start/stop, task lifecycle) for multi-agent workflows where appropriate.

**Explicitly NOT responsibilities of this layer:**

- The wire-level evidence itself (layer 3 produces it; layer 5 consumes and packages it).
- Real-time authorization decisions (layer 2/3/4).
- Admission decisions (layer 1).

**Known work in this layer:**

- **ACTA signed receipts** — `draft-farley-acta-signed-receipts-01` (IETF Internet-Draft) by tommylauren. Portable Ed25519-signed receipt format, issuer-blind verification, lifecycle receipts for multi-agent swarms. Reference implementation at `protect-mcp` (npm).
- **Tamper-evident audit record** (Scott Rhodes, factored out of ATSA SEP-2809 into its own effort).
- **MCP-S verified-context blocks** — structured per-call evidence that an ACTA-style receipt can be built FROM, but not itself a portable receipt.

**Open questions:**

- Does the receipt format need to carry the underlying layer-3 evidence verbatim, or a hash commitment to it?
- How are receipts revoked or invalidated when the admission they reference is revoked?
- Is there a standardized receipt schema, or per-deployment schemas with a common envelope?

---

## 4. Composition contracts

The contracts below define what each layer produces for its neighbours. They are interface descriptions, not wire formats — the wire format of each layer is defined by the proposals in that layer.

### 4.1 Layer 1 → Layer 3 (admitted identity → runtime anchor)

When a server is admitted (layer 1), the runtime layer (3) MUST be able to obtain a stable **admitted-identity anchor** consisting of at least:

- An **unforgeable server identifier** (public key, certificate fingerprint, or attested workload claim).
- The **admission sensitivity** under which the server was admitted.
- A **validity window** — when admission was granted and (if applicable) when it expires.

Layer 3 uses the anchor as the trust root when verifying response signatures. A response signed by a public key that does not match the anchor MUST be rejected, even if the signature is cryptographically valid.

> **TODO (ATSA author):** confirm the publication mechanism by which the admitted-identity anchor is made available to the runtime layer in ATSA. Is it returned by the admission API, fetched on demand, or pinned at configuration time?

### 4.2 Layer 2 → Layer 4 (authorization grant → enforcement input)

The caller-governance layer (2) produces an **authorization grant** consumed by the enforcement layer (4). The grant MUST be:

- **Verifiable independently of the caller** (typically: signed by a delegating authority that the enforcement layer trusts a priori).
- **Bound** to one or more of: the admitted server (from layer 1), the caller's identity, the requested scope, an expiry.
- **Replayable safely** — if a grant is reused beyond its intended call, the enforcement layer's replay protection (in layer 3) catches it.

Layer 4 MUST NOT accept a grant whose signature it cannot verify, even if the grant's claims are otherwise plausible.

### 4.3 Layer 3 → Layer 4 (verified evidence → enforcement)

The runtime evidence layer (3) produces a **verified-context record** that the enforcement layer (4) propagates to the inner tool server. The record MUST be:

- **Constructed by the interceptor**, not by the caller (the caller's claims are inputs to the record, not the record itself).
- **Cryptographically bound** to the per-call signature evidence.
- **Carried over the wire** in a way the inner server can read without itself participating in the verification (e.g., a structured JSON-RPC `_meta` block).
- **Replaced if present** — if the caller pre-populates the verified-context field, the interceptor MUST overwrite it.

### 4.4 Layer 3 → Layer 5 (per-call evidence → receipt source)

The runtime evidence layer (3) produces evidence that the audit layer (5) packages into a portable receipt. The evidence available to layer 5 SHOULD include at minimum:

- The admitted-identity anchor (from §4.1).
- The authorization grant under which the call was permitted (from §4.2).
- The canonical preimage and signatures of the request and response.
- The verified-context record (from §4.3).
- Time / nonce / freshness metadata sufficient to reproduce the verification.

Layer 5 MAY commit to this evidence by hash rather than carrying it verbatim, depending on the receipt format's design goals.

> **TODO (ACTA author):** confirm whether ACTA's signed-receipts format expects evidence verbatim, by hash commitment, or both.

### 4.5 Layer 5 ← drift evidence stream

When a continuous schema-drift monitor (a specialized layer 3 evidence stream) detects that the admitted server's tool surface has changed, it produces a **drift event** that the audit layer (5) MAY package into a drift receipt. The drift event MUST be anchored to the admitted-identity anchor (§4.1) so a downstream verifier can distinguish "the server we admitted changed its tools" from "a different server is impersonating the admitted one."

---

## 5. Mapping of current proposals

Where current proposals fit in the five-layer decomposition. **Strong** = the proposal's primary domain. **Partial** = the proposal covers part of the layer but defers other parts. **—** = the proposal does not address that layer.

| Proposal | Layer 1 (admission) | Layer 2 (governance) | Layer 3 (runtime evidence) | Layer 4 (interception) | Layer 5 (audit/receipts) |
|---|---|---|---|---|---|
| **ATSA (SEP-2809)** | Strong | Partial (clearance includes sensitivity) | — | — | — |
| **MCP-S** | Partial (mTLS identity verification) | Strong (AuthorizationProfile + Reference Signed Profile) | Strong (per-call sign/verify, freshness, replay, response binding, verified-context) | Strong (mcps-proxy) | Partial (primitives, no portable receipt format) |
| **SEAL / SMCP** | Partial (workload attestation) | Strong (deny-by-default capability scopes) | Partial (request sign/verify, no response binding in v1.0) | Strong (aegis-seal-gateway) | Partial (audit log, not portable receipts) |
| **ACTA signed receipts** | — | — | — | — | Strong |
| **Drift monitoring** | — | — | Strong (complementary evidence stream) | — | Partial (drift events feed receipts) |
| **Interceptors WG** | — | — | — | Strong | — |
| **Annotations SEP-1913** | — | — | — | — | Substrate (metadata that receipts may reference) |

Reading the table:

- No proposal currently covers ALL five layers. This is the intended state — single-proposal completeness is an anti-pattern (§6.1).
- Layers 1 and 5 each have a clear specialist (ATSA, ACTA respectively). Layer 4 has an institutional home (Interceptors WG).
- Layers 2, 3, and 4 are currently most-fully realized in MCP-S.
- SEAL / SMCP and MCP-S occupy the same architectural slot at layers 2-4 with different design choices (JWT-based session tokens vs. per-call signing); they are alternative implementations of the same layers rather than complementary ones.

---

## 6. Anti-patterns

### 6.1 Layer collapse

A proposal attempts to cover all five layers in a single mechanism. The result is that no individual layer is well-specified, and the proposal accumulates a constituency of objections from authors of every adjacent layer. SMCP v1.0 was critiqued in this way (Justin Cappos: *"underspecified"*; QueBallSharken: *"collapses onto an unverified trusted gateway"*; Starlight143: *"strict separation between envelope authentication and runtime policy"*).

**Mitigation:** scope each proposal to one to three adjacent layers; explicitly defer the others.

### 6.2 Layer duplication with incompatible interfaces

Two proposals at the same layer choose incompatible representations (e.g., one publishes admitted identity as a JWT, another as a CBOR-encoded attestation). Downstream layers must then implement N adapters.

**Mitigation:** community alignment on canonical wire formats per layer, even when implementations differ.

### 6.3 Implicit dependencies

A proposal at layer 3 silently assumes a layer 1 behavior without contract (e.g., "the admitted server's public key is always available somewhere"). When the layer 1 implementation does not publish that key in the expected way, integration breaks.

**Mitigation:** the composition contracts in §4. Every cross-layer assumption MUST be a named contract.

### 6.4 Smuggled trust

A proposal allows the caller to populate a field that the receiver treats as authoritative. The most-common form is a "verified-context" field that the caller can set themselves, which the inner server then trusts.

**Mitigation:** layer 3's verified-context record (§4.3) is **constructed by the interceptor**, not the caller. If the caller pre-populates the field, the interceptor MUST overwrite it.

---

## 7. Open questions for the IG

1. **Is this the right taxonomy?** The five layers are derived from a single conversation. They appear load-bearing but have not been stress-tested against e.g. multi-region deployments, MCP-over-HTTP, or sandboxed sub-agents.
2. **Should layer 4 (interception/enforcement) be the home for inner-server isolation (sandbox, rlimits)?** MCP-S's `mcps-proxy` implements this today; the Interceptors WG charter may or may not include it.
3. **Are admission and authorization always separable?** Some deployment models (e.g., capability-based ones) blur the two. Should the layered model accommodate that, or assert separability as a normative property?
4. **What is the right home for this document?** A GitHub Discussion (per §1.1's intent) gives community visibility but no version control; an Informational SEP gives durability but is a heavier commitment.
5. **Do existing proposals agree their mapping in §5 is fair?** Especially: ATSA author (Alfredo Metere), ACTA author (tommylauren), SEAL/SMCP author (Jeshua ben Joseph), Interceptors WG leads.

---

## 8. Acknowledgments

The five-layer taxonomy is proposed by Maaz Khan (Interlock) in the Security IG Discord thread of 2026-06-06, with the refinement (moving "evidence" from layer 5 to layer 3) on 2026-06-07. The decomposition was discussed openly in the same thread with composition examples drawn from the ATSA / drift-monitoring conversation between Maaz and Alfredo Metere (Enclawed) of 2026-06-01.

Specific proposals referenced:

- **ATSA (SEP-2809)** — Alfredo Metere (Enclawed). PR: [#2809](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2809). Preprint: [Zenodo 10.5281/zenodo.20349263](https://doi.org/10.5281/zenodo.20349263).
- **ACTA signed receipts** — tommylauren. IETF Internet-Draft: `draft-farley-acta-signed-receipts-01`. Reference impl: `protect-mcp` on npm.
- **SEAL / SMCP** — Jeshua ben Joseph (100monkeys.ai). Discussion: [modelcontextprotocol/discussions/689](https://github.com/orgs/modelcontextprotocol/discussions/689). Repos: [`seal-protocol`](https://github.com/100monkeys-ai/seal-protocol) (SDKs), [`aegis-seal-gateway`](https://github.com/100monkeys-ai/aegis-seal-gateway) (Rust gateway).
- **MCP-S** — Mats Sundvall. Repo: [github.com/matssun/mcps](https://github.com/matssun/mcps).
- **Annotations (SEP-1913)** — referenced as substrate.
- **Continuous drift monitoring** — Maaz Khan (Interlock).
- **Interceptors WG** — kicked off 2026-04-22.

This document is offered under Apache-2.0 by its primary author. Contributions via pull request to the [MCP-S repository](https://github.com/matssun/mcps) are welcome at this stage; if the document advances to a GitHub Discussion or Informational SEP, contribution moves to the relevant MCP project venue.

---

## 9. Status and next steps

| Phase | Status | Venue |
|---|---|---|
| 0. Private draft in MCP-S repo | **In progress** (this file) | `docs/spec/layered-security-architecture.md` |
| 1. Layer-author review | Pending | Direct outreach to ATSA, ACTA, SMCP, drift authors |
| 2. v0.2 with author confirmations | Pending | This file |
| 3. Public draft as GitHub Discussion | Pending | `modelcontextprotocol/modelcontextprotocol/discussions` |
| 4. (If well-received) Informational SEP | Pending | `seps/0000-layered-security-architecture.md` |

### Immediate todos

- [ ] Confirm the ATSA admitted-identity anchor publication mechanism (§4.1). Direct outreach to Alfredo Metere.
- [ ] Confirm the ACTA evidence-input shape (§4.4). Direct outreach to tommylauren.
- [ ] Confirm the SEAL / SMCP author's mapping (§5). Direct outreach to Jeshua ben Joseph.
- [ ] Confirm the drift event format (§4.5). Direct outreach / review by Maaz Khan.
- [ ] Decide whether layer 4 includes inner-server isolation (§7 Q2).
- [ ] Resolve the home-venue question (§7 Q4).

### What this document deliberately does NOT do yet

- It does NOT specify any wire format for any layer.
- It does NOT recommend one proposal over another within a layer.
- It does NOT propose adding any feature to any proposal.
- It does NOT take a position on Standards Track vs Extensions Track for the proposals it maps.

These are deferred to the individual proposals or their successor SEPs.
