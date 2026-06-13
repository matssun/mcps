<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-022: Signing Key Custody at Scale — Per-Node Keys, Explicit Anchor, Optional KMS

## Status

Accepted (targets v0.3). Tier 1 (`per_node_keyset`, default) and the
`shared_remote_signer` admission gate are implemented in `mcps-proxy`
(`authorized_keyset` module: `AuthorizedKeySet` + `KeySetTrustResolver`),
composing with ADR-MCPS-021's `BoundedTrustCache`. Tier 2/3 hardware/KMS custody
remains the `DelegatedResponseSigner` seam, landing fully under ADR-MCPS-019.

## Context

The proxy signs responses through a non-exporting seam that already exists:

- `ResponseSigner` — the minimal *"sign these canonical bytes, return the
  public key"* operation.
- `KeySource: ResponseSigner` — adds the TLS server key + client-CA anchors.
- `DelegatedResponseSigner` — holds **only** a signing callback and the paired
  public key, with no accessor to recover key material; its doc names it as the
  seam for "the concrete PKCS#11 / cloud-KMS `ResponseSigner` adapter."

ADR-MCPS-017 deferred enterprise key custody (HSM/KMS). In a multi-node fleet,
every node must produce response signatures. The naive "one shared identity"
approach tempts copying one private key onto N hosts — which is the wrong thing
to do. This ADR decides the custody and identity model for the fleet. It
primarily governs **server/proxy response signing at scale** and how clients
validate that response signer.

## Definitions

- **Response-signing identity mode** — how a single `audience` presents its
  response-signing identity across the fleet. One of `per_node_keyset` or
  `shared_remote_signer`.
- **Authorized key-set / admission document** — the explicit, governed record
  binding each node key to the server identity it may represent (minimum fields
  in the Decision).

## Decision

Define key custody as a **tiered `KeySource`** decision. **Per-node keys are the
v0.3 default**; a KMS/HSM shared identity is an optional higher-custody tier;
copying a private key across nodes is forbidden.

| Tier | Custody | Server identity / anchor | KMS? |
|---|---|---|---|
| **1 — per-node software keys** *(default)* | Each node holds its own Ed25519 keypair | Explicit authorized **key set** governed by ADR-MCPS-021 | no |
| **2 — per-node hardware-bound keys** *(recommended where available)* | Per-node key in TPM / PKCS#11 / OS keystore / HSM slot, non-exporting | Explicit authorized key set (ADR-MCPS-021) | no |
| **3 — shared identity via remote signer** *(optional)* | All nodes sign through one **non-exporting** KMS/HSM/remote signer | Single stable server key clients can pin | yes |

**Tier 3 is a higher *key-custody* tier, not a strictly stronger *blast-radius*
tier.** It improves non-exportability, centralized policy, and auditability, but
compromise of a node's KMS credential may allow signing as the whole server
identity until that credential is revoked. Per-node software keys may be weaker
custody but tighter blast radius.

### Response-signing identity mode (one per audience)

For v0.3, a deployment MUST declare **one** response-signing identity mode per
`audience`:

- `per_node_keyset`
- `shared_remote_signer`

A deployment MUST NOT silently mix both modes for the same audience, except
during an explicitly configured **migration window** with documented start/end
conditions (see Migration). Mixed steady-state operation is deferred to a future
migration profile.

### Normative rules

- A shared single identity across nodes **MUST NOT** be implemented by copying
  one private key onto multiple hosts. If a deployment wants one signing
  identity, it **MUST** use a non-exporting KMS/HSM/remote-signer `KeySource`
  (the `DelegatedResponseSigner` seam).
- For per-node keys, the client/verifier **MUST** trust an **explicit authorized
  server key set / admission document** governed by ADR-MCPS-021 — never a loose
  flat list of discovered keys.
- Node key lifecycle follows ADR-MCPS-021's propagation window `T`: publish node
  key → wait ≥ `T` → node begins signing → revoke on decommission/compromise →
  revocation enforced within `T`.
- **Algorithm boundary:** all `KeySource` tiers MUST produce signatures using
  algorithms allowed by MCP-S Core for the relevant profile. For v0.3 this means
  **Ed25519**, unless and until a future ADR adds algorithm agility. A KMS
  integration MUST NOT quietly introduce a different algorithm and call it
  MCP-S-compatible.

### Authorized key-set / admission document — minimum semantics

The document MUST bind each node key to the server `audience` it is authorized to
represent, and MUST include, per entry:

- `key_id` and the public verification key
- issuer / trust-root authority
- audience / server identity the key may represent
- node identity or label
- `valid_from` (and `valid_until` if applicable)
- `status`: `active` / `revoked` / `disabled`
- `generation` / version (for ADR-MCPS-021 propagation + revocation)
- a signature over the document, when distributed as a manifest

This keeps the format implementation-independent while preventing "just a JSON
array of public keys" from becoming the anchor. The exact wire format may later
be specified by an ATSA / signed-manifest ADR (layer-1 composition).

### Verification responsibility

A client verifying an MCP-S response MUST accept only response signatures whose
`(server_signer, key_id)` resolves to an **active** key in the authorized server
key set for the configured `audience`. The proxy continues to verify request
signatures per Core; this ADR governs the *response*-signing identity at scale.

### Non-exportability vs. the seam

The `DelegatedResponseSigner` seam prevents MCP-S code from *requiring* key
export, but it does **not** by itself prove the backing key is non-exporting.
Tier 1 software keys are exportable by definition if stored in a file. Tier 3
non-exportability is a property of the KMS/HSM/remote-signer backend and MUST be
documented by that adapter — the seam alone is not the proof.

### Credential compromise vs. key compromise (Tier 3)

For Tier 3, compromise of a node *credential* MUST be handled by revoking that
node's KMS/HSM access credential or policy grant — not necessarily by rotating
the shared signing key. If the shared signing **key itself** is suspected
compromised, the server identity key MUST be rotated as a fleet-wide incident.

### Migration — single key → per-node key set

1. Publish the key-set trust root / admission document.
2. Wait ≥ `T` for propagation.
3. Add node keys as `active`.
4. Wait ≥ `T`.
5. Begin per-node signing.
6. Retain the prior single key as `active` until all in-flight responses and
   cached trust state expire.
7. Revoke the prior key.

## Threat Model

- **Trust boundary:** one operator; all node keys inside the TCB.
- **Per-node keys (Tier 1/2):** compromise of one node compromises *only* that
  node's key → revoke that key via ADR-MCPS-021, fleet unaffected. Tight blast
  radius. No shared secret to rotate everywhere.
- **Shared KMS identity (Tier 3):** higher assurance for key custody, **not
  necessarily smaller blast radius**. A compromised node KMS credential may allow
  signing as the shared server identity until that credential or policy grant is
  revoked (the raw key stays in the KMS). Mitigated by KMS access policy,
  per-node credentials, and KMS audit logs.
- **Forbidden posture:** copied private key — a single node compromise leaks the
  whole fleet's signing identity with no isolation. Rejected normatively.

## Conformance Vectors (ADR-MCPS-011)

- **Per-node acceptance:** in `per_node_keyset`, node A key accepted, node B key
  accepted, an unknown key rejected.
- **No `key_id` collision:** two different nodes must not present the same
  `key_id` unless they are explicitly the same key entry.
- **Shared-identity acceptance:** in `shared_remote_signer`, only the configured
  shared `key_id` is accepted.
- **Mixed-mode disabled:** a per-node key is rejected when the audience is
  configured `shared_remote_signer`-only (outside a migration window).
- **Key-set version change:** a revoked key is rejected after ADR-MCPS-021
  propagation.
- **Anchor governance:** adding a node key takes ≥ `T` to be accepted fleet-wide;
  revoking one is enforced within `T` (delegates to ADR-MCPS-021 vectors).
- **Algorithm boundary:** a signature in an algorithm Core does not allow is
  rejected, regardless of tier.
- **Non-flat trust:** a well-formed key not present as `active` in the authorized
  set is rejected.
- **Documentation check:** no test or example shows copying one private key into
  multiple node configs.

## Rationale

The same principle as ADR-MCPS-020: the architecture defines the contract, not
one operational backend. Per-node keys avoid a mandatory KMS dependency, give a
tighter blast radius, and reuse ADR-MCPS-021 for anchor management — the node-key
set *is* trust state. KMS shared identity is genuinely useful (single pinned
identity, centralized signing policy, compliance audit) so it is supported, but
not required for the v0.3 multi-node claim. One identity mode per audience keeps
client trust rules and audit interpretation unambiguous.

## Alternatives Considered

- **KMS single-identity required** — rejected as a v0.3 blocker: a large
  sub-project (access policy, availability, per-sign latency) that should not
  gate the multi-node baseline.
- **Per-node keys as a flat discovered list** — rejected: that is "trust any key
  that shows up"; the anchor must be an explicit governed set with the minimum
  fields above.
- **Mixed identity modes per audience** — rejected for v0.3: complicates client
  trust rules and audit; allowed only inside an explicit migration window.
- **Copied shared private key** — rejected normatively (no blast-radius
  isolation).

## Consequences

### Positive
- No mandatory KMS; tight per-node blast radius; anchor management reuses 021;
  one unambiguous identity mode per audience.

### Negative
- Clients must pin a key-set/trust-root rather than a single key (an
  admission-model change touching the layer-1 contract); migration needs care.

### Neutral
- Tier 3 remains available for operators who need a single pinned identity.

## Compliance and Enforcement

`security-boundary.md`: *"v0.3 supports multi-node deployments with per-node
signing keys inside one trust domain; the server identity is an explicit
authorized key set managed through ADR-MCPS-021 trust propagation. KMS/HSM-backed
shared identity is supported as a higher key-custody tier (not necessarily
smaller blast radius), not required. Deployments MUST NOT copy a single shared
private key across nodes to simulate one server identity, and MUST declare one
response-signing identity mode per audience."*

Normative: the authorized key-set/admission document MUST bind node keys to the
server `audience` they may represent; a key that is well-formed but not present
as `active` in the authorized set MUST be rejected; all tiers MUST sign with a
Core-allowed algorithm (Ed25519 for v0.3).

## Related

- ADR-MCPS-003 (Signing Locus)
- ADR-MCPS-021 (governs the authorized key-set anchor and its propagation)
- ADR-MCPS-019 (Phase 7 external backends — the PKCS#11/KMS adapter lands here)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- The exact wire format of the authorized key-set / admission document — a signed
  manifest, an ATSA admission credential (layer-1 composition), or both. v0.3
  fixes the minimum semantics; the wire format may be a later ADR.
- Whether the migration window needs a dedicated strict-mode guard so it cannot
  remain open indefinitely.
