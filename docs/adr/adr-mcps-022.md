<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-022: Signing Key Custody at Scale — Per-Node Keys, Explicit Anchor, Optional KMS

## Status

Proposed (v0.3 sketch — under review)

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
to do. This ADR decides the custody and identity model for the fleet.

## Decision

Define key custody as a **tiered `KeySource`** decision. **Per-node keys are the
v0.3 default**; a KMS/HSM shared identity is an optional higher-assurance tier;
copying a private key across nodes is forbidden.

| Tier | Custody | Server identity / anchor | KMS? |
|---|---|---|---|
| **1 — per-node software keys** *(default)* | Each node holds its own Ed25519 keypair | Explicit authorized **key set** governed by ADR-MCPS-021 | no |
| **2 — per-node hardware-bound keys** *(recommended where available)* | Per-node key in TPM / PKCS#11 / OS keystore / HSM slot, non-exporting | Explicit authorized key set (ADR-MCPS-021) | no |
| **3 — shared identity via remote signer** *(optional)* | All nodes sign through one **non-exporting** KMS/HSM/remote signer | Single stable server key clients can pin | yes |

**Normative rules:**

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

**Client-facing consequence:** per-node keys change the admitted-identity anchor
(the layer-1 contract, ATSA's territory in the layered-architecture doc) from
"pin one key" to "pin a trust root authorizing the current authorized key set."
That is part of the MCP-S trust model, not an operational detail.

## Threat Model

- **Trust boundary:** one operator; all node keys inside the TCB.
- **Per-node keys (Tier 1/2):** compromise of one node compromises *only* that
  node's key → revoke that key via ADR-MCPS-021, fleet unaffected. Tight blast
  radius. No shared secret to rotate everywhere.
- **Shared KMS identity (Tier 3):** compromise of a node's KMS *credential*
  grants the ability to sign as the whole server identity for as long as the
  credential is valid (the raw key stays in the KMS). Wider blast radius;
  mitigated by KMS access policy, per-node credentials, and KMS audit logs.
- **Forbidden posture:** copied private key — a single node compromise leaks the
  whole fleet's signing identity with no isolation. Rejected normatively.

## Conformance Vectors (ADR-MCPS-011)

- **Per-node multi-key acceptance:** a response signed by any key in the
  authorized set verifies; a key outside the set is rejected.
- **Anchor governance:** adding a node key takes ≥ `T` to be accepted fleet-wide;
  revoking one is enforced within `T` (delegates to ADR-MCPS-021 vectors).
- **Non-exporting Tier 3:** the KMS `ResponseSigner` signs without exposing key
  material (`DelegatedResponseSigner` has no recovery accessor).
- **No flat-list trust:** a key presented without membership in the explicit
  authorized set is rejected even if otherwise well-formed.

## Rationale

The same principle as ADR-MCPS-020: the architecture defines the contract, not
one operational backend. Per-node keys avoid a mandatory KMS dependency, give a
tighter blast radius, and reuse ADR-MCPS-021 for anchor management — the node-key
set *is* trust state. KMS shared identity is genuinely useful (single pinned
identity, centralized signing policy, compliance audit) so it is supported, but
not required for the v0.3 multi-node claim.

## Alternatives Considered

- **KMS single-identity required** — rejected as a v0.3 blocker: a large
  sub-project (access policy, availability, per-sign latency) that should not
  gate the multi-node baseline.
- **Per-node keys as a flat discovered list** — rejected: that is "trust any key
  that shows up"; the anchor must be an explicit governed set.
- **Copied shared private key** — rejected normatively (no blast-radius
  isolation).

## Consequences

### Positive
- No mandatory KMS; tight per-node blast radius; anchor management reuses 021.

### Negative
- Clients must pin a key-set/trust-root rather than a single key (an
  admission-model change that touches the layer-1 contract).

### Neutral
- Tier 3 remains available for operators who need a single pinned identity.

## Compliance and Enforcement

`security-boundary.md`: *"v0.3 supports multi-node deployments with per-node
signing keys inside one trust domain; the server identity is an explicit
authorized key set managed through ADR-MCPS-021 trust propagation. KMS/HSM-backed
shared identity is supported as a higher-assurance optional tier, not required.
Deployments MUST NOT copy a single shared private key across nodes to simulate
one server identity."*

## Related

- ADR-MCPS-003 (Signing Locus)
- ADR-MCPS-021 (governs the authorized key-set anchor and its propagation)
- ADR-MCPS-019 (Phase 7 external backends — the PKCS#11/KMS adapter lands here)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- The wire/format of the "authorized server key set / admission document" — a
  signed manifest, an ATSA admission credential (layer-1 composition), or both.
- Whether Tier 3's single identity coexists with per-node keys in a mixed fleet,
  or is mutually exclusive per deployment.
