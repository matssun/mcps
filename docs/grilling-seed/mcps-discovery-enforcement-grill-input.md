<!-- SPDX-License-Identifier: Apache-2.0 -->

# Grill Input: MCP-S Discovery, Capability Advertisement, and Enforcement Policy

**Purpose:** Input document for a grilling session that will produce an ADR.  
**Candidate ADR title:** `ADR-MCPS-020: Discovery and MCP-S Enforcement Policy`  
**Status:** Draft input for review, not a decision record.  
**Target release:** MCP-S draft-02 / v0.6 candidate, or later if the grill decides discovery is not ready.  
**Primary question:** How should an MCP-S-capable client or client-side proxy discover MCP-S support and decide whether to require, allow, or reject legacy MCP behavior?

---

## 1. Background

MCP-S has so far focused mainly on runtime evidence: request signatures, response signatures, freshness, replay protection, audience binding, authorization-evidence binding, canonical preimages, and response-to-request binding.

That is not enough for adoption. A client, SDK, or local client proxy needs a way to know whether a target server claims MCP-S support, which profile versions and canonicalization schemes are available, and whether the local security policy allows legacy MCP.

This creates a discovery and enforcement problem.

A discovery mechanism may tell the client:

- the server claims MCP-S support;
- the server claims support for one or more MCP-S profile versions;
- the server claims support for specific canonicalization identifiers;
- the server claims support for specific authorization-binding forms;
- the server provides a server identity hint or signer hint;
- the server provides a policy or deployment profile identifier.

However, a discovery result is only a claim. It is not the security proof.

The security proof comes from cryptographic MCP-S verification:

- signed request evidence;
- protected `version`;
- protected `canonicalization_id`;
- protected `authorization_binding`;
- valid audience binding;
- valid freshness and replay checks;
- signed response evidence;
- valid `server_signer`;
- valid response-to-request binding.

Therefore, discovery must not become a downgrade mechanism.

---

## 2. Core problem

An MCP-S-capable client or proxy needs to know how to behave when contacting a server.

It may face at least these cases:

1. The server supports MCP-S draft-02 and advertises it.
2. The server supports MCP-S but does not advertise it correctly.
3. The server advertises MCP-S but does not produce valid MCP-S evidence.
4. The server is legacy MCP only.
5. An intermediary strips or alters MCP-S discovery metadata.
6. An attacker or misconfiguration makes MCP-S capability appear absent.
7. A server advertises weaker or older MCP-S versions to trigger downgrade.
8. A server advertises unsupported canonicalization or authorization-binding forms.
9. A client is configured for strict enterprise security and must fail closed.
10. A client is configured for migration or development and may allow legacy MCP explicitly.

The ADR must answer:

> What is the authoritative source of truth for MCP-S enforcement: server discovery, client policy, or cryptographic verification?

Proposed answer:

> Discovery is advisory. Client policy is authoritative for enforcement. Cryptographic MCP-S verification is the security proof.

---

## 3. Proposed decision posture

The ADR should consider adopting this posture:

```text
MCP-S discovery is advisory.
MCP-S enforcement is policy-driven.
MCP-S verification is cryptographic.
MCP-S-capable clients MUST NOT silently downgrade to legacy MCP.
```

This means:

- A server capability claim may help the client choose an MCP-S path.
- A missing capability claim must not automatically mean legacy MCP is allowed.
- A server capability claim must not override local client/operator policy.
- A server capability claim must not be treated as proof that MCP-S is active.
- The client must require successful MCP-S evidence verification when policy requires MCP-S.
- Legacy MCP may be supported only under explicit policy.

---

## 4. Candidate enforcement modes

The ADR should define a small, explicit set of client-side enforcement modes.

### 4.1 `require_mcps`

Enterprise strict mode.

Behavior:

- The client or proxy requires MCP-S for the configured server/audience.
- If MCP-S discovery is absent, invalid, inconsistent, or unsupported, the client may still attempt MCP-S if configured, but must not fall back to unsigned legacy MCP.
- If valid MCP-S request/response evidence is not produced and verified, the call fails closed.
- Legacy MCP is rejected.

Intended for:

- production enterprise security;
- regulated deployments;
- high-risk tools;
- servers handling sensitive data;
- deployments that claim MCP-S protection.

### 4.2 `allow_legacy_explicit`

Migration mode.

Behavior:

- The client or proxy supports both MCP-S and ordinary MCP.
- Legacy MCP is allowed only because the operator explicitly configured it for that server, route, tool, or environment.
- The client should prefer MCP-S when it is available and valid.
- If MCP-S fails, fallback to legacy is allowed only if policy says fallback is allowed for that endpoint.
- The downgrade should be visible in logs/audit.

Intended for:

- transitional deployments;
- mixed MCP-S and legacy MCP environments;
- development environments with explicit risk acceptance.

### 4.3 `opportunistic_mcps`

Development or exploratory mode.

Behavior:

- The client tries MCP-S if advertised or configured.
- If not available, it may use legacy MCP.
- This mode is not an enterprise security posture.
- It must be clearly labelled as non-production unless the ADR explicitly decides otherwise.

Intended for:

- demos;
- local development;
- compatibility testing;
- early ecosystem adoption.

Open grill question:

> Should `opportunistic_mcps` exist at all, or should the project only define `require_mcps` and `allow_legacy_explicit`?

---

## 5. Discovery surfaces to evaluate

The grill should decide where MCP-S discovery information lives.

Candidate surfaces:

### 5.1 MCP initialize capabilities

The server may advertise MCP-S capability during the MCP initialization flow, where such a flow exists.

Example shape:

```json
{
  "capabilities": {
    "mcps": {
      "versions": ["draft-02"],
      "canonicalization_ids": ["mcps-jcs-int53-json-v1"],
      "authorization_binding_types": [
        "opaque-bytes",
        "authz-system-reference"
      ],
      "server_signer_hint": "kid-or-trust-resolver-id",
      "security_policy_id": "enterprise-strict-v1"
    }
  }
}
```

Security concern:

- This is useful as discovery, but it is not enough for security unless the result is protected, bound, or later verified through signed MCP-S evidence.
- The client must not treat this as proof by itself.

### 5.2 MCP `server/discover`

If MCP defines or requires a `server/discover` surface, MCP-S can define an extension block there.

Example shape:

```json
{
  "mcp": {
    "server": {
      "name": "example",
      "version": "1.2.3"
    }
  },
  "mcps": {
    "versions": ["draft-02"],
    "canonicalization_ids": ["mcps-jcs-int53-json-v1"],
    "authorization_binding_types": [
      "opaque-bytes",
      "authz-system-reference"
    ],
    "response_signing_required": true,
    "server_signer_hint": "kid-or-trust-resolver-id"
  }
}
```

Security concern:

- Self-reported names and versions are observability metadata, not security identity.
- Server identity should come from authenticated identity material such as mTLS certificate identity and/or `server_signer` trust resolution.
- Discovery metadata may be logged, but must not drive trust unless separately attested or cryptographically bound.

### 5.3 Per-request signed `_meta`

MCP-S may require security-relevant protocol context to appear in a signed region of each request.

Relevant principle:

```text
Every security-relevant metadata field must either be in the MCP-S signing scope
or be ignored for security decisions.
```

This is a strong rule for preventing downgrade-via-metadata attacks.

Potential shape:

```json
{
  "_meta": {
    "se.syncom/mcps": {
      "version": "draft-02",
      "canonicalization_id": "mcps-jcs-int53-json-v1",
      "client_enforcement_mode": "require_mcps"
    }
  }
}
```

Open issue:

- Should enforcement mode ever travel on the wire?
- Or should enforcement mode be local-only operator/client policy?

Proposed answer:

- Enforcement mode should be local policy, not server-directed.
- Wire metadata can declare profile/version used by a signed message, but must not tell the verifier to weaken policy.

### 5.4 Static client configuration

For enterprise use, the client or local proxy may be configured with expected MCP-S posture per server/audience.

Example:

```yaml
servers:
  "payments-mcp":
    audience: "mcp-server://payments.example.com"
    enforcement: "require_mcps"
    accepted_versions:
      - "draft-02"
    accepted_canonicalization_ids:
      - "mcps-jcs-int53-json-v1"
    accepted_authorization_binding_types:
      - "opaque-bytes"
      - "authz-system-reference"
    expected_server_signers:
      - "kms://projects/acme/locations/global/keyRings/mcps/cryptoKeys/payments"
```

This is likely the enterprise baseline.

Discovery can refine or confirm, but not replace this policy.

---

## 6. Downgrade threats

The grill should explicitly test the ADR against these downgrade attacks.

### 6.1 Capability stripping

An intermediary removes the MCP-S capability block.

Expected behavior:

- `require_mcps`: fail closed or continue with configured MCP-S attempt; never fallback to legacy.
- `allow_legacy_explicit`: fallback only if explicitly allowed.
- `opportunistic_mcps`: may fallback, but must be labelled non-enterprise.

### 6.2 Version downgrade

A server or attacker advertises only draft-01 when the client expects draft-02.

Expected behavior:

- If draft-01 is not explicitly allowed, fail closed.
- If dual-mode migration is explicitly configured, allow only under that policy.
- Log downgrade or legacy path clearly.

### 6.3 Canonicalization downgrade

A server advertises an older, weaker, or unknown canonicalization identifier.

Expected behavior:

- Unknown canonicalization id: fail closed.
- Known but not allowed by policy: fail closed.
- Message-selected canonicalization id must not cause verifier to load arbitrary schemes.

### 6.4 Authorization-binding downgrade

A server or path attempts to replace `authz-system-reference` with `opaque-bytes`, or remove authorization binding entirely.

Expected behavior:

- If policy requires a binding type, mismatch fails closed.
- Missing authorization binding fails closed when authorization binding is required.
- Structured authorization-object hashing is not accepted unless explicit profile exists.

### 6.5 Server identity confusion

A server claims a name/version but signs with an unexpected `server_signer`.

Expected behavior:

- Name/version may be logged.
- Trust decision follows authenticated identity and `server_signer` resolution.
- Unexpected signer fails closed under `require_mcps`.

---

## 7. Proposed conformance vectors

The ADR should require test vectors and integration tests for:

1. MCP-S advertised and valid: accepted under `require_mcps`.
2. MCP-S absent under `require_mcps`: rejected.
3. MCP-S absent under explicit legacy policy: accepted as legacy and audited.
4. MCP-S advertised but response unsigned: rejected under `require_mcps`.
5. MCP-S advertised but invalid `server_signer`: rejected.
6. MCP-S advertised with unsupported version: rejected.
7. MCP-S advertised with unsupported canonicalization id: rejected.
8. MCP-S advertised with allowed version/canonicalization but message uses different values: rejected.
9. Discovery metadata stripped: no silent downgrade.
10. Discovery metadata tampered: no policy weakening.
11. Unknown capability keys in signed security region: fail closed.
12. Observability metadata changed: no security decision changes.
13. Legacy MCP explicitly allowed: call succeeds but is visibly marked as legacy/no-runtime-evidence.
14. Opportunistic mode, if retained: call succeeds with explicit non-enterprise warning.

---

## 8. Key design questions for the grilling session

### Q1. Does MCP-S require a discovery protocol before v0.6 can be credible?

Candidate answers:

- Yes, at least as ADR and minimal implementation.
- Yes, but implementation can follow after core draft-02.
- No, static configuration is enough for v0.6.

### Q2. Should MCP-S discovery be part of MCP initialize, `server/discover`, per-request `_meta`, or all of them?

Grill concerns:

- compatibility with current MCP;
- stateless MCP behavior;
- protection against downgrade;
- ease of implementation;
- client proxy support.

### Q3. What is the enterprise default?

Proposed answer:

```text
No implicit default. Operator/client policy must explicitly choose.
Production enterprise profile should use require_mcps.
```

### Q4. Should legacy fallback exist?

Proposed answer:

```text
Yes, but only as explicit migration policy.
No silent downgrade.
```

### Q5. Should server self-reported name/version be trusted?

Proposed answer:

```text
No. It is observability metadata only unless attested or bound by a trusted authority.
Security identity comes from mTLS identity and/or server_signer trust resolution.
```

### Q6. Should the server advertise `security_policy_id`?

Possible answer:

- It may advertise a policy profile id for observability or compatibility.
- The client must not accept a server-provided policy id as authority to weaken local policy.
- The client may require that the advertised policy id match its expected policy.

### Q7. Should enforcement mode be transmitted?

Proposed answer:

- No, enforcement mode is local policy.
- The message may declare which MCP-S version/canonicalization was used.
- The verifier enforces local expected-version policy.

### Q8. How should discovery relate to signed runtime evidence?

Proposed answer:

- Discovery tells the client what to try.
- Signed runtime evidence proves what actually happened.
- If there is a conflict, verification and client policy win.

---

## 9. Draft ADR decision candidate

The grilling session may choose to turn this into the following ADR decision:

```text
MCP-S clients and client-side proxies MUST implement explicit enforcement policy.
MCP-S discovery is advisory and MUST NOT be treated as proof of protection.
A server capability claim MUST NOT override local client/operator policy.
A client MUST NOT silently downgrade from MCP-S to legacy MCP.
Legacy MCP MAY be allowed only under explicit policy.
For enterprise deployments, the recommended posture is require_mcps.
The authoritative proof of MCP-S operation is successful cryptographic verification
of MCP-S request and response evidence, not discovery metadata.
```

---

## 10. Implementation implications

If accepted, implementation likely needs:

- client/proxy configuration for enforcement mode;
- accepted MCP-S versions;
- accepted canonicalization identifiers;
- accepted authorization-binding types;
- expected audience;
- expected server signer/trust resolver;
- discovery parser for MCP-S capability metadata;
- explicit downgrade/legacy audit events;
- fail-closed error taxonomy for missing, unsupported, or mismatched discovery/evidence;
- conformance tests for downgrade resistance.

---

## 11. Non-goals

This ADR should not define:

- full EMA integration;
- full authorization policy semantics;
- a complete SBOM or server inventory standard;
- self-reported server metadata as trusted identity;
- native support in third-party clients;
- structured authorization-object hashing;
- a general MCP negotiation redesign.

---

## 12. Acceptance criteria for the grill

The ADR produced from this grilling session should be accepted only if it answers:

- What discovery surfaces MCP-S uses.
- What discovery metadata is advisory versus security-relevant.
- What the client does when MCP-S is absent.
- Whether legacy MCP can be used, and under what explicit policy.
- How downgrade attacks are prevented.
- How `version` and `canonicalization_id` interact with expected-version policy.
- How discovery relates to signed request/response evidence.
- What conformance vectors must exist before implementation is called complete.
- What is required for enterprise posture versus development posture.
