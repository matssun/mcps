<!-- SPDX-License-Identifier: Apache-2.0 -->

# Grill Input: MCP-S Client-Side Integration Model

**Purpose:** Input document for a grilling session that will produce an ADR.  
**Candidate ADR title:** `ADR-MCPS-021: Client-Side MCP-S Integration Model`  
**Status:** Draft input for review, not a decision record.  
**Target release:** MCP-S draft-02 / v0.6 candidate, or later if the grill decides client-side support should be staged.  
**Primary question:** How should MCP-S be adopted by clients, hosts, SDKs, and local proxies so that MCP-S is deployable without waiting for native support from every MCP host?

---

## 1. Background

MCP-S is a two-sided runtime-evidence protocol.

The server side alone cannot provide the full security properties. A server-side MCP-S wrapper can verify signed requests and sign responses, but it cannot create client request signatures, generate client nonces, bind client-side authorization evidence, or verify the response at the receiving end.

For full MCP-S, some client-side component must:

- construct signed MCP-S request evidence;
- include protected `version`;
- include protected `canonicalization_id`;
- include nonce/freshness material;
- bind the request to an intended audience;
- bind the request to authorization evidence;
- remember or recompute the request hash;
- receive and verify the server's signed response;
- validate `server_signer`;
- validate response-to-request binding;
- enforce downgrade and legacy policy.

If MCP-S is only a server wrapper, adoption will be limited. Ordinary MCP clients will not know how to produce MCP-S evidence, and MCP-S-enabled servers will have to either reject them or run in a weaker compatibility mode.

Therefore, the client-side integration model is a first-class architectural issue.

---

## 2. Core problem

The MCP ecosystem contains multiple hosts and clients. MCP-S cannot assume immediate native implementation by all major clients.

The project needs a practical adoption path that allows MCP-S to be used before native support arrives.

The ADR should answer:

> What client-side components are valid MCP-S implementations, and which should be built first?

Proposed answer:

> MCP-S should define three client integration modes: native client support, local client-side proxy, and SDK wrapper. The client-side proxy should be the first practical adoption bridge.

---

## 3. Candidate integration modes

## 3.1 Native MCP-S-aware client or host

Shape:

```text
MCP-S-aware host/client
  -> remote MCP-S server/proxy
  -> MCP server
```

Examples of eventual native hosts might include:

- Claude Desktop;
- Claude Code;
- VS Code;
- OpenAI MCP host/client environments;
- enterprise MCP hosts;
- custom internal MCP hosts.

Responsibilities:

- sign outgoing MCP requests;
- manage client signing keys;
- generate nonces;
- set freshness windows;
- set audience;
- attach `authorization_binding`;
- track request hashes;
- verify response signatures;
- validate `server_signer`;
- validate response-to-request binding;
- enforce discovery and downgrade policy;
- surface useful security errors to the user/operator.

Advantages:

- cleanest long-term architecture;
- best UX;
- least proxy complexity;
- easiest to integrate with host identity and authorization flows.

Disadvantages:

- requires ecosystem adoption;
- depends on third-party vendors;
- cannot be the only near-term path;
- may require standardization before major clients implement it.

Proposed ADR stance:

```text
Native MCP-S support is the long-term ideal, but not the initial adoption dependency.
```

---

## 3.2 Local client-side MCP-S proxy

Shape:

```text
ordinary MCP client
  -> local MCP-S client proxy
  -> remote MCP-S server/proxy
  -> ordinary MCP server
```

This is likely the most important early adoption path.

The ordinary MCP client talks standard MCP to a local endpoint. The local MCP-S proxy adds MCP-S evidence on outbound calls and verifies MCP-S evidence on inbound responses.

Responsibilities:

- expose a standard MCP-compatible local endpoint;
- discover or configure remote server MCP-S posture;
- sign outgoing requests;
- insert MCP-S envelope/evidence;
- generate nonce/freshness;
- set audience;
- attach authorization binding;
- track pending request hashes;
- forward to remote MCP-S server/proxy;
- verify signed responses;
- reject response binding failures;
- enforce strict, migration, or development policy;
- support legacy MCP only under explicit policy;
- audit downgrade or legacy paths.

Advantages:

- does not require modifying existing MCP clients;
- demonstrates MCP-S value before native client adoption;
- can be used by enterprises as a controlled gateway;
- centralizes policy and trust configuration;
- supports mixed MCP-S and legacy MCP environments during migration.

Disadvantages:

- introduces local deployment component;
- must handle transport details;
- must maintain request/response correlation;
- may need per-client configuration;
- may be harder for browser-only or hosted clients;
- risk of becoming too large if it tries to be a general MCP orchestrator.

Design constraint:

```text
The client-side proxy must be a security adapter, not a general agent orchestrator.
```

It should not become responsible for:

- tool selection;
- agent planning;
- user consent UX beyond security errors;
- general workflow orchestration;
- authorization policy semantics beyond binding and configured enforcement.

Proposed ADR stance:

```text
The local client-side proxy is the first practical adoption bridge for MCP-S.
```

---

## 3.3 SDK wrapper

Shape:

```text
application code
  -> MCP-S SDK wrapper
  -> existing MCP SDK
  -> MCP-S server/proxy
  -> MCP server
```

Candidate SDKs:

- TypeScript wrapper around existing MCP TypeScript SDK;
- Python wrapper around existing MCP Python SDK;
- Rust client library for MCP-S-native deployments;
- later Java/Kotlin/C# if enterprise demand exists.

Responsibilities:

- provide a thin wrapper around existing MCP client calls;
- sign requests;
- manage nonce/freshness;
- set audience;
- attach authorization binding;
- track request hash;
- verify response signatures;
- enforce expected server signer;
- enforce downgrade/legacy policy;
- expose strongly typed errors.

Advantages:

- good for developers building custom MCP clients;
- easier to test than native host integration;
- can share core logic with the local proxy;
- language-native ergonomics;
- can be adopted incrementally.

Disadvantages:

- requires application developers to choose MCP-S wrapper;
- not transparent to unmodified clients;
- may depend on hooks exposed by existing SDKs;
- multiple languages increase maintenance burden.

Proposed ADR stance:

```text
SDK wrappers are important, but they should reuse the same core protocol and policy logic as the client-side proxy.
```

---

## 4. Proposed implementation priority

The grilling session should evaluate this priority order:

```text
1. Define client discovery/enforcement policy.
2. Implement local client-side MCP-S proxy.
3. Implement one SDK wrapper, probably TypeScript or Python.
4. Add Rust client support if useful for internal/proxy reuse.
5. Treat native host/client support as future ecosystem adoption.
```

Rationale:

- Native client support depends on external parties.
- SDK wrappers help developers, but not ordinary existing clients.
- Client-side proxy allows adoption without waiting for client vendors.
- Proxy and SDK can share core signing/verification/policy logic.

---

## 5. Required client-side security responsibilities

Any conforming MCP-S client-side component must implement the following responsibilities.

### 5.1 Request signing

The client-side component must sign the exact MCP request preimage defined by the active MCP-S profile.

Requirements:

- include protected `version`;
- include protected `canonicalization_id`;
- exclude only explicitly excluded fields such as `signature.value`;
- include security-relevant metadata in signing scope;
- reject unsupported canonicalization schemes.

### 5.2 Freshness and replay material

The client-side component must generate freshness material.

Requirements:

- nonce or request identifier;
- issued-at timestamp;
- expiry or max age;
- no nonce reuse within configured window;
- server/proxy must reject replay.

### 5.3 Audience binding

The client-side component must set the intended audience.

Requirements:

- audience should identify the expected MCP-S verifier/server/security endpoint;
- audience must be protected by signature;
- verifier must reject audience mismatch.

### 5.4 Authorization-evidence binding

The client-side component must attach authorization binding when required by policy.

Base draft-02 binding forms:

```text
1. opaque-bytes
2. authz-system-reference
```

Deferred:

```text
3. structured authorization-object hashing
```

Responsibilities:

- attach `authorization_binding`;
- include the binding in the signed preimage;
- for `opaque-bytes`, bind to the exact artifact bytes;
- for `authz-system-reference`, bind to authorization-system-produced reference/digest;
- never interpret arbitrary structured authorization object semantics in the base profile.

### 5.5 Request-hash tracking

The client-side component must remember or recompute the request hash needed to verify response binding.

Requirements:

- track outstanding request hashes;
- correlate responses to requests;
- reject response with mismatched `request_hash`;
- handle timeouts and cleanup.

### 5.6 Response verification

The client-side component must verify signed responses.

Requirements:

- verify response signature;
- verify protected response `version`;
- verify protected response `canonicalization_id`;
- verify `server_signer` through trust resolver;
- verify `request_hash`;
- reject unsigned response when MCP-S is required;
- reject response signed by unexpected signer.

### 5.7 Downgrade enforcement

The client-side component must enforce configured policy.

Requirements:

- no silent downgrade from MCP-S to legacy MCP;
- allow legacy only under explicit policy;
- log/audit legacy behavior;
- reject unsupported versions/canonicalization/binding types.

---

## 6. Legacy MCP handling

The client-side proxy and SDK wrappers may need to handle ordinary legacy MCP. This is necessary for adoption, but dangerous if automatic.

Proposed policy:

```text
Legacy MCP support is allowed only under explicit operator/client policy.
```

The local proxy should be able to route both:

```text
ordinary MCP client -> local proxy -> legacy MCP server
ordinary MCP client -> local proxy -> MCP-S server/proxy
```

But the route must be classified:

```text
route security posture:
  mcps_verified
  legacy_explicit
  rejected_missing_mcps
  rejected_invalid_mcps
```

The client developer should not have to think about every server manually, but the operator policy must.

Possible route config:

```yaml
routes:
  payments:
    remote: "https://payments.example.com/mcp"
    enforcement: "require_mcps"

  internal-demo:
    remote: "http://localhost:8123/mcp"
    enforcement: "allow_legacy_explicit"

  experimental:
    remote: "http://localhost:8124/mcp"
    enforcement: "opportunistic_mcps"
```

---

## 7. Client-side proxy minimal architecture

A minimal client proxy could contain:

```text
local MCP listener
route registry
discovery client
policy engine
request signer
nonce/freshness store
authorization-binding adapter
remote transport adapter
response verifier
trust resolver
audit/event sink
error mapper
```

It should avoid becoming:

- an agent orchestrator;
- a planner;
- a tool router beyond configured routes;
- a full enterprise policy engine;
- a general-purpose API gateway.

Minimal request flow:

```text
1. Receive ordinary MCP request from local client.
2. Resolve route and enforcement policy.
3. Discover or load configured remote MCP-S posture.
4. If MCP-S required, construct MCP-S signed request.
5. Add version, canonicalization_id, audience, nonce, freshness, authorization_binding.
6. Forward to remote MCP-S server/proxy.
7. Receive response.
8. Verify response signature, server_signer, and request_hash.
9. Return ordinary MCP response to local client, or fail with mapped error.
```

Minimal legacy flow:

```text
1. Receive ordinary MCP request from local client.
2. Resolve route.
3. Confirm legacy is explicitly allowed.
4. Forward ordinary MCP request.
5. Mark response path as legacy/no-runtime-evidence.
6. Audit legacy usage.
```

---

## 8. SDK wrapper minimal shape

A thin SDK wrapper should aim for:

```python
client = McpsClient.wrap(
    mcp_client,
    policy=McpsPolicy.require_mcps(
        audience="mcp-server://payments.example.com",
        accepted_versions=["draft-02"],
        accepted_canonicalization_ids=["mcps-jcs-int53-json-v1"],
        expected_server_signers=[...],
    ),
    signer=client_signer,
    authorization_binding_provider=authz_provider,
    trust_resolver=trust_resolver,
)
```

Or in TypeScript:

```ts
const client = McpsClient.wrap(mcpClient, {
  policy: {
    enforcement: "require_mcps",
    audience: "mcp-server://payments.example.com",
    acceptedVersions: ["draft-02"],
    acceptedCanonicalizationIds: ["mcps-jcs-int53-json-v1"],
    expectedServerSigners: [...]
  },
  signer,
  authorizationBindingProvider,
  trustResolver
});
```

Design goal:

```text
Wrap existing SDK calls rather than reimplementing all MCP client behavior.
```

Open question:

> Do existing MCP SDKs expose enough hooks to wrap request/response bytes without forking?

---

## 9. Key design questions for the grilling session

### Q1. Is MCP-S a two-sided protocol?

Proposed answer:

```text
Yes. Full MCP-S requires a client-side component and a server-side verifier/signer.
```

### Q2. Which client-side integration mode should be implemented first?

Proposed answer:

```text
Local client-side proxy first.
SDK wrapper second.
Native client support later.
```

### Q3. Should the proxy hide MCP-S from ordinary clients?

Proposed answer:

```text
Yes, as much as possible. The ordinary client should speak normal MCP locally.
The proxy handles MCP-S evidence externally.
```

### Q4. Should the proxy support legacy MCP?

Proposed answer:

```text
Yes, but only under explicit route/operator policy.
No silent downgrade.
```

### Q5. Should the SDK be a thin wrapper around existing MCP SDKs?

Proposed answer:

```text
Yes, if existing SDK hooks allow it.
Otherwise define the smallest adapter layer needed.
```

### Q6. What language should come first?

Candidate answers:

- TypeScript first because many MCP clients/hosts use TypeScript.
- Python first because it is fast to prototype and useful for enterprise scripts.
- Rust first because core MCP-S implementation is Rust and proxy reuse is easier.

Proposed grill direction:

```text
Implement proxy in Rust if that matches the existing MCP-S codebase.
Implement first SDK wrapper in the ecosystem language with highest adoption leverage.
```

### Q7. Where do client signing keys live?

Options:

- local file key for development;
- OS keychain;
- enterprise KMS;
- hardware-backed key;
- workload identity / mTLS-derived identity;
- delegated signing service.

The ADR should not necessarily solve all key management, but it must not ignore it.

### Q8. How does authorization binding get into the client-side component?

Options:

- static opaque artifact provider;
- token provider;
- EMA/ext-auth profile later;
- authorization-system-reference resolver;
- integration with enterprise IdP or policy agent.

Proposed answer:

```text
The client integration model defines the hook.
Authorization profiles define the source-specific behavior.
```

### Q9. How does the client expose errors?

Error classes should distinguish:

- MCP-S required but not available;
- discovery absent;
- unsupported MCP-S version;
- unsupported canonicalization id;
- missing authorization binding;
- authorization binding mismatch;
- invalid request signature;
- invalid response signature;
- unexpected server signer;
- response request-hash mismatch;
- legacy route explicitly allowed;
- legacy route forbidden.

---

## 10. Proposed conformance tests

A conforming client-side component should have tests for:

1. Signs ordinary MCP request into MCP-S draft-02 request.
2. Includes protected `version`.
3. Includes protected `canonicalization_id`.
4. Includes nonce/freshness.
5. Includes audience.
6. Includes `authorization_binding`.
7. Rejects unsupported canonicalization id.
8. Tracks request hash.
9. Verifies valid signed response.
10. Rejects unsigned response under `require_mcps`.
11. Rejects invalid response signature.
12. Rejects unexpected `server_signer`.
13. Rejects mismatched `request_hash`.
14. Allows legacy route only under explicit policy.
15. Rejects legacy route under `require_mcps`.
16. Does not silently downgrade when discovery metadata is absent.
17. Audits legacy calls distinctly from MCP-S verified calls.
18. Handles timeout and pending request-hash cleanup.
19. Handles repeated nonce prevention.
20. Handles authz-system-reference binding via configured profile/resolver.
21. Rejects authz-system-reference if no matching resolver/profile exists.
22. Rejects structured authorization-object hashing in base profile.

---

## 11. Proposed ADR decision candidate

The grilling session may choose to turn this into the following ADR decision:

```text
MCP-S is a two-sided runtime-evidence protocol.
Full MCP-S protection requires a client-side component that signs requests,
binds authorization evidence, tracks request hashes, and verifies signed responses.

MCP-S defines three client integration modes:
native client support, local client-side proxy, and SDK wrapper.

Native client support is the long-term ideal but not the initial adoption dependency.
The local client-side proxy is the first practical adoption bridge because it allows
ordinary MCP clients to use MCP-S-protected remote servers without client modification.
SDK wrappers should be provided for developers building custom MCP clients and should
reuse the same core signing, verification, and enforcement logic as the proxy.

The proxy and SDK may support legacy MCP only under explicit policy.
They must never silently downgrade from MCP-S to legacy MCP.
```

---

## 12. Implementation implications

If accepted, implementation likely needs:

- a local client-side proxy crate/binary;
- shared client-side signing library;
- shared response verification library;
- route and enforcement-policy configuration;
- trust resolver configuration;
- authorization-binding provider interface;
- nonce/freshness store;
- request-hash tracking store;
- error taxonomy for client-side failures;
- audit events for verified MCP-S versus explicit legacy;
- SDK wrapper design for at least one language;
- end-to-end tests with:
  - ordinary MCP client;
  - local MCP-S proxy;
  - remote MCP-S server/proxy;
  - ordinary MCP server.

---

## 13. Non-goals

This ADR should not define:

- native implementation details for Claude, OpenAI, VS Code, or other external clients;
- complete EMA/ext-auth integration;
- general MCP authorization semantics;
- server-side canonicalization details already covered by draft-02 canonical preimage ADR;
- self-reported server metadata as trusted security identity;
- general agent orchestration;
- a universal MCP router;
- full key-management product design.

---

## 14. Acceptance criteria for the grill

The ADR produced from this grilling session should be accepted only if it answers:

- Whether MCP-S is explicitly two-sided.
- Which client integration modes are recognized.
- Which mode is implemented first.
- How ordinary clients can use MCP-S without modification.
- How legacy MCP is handled without silent downgrade.
- What minimum responsibilities any MCP-S client-side component has.
- What logic is shared between proxy and SDK.
- What is out of scope for the proxy.
- What conformance tests prove the client side works.
- What remains dependent on future ecosystem/native client adoption.
