<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-047: Stateless Multi-Round-Trip Continuation Evidence

## Status

Accepted (v0.8, 2026-07-02). Shipped on top of the released v0.7.0 (the client
integration + stateless discovery line, ADR-MCPS-043/044). This continuation profile
is delivered end to end across the stack for **v0.8**: `mcps-core`
(the typed `continuation` binding + structural validator, `InputRequiredResult`
classification, response preimage hashing), `mcps-client-core` (continuation signing
via `RequestSigningInputs::with_continuation`, non-terminal correlation
`record_input_required`, `verify_and_classify_response`), the **client proxy**
(`mcps-client-proxy` transparently drives the elicitation → continuation round trip),
and BOTH client SDKs — the **Python SDK** (`sdk/python`) and the **TypeScript SDK**
(`sdk/typescript`), which bind the identical `mcps-client-core` seam (via PyO3 and
napi-rs respectively) so the signed continuation preimage is byte-identical across
every leg. It is NOT part of the v0.7 scope, which stays the client-initiated
request/response subset.

**Implementation status (v0.8, `feat/adr-047-v0.8`):** D1–D9 implemented and tested.
The server/proxy PEP (D6) rides the ordinary draft-02 request verification — the
`continuation` object is inside the signed preimage and the structural validator
runs in `extract_draft02_request_envelope`, so a malformed / typed-wrong / tampered
continuation fails closed with no bespoke proxy code. Shared conformance vectors
d12–d15 (valid continuation, `continuation_type_unsupported`, `continuation_malformed`,
signed `InputRequiredResult`) are in the draft-02 corpus, exercised by core, the
proxy, and both SDKs against the one oracle. Both SDKs verify the `InputRequiredResult`,
hold the non-terminal correlation entry, and sign the bound continuation, with the
server-initiated boundary fail-closed by default (arbitrary push rejected under
`require_mcps`; `allow_unverified_server_initiated` a degraded migration opt-out only).
Acceptance remains a human gate. The application-level cross-check of the continuation
hashes against a specific
server-held prompt stays with the server's `requestState` validation (D5), outside
MCP-S core.

Replaces the earlier broad "Bidirectional Runtime Evidence" framing. The newer
stateless MCP model changes the problem: server-to-client requests are no longer
arbitrary server push. Under SEP-2260, server-initiated requests may only occur
while the server is actively processing a client request. Under SEP-2322, the
server returns an `InputRequiredResult`, and the client re-issues the original call
with `inputResponses` and the echoed `requestState`.

Therefore the MCP-S problem is not general bidirectional messaging. It is
stateless multi-round-trip continuation evidence.

This ADR depends on:

- ADR-MCPS-026: security-relevant stateless `_meta` must be signed or ignored;
- ADR-MCPS-038: draft-02 envelope shape;
- ADR-MCPS-039: authorization-binding forms;
- ADR-MCPS-043: discovery / route policy;
- ADR-MCPS-044: client correlation and response verification;
- ADR-MCPS-046: signed rejection receipts, as a related non-success response path.

## Context

MCP-S draft-02 secures the ordinary client-initiated request/response path:

1. The client signs a request.
2. The server verifies the request.
3. The server signs a response bound to the client's `request_hash`.
4. The client verifies the server signature and checks that the response
   `request_hash` equals the request hash it is holding.

That binding is the core return-leg guarantee. It prevents response substitution,
cross-request splicing, stale response replay, and wrong-server responses.

The older concern was that MCP is bidirectional and servers could send messages
that were not responses to any client request. Those messages had no
`request_hash` anchor, so MCP-S had no safe verification point.

The stateless MCP model changes this. Server-to-client requests such as
elicitation are now request-associated. Instead of pushing an unsolicited request
over a persistent channel, the server returns:

```json
{
  "resultType": "inputRequired",
  "inputRequests": {
    "confirm": {
      "type": "elicitation",
      "message": "Delete 3 files?",
      "schema": { "type": "boolean" }
    }
  },
  "requestState": "eyJzdGVwIjoxLCJmaWxlcyI6WyJhIiwiYiIsImMiXX0="
}
```

The `InputRequiredResult` is a RESPONSE to a signed client request, and the
client's answer is a FRESH signed continuation request. Both legs verify with the
existing draft-02 request/response machinery — no server push, no persistent
channel, no `initialize`-anchored session state. The remaining work is to make the
multi-round-trip *linkage* itself cryptographic evidence, so a continuation cannot
be detached from the prompt it answers.

## Decision

### D1 — Strict MCP-S supports stateless request/response and multi-round-trip continuation, not arbitrary server push

MCP-S strict mode covers:

```text
client signed request
  -> server signed response

client signed request
  -> server signed InputRequiredResult
  -> client signed continuation request
  -> server signed terminal response
```

MCP-S strict mode does NOT cover arbitrary unsolicited server push. If a server
sends an unverifiable server-initiated message outside this request-associated
multi-round-trip structure, the client fails closed under `require_mcps`.

`allow_unverified_server_initiated` remains a degraded migration policy only. It
MUST be audited as no-evidence and MUST NOT be described as strict enterprise
MCP-S.

### D2 — `InputRequiredResult` is verified as an ordinary signed server response

When the server needs client input, it returns an `InputRequiredResult` as the
response to a signed client request. The MCP-S server/proxy MUST sign that response
using the ordinary draft-02 response path. The signed response evidence MUST
include: `version`, `canonicalization_id`, `request_hash`, `server_signer`,
`issued_at`, `signature`.

The client accepts the `InputRequiredResult` only if:

- the response signature verifies;
- `server_signer` resolves to an expected trusted server signer;
- `version` is allowed by local policy;
- `canonicalization_id` is allowed by local policy;
- `response.request_hash` matches an outstanding client `request_hash`;
- the result body, including `inputRequests` and `requestState`, is inside the
  signed preimage.

Only after this verification may the client display or act on the elicitation
prompt.

### D3 — The continuation request is a fresh signed client request

The client continuation is NOT a trusted reuse of the prior request. It is a new
signed MCP-S request. The continuation request MUST include:

- the original method / call shape required by MCP;
- `inputResponses`;
- the echoed `requestState` exactly as received;
- a fresh client `nonce`;
- fresh `issued_at` / `expires_at`;
- `audience`;
- `on_behalf_of` / signer evidence as required by the active profile;
- `authorization_binding` as required by route policy;
- continuation binding to the verified `InputRequiredResult` (D4).

The continuation request is verified by the server using the ordinary draft-02
request verification path.

### D4 — Continuation binding is mandatory

The client MUST bind its continuation request to the exact signed
`InputRequiredResult` it is answering. The continuation request SHOULD carry a
protected field equivalent to:

```json
{
  "continuation": {
    "type": "mcp-mrt",
    "previous_request_hash": "sha256:...",
    "input_required_response_hash": "sha256:..."
  }
}
```

Definitions:

- `previous_request_hash` — the `request_hash` of the client request that produced
  the `InputRequiredResult`.
- `input_required_response_hash` — the hash of the signed response preimage for the
  verified `InputRequiredResult`.

This prevents a client continuation from being detached from the prompt it is
answering. The continuation object MUST be inside the signed client request
preimage. If the continuation object is missing, malformed, or mismatched for a
multi-round-trip continuation, verification fails closed.

### D5 — `requestState` is opaque and must be echoed verbatim

`requestState` is server continuation state. MCP-S does not interpret it. The
client MUST treat `requestState` as opaque bytes/text and include it verbatim in
the signed continuation request.

The server MUST validate `requestState` as authentic, untampered, and intended for
the continuation. MCP-S binds the value into the signed client request, but it does
not define the server's internal `requestState` format. If `requestState` is
altered, omitted, replayed, expired, or invalid according to the server's
continuation-state rules, the server rejects the continuation.

### D6 — Authorization is evaluated again on the continuation request

A continuation request is still a request. Therefore it MUST carry whatever
`authorization_binding` is required by route policy. MCP-S does not assume that
authorization from the first round automatically grants the continuation. The
policy layer may decide that:

- the original authorization remains valid;
- a fresh authorization reference is required;
- the continuation must use the same authorization scope;
- the continuation must be rejected because the authorization state changed.

MCP-S only binds the continuation request to authorization evidence. It does not
interpret authorization semantics.

### D7 — Client correlation store is extended, but the server remains stateless

The client correlation store must support multi-round-trip state. For an
outstanding request that returns `InputRequiredResult`, the client does NOT consume
the correlation entry as terminal. Instead it records:

- original `request_hash`;
- verified `input_required_response_hash`;
- request id / method context;
- deadline / expiry;
- route / audience;
- expected server signer;
- continuation state needed to validate the next response.

When the continuation request is sent, it gets its own fresh request hash and
ordinary response expectation.

The server side remains stateless with respect to MCP-S session state. Any server
continuation state needed to resume work must be carried in `requestState` or in a
server-side store explicitly owned by the application. MCP-S does not require an
`initialize`-anchored session.

### D8 — No `initialize` anchor

This ADR does not use `initialize` as a security anchor. The stateless MCP
direction removes the need for a connection-time security handshake. MCP-S
continuation evidence is carried in signed per-message evidence:

```text
first client request
signed InputRequiredResult response
signed continuation request
signed terminal response
```

Any metadata that influences MCP-S verification MUST be signed or ignored for
security decisions, consistent with [026](adr-mcps-026.md).

### D9 — Arbitrary server push remains out of the strict profile

This ADR does not secure arbitrary server-initiated messages such as: unsolicited
`logging/message`, unsolicited `resources/updated`, unsolicited
`tools/list_changed`, persistent stream notifications, or server push outside an
active client request.

If such features are required, they need a separate future ADR for a bidirectional
or subscription evidence profile. Under `require_mcps`, these messages fail closed
unless represented by the stateless multi-round-trip mechanism defined here.

## Conformance vectors

The implementation must provide vectors for:

**`InputRequiredResult` verification**

- signed client request produces signed `InputRequiredResult`;
- client verifies response signature;
- client verifies `server_signer`;
- client verifies `request_hash`;
- tampered `inputRequests` fails response verification;
- tampered `requestState` fails response verification;
- wrong `request_hash` fails closed;
- unsupported `canonicalization_id` fails closed;
- unsigned `InputRequiredResult` fails closed under `require_mcps`.

**Continuation request**

- continuation request includes `inputResponses`;
- continuation request includes echoed `requestState` verbatim;
- continuation request includes fresh nonce/freshness;
- continuation request includes authorization binding as required;
- continuation request includes `previous_request_hash`;
- continuation request includes `input_required_response_hash`;
- tampered continuation binding fails closed;
- continuation bound to a different `InputRequiredResult` fails closed;
- continuation replay fails closed;
- continuation with missing authorization binding fails closed when policy requires it.

**Terminal response**

- terminal response binds to the continuation request hash;
- response bound to the first-round request hash instead of the continuation hash
  fails closed;
- tampered terminal response fails closed.

**Degraded mode**

- unverified server-initiated message passes only under explicit degraded policy;
- degraded message is audited as no-evidence;
- degraded mode is never accepted as `require_mcps`.

## Non-goals

- No arbitrary server push support.
- No persistent bidirectional session profile.
- No `initialize`-anchored security state.
- No interpretation of `requestState` by MCP-S.
- No judgment that an elicitation prompt is safe merely because it is authentic.
- No authorization semantics inside MCP-S.
- No new cryptography.

## Consequences

Strict MCP-S no longer needs to exclude stateless elicitation-style flows. It can
support them as signed multi-round-trip continuations.

The trust rule remains intact: the client only acts on a server prompt after
verifying it as a signed response bound to a client request. The continuation is
also protected: the server only acts on client input after verifying a fresh signed
continuation bound to the exact signed `InputRequiredResult`.

This keeps MCP-S aligned with the stateless MCP direction while avoiding an
unnecessary general bidirectional evidence system.

## Implementation plan

Delivered in v0.8 across the whole stack (core → client-core → client proxy → SDK),
in this order:

1. Extend `mcps-core` response classification to recognize a verified
   `InputRequiredResult`.
2. Add response hashing for the signed `InputRequiredResult` preimage.
3. Extend `mcps-client-core` correlation state to retain non-terminal
   `InputRequiredResult` entries (associate-without-consume).
4. Define the signed continuation metadata shape.
5. Add continuation request signing support in `mcps-client-core`.
6. Add server/proxy verification rules for continuation binding (`mcps-proxy` PEP).
7. Surface the flow through the adoption bridge — the **client proxy**
   (`mcps-client-proxy`) drives the `InputRequiredResult` → continuation round trip
   transparently for an unmodified MCP client.
8. Bind it in BOTH client SDKs — the **Python SDK** (`sdk/python`, PyO3) and the
   **TypeScript SDK** (`sdk/typescript`, napi-rs): verify `InputRequiredResult`, hold
   the non-terminal correlation entry, and sign the continuation — exposed so an
   `mcp` `ClientSession` / `Client` elicitation works under `require_mcps`.
9. Add conformance vectors (shared corpus, exercised by core, proxy, and both SDKs).
10. Keep arbitrary server push fail-closed under `require_mcps`.

## Open questions

- Exact wire location for the continuation object.
- Whether `input_required_response_hash` should be encoded as `sha256:<base64url>`
  or split into `digest_alg` / `digest_value`.
- Whether `previous_request_hash` is redundant if `input_required_response_hash`
  already commits to the original response.
- Whether continuation binding should be mandatory for all `inputResponses`, or only
  when `requestState` is present.
- How much of `requestState` validation belongs in MCP-S test fixtures versus the
  demo application.
