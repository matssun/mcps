<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-008: Verified-Context Propagation to Inner MCP Servers

## Status

Accepted

## Context

Derived from PRD; depends on ADR-MCPS-003. A sidecar can verify MCP-S at the boundary, but if the inner MCP server uses broad downstream credentials, confused-deputy risk remains. The inner server therefore needs the verified identity context per request. The brief offers three vague options for `stdio` ("local metadata channel, environment handle, or verified context object") and never commits. The mechanism must be per-request, require no inner-server rewrite, and be unspoofable by the original caller.

## Decision

A sidecar propagates verified request context to an inner MCP server by injecting an in-band `_meta` block under `se.syncom/mcps.verified` (carrying `verified_signer`, `key_id`, `on_behalf_of`, `audience`, `authorization_hash`, `request_hash`, `verifier`, `verified_at`); the sidecar MUST strip any caller-supplied verified-context key regardless of inbound signature validity and be its sole writer, strips the external `*.request` envelope from the forwarded message by default, leaves the block unsigned (trust derives from the private local channel), and treats it as a local-boundary artifact that is never a portable credential.

## Rationale

Only in-band `_meta` injection satisfies per-request + no-inner-rewrite + unspoofable simultaneously: environment variables are fixed at process spawn and cannot carry per-request context for a long-lived `stdio` server; a separate side-channel requires the inner server to read a non-standard channel, defeating the "protect existing servers" goal. The strip-and-sole-writer rule mirrors the brief's HTTP-header overwrite rule. For `stdio` the subprocess stdin pipe is the private channel; for loopback HTTP, a private loopback/Unix socket. Honest caveat: an unmodified inner server is protected *at the request boundary* but cannot enforce downstream least-privilege unless it is MCP-S-aware or its downstream calls are sidecar-mediated.

## Alternatives Considered

- **Environment variable**: rejected — process-spawn scope, not per-request.
- **Mandatory out-of-band side-channel (extra fd / socket)**: rejected — requires modifying the inner server, defeating the unmodified-server goal.
- **Signed verified-context block in Core**: rejected — forces the inner server to hold the sidecar key and do crypto (a partial rewrite); deferred to a future native profile.

## Consequences

### Positive
- Per-request, transport-uniform, and works with unmodified inner servers.

### Negative
- Trust depends on local channel isolation; confused-deputy is only partially mitigated (documented, not eliminated).

### Neutral
- A future native profile may define signed verified-context propagation; a debug/audit mode may preserve the original envelope under a separate diagnostic key.

## Compliance and Enforcement

Conformance sidecar-forwarding tests assert: caller-supplied `*.verified` is stripped, a fresh block is injected from the verification result only, and the external `*.request` is removed by default. Proxy code review.

## Related

- PRD: (author's private monorepo)
- Depends on: ADR-MCPS-003
- Siblings: ADR-MCPS-010 (extension identifier), ADR-MCPS-011 (delivery)
