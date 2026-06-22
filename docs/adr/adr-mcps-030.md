<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-030: MCP-S Core Is Method-Transparent — Tool Catalog Integrity Is Excluded

## Status

Accepted (v0.4 — 2026-06-21). Records the removal of the former ADR-MCPS-029
manifest-enforcement design from this repository; that design is **relocated** to
the `mcp-tool-catalog-integrity` project as ADR-MTCI-002, where tool-catalog
integrity now lives.

## Context

The former ADR-MCPS-029 (removed from this repository; relocated to
`mcp-tool-catalog-integrity` ADR-MTCI-002) proposed wiring signed-tool-manifest
enforcement into the proxy
dispatch path: the proxy would parse `tools/list` results, recompute tool
descriptor hashes, verify an operator-supplied signed manifest, pin it, and fail
closed on a rug pull. Implementing it would make the proxy **MCP-method-aware** —
it would have to understand `tools/list` response semantics rather than treating
MCP message bodies as opaque, signed/verified envelopes.

MCP-S Core's strongest property — and its cleanest standards-proposal story — is
that it is a **transport-agnostic message-security envelope** that does *not* need
to understand any particular MCP method. It binds and verifies the message,
signer, audience, authorization, freshness, replay, and response, for *any*
method. Tool catalog governance (which tools a server may advertise, whether a
descriptor changed, whether a catalog was operator-approved) is a distinct
semantic layer and an **actively-evolving MCP-community domain** (tool poisoning,
rug-pull detection, descriptor attestation). Folding it into MCP-S Core would
over-broaden MCP-S's responsibilities, entangle its adoption with tool-catalog
work, and make the base proposal harder to evaluate and accept.

The signed-tool-manifest subsystem (`manifest`, `manifest_verifier`,
`manifest_pin`, `manifest_error` in `mcps-policy`) was implemented and unit-tested
but **never wired into any production path** — the proxy remained byte/method
transparent. So no live integration is being removed; only unreachable library
code and a rejected design.

## Decision

1. **MCP-S Core remains method-transparent.** It MUST NOT parse `tools/list`,
   `resources/list`, `prompts/list`, `tools/call`, or any other MCP method body to
   enforce method semantics. It binds and verifies MCP *messages* regardless of
   method.
2. **Tool catalog integrity is excluded from MCP-S Core.** Signed tool manifests,
   tool descriptor hashing, catalog pinning, and rug-pull / drift detection are
   **not** MCP-S concerns.
3. **The signed-tool-manifest subsystem is removed** from `mcps-policy`
   (`manifest.rs`, `manifest_verifier.rs`, `manifest_pin.rs`, `manifest_error.rs`
   and their re-exports). It remains recoverable in git history.
4. **Tool catalog integrity is relocated** to a separate, standalone MCP extension
   — `mcp-tool-catalog-integrity` (MTCI) — which depends on no MCP-S crate, is not
   branded as an MCP-S extension, and **composes with** MCP-S without requiring it.
5. The former ADR-MCPS-029 manifest-enforcement design is **removed** from this
   repository and **relocated** to `mcp-tool-catalog-integrity` (ADR-MTCI-002);
   its wiring is **not implemented** here. The tracking issues for the relocated
   work (#84, #86, #87, #118) are closed against MCP-S and continue (redesigned)
   in the MTCI repository.

This clarifies the relationship to ADR-MCPS-017's deferred-follow-ups list:
"signed tool manifests" are excluded from MCP-S entirely and live in MTCI.
(ADR-MCPS-017 should be updated to remove "signed tool manifests" from its deferred list to keep the ADR set consistent.)

## Proposal boundary (non-goal text)

> **Non-goal:** MCP-S does not define MCP tool catalog governance, tool descriptor
> review, signed tool manifests, tool safety classification, host UI confirmation,
> or tool invocation policy. MCP-S secures MCP messages and verified security
> context. Tool catalog integrity and anti-rug-pull mechanisms may be defined by
> separate MCP extensions or profiles and can compose with MCP-S.

## Rationale

A minimal, orthogonal security envelope is easier to review, compose, and propose
upstream than a security gateway that also owns tool-catalog semantics. Keeping
MCP-S method-transparent preserves its central claim ("we do not need to
understand every MCP method") and avoids competing with — or appearing to preempt
— the MCP community's tool-catalog/security work. Tool catalog integrity is a
real, valuable problem; relocating it to a clean-room, single-purpose extension
lets it be reviewed and adopted on its own terms.

## Consequences

### Positive
- The MCP-S proposal stays narrow and orthogonal; the proxy keeps its
  body-transparent design.
- Tool catalog integrity (MTCI) is publishable and reviewable independently.

### Negative
- A deployment wanting both message security and catalog integrity adopts two
  profiles. Accepted: they are genuinely separate concerns.

### Neutral
- The boundary must be actively defended in review; no MCP-S change may
  reintroduce MCP-method-semantic parsing for tool-catalog enforcement.

## Related

- Former ADR-MCPS-029 (removed from this repository; the manifest-enforcement
  design relocated to `mcp-tool-catalog-integrity` ADR-MTCI-002)
- [ADR-MCPS-017](adr-mcps-017.md) (deferred-follow-ups list; should be updated per this ADR to remove signed tool manifests)
- `mcp-tool-catalog-integrity` (the relocated extension; ADR-MTCI-001 mirrors this
  boundary from the other side)
- Closed against MCP-S: issues #84, #86, #87, #118
