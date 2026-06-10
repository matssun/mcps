<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-026: Signing Scope Versus Stateless Per-Request `_meta` (SEP-2575)

## Status

Proposed — **conditional on the MCP 2026-07-28 release candidate**; revisit if
the referenced SEP schema changes materially (v0.3 delta sketch). SEP-2575's
`_meta` key set is "proposed but not locked" upstream; this ADR binds to the
*category* of fields (per-request protocol context) and names the minimum that
must be in MCP-S signing scope.

## Context

ADR-MCPS-004 signs the **whole JSON-RPC object** with Ed25519 over JCS
(ADR-MCPS-005); ADR-MCPS-002 freezes the public envelope vocabulary. The
verifier checks one canonical preimage.

The MCP 2026-07-28 stateless release removes the `initialize`/`initialized`
handshake and protocol-level sessions (SEP-2575, SEP-2567). Protocol context that
used to be negotiated **once per session** now travels in **unsigned `_meta` on
every request**: at minimum the protocol version
(`io.modelcontextprotocol/protocolVersion`), client info, and client
capabilities — "clients specify capabilities in `_meta` per-request instead of
negotiating once at connection time."

If any of these per-request fields influence an MCP-S decision but sit **outside
the signed preimage**, an attacker who can modify `_meta` in flight can change
the protocol/capability context under an otherwise-valid signature — a
**downgrade-via-`_meta`** attack (e.g. forcing an older protocol version or
narrower capability profile to dodge a check). This ADR fixes the signing scope.

## Definitions

- **Security-relevant `_meta` field** — any per-request `_meta` value that
  influences an MCP-S verification, authorization, capability-gating, or audit
  decision. `protocolVersion` is security-relevant by default (it gates
  behavior).
- **Signing scope** — the exact set of bytes covered by the MCP-S canonical
  signature (ADR-MCPS-004/005).

## Decision

Every **security-relevant `_meta` field MUST be inside the MCP-S signing scope,
or it MUST be explicitly excluded from the trust boundary and ignored for every
security decision.** There is no third option: a field that is both
decision-influencing and unsigned is forbidden.

1. **`protocolVersion` is in signing scope.** The per-request protocol version
   MUST be covered by the signature. A request whose `_meta` protocol version is
   altered after signing MUST fail verification. This closes protocol downgrade.
2. **Decision-influencing capability/client fields are in signing scope.** Any
   `_meta` client-capability or client-info field that MCP-S uses to gate
   behavior MUST be signed. If MCP-S does not gate on a field, that field MAY
   remain unsigned transport metadata and MUST then be ignored for security.
3. **Canonicalization is explicit about `_meta`.** ADR-MCPS-005 canonicalization
   MUST define deterministically whether `_meta` (and which keys within it) are
   part of the preimage. `_meta` MUST NOT be silently dropped from or silently
   folded into the signature; the rule is stated, not incidental.
4. **Trace/observability fields are explicitly excluded from signing scope.** W3C
   Trace Context (`traceparent`, `tracestate`, `baggage`, SEP-414) and similar
   observability `_meta` are mutated by middle boxes by design; they MUST NOT be
   in signing scope and MUST NOT influence any security decision. They are
   audit-correlation only.
5. **Unknown `_meta` keys follow the fail-closed message rules.** Consistent with
   ADR-MCPS-009, an unknown or unexpected key inside a *signed* region fails
   closed; observability keys live in the explicitly-unsigned region.

## Threat Model

- **Trust boundary:** one operator; `_meta` is attacker-influenceable in flight
  exactly like any other transport-visible field.
- **Primary threat:** downgrade-via-`_meta` — an attacker mutates the unsigned
  per-request protocol version or capability set to force MCP-S onto a weaker
  path while preserving a valid body signature.
- **Defeated by:** placing every decision-influencing `_meta` field in signing
  scope, so mutation breaks the signature.
- **Observability carve-out:** trace fields are intentionally unsigned and
  intentionally non-decisional, so mutating them changes only correlation, never
  security.
- **Deferred:** signing of fields MCP-S does not yet consume — named, not
  specified, so scope does not silently grow.

## Conformance Vectors (ADR-MCPS-011)

- **Protocol-version tamper:** altering `_meta` `protocolVersion` after signing
  fails verification.
- **Capability tamper:** altering a security-relevant `_meta` capability after
  signing fails verification.
- **Trace mutation is safe:** changing `traceparent`/`tracestate`/`baggage` does
  **not** break the signature and does **not** change any security decision.
- **No silent drop:** a verifier that omits `_meta` from the preimage when the
  signer included it (or vice versa) fails closed, not silently accepts.
- **Non-decisional unsigned field:** an unsigned `_meta` field MCP-S does not
  gate on cannot influence verification or authorization.
- **Unknown signed-region key:** an unexpected key inside the signed region fails
  closed (ADR-MCPS-009 consistency).

## Rationale

The stateless model's per-request `_meta` is the right place for protocol context
to live, but it moves that context from a negotiated-once channel into the
attacker's reach on every call. The only honest options are "sign it" or "never
decide on it"; the dangerous middle — decide on an unsigned field — is exactly
the downgrade bug. Making the canonicalization rule for `_meta` explicit (rather
than emergent) keeps signer and verifier in lockstep as the upstream `_meta` key
set settles.

## Alternatives Considered

- **Sign the entire `_meta` blob including trace fields** — rejected: trace
  fields are mutated by legitimate middle boxes; signing them breaks distributed
  tracing and couples security to observability.
- **Leave `_meta` entirely unsigned** — rejected: enables protocol/capability
  downgrade under a valid body signature.
- **Defer until SEP-2575 locks** — rejected: the *category* (per-request protocol
  context) is stable enough to state the rule now; the field list is the only
  moving part, and the rule is written to absorb it.

## Consequences

### Positive
- Closes downgrade-via-`_meta`; signer/verifier agree on `_meta` scope
  deterministically; observability stays unsigned and free to flow.

### Negative
- The canonicalization spec (ADR-MCPS-005) and the signer/verifier must define
  the `_meta` partition precisely and track the final SEP-2575 key set.

### Neutral
- Most `_meta` (trace/observability) remains unsigned; only decision-influencing
  fields are added to scope.

## Compliance and Enforcement

`security-boundary.md` addition: *"In the stateless MCP model, per-request `_meta`
protocol context — protocol version at minimum, and any capability MCP-S gates on
— is covered by the MCP-S signature. Observability `_meta` (W3C Trace Context) is
explicitly unsigned and never influences a security decision. A
decision-influencing field that is not signed is forbidden."*

## Related

- ADR-MCPS-002 (Frozen Public Envelope Vocabulary)
- ADR-MCPS-004 / ADR-MCPS-005 (Ed25519-over-JCS signing of the whole object;
  canonicalization that must now define `_meta` scope)
- ADR-MCPS-009 (Fail-Closed Message Constraints — unknown-field rejection)
- ADR-MCPS-011 (conformance-as-specification)
- SEP-2575 (stateless per-request `_meta`), SEP-2567 (sessions removed),
  SEP-414 (W3C Trace Context in `_meta`)

## Open Questions for Review

- The exact final SEP-2575 `_meta` key set and which keys beyond
  `protocolVersion` MCP-S gates on (drives the signed/unsigned partition).
- Whether the signed `_meta` partition is expressed as an allow-list of signed
  keys or a single nested signed object distinct from the observability region.
