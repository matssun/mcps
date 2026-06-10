<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-027: Extension Identifier Reassignment to `se.syncom/mcps`

## Status

Accepted (implemented in the same change). Supersedes the identifier choice in
ADR-MCPS-010; the incubation strategy and preimage-stability rule of ADR-MCPS-010
remain in force.

## Context

ADR-MCPS-010 chose `name.sundvall/mcps-security` as the controlled, explicitly
non-official incubation extension identifier, on a personal domain, and reserved
the right to change it between draft versions pre-1.0 (the identifier is part of
the canonical preimage, so any change regenerates the conformance vectors).

Two things have changed since:

1. The MCP 2026-07-28 release introduces a first-class **Extensions Framework**
   (SEP-2133): extensions are identified by reverse-DNS IDs (e.g.
   `io.modelcontextprotocol/oauth-client-credentials`) and negotiated through an
   `extensions` capability map. MCP-S wants a stable reverse-DNS identifier under
   a domain the maintainer controls, suitable to advertise as a (still
   non-official) extension and to carry into an eventual Extensions-Track
   proposal.
2. The maintainer controls **`syncom.se`** (an organization domain) and prefers
   it over the personal `name.sundvall` placeholder.

ADR-MCPS-010 explicitly rejected "register a dedicated project domain now" as
unnecessary friction. That trade-off is now reversed: the SEP-2133 framework
gives the identifier an external role, and a stable organization domain is worth
the one-time vector regeneration while still pre-1.0.

## Decision

Reassign every MCP-S wire identifier from the `name.sundvall` root to the
`se.syncom` root, retiring `name.sundvall` from the wire format entirely:

| Role | Old | New |
|---|---|---|
| Extension identifier (`EXTENSION_ID`) | `name.sundvall/mcps-security` | `se.syncom/mcps` |
| Request `_meta` key | `name.sundvall/mcps-security.request` | `se.syncom/mcps.request` |
| Response `_meta` key | `name.sundvall/mcps-security.response` | `se.syncom/mcps.response` |
| Verified-context `_meta` key (unsigned, sidecar→inner) | `name.sundvall/mcps-security.verified` | `se.syncom/mcps.verified` |
| Authorization `_meta` key (`AUTHORIZATION_META_KEY`) | `name.sundvall/mcps-security.authorization` | `se.syncom/mcps.authorization` |
| Reference authorization profile id | `name.sundvall/mcps-authz-reference-v1` | `se.syncom/mcps-authz-reference-v1` |
| Biscuit authorization profile id (example) | `name.sundvall/mcps-authz-biscuit-v1` | `se.syncom/mcps-authz-biscuit-v1` |

Notes:

- The descriptive `-security` suffix is dropped from the extension identifier
  (`mcps` already denotes the secure profile); the authorization profile IDs keep
  their descriptive tails and only swap the root.
- The envelope `version` stays `draft-01`. This reassignment is a pre-1.0
  incubation identifier change permitted by ADR-MCPS-010, not a new draft
  version; a draft-version bump remains a separate future decision.
- The new `se.syncom/mcps` identifier is also the value MCP-S advertises in the
  SEP-2133 `extensions` capability map, keeping the negotiated extension ID and
  the `_meta` key namespace identical.
- The identifier remains **controlled and explicitly non-official**. An
  upstream-assigned `io.modelcontextprotocol/*` identifier would define a further
  new wire profile, per ADR-MCPS-010.

## Consequences

- **Preimage change → vectors regenerated.** The identifier lives inside the
  signed `_meta` keys, so the canonical preimage changed. All Phase 1–4 core
  vectors (`mcps-core/tests/vectors/*.json`) and the Phase 5 policy vectors
  (`mcps-policy/tests/vectors/phase5_vectors.json`) were regenerated with real
  signatures over the new bytes, via the existing deterministic generators
  (`mcps-core` `write_fixtures`; `mcps-policy` `gen_phase5_vectors`).
- A cargo entry point (`mcps-policy` example `gen_phase5_vectors`) was added so
  the Phase 5 vectors can be regenerated without Bazel in the standalone repo,
  mirroring the monorepo Bazel target.
- The single-source-of-truth constants (`mcps_core::ids`,
  `mcps_policy::AUTHORIZATION_META_KEY`, `mcps_policy::REFERENCE_PROFILE_ID`)
  changed once; all references flow from them.
- Living specs and runbooks were updated to the new identifier; ADR-MCPS-010's
  body is preserved unchanged as the historical record of the original choice.

## Compliance and Enforcement

The frozen-string test in `mcps-core/src/ids.rs` pins the new values; the
committed-vector byte-equality check in `mcps-core/tests/vectors_test.rs` and the
Phase 5 replay test in `mcps-policy/tests/vectors_test.rs` fail closed if any
identifier or signature drifts. `CONTEXT.md` / `security-boundary.md` record the
identifier; vectors are regenerated whenever a preimage-affecting field changes
(ADR-MCPS-010 rule, carried forward).

## Related

- ADR-MCPS-010 (superseded identifier choice; incubation + preimage-stability
  rule still in force)
- ADR-MCPS-002 (Frozen Public Envelope Vocabulary)
- ADR-MCPS-004 / ADR-MCPS-005 (the signing rule and canonicalization that make
  the identifier part of the preimage)
- ADR-MCPS-008 (verified-context key), ADR-MCPS-013 (authorization block + profile id)
- ADR-MCPS-011 (conformance-as-specification; vector regeneration)
- SEP-2133 (MCP Extensions Framework — the external role for this identifier)
