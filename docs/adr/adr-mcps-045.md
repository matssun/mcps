<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-045: End-to-End Walkthrough — Tiered E2E Ladder and Client-Proxy Wire Interop

## Status

Proposed — v0.7 work, Phase 0 spike output (2026-06-30). Closes the
"prove v0.7 end-to-end" gap left open by [044](adr-mcps-044.md) (Client
Integration Model), which specified the client proxy but landed it with
**in-process** tests only. Depends on the existing `verify_request_dispatch`
([038](adr-mcps-038.md) draft-02 envelope), `mcps-transport` mTLS
([028](adr-mcps-028.md)), and the GCP Cloud KMS key source.

## Context

Two facts from the spike (read-only, on `release/0.7`):

1. **Wire-version mismatch is real and structural.** `mcps-client-core`
   signs **draft-02 only** (`build_signed_request`, pinned `VERSION_DRAFT_02`);
   the `mcps-client-proxy` pins draft-02 (`proxy.rs:181`). The server-side PEP
   `mcps-proxy` verifies **draft-01 only** on the wire (`proxy.rs:271` calls
   `mcps_core::verify_request`; the draft-02 path was deferred to MCPS-37/#183).
   The new client stack and the real-process server **cannot talk over a socket
   today.** The existing real-process e2e (`mcps-demo/tests/demo_e2e_test.rs`)
   proves the *server* side with the *old* draft-01 ambassador (`mcps-host`),
   not the v0.7 client proxy.

2. **The bridge already exists in Core.** `mcps_core::verify_request_dispatch`
   (`pipeline.rs:653`) reads the untrusted envelope `version`, rejects
   downgrades per `ExpectedVersionPolicy` (`Draft02Only` is the recommended
   posture), and dispatches to the matching profile verifier. The server PEP
   simply does not call it yet.

The user also fixed the shape of the deliverable: the tests must read as a
**logical ladder of personas**, each step adding exactly one security concept,
each with a one-screen "what this proves" note — not a wall of framework prose.

## Decision

### D1 — Server PEP gains draft-02 on the wire via the existing dispatcher

`mcps-proxy` calls `verify_request_dispatch` with `ExpectedVersionPolicy`
resolved from operator config (`Draft02Only` recommended; `Draft01AndDraft02`
for migration) instead of the hardcoded draft-01 `verify_request`. The
`VerifiedContext` builder (`proxy.rs:434`) stops forcing `draft01_hash()` and
accepts the draft-02 typed `authorization_binding`. This is the already-planned
MCPS-37 work; it reuses tested Core code.

**Rejected — option (a):** teaching `mcps-client-core` to also sign draft-01.
It fights the deliberately draft-02-only client seam (CONTEXT glossary), would
re-derive draft-01 host signing that already lives in `mcps-host`, and points
backward instead of toward the v0.6+ envelope.

### D2 — Real client→remote transport reuses `mcps-transport` mTLS

The `mcps-client-proxy` `RemoteTransport` trait gets a real implementation over
the existing verifying mTLS client (`mcps-transport`), which the server PEP
already terminates. The lowest ladder tiers use a plain loopback transport (no
mTLS) so the first thing a reader runs has no certificate setup; mTLS is the
*one new concept* a later tier introduces.

### D3 — The tiered e2e ladder is the organizing structure

All e2e tests are grouped as a persona ladder. Each tier = one test module +
a ≤10-line header (persona · what it proves · the single new concept · the one
command to run it). Each tier adds exactly one capability over the previous.

| Tier | Persona | New concept this tier adds | Transport | Keys | Authz |
|------|---------|----------------------------|-----------|------|-------|
| **T0** Hello, signed call | Individual, "just see it work" | object signing + response binding (authenticity, not yet authorization) | loopback | software | none |
| **T1** Real tools, fail closed | Individual, maturing | extended fileserver (`read`/`write`/`stat`) + the fail-closed cases (tamper, replay, unsigned) over the wire | loopback | software | none |
| **T2** Internal roles | Small company, internal | scoped delegated authorization — reader vs admin grant; write **denied before dispatch** (received-log proves the inner never ran) | loopback | software | reference profile |
| **T3** External users | Small company, external users | mTLS identity binding (`transport-binding exact`) + transport negatives (no cert, untrusted CA, identity≠signer) | **mTLS** | software | reference profile |
| **T4** Enterprise key custody | Larger enterprise | **both** client and server signing keys in GCP Cloud KMS (non-exporting); the full four-hop with cloud-held identities | mTLS | **GCP KMS** | reference profile |

T0–T3 run offline with `cargo test`; T4 is `#[ignore]`/env-gated and runs from
the live-cloud script. The ladder maps onto the phases:

- **Phase 1** — extend `mcps-demo-fileserver` (`read_file`/`write_file`/`stat`,
  scope tags, optional `--received-log`) → enables **T1**, **T2**.
- **Phase 2** — scoped `mcps-policy` grants (reader/admin) → **T2**.
- **Phase 3** — `mcps-client-proxy-cli` binary + real `RemoteTransport`; the
  multi-process harness → **T0**, **T1**; plus D1 server wiring. mTLS variant →
  **T3**.
- **Phase 4** — client-side GCP KMS signer in `mcps-client-core` + live lane →
  **T4**.
- **Phase 5** — sanitized two-version model (real `work/` script gitignored; a
  committed placeholder template; tracked-file leak guard).

### D4 — One discoverable home, runnable in one command per tier

The ladder lives in a single dedicated crate (working name `mcps-walkthrough`)
with one test file per tier and a top-level `README.md` that *is* the ladder
table above. It reuses `mcps-demo` building blocks (`DemoFixtures`,
`build_demo_proxy`, the proxy flag set) rather than duplicating them. A
`scripts/walkthrough.sh` runs T0–T3 in order; T4 has its own cloud script.

## Consequences

- The v0.7 client proxy gets its first **real-process, real-socket** proof,
  closing the gap [044](adr-mcps-044.md) left.
- `mcps-proxy` becomes draft-02-capable on the wire (D1) — a real production
  step, not test-only scaffolding.
- New surface to build: a client-proxy CLI binary, a real `RemoteTransport`
  impl, a client-side KMS signer, the walkthrough crate. Each is one phase /
  one PR onto `release/0.7` (not `main`) until the epic is complete.
- Open naming decision for the owner: the walkthrough crate name
  (`mcps-walkthrough` vs `mcps-e2e` vs `mcps-tour`).
