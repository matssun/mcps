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

**Project direction:** nothing here is shipped — the repo is a public
work-in-progress driving toward a standards proposal. Internally we develop
against **draft-02 only**; draft-01 is legacy, slated for eventual retirement,
and gains no new code.

`mcps-proxy` therefore calls `verify_request_dispatch` with
`ExpectedVersionPolicy::Draft02Only` instead of the hardcoded draft-01
`verify_request`. No migration posture is wired into the new path. The
`VerifiedContext` builder (`proxy.rs:434`) stops forcing `draft01_hash()` and
accepts the draft-02 typed `authorization_binding`. This is the already-planned
MCPS-37 work; it reuses tested Core code.

The pre-existing draft-01 demo (`mcps-host` + `demo_e2e_test.rs`) is left
untouched for now and is **not** a constraint on the new path; it is migrated to
draft-02 or retired as a later cleanup, not preserved as a dual-version
requirement.

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
| **T2** Internal roles | Small company, internal | scoped delegated authorization — reader vs admin grant; reader's write **denied before dispatch** (`authorization_scope_denied`, proxy lifecycle sink shows the inner was never reached), admin's write allowed | loopback | software | reference profile |
| **T3** External users | Small company, external users | mTLS identity binding (`transport-binding exact`) + transport negatives (no cert, untrusted CA, identity≠signer); plus the **received-log cross-process confirmation** — a denied reader write leaves the inner's own append-only record unchanged, an allowed admin write is recorded | **mTLS** | software | reference profile |
| **T4** Enterprise key custody | Larger enterprise | **both** client and server signing keys in GCP Cloud KMS (non-exporting); the full four-hop with cloud-held identities | mTLS | **GCP KMS** | reference profile |

T0–T3 run offline with `cargo test`; T4 is `#[ignore]`/env-gated and runs from
the live-cloud script. The ladder maps onto the phases:

- **Phase 1** — extend `mcps-demo-fileserver` (`read_file`/`write_file`/`stat`,
  scope tags, optional `--received-log`) → enables **T1**, **T2**.
- **Phase 2** — scoped `mcps-policy` grants (reader/admin); reader's write denied
  before dispatch, proven via the proxy lifecycle sink (no `--received-log`
  wiring — the demo proxy clears the inner environment, so the on-disk cross-check
  is a cross-process concern deferred to Phase 3) → **T2**.
- **Phase 3** — the multi-process four-hop, in sub-phases:
  - **3a** — D1 server wiring: `verify_request_dispatch` + `ExpectedVersionPolicy`
    field/builder/`--expected-version-policy` flag (default `Draft01AndDraft02`;
    walkthrough opts into `Draft02Only`).
  - **3b** — `mcps-client-proxy-cli` binary + a real mTLS `RemoteTransport`.
  - **3b.5** — *server* draft-02 serving in `mcps-proxy`. **Necessary discovery:**
    D1 wired only the *verify* step; `build_forwarded_request` / `build_signed_response`
    were still draft-01-only (a draft-02 verdict failed closed at the
    `authorization_hash` extraction). 3b.5 version-branches both: a draft-02
    verified context (binding, no hash sentinel) and a protected draft-02 response
    envelope. Without it the four-hop only proves verification, not serving.
  - **3c** — the `mcps-walkthrough` crate + the four-hop harness → **T0**, **T1**.
    NOTE: the client-proxy is mTLS-only, so the four-hop runs over
    **mTLS-on-loopback** throughout (not plain loopback); the lower tiers
    deliberately leave transport-identity *binding* off (`--transport-binding
    none`) — message-level security is transport-independent.
  - **3d** — **T3** (DONE): `--transport-binding exact` + a server-name negative +
    the `--received-log` cross-process confirmation. The tier file
    (`t3_external_users_transport_binding.rs`, 4 tests) proves: a matching identity
    passes `exact` and is recorded in the inner's own log (one inner spawn); the
    SAME mismatched client cert passes with binding OFF but is denied-before-
    dispatch under `exact` — isolating the binding as the cause — with the denied
    call absent from the inner's record and ZERO inner spawns; a wrong expected
    `--server-name` fails closed with no inner data. **Wire-honesty discovery:** at
    the four-hop boundary the client cannot surface the remote's *reason*
    (`transport_binding_failed` rides an UNSIGNED error body the client rightly
    distrusts → it reports a generic fail-closed verdict). So T3 proves the
    OUTCOME (denied before dispatch, cross-process); the server-side reason token
    stays pinned by the in-process `mcps-proxy` suite. Downgrade negatives live in
    `proxy_version_policy_test`, not re-proven here. The capability gap this exposes
    — a client cannot learn a TRUSTED rejection reason over an untrusted channel —
    is addressed by [046](adr-mcps-046.md) (Signed Rejection Receipts), a separate
    protocol feature; T3 deliberately does not pre-empt it.
- **Phase 4** (client KMS signer DONE) — a non-exporting Cloud KMS **client**
  signer (`KmsClientSigner` in `mcps-client-proxy-cli`, behind the optional
  `gcp_kms` feature) bridges `mcps-client-core`'s `ClientSigner` to the
  live-tested `GcpKmsEd25519Backend` from `mcps-proxy` (reuse-in-place; a default
  build stays software+mTLS). GCP Cloud KMS natively supports Ed25519
  (`EC_SIGN_ED25519`), so the key is held in KMS and signs the same PureEdDSA
  preimage — no alg substitution. Proven OFFLINE via the no-network fake backend
  (a KMS-bridge signature verifies under the unmodified `mcps-core` verifier;
  custody `NonExporting` passes the hardening profile) and LIVE via an `#[ignore]`
  client lane + the cloud script. `--key-source gcp-kms` enforces the
  non-exporting profile; a default build refuses it rather than degrading.
  *Follow-up:* extract the KMS backend into a neutral shared crate so the client
  need not depend on the server crate.
  - **FOLLOW-UP — T4 integrated four-hop over Cloud KMS (NOT yet proven).** A
    single live run with the client signer = Cloud KMS AND the server signer =
    Cloud KMS over the real socket, the harness fetching BOTH public keys for the
    trust wiring (two distinct KMS keys); manual/live-gated, validated only with
    cloud credentials. v0.7 ships the two halves as separate live lanes (client
    KMS signer + server KMS response signing) but does NOT claim the integrated
    run — see CHANGELOG `[0.7.0]` "NOT yet claimed."
- **Phase 5** (DONE) — sanitized two-version model: the real `work/` script stays
  gitignored; a committed placeholder (`scripts/test-gcp-cloud.sh.example`, all
  identifiers replaced) documents the full lane incl. the client KMS key; and a
  tracked-file leak guard (`mcps-walkthrough/tests/no_tracked_secrets.rs`) asserts
  — via `git grep` over tracked files only, with the forbidden identifiers
  assembled from fragments so the guard is not itself the leak — that no real
  account/project identifier is ever committed.

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
