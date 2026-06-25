<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S

## Why should I care?

**Problem.** An MCP tool call crosses a trust boundary as plain JSON-RPC. Nothing
stops it being forged, replayed, stripped of its authorization context, or
answered by a tampered response.

**MCP-S answer.** MCP-S protects *individual MCP calls* with object-level
signatures, freshness, replay protection, delegated-authorization binding,
response binding, and sidecar-injected verified context — proven on a single-node
Rust-native path and against live Google Cloud KMS (v0.5.1).

**Non-goals.** MCP-S is **not** OAuth, **not** EMA, **not** sandboxing, **not** a
full audit-receipt format. It composes with those layers rather than replacing
them.

See [`docs/MCP-S-IN-ONE-PAGE.md`](docs/MCP-S-IN-ONE-PAGE.md) for the one-page
overview.

## Overview

MCP-S is an experimental third-party security extension proposal for the Model Context Protocol (MCP).

It provides a reference implementation and conformance package for protecting MCP tool calls with:

- object-level request and response signatures;
- freshness and replay protection;
- delegated authorization binding;
- Rust-native mTLS transport hardening;
- sidecar-based protection of ordinary MCP stdio servers;
- signed response verification by the host/client side.

MCP-S is not part of the official MCP specification unless and until it is accepted through the MCP governance and SEP process.

## Quickstart — see MCP-S fail closed

Run the single-node demo and watch the proxy accept exactly one valid signed
call and fail closed on ten tampered, stale, replayed, mis-routed, unauthorized,
or unbound calls — real v0.5.1 behavior, no cloud credentials:

```sh
./scripts/demo-local.sh
```

Expected final line: `OK: MCP-S local demo completed`. The two bins also run
directly under Cargo (`cargo run -p mcps-demo --bin demo_positive` /
`demo_negative`, after `cargo build --workspace --bins`) or Bazel
(`bazel run //mcps-demo:demo_negative`) with no env setup.

Full walkthrough, the grouped fail-closed output, and what each case proves:
[`docs/quickstart-local.md`](docs/quickstart-local.md). For the live Google Cloud
KMS key-custody path (optional, separate): [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md).

## Project status

Current status:

> Experimental / incubating third-party MCP security extension proposal.

Current implementation claim:

> MCP-S is production-hardened for single-node Rust-native deployments.

### Release 0.5 — proposal-readiness over frozen `draft-01`

0.5 is a **proposal-readiness** release. Its work is documentation, conformance,
and claim hardening over the existing `draft-01` wire envelope — making every
security claim reviewable and traceable to a green test — **not** new protocol
mechanism. 0.5 adds **zero** wire-envelope fields; request and response envelopes
are unchanged, and any claim `draft-01` cannot support is ejected to a future
`draft-02` ADR rather than smuggled in as a field addition
([`docs/spec/proposal-scope.md`](docs/spec/proposal-scope.md)).

What 0.5 lands:

- **One canonical claim surface.** The [v0.5 claim matrix](docs/spec/v0.5-claim-matrix.md)
  (§A per-capability reviewer-facing claims; §B the four-axis deployment-tier
  composition) supersedes the v0.3 matrix, with the NSA/threat-coverage matrix
  derived from §A over one evidence spine.
- **Method-transparency is CI-enforced** (ADR-MCPS-034): a behavioral-equivalence
  test plus a static drift guard in `mcps-conformance`.
- **Audit-evidence vocabulary is derived from the frozen error taxonomy**
  (ADR-MCPS-035), guarded against drift in CI.
- **Proposal-readiness is a dual gate** — mechanical CI **and** owner HITL
  sign-off (ADR-MCPS-036; [security boundary](docs/spec/security-boundary.md) §10).
- A round of feature-gated security fixes (OCSP DNS-rebinding and freshness,
  verify-before-return at the PKCS#11/KMS signer seams, per-method key-reference
  scope, bounded replay-cache growth). See [`CHANGELOG.md`](CHANGELOG.md).

Decisions are recorded in ADR-MCPS-031..036 (all Accepted). The predecessor
**0.4** release wired the v0.3 tiered multi-node profile into enforced backends
(etcd CP replay, revocation tiers, LB-signed ingress assertion), landed the v0.4
audit-remediation cluster, and purified MCP-S Core of the tool-catalog manifest
subsystem (ADR-MCPS-030).

This means the current implementation has demonstrated a complete single-node end-to-end path:

```text
HostSession client
  -> signed MCP-S request
  -> mTLS transport
  -> mcps-proxy
  -> Core signature/freshness/replay verification
  -> delegated authorization
  -> verified-context injection
  -> persistent inner MCP server
  -> signed response
  -> HostSession response verification
```

## Deployment profiles

`mcps-proxy` is one binary. The cargo features you compile it with determine
which controls are available — do not conflate the lean default with the
production high-assurance profile.

### Lean default (no cargo features)

- Minimal runtime closure (ADR-MCPS-018): no Redis, no PKCS#11, no online-OCSP
  dependency is linked in.
- Intended for local, dev, and minimal single-node deployments.
- Shared replay protection, HSM/KMS key custody, and online OCSP revocation are
  **unavailable** in this build: selecting `--replay-cache shared` or a PKCS#11
  key source fails closed at startup rather than degrading.

Build with:

```sh
cargo build --release -p mcps-proxy
```

### High-assurance profile (`--features pkcs11_keysource,redis_replay,online_ocsp`)

Enables the three high-assurance backends:

- **distributed replay protection** via a shared atomic Redis ReplayCache
  (`redis_replay`);
- **HSM/KMS-backed key custody** via a PKCS#11 key source (`pkcs11_keysource`);
- **online certificate revocation** via OCSP (`online_ocsp`), alongside the
  offline CRL path available in both flavors.

Build with:

```sh
cargo build --release -p mcps-proxy \
    --features pkcs11_keysource,redis_replay,online_ocsp
```

**Multi-node MCP-S deployments MUST use the high-assurance profile** with
`--replay-cache shared --replay-redis-url redis://...` so all proxy nodes share
replay state. A per-node cache (the lean default) does not prevent cross-node
replays.

## What MCP-S does not yet claim

The current implementation does not claim:

- official MCP extension status;
- reverse-proxy mTLS integration in the lean default (it is available via the
  forwarded-identity path, but enterprise ingress hardening is delivered through
  the high-assurance feature profile);
- offline-hermetic or air-gapped build reproducibility (the cold-clone gate is
  "no-submodule, lockfile-reproducible with network access to crates.io", not
  offline-hermetic).

Horizontal-scale replay protection, HSM/KMS-backed key custody, full CRL/OCSP
certificate revocation, OS-level sandboxing of wrapped servers, and signed
tool-manifest enforcement are gated on the
`pkcs11_keysource,redis_replay,online_ocsp` cargo features (see Deployment
profiles); they are **not** linked into the lean default build and must not be
implied for it.

## Extension identifier

During incubation, MCP-S should use a controlled third-party identifier, for example:

```text
se.syncom/mcps
```

Do not use:

```text
io.modelcontextprotocol/...
```

unless MCP-S is accepted through the official MCP extension process.

## Build and test

The workspace builds with either Cargo or Bazel. Cargo is the public-facing
default; Bazel is the hermetic build path the maintainer uses internally and
both `Cargo.toml` and `BUILD.bazel` files are committed for every crate.

### Cargo (recommended for OSS contributors)

```sh
# Compile the whole workspace (libs + bins).
cargo build --workspace --bins

# Run the full test suite. The first step is required because Cargo does not
# auto-build cross-crate binaries for integration tests; the bins must exist on
# disk before the multi-process tests spawn them. With the bins in place, the
# suite is fully green:
#
#     test result: ok. 678 passed; 0 failed; 1 ignored
cargo test --workspace
```

The 1 ignored test (`write_fixtures` in `mcps-core/tests/vectors_test.rs`) is
a deliberately `#[ignore]`-gated developer-only fixture writer, not a skipped
production test.

### Bazel

```sh
bazel test //...
```

## Repository layout

```text
README.md                  This file.
CHANGELOG.md               Release notes (Keep a Changelog format).
CONTRIBUTING.md            Contribution + licensing-of-contributions terms.
SECURITY.md                Vulnerability-reporting process.
THIRD_PARTY.md             Third-party-component policy.
LICENSE                    Apache-2.0.
NOTICE.md                  Required Apache-2.0 attributions.
Cargo.toml                 Workspace manifest.
MODULE.bazel               Bazel module definition.

mcps-core/                 Pure verification crate (no networking/async/fs).
mcps-host/                 Client-side ambassador (signing + bound verify).
mcps-transport/            Verifying mTLS client.
mcps-proxy/                Server-side sidecar (TLS termination, OCSP, sandbox, Redis/PKCS#11).
mcps-policy/               Delegated-authorization profiles (Phase 5).
mcps-conformance/          Black-box conformance harness.
mcps-demo/                 Single-node demo harness.
mcps-demo-server/          Long-lived stdio MCP server (demo target).
mcps-demo-fileserver/      Minimal stdio MCP server (demo target).
mcps-test-paths/           Test-only: resolve binaries + fixtures under Bazel OR Cargo.

docs/adr/                  Architecture decision records (ADR-MCPS-001..036).
docs/spec/                 Spec briefs (core spec, security boundary, claim matrix, proposal scope).
docs/security/             Multi-agent audit reports + per-finding remediation log + cross-round ledger.
docs/LICENSING.md          Per-file licensing notes.
docs/PROJECT_STATUS.md     Current stage and what "experimental" means here.
docs/SECURITY_BOUNDARY.md  What MCP-S protects (and what it explicitly does not).
docs/UPSTREAM_PROPOSAL_PROCESS.md  Path from third-party extension to an MCP SEP.
docs/RELEASE_CHECKLIST.md  Steps run before tagging a release.
docs/*-guide.md            Operator runbooks (sidecar, host, transport, conformance, dogfood).
```

## For security reviewers

If you are evaluating MCP-S, read these in order — they route through the same
materials the [upstream-proposal package](docs/UPSTREAM_PROPOSAL_PROCESS.md)
requires (motivation/threat model, security boundary, envelope and signature
rules, replay/freshness model, authorization profile, transport hardening,
conformance, reference implementation, demos, and non-goals):

1. **One page** — [`docs/MCP-S-IN-ONE-PAGE.md`](docs/MCP-S-IN-ONE-PAGE.md):
   what it is, the threat, where it sits, what v0.5.1 proves, what it does not claim.
2. **Security boundary** — [`docs/spec/security-boundary.md`](docs/spec/security-boundary.md):
   what MCP-S protects and what it explicitly does not.
3. **v0.5 claim matrix** — [`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md):
   every reviewer-facing claim, each traceable to a green test.
4. **GCP KMS validation** — [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md)
   (front door) and [`docs/security/google-validation-plan.md`](docs/security/google-validation-plan.md)
   (full plan): the live enterprise key-custody proof.
5. **Conformance guide** — [`docs/conformance-guide.md`](docs/conformance-guide.md):
   the black-box conformance harness and vectors.
6. **EMA composition** — [`docs/spec/ema-composition.md`](docs/spec/ema-composition.md):
   how MCP-S would compose with Enterprise-Managed Authorization (a **proposed**
   design note — EMA is not implemented or demoed in v0.5.1).
7. **Run it** — [`docs/quickstart-local.md`](docs/quickstart-local.md): the
   local fail-closed demo (`./scripts/demo-local.sh`), no cloud credentials.

## Documentation index

- **One-page overview:** [`docs/MCP-S-IN-ONE-PAGE.md`](docs/MCP-S-IN-ONE-PAGE.md) —
  what MCP-S is, the threat it addresses, where it sits relative to EMA/OAuth, and
  what v0.5.1 proves.
- **Quickstarts:** [`docs/quickstart-local.md`](docs/quickstart-local.md)
  (local fail-closed demo, no cloud) and
  [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md) (live GCP Cloud KMS).
- **Releases:** [`CHANGELOG.md`](CHANGELOG.md).
- **Architecture decisions:** [`docs/adr/`](docs/adr/) — start with
  [ADR-MCPS-001](docs/adr/adr-mcps-001.md) (trust model) and
  [ADR-MCPS-011](docs/adr/adr-mcps-011.md) (core firewall).
- **Specification briefs:** [`docs/spec/`](docs/spec/) — the core spec, the
  [security boundary](docs/SECURITY_BOUNDARY.md), and the upstream-proposal
  brief intended for an eventual MCP SEP submission.
- **Security:** [`docs/security/`](docs/security/) — multi-agent
  Claude Opus 4.8 audits (v0.1 and v0.2), the per-finding remediation log for
  v0.2.0, and the cross-round [finding ledger](docs/security/finding-ledger.jsonl).
  Vulnerability reporting: [`SECURITY.md`](SECURITY.md).
- **Operator guides:** [`docs/sidecar-deployment-guide.md`](docs/sidecar-deployment-guide.md),
  [`docs/host-integration-guide.md`](docs/host-integration-guide.md),
  [`docs/transport-hardening-guide.md`](docs/transport-hardening-guide.md),
  [`docs/conformance-guide.md`](docs/conformance-guide.md),
  [`docs/dogfood-runbook.md`](docs/dogfood-runbook.md).
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Unless otherwise stated, all files in this repository are licensed under the
Apache License, Version 2.0. See [`LICENSE`](LICENSE), [`NOTICE.md`](NOTICE.md),
and [`docs/LICENSING.md`](docs/LICENSING.md).

## Disclaimer

MCP-S is an independent experimental proposal. It is not endorsed by the MCP project, Anthropic, or any MCP maintainer unless explicitly accepted through the relevant public governance process.
