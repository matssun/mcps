<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to MCP-S are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0 the public surface is explicitly unstable: minor versions may break API
or wire-format compatibility while the design lines from
[`docs/adr/`](docs/adr/) settle.

## [0.2.0] — 2026-06-05

This is the **initial public release** of MCP-S. v0.1 existed only inside the
authoring monorepo and was never published as source; it is captured here for
historical accuracy because both the architecture and the security review
process span it.

### Public-release scope

- Apache-2.0 licensed Rust workspace, ten crates:
  `mcps-core` (pure verification), `mcps-host` (client-side ambassador),
  `mcps-transport` (verifying mTLS client), `mcps-proxy` (server-side sidecar
  with TLS termination, OCSP, sandbox, Redis replay, PKCS#11 key sources),
  `mcps-policy` (delegated-authorization profiles, Phase 5),
  `mcps-conformance` (black-box conformance harness), three demo crates
  (`mcps-demo`, `mcps-demo-server`, `mcps-demo-fileserver`), and the test-only
  `mcps-test-paths` helper that lets the same integration tests run under
  Bazel runfiles OR a plain Cargo build.
- 19 architecture-decision records under [`docs/adr/`](docs/adr/) covering the
  trust model, core invariants, transport layering, authorization profile
  abstraction, and Phase 7 external backends.
- Specification briefs under [`docs/spec/`](docs/spec/) including the core
  spec, security boundary, and the upstream-proposal brief intended for an
  eventual MCP SEP submission.
- Two multi-agent Claude Opus 4.8 security audits and a per-finding
  remediation log under [`docs/security/`](docs/security/).

### Added — Phase 6 transport hardening

- **mTLS transport (`mcps-transport`)** — a blocking rustls client that
  presents a client certificate AND verifies the proxy's server certificate +
  identity against a configured server CA, including
  per-socket DoS hardening (read/write timeouts) and an aggregate
  response-read deadline that bounds slow-trickle peers
  (ADR-MCPS-015, [`mcps-transport/src/lib.rs`](mcps-transport/src/lib.rs)).
- **Server-side mTLS termination + identity verification** in `mcps-proxy`
  with configurable identity policies (SAN URI / SAN DNS / CN-legacy),
  exact transport-binding enforcement, and short-lived-cert posture
  (ADR-MCPS-014).

### Added — Phase 5 delegated authorization

- **`AuthorizationProfile` abstraction** with the Reference Signed
  Authorization Profile as the first implementation; policy evaluator runs
  AFTER core verification and BEFORE dispatch
  (ADR-MCPS-013, [`mcps-policy/src/`](mcps-policy/src/)).
- **Per-profile conformance vectors** under
  [`mcps-policy/tests/vectors/`](mcps-policy/tests/vectors/) covering every
  documented allow / deny code (12-token coverage).

### Added — Phase 7 external backends (feature-gated, off by default)

- **`pkcs11_keysource`** — vendor-neutral PKCS#11 backend for the
  response-signing key; key material never leaves the token.
- **`redis_replay`** — Redis-backed shared atomic replay cache for
  horizontally-scaled deployments, with bounded connection/read/write timeouts
  and TTL aligned to clock skew.
- **`online_ocsp`** — RFC 6960 §3.2 OCSP client-cert revocation, including
  full responder-signature trust chain
  (signature + responder identity + CertID binding + freshness + nonce).
- **Linux sandbox enforcement** (Landlock fs allowlists + seccomp egress
  filter), fail-closed on platforms without a kernel backend
  (ADR-MCPS-016 / ADR-MCPS-017).

### Security

This release is the product of two independent multi-agent Claude Opus 4.8
audits, totalling **282 agents and ~14.55M tokens** of review across both
rounds. The full audit reports are committed under
[`docs/security/`](docs/security/), alongside a per-finding remediation log.

- **v0.1 audit (2026-06-01)** — 3 High / 14 Medium / 36 Low / 53 Info,
  0 Critical. Overall residual-risk rating at audit time: **MODERATE**.
- **v0.2 audit (2026-06-02)** — 4 Critical / 15 High / 30 Medium / 59 Low /
  254 Info on the hardening branch. Overall residual-risk rating at audit
  time: **HIGH**.
- **Remediation in this release**: all 4 Critical, all 15 High, and 28 of 30
  Medium findings are **Addressed** with regression tests. The remaining 2
  Mediums (M01/M02 in [`docs/security/remediation-v0.2.md`](docs/security/remediation-v0.2.md))
  are **Deferred to v0.3**; their fail-mode is fail-closed and does NOT admit
  unauthorized requests.

Notable cross-cutting fixes folded in:

- OCSP responder verification rebuilt to enforce signature + identity +
  CertID + freshness + nonce per RFC 6960 §3.2; the single OCSP defect
  surfaced by four audit lenses is closed
  ([`mcps-proxy/src/ocsp.rs`](mcps-proxy/src/ocsp.rs)).
- Manifest pin atomicity (audit H-1) — repository now writes the pin file
  atomically via rename
  ([`mcps-policy/src/manifest_verifier.rs`](mcps-policy/src/manifest_verifier.rs)).
- Redis replay backend (audit H-8 / H-9 / H-10) — bounded connect, read, and
  write timeouts so the single-threaded serve loop cannot hang
  ([`mcps-proxy/src/redis_store.rs`](mcps-proxy/src/redis_store.rs)).
- `--strict` / `--production` postures now reject group/world-readable key
  files and disabled client-cert lifetime enforcement
  ([`mcps-proxy/src/main.rs`](mcps-proxy/src/main.rs),
  [`mcps-proxy/src/cli.rs`](mcps-proxy/src/cli.rs)).

### Build

- Cargo and Bazel coexist by design: every crate carries both a `Cargo.toml`
  and a `BUILD.bazel`, and the workspace is buildable with **either**
  toolchain. Cargo is the public-facing default for OSS contributors;
  Bazel remains the hermetic build path the maintainer uses internally.
- A small `mcps-test-paths` dev-dependency lets the same integration tests
  resolve child-process binaries and data fixtures under Bazel runfiles OR
  a plain Cargo build — see
  [`mcps-test-paths/src/lib.rs`](mcps-test-paths/src/lib.rs).

### Known limitations

- Two Medium findings (`M-01`, `M-02`) remain deferred to v0.3; both relate
  to fail-closed correctness gaps that do NOT admit unauthorized requests.
- Sandbox kernel enforcement (Landlock + seccomp) is Linux-only; on
  macOS / Windows / older Linux the proxy fails closed if
  `--inner-sandbox enforce` is requested (ADR-MCPS-017).
- The crate names and wire formats are explicitly unstable until 1.0; the
  ADR set names the surfaces most likely to evolve.

---

## [0.1.0] — 2026-06-01 (unpublished)

v0.1 is the internal pre-public baseline. It is NOT released as a public
crate or source archive; this entry is recorded so the v0.2 changelog,
audit, and remediation documents have an unambiguous predecessor to refer
to. The v0.1 audit report at
[`docs/security/audit-v0.1.md`](docs/security/audit-v0.1.md) captures the
state of the codebase at this point.

### Highlights

- Pure `mcps-core` verification crate with canonicalization, signature
  verification, replay detection, and the verified-context contract.
- `mcps-proxy` server-side sidecar with stdio transport, response signing,
  and verified-context propagation to an unmodified inner MCP server.
- `mcps-host` client-side ambassador for request signing and bound
  response verification.
- Black-box `mcps-conformance` harness (object + stdio targets).
- 18 ADRs covering the trust model, core invariants, and Phase 1-5 design
  decisions.

### Audit summary

- 3 High / 14 Medium / 36 Low / 53 Info, 0 Critical.
- Residual-risk rating at audit time: **MODERATE**.
- Four findings were partial carry-overs into the v0.2 hardening branch;
  all are closed in v0.2.0 per the
  [v0.2 remediation log](docs/security/remediation-v0.2.md).

[0.2.0]: https://github.com/matssun/mcps/releases/tag/v0.2.0
[0.1.0]: https://github.com/matssun/mcps/releases/tag/v0.1.0
