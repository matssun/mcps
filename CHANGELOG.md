<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to MCP-S are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0 the public surface is explicitly unstable: minor versions may break API
or wire-format compatibility while the design lines from
[`docs/adr/`](docs/adr/) settle.

## [0.8.0] — 2026-07-02

**Stateless multi-round-trip continuation + the TypeScript SDK.** v0.8 folds
request-associated elicitation into strict MCP-S as signed multi-round-trip (MRT)
continuation evidence (ADR [047](docs/adr/adr-mcps-047.md)), and ships a second
client SDK — TypeScript — bound to the SAME audited `mcps-client-core` as the Python
SDK and the proxy. Built on top of the released v0.7.0.

### Added in v0.8

- **Stateless MRT continuation evidence** (`mcps-core` / `mcps-client-core` /
  `mcps-client-proxy`). A signed `InputRequiredResult` is verified as an ordinary
  server response and classified non-terminal; the client answers with a fresh signed
  continuation request bound to it (`previous_request_hash` +
  `input_required_response_hash`), verified server-side by the ordinary draft-02
  request path (the continuation object rides inside the signed preimage — no bespoke
  proxy code). Non-terminal correlation is associate-without-consume; the client proxy
  drives the elicitation → continuation round trip transparently. Shared conformance
  vectors **d12–d15**.
- **TypeScript SDK** (`sdk/typescript`, NEW). A `napi-rs` binding to the audited
  `mcps-client-core` — the exact analog of the Python PyO3 binding, so the canonical
  signed preimage is byte-identical across every SDK and the proxy by construction.
  Transport adapters (stdio + one-POST-per-request mTLS), authorization-binding
  providers, non-exporting (KMS/HSM) custody, and MRT continuation. Verified against
  the same independent oracle vectors as the Python SDK.
- **Python SDK** conformance driver gains MRT continuation support (parity with
  TypeScript), so the interchangeable-driver matrix stays a true parity harness.
- **Cross-SDK MRT parity matrix.** A safe, deterministic `delete_files` elicitation
  tool on `mcps-demo-fileserver` (a dry-run that carries its pending state in the
  opaque `requestState`) drives the elicitation → continuation SECURITY SHAPE end to
  end through the real four-hop across the **Rust reference, Python, and TypeScript**
  drivers.

### Not in v0.8 (gaps / deferred)

- **Arbitrary server push stays out of strict MCP-S** and fails closed under
  `require_mcps` (ADR-047 / D9); `allow_unverified_server_initiated` remains a
  degraded migration opt-out only, audited as no-evidence.
- **ADR-MCPS-044 (Client-Side Integration Model) stays Proposed.** Both SDKs realize
  it, but its full scope is not yet claimed complete — not overclaiming.
- **ADR-MCPS-046 (Signed Rejection Receipts) stays deferred / design-only.**
- **TypeScript SDK live cross-process mTLS e2es are not yet written.** The driver
  matrix already exercises the TS SDK through the real four-hop; dedicated mTLS e2es
  mirroring the Python `test_e2e_*` suite are a follow-up.
- **The TypeScript conformance driver's Cloud KMS path signs via a synchronous
  `curl`** (Node has no native synchronous HTTP, and the napi non-exporting sign
  callback is synchronous); the offline/software path is fully in-process.

## [0.7.0] — 2026-07-02

**End-to-end walkthrough — the v0.7 persona ladder.** v0.7 closes the
"prove v0.7 end-to-end" gap with a real, multi-process MCP-S path: an ordinary
plain-MCP client → `mcps-client-proxy-cli` (signs draft-02, dials mTLS) →
`mcps-proxy` server PEP (verifies draft-02, strips, injects verified context,
serves) → an unmodified inner MCP server, organized as a persona ladder of
runnable tiers (ADR [045](docs/adr/adr-mcps-045.md)).

### Proven in v0.7

- **The real four-hop MCP-S path, offline.** T0/T1/T3 run the full topology as
  separate OS processes over mTLS-on-loopback (`mcps-walkthrough`); the server PEP
  now verifies AND serves draft-02 end to end (version-branched forward +
  protected response; draft-01 path untouched).
- **Scoped authorization, deny-before-dispatch.** A reader's `write_file` is
  refused with `authorization_scope_denied` before the inner server is ever
  reached (T2; the inner's own received-log confirms it across processes at T3).
- **Transport-identity binding (T3).** `--transport-binding exact` ties the
  verified mTLS client identity to the request signer; a mismatched identity is
  denied before dispatch (proven by the inner's own append-only log + zero inner
  spawns), while the same cert passes with binding off — isolating the binding as
  the cause.
- **Client Cloud KMS signer (offline + ignored live lane).** A non-exporting
  `KmsClientSigner` (feature `gcp_kms`) signs through GCP Cloud KMS
  (`EC_SIGN_ED25519`, no algorithm substitution); proven OFFLINE against the
  unmodified `mcps-core` verifier via a no-network fake backend, plus an
  `#[ignore]` live lane.
- **Server Cloud KMS support (existing live lane).** `mcps-proxy --key-source
  GcpKms` continues to sign responses from a non-exporting Cloud KMS key
  (feature `gcp_kms_keysource`, live lanes).
- **Integrated Cloud KMS four-hop — Tier T4 (live, #218).** A single live run
  with the client request signer AND the server response signer BOTH non-exporting
  in Cloud KMS (two distinct keys), over the real mTLS socket. The walkthrough
  harness (`FourHop::launch_kms`, feature `gcp_kms`) fetches both KMS public keys
  to wire trust and drives a signed round-trip end to end; `#[ignore]`d, run from
  the cloud script (command 5). PROVEN against a real Cloud KMS project.
- **Secret-hygiene guard.** A tracked-file leak guard
  (`mcps-walkthrough` `no_tracked_secrets`) asserts no real account/project
  identifier is committed; the live-cloud script stays gitignored behind a
  sanitized committed placeholder.
- **Python SDK — request-side slice (#199).** `mcps-python-sdk` gains request
  signing + custody/signer-policy binding (request side only;
  ADR [044](docs/adr/adr-mcps-044.md)).
- **Multi-SDK test architecture — pluggable client leg.** The four-hop harness's
  client leg is a `ClientDriver` seam: every MCP-S SDK is an interchangeable client
  behind one stdio + CLI contract (`mcps-client-proxy-cli` is the reference), and
  the `sdk_driver_matrix` runs the tiers against each configured driver (skip-not-
  fail). Ready for the upcoming TypeScript/Rust SDKs (`MCPS_DRIVER_*`).
- **Python SDK — live four-hop interop, software AND Cloud KMS.** `mcps_sdk.driver`
  makes the Python SDK a live client leg: it signs via the SDK's audited core, mTLS-
  POSTs to the real `mcps-proxy`, and verifies the server-signed response. Proven
  green in the matrix; and with `--key-source gcp-kms` the Python client signs every
  request with a NON-EXPORTING Cloud KMS key (`Signer.non_exporting` → `asymmetric
  Sign`) across the integrated four-hop (`t4_python_kms_custody`, live, #[ignore]).
  Both the happy path AND the untrusted-server negative are proven cross-language
  through the four-hop: every driver must fail closed when it cannot verify the
  server's response. Surfaced (and fixed) a real cross-language cert defect: the demo
  TLS leaves lacked an Authority Key Identifier — tolerated by rustls, rejected by
  OpenSSL (Python).

### NOT yet claimed in v0.7

- **Signed rejection reasons across the wire.** A client that fails closed cannot
  yet surface the remote's specific reason (e.g. `transport_binding_failed`) — it
  rides an unsigned error body the client rightly distrusts. The fix (signed
  rejection receipts) is designed, not built: ADR
  [046](docs/adr/adr-mcps-046.md).

### Build & test

The **Cargo** workspace is the authoritative, maintained test gate and is fully
green (1104 tests across the workspace, 0 failures). The Cloud KMS lanes and the
live cross-language KMS four-hop are intentionally `#[ignore]`/manual (they require
live cloud credentials). The **Bazel** build has
known, pre-existing **non-gating** `BUILD`-file parity rot — unrelated to this
release — e.g. `//mcps-proxy:mcps_proxy_cli` missing a `//mcps-core:mcps_core`
dep (present already before this epic) and `pkcs11` test-dep gaps; tracked
separately and NOT mixed into this line.

## [0.6.0] — 2026-06-30

**Runtime-evidence preimages — a `draft-02` wire-envelope change.** v0.6
introduces the `draft-02` profile alongside the released `draft-01`/v0.5.1
baseline: two protected envelope identifiers (`version: "draft-02"` and a
self-describing `canonicalization_id`), an explicit canonical-preimage exclusion
predicate, a typed `authorization_binding` object (both `opaque-bytes` and
`authz-system-reference` base forms), nine new fail-closed wire codes, a dual
verifier with strict version dispatch and a required expected-version policy, and
a separate frozen conformance corpus with a static interop oracle.
`draft-01`/v0.5.1 stays byte-for-byte and verdict-for-verdict unchanged.
Resolved in the v0.6 grill (2026-06-29);
ADRs [037](docs/adr/adr-mcps-037.md)–[042](docs/adr/adr-mcps-042.md).

**Scope.** v0.6 ships the draft-02 profile, verifier, authorization-binding
policy wiring, and conformance corpus (including a live Cloud KMS draft-02
envelope lane). The `mcps-host`/`mcps-proxy` production paths still emit and
serve `draft-01`; adopting the draft-02 signing/serving path end-to-end is a
follow-up. The dual verifier exists so both profiles coexist at the verification
boundary during that migration.

### Documented limitation — integer-only canonicalization (`mcps-jcs-int53-json-v1`)

The first `draft-02` canonicalization scheme keeps the integer-only JSON number
domain (±(2^53 − 1)), named `mcps-jcs-int53-json-v1`. **MCP-S v0.6 does NOT
protect a signed payload that contains JSON fractional numbers** —
`{"temperature":0.7}`, `{"price":19.99}`, a latitude — such messages fail closed
with `mcps.canonicalization_failed` unless the value is carried as a string. This
is an intentional, named, machine-checked scope boundary (a required honesty
conformance vector proves `0.7`/`19.99` are rejected), not a defect: full
RFC 8785 fractional-number serialization is the highest-risk cross-implementation
interop surface and is **deferred to a future, separately-named, separately-
vector-hardened `mcps-jcs-…-v2` scheme** admitted through the canonicalization
allowlist — never by widening v1 ([ADR-MCPS-037](docs/adr/adr-mcps-037.md)).

## [0.5.1] — 2026-06-24

**Live Google Cloud KMS validation release.** No wire-envelope changes: this
release proves the already-shipped GCP Cloud KMS adapter against **real** Cloud
KMS and adds a one-command reproduction harness. It is evidence and test surface,
not new protocol mechanism (see
[`docs/security/google-validation-plan.md`](docs/security/google-validation-plan.md)).
The `draft-01` request/response envelopes are unchanged.

### Added

- **Live GCP delegated-TLS test lane**
  (`mcps-proxy/tests/gcp_kms_delegated_tls_live_test.rs`). Proves the proxy's TLS
  *server* private key can live entirely in Cloud KMS and never leave it: the
  server leaf is minted over the KMS **public** key (rcgen `RemoteKeyPair`, no
  private key), and a fully-validating rustls mTLS handshake completes only
  because a live `asymmetricSign` produced the `CertificateVerify`. Negative
  lanes: a leaf not bound to the KMS key is rejected at config construction
  (`DelegatedKeyMismatch`), and an untrusted client certificate is rejected at the
  handshake (fail closed).
- **Object-signing negative lanes** in `gcp_kms_live_test.rs`: wrong-identity (a
  signature must not verify under a foreign key), bad-token fail-closed (an
  invalid access token must fail backend construction), and non-Ed25519 rejection
  (a provisioned RSA key version is rejected at construction, variant-matched).
- **One-command reproduction harness**
  (`docs/security/gcloud-kms-validation.sh`): sanitized, no secrets, `PROJECT_ID`
  placeholder-guarded; enables the KMS API, idempotently provisions the keys, and
  runs both live lanes.
- **First-time Google Cloud onboarding** in the validation plan ("Reproducing
  Stage 1 locally"): the account, billing, project, and `gcloud auth` steps a
  brand-new user needs before running the harness.

## [0.5.0] — 2026-06-23

**Proposal-readiness release over the frozen `draft-01` wire envelope.** 0.5 adds
**zero** wire-envelope fields; request and response envelopes are unchanged. The
work is documentation, conformance, and claim hardening — making every security
claim reviewable and traceable to a green test — not new protocol mechanism. Any
claim `draft-01` cannot support is ejected to a future `draft-02` ADR rather than
smuggled in as a field addition (ADR-MCPS-031, [`docs/spec/proposal-scope.md`](docs/spec/proposal-scope.md)).
Proposal-readiness is gated twice: mechanical CI **and** owner HITL sign-off over
one evidence spine (ADR-MCPS-036; [`security-boundary.md`](docs/spec/security-boundary.md) §10).

### Added — proposal-readiness artifacts

- **ADR-MCPS-031..036 (Accepted).** 031 frames 0.5 as proposal-readiness over a
  frozen `draft-01`; 032 consolidates docs to one canonical boundary + docs root;
  033 defines the two-section v0.5 claim matrix (NSA/threat-coverage matrix
  derived from §A, one evidence spine); 034 makes method-transparency
  CI-enforced; 035 derives the audit-evidence vocabulary from the frozen error
  taxonomy; 036 defines the dual proposal-readiness gate (mechanical CI + owner
  HITL).
- **v0.5 claim matrix** ([`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md),
  supersedes the v0.3 matrix): §A per-capability reviewer-facing claims, §B the
  four-axis deployment-tier composition (AND of declared tiers, bounded by the
  weakest).
- **New spec briefs:** [`proposal-scope.md`](docs/spec/proposal-scope.md) (draft-01
  freeze + bind-not-interpret authorization), [`composability.md`](docs/spec/composability.md),
  [`threat-coverage-matrix.md`](docs/spec/threat-coverage-matrix.md); glossary and
  v0.5 grilling seed.
- **Method-transparency is CI-enforced (ADR-MCPS-034):** a behavioral-equivalence
  test plus a static drift guard in `mcps-conformance` (`method_transparency_test`,
  `method_name_drift_guard_test`, `security_traceability_guard_test`,
  `forbidden_claim_guard_test`, `audit_vocabulary_guard_test`).

### Security

- **OCSP DNS-rebinding fix (#128).** The OCSP fetch is pinned to the vetted
  resolved IPs, closing a rebinding window between resolution and connection.
- **OCSP freshness when `nextUpdate` is absent (#136).** Acceptance age is bounded
  by `thisUpdate` + a `max_age` cap instead of being accepted unbounded.
- **Verify-before-return at the remote-signer seams (#137, #138).** PKCS#11 and
  KMS response signing now verify the produced signature before returning it,
  centralized at the response-signer seam.
- **Per-method key-reference scope (#133).** A key reference scopes its target
  per-method; empty-tool grants are rejected.
- **LB-assertion fails closed without a transport binding (#135).** A wired
  load-balancer ingress assertion with no transport binding now fails closed
  rather than admitting.
- **Replay-cache growth bounded (#140).** The file and in-memory replay paths are
  growth-bounded, and durable inline-prune is anchored on a real clock rather than
  request expiry.
- **Non-positive-TTL replay rejected pre-store (MCPS-08, #142).** Requests with a
  non-positive TTL are rejected before the store write, on the etcd backend too.

### Note

Internal version (`VERSION`, workspace `Cargo.toml`) advances from 0.3.1 to 0.5.0.
0.4.0 (below) was tagged retroactively from the hardening-epic history; it carried
no separate release commit, so the source tree at the v0.4.0 tag still declares
0.3.1.

## [0.4.0] — 2026-06-22

**Hardening-epic release (#68).** 0.4 wires the v0.3 tiered multi-node profile from
declared tiers into enforced backends, lands the full audit-remediation cluster
from the v0.4 Stage 1–2 audit round, and purifies MCP-S Core. *Tagged
retroactively* at the first-parent tip of the epic (`09f3250`, just before the 0.5
proposal-readiness work) — the tag was created after the fact, so no release commit
bumps `VERSION`/`Cargo.toml` at this point in history.

### Added — four-axis multi-node profile, wired

- **Axis 1 — LINEARIZABLE CP replay backend (#69).** An etcd-backed CPStore
  replay backend, the concrete realization of the v0.3 `LINEARIZABLE` tier.
- **Axis 2 — near-zero revocation tiers (#70).** Live + push revocation tiers
  wired into the trust resolver, with an injective trust-cache key.
- **Axis 4 — Tier-3 LB-signed ingress assertion (#71).** A request-bound,
  load-balancer-signed ingress assertion, wired into the serve path with
  serve-level acceptance.

### Security & hardening — v0.4 audit remediation

- **Seccomp egress (#98).** `io_uring` egress is denied in the `DenyAll` seccomp
  posture.
- **Production-surface sealing (#81, #83).** Test nonce/clock fixtures are
  feature-gated off the production surface; `VerifiedResult`/`VerifiedResponse`
  are sealed against out-of-band construction.
- **Strict-mode replay durability (#78, #90).** Replay caches self-declare a
  type-level durability class; strict mode rejects a non-durable in-memory cache
  and forbids `inherit-env` together with an env key source.
- **Reference-authz acknowledge gate + epoch-clock diagnosis (#94).**
- **Signed-manifest canonicalization & identity (#85, #87).** Duplicate keys in
  signed manifest bytes are rejected, `key_id` is cross-checked, the validity
  window is skew-tolerant, and inverted windows / unknown wire members are
  rejected.
- **Server read-path deadline (#100).** An aggregate wall-clock deadline on the
  server read path closes a slow-loris exposure.
- **Redis handshake watchdog (#97).** Abandoned Redis connect-handshake watchdog
  threads are bounded.
- **Working-dir TOCTOU (#93).** An explicit `--inner-working-dir` is hardened
  against symlink/TOCTOU with an explicit `O_RDONLY` no-follow open.
- **Key custody (#76).** The unused `Clone` on `SigningKey` is dropped and the
  custody boundary documented.
- **OCSP SSRF guards (#130).** Redirect-follow and empty-label-host SSRF bypasses
  on the OCSP fetch path are closed.
- **Centralized Ed25519 alg gate (#131).** The Ed25519 envelope algorithm gate is
  centralized in Core.

### Changed — Core purification (ADR-MCPS-030)

- The tool-catalog **signed-manifest subsystem is removed from MCP-S Core**; the
  manifest-enforcement design (formerly ADR-MCPS-029) is relocated to MTCI. Core
  is once again pure verification.

### Added — security process

- **Cross-round finding ledger** ([`docs/security/finding-ledger.jsonl`](docs/security/finding-ledger.jsonl)):
  durable per-finding disposition memory so a later audit round verifies only what
  is genuinely new and flags regressions loudly.

## [0.3.1] — 2026-06-21

Security-hardening patch release. No API or wire-format change relative to
0.3.0 — every change is a defensive fix or documentation correction surfaced by
the **Stage 1–2 security-audit funnel** (deterministic pre-scan + 3-lens review,
without the verify gate). Findings were triaged file-by-file: 10 fixed with
regression tests, 3 closed as false positives, and the remaining cluster
deferred to the v0.4 hardening epic (#68) as intentional ADR-MCPS-017
single-node-ceiling posture. The full verified (3-skeptic) scan is scheduled for
v0.4.

### Security

- **OCSP delegated-responder validity window (#95, RFC 6960).** A delegated
  responder certificate presented outside its `notBefore`/`notAfter` window is
  now rejected instead of trusted.
- **Authorization-grant timestamp taxonomy (#88).** An unparseable RFC 3339
  expiry on a delegated grant now fails as `AuthorizationMalformed` rather than
  being misclassified as `AuthorizationExpired`.
- **JCS duplicate-key invariant (#74).** A hand-built `JcsValue::Object`
  containing duplicate keys now fails closed (`CanonicalizationFailed`) rather
  than producing an ambiguous canonical form.
- **Injective trust-resolver composite key (#79).** `InMemoryTrustResolver`
  composes its lookup key with a length-prefixed encoding, removing a
  delimiter-collision class across `(signer, key_id)` pairs.
- **Bounded KMS response reads (#89, #92).** The AWS-KMS response body is read
  under an explicit byte cap (reject only when the length exceeds the cap), and
  GCP-KMS token-expiry arithmetic saturates on overflow instead of panicking.

### Fixed

- **Freshness-window overflow (#82).** Freshness-window expiry uses
  `checked_add`, failing closed instead of panicking on `i64` overflow.
- **Replay prune boundary (#91).** Durable-replay pruning is now inclusive at
  `retain_until` (`>=`), matching the in-memory store and removing a one-tick
  off-by-one retention gap.
- **Response taxonomy precision (#77).** `verify_response` rejects batch and
  notification shapes *before* canonicalization, restoring symmetry with
  `verify_request`.

### Documentation

- Corrected a stale `shared_replay` module doc and documented the
  `sandbox_linux` `try_clone` async-signal-safety caveat (#99, #98).

## [0.3.0] — 2026-06-16

This release adds the **tiered multi-node profile within one trust domain**
(epic #7). v0.2 was production-hardened for single-node deployments; v0.3
makes a *bounded, honest* multi-node claim: each of four security axes declares
a tier, and the composed claim is the **conjunction of the four declared tiers,
bounded by the weakest**. The proxy can never surface a claim stronger than its
configured tier. The enforcement artifacts are
[`docs/spec/v0.3-claim-matrix.md`](docs/spec/v0.3-claim-matrix.md),
[`docs/spec/v0.3-claim-boundary.md`](docs/spec/v0.3-claim-boundary.md), and
[`docs/spec/security-boundary.md`](docs/spec/security-boundary.md), backed by
the conformance manifest and `mcps-conformance` drift guard.

### Added — tiered multi-node claim matrix (the four axes)

- **Axis 1 — replay-store durability (ADR-MCPS-020).** Tiers `REDIS_ASYNC`,
  `REDIS_WAIT_QUORUM`, `LINEARIZABLE` (named; CP backend deferred), and
  `SINGLE_STORE_FAIL_CLOSED`, each surfacing its own honest guarantee.
  Strict-production deployments must declare `REDIS_WAIT_QUORUM` or stronger.
- **Axis 2 — trust propagation / revocation window `T` (ADR-MCPS-021).**
  Bounded-cache eventual trust: revocation enforced fleet-wide within `T`
  (default 60s), fail-closed on store outage past `T`. Zero-window revocation
  is a forbidden claim in v0.3.
- **Axis 3 — signing-key custody (ADR-MCPS-022 / ADR-MCPS-028).**
  `per_node_keyset` (default; tight blast radius) or `shared_remote_signer`
  (one non-exporting KMS/HSM identity). Copying a private key across nodes is
  normatively forbidden in every mode.
- **Axis 4 — ingress / transport binding (ADR-MCPS-023).** `end_to_end_mtls`
  (peer bound to the request signer end-to-end) or `trusted_ingress_asserted`
  (explicitly weakened; ingress in the TCB, authenticated LB↔node hop).

### Added — native cloud-KMS + delegated TLS key custody (ADR-MCPS-028 §B–§G)

- **Native cloud-KMS Ed25519 response signers** — AWS KMS
  (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType=RAW`) and GCP Cloud
  KMS (`EC_SIGN_ED25519`), each over a blocking, hand-audited transport
  (SigV4 / OAuth2 + `ureq`), **not** the async vendor SDKs — the ADR-MCPS-018
  lean-sync firewall is preserved. The private key never leaves the KMS.
- **Delegated TLS-server-key custody (§G)** — the TLS server key can also stay
  non-exporting, via the `RawEd25519TlsSigner` seam and a delegated rustls
  certificate resolver, wired across PKCS#11, AWS KMS, and GCP KMS backends.
  Cross-cutting invariants enforced fail-closed: Ed25519-only, cert↔signer
  public-key match at config construction, a TLS credential distinct from the
  object-signing key, and delegated-XOR-exported mutual exclusion.
- **Cloud-KMS live CI lanes** — nightly-real-only (no faithful Ed25519 KMS
  emulator exists), secret-gated and non-blocking, with an anti-gaming hard
  fail; the load-bearing proof is `mcps-core` verifying the signature over the
  exact canonical preimage, never the provider's own `Verify`.

### Added — MCP SEP composition and trust hygiene

- **Replay safety under MCP multi round-trip requests (ADR-MCPS-024, SEP-2322).**
- **Untrusted transport routing headers (ADR-MCPS-025, SEP-2243)** — `Mcp-Method`
  / `Mcp-Name` never assert identity and never influence a security decision, in
  every ingress mode.
- **Signing scope vs. stateless per-request `_meta` (ADR-MCPS-026, SEP-2575).**
- **Extension-identifier reassignment to `se.syncom/mcps` (ADR-MCPS-027).**

### Known limitations — forbidden claims (tracked for v0.4, epic #68)

The composed claim licenses none of the following; each is a deferred tier
named in its ADR and tracked as v0.4 axis-hardening:

- Linearizable / unconditional replay safety (Axis 1 — needs the `CPStore`
  backend).
- Zero-window / instantaneous revocation (Axis 2 — needs live or push tiers).
- Smaller-than-per-node blast radius for a shared signer (Axis 3).
- End-to-end binding under `trusted_ingress_asserted` (Axis 4 — needs the
  LB-signed, request-bound Tier 3 assertion).
- Multi-tenant isolation between distrusting operators, and a hostile-shared-store
  threat model, both remain explicitly excluded from v0.3.

### Build

- Workspace version bumped to `0.3.0` across all crates. Cargo + Bazel still
  coexist; every crate carries both a `Cargo.toml` and a `BUILD.bazel`.

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

[0.3.1]: https://github.com/matssun/mcps/releases/tag/v0.3.1
[0.3.0]: https://github.com/matssun/mcps/releases/tag/v0.3.0
[0.2.0]: https://github.com/matssun/mcps/releases/tag/v0.2.0
[0.1.0]: https://github.com/matssun/mcps/releases/tag/v0.1.0
