<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S in one page

*An experimental third-party security extension proposal for the Model Context
Protocol (MCP). Not an official MCP extension unless accepted through the MCP
governance and SEP process.*

## What is MCP-S?

MCP-S is a reference implementation and conformance package that protects
**individual MCP tool calls** — not the session, not the transport alone, but the
call itself. Every request and response carries an object-level Ed25519
signature, and a Rust-native sidecar (`mcps-proxy`) verifies that signature plus
freshness, replay state, and delegated authorization *before* the call ever
reaches the inner MCP server. The response is signed and bound back to the
request hash, so the host can prove the answer it received belongs to the
question it asked.

It is built to wrap ordinary MCP stdio servers without modifying them: the
sidecar terminates mTLS, verifies, strips any caller-supplied "verified context,"
injects its own sidecar-owned context, and forwards to a long-lived inner
process. Denied requests never reach that process.

## What threat does it address?

An MCP tool call crosses a trust boundary as plain JSON-RPC. On its own that
leaves it open to:

- **Forgery** — an attacker fabricates a tool call the host never authorized.
- **Replay** — a previously valid call is captured and resubmitted.
- **Authorization stripping / confusion** — the call arrives without, or with
  forged, authorization context.
- **Response tampering** — the answer is altered, or a response from one request
  is substituted for another.
- **Channel confusion** — a signed call is lifted onto a different transport.

MCP-S closes these with object signatures, a freshness window, a replay cache
keyed on `(signer, audience, nonce)`, delegated-authorization *binding*,
response-to-request hash binding, and transport channel binding. This mirrors,
line for line, the public NSA/CISA MCP-hardening direction: sign and verify MCP
messages, carry expiry and replay metadata, and bind requests to time and
context.

## Where does it sit relative to EMA and OAuth?

MCP-S is a **per-message authenticity and integrity layer**. It is deliberately
*not*:

- **OAuth / OIDC** — those establish *who the caller is* and mint tokens. MCP-S
  consumes an authorization decision and **binds** it to a specific signed call;
  it does not issue identity or interpret an enterprise authz system.
- **EMA (enterprise-managed authorization)** — MCP-S does not implement EMA. It
  composes beneath one: EMA can decide policy, MCP-S makes that decision
  unforgeable and unreplayable on the wire.
- **Sandboxing** — MCP-S controls *what reaches* the inner server, not what that
  server can do to the host OS once it runs.
- **An audit-receipt format** — MCP-S emits a frozen audit-event taxonomy, but
  portable, signed audit receipts are not claimed.

Think of it as the layer that makes "this exact call, authorized this way, at
this time" cryptographically checkable — and it stacks with the identity,
policy, and isolation layers around it.

## What does v0.5.1 prove?

**Single-node Rust-native end-to-end path (demonstrated).** HostSession signs a
request → mTLS → `mcps-proxy` verifies signature, freshness, replay, and
delegated authorization → strips caller context, injects sidecar context →
persistent inner MCP server handles it → signed, request-bound response →
HostSession verifies the response. Denied requests never reach the inner server.

**Live Google Cloud KMS validation (new in v0.5.1).** Against *real* Cloud KMS,
not an emulator:

- **Object signing** with an `EC_SIGN_ED25519` key: signatures produced by a live
  `asymmetricSign` and verified by `mcps-core`. The private key never leaves KMS
  — only `getPublicKey` and `asymmetricSign` calls appear in the request log.
- **Delegated TLS server-signing**: a fully-validating rustls mTLS handshake
  completes *only* because a live KMS `asymmetricSign` produced the
  `CertificateVerify`. The TLS private key lives entirely in KMS — the server
  leaf is minted over the KMS public key, with no local private key.
- **Fail-closed negative lanes**: wrong-identity, bad-token, non-Ed25519 key,
  a leaf not bound to the KMS key, and an untrusted client certificate all
  reject — with the correct frozen wire codes.

This is evidence and test surface, not new protocol mechanism: the `draft-01`
request/response envelopes are unchanged.

## What does it not claim?

- official MCP extension status;
- universal enterprise authorization, or an EMA implementation;
- portable audit receipts;
- full SIEM / Security Command Center integration (the audit taxonomy is frozen
  and SCC-mappable, but the integration itself is unbuilt);
- broad multi-cloud live validation — **GCP Cloud KMS is live-proven; the AWS KMS
  adapter is shipped but not yet live-proven**, so multi-cloud custody is not
  claimed until AWS is also live-proven;
- horizontally scaled replay protection, full CRL/OCSP revocation, OS-level
  sandboxing of wrapped servers, and signed tool-manifest enforcement — these are
  gated on the high-assurance cargo features and are **not** in the lean default
  build.

## How do I run the demo?

Single-node end-to-end demo (Cargo):

```sh
cargo build --workspace --bins
cargo test --workspace
```

Live Google Cloud KMS validation (one command, after first-time gcloud setup —
needs a billing-enabled GCP project; the script enables the KMS API and
provisions keys idempotently):

```sh
PROJECT_ID="<your-project-id>" ./docs/security/gcloud-kms-validation.sh
```

It runs both live lanes (`gcp_kms_live_test.rs` object signing,
`gcp_kms_delegated_tls_live_test.rs` delegated TLS) built with
`--features gcp_kms_keysource`. See
[`docs/security/google-validation-plan.md`](security/google-validation-plan.md)
for full setup and exit criteria.

## Where is the spec?

- **Specification briefs:** [`docs/spec/`](spec/) — the core spec, the
  [security boundary](spec/security-boundary.md), the
  [v0.5 claim matrix](spec/v0.5-claim-matrix.md), and
  [proposal scope](spec/proposal-scope.md) (the `draft-01` freeze).
- **Architecture decisions:** [`docs/adr/`](adr/) — start with
  [ADR-MCPS-001](adr/adr-mcps-001.md) (trust model) and
  [ADR-MCPS-011](adr/adr-mcps-011.md) (core firewall).
- **Project status & non-claims:** [`docs/PROJECT_STATUS.md`](PROJECT_STATUS.md).
- **Google KMS validation:**
  [`docs/security/google-validation-plan.md`](security/google-validation-plan.md).
- **Upstream proposal path:**
  [`docs/UPSTREAM_PROPOSAL_PROCESS.md`](UPSTREAM_PROPOSAL_PROCESS.md).
