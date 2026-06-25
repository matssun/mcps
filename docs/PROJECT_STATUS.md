<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Project Status

## Current status

MCP-S is an experimental third-party security extension proposal for MCP.

It is not an official MCP extension unless accepted through the official MCP governance and proposal process.

## Current implementation claim

The current implementation may claim:

> MCP-S is production-hardened for single-node Rust-native deployments.

This claim is bounded and should not be broadened without additional implementation, tests, and documentation.

## Demonstrated capabilities

The current demonstration and live-validation package proves:

### Single-node Rust-native end-to-end path

- HostSession signs outbound requests; client transport verifies server
  certificate and identity; mTLS to `mcps-proxy`;
- `mcps-proxy` verifies object signatures, freshness/replay, and delegated
  authorization before dispatch;
- caller-supplied verified context is stripped, sidecar-owned context injected;
- a persistent inner MCP server handles multiple requests; denied requests never
  reach it; responses are signed and bound to the request hash; HostSession
  verifies the response signature.

### Live Google Cloud KMS validation (v0.5.1)

- **Object signing against real Cloud KMS** (`EC_SIGN_ED25519`): signatures
  produced by a live `asymmetricSign` and verified by `mcps-core`; the private
  key never leaves KMS (`getPublicKey`/`asymmetricSign` only).
- **Delegated TLS server-signing against real Cloud KMS**: a fully-validating
  rustls mTLS handshake completes only because a live KMS `asymmetricSign`
  produced the `CertificateVerify`; the TLS private key lives entirely in KMS
  (leaf minted over the KMS public key).
- **Fail-closed negative lanes**: wrong-identity, bad-token, non-Ed25519 key,
  leaf-not-bound-to-KMS-key, and untrusted-client cases all reject with the
  correct frozen wire codes.
- One-command reproduction harness (`docs/security/gcloud-kms-validation.sh`).

## Not yet claimed

MCP-S does not currently claim:

- official MCP extension status;
- universal enterprise authorization (MCP-S binds authorization decisions; it
  does not interpret or replace an enterprise authz system);
- an EMA (enterprise-managed authorization) implementation;
- portable audit receipts;
- full SIEM / Security Command Center integration (the audit taxonomy is frozen
  and SCC-mappable, but the integration itself is unbuilt — Stages 2–3 of the
  Google validation plan);
- broad multi-cloud live validation: GCP Cloud KMS is live-proven; the AWS KMS
  adapter is shipped but **not** yet live-proven, so multi-cloud custody is not
  claimed until AWS is also live-proven;
- horizontally scaled replay protection, full CRL/OCSP revocation, OS-level
  sandboxing of wrapped servers, and signed tool-manifest enforcement (gated on
  the high-assurance cargo features — see the README deployment profiles).

## Proposal readiness

Before submitting MCP-S as an MCP extension proposal, ensure that the repository contains a clear specification, security boundary, test traceability document or manifest, runnable reference implementation, conformance vectors, demo evidence, explicit non-claims, and license/contribution files.
