<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quickstart — live Google Cloud KMS validation

This proves **v0.5.1's live enterprise key-custody path**: MCP-S signing keys can
live entirely inside Google Cloud KMS and never leave it, while a fully-validating
signature and mTLS handshake still complete against *real* Cloud KMS — not an
emulator.

It exercises the already-shipped `GcpKmsKeySource` adapter
(`mcps-proxy/src/gcp_kms_keysource.rs`). No protocol change is involved; the
`draft-01` request/response envelopes are unchanged. This is evidence and test
surface.

## Run it

```sh
PROJECT_ID="<your-project-id>" ./docs/security/gcloud-kms-validation.sh
```

The harness contains no secrets (you supply `PROJECT_ID`), enables the Cloud KMS
API, idempotently provisions an `EC_SIGN_ED25519` key (KMS keys cannot be
deleted, so re-runs reuse them), and runs both live test lanes built with
`--features gcp_kms_keysource`.

You need a billing-enabled GCP project and an authenticated `gcloud` first. The
one-time, no-CLI-shortcut setup (Google account → Cloud signup → billing account
→ project linked to billing → install gcloud → `gcloud auth login`) is written
out in [`docs/security/google-validation-plan.md`](security/google-validation-plan.md)
under *Reproducing Stage 1 locally*. New accounts get ~$300 in free-trial
credits — ample for this proof (KMS crypto ops run ~$0.03 per 10,000).

## What the harness proves

**Object signing through Cloud KMS** (`gcp_kms_live_test.rs`)

- A signature is produced by a live `asymmetricSign` over the raw canonical MCP-S
  preimage (PureEdDSA, not a digest) and verified by `mcps-core`.
- The private key never leaves KMS — only `getPublicKey` and `asymmetricSign`
  appear in the request log.

**Delegated TLS server signing through Cloud KMS** (`gcp_kms_delegated_tls_live_test.rs`)

- A fully-validating rustls mTLS handshake completes **only** because a live KMS
  `asymmetricSign` produced the server's `CertificateVerify`.
- The TLS server private key lives entirely in KMS: the leaf is minted over the
  KMS *public* key (rcgen `RemoteKeyPair`), with no local private key.

**Fail-closed negative lanes** — every one must reject:

| Case | Rejected at | Why |
|---|---|---|
| Wrong identity | verify | a signature must not verify under a foreign key |
| Bad access token | backend construction | an invalid token must fail closed, not degrade |
| Non-Ed25519 key | backend construction | a provisioned RSA key version is rejected, variant-matched |
| Leaf not bound to KMS key | config construction | `DelegatedKeyMismatch` |
| Untrusted client cert | mTLS handshake | client identity not in the trust set |

## Exit criteria

A clean run shows: the public key fetched with algorithm asserted
`EC_SIGN_ED25519`; signatures produced by Cloud KMS and verified by `mcps-core`;
a live KMS-signed mTLS handshake completing; every negative case rejected with
the correct frozen wire code; and the private key never leaving KMS.

## What this does *not* claim

- **AWS** — the AWS KMS adapter (`mcps-proxy/src/aws_kms_keysource.rs`) is shipped
  but **not** yet live-proven. Multi-cloud custody is not claimed until AWS is
  also live-proven.
- **SIEM / Security Command Center integration** — the audit taxonomy is frozen
  and SCC-mappable, but the integration itself is unbuilt (Stages 2–3 of the
  validation plan, gated on sponsored access).

## References

- [`docs/security/google-validation-plan.md`](security/google-validation-plan.md) — the full staged plan and cost reality.
- [`docs/security/gcloud-kms-validation.sh`](security/gcloud-kms-validation.sh) — the harness.
- [`docs/adr/adr-mcps-028.md`](adr/adr-mcps-028.md) — native Cloud-KMS response signers (AWS + GCP).
- `mcps-proxy/src/gcp_kms_keysource.rs` — the adapter under test.
