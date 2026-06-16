<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-028: Native Cloud-KMS Response Signers — AWS KMS and GCP Cloud KMS (Ed25519, non-exporting)

## Status

Proposed (v0.3 follow-up — design). Child of ADR-MCPS-019 (external backends) and
ADR-MCPS-022 (signing key custody at scale). Implementation lands as its own
follow-up PR(s) per the design-PR-then-implementation rhythm. Does **not** change
the MCP-S signature contract: MCP-S Core stays Ed25519-only (ADR-MCPS-004).

## Context

MCP-S signs every response with Ed25519 over the canonical JCS preimage, **directly
— no pre-hash** (`mcps-core/src/crypto.rs`; Ed25519ph is forbidden). The
`ResponseSigner` seam (`mcps-proxy/src/key_source.rs`) already lets a non-exporting
backend drive the full response-signing path without ever surrendering the private
key: `sign_response(preimage) -> Base64URL-no-pad(sig)` + `response_public_key() ->
VerificationKey`. `Pkcs11KeySource` implements this against any PKCS#11 token
(SoftHSM2 in CI; equally AWS CloudHSM, GCP via its PKCS#11 library, Azure Managed
HSM, Luna/Thales, YubiHSM). So HSM custody — the response-signing key never leaving
the device — is **already delivered and live-tested** via the generic PKCS#11 path.

What is missing is **native managed-KMS** custody for operators who use a cloud
KMS's own REST API rather than a PKCS#11 endpoint.

### Provider Ed25519 support (the compatibility-critical fact)

A native KMS adapter is only viable if the KMS can produce a **PureEdDSA Ed25519
signature over raw bytes** — byte-identical to what `SigningKey::sign` /
`CKM_EDDSA` produce, so it verifies under the existing `mcps-core` verifier.

| Provider | Native Ed25519 signing | MCP-S-compatible mode | Native adapter |
|---|---|---|---|
| **AWS KMS** | **Yes** (since 2025-11-07) | key spec `ECC_NIST_EDWARDS25519`, alg `ED25519_SHA_512`, **`MessageType: RAW`** (PureEdDSA) — **not** `ED25519_PH_SHA_512`/`DIGEST` (that is Ed25519ph, forbidden) | **In scope** |
| **GCP Cloud KMS** | **Yes** | purpose `ASYMMETRIC_SIGN`, algorithm `EC_SIGN_ED25519` (PureEdDSA on Edwards25519, raw data input) | **In scope** |
| **PKCS#11 HSM** (incl. AWS CloudHSM, Azure Managed HSM) | Yes (`CKM_EDDSA`) | already implemented (`Pkcs11KeySource`) | **Done** |
| **Azure Key Vault / Managed HSM (native REST)** | **No** (RSA + EC NIST P-curves/secp256k1 only as of current docs) | — | **Unsupported** (see Decision E) |

An earlier internal analysis claimed AWS KMS could not sign Ed25519. That premise
was **stale and is withdrawn**: AWS KMS added EdDSA (Edwards25519) on 2025-11-07.
No protocol change is required for native AWS or GCP support.

## Decision

**A. Keep MCP-S Core Ed25519-only.** Compatibility is delivered by honest adapters
and explicit unsupported boundaries — never by lowering the protocol to the weakest
common KMS algorithm set. No signature-suite agility is introduced by this ADR.

**B. Native AWS KMS `ResponseSigner`** (`AwsKmsKeySource`, feature `aws_kms_keysource`).
Signs via KMS `Sign` with `SigningAlgorithm = ED25519_SHA_512` and
**`MessageType = RAW`** over the canonical preimage; returns the raw 64-byte
signature base64url-no-pad-encoded (identical wire form to every other signer).
`response_public_key()` fetches the KMS public key (SPKI), extracts the raw 32-byte
Ed25519 point, and constructs a `VerificationKey`. The KMS key MUST be
`ECC_NIST_EDWARDS25519`; any other key spec fails closed at construction.

**B.1 Transport — blocking `ureq` + a minimal audited SigV4 signer; NOT the AWS
SDK** *(ratified 2026-06-15).* The adapter reaches KMS over blocking HTTPS (`ureq`,
reusing the in-closure rustls/`ring` provider) and signs requests with a tiny,
self-contained SigV4 implementation (HMAC-SHA256 over the in-closure RustCrypto
primitives). The async `aws-sdk-kms` / `tokio` / Smithy stack is **forbidden** here:
the ADR-MCPS-018 lean-closure / "all Phase-7 backends are SYNC, no async runtime"
rule is a hard architectural constraint, and pulling tokio + a `block_on` bridge
into this firewalled workspace would violate the shape of the system (the OCSP
path's blocking-`ureq` precedent is the model). The client surface is deliberately
TINY — only KMS `GetPublicKey` and `Sign`; no general KMS client, no encrypt/
decrypt, no key-management or policy operations. Credentials are the explicit,
narrow set (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / optional
`AWS_SESSION_TOKEN` / explicit region / optional endpoint override); SDK-style
credential discovery (profiles, IMDS, IRSA) is intentionally NOT provided. The SigV4
signer is proven against AWS's published `get-vanilla` test vector, and EVERY
KMS-returned signature is verified locally against the advertised public key (under
the unmodified `mcps-core` verifier) before it is emitted.

**C. Native GCP Cloud KMS `ResponseSigner`** (`GcpKmsKeySource`, feature
`gcp_kms_keysource`). Signs via `asymmetricSign` against an `EC_SIGN_ED25519` key
version (raw `data`, not `digest`); same raw-64-byte → base64url contract.
`response_public_key()` parses the version's PEM public key to the raw point.

**C.1 Transport — blocking `ureq` + OAuth2 bearer; NOT the google-cloud SDK.**
Mirrors §B.1: Cloud KMS is reached over blocking HTTPS (`ureq`), and the async
google-cloud SDK / tokio stack is **forbidden** (ADR-MCPS-018 lean-sync firewall).
The surface is the two operations only — `getPublicKey` + `asymmetricSign`. The
bearer token comes from a NARROW, explicit set of sources — an operator-supplied
`MCPS_GCP_ACCESS_TOKEN` or the GCE/GKE metadata server (workload identity) — never a
silent application-default-credentials chain; the service-account JWT-file→token
exchange (which needs RSA) is a deliberately deferred follow-up. As in §B, every
KMS-returned signature is verified locally against the advertised public key before
it is emitted.

**D. Non-exporting invariant + fail-closed.** Both adapters implement only the
`ResponseSigner` operations; the private key never crosses the trait boundary
(it never leaves the KMS). A wrong key spec, a prehash/digest mode, a wrong-length
signature, or a public key that is off-curve / non-canonical fails closed
(`KeyError::Malformed`) — never a silent fallback to a local key.

**E. Azure native REST is explicitly unsupported** for MCP-S object signing while
Azure exposes no Ed25519 signing key type. This is recorded as a
**provider-limited** boundary, not an MCP-S gap. Azure HSM custody remains
available through the **PKCS#11** path (Managed HSM) where `CKM_EDDSA` is offered.
Should Azure add Ed25519, a native adapter is a mechanical follow-up; broad
managed-KMS algorithm agility, if ever wanted, is a separate protocol-level ADR and
is **not** opened here.

**F. Repository boundary.** The generic cloud adapters (AWS, GCP) ship in the public
`mcps` repo behind their feature gates. Internal-platform adapters (the in-house
HSM/IDP/KMS) live in the monorepo as private implementations of the **same**
`ResponseSigner` trait — the trait is the only coupling; no internal specifics enter
the public repo.

**G. TLS-key custody — delegated TLS handshake signing.** The object-signing key
(§B–§F) lives in the device/KMS; this item closes the matching gap for the TLS
*server* key, which was still exported via `KeySource::tls_server_key`. The generic
mechanism is implemented: a custom `rustls::sign::SigningKey`
(`DelegatedEd25519SigningKey`) whose `Signer::sign` forwards the to-be-signed
handshake transcript to a non-exporting `RawEd25519TlsSigner` (PKCS#11 token / AWS
or GCP KMS), paired with the public server cert via a `DelegatedCertResolver` and a
`with_cert_resolver` server-config path that shares the exported-key path's
fail-closed client-cert verifier. It is **Ed25519-only**: rustls signs the TLS 1.3
transcript with `SignatureScheme::ED25519` (PureEdDSA over the message), exactly the
raw-sign primitive the KMS/PKCS#11 backends expose, so the TLS certificate MUST be
an Ed25519 cert whose key lives in the device/KMS (a non-Ed25519 TLS cert fails
closed — no scheme offered). The TLS key is a SEPARATE credential from the
object-signing key. Wire-correctness is proven by a real in-process mTLS handshake
in which a rustls client completes the handshake against a server whose TLS key
never reaches rustls. The per-backend TLS-key wiring (a second KMS key id / token
object, plus its CLI flags, and the `KeySource` seam selecting the delegated path)
is sequenced as the immediate follow-up to this mechanism. Note the operational
consequence for the KMS path: delegated TLS makes a KMS `Sign` network call on every
TLS handshake (latency + availability coupling), an accepted trade-off for the
never-export property; the PKCS#11 path signs locally on the token.

**G.1 Completion plan — wiring the backends to the §G mechanism.** The §G mechanism
is generic; making TLS-key custody usable end-to-end requires wiring each real
backend to it. This is the planned, scoped remaining work (tracked as GitHub
issues; design recorded here):

1. *Seam + path selection.* Add `KeySource::tls_delegated_signer(&self) ->
   Option<Arc<dyn RawEd25519TlsSigner>>` defaulting to `None` — the file/env/PKCS#11
   object-signing sources keep exporting the TLS key, so the default build is
   unchanged. When it returns `Some`, the proxy builds the server config via the
   delegated path (`build_server_config_delegated_with_crls`) and does NOT call
   `tls_server_key`. Configuring both an exported `--tls-key` and a delegated TLS
   key is rejected (mutually exclusive, fail closed).
2. *AWS + GCP Cloud KMS.* `KmsEd25519Backend` implements `RawEd25519TlsSigner` keyed
   by a SECOND KMS key (the TLS key, distinct from the object-signing key), reusing
   the existing RAW-Ed25519 `Sign`/`asymmetricSign` path. CLI: `--aws-kms-tls-key-id`
   / `--gcp-kms-tls-key-version`, with `--tls-key` relaxed when set.
3. *PKCS#11.* A second token object (TLS key label) using a `CKM_EDDSA` signing
   operation (`sign_tls_ed25519`), implementing `RawEd25519TlsSigner`. CLI:
   `--pkcs11-tls-key-label`. The PKCS#11 path signs locally on the token (no
   per-handshake network call, unlike KMS).

Each path is proven by a real in-process mTLS handshake under full WebPKI server
validation (chain + validity + hostname + `CertificateVerify` signature) — a
corrupted delegated signature must fail the handshake. The internal-platform TLS
key (§F) is wired privately in the monorepo against the same `RawEd25519TlsSigner`
trait; no internal specifics enter this repo.

## Verification (no-gaming)

Per the live-infra-lane discipline already used for Redis / SoftHSM2 / OCSP, each
adapter is proven by a black-box live test under `MCPS_REQUIRE_LIVE_INFRA=1`:

- **AWS** — LocalStack KMS emulator in CI (creates an `ECC_NIST_EDWARDS25519` key);
  optional nightly lane against real AWS KMS with provided creds.
- **GCP** — Cloud KMS emulator in CI; optional nightly real-endpoint lane.
- **Internal platform** — the in-house KMS test endpoint (monorepo-side adapter).

The load-bearing assertion in every lane: a signature produced by the KMS adapter
over a preimage **verifies under `response_public_key()` using the unmodified
`mcps-core` Ed25519 verifier** — proving byte-level protocol compatibility, and that
the adapter uses PureEdDSA-RAW (a prehash signature would fail this check).

## Consequences

- Native AWS KMS and GCP Cloud KMS become first-class custody backends with the
  response-signing key never leaving the KMS; AWS/GCP/Azure HSM and any PKCS#11
  device remain covered by the existing generic path.
- The v0.3 claim matrix Axis-3 (`shared_remote_signer`) gains concrete, live-verified
  managed-KMS backings beyond PKCS#11.
- Azure-native REST signing is a documented, honest unsupported boundary — surfaced,
  not hidden.
- Default builds are unaffected (both adapters are off-by-default feature gates; the
  cloud SDKs are not linked unless enabled).
