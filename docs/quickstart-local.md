<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quickstart — local demo (no cloud credentials)

The fastest way to see what MCP-S actually does: run the single-node sidecar demo
and watch the proxy **accept exactly one valid signed call** and **fail closed on
every tampered, stale, replayed, mis-routed, unauthorized, or unbound call**. This
is real v0.5.1 behavior — the binaries exit non-zero if any expected rejection
does not happen, so a green run is a security assertion, not a printout.

## Run it

```sh
./scripts/demo-local.sh
```

That builds the workspace and runs both demos. Expected final line:

```text
OK: MCP-S local demo completed
```

The script wraps the two runnable bins; you can also run them directly (under
Bazel or, after `cargo build --workspace --bins`, under Cargo — no env setup
needed either way):

```sh
cargo run -p mcps-demo --bin demo_positive   # the one authorized call
cargo run -p mcps-demo --bin demo_negative   # ten fail-closed cases
# or:
bazel run //mcps-demo:demo_positive
bazel run //mcps-demo:demo_negative
```

## What it proves

**Positive path (`demo_positive`)** — one authorized `list_files` call round-trips
client → proxy → inner → client: the proxy verifies the envelope, checks
freshness/replay, evaluates authorization (ALLOW), strips the external envelope,
injects the sidecar-owned verified context, runs the inner MCP-unaware
fileserver, signs the response, and the client verifies that response against the
**stored** request hash.

**Fail-closed paths (`demo_negative`)** — ten cases, grouped, each rejected with
its frozen `mcps.*` reason code:

```text
Request integrity:
  PASS tampered_body            mcps.invalid_signature
  PASS tampered_id              mcps.invalid_signature
Freshness / replay:
  PASS replay                   mcps.replay_detected
  PASS expired                  mcps.expired_request
Routing / binding:
  PASS wrong_audience           mcps.invalid_audience
  PASS missing_envelope         mcps.missing_envelope
Verified context:
  PASS caller_verified          stripped+replaced
Authorization:
  PASS unauthorized_path        mcps.authorization_scope_denied
Response binding:
  PASS wrong_response_hash      mcps.response_hash_mismatch
  PASS bad_response_signature   mcps.response_sig_invalid
```

In plain terms, the demo proves:

- a valid signed MCP-S request reaches the inner MCP server;
- a tampered request (body or id) is rejected before dispatch;
- a replayed request is rejected (the first send is accepted; the replay is denied);
- an expired request is rejected;
- a wrong-audience request is rejected;
- a request with no MCP-S envelope is rejected;
- caller-supplied verified context is stripped and replaced by the sidecar;
- an unauthorized path is denied **before** the inner server is reached;
- a response not bound to the request is rejected by the client;
- a corrupted response signature is rejected by the client.

## Verifying the demo scripts themselves

To confirm the demo entry points work on a clean checkout (build succeeds, the
positive call round-trips, all ten fail-closed cases surface their frozen
`mcps.*` codes, and the GCP wrapper fails closed without `PROJECT_ID`), run the
offline smoke test — no cloud credentials required:

```sh
./scripts/test-demos.sh
```

It exits non-zero, naming the failing assertion, if any demo regresses.

## Next: optional live GCP Cloud KMS validation

Cloud is **not** a dependency of this demo. When you want to prove the
non-exporting GCP key-custody path (object signing and delegated-TLS server
signing performed inside Cloud KMS), run it separately:

```sh
PROJECT_ID=my-gcp-project ./scripts/demo-gcp-kms.sh
```

See [`docs/quickstart-gcp-kms.md`](quickstart-gcp-kms.md).

## See also

- [`docs/security/google-validation-plan.md`](security/google-validation-plan.md) — the full staged GCP validation plan.
- [`docs/security/gcloud-kms-validation.sh`](security/gcloud-kms-validation.sh) — the live KMS harness.
- [`docs/spec/security-boundary.md`](spec/security-boundary.md) — what MCP-S protects and what it does not.
- [`docs/spec/v0.5-claim-matrix.md`](spec/v0.5-claim-matrix.md) — every claim, each traceable to a green test.
- [`docs/demo-minimal-fileserver.md`](demo-minimal-fileserver.md) — the full demo walkthrough and threat-case table.
