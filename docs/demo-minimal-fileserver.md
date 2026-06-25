# MCP-S Minimal Fileserver Demo

**Audience:** an engineer who wants to RUN the self-contained MCP-S single-node
demo from a fresh clone, with Bazel only, and see — end to end — what the MCP-S
sidecar protects and how it fails closed.

This guide explains **how to run** the demo and **what each line of output
means**. It does not restate the protocol rules (those live in the
[MCP-S Core Specification](spec/mcps-core-spec.md)) or the
claim boundary (that lives in the
[MCP-S Security Boundary](spec/security-boundary.md)).

## Purpose

The demo wires the existing MCP-S building blocks into one cohesive, runnable
round trip against a real, MCP-S-**unaware** inner MCP server:

```text
HostSession (client) signs an authorized list_files request
  -> mcps-proxy verifies the Core envelope (signature, freshness, replay)
  -> mcps-proxy evaluates Phase 5 delegated authorization (allow/deny)
  -> mcps-proxy strips the external request envelope
  -> mcps-proxy injects the sidecar-owned verified context (sole writer)
  -> mcps-demo-fileserver executes list_files, confined to a demo root
  -> mcps-proxy signs the response
  -> HostSession (client) verifies the response against the STORED request hash
```

Two runnable entry points drive this:

- **`demo_positive`** — the cohesive good path: one authorized `list_files`
  call round-trips and the client verifies the signed response.
- **`demo_negative`** — the fail-closed security path: ten rejected cases, each
  printing the exact frozen `mcps.*` reason code and whether the inner server
  was reached.

The inner server, `mcps-demo-fileserver`, is a minimal plain-MCP stdio server
that knows nothing about MCP-S. It exposes one tool, `list_files`, confined to a
committed `demo_root/` fixture. The point is precisely that the security
property is provided by the **sidecar wrapping an unmodified inner server**, not
by the inner server itself.

## Security claim being demonstrated

The demo demonstrates the **single-node** MCP-S claim:

> "production-hardened for single-node Rust-native deployments."

Concretely, the demo shows that the sidecar, in front of an unmodified inner
server:

- verifies the request object signature against an injected trust resolver, and
  rejects a tampered body or a tampered JSON-RPC id (`mcps.invalid_signature`);
- enforces freshness and **local** replay protection
  (`mcps.expired_request`, `mcps.replay_detected`);
- enforces audience binding (`mcps.invalid_audience`) and requires the MCP-S
  request envelope to be present (`mcps.missing_envelope`);
- is the **sole writer** of the verified context: a caller-smuggled `.verified`
  block is stripped and replaced, never trusted;
- enforces Phase 5 delegated authorization **before dispatch**, so a
  signed-but-unauthorized path is denied (`mcps.authorization_scope_denied`)
  and the inner server is never reached;
- signs the response so the client can bind it to the exact request it sent,
  rejecting a wrong-hash binding (`mcps.response_hash_mismatch`) or a corrupted
  response signature (`mcps.response_sig_invalid`).

See the [MCP-S Security Boundary](spec/security-boundary.md)
for the authoritative statement of what this claim does and does not cover.

## Non-goals

This is a **self-contained demonstration, not a production rollout.** The demo
deliberately does **not** demonstrate, and the demo must **not** be read to
claim, any of the following:

- **No horizontal scale.** Replay protection in this demo is a local in-memory
  cache (`InMemoryReplayCache`); replay safety holds only within one proxy
  instance. Multi-node operation needs a shared, atomic replay cache, which this
  demo does not exercise.
- **No OS sandboxing.** The proxy applies a hardened launch policy (controlled
  working directory, minimized environment, bounded stderr, coarse `setrlimit`
  ceilings), but this is **not** an OS-level sandbox or containment boundary.
- **No HSM/KMS.** Keys in the demo are deterministic in-process test keys
  derived from fixed seeds. There is no hardware or cloud key custody.
- **No CRL/OCSP.** The demo uses no certificate-revocation infrastructure.
- **No reverse-proxy mTLS.** The demo round-trips raw JSON-RPC bytes in-process;
  there is no TLS termination, mutual TLS, or transport-layer client-cert
  handling in this path.

## Prerequisites

- A clean checkout of this repository.
- A working Bazel toolchain (the repository's standard Bazel + central toolchain
  setup).

That is all. The demo is **self-contained** (ADR-MCPS-001): it depends only on
the sibling in-workspace MCP-S crates plus the pinned serde subset. It needs
**no external services, no databases, no network, and no other monorepo
components or applications.** The inner-server binary and the `demo_root/`
fixture are delivered to the demo via Bazel runfiles; nothing is hardcoded.

## Commands to run

Run all commands from the repository root.

The simplest path builds the workspace and runs both demos in one command (no
cloud credentials, no env setup):

```sh
./scripts/demo-local.sh
```

Or run the lanes individually under either build system. The demo bins resolve
the inner fileserver and the `demo_root/` fixture automatically (Bazel runfiles
env vars when set; otherwise the Cargo `target/<profile>/` output and the
workspace-relative fixture — see [`mcps-demo/src/demo_paths.rs`](../mcps-demo/src/demo_paths.rs)),
so no env vars are required for the Cargo path:

```sh
# Cargo (after `cargo build --workspace --bins`):
cargo run -p mcps-demo --bin demo_positive   # the positive happy path
cargo run -p mcps-demo --bin demo_negative   # the ten fail-closed cases

# Bazel:
bazel run //mcps-demo:demo_positive
bazel run //mcps-demo:demo_negative

# The full test suite for the demo crates.
bazel test //mcps-demo:all //mcps-demo-fileserver:all
```

The runnable binaries are `//mcps-demo:demo_positive` and
`//mcps-demo:demo_negative`. The test targets follow the `nt_rust_test`
convention, one target per test file, e.g. `//mcps-demo:demo_positive_test`,
`//mcps-demo:demo_negative_test`, `//mcps-demo:demo_proxy_test`,
`//mcps-demo:demo_authorization_test`, `//mcps-demo:demo_client_test`, and
`//mcps-demo-fileserver:server_test`.

## The multi-process mTLS demonstration (Phase 6.6, epic #3948)

The `demo_positive` / `demo_negative` binaries above drive the **client → proxy**
hop **in-process**. Epic adds the **multi-process** demonstration over the
proxy's real production transport: the demo host-side client opens a real
mutual-TLS socket to `mcps_proxy_cli` running as a **separate OS process**. (The
client models the host boundary, not the model: the LLM never holds key material —
`HostSession` signs on behalf of the host layer, and `mcps-transport` only carries
bytes.) This is the topology
governed by the
the MCPS-P6.6 e2e test plan:

```text
this process: DemoHostClient (HostSession) signs + mcps-transport mTLS POST
   │  real mTLS socket (127.0.0.1:<ephemeral>)
   ▼
mcps_proxy_cli  (SEPARATE OS process: mTLS terminate + verify, Core verify,
   │             freshness, durable replay, transport-binding EXACT,
   │             Phase-5 authz=reference, strip caller .verified / inject
   │             sidecar verified context, sign response)
   │  stdio, one subprocess per request
   ▼
mcps_demo_fileserver_bin  (the ordinary inner MCP server; list_files over demo_root/)
```

Run it:

```sh
# The runnable multi-process mTLS positive path (matrix P1).
bazel run //mcps-demo:demo_e2e

# The hermetic multi-process test suites behind the matrix below.
bazel test //mcps-demo:demo_e2e_test \
  //mcps-demo:demo_negative_e2e_test \
  //mcps-demo:demo_transport_e2e_test \
  //mcps-demo:demo_posture_e2e_test
```

The proxy binary, the inner fileserver binary, and the committed `demo_root/`
fixture are delivered via Bazel runfiles and resolved from the
`$(rlocationpath ...)` env vars the BUILD target stamps; nothing is hardcoded and
there is still no manual key/cert step. Unlike `demo_positive`, the `demo_e2e`
bin **mints fresh security material at runtime** (real per-run keys and certs),
so the hashes it prints are **not** reproducible verbatim — read the success line
below as a **shape**, not a fixed string.

### Why a separate `mcps-transport` crate (crate-boundary note)

The multi-process client needs a real mTLS transport, but that transport does
**not** live on `mcps-host`. The boundary is deliberate:

- **`mcps-host` is intentionally transport-free.** It is the agent's local
  key/actor context: it signs the MCP-S request envelope
  (`HostSigner` / `HostSession`) and verifies signed server responses
  (re-exporting `mcps_core::verify_response`). It "produces and consumes raw
  JSON-RPC bytes; the transport … is the caller's concern," so it stays free of
  networking and async and keeps the security-critical core small.
- **`mcps-transport` provides the client-side transport adapter.** It is a
  reusable blocking `rustls` (ring) client that presents a client certificate for
  mTLS client-auth **and** verifies the proxy's server certificate and identity
  against a configured server CA using rustls' standard `WebPkiServerVerifier`
  (not a fake accept-any verifier). It is transport-only: it carries raw
  request/response bytes, does **no signing**, and depends on neither `mcps-host`
  nor `mcps-proxy`.
- **Responsibility stays put.** `mcps-host` remains responsible for signing
  requests and verifying responses; `mcps-transport` only carries bytes; the
  proxy remains the server-side authority. The demo client composes the two:
  `HostSession` signs, `MtlsClient` carries.

### Expected successful output

`bazel run //mcps-demo:demo_e2e` brings up the proxy, drives the authorized P1
flow over the real mTLS socket, and prints the verified response and a final
`OK`. The proxy also emits informational `mcps-proxy:` lines (key-file mode
warnings, the cert-lifetime ceiling notice, the inner-launch policy, and the
`inner_*` lifecycle events) on stderr. The salient lines are:

```text
proxy-up addr=127.0.0.1:<port> inner=mcps_demo_fileserver_bin authz=reference replay=file binding=exact
response-verified signer=did:example:agent-1 audience=did:example:server-1 request_hash=sha256:<hash> authorization_hash=sha256:<hash> server_signer=did:example:server-1 tool=list_files path=reports entries=["q1.txt", "q2.txt"]
OK: authorized list_files round-tripped client -> mcps_proxy_cli (separate process, real mTLS) -> mcps_demo_fileserver_bin -> client; transport-binding exact satisfied (mTLS identity == request signer)
```

What to read from it:

- `binding=exact` plus a non-error `response-verified` line means the mTLS client
  cert's URI SAN **equalled** the request signer — the transport binding was
  **satisfied**, not bypassed.
- `entries=["q1.txt", "q2.txt"]` is the real listing the inner fileserver
  returned for `demo_root/reports/` — the inner server actually executed.
- the client verified the signed response under `server_signer=did:example:server-1`
  against the `request_hash` it stored at sign time; the process exits `0`.

### Traceability matrix

Every scenario in the multi-process matrix maps to a specific `#[test]` function
and Bazel test target. Reading the table top to bottom is the proof that "all
security practices are demonstrated" over the real transport. This matrix folds
in the demo test-traceability gap tracked as.

| Scenario | What it proves | Enforcing layer | Bazel test target (`#[test]` fn) |
|----------|----------------|-----------------|----------------------------------|
| P1 | Authorized `list_files` round-trips client → proxy → inner → client over real mTLS; signed response verifies vs the stored request hash; binding `exact` satisfied; fixture entries (`q1.txt`, `q2.txt`) returned | full pipeline | `//mcps-demo:demo_e2e_test` (`positive_path_multi_process_mtls_round_trip`) |
| A1 | Body tampered after signing → `mcps.invalid_signature`; inner NOT reached | Core verify | `//mcps-demo:demo_negative_e2e_test` (`a1_tampered_request_body_rejected_over_wire`) |
| A2 | JSON-RPC id tampered after signing → `mcps.invalid_signature`; inner NOT reached | Core verify | `//mcps-demo:demo_negative_e2e_test` (`a2_tampered_jsonrpc_id_rejected_over_wire`) |
| A3 | Replay on a FRESH mTLS connection → `mcps.replay_detected` (first send succeeds, second denied) | Core / replay | `//mcps-demo:demo_negative_e2e_test` (`a3_replayed_request_rejected_on_fresh_connection`) |
| A4 | Expired request → `mcps.expired_request`; inner NOT reached | Core / freshness | `//mcps-demo:demo_negative_e2e_test` (`a4_expired_request_rejected_over_wire`) |
| A5 | Wrong audience → `mcps.invalid_audience`; inner NOT reached | Core verify | `//mcps-demo:demo_negative_e2e_test` (`a5_wrong_audience_rejected_over_wire`) |
| A6 | Missing MCP-S envelope → `mcps.missing_envelope`; inner NOT reached | Core verify | `//mcps-demo:demo_negative_e2e_test` (`a6_missing_envelope_rejected_over_wire`) |
| A7 | Caller-smuggled `.verified` block stripped & replaced by the sidecar; call still succeeds and verifies under the server | proxy strip/inject | `//mcps-demo:demo_negative_e2e_test` (`a7_smuggled_verified_metadata_stripped_and_replaced_over_wire`) |
| A8 | Validly-signed but non-granted path → `mcps.authorization_scope_denied`; deny-before-dispatch, inner NOT reached | Phase-5 authz | `//mcps-demo:demo_negative_e2e_test` (`a8_unauthorized_path_rejected_over_wire`) |
| A9 | Server signs a different body under the same id → client rejects with `McpsError::ResponseHashMismatch` (inner reached; client refuses the binding) | client response verify | `//mcps-demo:demo_negative_e2e_test` (`a9_wrong_response_hash_rejected_by_client_over_wire`) |
| A10 | Corrupted response signature → client rejects with `McpsError::ResponseSigInvalid` (inner reached; client refuses the signature) | client response verify | `//mcps-demo:demo_negative_e2e_test` (`a10_bad_response_signature_rejected_by_client_over_wire`) |
| T1 | No client cert presented → mTLS handshake rejected; inner NOT reached | mTLS handshake | `//mcps-demo:demo_transport_e2e_test` (`t1_no_client_cert_rejected_at_handshake`) |
| T2 | Client cert from an untrusted CA → handshake rejected; inner NOT reached | mTLS handshake | `//mcps-demo:demo_transport_e2e_test` (`t2_untrusted_client_ca_rejected_at_handshake`) |
| T3 | Trusted cert whose identity ≠ request signer under binding `exact` → `mcps.transport_binding_failed`; deny-before-dispatch | transport binding | `//mcps-demo:demo_transport_e2e_test` (`t3_identity_not_signer_transport_binding_failed`) |
| T4 | Client cert over `--max-client-cert-lifetime` → `mcps.transport_binding_failed`; inner NOT reached | transport posture | `//mcps-demo:demo_transport_e2e_test` (`t4_over_lifetime_client_cert_rejected`) |
| T5 | Untrusted server cert → the verifying client aborts the handshake (`TransportError::Handshake`) before sending the body; proves server authentication | mTLS handshake (client) | `//mcps-demo:demo_transport_e2e_test` (`t5_untrusted_server_cert_refused_by_client`) |
| C1 | `--key-source env` fails closed: WITHOUT `--allow-env-keysource` the parse-time gate refuses it; and (MCPS-076) because `EnvKeySource` is gated behind the non-default `dev_env_key_source` feature, the production binary refuses env key material EVEN WITH `--allow-env-keysource` (diagnostic names the feature rebuild). Either way: non-zero exit, no listening socket. Positive env-load control is the feature-built `//mcps-proxy:dev_env_key_source_test`. | startup posture | `//mcps-demo:demo_posture_e2e_test` (`c1_env_keysource_without_opt_in_fails_closed_no_listener`, `c1_env_keysource_fails_closed_even_with_opt_in_in_production_build`) |
| C2 | Request accepted by one proxy process is rejected `mcps.replay_detected` by a fresh proxy process sharing the same durable `--replay-path` | durable replay | `//mcps-demo:demo_posture_e2e_test` (`c2_replay_detected_after_proxy_restart_with_shared_durable_cache`) |

The four multi-process suites total 19 test functions
(1 + 10 + 5 + 3 = P1 + A1–A10 + T1–T5 + C1/C1-control/C2).

**Supporting in-process evidence.** The matrix above is the multi-process proof;
the same building blocks are also proven in-process by the unit suites this epic
landed:

- `//mcps-transport:mtls_client_test` — the verifying mTLS client:
  trusted server cert accepted; untrusted / wrong-identity / expired server cert
  refused at the handshake; client-cert presentation still works.
- `//mcps-demo:demo_mtls_client_test` — the runnable client path
  (`HostSession` sign → `MtlsClient` carry → response verify) against a real
  `mcps_proxy::serve_once` server, in-process.
- `//mcps-demo:demo_fixtures_test` — the shared `DemoFixtures` helper is
  internally consistent: one source of truth drives both proxy and client sides,
  and the mismatched identity chains to the same client CA yet differs from the
  signer (the T3 setup).

## The long-lived MCP server demonstration (Phase 6.6B, epic #3962)

Everything above fronts `mcps_demo_fileserver_bin`, an inner shaped like a
**one-shot** server: `mcps_proxy_cli` spawns a fresh inner subprocess **per
request**. Epic (P6.6B) closes the remaining shape gap by proving the same
sidecar can front an **ordinary, long-lived MCP stdio server** —
`mcps_demo_server_bin` — that is **spawned and initialized once** and then serves
**many requests over one persistent process**. The demo server is deliberately
**MCP-S-unaware**: it speaks plain MCP JSON-RPC over newline-delimited stdio
(`initialize` / `tools/list` / `tools/call` / `shutdown`) and knows nothing about
signing, mTLS, or authorization. The proxy supplies all of that. It exposes three
scoped demo tools for the Phase-5 policy demonstration: `echo` (public),
`list_items` (protected), and `reset_items` (admin).

The proxy selects the long-lived process model with `--inner-mode persistent`
(the default is `oneshot`, which is what the fileserver demo uses):

```text
this process: DemoHostClient (HostSession) signs + mcps-transport mTLS POST
   │  real mTLS socket (127.0.0.1:<ephemeral>)
   ▼
mcps_proxy_cli --inner-mode persistent
   │  (SEPARATE OS process: mTLS terminate + verify, Core verify, freshness,
   │   durable replay, transport-binding EXACT, Phase-5 authz=reference,
   │   strip caller .verified / inject sidecar verified context per request,
   │   sign response)
   │  stdio, ONE persistent subprocess: spawned + initialized ONCE,
   │  then serves every request over the same process
   ▼
mcps_demo_server_bin  (the ordinary LONG-LIVED inner MCP server;
                       echo / list_items / reset_items over one session)
```

Run it:

```sh
# The runnable multi-process mTLS persistent path: three authorized tools/call
# over ONE persistent inner, plus one admin call scope-denied before dispatch.
bazel run //mcps-demo:demo_e2e_persistent

# The hermetic test targets behind the persistent matrix below.
bazel test //mcps-demo:demo_e2e_persistent_test \
  //mcps-proxy:persistent_inner_test \
  //mcps-proxy:persistent_session_test \
  //mcps-proxy:persistent_scope_test \
  //mcps-demo-server:server_test \
  //mcps-demo-server:persistence_e2e_test
```

The proxy binary and the demo-server binary are delivered via Bazel runfiles and
resolved from the `$(rlocationpath ...)` env vars (`MCPS_PROXY_CLI`,
`DEMO_SERVER_BIN`); nothing is hardcoded and there is no manual key/cert step. As
with `demo_e2e`, the runnable bin **mints fresh security material at runtime**, so
the hashes it prints are **not** reproducible verbatim — read the success line as
a **shape**, not a fixed string.

### Why `inner_request_forwarded`, not `inner_spawned`, is the deny probe here

For the one-shot fileserver, `mcps_proxy_cli` spawns the inner **per request,
lazily, inside `dispatch`** — which runs strictly **after** Core verification,
freshness/replay, transport-binding, and authorization. So a pre-dispatch denial
returns before any spawn, and **zero `inner_spawned`** is a sound "inner not
reached" assertion there.

That assertion is **invalid for a persistent inner.** The process is already
running — it was spawned **once at startup**, so `inner_spawned` fires exactly
**once** regardless of what any later request does. The deny-before-dispatch
signal is therefore a **different** event: the proxy emits
`inner_request_forwarded` only when a verified, authorized request is actually
written to the long-lived session. A pre-dispatch denial adds **zero**
`inner_request_forwarded` while the count of `inner_spawned` stays at one and the
session stays alive. The persistent suites assert exactly that (and the demo
binary prints `rejected before dispatch; persistent inner never forwarded` on the
denied `reset_items` call).

### The reference profile and the "public = baseline grant" nuance

The Phase-5 reference profile **denies a bare call that carries no authorization
block** (`mcps.authorization_block_missing`) — fail-closed is the default. So a
"public" tool is **not** modeled as "no grant at all"; it is modeled as a
**minimal baseline grant** that covers exactly that tool. In the persistent scope
test, the public `echo` succeeds when presented with an `echo`-only baseline
grant; the protected `list_items` succeeds only with a `list_items` grant and is
scope-denied when presented with only the public grant; and the admin
`reset_items` is covered by **no** grant ever minted, so it is always denied.
"Public needs no special grant" means the baseline grant, not the absence of one.

### Crate map (who does what)

- **`mcps-demo-server`** — the ordinary, **long-lived**, **MCP-S-unaware** inner
  server. Plain MCP JSON-RPC over stdio, persistent across requests. Self-
  contained: it depends on no other in-repo crate and has no async/network/DB.
- **`mcps-proxy`** — the **Policy Enforcement Point (PEP)**. It is the server-side
  authority: terminate + verify mTLS, verify the Core envelope, enforce
  freshness/durable replay, enforce `--transport-binding exact`, evaluate Phase-5
  authorization, strip any caller `.verified` and inject its own per request, and
  sign the response. `--inner-mode persistent` makes it run the inner as one
  long-lived session.
- **`mcps-host`** — intentionally **transport-free**. `HostSession` signs the
  request envelope and verifies signed responses; it holds no socket and no async.
- **`mcps-transport`** — **carries bytes only**. The verifying blocking rustls
  mTLS client: presents the client cert and verifies the proxy's server cert; it
  does **no** signing.

### Expected successful output

`bazel run //mcps-demo:demo_e2e_persistent` brings up the proxy in persistent
mode, drives three authorized `tools/call` over the one inner session, then a
denied admin call, and prints a final `OK`. The proxy emits informational
`mcps-proxy:` stderr lines, including `inner process model = persistent
(spawn-once + initialize handshake; …)` and a single `inner_spawned` event. The
salient lines are (hashes/ports vary per run):

```text
mcps-proxy: inner process model = persistent (spawn-once + initialize handshake; long-lived inner serves many requests over one process)
mcps-proxy: inner-event inner_spawned inner=<…>/mcps_demo_server_bin Spawned { pid: <pid> }
proxy-up addr=127.0.0.1:<port> inner=mcps_demo_server_bin inner_mode=persistent authz=reference replay=file binding=exact
authorized-call#0 tool=echo signer=did:example:agent-1 request_hash=sha256:<hash> server_signer=did:example:server-1 result={…"text":"hello-persistent"…}
authorized-call#1 tool=list_items signer=did:example:agent-1 request_hash=sha256:<hash> server_signer=did:example:server-1 result={…"items":["alpha","beta","gamma"]…}
authorized-call#2 tool=echo signer=did:example:agent-1 request_hash=sha256:<hash> server_signer=did:example:server-1 result={…"text":"still-alive"…}
denied-call tool=reset_items reason=mcps.authorization_scope_denied (rejected before dispatch; persistent inner never forwarded)
OK: 3 authorized tools/call round-tripped over ONE persistent inner (client -> mcps_proxy_cli --inner-mode persistent (separate process, real mTLS) -> mcps_demo_server_bin -> client); admin reset_items scope-denied before dispatch; transport-binding exact satisfied (mTLS identity == request signer)
```

What to read from it:

- `inner_mode=persistent` plus a **single** `inner_spawned` line means the inner
  was spawned and initialized **once**; all three authorized calls reused that one
  process.
- the three `authorized-call#*` lines each carry a `request_hash` the client
  stored at sign time and a `server_signer` it verified the response under —
  `binding=exact` was satisfied (the mTLS identity equalled the request signer).
- the `denied-call` line shows the admin `reset_items` was scope-denied **before
  dispatch**; the persistent inner kept serving (the third `echo` after it still
  returns `still-alive`).

### Traceability matrix (persistent / long-lived inner)

Each persistent scenario maps to a specific `#[test]` function and Bazel test
target. The first two rows are the long-lived server proven **on its own** (#3956,
the MCP-S-unaware server); the rest are the sidecar fronting it.

| Scenario | What it proves | Enforcing layer | Bazel test target (`#[test]` fn) |
|----------|----------------|-----------------|----------------------------------|
| Long-lived server, in-process | `initialize` gates the lifecycle; `tools/list` advertises the three scoped tools; each tool's `tools/call` behaves; malformed/unknown inputs are JSON-RPC errors, not panics; `shutdown` is acknowledged | demo server (MCP-S-unaware) | `//mcps-demo-server:server_test` (11 fns incl. `initialize_returns_well_formed_result`, `tools_list_includes_three_scoped_tools_after_initialize`, `shutdown_is_acknowledged_and_flagged_to_stop`) |
| Long-lived server, real process | The REAL binary serves `initialize` + several `tools/call` over **one** process (newline-delimited stdin), one response per request, correlated by id in order, clean exit on EOF | demo server persistence | `//mcps-demo-server:persistence_e2e_test` (`many_requests_over_one_long_lived_process`) |
| Proxy fronts a persistent inner | The proxy spawns the real demo server **once**, does the `initialize` handshake once, forwards N verified requests over the **same** process: one `inner_spawned`, N `inner_request_forwarded`; fail-closed on inner crash / malformed line / handshake failure; a pre-dispatch denial yields **zero** added `inner_request_forwarded` while the inner stays alive | proxy persistent inner | `//mcps-proxy:persistent_inner_test` (6 fns: `persistent_inner_initializes_and_forwards_one_request`, `n_requests_over_one_persistent_inner_process`, `pre_dispatch_denial_yields_zero_forwards_while_inner_stays_alive`, `inner_crash_mid_session_fails_closed_not_hang_or_panic`, `malformed_response_line_fails_closed`, `handshake_failure_aborts_construction`) |
| Per-request strip/inject over one session | Over N (≥3) requests on the SINGLE session, a forged caller `.verified` is stripped and a sidecar-owned context (verifier = this proxy, verified_signer = the verified inbound signer, with on_behalf_of/request_hash) is injected **fresh every request**; one `inner_spawned`, N `inner_request_forwarded`, N `inner_response_signed`, one clean `inner_exited` on teardown | proxy strip/inject | `//mcps-proxy:persistent_session_test` (`per_request_strip_inject_over_one_persistent_session`) |
| Phase-5 scopes public / protected / admin | Over one persistent session: public `echo` succeeds with the baseline grant; protected `list_items` succeeds with its grant and is `mcps.authorization_scope_denied` with only the public grant; admin `reset_items` is denied (no grant); each denial adds **zero** `inner_request_forwarded` and the session keeps serving (a later authorized call still succeeds); exactly 3 forwarded, 3 signed, 1 `inner_spawned`, 1 `inner_exited` on teardown | Phase-5 authz (deny-before-dispatch) | `//mcps-proxy:persistent_scope_test` (`phase5_scopes_over_one_persistent_session`) |
| Multi-process mTLS over the long-lived server | The real `mcps_proxy_cli --inner-mode persistent` (separate OS process, mTLS, authz=reference, durable replay, binding=exact) fronts the real demo server: three authorized `tools/call` (echo, list_items, echo) round-trip over ONE inner process and each signed response verifies vs the stored request hash under the proxy's server signer; the admin `reset_items` is `mcps.authorization_scope_denied` and the session keeps serving; the proxy ran as a separate process | full pipeline, persistent | `//mcps-demo:demo_e2e_persistent_test` (`persistent_multi_call_multi_process_mtls`) |

The persistent suites total **20 test functions** (11 + 1 server-side, plus 6 + 1
+ 1 proxy-side, plus 1 multi-process). The `bazel run` target
`//mcps-demo:demo_e2e_persistent` is the runnable form of the last row.

This is the counterpart to the one-shot matrix above: the P6.6A demo findings flagged that
"zero `inner_spawned`" is topology-specific and must become "zero
`inner_request_forwarded`" for a long-lived inner; the persistent suites
implement exactly that invariant.

## How the demo provisions keys, trust, authorization, and replay

There is **no manual key-generation step and no key/cert files to create.** The
demo provisions every security input **programmatically and deterministically**
so the round trip is reproducible. The exact wiring lives in these functions:

### Key/cert setup

The demo uses **in-process Ed25519 signing keys derived from fixed seeds** —
there are no certificates and no files. In `src/bin/demo_positive.rs` (and the
identical setup in `demo_negative.rs`):

- `signer_key()` — `SigningKey::from_seed_bytes(&[1u8; 32])`, the host/agent
  request-signing key.
- `server_key()` — `SigningKey::from_seed_bytes(&[2u8; 32])`, the proxy's
  response-signing key.
- `issuer_key()` — `SigningKey::from_seed_bytes(&[42u8; 32])`, the
  authorization-grant issuer key.

The language model side never holds a private key: the client (`DemoHostClient`
in `src/client.rs`) exposes only the public **signer identity**
(`did:example:agent-1`) and has **no private-key accessor**.

### Trust resolver setup

Trust is an in-memory map of `(identity, key_id) -> public_key`, built in
`inbound_resolver()` / `server_resolver()`:

- the **inbound** resolver (used by the proxy) holds the request-signer public
  key **and** the grant-issuer public key — the proxy reuses one resolver for
  both Core verification and the policy signature check;
- the **server** resolver (used by the client to verify the response) holds the
  proxy's response-signer public key.

### Authorization artifact setup

The demo mints a single Reference Signed Authorization grant programmatically.
The wiring is in `src/demo_authorization.rs`:

- `DemoGrantSpec` pins every Phase 5 dimension — issuer, grantee (must equal the
  verified signer), subject (`on_behalf_of`), audience, the
  `tools/call` / `list_files` operation, the allowed `path` argument
  (`reports`), and the `[not_before, expires_at]` validity window;
- `mint_demo_grant(...)` signs that spec with the issuer key into the canonical
  artifact bytes;
- `DemoGrant::authorization_block()` produces the `_meta.authorization` block
  attached to the request, and `DemoGrant::authorization_hash()` produces the
  `authorization_hash` the host signs into the request envelope so the evaluator
  can bind the artifact to the request before trusting its claims;
- `demo_policy_evaluator()` builds a `PolicyEvaluator` with the Reference
  Profile registered;
- `build_demo_proxy_with_policy(...)` applies
  `Proxy::with_policy_enforcement(...)` so a denial fails closed **before** the
  inner server is launched.

### Replay cache setup

Replay protection is an in-memory cache, constructed in the demo as
`InMemoryReplayCache::new(SKEW)` (`SKEW = 300` seconds of tolerated clock skew).
This is the **single-node** posture: it is local to one proxy instance. The
inner-launch hardening policy (minimized environment, controlled working
directory at `demo_root`, bounded stderr, coarse `setrlimit` ceilings) is
assembled in `demo_inner_launch(...)` in `src/demo_proxy.rs`.

### Inner server command

The inner server is launched by the proxy as a stdio subprocess. Its command is
assembled by `demo_inner_command(...)` and is equivalent to:

```sh
mcps-demo-fileserver --demo-root <DEMO_ROOT>
```

`--demo-root` is required. In the demo, both the binary path and `<DEMO_ROOT>`
are resolved from Bazel runfiles (env vars `INNER_FILESERVER_BIN` and
`DEMO_ROOT_README` stamped by the BUILD target via `$(rlocationpath ...)`); you
do not invoke this command by hand. The inner-server binary's own Bazel label is
`//mcps-demo-fileserver:mcps_demo_fileserver_bin`.

## Expected successful output

`bazel run //mcps-demo:demo_positive` prints a structured allow-decision line,
the verified response, the proxy/inner lifecycle events, and a final `OK`. The
keys and clock are fixed, so the hashes below are reproducible verbatim:

```text
allow-decision signer=did:example:agent-1 on_behalf_of=did:example:user-1 audience=did:example:server-1 request_hash=sha256:TLrZqxdpAPS29_TwTmmV7pkgRgQ8xwSqt4wPQxtwcj8 authorization_hash=sha256:eljlYtAwSpFdtB7tEIN15xfeHCJjyeiFelHRNCOkdO8 method=tools/call tool=list_files path=reports policy_result=allow
response-verified server_signer=did:example:server-1 request_hash=sha256:TLrZqxdpAPS29_TwTmmV7pkgRgQ8xwSqt4wPQxtwcj8 entries=["q1.txt", "q2.txt"]
lifecycle-events ["inner_request_forwarded", "inner_spawned", "inner_exited", "inner_response_signed"]
OK: authorized list_files round-tripped client -> proxy -> inner -> client
```

What to read from it:

- `policy_result=allow` — the Phase 5 evaluation allowed the call before
  dispatch.
- `entries=["q1.txt", "q2.txt"]` — the real listing returned by the inner
  fileserver for `demo_root/reports/`.
- the `response-verified` line shows the client bound the response to the **same**
  `request_hash` it stored at sign time, under the server's signing identity.
- the process exits `0`.

## Expected failure outputs

`demo_negative` drives ten rejected cases, grouped by category, and prints one
`PASS` line per case carrying the frozen `mcps.*` reason code. It exits `0` only
if **every** case is rejected with the expected reason **and** the expected
inner-reach behavior — a missing rejection is a security regression and the demo
fails loudly with a non-zero exit. Observed output:

```text
MCP-S local fail-closed paths — each case must be rejected with its frozen mcps.* reason:

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
  PASS caller_verified          stripped+replaced (impostor .verified stripped; verifier=did:example:server-1)

Authorization:
  PASS unauthorized_path        mcps.authorization_scope_denied

Response binding:
  PASS wrong_response_hash      mcps.response_hash_mismatch
  PASS bad_response_signature   mcps.response_sig_invalid

OK: all 10 fail-closed cases rejected with the expected mcps.* reason
```

The printed line is cosmetic; the **assertions** behind each `PASS` are the
contract, and they include the inner-reach expectation as well as the reason code:

- Pre-dispatch cases (`tampered_body`, `tampered_id`, `expired`, `wrong_audience`,
  `missing_envelope`, `unauthorized_path`) assert the inner fileserver was **never
  reached** — the sidecar refused the request before it was spawned.
- `replay` asserts the inner server **was** reached, because the **first**
  (accepted) send legitimately reached it; the security property is that the
  **second**, replayed send is denied.
- `caller_verified` is **not** a denial: a caller-smuggled `.verified` block is
  silently stripped and replaced by the sidecar's own verified context, and the
  response still verifies under the server (`verifier=did:example:server-1`).
- `wrong_response_hash` and `bad_response_signature` reach the inner server (the
  request was legitimate) but the **client** refuses the response binding — a
  wrong-hash binding and a corrupted response signature, respectively.

## Troubleshooting

- **`//...` label errors / target not found.** Make sure you are at the
  repository root and use `//mcps-demo:...` labels.
- **`cannot locate the inner 'mcps-demo-fileserver' binary` (Cargo).** The demo
  resolves the inner server from the Cargo `target/<profile>/` output. Build it
  first with `cargo build --workspace --bins` (or just run
  `./scripts/demo-local.sh`, which builds before running). Under Bazel the
  runfiles env vars are stamped automatically; under Cargo no env vars are needed.
- **`demo_positive FAILED: ...` / `demo_negative FAILED: ...`.** The demos fail
  loudly by design. The message names the failing step (e.g. a verification or
  authorization error); treat it as a real signal, not noise.
- **Stale results after editing.** `bazel run`/`bazel test` rebuild on change;
  if output looks cached and unexpected, confirm you edited the file Bazel is
  building and re-run.

## Known limitations

- The demo is **single-node** and uses an **in-memory** replay cache; it does
  not demonstrate multi-node / shared-replay operation.
- Keys are **deterministic in-process test seeds**, not real key custody. Do not
  copy the seed pattern into anything production-bound.
- The hardened inner launch is a process-launch policy, **not** an OS sandbox.
- Identities are illustrative `did:example:*` strings, not a real identity
  system.
- This is a demonstration harness. It is **not** a production deployment
  artifact and must not be described as one. See the non-goals above.

## References

- [MCP-S Security Boundary](spec/security-boundary.md) — the
  authoritative statement of the single-node claim and the forbidden claims.
- [MCP-S Conformance Guide](conformance-guide.md) — how to run the executable
  conformance suite and the drift-guarded conformance manifest
  (`mcps-conformance/conformance_manifest.json`) that enumerates
  every vector and test target.
- MCPS-P6.6 e2e test plan — the plan that defines the multi-process topology
  and the P1 / A1–A10 / T1–T5 / C1–C2 scenario matrix demonstrated above.
- MCPS-P6.6 demo findings — the honest gate statement and the security-boundary
  linkage. The dedicated demo test-traceability mapping now lives in the matrix
  above.
- MCPS-P6.6B demo findings — the long-lived-server gate statement and why the
  real-internal-server dogfood is optional and non-gating.
