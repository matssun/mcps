# MCP-S Dogfood Runbook — wrapping the real `intelli_code_mcp` server

> **Note for public-repo readers.** This runbook documents an internal dogfood
> exercise: wrapping the author's private `intelli_code_mcp` server (not present
> in this repository) with `mcps_proxy_cli`. It is preserved as a worked example
> of how to dogfood the MCP-S sidecar around any real MCP stdio server — adapt
> the inner-command path and the 12 acceptance checks for your own inner.
> References to `applications/...` paths are to the author's monorepo and are
> not resolvable here.

**Audience:** the operator who will execute and **record** the MCP-S dogfood for
#3862 (MCPS-042). This is a
**human-in-the-loop (HITL)** acceptance task: it requires running the production
`mcps_proxy_cli` around the **real** `intelli_code_mcp` stdio server over mTLS
with signed requests, then observing and recording the 12 acceptance checks.

This document is the turnkey procedure. It does **not** claim the dogfood has been
run — running, observing, and signing off are the operator's job. The mechanical
reference is the already-passing full-stack test
[`mcps-proxy/tests/full_stack_test.rs`](../mcps-proxy/tests/full_stack_test.rs),
which wires `mcps_proxy_cli` around a real inner subprocess over real mTLS with
signed requests and walks the same security matrix. **The dogfood is "do what
`full_stack_test` does, but with `intelli_code_mcp` as the inner, and walk the 12
checks by hand."**

The CLI flags are documented in the
[Sidecar Deployment Guide](sidecar-deployment-guide.md) — that is the source of
truth for flag semantics; this runbook links to it rather than duplicating it.
Host-side response verification is documented in the
[Host Integration Guide](host-integration-guide.md). The rules being exercised
are in the [MCP-S Core Specification](spec/mcps-core-spec.md).

> **Scope note.** This is the dogfood for. The flagship
> `accounting_workflow_mcp` (author's private monorepo)
> demo follows the **same
> procedure** with a higher blast radius (a write-capable accounting inner). Once
> this runbook is green for `intelli_code_mcp`, repeat it for that target,
> substituting the inner `--inner-command` and tightening the trust/authz config
> as that demo's brief requires.

---

## 0. The mental model

```text
HostSession (mcps-host)                mcps_proxy_cli (PEP)              inner stdio server
  sign_tool_call  ── signed bytes ──▶  terminate TLS + verify mTLS  ──▶  intelli_code_mcp
                                       verify object signature           (mcp_server py_binary)
                                       (authz, transport binding)
                                       strip caller .verified
                                       inject sidecar .verified  ── stdin ─▶ FastMCP _meta
                                       read inner stdout (protocol)  ◀── stdout ──
  verify_response ◀── signed bytes ──  sign response, bind request_hash
```

The proxy is the policy-enforcement point: an invalid request is rejected with a
signed / `mcps.*` error and **never** reaches the inner. The inner's **stdout** is
the protocol stream; its **stderr** is captured separately into a bounded log.

---

## 1. Prerequisites

All build/run goes through Bazel (`bazel run` / `bazel test`) — never invoke the
binaries directly. Run everything from the repository root.

### 1.1 Bazel build prerequisites

This repository is a self-contained Bazel module (`MODULE.bazel` is committed at
the repo root). `bazel test //...` should work from a fresh clone with no extra
preparation. The dependency-sync step and submodule initialization referenced in
earlier versions of this runbook are specific to the author's monorepo and are
not required here.

### 1.2 Build the two binaries

```bash
# The production policy-enforcement point.
bazel build //mcps-proxy:mcps_proxy_cli

# The real inner MCP server.
bazel build //applications/intelli_code/intelli_code_mcp:mcp_server
```

`mcp_server` is a `py_binary` (`main = src/intelli_code_mcp/mcp_main.py`); running
it starts a FastMCP stdio server (`create_server().run()`) exposing
`query_codebase`, `get_symbol_source`, and `find_misplaced_interfaces`.

After `bazel build`, note the executable launcher path Bazel produced:

```bash
INNER_BIN="$(bazel cquery --output=files //applications/intelli_code/intelli_code_mcp:mcp_server 2>/dev/null)"
echo "inner launcher = ${INNER_BIN}"
```

That launcher is a self-contained wrapper that sets up its own runfiles tree, so
it is the cleanest thing to put after `--inner-command` (simpler than
`bazel run`, which writes diagnostics to the very stdout the proxy reads as the
protocol stream — see the env-allowlist discussion in §2.2).

### 1.3 Key material, trust, and a Phase-5 authorization profile

Mint the same shapes `full_stack_test` mints in-process, but on disk. You need:

| Artifact | Purpose | Flag |
| --- | --- | --- |
| Ed25519 signing-key **seed** (Base64URL-no-pad, 32 bytes) | The proxy's response-signing key | `--signing-key-seed` |
| TLS server **cert chain** (PEM) + **key** (PEM) | The proxy's TLS identity (SAN `localhost`) | `--tls-cert` / `--tls-key` |
| Client-**CA** (PEM) | Trust anchor for client certs | `--client-ca` |
| A client **leaf cert** whose **URI SAN** equals the request `signer` | The agent's mTLS identity | (presented by the host, not a proxy flag) |
| **Trust file** (JSON array) | Request-signer + authorization-issuer public keys | `--trust` |

The trust file is a JSON array of `{ "signer", "key_id", "public_key" }`
(public key Base64URL-no-pad), exactly as `cli::load_trust` parses it. It carries
**both** the request-signer key and (for `--authz reference`) the
authorization-issuer key.

```json
[
  {
    "signer": "spiffe://example.org/agent-1",
    "key_id": "key-a",
    "public_key": "<request-signer public key, b64url-no-pad>"
  },
  {
    "signer": "did:example:authz-issuer-1",
    "key_id": "authz-key-1",
    "public_key": "<authorization-issuer public key, b64url-no-pad>"
  }
]
```

> **Minting keys.** The simplest reproducible source is the same code the test
> uses: `mcps_core::SigningKey::from_seed_bytes(..)` for the signing keys (write
> `b64url_encode(seed)` to the seed file and the matching `public_key().to_b64url()`
> into the trust file) and `rcgen` for the CA + leaves (`KeyPair::generate`,
> `CertificateParams` with `ExtendedKeyUsagePurpose::ClientAuth` and a URI SAN ==
> the request `signer`). See `full_stack_test.rs` `write_material()` /
> `trusted_client_cert()` for the exact recipe. A tiny throwaway `cargo`/`rcgen`
> script or `openssl` will both work; keep the private material in a temp dir,
> `chmod 0600` the seed and TLS key (the proxy warns on group/world-readable key
> files).

**Phase-5 authorization profile / grant.** Enabling `--authz reference` turns on
the Reference Signed Authorization Profile (ADR-MCPS-013). Each signed request
carries an `authorization_hash` that binds to a signed authorization artifact
issued by the authorization-issuer key in the trust file. For the **happy-path**
checks you need a request whose authorization is **accepted**; for check #9 you
need one that is **rejected** (e.g. a request whose authorization artifact does
not authorize the called tool / on-behalf-of). Construct both with the host
tooling used in the Phase-5 vectors (`mcps-policy` Reference profile fixtures);
the `authorization_hash` you pass to `HostSession::sign_tool_call` must match the
artifact the issuer signed.

---

## 2. The wrapping command

### 2.1 The fully-hardened invocation

This mirrors `full_stack_test::spawn_proxy` flag-for-flag, adds Phase-5 authz, a
durable replay cache, env minimization, an explicit working dir, stderr caps, and
rlimits, and wraps the real `intelli_code_mcp` inner.

```bash
bazel run //mcps-proxy:mcps_proxy_cli -- \
  --bind 127.0.0.1:8443 \
  --audience did:example:server-1 \
  --server-signer did:example:server-1 \
  --server-key-id server-key-1 \
  --key-source file \
  --signing-key-seed   "$KEYDIR/signing.seed" \
  --tls-cert           "$KEYDIR/server-chain.pem" \
  --tls-key            "$KEYDIR/server-key.pem" \
  --client-ca          "$KEYDIR/client-ca.pem" \
  --trust              "$KEYDIR/trust.json" \
  --authz reference \
  --transport-binding exact \
  --transport-identity-source uri_san \
  --max-client-cert-lifetime 1h \
  --replay-cache file --replay-path "$STATEDIR/replay.json" \
  --inner-working-dir "$INNERWD" \
  --inner-stderr-cap-bytes 65536 \
  --inner-stderr-cap-lines 512 \
  --inner-rlimit-nofile 256 \
  --inner-rlimit-cpu-seconds 30 \
  --inner-rlimit-as-bytes 1073741824 \
  --inner-rlimit-core-bytes 0 \
  --inner-env-allow PATH \
  --inner-command "$INNER_BIN"
```

`--inner-command` **consumes the rest of argv**, so it must be last. `$INNER_BIN`
is the launcher path from §1.2; `$INNERWD` is a real, existing directory you
control (a missing dir fails startup closed). Set `$KEYDIR` / `$STATEDIR` to your
temp locations.

On startup the proxy prints the listen line, the effective inner working dir
(labelled "controlled start dir, NOT a filesystem sandbox"), the stderr caps, and
the configured rlimits (labelled "RESOURCE HARDENING, NOT a sandbox"). Those
labels are the honest-boundary statements from ADR-MCPS-016 — heed them.

### 2.2 The `bazel run` / runfiles env allowlist (the crux of check #2)

Env minimization is **on by default**: the proxy **clears** the inner's
environment and passes through only what `--inner-env` / `--inner-env-allow`
permit (`--inherit-env false` is the default). A naive `bazel run` of a
`py_binary` inner can fail to start because the launcher needs a few env vars
(typically `PATH`, and possibly runfiles-discovery vars like `RUNFILES_DIR` /
`RUNFILES_MANIFEST_FILE` / `PYTHONPATH` depending on how the launcher is invoked).

**The correct fix is to ALLOWLIST exactly those vars, not to disable
minimization** (`--inherit-env true` re-opens the env-leak the test
`secret_in_proxy_env_is_not_visible_to_inner_by_default` exists to prevent).

**Two ways to launch the inner, in order of preference:**

1. **Built launcher path (recommended).** Use `$INNER_BIN` from §1.2 directly as
   `--inner-command`. A Bazel-built `py_binary` launcher generally only needs
   `PATH` (to find the interpreter) and bootstraps its own runfiles tree relative
   to its own location, so `--inner-env-allow PATH` is usually sufficient. This
   keeps the protocol stream clean (no `bazel` build chatter on stdout).

2. **`bazel run` inner.** If you must use `bazel run ... -- ...` as the inner
   command, be aware `bazel run` emits build/run diagnostics that can pollute
   stdout (the protocol stream); prefer the built path. If you do use it, the
   launcher will need the runfiles-discovery vars in addition to `PATH`.

**Discovery method (do NOT guess the var set).** Determine empirically which vars
the launcher needs to start under a cleared environment:

```bash
# Reproduce env-minimization for the inner ALONE (cleared env), then add vars
# back one at a time until it starts and emits a clean JSON-RPC frame on stdout.

# (a) Confirm it FAILS with a fully-cleared environment:
env -i "$INNER_BIN" </dev/null

# (b) Add PATH only and retry:
env -i PATH="$PATH" "$INNER_BIN" </dev/null

# (c) If it still cannot find runfiles, add the runfiles-discovery vars Bazel set
#     for THIS process (inspect them first), one at a time:
env | grep -E '^(PATH|RUNFILES_DIR|RUNFILES_MANIFEST_FILE|PYTHONPATH)='
env -i PATH="$PATH" RUNFILES_DIR="$RUNFILES_DIR" "$INNER_BIN" </dev/null
```

Each var that the inner provably needs to start becomes one
`--inner-env-allow <NAME>` on the proxy command (the proxy passes through that
var **from its own environment**; a name absent from the proxy env fails startup
loudly). Record the final allowlist you arrived at in the recording template
(check #4). The expectation, to be confirmed by the operator, is that a
**built launcher** needs only `PATH`; a `bazel run` inner additionally needs the
runfiles-discovery var(s) surfaced above. **State the actual set you used — do
not assume.**

### 2.3 Driving the proxy (the host side)

Use `mcps-host` `HostSession` to sign requests and verify responses, exactly as
`full_stack_test::signed_request` / `verify_response` do, and present the trusted
client certificate (URI SAN == request `signer`) on the mTLS connection. You can:

- drive it from a small Rust harness that reuses `HostSession` + a rustls client
  (the test file is a copyable template — `round_trip`, `trusted_client_cert`,
  `signed_request`); or
- adapt the test itself into a throwaway binary pointed at `intelli_code_mcp`.

Send a real tool call, e.g. `tools/call` for `query_codebase` with a valid
read-only SQL argument, on behalf of a user identity, with a fresh nonce.

---

## 3. The 12 acceptance checks

Run the hardened proxy from §2.1 and drive it from §2.3. For each check, the
"observe" column is what you read off the proxy's stderr log and/or the response
the host verifies. Record each in the §4 template.

| # | Check | How to exercise + observe | Pass criterion |
| --- | --- | --- | --- |
| 1 | **Inner launched via production mechanism** | Start the proxy from §2.1. Watch its startup stderr: `mcps-proxy: listening on 127.0.0.1:8443 (PEP; inner = [...])` and an `inner_spawned` lifecycle event on the first request. | The inner is the real `intelli_code_mcp` `mcp_server`, spawned by `mcps_proxy_cli` via `SubprocessInner` (per-request spawn), not started by hand. |
| 2 | **`bazel run` / built inner starts under env-minimization (allowlist, not disable)** | Use the §2.2 allowlist (e.g. `--inner-env-allow PATH`) with the **default** `--inherit-env false`. Send a request; the inner must start and answer. | The inner starts and produces a valid protocol frame **with** minimization on and **without** `--inherit-env true`. Record the exact allowlist used. |
| 3 | **Explicit working dir** | Pass `--inner-working-dir "$INNERWD"`. Read the startup line `inner working dir = $INNERWD (controlled start dir ...)`. | The effective working dir is the explicit `$INNERWD`, never silently the proxy's cwd. (A bogus dir must fail startup — optional negative spot-check.) |
| 4 | **Required env allowlisted, not inherited** | With `--inherit-env false`, confirm the inner sees **only** the allowlisted vars. Spot-check: put a secret-looking var in the proxy env (as an env KeySource would) and confirm the inner cannot see it. | The inner runs with only the §2.2 allowlist; non-allowlisted proxy vars (incl. any secret) are **not** visible to the inner. |
| 5 | **Caller-supplied `.verified` is stripped** | From the host, send a `tools/call` that maliciously includes its own `_meta["se.syncom/mcps.verified"]` block (forged context). | The inner receives the **proxy-injected** `.verified`, not the caller's — the caller's block is discarded regardless of its contents (proxy `build_forwarded_request` strips then injects). |
| 6 | **Sidecar-injected `.verified` reaches the inner** | Send a valid signed+authorized request. Have the inner echo / log the `_meta` it received (or read it via a tool that surfaces `_meta`). | The inner's request `_meta` contains `se.syncom/mcps.verified` with `verified_signer`, `key_id`, `on_behalf_of`, `audience`, `request_hash`, etc., derived only from the verification result. |
| 7 | **Valid signed + authorized request succeeds** | Valid client cert (URI SAN == signer), request signed by the matching signer, valid `authorization_hash`, fresh nonce, called via mTLS. | The host receives a non-error response; the inner produced a real `query_codebase` result; the proxy logged `inner_request_forwarded` + `inner_response_signed`. |
| 8 | **Invalid signature rejected before the inner** | Tamper one byte of the signed request body after signing (e.g. mutate an argument), keep the cert valid. | Response error message is `mcps.invalid_signature`; **no** `inner_spawned` for this request — rejection precedes dispatch. (Matches `full_stack_test` case 4.) |
| 9 | **Failed Phase-5 authorization rejected before the inner** | Send a validly-signed request whose authorization artifact does **not** authorize the called tool / `on_behalf_of` (or omit/garble the `authorization_hash` binding) with `--authz reference` on. | Response is a `mcps.*` authorization-failure error; the inner is **not** invoked for this request. |
| 10 | **Response signed by the proxy/server side** | On the happy path (#7), inspect the response bytes. | The response carries the `se.syncom/mcps.response` block; `server_signer` == `--server-signer`; signature verifies against the server key in the resolver. |
| 11 | **`HostSession` verifies the response via `request_hash` correlation** | Call `session.verify_response(&response_bytes, &resolver)` on the host for the #7 response. | `verify_response` succeeds: the response's `request_hash` equals the **stored** hash for that JSON-RPC id, and the server signature verifies. A response over a wrong hash must fail `mcps.response_hash_mismatch` (optional negative spot-check). |
| 12 | **stderr captured separately, stdout protocol-clean** | Drive any request; inspect the proxy's stderr log vs the bytes returned as the protocol response. | Inner stderr appears only in the proxy's bounded structured log (never on the protocol stream); the protocol response is a clean JSON-RPC frame with no inner stderr bleed. If the inner is noisy past the cap, an `inner_stderr_truncated` event is emitted. |

> Checks #8 and #9 are the "rejected before the inner" guarantees — confirm by
> the **absence** of an `inner_spawned` lifecycle event for that request in the
> proxy log, not just by the error message.

---

## 4. Recording template

Fill this in as you execute. The completed table (plus saved proxy-stderr
excerpts and host-side verification output as evidence) satisfies the
**"recorded"** acceptance criterion of. Save evidence artifacts alongside
this file or attach them to the issue.

| Check | Pass / Fail | Evidence / notes (log excerpt, error message, file ref) | Date | Operator |
| --- | --- | --- | --- | --- |
| 1 — inner launched via production mechanism | | | | |
| 2 — inner starts under env-minimization (allowlist used: `____`) | | | | |
| 3 — explicit working dir | | | | |
| 4 — required env allowlisted, not inherited | | | | |
| 5 — caller `.verified` stripped | | | | |
| 6 — sidecar `.verified` reaches inner | | | | |
| 7 — valid signed + authorized succeeds | | | | |
| 8 — invalid signature → `mcps.invalid_signature` (no spawn) | | | | |
| 9 — failed Phase-5 authz rejected (no spawn) | | | | |
| 10 — response signed by server side | | | | |
| 11 — `HostSession` verifies via `request_hash` | | | | |
| 12 — stderr separate, stdout protocol-clean | | | | |

**Environment recorded:** commit SHA `________`, `bazel` version `________`,
inner launcher path `________`, final `--inner-env-allow` set `________`, OS
`________`.

**Overall sign-off:** all 12 PASS? `Yes / No` — operator `________`, date
`________`.

---

## 5. References

- Mechanical reference (authoritative): [`full_stack_test.rs`](../mcps-proxy/tests/full_stack_test.rs)
- CLI flag semantics: [Sidecar Deployment Guide](sidecar-deployment-guide.md)
- TLS / mTLS / binding / KeySource / replay: [Transport Hardening Guide](transport-hardening-guide.md)
- Host signing + response verification: [Host Integration Guide](host-integration-guide.md)
- Verified-context keys + verification pipeline: [MCP-S Core Specification](spec/mcps-core-spec.md)
- Inner: `intelli_code_mcp` (author's private monorepo; not in this repository)
</content>
</invoke>
