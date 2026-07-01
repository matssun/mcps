# MCP-S Python SDK (`mcps-sdk`)

Runtime-evidence security for the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):
signed requests and verified responses, added without changing application code.

> **Status (issue #199, ADR-MCPS-044).** The full client obligation is bound and
> tested over the audited `mcps-client-core` via PyO3: request signing
> (`sign_request`), custody/signer policy (`Signer` / `SignerPolicy`), response
> verification (`verify_response` / `TrustResolver`), in-flight correlation
> (`CorrelationStore`), and the **transport adapter** (`McpsTransport` / `connect`)
> that signs/verifies at the byte boundary so `mcp.ClientSession` speaks plain MCP.
> 91 tests pass, all parity against independent `mcps-client-core` oracle vectors —
> including **three live cross-process e2es against real Rust binaries**:
> 1. **stdio** — the adapter drives a real `tools/call` to the real server-side
>    proxy (`mcps-stdio-server --mode proxy` = `mcps_proxy::Proxy`).
> 2. **mTLS/HTTP (raw request)** — the SDK signs a `read_file`, opens one mTLS
>    connection, and `POST`s it to the **real production `mcps-proxy`** fronting the
>    **real `mcps-demo-fileserver`**; the production-signed response is verified +
>    correlated back to a plain MCP result.
> 3. **mTLS/HTTP (full `ClientSession`)** — a real `mcp.ClientSession` runs
>    `initialize()` then `call_tool("read_file")` over `connect_mtls_http`, mapping
>    ClientSession's stream model onto the proxy's one-POST-per-connection wire
>    (step ii). `initialize` round-trips as a signed request; client→server
>    notifications are dropped (no fire-and-forget channel); a rejected response is
>    delivered as a JSON-RPC error correlated to the request id so the awaiting call
>    raises rather than hangs. All three have a fail-closed live negative.
>
> **Multi-path inbound decode + server-initiated policy (done).** `streamable.py`
> decodes all three streamable-HTTP inbound sites (direct JSON, POST-SSE,
> standalone GET-SSE) to JSON-RPC payloads and routes EVERY one through the same
> verification. Server-initiated messages (a server→client request/notification)
> carry no `request_hash`, so the core cannot verify them and draft-02 defines no
> evidence for this direction. **Strict MCP-S is the client-initiated
> request/response subset:** the inbound policy **fails closed** by default
> (`mcps.missing_envelope` / `mcps.notification_forbidden`).
> `allow_unverified_server_initiated` is a **degraded/migration opt-out only**
> (delivered, audited as no-evidence) — never strict MCP-S. A future v0.8 profile
> (stateless multi-round-trip continuation) will fold request-associated elicitation
> (`InputRequiredResult` → signed continuation) back into the strict request/response
> profile; **arbitrary** server push stays out of scope and fails closed.
>
> **Authorization-binding provider (done).** The signed request's
> `authorization_binding.digest_value` is now computed by the audited core from the
> ACTUAL artifact, not handed in as a constant. `authorization.py` mirrors
> `mcps-client-core::authz`: `OpaqueBytesProvider` binds the exact decoded artifact
> bytes (`base64url-no-pad(SHA-256(bytes))`, computed in Rust — checked against an
> independent stdlib-SHA-256 oracle), `AuthzSystemReferenceProvider` binds an
> external authz system's digest+reference, and `AuthorizationBindingPolicy` fails a
> route closed to permitted binding types (`mcps.authorization_binding_type_unsupported`).
> `McpsConfig.authorization` / `authorization_policy` wire a provider per request
> (called with a real `BindingRequestContext`); the live mTLS `ClientSession` e2e
> signs via `OpaqueBytesProvider` so the production proxy accepts a real-evidence
> digest. The raw `binding_digest_*` kwargs remain as a documented dev/test shortcut.
>
> **Non-exporting custody (done).** `Signer.non_exporting(signer_id, key_id,
> sign_callback)` is a signer whose private key NEVER enters the SDK — it holds only
> a `preimage -> signature` callback (a KMS/HSM client call in production). Custody is
> `NonExporting`, the only class `SignerPolicy.require_non_exporting()` accepts.
> `SigningDevice.from_seed(...)` is the HSM/KMS stand-in: it encapsulates the key and
> exposes ONLY `.sign(preimage)` (no getter). Proven both ways — the hardening
> profile rejects software/dev-file keys (`mcps.actor_binding_failed`) and accepts
> the device-delegated signer; the delegation is byte-identical to the direct
> software path (same evidence, key just moved behind the device); a device that
> can't sign fails closed; and a live mTLS test signs via the non-exporting signer
> under the **production** hardening profile, accepted by the real `mcps-proxy`.
> **Remaining:** an incremental SSE *streaming* transport (consuming events on a
> long-lived connection — the decoder is the layer it plugs into) and pinning
> upstream `mcp`.
>
> Transport/e2e tests need `mcp` (Python ≥ 3.10): `uv venv --python 3.12 .venv312`.
> The stdio e2e needs `cargo build -p mcps-conformance --bin mcps-stdio-server`; the
> mTLS e2e needs `cargo build -p mcps-proxy -p mcps-demo-fileserver` + cargo (to mint
> `DemoFixtures` material). All skip cleanly if absent.

## Why this exists, and why it's an *adapter*

MCP-S is a two-sided protocol: the client must sign the **exact** canonical
outbound bytes before they leave the process and verify the **exact** inbound
response bytes before the app parses them. The `mcps-client-proxy` already does
this as a sidecar; this SDK does it **in-process**.

The wrap-or-fork spike found that the MCP Python SDK serializes JSON-RPC *inside*
each transport — the anyio stream between `ClientSession` and the transport
carries already-parsed pydantic objects, not bytes. So the only seam with
exact-byte control is the transport itself. Per ADR-MCPS-044 this is the
**transport-adapter** path (not a transparent wrapper): we ship our own
implementation of the SDK's public `Transport` protocol.

```
application code
  -> mcp.ClientSession        plain MCP; unaware of MCP-S
  -> McpsTransport (this SDK)  signs outbound bytes / verifies inbound bytes
  -> mcps_sdk._core (PyO3)     the AUDITED mcps-client-core logic, in Rust
  -> remote MCP-S server / proxy
```

## Why PyO3, not pure Python

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcps-client-core` crate — the same code the proxy uses. Binding to it (rather
than reimplementing it in Python) guarantees the canonical signed preimage is
byte-identical across SDK and proxy, by construction, and means a draft-spec
change is edited in one place. The Python you actually touch — the transport
adapter, `connect()`, policy, tests — stays plain Python. End users `pip install`
a prebuilt `abi3` wheel and need no Rust toolchain.

## Layout

```
sdk/python/
  Cargo.toml             # PyO3 cdylib -> mcps_sdk._core; OWN workspace (separate from root)
  src/lib.rs             # the binding (constants now; sign/verify/enforce next)
  pyproject.toml         # maturin backend, mixed Rust/Python layout
  python/mcps_sdk/
    __init__.py          # public surface
    transport.py         # McpsTransport — the pipeline mirroring proxy.rs::handle
    client.py            # connect() helper over ClientSession
  tests/
    test_parity_stdio.py # byte-parity gate vs the Rust proxy (#199)
```

## Develop

```sh
cd sdk/python
python -m venv .venv && . .venv/bin/activate
pip install -U maturin pytest
maturin develop            # builds mcps_sdk._core against the in-repo Rust crates
pytest                     # test_core_link runs; parity tests skip until impl
```

## Known open work (from the spike)

- **Pin upstream `mcp`.** The package is mid-refactor (the v1 session layer was
  removed; message types moved to `mcp_types`). Pin to an exact version once the
  transport seam stabilizes.
- ~~**Streamable HTTP has three inbound decode sites** (direct JSON, POST-SSE,
  standalone-GET SSE) — all must route through verification.~~ Done: `streamable.py`
  (`decode_inbound` / `verify_inbound_messages`). Remaining is the incremental SSE
  *streaming* transport that consumes a long-lived connection.
- ~~**Server-initiated messages** (sampling / roots / notifications) aren't
  responses to a correlated request, so the `request_hash` binding doesn't cover
  them; the adapter needs an inbound policy for them.~~ Done: fail-closed inbound
  policy (the core cannot verify them — no `request_hash`), opt-out via
  `McpsConfig.allow_unverified_server_initiated`.
- **Transport-as-dispatcher rework** upstream may move the integration seam.

See ADR-MCPS-044 §SDK wrap-or-fork rule and issue #199.
