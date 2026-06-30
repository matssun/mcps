# MCP-S Python SDK (`mcps-sdk`)

Runtime-evidence security for the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):
signed requests and verified responses, added without changing application code.

> **Status: scaffold (issue #199, ADR-MCPS-044).** The structure, the build
> wiring, and the security pipeline contract are in place. The native bindings
> and the transport bodies are stubbed (`NotImplementedError` / `TODO(#199)`).
> The one thing that works today is the PyO3 link to the audited core
> (`test_core_link`).

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
- **Streamable HTTP has three inbound decode sites** (direct JSON, POST-SSE,
  standalone-GET SSE) — all must route through verification.
- **Server-initiated messages** (sampling / roots / notifications) aren't
  responses to a correlated request, so the `request_hash` binding doesn't cover
  them; the adapter needs an inbound policy for them.
- **Transport-as-dispatcher rework** upstream may move the integration seam.

See ADR-MCPS-044 §SDK wrap-or-fork rule and issue #199.
