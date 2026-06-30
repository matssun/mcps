# MCP-S walkthrough — the persona ladder

A ladder of small, runnable demos. Each rung adds **one** security concept and is
a real test you can read and run. Start at the top; stop wherever your needs are
met.

Every rung runs the **real four-hop topology** as separate OS processes — nothing
is faked:

```
ordinary MCP client (the test)
  │  plain MCP JSON-RPC
  ▼
mcps-client-proxy-cli   ── signs a draft-02 envelope, dials mTLS ──┐
                                                                    │
mcps-proxy (server PEP)  ◀── verifying mTLS over loopback ─────────┘
  │  verify draft-02 → strip → inject verified context → forward
  ▼
mcps-demo-fileserver     ── an ordinary, MCP-S-unaware MCP server
```

The local client speaks **only plain MCP**. All signing and verification live in
the two proxies; the inner server is unmodified. The channel is mTLS-on-loopback
throughout — MCP-S's guarantee is *message-level*, so the lower rungs prove it
without binding the transport identity (that's a later rung).

## The ladder

| Tier | Persona | New concept | Run |
|------|---------|-------------|-----|
| **T0** Hello, signed call | An individual, "just see it work" | object signing + response binding (authenticity), end to end | `cargo test -p mcps-walkthrough --test t0_hello_signed_call` |
| **T1** Real tools, fail closed | …maturing | real `read`/`write`/`stat`/`list` over the signed channel + a fail-closed input | `cargo test -p mcps-walkthrough --test t1_real_tools_fail_closed` |
| **T2** Internal roles | Small company, internal | scoped authorization — reader vs admin; a reader's write is **denied before dispatch** | `cargo test -p mcps-demo --test demo_scope_test` |
| **T3** External users | Small company, external | mTLS identity binding (`--transport-binding exact`) + a server-name negative + the cross-process received-log deny proof | `cargo test -p mcps-walkthrough --test t3_external_users_transport_binding` |
| **T4** Enterprise key custody | Larger enterprise | client + server signing keys in cloud KMS (non-exporting) | `./scripts/test-gcp-cloud.sh.example` (copy to `work/`, fill in your project) |

T0–T3 run offline with `cargo test`. T0, T1, and T3 run the real four-hop; T2 is
currently demonstrated in-process in `mcps-demo` (`demo_scope_test`), with its
four-hop variant to follow. T4's new capability — a non-exporting Cloud KMS
**client** signer (`mcps-client-proxy-cli --key-source gcp-kms`, feature
`gcp_kms`) — is proven offline against the unmodified `mcps-core` verifier
(`cargo test -p mcps-client-proxy-cli --features gcp_kms`) and validated end to
end against a live cloud project via the script above. A tracked-file leak guard
(`cargo test -p mcps-walkthrough --test no_tracked_secrets`) keeps real project
identifiers out of the repo.

## How a rung is built

Each test calls `FourHop::launch()` (see `src/lib.rs`), which mints ephemeral
mTLS material (`DemoFixtures`), spawns both proxies pointed at a writable demo
root, and exposes `call(plain_request) -> plain_response`. Everything is wiped on
drop. Read one test top-to-bottom — that's the whole demo.
