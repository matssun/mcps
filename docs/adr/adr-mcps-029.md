<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-029: Wire Signed-Manifest Enforcement into the Proxy Dispatch Path

## Status

**Superseded by [ADR-MCPS-030](adr-mcps-030.md) (2026-06-21).** This ADR proposed
making the proxy parse `tools/list` and enforce signed tool manifests on the
dispatch path. On review, that crosses MCP-S Core from message security into MCP
tool-catalog governance — a separate, actively-evolving MCP domain. ADR-MCPS-030
keeps MCP-S Core method-transparent and relocates tool-catalog integrity to a
separate MCP extension (`mcp-tool-catalog-integrity`). **This design was never
implemented**, and the `ManifestVerifier` / `ManifestPinStore` subsystem it
referenced has been removed from `mcps-policy`. The text below is retained as the
historical record of the rejected approach.

_Original status — Proposed (v0.4 — 2026-06-21), DESIGN ONLY, NOT YET IMPLEMENTED;
implementation was tracked by issue #118. The `ManifestVerifier` / `ManifestPinStore`
/ `RevocationSource` subsystem (issue #3866) was implemented and unit-tested in
`mcps-policy` but never wired into any production dispatch path. This ADR was the
deferred follow-up that ADR-MCPS-017 named (*"signed tool manifests … each
requiring its own ADR / threat model"*); it decided the interception point,
operator config surface, durable pin-store design, and the fail-closed response to
a manifest verification failure / rug pull._

## Context

The signed-tool-manifest subsystem exists and is correct, but unreachable:

- **#84** — `ManifestVerifier` / `ToolManifest` have no production caller; the
  only non-test references are the four `pub use` re-exports in
  `mcps-policy/src/lib.rs`.
- **#87** — the entire `ManifestVerifier::verify` pipeline
  (`ManifestVerifier::verify` in `mcps-policy/src/manifest_verifier.rs`) is dead code outside
  `#[cfg(test)]`. The verifier itself is sound and well-tested: schema-hash bind,
  identity self-consistency, Ed25519 signer resolution, manifest revocation,
  symmetric-clock-skew validity window, DoS breadth/size bounds, TOFU rug-pull
  pin, and deny-before-commit. The defect is purely that nothing calls it on the
  live path. (The two LOW items in #87 — clock-skew tolerance and the redundant
  top-level `key_id` — are already addressed in the verifier: the window now uses
  symmetric `MAX_CLOCK_SKEW_SECS` and `key_id` self-consistency is enforced in
  `manifest_verifier.rs`.)
- **#86** — the only `ManifestPinStore` impl is `InMemoryManifestPinStore`
  (`InMemoryManifestPinStore` in `mcps-policy/src/manifest_pin.rs`, a `BTreeMap`). Rug-pull detection is
  trust-on-first-use, so an in-memory store resets every restart: a restarted
  proxy silently re-trusts a rug-pulled schema as a fresh first sighting. No
  `DurableManifestPinStore` exists.

**Why this is not mechanical wiring — the crux.** The proxy is *byte-transparent
to MCP response semantics*. `Proxy::handle_with_transport` →
`dispatch_and_sign` (`mcps-proxy/src/proxy.rs`) →
`build_signed_response` (`mcps-proxy/src/proxy.rs`) forwards the inner
server's `result` opaquely: it normalizes the result *shape* (object / scalar /
inner-error) and signs it bound to the verified `request_hash`, but it **never
inspects `tools/list` result content**. There is no tool-listing model, no schema
concept, nowhere a manifest is fetched or compared. The SEP-2243 routing headers
(`mcp-method` / `mcp-name`, `transport.rs`) are **untrusted hints** the proxy
explicitly does *not* route on (ADR-MCPS-025) — so the interception point cannot
key off the `mcp-method` header. `VerifiedRequest`
(`mcps-core/src/pipeline.rs`) does not carry the JSON-RPC `method` either.

So introducing manifest enforcement is a substantial new feature: identify
`tools/list` responses from authoritative (signed-body) data, parse the tool
array, obtain and verify the server's signed manifest, recompute each tool's
schema hash against the live listing, pin, and fail closed on mismatch. None of
that scaffolding exists, and the failure-response decision is a security-policy
call that no existing ADR makes. That decision is this ADR.

## Definitions

- **`signed tool manifest`** — the operator-supplied, Ed25519-signed
  `ToolManifest` (`mcps-policy/src/manifest.rs`) attesting the
  `(name, version, schema_hash)` set a given inner server is permitted to expose.
- **`schema_hash`** — `sha256_hash_id(canonicalize(schema))` over a tool's
  combined `{input, output}` JSON Schema; the value the verifier recomputes and
  pins.
- **`rug pull`** — an inner server that, after a first trusted sighting, serves a
  *changed* schema under an *unchanged* `(name, version)`. TOFU pinning detects
  it only if the first-trusted pins survive process restarts — hence the durable
  store.
- **`manifest enforcement`** — the live-path act of verifying the operator's
  signed manifest and asserting the inner server's live `tools/list` advertised
  tool set matches the verified, pinned `(name, version, schema_hash)` set,
  fail-closed.
- **`ManifestPinStore`** — the `mcps-policy` trait
  (`manifest_pin.rs`, `check_and_record`) the verifier mutates to record TOFU
  pins; the durable impl persists this state across restarts.

## Decision

Enforce signed tool manifests on the live proxy dispatch path via an
operator-supplied signed manifest, a durable pin store, and a **fail-closed**
rejection of any verification failure / rug pull / revoked manifest. Enforcement
is **opt-in** and configured through a flag surface that mirrors the existing
`--trust` / `--revocation-list` / `--replay-cache` patterns.

### 1. Interception point and message model (resolves the #84/#87 crux)

**Decided: operator-supplied signed manifest, verified against the live
`tools/list` — option (b) of #118.** The proxy stays method-agnostic on routing
(it does not trust `mcp-method`); enforcement reads the **authoritative
signed-body method** instead.

- **Where.** A dedicated `verify_tools_list` step inside `dispatch_and_sign`
  (`dispatch_and_sign` in `mcps-proxy/src/proxy.rs`), invoked **only when manifest enforcement is
  configured**. `dispatch_and_sign` already holds `request_bytes` (the
  verify-validated request body) and `inner_response`; the manifest check sits
  between the `inner.dispatch(&forwarded)` call and `build_signed_response`. This
  keeps the byte-transparency of `build_signed_response` intact for every other
  method and confines all `tools/list`-shape coupling to the new step.
- **How the method is identified.** From the **verified request body**
  (`request_bytes`, the same bytes `verify_request` validated — its signature
  covers `method`), *not* from the untrusted `mcp-method` routing header. The step
  fires only when that authoritative method is `tools/list`.
- **What is compared.** Parse the inner `tools/list` `result.tools[]` into the
  live `(name, version, schema_hash)` set (recomputing each `schema_hash` the same
  way the verifier does). Load the operator-supplied signed manifest, verify it
  via `ManifestVerifier::verify`, and assert the live set **equals** the verified
  manifest's `(name, version, schema_hash)` set (no missing, no extra, no
  schema-diverged tool). The manifest is consumed through the dup-key-rejecting
  wire-entry seam `parse_manifest_bytes(&[u8])` (in `mcps-policy/src/manifest.rs`,
  `deny_unknown_fields`).
- **Why (b) not (a).** Option (a) — intercept and trust `mcp-method == tools/list`
  — couples the proxy's routing to an untrusted header and to the MCP listing
  shape on the hot path for every method. Option (b) confines the shape-coupling
  to one configured step keyed off authoritative data, and the manifest signer is
  a *distinct* trust anchor from the request signer (below), which (a) conflates.

### 2. Failure response — **fail-closed** (the load-bearing security decision)

On ANY `ManifestError` (bad signature / unresolved signer / revoked manifest /
expired window / rug-pull pin mismatch / size-bound breach) **or** a live-set
mismatch against the verified manifest, the proxy **replaces the `tools/list`
response with a signed JSON-RPC error and never returns the inner listing.**

- **Decided: fail-closed rejection.** Consistent with every other proxy deny
  (`json_rpc_error_object` for authorization / replay / response-signature
  failures): the error object is signed and request-hash-bound through the same
  path, so the client gets a verifiable deny, not an unsigned pass-through.
- **Rejected: drop-the-tool.** Silently stripping the offending tool from the
  listing hides a live attack (a rug pull is evidence of a compromised or hostile
  inner server, not a benign drift) and yields a *partial* listing the client
  cannot distinguish from a legitimate one. A rug pull on one tool is reason to
  distrust the whole listing.
- **Rejected: audit-only.** Logging-without-blocking leaves the rug-pull /
  forged-manifest path reachable in a "deployed with enforcement on" posture,
  which is exactly the false-assurance #84/#87 warn against.

This is the key decision requiring sign-off. The recommendation is **fail-closed
rejection** because the entire MCP-S value proposition is that a client's
integrity guarantees do not depend on what a hostile inner server returns;
silently degrading on a manifest failure would re-open that gap.

### 3. Trust anchor and revocation provenance

- **Manifest signer trust:** a **separate `--manifest-trust <path>`** anchor set
  (a `TrustResolver` over the manifest-signer keys), *not* the request-signer
  `--trust` anchor. Manifest-signing identity (who attests the tool set — an
  operator / publisher role) is distinct from request-signing identity (who calls
  the proxy), and conflating them would over-grant.
- **Manifest revocation:** a **separate `--manifest-revocation <path>`**
  (repeatable / comma-separated), reusing the offline deny-list *shape* of
  `--revocation-list` but a distinct source, so revoking a manifest does not
  perturb request-signer revocation and vice-versa.

### 4. Durable pin store (closes #86)

Add `DurableManifestPinStore` in `mcps-proxy/src/`, mirroring
`mcps-proxy/src/durable_replay.rs` (`DurableReplayCache`) **exactly**:

- **State.** `BTreeMap<String /*name*/, (version, schema_hash)>` persisted as a
  JSON array.
- **`open(path)`** loads existing pins; a corrupt / malformed / wrong-shape file
  **fails closed** (as `DurableReplayCache::open` does), never loads as empty.
- **Every `check_and_record` mutation persists atomically** via the
  `durable_replay.rs::persist` sequence: write a temp file, `sync_all` (flush data
  + metadata to stable storage) **before** the atomic `rename`, then fsync the
  containing directory **after** the rename so the rename itself is durable. On
  persist failure the in-memory pin is **rolled back** and the error surfaces as a
  fail-closed `ManifestError`, so a transient failure can be retried and a partial
  write is never observed.
- **Trait.** Implements the existing `mcps_policy::ManifestPinStore` trait
  (`manifest_pin.rs`) so it drops into `ManifestVerifier::verify` unchanged.
- **Lean-sync firewall (ADR-MCPS-011/012).** Sync `std::fs` only — **no async, no
  tokio, no vendor SDK.** `mcps-core` purity is untouched; this store lives in
  `mcps-proxy`, exactly like `DurableReplayCache`.
- **TOFU-survives-restart.** Because pins are fsync-persisted and re-read on
  `open`, a restarted proxy remembers the first-trusted schema and a post-restart
  rug pull is rejected — the durability gap #86 names is closed.

### 5. Operator config surface (mirrors `mcps-proxy/src/cli.rs`)

Wiring is offered through a `Proxy::with_manifest_enforcement(verifier, resolver,
revocation, pin_store, manifest_bytes)` builder seam, mirroring
`with_policy_enforcement` / `with_lb_assertion`
/ `with_replay_cache` (all in `mcps-proxy/src/proxy.rs`). The CLI flags mirror the established
patterns:

| Flag | Mirrors | Meaning |
|---|---|---|
| `--manifest <path>` | `--authz` policy file | the operator-supplied signed manifest to enforce against |
| `--manifest-trust <path>` | `--trust` | trust anchors for manifest **signers** (distinct from request signers) |
| `--manifest-revocation <path>` (repeatable / comma-separated) | `--revocation-list` | manifest revocation deny-list |
| `--manifest-pin-store <path>` | `--replay-path` (`--replay-cache file`) | durable pin-store file |
| `--allow-empty-manifest-revocation` | `--allow-empty-revocation` | explicit ack to enforce with an empty manifest deny-list |

Enabling enforcement without `--manifest` (or without `--manifest-pin-store`) is
refused at CLI validation — the same dangling-flag, fail-closed posture
`mcps-proxy/src/cli.rs` already applies to `--replay-cache file` requiring
`--replay-path` and `--authz reference` requiring its acknowledgements. The
durable store is the production tier; the in-memory store remains **test-only**.

### 6. Strict-mode interaction

Under `--strict` / `--production` (`mcps-proxy/src/cli.rs`), **if a `--manifest` is
configured, the durable `--manifest-pin-store` is REQUIRED** — strict mode must
not silently run rug-pull protection against an in-memory store that forgets pins
on restart. Whether `--strict` should make manifest enforcement *mandatory*
(refuse to start without `--manifest`) is left as an **open question for sign-off
(below)**: the conservative default is to keep enforcement opt-in but, once
enabled, hardened — consistent with how `--strict` refuses to enable
`lb-assertion` silently rather than forcing it on.

### 7. Conformance vectors (added with the implementing PR, not here)

A `mcps-conformance` target driving the LIVE proxy dispatch path that asserts:

1. **clean accept** — a signed manifest whose `(name, version, schema_hash)` set
   matches the inner server's `tools/list` is accepted and the listing is
   returned (signed as today);
2. **forged-signature / bad-signer reject** — a manifest with an invalid
   signature or a signer absent from `--manifest-trust` is rejected end-to-end
   (signed JSON-RPC error, inner listing suppressed);
3. **rug-pull-across-restart reject** — same `(name, version)`, schema changed
   after a first trusted sighting, asserted **across a pin-store reopen** to prove
   durability — rejected;
4. **manifest-revoked reject** — a manifest whose id is on the
   `--manifest-revocation` deny-list is rejected.

The implementing PR adds the target to
`mcps-conformance/conformance_manifest.json`, bumps the count to the new list
length, and keeps `drift_guard` green. **No `conformance_manifest.json` change is
made in this design PR.**

## Threat Model

- **Trust boundary:** one operator running the proxy; the inner MCP server is
  *not* trusted to be honest about the tool set it advertises (it may be
  compromised or hostile). The manifest signer is a distinct, operator-controlled
  attesting identity.
- **Primary threat:** a compromised / hostile inner server performs a **rug
  pull** — advertising a tool whose schema has silently changed under an unchanged
  `(name, version)` — or presents an **unsigned / forged manifest**, to get the
  client to call a tool with attacker-altered semantics. Defeated by:
  schema-hash binding + manifest signature verification (so an unsigned/forged
  manifest never resolves), TOFU pinning against the **durable** store (so a
  changed schema after first trust is caught even across restart), and
  fail-closed rejection of the listing on any mismatch.
- **Restart-amnesia threat (#86):** an attacker who can force / await a proxy
  restart hopes the pins reset so the rug-pulled schema is re-trusted as a fresh
  first sighting. Defeated by the durable, fsync-persisted, reopen-on-start pin
  store.
- **Untrusted-routing-header threat:** an attacker sets `mcp-method: tools/list`
  (or omits it) to dodge or trigger the interception. Defeated because the step
  keys off the **authoritative signed-body method**, never the routing header
  (ADR-MCPS-025).
- **Manifest-revocation evasion:** a manifest whose signer key or id has been
  compromised is denied via `--manifest-revocation`, on a source distinct from
  request-signer revocation so the two cannot mask each other.
- **DoS at the trust boundary:** a hostile-but-resolvable manifest with an absurd
  tool count or enormous schema blobs is bounded by the verifier's existing
  `MAX_TOOLS` / `MAX_TOOL_SCHEMA_BYTES` / `MAX_TOTAL_SCHEMA_BYTES` checks before
  any per-tool work.
- **Residual — external pin-store rollback (mirrors `DurableReplayCache`):**
  restoring the pin-store file from a stale snapshot / backup re-opens a TOFU
  window for the rolled-back interval — there is no monotonic counter or external
  anchor to detect it. Same caveat the durable replay cache documents; mitigate by
  not restoring the pin file from stale snapshots. Recorded here, not solved here.
- **Scope boundary (purity / firewall preserved):** this ADR does **not** loosen
  `mcps-core` purity or the ADR-MCPS-011/012 lean-sync firewall; any networked
  manifest-revocation source would have to be sync `ureq`, feature-gated, with no
  async/tokio/vendor-SDK — and is not introduced here (the offline deny-list is the
  v0.4 source).

## Conformance Vectors (ADR-MCPS-011)

- Clean signed manifest matching the live `tools/list` → **accepted**, listing
  returned (and still response-signed as today).
- Forged signature / signer absent from `--manifest-trust` → **rejected**
  end-to-end; signed JSON-RPC error; inner listing **suppressed** (never partially
  stripped).
- Rug pull (same `(name, version)`, changed schema) after a first trusted sighting
  → **rejected**.
- Rug pull asserted **across a pin-store reopen** (durability) → **rejected** (not
  re-trusted as a fresh first sighting).
- Revoked manifest id on `--manifest-revocation` → **rejected**.
- Interception keys off the **authoritative signed-body method**, not the
  `mcp-method` header: a forged/absent `mcp-method` does not change the verdict.
- Enforcement configured without `--manifest` or `--manifest-pin-store` → **refused
  at CLI validation** (fail closed).
- Corrupt / malformed pin-store file at `open` → **fails closed**, never loads as
  empty.
- A persist failure on `check_and_record` → in-memory pin rolled back; surfaces as
  a fail-closed error.
- Manifest enforcement does **not** bypass MCP-S request/response object-signature
  verification, nor Phase-5 (ADR-MCPS-013) authorization — it is an additional
  gate, not a replacement.

## Rationale

The verifier was deliberately built ahead of the integration decision (ADR-MCPS-017
named signed tool manifests as a deferred item *"requiring its own ADR / threat
model"*), so the gap is a gated design item, not a silent hole. The hard part is
honest: the proxy is body-transparent by design, and the cleanest place to add the
single point of MCP-shape coupling is a dedicated, configured `verify_tools_list`
step keyed off authoritative signed-body data, leaving every other method's
byte-transparency untouched. Fail-closed rejection is the only response consistent
with MCP-S's core promise — that client integrity does not depend on a hostile
inner server — and with how every other proxy deny already behaves. The durable
pin store is a near-mechanical mirror of `DurableReplayCache`, reusing a pattern
already proven and audited (MCPS-083 / audit M-8), which is why #86 is closable
with high confidence once the policy decisions land.

## Alternatives Considered

- **Intercept on the `mcp-method` routing header (option (a)).** Rejected: the
  header is an untrusted hint the proxy must not route on (ADR-MCPS-025), and it
  couples the hot path for every method to the MCP listing shape.
- **Drop the offending tool / audit-only on failure.** Rejected: both leave the
  rug-pull / forged-manifest path reachable in a "enforcement on" posture and hand
  the client a listing it cannot trust; see §2.
- **Reuse `--trust` / `--revocation-list` for manifests.** Rejected: manifest
  signer identity is distinct from request signer identity; conflating the anchors
  over-grants and entangles two revocation domains.
- **In-memory pin store in production.** Rejected: defeats rug-pull protection
  across restarts (#86); the store is test-only.
- **A networked/online manifest-revocation source now.** Rejected as scope: would
  require a sync, feature-gated `ureq` source under the lean-sync firewall — its
  own follow-up. v0.4 uses the offline deny-list.
- **Fold this into ADR-MCPS-017 / ship without an ADR.** Rejected: ADR-MCPS-017
  explicitly defers it to its own ADR with its own threat model — this document.

## Consequences

### Positive
- #3866 rug-pull and forged-manifest protection becomes reachable
  on the live path; #84/#87 (no caller) and #86 (no durable store) are closable.
- The byte-transparency of `build_signed_response` is preserved for every method
  except a single configured `tools/list` step.
- The durable pin store reuses an already-audited atomic-persist pattern.

### Negative
- A new MCP-shape-coupled step in the proxy (`tools/list` parsing) — the first
  place the proxy parses response content, confined and configured.
- One more durable file (the pin store) with the same external-rollback caveat as
  the replay cache; operators must protect it from stale-snapshot restore.

### Neutral
- Enforcement is opt-in; deployments that do not configure `--manifest` are
  unchanged. Strict mode hardens (durable store required) but does not — pending
  the open question — mandate enforcement.

## Compliance and Enforcement

`security-boundary.md` MUST state, once the implementing PR lands, that signed
tool-manifest enforcement is **opt-in**, that when enabled it is **fail-closed**
(a verification failure / rug pull / revoked manifest replaces the listing with a
signed error, never a partial or unsigned listing), that it requires a **durable**
pin store to survive restart, and that it does **not** replace request/response
signature verification or Phase-5 authorization. Until the implementing PR merges,
no document or claim may assert that manifest / rug-pull protection is enforced in
production — code review rejects any such claim, exactly as ADR-MCPS-017 requires
for deferred capabilities. The `mcps-conformance` vectors (§7) are the machine-checked
enforcement artifact; the claim-matrix row lands with them.

## Related

- ADR-MCPS-017 (single-node ceiling; **defers** signed tool manifests to "its own
  ADR / threat model" — this ADR is that follow-up)
- issue #3866 (manifest verifier, pin store, revocation, manifest
  DTOs — implemented and unit-tested; the signed-tool-manifest verifier work
  ADR-MCPS-017 deferred to "its own ADR / threat model")
- ADR-MCPS-025 (untrusted SEP-2243 routing headers — why the interception keys off
  the signed body, not `mcp-method`)
- ADR-MCPS-013 (Phase-5 authorization — not bypassed by manifest enforcement)
- ADR-MCPS-011 / ADR-MCPS-012 (conformance-as-specification; lean-sync firewall and
  `mcps-core` purity — not loosened)
- ADR-MCPS-020 (durable replay store — the `DurableReplayCache` pattern the durable
  pin store mirrors)
- Tracking issue #118 (consolidates #84, #86, #87); audit findings #84, #86, #87
- Durable-store pattern: `mcps-proxy/src/durable_replay.rs`
- Dispatch seam: `mcps-proxy/src/proxy.rs` (`dispatch_and_sign` / `build_signed_response`)
- Wire-entry seam: `parse_manifest_bytes` (`mcps-policy/src/manifest.rs`)

## Open Questions for Review

- **Strict-mode mandate.** Should `--strict` / `--production` make manifest
  enforcement *mandatory* (refuse to start without `--manifest`), or only harden it
  (require the durable pin store) when configured? §6 recommends the latter
  (opt-in but hardened); the stricter posture is the alternative for sign-off.
- **Manifest distribution beyond a file.** Is an operator-supplied file
  (`--manifest`) sufficient for v0.4, or is an out-of-band well-known method to
  fetch the inner server's signed manifest needed? This ADR decides the file
  source; a fetch mechanism would be a follow-up.
- **Live-set strictness.** Must the live `tools/list` set **equal** the manifest
  set exactly (recommended), or may the manifest be a permitted **superset** (the
  server may advertise fewer tools than attested)? Exact-match is the conservative
  default; subset-allowed is the alternative for sign-off.
- **Online manifest revocation.** Deferred: a sync, feature-gated `ureq`
  manifest-revocation source under the lean-sync firewall, if offline deny-lists
  prove insufficient — its own follow-up, not this ADR.
