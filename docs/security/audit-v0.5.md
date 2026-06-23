<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Code & Security Re-Audit — 0.5

> **Note for public-repo readers.** This is the audit record for the 0.5
> proposal-readiness release, produced by the same multi-agent review workflow
> as the prior rounds. Like the 0.2/0.3/0.4 rounds, it ran **Stage 1+2 only**
> (deterministic find + false-positive filter, reconciled against the
> cross-round [`finding-ledger.jsonl`](finding-ledger.jsonl)) — the expensive
> Stage-3 3-skeptic verify gate was **not** run for this round.

| Field | Value |
|---|---|
| Audit date | 2026-06-23 |
| Subject | MCP-S Rust workspace |
| Revision audited | `main @ 622ee5f` (release commit `afe9a43` is the docs/version bump only) |
| Target version | 0.5.0 |
| Predecessor | [0.2 re-audit (2026-06-02)](./audit-v0.2.md) |
| Scope | **Delta** since the ledger seed `32f1430` — the 12 changed security-relevant source files |
| Stages run | Stage 1 (find, security lens) + Stage 2 (ledger-reconcile + false-positive filter). **No Stage-3 verify gate.** |
| Engine | Claude Opus multi-agent workflow (`wf_3f30cfe3-0cf`, 13 agents, ~456K tokens, ~2 min) |
| Standard | High-assurance — hostile client **and** hostile inner server, plus network MITM |
| **Result** | **No additional Critical / High / Medium / Low findings.** |

---

## 1. Result

**No additional findings in the Critical-to-Low range were found.** This run was
performed immediately before the 0.5 version/tagging session, against
`main @ 622ee5f`, scoped to the delta since the cross-round ledger seed
(`32f1430`). Every candidate surfaced by the find stage was either out of scope
(a hard-excluded DoS class) or already dispositioned in the
[finding ledger](finding-ledger.jsonl); none survived the false-positive filter
as a new, reportable vulnerability.

| Severity | New findings (this round) |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

## 2. Scope & method

This was a **delta round**: the audited surface is only the code that changed
between the ledger seed `32f1430` and the audited head `622ee5f` — the 12
changed security-relevant source files, predominantly the 0.5 security-fix
commits themselves (OCSP DNS-rebinding pin #128, OCSP freshness #136,
verify-before-return at the PKCS#11/KMS signer seams #137/#138, per-method
key-reference scope #133, LB-assertion transport binding #135, bounded
replay-cache growth #140, non-positive-TTL rejection #142):

```
mcps-core/src/audit.rs            mcps-proxy/src/durable_replay.rs
mcps-core/src/crypto.rs           mcps-proxy/src/etcd_store.rs
mcps-core/src/pipeline.rs         mcps-proxy/src/kms_keysource.rs
mcps-policy/src/reference.rs      mcps-proxy/src/ocsp.rs
mcps-proxy/src/pkcs11_keysource.rs mcps-proxy/src/proxy.rs
mcps-proxy/src/redis_store.rs     mcps-proxy/src/shared_replay.rs
```

Conformance `tests/` and `mcps-test-paths` were excluded as test code.

Each changed file was audited by an independent find agent under the
security lens (general / conformance / security lenses, security lens applied
here), tracing data flow from untrusted client/inner-server inputs to sensitive
operations. Every candidate finding was then passed to a parallel
false-positive / ledger-reconcile agent that (a) confirmed or refuted the
exploit path from source and (b) reconciled the finding against
[`finding-ledger.jsonl`](finding-ledger.jsonl) — suppressing anything already
dispositioned (false-positive / accepted-risk / fixed / positive-control) and
flagging any resurfaced `fixed` finding as a regression.

## 3. Dispositioned candidate

One candidate was raised and **suppressed** on two independent grounds:

| File | Title | Disposition | Why |
|---|---|---|---|
| `mcps-proxy/src/durable_replay.rs` | Global `MAX_ENTRIES` ceiling lets a client wedge the replay cache into a restart-persistent fail-closed state | Suppressed (not reported) | (1) DoS / resource-exhaustion — a hard-excluded class; (2) reconciled as **tracked** against the ledger (the bounded-growth tradeoff was dispositioned when the #140 prune cap landed). |

## 4. Caveat

A clean Stage-1+2 result means *"no new finding survived the false-positive
filter,"* **not** *"verified clean by the 3-skeptic gate."* Consistent with the
documented methodology, the audited surface for this round is mostly remediation
code already reconciled against the ledger, so a no-new-finding outcome is the
expected result. A full verified (Stage-3) re-audit may be scheduled against a
future revision per
[`README.md`](README.md#how-to-extend-this-record).
