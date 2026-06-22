<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Security — audits and remediation

This directory is the public record of the security review process applied to
MCP-S before its initial public release as v0.2.0.

## Documents

| File | Purpose |
|---|---|
| [`audit-v0.1.md`](audit-v0.1.md) | The 2026-06-01 multi-agent code audit of the v0.1 architecture, sanitized for public release. **3 High / 14 Medium / 36 Low / 53 Info, 0 Critical.** Overall residual-risk rating at audit time: **MODERATE**. |
| [`audit-v0.2.md`](audit-v0.2.md) | The 2026-06-02 multi-agent re-audit, three-tier (full-depth review of new code + remediation verification of v0.1 findings + core-invariant regression sweep), against the v0.2 hardening branch. **4 Critical / 15 High / 30 Medium / 59 Low / 254 Info.** Overall residual-risk rating at audit time: **HIGH**. |
| [`remediation-v0.2.md`](remediation-v0.2.md) | Finding-by-finding remediation status for the v0.2.0 source tree shipped in this repository. **All Critical, all High, and 28 of 30 Medium findings are Addressed.** 2 Mediums are Deferred to v0.3 with documented fail-mode (fail-closed, no admission impact). The v0.1 audit's four partial carry-overs are all closed. |

## The cost of rigor

Both audits were produced by the same multi-agent Claude Opus 4.8 review
workflow, operated under high-assurance scrutiny (assume hostile client AND
hostile inner server) with a 3-skeptic adversarial verification gate (≥2/3
must independently confirm a finding from source).

| Audit | Engine | Agents | Tokens | Wall-clock |
|---|---|---:|---:|---:|
| v0.1 (2026-06-01) | Claude Opus 4.8 multi-agent | 165 | 8.24M | 33 min |
| v0.2 (2026-06-02) | Claude Opus 4.8 multi-agent | 117 | 6.31M | ~31 min |
| **Total** | | **282** | **14.55M** | **~64 min** |

The token figure is the honest input to "how much rigor went into this code
before it went public": ~14.5 million tokens across two independent
multi-agent rounds. This is what the project funded with paid Claude Max 20x
capacity, and is the reason the maintainer applied to Anthropic's
[Claude for Open Source](https://www.anthropic.com/claude-for-oss-terms)
program — to sustain reviews of this depth across future releases.

## Residual risk after remediation

The v0.2 audit's headline **HIGH** rating was assigned at audit time, against
the un-remediated state. After the two remediation commits referenced in
[`remediation-v0.2.md`](remediation-v0.2.md), residual risk on the audited
clusters is meaningfully reduced:

- All four Critical findings (one OCSP defect surfaced by four lenses) are
  fixed; the OCSP trust chain now enforces signature, responder identity,
  CertID binding, freshness window, and request-bound nonce per RFC 6960 §3.2.
- All fifteen High findings are fixed (manifest atomicity, Redis TTL, Redis
  socket timeouts, `--strict` posture, OCSP residuals).
- Twenty-eight of thirty Medium findings are fixed; two are deferred to v0.3
  with a fail-closed correctness gap that does not admit unauthorized
  requests.

MCP-S v0.2.0 ships as **experimental / incubating** — a third-party security
extension proposal for the Model Context Protocol, not an official MCP
extension. See the [SECURITY_BOUNDARY](../../docs/spec/security-boundary.md)
for the authoritative statement of what the current implementation claims and
what it explicitly does not.

## Issue tracking

The two deferred Mediums from the v0.2 audit are filed as separate GitHub
issues in this repository for forward traceability, both labelled
`security` / `deferred` / `medium` / `v0.3` and grouped under the
[`MCP-S v0.3 hardening`](https://github.com/users/matssun/projects/26)
project:

1. **Issue #1 — M-01** (`OnBehalfOfMissing` / P005 serde_json prefix coupling).
2. **Issue #2 — M-02** (`AuthorizationHashMissing` / P007 serde_json prefix
   coupling; the same v0.3 refactor closes the v0.1 carry-over **M-2** cross-
   omission case).

The four v0.1-audit partial findings are all closed in v0.2.0 and are not
filed as issues; their fix locations are recorded in the
[remediation log](remediation-v0.2.md#01-audit-carry-overs--all-closed-in-v020).

The audit workflow finding store itself (the per-agent JSONL outputs and the
3-skeptic verification panel records) was generated in the author's monorepo
and is not included in this repository. The audit reports and this
remediation document are the publish-ready record. Re-running the audit
workflow against a future revision of this repository is the right way to
extend the audit history.

## Finding ledger — cross-round disposition memory

Re-running the audit is expensive, and most of that cost is the 3-skeptic
verify gate. Paying it again on a finding already adjudicated in a prior round
(fixed, false-positive, accepted-risk) is waste. [`finding-ledger.jsonl`](finding-ledger.jsonl)
is the durable, version-controlled record of every finding ever seen and how it
was dispositioned, so a later round can suppress the already-handled set and
verify only what is genuinely new.

- **Identity:** each finding has a coarse fingerprint — the **first 16 hex
  characters** (a truncation, not a full 40-hex digest) of `sha1(file-basename |
  sorted significant title tokens)`. It is stable under line drift and reworded
  titles; line numbers and exact wording are deliberately excluded. The
  `file-basename` (not the full crate-relative path) is used on purpose so a
  finding survives a file move within the tree. The bounded cost: two findings in
  same-named files in different crates (e.g. `mcps-core/src/lib.rs` vs
  `mcps-proxy/src/lib.rs`) that *also* share the same significant title tokens
  would collide. In practice the title-token sets differ across crates, so the
  current ledger has **zero fingerprint collisions**; and reconcile never
  auto-suppresses on fingerprint alone — a same-file/same-category match it cannot
  confirm is surfaced as a *fuzzy candidate* for human review (below), so a
  collision degrades to a manual check, not a silent mis-suppression.
- **`category`** is a free-text label carried from the review lens (e.g.
  `replay-freshness`, `key-custody`, `mTLS identity binding`) and is used by
  reconcile only as a **soft** signal feeding fuzzy-candidate surfacing — it is
  not a controlled vocabulary and is never the basis for automatic suppression, so
  vocabulary drift degrades match recall gracefully rather than mis-bucketing.
- **`status`:** `open` (tracked by an issue) · `fixed` (carry the PR; a
  recurrence is a **regression**) · `false-positive` · `accepted-risk` ·
  `wontfix` · `superseded` (code removed) · `positive-control` (an INFO good
  control) · `handled-prior-round` (filed + closed previously, exact resolution
  not re-derived).
- **`verified.method`** records *how* a disposition was reached and never
  overclaims: `gate-3skeptic` · `manual-source` · `fix-merged` ·
  `review-adjudicated` · `intentional-posture` · `closed-issue` · `removed-code`.
  The v0.1 audit ([`audit-v0.1.md`](audit-v0.1.md)) ran the full three-stage round
  *including* the 3-skeptic verify gate; v0.2, v0.3 (closed at 0.3.1), and the
  current v0.4 round ran Stage 1+2 only to save tokens, and **false positives were
  identified by hand during remediation** — those FP determinations are captured
  here (`review-adjudicated`), which is the whole point: a later round must not
  re-evaluate a finding a prior round already proved false.
- **Reconcile:** at the start of each round the funnel matches the new pre-run
  against the ledger and buckets findings into *new* (verify these), *tracked*
  (already filed), *regression* (a `fixed` finding reappeared — loud), and
  *suppressed* (FP/accepted/positive-control — skipped). Same-file/same-category
  near-misses are surfaced as *fuzzy candidates* for confirmation, never silently
  suppressed.

The ledger is seeded from the prior Stage-1+2 round (issues #74–#101 @ `45a1876`,
dispositioned from their triage comments: false-positive / fixed / accepted-risk
per ADR posture) and the current round (@ `32f1430`); the manifest-subsystem
findings are `superseded` (removed in the ADR-030 purification).

The in-repo artifacts are this README and [`finding-ledger.jsonl`](finding-ledger.jsonl)
itself (the JSONL is self-describing — one finding per line). The generator/reconcile
tool (`ledger.py`) lives in the author's separate `security-audit-funnel` automation,
not in this repository, so there is no `scripts/` directory here; the ledger format
above is the contract a re-implementation must honor.

## How to extend this record

If you re-run a multi-agent security audit against a future release of this
repository, place the resulting report in this directory as `audit-vX.Y.md`
and accompany it with a `remediation-vX.Y.md` that tracks per-finding status
against the released source tree. Lows and Infos may continue to be
aggregated by count; Critical, High, and Medium should be enumerated. Ingest
the round into [`finding-ledger.jsonl`](finding-ledger.jsonl) and reconcile
before verifying, so the verify gate runs only on new findings.
