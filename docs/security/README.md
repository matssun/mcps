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

## How to extend this record

If you re-run a multi-agent security audit against a future release of this
repository, place the resulting report in this directory as `audit-vX.Y.md`
and accompany it with a `remediation-vX.Y.md` that tracks per-finding status
against the released source tree. Lows and Infos may continue to be
aggregated by count; Critical, High, and Medium should be enumerated.
