<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S × EMA composition (proposed)

> **Status: proposed design note — NOT implemented, NOT demoed in v0.5.1.**
> EMA (Enterprise-Managed Authorization) exists in the MCP ecosystem as a
> *proposal*. This document records how MCP-S would compose with it so the two
> are not conflated. It describes no shipped code and backs no v0.5.1 claim.
> What v0.5.1 actually demonstrates is the basic sidecar path (Diagram A) and
> the [live GCP KMS validation](../quickstart-gcp-kms.md).

## The one-line distinction

> **EMA decides whether the enterprise user/client may *obtain* authorization.
> MCP-S proves that a *concrete MCP call* was signed, fresh, non-replayed,
> response-bound, and bound to that EMA-derived authorization artifact.**

EMA is an *authorization-issuance* concern: identity, policy, consent, scope. It
answers "may this principal be granted this capability?" MCP-S is a *per-message
authenticity* concern: it answers "is *this exact call*, on the wire, genuinely
the authorized one — unforged, unreplayed, and is its response genuinely bound
back to it?" They sit at different layers and compose; neither replaces the
other.

MCP-S **binds, it does not interpret.** It treats the EMA-derived authorization
artifact as an opaque, hashed input bound into the signed request envelope. It
does not parse EMA policy, re-decide scope, or re-run the enterprise's
authorization logic.

## Diagram A — basic MCP-S sidecar path (this is what v0.5.1 demos)

No EMA. The host client signs each call; the proxy verifies and enforces before
the inner MCP server is ever reached.

```text
┌────────────────┐  signed MCP-S request  ┌───────────────────────────┐   stdio   ┌──────────────────┐
│ HostSession    │ ─────────────────────► │ mcps-proxy (sidecar)      │ ────────► │ inner MCP server │
│ client         │      (mTLS)            │  • verify object signature│           │ (unmodified)     │
│  • signs req   │                        │  • freshness / replay     │           │                  │
│  • verifies    │ ◄───────────────────── │  • delegated authz BIND   │ ◄──────── │  runs the tool   │
│    response    │  signed, hash-bound    │  • strip caller .verified │           │                  │
└────────────────┘     response           │  • inject sidecar context │           └──────────────────┘
                                          │  • sign response          │
                                          └───────────────────────────┘
                                            denied requests never reach the inner server
```

## Two composition modes

When EMA is present, MCP-S composes in one of two distinct modes. **Pick one per
deployment and state which** — see the *"EMA twice"* warning below.

### Mode 1 — EMA *binding* mode (for EMA-native MCP servers)

The MCP server (or its platform) is itself EMA-aware and performs the
authorization decision. MCP-S does **not** re-decide authorization; it **binds**
the EMA authorization artifact into the signed call so the artifact cannot be
swapped, forged, replayed, or detached from the specific request — and binds the
response back to that request.

Use this when the backend already enforces EMA. MCP-S adds message authenticity,
freshness, replay protection, and response binding *around* the EMA decision.

```text
┌────────────┐  signed req + bound      ┌──────────────────────┐         ┌──────────────────────────┐
│ HostSession│  EMA-artifact hash       │ mcps-proxy           │  stdio  │ EMA-native MCP server     │
│ client     │ ───────────────────────► │  • verify signature  │ ──────► │  • reads EMA artifact     │
│            │       (mTLS)             │  • freshness/replay  │         │  • MAKES the authz        │
│            │                          │  • BIND EMA artifact │         │    DECISION (EMA enforce) │
│            │ ◄─────────────────────── │    (does NOT decide) │ ◄────── │  • runs tool              │
└────────────┘  hash-bound response     │  • bind response     │         └──────────────────────────┘
                                        └──────────────────────┘
                                  MCP-S guarantees authenticity; the SERVER enforces EMA.
```

### Mode 2 — EMA *enforcement* mode (only for private backends behind MCP-S)

The backend is **not** EMA-aware — it is a private server fully behind the MCP-S
sidecar. Here the MCP-S delegated-authorization layer enforces the
EMA-derived grant *before dispatch* (deny-before-dispatch), because nothing
downstream will.

Use this **only** when the backend is private and the sidecar is the sole
enforcement point. Do **not** use it in front of a server that itself enforces
EMA.

```text
┌────────────┐  signed req + EMA-       ┌────────────────────────────┐   stdio   ┌────────────────────┐
│ HostSession│  derived grant           │ mcps-proxy                 │ ────────► │ PRIVATE backend    │
│ client     │ ───────────────────────► │  • verify signature        │           │ (not EMA-aware,    │
│            │       (mTLS)             │  • freshness/replay         │           │  fully behind the  │
│            │                          │  • ENFORCE the grant        │           │  sidecar)          │
│            │ ◄─────────────────────── │    (deny-before-dispatch)   │ ◄──────── │  runs tool only if │
└────────────┘  hash-bound response     │  • bind response            │           │  the proxy allowed │
                                        └────────────────────────────┘
                                  MCP-S is the SOLE enforcement point.
```

## The "EMA twice" warning

Do **not** run EMA enforcement in both the sidecar (Mode 2) **and** an EMA-native
backend (Mode 1) for the same call. Enforcing the same authorization twice in two
places is an ambiguity, not extra safety:

- the two evaluators can **disagree** (different policy versions, clock skew,
  partial revocation visibility), producing inconsistent allow/deny;
- it is unclear **which** decision is authoritative for audit;
- a permissive sidecar policy can silently **widen** a stricter backend decision,
  or a stricter sidecar can **shadow-deny** calls the backend would have allowed,
  hiding the real policy surface.

**Rule:** exactly one component enforces EMA per call. If the backend is
EMA-native, use Mode 1 and let the backend decide (MCP-S binds, does not decide).
If the backend is private, use Mode 2 and let the sidecar enforce. State the mode
explicitly in the deployment's security posture.

## What this means for claims

- MCP-S does **not** implement EMA and makes **no** EMA claim in v0.5.1.
- MCP-S's contribution in either mode is the same: per-message signature,
  freshness, replay protection, transport binding, response-to-request binding,
  and *binding* the authorization artifact — not authorization issuance.
- See [`docs/PROJECT_STATUS.md`](../PROJECT_STATUS.md) for the current claims and
  non-claims, and [`docs/spec/security-boundary.md`](security-boundary.md) for the
  protected/unprotected surface.
