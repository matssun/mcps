<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Architecture Decision Records

This directory holds the Architecture Decision Records that govern MCP-S.

Each ADR records the context, decision, rationale, alternatives, and
consequences of one architectural choice. They are intentionally short — the
shortest defensible form of "what we decided and why" — so they remain
maintainable as the project evolves.

## Index

| ID | Title |
|---|---|
| [ADR-MCPS-001](adr-mcps-001.md) | Clean-Room Public Protocol — Vocabulary Firewall and Public TrustResolver Trait |
| [ADR-MCPS-002](adr-mcps-002.md) | Frozen Public Envelope Vocabulary |
| [ADR-MCPS-003](adr-mcps-003.md) | Signing Locus — What `signer` and a Signature Prove |
| [ADR-MCPS-004](adr-mcps-004.md) | Ed25519-over-JCS Signing Rule for the Whole JSON-RPC Object |
| [ADR-MCPS-005](adr-mcps-005.md) | JCS-Safe JSON Value Domain with Fail-Closed Canonicalization |
| [ADR-MCPS-006](adr-mcps-006.md) | Freshness and Replay Model — Injected ReplayCache, No `sequence` in Core v1 |
| [ADR-MCPS-007](adr-mcps-007.md) | Trust Resolution, Key Rotation, and Revocation Model |
| [ADR-MCPS-008](adr-mcps-008.md) | Verified-Context Propagation to Inner MCP Servers |
| [ADR-MCPS-009](adr-mcps-009.md) | Fail-Closed Message Constraints — Batch, Notification, Unknown-Field Rejection |
| [ADR-MCPS-010](adr-mcps-010.md) | Incubation Strategy, Extension Identifier, and Preimage-Stability Rule |
| [ADR-MCPS-011](adr-mcps-011.md) | Workspace Structure, Phased Delivery, and Conformance-as-Specification |
| [ADR-MCPS-012](adr-mcps-012.md) | Project Placement & Build Integration |
| [ADR-MCPS-013](adr-mcps-013.md) | Delegated Authorization — AuthorizationProfile Abstraction (Phase 5) |
| [ADR-MCPS-014](adr-mcps-014.md) | Phase 6 — Rust-Native Transport Hardening |
| [ADR-MCPS-015](adr-mcps-015.md) | Client Host-Session Architecture |
| [ADR-MCPS-016](adr-mcps-016.md) | Inner-Server Isolation Boundary |
| [ADR-MCPS-017](adr-mcps-017.md) | Single-Node Production Claim Ceiling and Deferred Enterprise Capabilities |
| [ADR-MCPS-018](adr-mcps-018.md) | CI Reproducibility Posture and Conformance-Manifest Authority |
| [ADR-MCPS-019](adr-mcps-019.md) | Phase 7 External Backends (stub — published here for the first time) |
| [ADR-MCPS-020](adr-mcps-020.md) | Distributed Atomic Replay Store — Durability Contract for Horizontally-Scaled Replay Safety (v0.3 sketch) |
| [ADR-MCPS-021](adr-mcps-021.md) | Cluster Trust State — Revocation and Rotation Propagation Across Nodes (v0.3 sketch) |
| [ADR-MCPS-022](adr-mcps-022.md) | Signing Key Custody at Scale — Per-Node Keys, Explicit Anchor, Optional KMS (v0.3 sketch) |
| [ADR-MCPS-023](adr-mcps-023.md) | Ingress and Reverse-Proxy mTLS — End-to-End Binding vs. Trusted-Ingress Re-Assertion (v0.3 sketch) |
| [ADR-MCPS-024](adr-mcps-024.md) | Replay Safety Under MCP Multi Round-Trip Requests (SEP-2322) — v0.3 RC delta |
| [ADR-MCPS-025](adr-mcps-025.md) | Untrusted Transport Routing Headers — MCP-S Composition with SEP-2243 — v0.3 RC delta |
| [ADR-MCPS-026](adr-mcps-026.md) | Signing Scope Versus Stateless Per-Request `_meta` (SEP-2575) — v0.3 RC delta |

## Provenance

ADR-MCPS-001 through ADR-MCPS-018 were originally published as GitHub
Discussions in the maintainer's private monorepo and have been copied here
verbatim (with only an SPDX header added) so they ship with the codebase they
govern. ADR-MCPS-019 was implemented but not previously written up; the
[stub](adr-mcps-019.md) consolidates the rule as it was applied in the v0.2.0
release.

## Conventions

- Each ADR is one markdown file named `adr-mcps-NNN.md` where `NNN` is the
  zero-padded three-digit ADR number.
- Status values: **Proposed**, **Accepted**, **Implemented**, **Superseded by
  ADR-MCPS-NNN**, **Deprecated**, **Withdrawn**.
- New ADRs are appended with the next sequential number. A decision that
  changes an earlier decision supersedes that ADR with an explicit note in
  both directions.
