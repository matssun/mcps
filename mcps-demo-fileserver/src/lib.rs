//! `mcps-demo-fileserver` — a minimal, MCP-S-UNAWARE stdio MCP server (MCPS-045).
//!
//! This is the in-tree demo target for MCPS-EPIC-P6.5: an ORDINARY MCP server
//! that the MCP-S sidecar (`mcps-proxy`) wraps unchanged. It speaks plain MCP
//! JSON-RPC (`initialize`, `tools/list`, `tools/call`) and exposes five file
//! tools — `list_files`, `read_file`, `stat` (scope `protected`), `write_file`
//! and `delete_files` (scope `admin`; `delete_files` is the ADR-MCPS-047
//! multi-round-trip elicitation demo, a SAFE dry-run) — confined to a configured
//! demo-root directory. It knows nothing about signing, envelopes, or verified context.
//!
//! Crate boundary (ADR-MCPS-001): self-contained — depends only on the pure
//! serde subset plus thiserror, no other in-repo crate, no async runtime. Unlike
//! the pure `mcps-core`, it MAY use `std::fs` / `std::io` (it is a file server).

pub mod error;
pub mod server;
pub mod stdio;

pub use error::FileServerError;
pub use server::FileServer;
pub use server::TOOL_LIST_FILES;
pub use server::TOOL_READ_FILE;
pub use server::TOOL_STAT;
pub use server::TOOL_WRITE_FILE;
pub use stdio::serve_stdio;
