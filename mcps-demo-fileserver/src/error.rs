//! Error type for the demo fileserver (MCPS-045).
//!
//! Every fallible path returns a [`FileServerError`] rather than panicking. The
//! server maps these to either a JSON-RPC error object (protocol-level faults)
//! or an `isError: true` tool result (`list_files` failures), so bad input is
//! always handled in-band. `unwrap`/`panic!` are reserved for unreachable
//! invariants only.

use thiserror::Error;

/// All ways the demo fileserver can fail to produce a normal result.
#[derive(Debug, Error)]
pub enum FileServerError {
    /// The request bytes were not valid JSON-RPC (parse error, -32700).
    #[error("parse error: {0}")]
    ParseError(String),

    /// The request was valid JSON but not a well-formed JSON-RPC request
    /// (missing/!string `method`, etc.) — invalid request, -32600.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The `method` is not one this server implements — method not found, -32601.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// `tools/call` named a tool this server does not expose — invalid params.
    #[error("unknown tool: {0}")]
    UnknownTool(String),

    /// A tool's parameters were missing or the wrong shape — invalid params.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    /// The requested `path` escapes the configured demo root. Refused.
    #[error("path '{0}' escapes the demo root")]
    PathEscapesRoot(String),

    /// The resolved directory could not be read (missing, not a directory, I/O).
    #[error("cannot read directory '{0}': {1}")]
    ReadDir(String, String),

    /// A file read/write/stat failed (missing, is-a-directory, permissions, I/O).
    #[error("cannot access '{0}': {1}")]
    Io(String, String),

    /// `read_file` target was not valid UTF-8 text (the demo serves text only).
    #[error("file '{0}' is not valid UTF-8 text")]
    NotUtf8(String),

    /// The file exceeds the demo's per-file byte ceiling. Refused.
    #[error("file '{0}' exceeds the {1}-byte demo limit")]
    TooLarge(String, u64),
}

impl FileServerError {
    /// The JSON-RPC error code for protocol-level faults. Tool-level failures
    /// (`PathEscapesRoot`, `ReadDir`, `InvalidParams` inside a call) are not sent
    /// as JSON-RPC errors — they become `isError: true` tool results — but a code
    /// is still defined for completeness and reuse.
    pub fn json_rpc_code(&self) -> i64 {
        match self {
            FileServerError::ParseError(_) => -32700,
            FileServerError::InvalidRequest(_) => -32600,
            FileServerError::MethodNotFound(_) => -32601,
            FileServerError::UnknownTool(_) => -32602,
            FileServerError::InvalidParams(_) => -32602,
            FileServerError::PathEscapesRoot(_) => -32602,
            FileServerError::ReadDir(_, _) => -32603,
            FileServerError::Io(_, _) => -32603,
            FileServerError::NotUtf8(_) => -32602,
            FileServerError::TooLarge(_, _) => -32602,
        }
    }
}
