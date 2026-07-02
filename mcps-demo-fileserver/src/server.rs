//! The demo fileserver (MCPS-045, extended in Phase 1): a minimal,
//! MCP-S-UNAWARE stdio MCP server.
//!
//! [`FileServer`] speaks plain MCP JSON-RPC: `initialize`, `tools/list`, and
//! `tools/call`. It exposes five file tools, all confined to a configured
//! demo-root directory:
//!   * `list_files`   — **protected**: list a directory's entries.
//!   * `read_file`    — **protected**: read a UTF-8 text file's contents.
//!   * `stat`         — **protected**: report a path's type and size.
//!   * `write_file`   — **admin**:     create or overwrite a text file.
//!   * `delete_files` — **admin**:     elicits confirmation first (ADR-MCPS-047
//!     multi-round-trip demo; a SAFE dry-run that never touches the filesystem).
//!
//! It knows nothing about MCP-S signing, envelopes, or verified context — that
//! is the sidecar's job (the proxy wraps this server unchanged). The
//! `net.mcps.intendedScope` annotation on each tool is pure metadata: the server
//! does NOT enforce it; the Phase-5 policy layer reads it to bind a grant to a
//! tool. So `write_file` carrying scope `admin` is a *hint* — the deny happens
//! at the proxy, never here.
//!
//! Confinement (independent of, and in addition to, any MCP-S authorization):
//! every requested `path` is joined onto the demo root and the result must stay
//! inside the root. Lexical `..` segments and absolute paths are rejected before
//! touching the filesystem; the joined path (read/stat) or its parent directory
//! (write) is then canonicalized so a symlink that would escape the root is also
//! refused. Nothing here ever panics on bad input — every failure is a
//! [`FileServerError`].
//!
//! Anti-gaming receipt (optional): when a received-log is attached
//! ([`FileServer::with_received_log`]) every `tools/call` this server actually
//! dispatches appends one JSON line `{"id":<id>,"tool":"<name>"}`. A call denied
//! upstream (e.g. by the proxy's authorization profile) never reaches here, so
//! the log is the inner's own proof of what ran — see the Phase-2 deny tests.

use std::cell::RefCell;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use serde_json::json;
use serde_json::Value;

use crate::error::FileServerError;

/// The MCP protocol version this demo server advertises.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// List a directory's entries. Intended scope: `protected`.
pub const TOOL_LIST_FILES: &str = "list_files";
/// Read a UTF-8 text file. Intended scope: `protected`.
pub const TOOL_READ_FILE: &str = "read_file";
/// Report a path's type and size. Intended scope: `protected`.
pub const TOOL_STAT: &str = "stat";
/// Create or overwrite a text file. Intended scope: `admin`.
pub const TOOL_WRITE_FILE: &str = "write_file";
/// Delete files — elicits confirmation first (ADR-MCPS-047 multi-round-trip demo;
/// a SAFE dry-run that never touches the filesystem). Intended scope: `admin`.
pub const TOOL_DELETE_FILES: &str = "delete_files";

/// The annotation key under which each tool publishes its intended Phase-5
/// scope. The server does NOT enforce it; the policy layer reads it.
const INTENDED_SCOPE_KEY: &str = "net.mcps.intendedScope";
/// Intended-scope tag values, surfaced as tool annotations for the policy demo.
const SCOPE_PROTECTED: &str = "protected";
const SCOPE_ADMIN: &str = "admin";

/// Largest file the demo will read or write, in bytes (1 MiB). A bigger target
/// fails closed with a tool error rather than allocate unboundedly.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// A plain MCP server that serves file tools under a fixed demo root.
pub struct FileServer {
    demo_root: PathBuf,
    /// Optional append-only sink recording every `tools/call` actually
    /// dispatched here. `None` by default — a normal run writes no file.
    received_log: RefCell<Option<File>>,
}

impl FileServer {
    /// Construct a server confined to `demo_root`. The root itself is not
    /// required to exist at construction time; per-call resolution reports a
    /// tool error if it cannot be read.
    pub fn new(demo_root: impl Into<PathBuf>) -> Self {
        FileServer {
            demo_root: demo_root.into(),
            received_log: RefCell::new(None),
        }
    }

    /// Enable the append-only received-call log at `path`. The file is opened
    /// create-write-truncate so the record reflects only THIS session. Returns
    /// the server for chaining; an open failure is an I/O error, not a panic.
    pub fn with_received_log(self, path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        *self.received_log.borrow_mut() = Some(file);
        Ok(self)
    }

    /// Append one received-`tools/call` record line, if the log is enabled. The
    /// id is echoed verbatim so a test can correlate exactly. Write failures are
    /// swallowed — best-effort instrumentation must never break the serve loop.
    fn record_received_call(&self, id: &Value, tool: &str) {
        if let Some(file) = self.received_log.borrow_mut().as_mut() {
            let line = json!({ "id": id.clone(), "tool": tool });
            if let Ok(mut bytes) = serde_json::to_vec(&line) {
                bytes.push(b'\n');
                let _ = file.write_all(&bytes);
                let _ = file.flush();
            }
        }
    }

    /// Handle one raw JSON-RPC request and return the raw response bytes. Never
    /// panics: parse/protocol faults become JSON-RPC error objects; tool
    /// failures become `isError: true` tool results.
    pub fn handle(&self, request_bytes: &[u8]) -> Vec<u8> {
        // Best-effort id recovery so error responses echo the request id.
        let parsed: Option<Value> = serde_json::from_slice(request_bytes).ok();
        let id = parsed
            .as_ref()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);

        let response = match self.dispatch(parsed.as_ref(), request_bytes) {
            Ok(result) => json_rpc_result(&id, result),
            Err(err) => json_rpc_error(&id, &err),
        };

        // Serialization of a Value we built ourselves cannot fail; fall back to a
        // static error object rather than unwrap to keep the no-panic guarantee.
        serde_json::to_vec(&response).unwrap_or_else(|_| {
            b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"serialization failed\"}}"
                .to_vec()
        })
    }

    /// Route a parsed request to its handler, returning the JSON-RPC `result`
    /// value on success. Tool runtime failures are folded into a successful
    /// `result` carrying `isError: true` (per MCP); only protocol-level faults
    /// propagate as [`FileServerError`].
    fn dispatch(
        &self,
        parsed: Option<&Value>,
        request_bytes: &[u8],
    ) -> Result<Value, FileServerError> {
        let request = parsed.ok_or_else(|| {
            FileServerError::ParseError(format!(
                "not valid JSON ({} bytes)",
                request_bytes.len()
            ))
        })?;

        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| FileServerError::InvalidRequest("missing string 'method'".into()))?;

        match method {
            "initialize" => Ok(self.initialize_result()),
            "tools/list" => Ok(self.tools_list_result()),
            "tools/call" => self.tools_call_result(request),
            other => Err(FileServerError::MethodNotFound(other.to_string())),
        }
    }

    /// The `initialize` result: protocol version, tool capability, server info.
    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "mcps-demo-fileserver",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })
    }

    /// The `tools/list` result: the five file tools, each tagged with its
    /// intended Phase-5 scope.
    fn tools_list_result(&self) -> Value {
        let path_schema = || {
            json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path resolved against (and confined to) the demo root.",
                    }
                },
                "required": ["path"],
                "additionalProperties": false,
            })
        };
        json!({
            "tools": [
                tool_descriptor(
                    TOOL_LIST_FILES,
                    "List the entries of a directory inside the demo root.",
                    SCOPE_PROTECTED,
                    path_schema(),
                ),
                tool_descriptor(
                    TOOL_READ_FILE,
                    "Read a UTF-8 text file inside the demo root.",
                    SCOPE_PROTECTED,
                    path_schema(),
                ),
                tool_descriptor(
                    TOOL_STAT,
                    "Report the type and size of a path inside the demo root.",
                    SCOPE_PROTECTED,
                    path_schema(),
                ),
                tool_descriptor(
                    TOOL_WRITE_FILE,
                    "Create or overwrite a text file inside the demo root.",
                    SCOPE_ADMIN,
                    json!({
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path resolved against (and confined to) the demo root.",
                            },
                            "content": {
                                "type": "string",
                                "description": "UTF-8 text to write.",
                            }
                        },
                        "required": ["path", "content"],
                        "additionalProperties": false,
                    }),
                ),
                tool_descriptor(
                    TOOL_DELETE_FILES,
                    "Delete files inside the demo root — elicits confirmation first \
                     (ADR-MCPS-047 multi-round-trip demo; a SAFE dry-run, never deletes).",
                    SCOPE_ADMIN,
                    json!({
                        "type": "object",
                        "properties": {
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Paths that would be deleted (the demo is a dry-run).",
                            }
                        },
                        "required": ["paths"],
                        "additionalProperties": false,
                    }),
                ),
            ]
        })
    }

    /// The `tools/call` result. Dispatches on the tool name; an unknown tool is a
    /// JSON-RPC error (`Err`), but a tool runtime failure (escape, missing file)
    /// is an in-band tool error result (`isError: true`).
    fn tools_call_result(&self, request: &Value) -> Result<Value, FileServerError> {
        let params = request.get("params").unwrap_or(&Value::Null);
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| FileServerError::InvalidParams("missing tool 'name'".into()))?;

        // Record receipt ONLY for recognized tools, AFTER the name matches and
        // BEFORE dispatch. An unknown tool falls through to the `Err` arm and is
        // NOT recorded — it never ran. This is the anti-gaming signal: the log
        // reflects exactly what this inner dispatched.
        match name {
            TOOL_LIST_FILES | TOOL_READ_FILE | TOOL_STAT | TOOL_WRITE_FILE
            | TOOL_DELETE_FILES => {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                self.record_received_call(&id, name);
            }
            _ => {}
        }

        let arguments = params.get("arguments").unwrap_or(&Value::Null);
        match name {
            TOOL_LIST_FILES => self.run_list_files(arguments),
            TOOL_READ_FILE => self.run_read_file(arguments),
            TOOL_STAT => self.run_stat(arguments),
            TOOL_WRITE_FILE => self.run_write_file(arguments),
            // delete_files needs the FULL params (the continuation carries
            // `inputResponses` + echoed `requestState` alongside `arguments`).
            TOOL_DELETE_FILES => self.run_delete_files(params),
            other => Err(FileServerError::UnknownTool(other.to_string())),
        }
    }

    /// `list_files`: list a directory's entries (sorted), confined to the root.
    fn run_list_files(&self, arguments: &Value) -> Result<Value, FileServerError> {
        let path = str_arg(arguments, "path", TOOL_LIST_FILES)?;
        match self.list_files(path) {
            Ok(entries) => Ok(list_success(path, entries)),
            Err(err) => Ok(tool_error(&err)),
        }
    }

    /// `read_file`: read a UTF-8 text file, confined to the root.
    fn run_read_file(&self, arguments: &Value) -> Result<Value, FileServerError> {
        let path = str_arg(arguments, "path", TOOL_READ_FILE)?;
        match self.read_file(path) {
            Ok(text) => Ok(read_success(path, &text)),
            Err(err) => Ok(tool_error(&err)),
        }
    }

    /// `stat`: report a path's type and size, confined to the root.
    fn run_stat(&self, arguments: &Value) -> Result<Value, FileServerError> {
        let path = str_arg(arguments, "path", TOOL_STAT)?;
        match self.stat(path) {
            Ok(info) => Ok(stat_success(info)),
            Err(err) => Ok(tool_error(&err)),
        }
    }

    /// `write_file`: create or overwrite a text file, confined to the root.
    fn run_write_file(&self, arguments: &Value) -> Result<Value, FileServerError> {
        let path = str_arg(arguments, "path", TOOL_WRITE_FILE)?;
        let content = str_arg(arguments, "content", TOOL_WRITE_FILE)?;
        match self.write_file(path, content) {
            Ok(written) => Ok(write_success(path, written)),
            Err(err) => Ok(tool_error(&err)),
        }
    }

    /// `delete_files` (ADR-MCPS-047 multi-round-trip demo): a deterministic, SAFE
    /// elicitation tool that proves the InputRequiredResult → continuation security
    /// shape. It NEVER touches the filesystem — `confirmed` merely reflects the
    /// elicited answer.
    ///
    /// This inner server is stateless across the two legs (the proxy may spawn a fresh
    /// inner per request), so the pending operation MUST travel in the opaque
    /// `requestState` — the ADR-MCPS-047 / D5 contract. MCP-S never interprets it; only
    /// this server encodes (first leg) and validates (continuation leg) it.
    ///
    /// * First call (no `inputResponses`): return an `InputRequiredResult` asking for
    ///   confirmation, with the pending `paths` encoded into `requestState`.
    /// * Continuation call (`inputResponses` + echoed `requestState`): validate that
    ///   `requestState` decodes and matches the echoed `paths` (D5 server validation),
    ///   then return a terminal result reporting the (dry-run) deletion.
    fn run_delete_files(&self, params: &Value) -> Result<Value, FileServerError> {
        let arguments = params.get("arguments").unwrap_or(&Value::Null);
        let paths = arguments.get("paths").and_then(Value::as_array).ok_or_else(|| {
            FileServerError::InvalidParams("delete_files requires an array 'paths' argument".into())
        })?;
        if !paths.iter().all(Value::is_string) {
            return Err(FileServerError::InvalidParams(
                "delete_files requires 'paths' to be an array of strings".into(),
            ));
        }

        match params.get("inputResponses") {
            // First leg — elicit confirmation; stash the paths in the opaque requestState.
            None => Ok(delete_files_elicit(paths)),
            // Continuation leg — validate the echoed requestState, then terminal result.
            Some(responses) => {
                let request_state = params
                    .get("requestState")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        FileServerError::InvalidParams(
                            "delete_files continuation requires an echoed 'requestState'".into(),
                        )
                    })?;
                Ok(delete_files_terminal(paths, responses, request_state))
            }
        }
    }

    /// Resolve `requested` against the demo root, refuse any escape, and return
    /// the directory's entries sorted by name. Never reads outside the root.
    fn list_files(&self, requested: &str) -> Result<Vec<Value>, FileServerError> {
        let resolved = self.resolve_within_root(requested)?;

        let read_dir = std::fs::read_dir(&resolved)
            .map_err(|e| FileServerError::ReadDir(requested.to_string(), e.to_string()))?;

        let mut entries: Vec<Value> = Vec::new();
        for entry in read_dir {
            let entry =
                entry.map_err(|e| FileServerError::ReadDir(requested.to_string(), e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // file_type() avoids following symlinks for classification; size is
            // best-effort (0 when metadata is unavailable, e.g. a broken symlink).
            let (kind, size) = match entry.metadata() {
                Ok(meta) if meta.is_dir() => ("directory", 0u64),
                Ok(meta) => ("file", meta.len()),
                Err(_) => ("unknown", 0u64),
            };
            entries.push(json!({ "name": name, "type": kind, "size": size }));
        }

        // Deterministic ordering so the committed fixture yields stable results.
        entries.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["name"].as_str().unwrap_or_default())
        });
        Ok(entries)
    }

    /// Resolve `requested` (read), refuse any escape, and return its UTF-8 text.
    /// A directory, an over-size file, or non-UTF-8 bytes are tool errors.
    fn read_file(&self, requested: &str) -> Result<String, FileServerError> {
        let resolved = self.resolve_within_root(requested)?;
        let meta = std::fs::metadata(&resolved)
            .map_err(|e| FileServerError::Io(requested.to_string(), e.to_string()))?;
        if meta.is_dir() {
            return Err(FileServerError::Io(requested.to_string(), "is a directory".into()));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(FileServerError::TooLarge(requested.to_string(), MAX_FILE_BYTES));
        }
        let bytes = std::fs::read(&resolved)
            .map_err(|e| FileServerError::Io(requested.to_string(), e.to_string()))?;
        String::from_utf8(bytes).map_err(|_| FileServerError::NotUtf8(requested.to_string()))
    }

    /// Resolve `requested` (stat), refuse any escape, and report type and size.
    fn stat(&self, requested: &str) -> Result<Value, FileServerError> {
        let resolved = self.resolve_within_root(requested)?;
        let meta = std::fs::metadata(&resolved)
            .map_err(|e| FileServerError::Io(requested.to_string(), e.to_string()))?;
        let kind = if meta.is_dir() { "directory" } else { "file" };
        let size = if meta.is_dir() { 0 } else { meta.len() };
        Ok(json!({ "path": requested, "type": kind, "size": size }))
    }

    /// Write `content` to `requested` (create or overwrite), confined to the
    /// root. Over-size content is refused before touching disk; a symlinked
    /// parent that would escape the root is refused by [`Self::resolve_for_write`].
    fn write_file(&self, requested: &str, content: &str) -> Result<u64, FileServerError> {
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(FileServerError::TooLarge(requested.to_string(), MAX_FILE_BYTES));
        }
        let target = self.resolve_for_write(requested)?;
        std::fs::write(&target, content.as_bytes())
            .map_err(|e| FileServerError::Io(requested.to_string(), e.to_string()))?;
        Ok(content.len() as u64)
    }

    /// Reject lexical escapes (`..`, absolute paths) before any filesystem
    /// access. Shared by every tool. `.`/normal segments are allowed.
    fn reject_lexical_escape<'a>(
        &self,
        requested: &'a str,
    ) -> Result<&'a Path, FileServerError> {
        let requested_path = Path::new(requested);
        for component in requested_path.components() {
            match component {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(FileServerError::PathEscapesRoot(requested.to_string()))
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }
        Ok(requested_path)
    }

    /// Canonicalize the demo root once (it must exist to serve any call).
    fn canonical_root(&self) -> Result<PathBuf, FileServerError> {
        self.demo_root
            .canonicalize()
            .map_err(|e| FileServerError::ReadDir(".".to_string(), e.to_string()))
    }

    /// Join `requested` onto the demo root and confine the result to the root,
    /// for read/list/stat (the target is expected to exist).
    ///
    /// Two layers of defense:
    ///   1. Lexical: reject absolute inputs and any `..` segment (no fs access).
    ///   2. Canonical: if the joined target exists, canonicalize it and require
    ///      containment, catching symlink escapes. If it does not exist, the
    ///      lexical check already barred `..`/abs, so the caller reports a
    ///      not-found tool error.
    fn resolve_within_root(&self, requested: &str) -> Result<PathBuf, FileServerError> {
        let requested_path = self.reject_lexical_escape(requested)?;
        let joined = self.demo_root.join(requested_path);
        let canonical_root = self.canonical_root()?;
        if let Ok(canonical_target) = joined.canonicalize() {
            if !canonical_target.starts_with(&canonical_root) {
                return Err(FileServerError::PathEscapesRoot(requested.to_string()));
            }
            return Ok(canonical_target);
        }
        Ok(joined)
    }

    /// Resolve a write target, confining it to the root. Because the target file
    /// may not exist yet, containment is enforced on its *parent directory*
    /// (which must exist and canonicalize inside the root) — so a symlinked
    /// parent cannot redirect the write outside the demo root. The final path is
    /// the canonical parent joined with the requested file name.
    fn resolve_for_write(&self, requested: &str) -> Result<PathBuf, FileServerError> {
        let requested_path = self.reject_lexical_escape(requested)?;
        let file_name = requested_path.file_name().ok_or_else(|| {
            FileServerError::InvalidParams(format!(
                "write_file requires a file path, got '{requested}'"
            ))
        })?;
        let parent_rel = requested_path.parent().unwrap_or_else(|| Path::new(""));
        let parent_abs = self.demo_root.join(parent_rel);
        let canonical_root = self.canonical_root()?;
        let canonical_parent = parent_abs
            .canonicalize()
            .map_err(|e| FileServerError::Io(requested.to_string(), e.to_string()))?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(FileServerError::PathEscapesRoot(requested.to_string()));
        }
        Ok(canonical_parent.join(file_name))
    }
}

/// Extract a required string argument, or a protocol-level `InvalidParams` fault.
fn str_arg<'a>(
    arguments: &'a Value,
    key: &str,
    tool: &str,
) -> Result<&'a str, FileServerError> {
    arguments.get(key).and_then(Value::as_str).ok_or_else(|| {
        FileServerError::InvalidParams(format!("{tool} requires a string '{key}' argument"))
    })
}

/// Build a tool descriptor with its intended-scope annotation.
fn tool_descriptor(name: &str, description: &str, intended_scope: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": { INTENDED_SCOPE_KEY: intended_scope },
    })
}

/// Wrap a JSON-RPC `result` value in the full response envelope.
fn json_rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.clone(), "result": result })
}

/// Wrap a [`FileServerError`] in a JSON-RPC error object.
fn json_rpc_error(id: &Value, err: &FileServerError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": { "code": err.json_rpc_code(), "message": err.to_string() }
    })
}

/// A successful `list_files` tool result (MCP `tools/call` result shape).
fn list_success(path: &str, entries: Vec<Value>) -> Value {
    let summary = format!("{} entr{} under '{}'", entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }, path);
    json!({
        "content": [ { "type": "text", "text": summary } ],
        "structuredContent": { "path": path, "entries": entries },
        "isError": false,
    })
}

/// A successful `read_file` tool result: the file's text in both the human
/// `content` and the machine `structuredContent`.
fn read_success(path: &str, text: &str) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "structuredContent": { "path": path, "content": text, "size": text.len() },
        "isError": false,
    })
}

/// A successful `write_file` tool result.
fn write_success(path: &str, bytes_written: u64) -> Value {
    let summary = format!("wrote {bytes_written} byte{} to '{}'",
        if bytes_written == 1 { "" } else { "s" }, path);
    json!({
        "content": [ { "type": "text", "text": summary } ],
        "structuredContent": { "path": path, "bytes_written": bytes_written },
        "isError": false,
    })
}

/// A successful `stat` tool result (`info` is the `{path,type,size}` object).
fn stat_success(info: Value) -> Value {
    let summary = format!("{} '{}' ({} bytes)",
        info["type"].as_str().unwrap_or("entry"),
        info["path"].as_str().unwrap_or(""),
        info["size"].as_u64().unwrap_or(0));
    json!({
        "content": [ { "type": "text", "text": summary } ],
        "structuredContent": info,
        "isError": false,
    })
}

/// The `delete_files` elicitation leg: an `InputRequiredResult` (SEP-2322) asking
/// for confirmation, with the pending paths encoded into the opaque `requestState`.
/// The `resultType: "inputRequired"` discriminator is what a verified client
/// classifies as non-terminal (ADR-MCPS-047).
fn delete_files_elicit(paths: &[Value]) -> Value {
    json!({
        "resultType": "inputRequired",
        "inputRequests": {
            "confirm": {
                "type": "elicitation",
                "message": format!("Delete {} file(s)?", paths.len()),
                "schema": { "type": "boolean" },
            }
        },
        "requestState": encode_request_state(paths),
    })
}

/// The `delete_files` continuation leg: validate the echoed `requestState` against
/// the echoed paths (server-side D5 validation), then return a terminal result. The
/// demo NEVER deletes anything — `confirmed` reflects the elicited answer, and a
/// tampered/foreign `requestState` is refused in-band.
fn delete_files_terminal(paths: &[Value], responses: &Value, request_state: &str) -> Value {
    match decode_request_state(request_state) {
        Some(state_paths) if state_paths.as_slice() == paths => {
            let confirmed = responses
                .get("confirm")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let deleted: Vec<Value> = if confirmed { paths.to_vec() } else { Vec::new() };
            let summary = if confirmed {
                format!("deleted {} file(s) (dry-run)", paths.len())
            } else {
                "deletion declined".to_string()
            };
            json!({
                "content": [ { "type": "text", "text": summary } ],
                "structuredContent": { "deleted": deleted, "confirmed": confirmed },
                "isError": false,
            })
        }
        _ => tool_error(&FileServerError::InvalidParams(
            "delete_files requestState is invalid or does not match the echoed paths".into(),
        )),
    }
}

/// Encode the pending paths as an opaque `requestState` token: lowercase hex of the
/// JSON-array bytes. Opaque to MCP-S and the client (echoed verbatim); meaningful
/// only to this server, which decodes it to resume — the ADR-MCPS-047 / D5 contract.
/// Hand-rolled hex keeps this MCP-S-unaware server dependency-free.
fn encode_request_state(paths: &[Value]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let json = Value::Array(paths.to_vec()).to_string();
    let mut out = String::with_capacity(json.len() * 2);
    for &b in json.as_bytes() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a `requestState` token back to the pending paths, or `None` if it is not
/// valid hex of a JSON array (a tampered/foreign token — refused by the caller).
fn decode_request_state(state: &str) -> Option<Vec<Value>> {
    let raw = state.as_bytes();
    if raw.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    let mut i = 0;
    while i < raw.len() {
        let hi = (raw[i] as char).to_digit(16)?;
        let lo = (raw[i + 1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
        i += 2;
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Array(paths)) => Some(paths),
        _ => None,
    }
}

/// An in-band tool error result (MCP `isError: true`); carries no payload.
fn tool_error(err: &FileServerError) -> Value {
    json!({
        "content": [ { "type": "text", "text": err.to_string() } ],
        "isError": true,
    })
}
