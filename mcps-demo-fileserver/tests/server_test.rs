//! Black-box tests for the demo fileserver (MCPS-045).
//!
//! Drive the public `FileServer::handle(raw_request_bytes) -> response_bytes`
//! seam with plain MCP JSON-RPC and assert on the parsed responses. The server
//! is MCP-S-UNAWARE: no signing, no envelopes, no verified context here.
//!
//! The committed `demo_root/` fixture makes every result deterministic. Tests
//! point the server at the in-tree fixture via CARGO_MANIFEST_DIR so they work
//! under both Cargo and Bazel (Cargo.toml is in compile_data).

use std::path::PathBuf;

use mcps_demo_fileserver::FileServer;
use serde_json::json;
use serde_json::Value;

/// Absolute path to the committed `demo_root/` fixture.
///
/// Under Bazel the fixture is delivered via runfiles: the BUILD target sets
/// `DEMO_ROOT_README` to `$(rlocationpath .../demo_root/readme.txt)`, which we
/// resolve against the runfiles root and take the parent of. Under plain Cargo
/// (no such env) we fall back to `CARGO_MANIFEST_DIR/demo_root`.
fn demo_root() -> PathBuf {
    if let Ok(rel) = std::env::var("DEMO_ROOT_README") {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                candidates.push(PathBuf::from(&root).join(&rel));
            }
        }
        candidates.push(PathBuf::from(&rel));
        for candidate in candidates {
            if candidate.exists() {
                return candidate
                    .parent()
                    .expect("readme.txt has a parent")
                    .to_path_buf();
            }
        }
        panic!("cannot locate demo_root via DEMO_ROOT_README='{rel}'");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demo_root")
}

/// Build a server rooted at the committed fixture.
fn server() -> FileServer {
    FileServer::new(demo_root())
}

/// Parse the server's response bytes into JSON.
fn handle(server: &FileServer, request: Value) -> Value {
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");
    let response_bytes = server.handle(&request_bytes);
    serde_json::from_slice(&response_bytes).expect("parse response")
}

#[test]
fn initialize_returns_well_formed_result() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        }),
    );

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response.get("error").is_none(), "initialize must not error");
    let result = &response["result"];
    assert!(result["protocolVersion"].is_string());
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["serverInfo"]["name"].is_string());
}

#[test]
fn tools_list_advertises_four_scoped_tools() {
    let server = server();
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );

    assert!(response.get("error").is_none());
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools array");

    // Map name -> intended scope, so the assertions don't depend on order.
    let scope_of = |name: &str| -> String {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("tool '{name}' present"))
            ["annotations"]["net.mcps.intendedScope"]
            .as_str()
            .expect("scope annotation")
            .to_string()
    };

    assert_eq!(tools.len(), 4, "list_files, read_file, stat, write_file");
    assert_eq!(scope_of("list_files"), "protected");
    assert_eq!(scope_of("read_file"), "protected");
    assert_eq!(scope_of("stat"), "protected");
    assert_eq!(scope_of("write_file"), "admin");

    // list_files keeps its single `path` arg; write_file also requires `content`.
    let list_schema = &tools.iter().find(|t| t["name"] == "list_files").unwrap()["inputSchema"];
    assert_eq!(list_schema["properties"]["path"]["type"], "string");
    let write_required = tools
        .iter()
        .find(|t| t["name"] == "write_file")
        .unwrap()["inputSchema"]["required"]
        .as_array()
        .expect("write required array");
    assert!(write_required.iter().any(|r| r == "path"));
    assert!(write_required.iter().any(|r| r == "content"));
}

#[test]
fn list_files_on_root_returns_fixture_entries_deterministically() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "." } }
        }),
    );

    assert!(response.get("error").is_none());
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    let entries = result["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    // Deterministic, sorted listing of the committed fixture root.
    assert_eq!(
        names,
        vec!["config.yaml", "data.csv", "readme.txt", "reports"]
    );
    // The subdirectory must be flagged as a directory.
    let reports = entries
        .iter()
        .find(|e| e["name"] == "reports")
        .expect("reports entry");
    assert_eq!(reports["type"], "directory");
}

#[test]
fn list_files_on_subdirectory_returns_its_entries() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "reports" } }
        }),
    );

    assert!(response.get("error").is_none());
    let entries = response["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["q1.txt", "q2.txt"]);
}

#[test]
fn list_files_refuses_dotdot_escape() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "../.." } }
        }),
    );

    // A refusal is reported as a tool error result (isError: true), never a panic
    // and never a directory listing.
    assert!(response.get("result").is_some(), "tool error is a result");
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
    let text = result["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(text.to_lowercase().contains("escape") || text.to_lowercase().contains("outside"));
}

#[test]
fn list_files_refuses_absolute_path_outside_root() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "/etc" } }
        }),
    );

    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
}

#[test]
fn list_files_on_missing_directory_is_a_tool_error_not_a_panic() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "does_not_exist" } }
        }),
    );

    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn unknown_tool_is_a_jsonrpc_error() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": { "name": "no_such_tool", "arguments": {} }
        }),
    );

    assert!(response.get("error").is_some(), "unknown tool -> JSON-RPC error");
    assert_eq!(response["id"], 8);
}

#[test]
fn unknown_method_is_a_jsonrpc_method_not_found_error() {
    let server = server();
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 9, "method": "no/such/method" }),
    );

    let error = &response["error"];
    assert_eq!(error["code"], -32601);
    assert_eq!(response["id"], 9);
}

#[test]
fn malformed_json_is_a_parse_error_with_null_id() {
    let server = server();
    let response_bytes = server.handle(b"{ this is not json ");
    let response: Value = serde_json::from_slice(&response_bytes).expect("parse response");
    assert_eq!(response["error"]["code"], -32700);
    assert_eq!(response["id"], Value::Null);
}

// --- Phase 1: read_file / stat / write_file ---------------------------------

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// A fresh, empty, WRITABLE root for mutation tests. Uses the per-test-binary
/// temp dir Cargo provides (`CARGO_TARGET_TMPDIR`), Bazel's `TEST_TMPDIR`, or the
/// system temp dir — never the committed read-only fixture.
fn writable_root() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let base = std::env::var("CARGO_TARGET_TMPDIR")
        .ok()
        .or_else(|| std::env::var("TEST_TMPDIR").ok())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let unique = format!(
        "fileserver_wr_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let dir = base.join(unique);
    std::fs::create_dir_all(&dir).expect("create writable root");
    dir
}

/// `tools/call` a tool with `arguments` and return the parsed response.
fn call(server: &FileServer, id: i64, name: &str, arguments: Value) -> Value {
    handle(
        server,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }),
    )
}

#[test]
fn read_file_returns_fixture_text() {
    let server = server();
    let expected = std::fs::read_to_string(demo_root().join("readme.txt")).expect("fixture readable");

    let response = call(&server, 20, "read_file", json!({ "path": "readme.txt" }));

    assert!(response.get("error").is_none());
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["content"], expected);
    assert_eq!(result["structuredContent"]["size"], expected.len());
    // The human content carries the same text.
    assert_eq!(result["content"][0]["text"], expected);
}

#[test]
fn read_file_on_a_directory_is_a_tool_error() {
    let server = server();
    let response = call(&server, 21, "read_file", json!({ "path": "reports" }));
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"].get("structuredContent").is_none());
}

#[test]
fn read_file_refuses_dotdot_escape() {
    let server = server();
    let response = call(&server, 22, "read_file", json!({ "path": "../Cargo.toml" }));
    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn read_file_on_non_utf8_bytes_is_a_tool_error() {
    let root = writable_root();
    std::fs::write(root.join("blob.bin"), [0xff, 0xfe, 0x00, 0x01]).expect("write blob");
    let server = FileServer::new(&root);

    let response = call(&server, 23, "read_file", json!({ "path": "blob.bin" }));

    let result = &response["result"];
    assert_eq!(result["isError"], true);
    let text = result["content"][0]["text"].as_str().expect("error text");
    assert!(text.to_lowercase().contains("utf-8"), "got: {text}");
}

#[test]
fn stat_reports_file_type_and_size() {
    let server = server();
    let size = std::fs::metadata(demo_root().join("readme.txt")).unwrap().len();

    let response = call(&server, 24, "stat", json!({ "path": "readme.txt" }));

    let sc = &response["result"]["structuredContent"];
    assert_eq!(sc["type"], "file");
    assert_eq!(sc["size"], size);
}

#[test]
fn stat_reports_directory() {
    let server = server();
    let response = call(&server, 25, "stat", json!({ "path": "reports" }));
    assert_eq!(response["result"]["structuredContent"]["type"], "directory");
}

#[test]
fn write_file_creates_then_read_back_round_trips() {
    let root = writable_root();
    let server = FileServer::new(&root);

    let write = call(&server, 26, "write_file", json!({ "path": "note.txt", "content": "hello" }));
    assert!(write.get("error").is_none());
    assert_eq!(write["result"]["isError"], false);
    assert_eq!(write["result"]["structuredContent"]["bytes_written"], 5);

    // It actually hit disk, inside the root.
    assert_eq!(std::fs::read_to_string(root.join("note.txt")).unwrap(), "hello");

    // And read_file sees it.
    let read = call(&server, 27, "read_file", json!({ "path": "note.txt" }));
    assert_eq!(read["result"]["structuredContent"]["content"], "hello");
}

#[test]
fn write_file_overwrites_existing_content() {
    let root = writable_root();
    let server = FileServer::new(&root);

    call(&server, 28, "write_file", json!({ "path": "note.txt", "content": "first" }));
    call(&server, 29, "write_file", json!({ "path": "note.txt", "content": "second" }));

    assert_eq!(std::fs::read_to_string(root.join("note.txt")).unwrap(), "second");
}

#[test]
fn write_file_refuses_dotdot_escape_and_writes_nothing_outside() {
    let root = writable_root();
    let server = FileServer::new(&root);

    let response = call(&server, 30, "write_file", json!({ "path": "../escaped.txt", "content": "x" }));

    assert_eq!(response["result"]["isError"], true);
    // Nothing was written to the parent of the root.
    assert!(!root.join("../escaped.txt").exists(), "escape must not create a file");
}

#[test]
fn write_file_into_missing_subdir_is_a_tool_error() {
    let root = writable_root();
    let server = FileServer::new(&root);

    // The parent dir `sub/` does not exist; the demo does not auto-create dirs.
    let response = call(&server, 31, "write_file", json!({ "path": "sub/note.txt", "content": "x" }));
    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn write_file_over_size_limit_is_refused_before_disk() {
    let root = writable_root();
    let server = FileServer::new(&root);

    let too_big = "a".repeat((1 << 20) + 1); // one byte over the 1 MiB ceiling
    let response = call(&server, 32, "write_file", json!({ "path": "big.txt", "content": too_big }));

    assert_eq!(response["result"]["isError"], true);
    assert!(!root.join("big.txt").exists(), "over-size write must not touch disk");
}

#[test]
fn write_file_missing_content_arg_is_a_jsonrpc_error() {
    let server = server();
    let response = call(&server, 33, "write_file", json!({ "path": "note.txt" }));
    // A missing required argument is a protocol-level fault, not a tool error.
    assert!(response.get("error").is_some(), "missing arg -> JSON-RPC error");
}

#[test]
fn received_log_records_dispatched_tools_only() {
    let root = writable_root();
    let log_path = root.join("received.log");
    let server = FileServer::new(&root)
        .with_received_log(&log_path)
        .expect("attach received log");

    // A recognized tool that runs -> recorded.
    call(&server, 40, "stat", json!({ "path": "." }));
    // An unknown tool -> JSON-RPC error, never dispatched -> NOT recorded.
    call(&server, 41, "no_such_tool", json!({}));

    let log = std::fs::read_to_string(&log_path).expect("read log");
    let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "exactly one dispatched call recorded, got: {log:?}");
    let entry: Value = serde_json::from_str(lines[0]).expect("log line is json");
    assert_eq!(entry["id"], 40);
    assert_eq!(entry["tool"], "stat");
}
