//! Tier T1 — "Real tools, fail closed" (ADR-MCPS-045).
//!
//! Persona: the same individual, maturing. Now the inner server has real,
//! side-effecting tools — `read_file`, `write_file`, `stat`, `list_files` — and
//! every call still flows through the signed four-hop channel. This tier shows
//! the tools working end to end AND that the system fails CLOSED on a bad request
//! (a demo-root escape is refused, nothing is written, and the refusal surfaces
//! as a clean plain-MCP error — no crash, no leak).
//!
//! The deeper MCP-S wire negatives (unsigned / tampered / wrong-signer /
//! downgrade) are the transport/protocol tier (T3) and the in-process §10 suite;
//! T1's new concept is REAL TOOLS over the signed channel + fail-closed inputs.

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::SEED_TEXT;

#[test]
fn write_then_read_round_trips_through_the_signed_channel() {
    let mut hop = FourHop::launch();

    // write_file creates a new file via the signed channel...
    let written = "notes written over MCP-S\n";
    let write_resp = hop.call(&tool_call(
        "t1-write",
        "write_file",
        serde_json::json!({ "path": "notes.txt", "content": written }),
    ));
    assert_eq!(
        structured(&write_resp)["bytes_written"].as_u64(),
        Some(written.len() as u64)
    );
    // ...and it actually landed on the inner's disk.
    assert_eq!(
        std::fs::read_to_string(hop.root_file("notes.txt")).expect("file on disk"),
        written
    );

    // read_file reads it back through the same channel.
    let read_resp = hop.call(&tool_call(
        "t1-read",
        "read_file",
        serde_json::json!({ "path": "notes.txt" }),
    ));
    assert_eq!(structured(&read_resp)["content"].as_str(), Some(written));
}

#[test]
fn stat_and_list_report_the_seeded_root() {
    let mut hop = FourHop::launch();

    let stat = hop.call(&tool_call("t1-stat", "stat", serde_json::json!({ "path": "hello.txt" })));
    let s = structured(&stat);
    assert_eq!(s["type"].as_str(), Some("file"));
    assert_eq!(s["size"].as_u64(), Some(SEED_TEXT.len() as u64));

    let list = hop.call(&tool_call("t1-list", "list_files", serde_json::json!({ "path": "." })));
    let names: Vec<&str> = structured(&list)["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"hello.txt"), "listing should include the seed: {names:?}");
}

#[test]
fn a_demo_root_escape_fails_closed_as_a_plain_error() {
    let mut hop = FourHop::launch();

    // A path escaping the demo root is refused by the inner fileserver; the
    // refusal surfaces to the ordinary client as a plain JSON-RPC error, and
    // nothing is read.
    let response = hop.call(&tool_call(
        "t1-escape",
        "read_file",
        serde_json::json!({ "path": "../../../../etc/passwd" }),
    ));
    assert!(
        response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true),
        "an escape must fail closed, not return file contents: {response}"
    );
    // Whatever the surface, no /etc/passwd content leaked back.
    let body = response.to_string();
    assert!(!body.contains("root:"), "no escaped file content may leak: {body}");
}
