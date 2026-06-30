//! Tier T0 — "Hello, signed call" (ADR-MCPS-045).
//!
//! Persona: an individual who just wants to SEE MCP-S work. The ordinary client
//! sends one plain `tools/call` and gets a plain result back — but in between,
//! across four real processes, the call was signed (draft-02), verified at the
//! server PEP, the result was signed and bound to the request, and the client
//! proxy verified that binding before handing back plain MCP.
//!
//! What this tier demonstrates: object signing + response binding (authenticity),
//! end to end, over real subprocesses. No authorization yet.

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::SEED_TEXT;

#[test]
fn a_signed_call_round_trips_all_four_hops_as_plain_mcp() {
    let mut hop = FourHop::launch();

    // The ordinary client reads a seeded file by name — plain MCP in.
    let response = hop.call(&tool_call("hello-1", "read_file", serde_json::json!({ "path": "hello.txt" })));

    // Plain MCP out: the seeded text came back through all four hops.
    let content = structured(&response)["content"]
        .as_str()
        .expect("read_file returns content");
    assert_eq!(content, SEED_TEXT);

    // Transparency: the client never sees an MCP-S envelope — the signed response
    // was verified and stripped by the client proxy.
    assert!(
        response["result"]["_meta"].is_null(),
        "no MCP-S envelope may leak to the ordinary client: {response}"
    );

    // The verified request actually reached the inner fileserver.
    assert!(hop.inner_spawn_count() >= 1, "the inner server must be reached");
}
