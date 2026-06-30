//! Tier T3 — "External users" (ADR-MCPS-045).
//!
//! Persona: the small company now exposes the server to EXTERNAL callers, so the
//! CHANNEL identity matters. The new concept is TRANSPORT-IDENTITY BINDING: the
//! server PEP runs `--transport-binding exact`, requiring the verified mTLS client
//! identity (URI SAN) to EQUAL the request signer. Message-level MCP-S still does
//! the real work; this tier ties it to the channel so a validly-issued client
//! certificate belonging to a DIFFERENT identity cannot front another signer's
//! requests.
//!
//! The proofs, all over the real four-hop:
//!   1. positive — a matching identity passes `exact`, and the inner's OWN
//!      append-only received-log records the dispatched call;
//!   2. attribution — the SAME mismatched client cert that is rejected under
//!      `exact` SUCCEEDS with binding OFF (`none`): the handshake/cert are valid,
//!      so the only thing the `exact` rejection can be attributing is the
//!      identity≠signer mismatch — not a broken channel;
//!   3. the cross-process deny — under `exact` the mismatched identity is refused
//!      before dispatch: nothing is written, and the inner's own record never saw
//!      the call (deny-at-the-PEP, proven across processes, not just by a proxy
//!      lifecycle marker);
//!   4. server-identity negative — a wrong expected `--server-name` yields no
//!      trustworthy signed response, so the client fails CLOSED and no inner data
//!      is returned.
//!
//! A note the tests make concrete: at this boundary the client's guarantee is
//! binary — it either gets a verified, response-bound envelope or it fails closed.
//! The *reason* a remote refused (e.g. `transport_binding_failed`) travels in an
//! UNSIGNED error body the client rightly distrusts, so the client surfaces a
//! generic fail-closed reason, not the remote's claim. The server-side reason is
//! pinned by the in-process `mcps-proxy` suite; here we prove the OUTCOME — denied
//! before dispatch — across real processes.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::ClientCert;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::FourHopOptions;
use mcps_walkthrough::TransportBinding;

/// A unique received-log path under the test temp area, plus a guard that wipes
/// its directory on drop. The inner fileserver creates the file itself; a request
/// denied before dispatch leaves it absent (read back as empty).
struct LogPath {
    path: PathBuf,
    dir: PathBuf,
}

impl LogPath {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .or_else(|| std::env::var_os("TEST_TMPDIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("mcps-walkthrough-t3-log-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create received-log dir");
        LogPath {
            path: dir.join("received.log"),
            dir,
        }
    }

    fn contents(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }
}

impl Drop for LogPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// True when the plain response is a fail-closed JSON-RPC error (no result).
fn failed_closed(resp: &serde_json::Value) -> bool {
    resp.get("error").is_some() && resp.get("result").is_none()
}

#[test]
fn matching_identity_passes_exact_binding_and_is_recorded() {
    let log = LogPath::new();
    let mut hop = FourHop::launch_with(FourHopOptions {
        transport_binding: TransportBinding::Exact,
        client_cert: ClientCert::Matching,
        received_log: Some(log.path.clone()),
        ..FourHopOptions::default()
    });

    let written = "external write under exact binding\n";
    let resp = hop.call(&tool_call(
        "t3-allow",
        "write_file",
        serde_json::json!({ "path": "external.txt", "content": written }),
    ));
    assert_eq!(
        structured(&resp)["bytes_written"].as_u64(),
        Some(written.len() as u64),
        "matching identity must pass exact binding: {resp}"
    );
    assert_eq!(
        std::fs::read_to_string(hop.root_file("external.txt")).expect("file on disk"),
        written
    );

    // The inner's OWN append-only record confirms it dispatched the allowed call,
    // and the PEP did spawn the inner once for it (the live counterpart to the
    // denied request's zero spawns below).
    let recorded = log.contents();
    assert!(
        recorded.contains("\"id\":\"t3-allow\"") && recorded.contains("\"tool\":\"write_file\""),
        "the inner's received-log must record the allowed dispatch: {recorded:?}"
    );
    assert_eq!(hop.inner_spawn_count(), 1, "an allowed call spawns the inner once");
}

#[test]
fn the_same_mismatched_cert_passes_with_binding_off() {
    // Binding OFF: mTLS still authenticates the channel (same client CA), but the
    // client identity is NOT required to equal the signer. The mismatched leaf is
    // a perfectly valid certificate, so the call SUCCEEDS — establishing that the
    // `exact` rejection in the next test is attributable to the identity binding,
    // not to a broken handshake or an untrusted cert.
    let mut hop = FourHop::launch_with(FourHopOptions {
        transport_binding: TransportBinding::None,
        client_cert: ClientCert::Mismatched,
        ..FourHopOptions::default()
    });

    let resp = hop.call(&tool_call(
        "t3-nobind",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    assert_eq!(
        structured(&resp)["content"].as_str(),
        Some(mcps_walkthrough::SEED_TEXT),
        "a valid mismatched cert must pass when identity binding is off: {resp}"
    );
}

#[test]
fn mismatched_identity_is_denied_before_dispatch_under_exact_binding() {
    let log = LogPath::new();
    let mut hop = FourHop::launch_with(FourHopOptions {
        transport_binding: TransportBinding::Exact,
        client_cert: ClientCert::Mismatched,
        received_log: Some(log.path.clone()),
        ..FourHopOptions::default()
    });

    // Same client CA → the handshake succeeds and the signed request reaches the
    // PEP; but the leaf's URI SAN != the request signer, so `exact` binding fails
    // CLOSED before the inner is ever consulted. The client cannot trust the
    // remote's (unsigned) reason, so it surfaces a generic fail-closed verdict —
    // the OUTCOME is what this tier proves.
    let resp = hop.call(&tool_call(
        "t3-deny",
        "write_file",
        serde_json::json!({ "path": "intruder.txt", "content": "should never land\n" }),
    ));
    assert!(
        failed_closed(&resp),
        "a mismatched mTLS identity must fail closed under exact binding: {resp}"
    );

    // Nothing was written...
    assert!(
        !hop.root_file("intruder.txt").exists(),
        "a denied request must not write to the demo root"
    );
    // ...the inner's OWN record never saw the call — the cross-process proof that
    // the deny happened at the PEP, not inside the inner server...
    let recorded = log.contents();
    assert!(
        !recorded.contains("\"id\":\"t3-deny\""),
        "the inner must never have recorded the denied call: {recorded:?}"
    );
    // ...and the PEP never even spawned the inner for this request.
    assert_eq!(
        hop.inner_spawn_count(),
        0,
        "the PEP must not dispatch to the inner for a denied request"
    );
}

#[test]
fn a_wrong_expected_server_name_fails_closed_with_no_inner_data() {
    // The client proxy verifies the remote's cert against the server CA AND the
    // expected name; a wrong name means the client never obtains a trustworthy
    // signed response, so it fails CLOSED. No inner file content is returned.
    let mut hop = FourHop::launch_with(FourHopOptions {
        transport_binding: TransportBinding::Exact,
        client_cert: ClientCert::Matching,
        received_log: None,
        server_name_override: Some("wrong.server.invalid".to_string()),
        ..FourHopOptions::default()
    });

    let resp = hop.call(&tool_call(
        "t3-badname",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    assert!(
        failed_closed(&resp),
        "a wrong server name must fail closed, not return a result: {resp}"
    );
    assert!(
        !resp.to_string().contains(mcps_walkthrough::SEED_TEXT.trim()),
        "no inner file content may be returned on a failed-closed exchange: {resp}"
    );
}
