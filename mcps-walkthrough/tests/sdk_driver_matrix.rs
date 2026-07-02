//! SDK driver matrix — the pluggable client-leg seam (multi-SDK test architecture).
//!
//! Every MCP-S SDK is an INTERCHANGEABLE client: it signs requests and verifies
//! responses, honoring the same stdio + CLI contract the Rust reference proxy does.
//! This test runs the T0 base case (a signed round-trip through the full four-hop)
//! against EVERY client driver configured in the environment.
//!
//! The Rust reference driver (`mcps-client-proxy-cli`) is always present; each
//! additional SDK driver joins via its env key — skip-not-fail, so a contributor
//! without a given SDK's toolchain runs the drivers they have and NEVER fails on the
//! ones they lack. What was skipped is logged, so a partial matrix never reads as
//! full coverage.
//!
//! Run the whole matrix (Rust reference + a Python SDK driver):
//! ```sh
//! MCPS_DRIVER_PYTHON="python3 -m mcps_sdk.driver" \
//!   cargo test -p mcps-walkthrough --test sdk_driver_matrix -- --nocapture
//! ```
//! With no env keys set it runs the Rust driver alone — the always-on lane.

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::tool_call_continuation;
use mcps_walkthrough::ClientDriver;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::FourHopOptions;
use mcps_walkthrough::SEED_TEXT;

#[test]
fn every_configured_sdk_driver_round_trips_a_signed_call() {
    let drivers = ClientDriver::available();

    // Surface which SDK drivers were NOT configured, so a partial run is never
    // mistaken for full multi-SDK coverage.
    for (label, key) in [
        ("python", "MCPS_DRIVER_PYTHON"),
        ("typescript", "MCPS_DRIVER_TS"),
    ] {
        if std::env::var_os(key).is_none() {
            eprintln!("[driver-matrix] SKIP {label}: {key} not set");
        }
    }

    for driver in &drivers {
        eprintln!("[driver-matrix] RUN {} ({:?})", driver.label, driver.command);
        let mut hop = FourHop::launch_with(FourHopOptions {
            client_driver: Some(driver.clone()),
            ..FourHopOptions::default()
        });

        // The T0 guarantee, driver-agnostic: a plain call is signed, verified,
        // served, response-signed, and the binding verified — all by whichever SDK
        // sits on the client leg — and the plain client sees no MCP-S envelope.
        let response = hop.call(&tool_call(
            &format!("matrix-{}", driver.label),
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        ));
        let content = structured(&response)["content"].as_str().unwrap_or_else(|| {
            panic!(
                "driver '{}' read_file returned no content: {response}",
                driver.label
            )
        });
        assert_eq!(
            content, SEED_TEXT,
            "driver '{}' must round-trip the signed call",
            driver.label
        );
        assert!(
            response["result"]["_meta"].is_null(),
            "driver '{}' leaked an MCP-S envelope to the plain client: {response}",
            driver.label
        );
        assert!(
            hop.inner_spawn_count() >= 1,
            "driver '{}' must reach the inner server",
            driver.label
        );
    }

    // The Rust reference driver is the always-on floor of the matrix.
    assert!(
        drivers.iter().any(|d| d.label == "rust"),
        "the Rust reference driver must always be available and run"
    );
}

/// The cross-language NEGATIVE: every configured driver must FAIL CLOSED when the
/// server is untrusted. The PEP signs a genuine response, but the client leg is
/// handed a valid-but-wrong server public key — so response verification cannot
/// succeed and no SDK may surface the file content. This proves each SDK's
/// verification is real (not a rubber stamp) through the whole four-hop, not just
/// in its own unit suite.
#[test]
fn every_configured_sdk_driver_fails_closed_on_an_untrusted_server() {
    for driver in &ClientDriver::available() {
        eprintln!("[driver-matrix-neg] RUN {} ({:?})", driver.label, driver.command);
        let mut hop = FourHop::launch_with(FourHopOptions {
            client_driver: Some(driver.clone()),
            tamper_server_pubkey: true,
            ..FourHopOptions::default()
        });

        let response = hop.call(&tool_call(
            &format!("neg-{}", driver.label),
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        ));

        // Fail closed: an error, and NEVER a plain result carrying the file text.
        assert!(
            response.get("error").is_some(),
            "driver '{}' must fail closed on an untrusted server, got: {response}",
            driver.label
        );
        assert!(
            response.get("result").is_none(),
            "driver '{}' must surface no result on a fail-closed exchange: {response}",
            driver.label
        );
        assert!(
            !response.to_string().contains(SEED_TEXT.trim()),
            "driver '{}' must not leak inner file content on fail-closed: {response}",
            driver.label
        );
    }
}

/// The ADR-MCPS-047 multi-round-trip (elicitation → continuation) SECURITY SHAPE,
/// driver-agnostic. This is NOT a test of MCP elicitation semantics — it proves the
/// one new MCP-S evidence class end to end through EVERY interchangeable client leg:
///
/// ```text
/// signed request
///   -> signed InputRequiredResult (bound to the first request_hash)
///   -> driver records the continuation state
///   -> signed continuation request (carries the continuation binding)
///   -> signed terminal response (bound to the CONTINUATION request_hash)
/// ```
///
/// If any leg's evidence failed — an unsigned/misbound InputRequiredResult, a missing
/// or malformed continuation binding, a terminal bound to the wrong request_hash — the
/// driver would fail closed and the round trip could not complete. Completion across
/// the Rust reference + every configured SDK driver is therefore the proof.
#[test]
fn every_configured_sdk_driver_completes_an_mrt_continuation() {
    let drivers = ClientDriver::available();

    for (label, key) in [
        ("python", "MCPS_DRIVER_PYTHON"),
        ("typescript", "MCPS_DRIVER_TS"),
    ] {
        if std::env::var_os(key).is_none() {
            eprintln!("[driver-matrix] SKIP mrt {label}: {key} not set");
        }
    }

    for driver in &drivers {
        eprintln!("[driver-matrix] MRT {} ({:?})", driver.label, driver.command);
        let mut hop = FourHop::launch_with(FourHopOptions {
            client_driver: Some(driver.clone()),
            ..FourHopOptions::default()
        });

        let paths = serde_json::json!(["a.txt", "b.txt"]);

        // Leg 1 — the ordinary client sends a plain `delete_files` call. The inner
        // returns an InputRequiredResult; the server signs it (bound to the request
        // hash) and the driver verifies + classifies it non-terminal, delivering the
        // elicitation as plain MCP with NO MCP-S envelope leaked.
        let elicit = hop.call(&tool_call(
            &format!("mrt1-{}", driver.label),
            "delete_files",
            serde_json::json!({ "paths": paths.clone() }),
        ));
        assert_eq!(
            elicit["result"]["resultType"], "inputRequired",
            "driver '{}' must surface the signed InputRequiredResult: {elicit}",
            driver.label
        );
        assert!(
            elicit["result"]["_meta"].is_null(),
            "driver '{}' leaked an MCP-S envelope on the elicitation: {elicit}",
            driver.label
        );
        let request_state = elicit["result"]["requestState"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "driver '{}' elicitation carried no requestState to echo: {elicit}",
                    driver.label
                )
            })
            .to_string();

        // Leg 2 — the client answers. The driver looks up the recorded continuation
        // binding by `requestState` and signs a continuation request carrying it; the
        // server verifies the continuation (its binding rides inside the signed
        // preimage) and the inner returns the terminal result, bound to the
        // CONTINUATION request hash. The plain client sees a clean terminal result.
        let terminal = hop.call(&tool_call_continuation(
            &format!("mrt2-{}", driver.label),
            "delete_files",
            serde_json::json!({ "paths": paths.clone() }),
            serde_json::json!({ "confirm": true }),
            &request_state,
        ));
        assert!(
            terminal.get("error").is_none(),
            "driver '{}' continuation must complete, got error: {terminal}",
            driver.label
        );
        let structured_content = structured(&terminal);
        assert_eq!(
            structured_content["confirmed"], true,
            "driver '{}' terminal must confirm the deletion: {terminal}",
            driver.label
        );
        assert_eq!(
            structured_content["deleted"], paths,
            "driver '{}' terminal must report the echoed paths",
            driver.label
        );
        assert!(
            terminal["result"]["_meta"].is_null(),
            "driver '{}' leaked an MCP-S envelope on the terminal: {terminal}",
            driver.label
        );
    }
}
