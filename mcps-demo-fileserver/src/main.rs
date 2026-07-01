//! `mcps-demo-fileserver` binary entrypoint (MCPS-045).
//!
//! Runs the demo fileserver as a plain stdio MCP server: reads newline-delimited
//! JSON-RPC requests from stdin and writes one response line per request to
//! stdout. The demo root is selected with `--demo-root <DIR>` (required). Arg
//! parsing is std-only (no clap), consistent with the sibling stdio servers.
//!
//! ## Received-request log (anti-gaming)
//! For "deny-before-dispatch / inner not reached" tests, the server can record
//! every `tools/call` it ACTUALLY dispatches to an append-only file: one JSON
//! line `{"id":<json-rpc id>,"tool":"<name>"}` per served call. Enable it with
//! `--received-log <PATH>` or the `MCPS_DEMO_FILESERVER_RECEIVED_LOG` env var
//! (the flag wins). OFF by default, so ordinary runs are unaffected.
//!
//! Usage:
//!   mcps-demo-fileserver --demo-root <DIR> [--received-log <PATH>]

use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use mcps_demo_fileserver::serve_stdio;
use mcps_demo_fileserver::FileServer;

/// Env var fallback for the received-request log path (the `--received-log` flag
/// takes precedence when both are present).
const RECEIVED_LOG_ENV: &str = "MCPS_DEMO_FILESERVER_RECEIVED_LOG";

/// The parsed CLI: the required demo root plus an optional received-log path.
struct CliArgs {
    demo_root: String,
    received_log: Option<PathBuf>,
}

fn parse_args(argv: &[String]) -> Result<CliArgs, String> {
    let mut iter = argv.iter();
    let mut demo_root: Option<String> = None;
    let mut received_log: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--demo-root" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--demo-root requires a value".to_string())?;
                demo_root = Some(value.clone());
            }
            "--received-log" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--received-log requires a value".to_string())?;
                received_log = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    let demo_root = demo_root.ok_or_else(|| {
        "usage: mcps-demo-fileserver --demo-root <DIR> [--received-log <PATH>]".to_string()
    })?;
    // Env var is the fallback; an explicit flag wins.
    if received_log.is_none() {
        if let Ok(path) = std::env::var(RECEIVED_LOG_ENV) {
            let path = path.trim();
            if !path.is_empty() {
                received_log = Some(PathBuf::from(path));
            }
        }
    }
    Ok(CliArgs {
        demo_root,
        received_log,
    })
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let mut server = FileServer::new(args.demo_root);
    if let Some(path) = args.received_log {
        server = server
            .with_received_log(&path)
            .map_err(|e| format!("open received-log '{}': {e}", path.display()))?;
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    serve_stdio(&server, BufReader::new(stdin.lock()), &mut stdout)
        .map_err(|e| format!("stdio serve loop failed: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcps-demo-fileserver: {err}");
            ExitCode::FAILURE
        }
    }
}
