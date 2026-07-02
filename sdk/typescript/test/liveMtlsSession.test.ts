/**
 * Live full-transport MCP-S over mTLS (mirrors Python `test_e2e_mtls_session.py`).
 *
 * Drives the real {@link McpsHttpTransport} the production {@link connectMtlsHttp} builds,
 * against the REAL `mcps-proxy` fronting the REAL `mcps-demo-fileserver`. Two tests:
 *
 *  1. a `read_file` call round-trips (one signed mTLS POST, verified server-signed result);
 *  2. an ADR-047 `delete_files` continuation: the server elicits an InputRequiredResult and
 *     the client answers it — the transport records the MRT binding on the elicit leg and
 *     binds it on the answer leg, and the REAL proxy signs BOTH responses over the actual
 *     runtime request hashes (so this exercises `this.mrt` threading against the production
 *     PEP, not a fixture stand-in).
 *
 * Driven at the transport level (not through an MCP `Client`) because the elicitation
 * arrives as an InputRequiredResult *result*, which a `Client` delivers but cannot itself
 * continue — the application (here, the test) supplies the answer leg, as the four-hop
 * driver does. `initialize` is skipped: the proxy + stateless fileserver dispatch
 * `tools/call` directly, as the conformance matrix proves.
 *
 * Needs cargo + the built binaries (skips cleanly otherwise):
 *   cargo build -p mcps-proxy -p mcps-demo-fileserver
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  McpsHttpTransport,
  Signer,
  SignerPolicy,
  TrustResolver,
  connectMtlsHttp,
  type McpsConfig,
} from "../dist/index.js";

const ROOT = resolve(__dirname, "..", "..", "..");
const PROXY = join(ROOT, "target", "debug", "mcps-proxy");
const FILESERVER = join(ROOT, "target", "debug", "mcps-demo-fileserver");
const HAVE_CARGO = spawnSync("cargo", ["--version"]).status === 0;
const RUNNABLE = existsSync(PROXY) && existsSync(FILESERVER) && HAVE_CARGO;

// Deterministic DemoFixtures defaults (only the TLS certs vary per run).
const SIGNER_SEED = Buffer.alloc(32, 1);
const SERVER_SEED = Buffer.alloc(32, 2);
const SIGNER = "did:example:agent-1";
const SIGNER_KEY = "key-1";
const SERVER = "did:example:server-1";
const SERVER_KEY = "server-key-1";
const AUDIENCE = "did:example:server-1";
const SERVER_NAME = "proxy.internal";
const ON_BEHALF_OF = "did:example:user-1";
// A concrete, valid authorization-binding digest (SHA-256 of the empty artifact) — the
// four-hop PEP verifies the signature over the binding but enforces no scope, so any
// self-consistent binding is accepted (the same value the driver signs with).
const AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const FILE_TEXT = "hello from the inner fileserver\n";

let proc: ChildProcess | undefined;
let outDir = "";
let demoDir = "";
let port = 0;

function config(): McpsConfig {
  const resolver = new TrustResolver();
  resolver.insertDevSeed(SERVER, SERVER_KEY, SERVER_SEED);
  return {
    signer: Signer.software(SIGNER_SEED, SIGNER, SIGNER_KEY),
    policy: new SignerPolicy(SIGNER, "dev-test", true),
    resolver,
    audience: AUDIENCE,
    onBehalfOf: ON_BEHALF_OF,
    bindingDigestAlg: "sha256",
    bindingDigestValue: AUTHZ_DIGEST,
    expectedServerSigner: SERVER,
    enforcementMode: "require_mcps",
    ttlSeconds: 300,
  };
}

function transport(): McpsHttpTransport {
  return connectMtlsHttp("127.0.0.1", port, config(), {
    serverCa: readFileSync(join(outDir, "server_ca.pem")),
    clientCert: readFileSync(join(outDir, "client_cert.pem")),
    clientKey: readFileSync(join(outDir, "client_key.pem")),
    serverName: SERVER_NAME,
  });
}

/** A serialized inbox over `onmessage`: `next()` resolves with the next delivered message. */
function inbox(t: McpsHttpTransport): () => Promise<any> {
  const queued: any[] = [];
  const waiters: Array<(m: any) => void> = [];
  t.onmessage = (m: any) => {
    const w = waiters.shift();
    if (w) w(m);
    else queued.push(m);
  };
  return () => {
    const m = queued.shift();
    return m !== undefined ? Promise.resolve(m) : new Promise((r) => waiters.push(r));
  };
}

const req = (id: string, params: Record<string, unknown>): any => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params,
});

beforeAll(async () => {
  if (!RUNNABLE) return;
  outDir = mkdtempSync(join(tmpdir(), "mcps_ts_sess_fx_"));
  demoDir = mkdtempSync(join(tmpdir(), "mcps_ts_sess_root_"));
  writeFileSync(join(demoDir, "greeting.txt"), FILE_TEXT);

  const emit = spawnSync(
    "cargo",
    ["run", "-q", "-p", "mcps-demo", "--example", "emit_mtls_fixtures", "--", outDir],
    { cwd: ROOT, encoding: "utf-8" },
  );
  if (emit.status !== 0) throw new Error(`emit_mtls_fixtures failed: ${emit.stderr}`);

  proc = spawn(
    PROXY,
    [
      "--bind", "127.0.0.1:0", "--audience", AUDIENCE,
      "--server-signer", SERVER, "--server-key-id", SERVER_KEY,
      "--max-clock-skew", "300", "--expected-version-policy", "draft-02-only",
      "--key-source", "file", "--signing-key-seed", join(outDir, "signing_seed"),
      "--tls-cert", join(outDir, "server_cert.pem"), "--tls-key", join(outDir, "server_key.pem"),
      "--client-ca", join(outDir, "client_ca.pem"), "--trust", join(outDir, "trust.json"),
      "--max-client-cert-lifetime", "175200h", "--transport-binding", "none",
      "--inner-working-dir", demoDir, "--inner-command", FILESERVER, "--demo-root", demoDir,
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );

  port = await new Promise<number>((resolvePort, rejectPort) => {
    const timer = setTimeout(() => rejectPort(new Error("mcps-proxy did not report a listening port")), 30000);
    let buf = "";
    proc!.stderr!.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = buf.match(/listening on 127\.0\.0\.1:(\d+)/);
      if (m) {
        clearTimeout(timer);
        resolvePort(parseInt(m[1], 10));
      }
    });
    proc!.on("exit", (code) => {
      clearTimeout(timer);
      rejectPort(new Error(`mcps-proxy exited early (code ${code})`));
    });
  });
}, 120000);

afterAll(() => {
  proc?.kill();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
  if (demoDir) rmSync(demoDir, { recursive: true, force: true });
});

describe.skipIf(!RUNNABLE)("live full-transport MCP-S over mTLS", () => {
  it("round-trips a read_file call over real mTLS", async () => {
    const t = transport();
    const next = inbox(t);
    await t.start();
    await t.send(req("rf-1", { name: "read_file", arguments: { path: "greeting.txt" } }));
    const result = await next();
    expect(result.result.isError).toBe(false);
    expect(result.result.content[0].text).toBe(FILE_TEXT);
    expect("_meta" in result.result).toBe(false); // the MCP-S envelope is stripped
    await t.close();
  });

  it("drives a delete_files continuation over real mTLS (transport MRT threading)", async () => {
    const t = transport();
    const next = inbox(t);
    await t.start();

    // Leg 1 — elicit: no inputResponses, so the server returns an InputRequiredResult and
    // the transport records its MRT binding.
    await t.send(req("del-1", { name: "delete_files", arguments: { paths: ["greeting.txt"] } }));
    const elicit = await next();
    expect(elicit.result.resultType).toBe("inputRequired");
    expect("_meta" in elicit.result).toBe(false);
    const state = elicit.result.requestState as string;

    // Leg 2 — answer: inputResponses + the echoed requestState. The transport must bind the
    // recorded continuation; the proxy verifies and the fileserver returns the terminal.
    await t.send(
      req("del-2", {
        name: "delete_files",
        arguments: { paths: ["greeting.txt"] },
        inputResponses: { confirm: true },
        requestState: state,
      }),
    );
    const terminal = await next();
    expect(terminal.result.isError).toBe(false);
    expect(terminal.result.structuredContent).toEqual({ deleted: ["greeting.txt"], confirmed: true });
    await t.close();
  });
});
