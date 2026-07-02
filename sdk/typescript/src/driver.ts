#!/usr/bin/env node
/**
 * MCP-S conformance driver — the TypeScript SDK as an interchangeable client leg.
 *
 * This is the TypeScript side of the multi-SDK test architecture (see
 * `mcps-walkthrough` `ClientDriver`), a drop-in for the Rust reference
 * `mcps-client-proxy-cli` and the Python `mcps_sdk.driver`. It is a thin stdio bridge:
 * it reads one plain MCP JSON-RPC request per line on stdin, signs it with the SDK,
 * POSTs it over mTLS to the `mcps-proxy` PEP, verifies the server-signed response,
 * strips the MCP-S envelope, and writes one plain MCP JSON-RPC response per line on
 * stdout.
 *
 * The signing/verification is the AUDITED `mcps-client-core` logic via the SDK's napi
 * core (`signRequestWithSigner` / `verifyResponse`). No `@modelcontextprotocol/sdk`
 * dependency: the harness IS the MCP client, so this bridge never opens a session; it
 * only signs the raw JSON-RPC it is handed.
 *
 * Run it as the walkthrough harness's TypeScript client leg::
 *
 *     MCPS_DRIVER_TS="node dist/driver.js" \
 *       cargo test -p mcps-walkthrough --test sdk_driver_matrix -- --nocapture
 *
 * The harness appends the shared client CLI arg surface (`--remote-addr` …). The
 * file/software key source is fully in-process; the `--key-source gcp-kms` path signs
 * via a synchronous `curl` call to Cloud KMS `asymmetricSign` (Node has no native
 * synchronous HTTP, and the napi non-exporting sign callback is synchronous).
 */

import { connect as tlsConnect } from "node:tls";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import * as core from "../native/binding.js";

// A concrete, valid authorization-binding digest (SHA-256 of the empty artifact,
// Base64URL-no-pad) — the same value the live mTLS interop test signs with. The
// four-hop PEP verifies the request signature over the preimage (which includes the
// binding) but enforces no authorization scope, so any self-consistent binding is
// accepted; this one is proven against the real proxy.
const AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

// JSON-RPC server-error code carrying a fail-closed MCP-S rejection back to the harness.
const MCPS_REJECTED_CODE = -32099;

interface Args {
  remoteAddr: string;
  serverName: string;
  signerId: string;
  keyId: string;
  signingKeySeed?: string;
  serverSigner: string;
  serverKeyId: string;
  serverPubkey: string;
  audience: string;
  tlsCert: string;
  tlsKey: string;
  serverCa: string;
  onBehalfOf: string;
  keySource: string;
  gcpKmsKeyVersion?: string;
  gcpKmsEndpoint?: string;
  gcpKmsUseMetadata: boolean;
}

function rfc3339(unix: number): string {
  return new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Decode Base64URL, tolerating missing padding (the SDK/CLI wire form). */
function b64urlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

/** Resolve `--signing-key-seed` (a Base64URL seed, or `@<path>`) to raw 32 seed bytes. */
function readSeed(spec: string): Buffer {
  let raw = spec;
  if (spec.startsWith("@")) {
    raw = readFileSync(spec.slice(1), "utf-8").trim();
  }
  const seed = b64urlDecode(raw);
  if (seed.length !== 32) {
    throw new Error(`signing key seed must be 32 bytes, got ${seed.length}`);
  }
  return seed;
}

/**
 * Reproduce `mcps_client_core::AudienceTuple::to_audience_string` from the 6-field
 * `--audience` form (`scheme,host,port,tenant,route,realm`). A drift makes the round
 * trip fail closed (audience mismatch), never silently pass.
 */
function canonicalAudience(sixField: string): string {
  const parts = sixField.split(",");
  if (parts.length !== 6) {
    throw new Error(`--audience must have 6 comma fields, got ${parts.length}: ${JSON.stringify(sixField)}`);
  }
  const [scheme, host, port, tenant, route, realm] = parts;
  return (
    `mcps-audience:v1:scheme=${scheme};host=${host};port=${port};` +
    `tenant=${tenant};route=${route};realm=${realm}`
  );
}

/** The OAuth2 bearer for Cloud KMS: the GCE metadata server or `MCPS_GCP_ACCESS_TOKEN`. */
function gcpAccessToken(useMetadata: boolean): string {
  if (useMetadata) {
    const out = execFileSync(
      "curl",
      [
        "-s",
        "-H",
        "Metadata-Flavor: Google",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      ],
      { encoding: "utf-8" },
    );
    return JSON.parse(out).access_token as string;
  }
  const token = process.env.MCPS_GCP_ACCESS_TOKEN ?? "";
  if (!token) {
    throw new Error(
      "MCPS_GCP_ACCESS_TOKEN must be set for --key-source gcp-kms (or pass --gcp-kms-use-metadata on GCE)",
    );
  }
  return token;
}

/**
 * A non-exporting signer callback: Ed25519-sign the preimage via Cloud KMS
 * `asymmetricSign` and return the Base64URL-no-pad signature the SDK core wants. The
 * KMS key is `EC_SIGN_ED25519` (PureEdDSA), so the RAW preimage is signed as `data`
 * (not a pre-hashed digest) — the SAME preimage/algorithm the software path signs. The
 * private key never leaves KMS (custody `NonExporting`). Synchronous via `curl` because
 * the napi sign callback must return a signature inline.
 */
function gcpKmsSignCallback(keyVersion: string, endpoint: string | undefined, token: string): (preimage: Buffer) => string {
  const base = endpoint ?? "https://cloudkms.googleapis.com";
  const url = `${base}/v1/${keyVersion}:asymmetricSign`;
  return (preimage: Buffer): string => {
    const body = JSON.stringify({ data: preimage.toString("base64") });
    const out = execFileSync(
      "curl",
      ["-s", "-X", "POST", url, "-H", `Authorization: Bearer ${token}`, "-H", "Content-Type: application/json", "-d", body],
      { encoding: "utf-8" },
    );
    const rawSig = Buffer.from(JSON.parse(out).signature as string, "base64"); // 64-byte Ed25519 sig
    return rawSig.toString("base64url");
  };
}

/** Build the request signer + custody policy for the configured key source. */
function buildSigner(args: Args): { signer: core.Signer; policy: core.SignerPolicy } {
  if (args.keySource === "gcp-kms") {
    if (!args.gcpKmsKeyVersion) throw new Error("--gcp-kms-key-version is required for --key-source gcp-kms");
    const token = gcpAccessToken(args.gcpKmsUseMetadata);
    const callback = gcpKmsSignCallback(args.gcpKmsKeyVersion, args.gcpKmsEndpoint, token);
    const signer = core.Signer.nonExporting(args.signerId, args.keyId, callback);
    const policy = new core.SignerPolicy(args.signerId, "production", true).requireNonExporting();
    return { signer, policy };
  }
  if (!args.signingKeySeed) throw new Error("--signing-key-seed is required for --key-source file");
  const signer = core.Signer.software(readSeed(args.signingKeySeed), args.signerId, args.keyId);
  const policy = new core.SignerPolicy(args.signerId, "dev-test", true);
  return { signer, policy };
}

/**
 * If `params` is a continuation answer (carries `inputResponses` AND an echoed
 * `requestState`, SEP-2322), return the `requestState` handle; else null. The handle
 * keys the recorded multi-round-trip binding (ADR-MCPS-047).
 */
function continuationState(params: unknown): string | null {
  if (typeof params === "object" && params !== null) {
    const p = params as Record<string, unknown>;
    if ("inputResponses" in p && "requestState" in p) {
      return typeof p.requestState === "string" ? p.requestState : null;
    }
  }
  return null;
}

/** Remove the MCP-S response envelope from `result._meta` so the harness sees plain MCP. */
function stripEnvelope(obj: Record<string, unknown>): Record<string, unknown> {
  const result = obj.result as Record<string, unknown> | undefined;
  if (result && typeof result === "object") {
    const meta = result._meta as Record<string, unknown> | undefined;
    if (meta && typeof meta === "object") {
      delete meta[core.responseMetaKey()];
      if (Object.keys(meta).length === 0) delete result._meta;
    }
  }
  return obj;
}

function parseArgs(argv: string[]): Args {
  const map = new Map<string, string>();
  const flags = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    if (key === "gcp-kms-use-metadata") {
      flags.add(key);
    } else {
      map.set(key, argv[++i]);
    }
  }
  const req = (k: string): string => {
    const v = map.get(k);
    if (v === undefined) throw new Error(`missing required arg --${k}`);
    return v;
  };
  return {
    remoteAddr: req("remote-addr"),
    serverName: req("server-name"),
    signerId: req("signer-id"),
    keyId: req("key-id"),
    signingKeySeed: map.get("signing-key-seed"),
    serverSigner: req("server-signer"),
    serverKeyId: req("server-key-id"),
    serverPubkey: req("server-pubkey"),
    audience: req("audience"),
    tlsCert: req("tls-cert"),
    tlsKey: req("tls-key"),
    serverCa: req("server-ca"),
    onBehalfOf: req("on-behalf-of"),
    keySource: map.get("key-source") ?? "file",
    gcpKmsKeyVersion: map.get("gcp-kms-key-version"),
    gcpKmsEndpoint: map.get("gcp-kms-endpoint"),
    gcpKmsUseMetadata: flags.has("gcp-kms-use-metadata"),
  };
}

/** One mTLS HTTP/1.1 POST per call (Connection: close) — the proxy's wire. */
function makePost(args: Args): (body: Buffer) => Promise<Buffer> {
  const [host, portStr] = args.remoteAddr.split(/:(?=[^:]+$)/);
  const port = parseInt(portStr, 10);
  const ca = readFileSync(args.serverCa);
  const cert = readFileSync(args.tlsCert);
  const key = readFileSync(args.tlsKey);
  return (body: Buffer) =>
    new Promise<Buffer>((resolve, reject) => {
      const socket = tlsConnect({ host, port, ca, cert, key, servername: args.serverName, timeout: 15000 });
      const chunks: Buffer[] = [];
      socket.on("secureConnect", () => {
        const head = Buffer.from(
          `POST / HTTP/1.1\r\nHost: ${args.serverName}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
        );
        socket.write(Buffer.concat([head, body]));
      });
      socket.on("data", (d: Buffer) => chunks.push(d));
      socket.on("error", reject);
      socket.on("timeout", () => reject(new Error("mTLS POST timed out")));
      socket.on("end", () => {
        const raw = Buffer.concat(chunks);
        const sep = raw.indexOf("\r\n\r\n");
        resolve(sep >= 0 ? raw.subarray(sep + 4) : raw);
      });
    });
}

function reject(rid: unknown, reason: string | undefined): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: rid ?? null,
    error: { code: MCPS_REJECTED_CODE, message: reason ?? "mcps.verification_failed" },
  };
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const args = parseArgs(argv);
  const { signer, policy } = buildSigner(args);
  const resolver = new core.TrustResolver();
  resolver.insertPublicKey(args.serverSigner, args.serverKeyId, b64urlDecode(args.serverPubkey));
  const audience = canonicalAudience(args.audience);
  const post = makePost(args);

  const emit = (obj: Record<string, unknown>): void => {
    process.stdout.write(JSON.stringify(obj) + "\n");
  };

  // ADR-MCPS-047 multi-round-trip state: the opaque server `requestState` handle ->
  // the verified continuation binding `[previousRequestHash, inputRequiredResponseHash]`.
  // Populated when an InputRequiredResult is verified; consumed (single-use) when the
  // client answers it. Persists across the line loop (one long-lived driver process).
  const mrt = new Map<string, [string, string]>();

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const rawLine of rl) {
    const line = rawLine.trim();
    if (!line) continue;
    const request = JSON.parse(line) as Record<string, unknown>;
    const rid = request.id;
    const method = request.method;
    if (typeof method !== "string") {
      emit(reject(rid, "mcps.missing_envelope"));
      continue;
    }
    const params = request.params ?? {};

    // ADR-MCPS-047 answer leg: a call carrying `inputResponses` + an echoed
    // `requestState` is a continuation. Bind it to the verified InputRequiredResult
    // recorded under that handle; no recorded state (unknown or already-used) fails
    // closed — we never sign an unbound continuation.
    let continuation: { continuationPreviousRequestHash?: string; continuationInputRequiredResponseHash?: string } =
      {};
    const requestState = continuationState(params);
    if (requestState !== null) {
      const entry = mrt.get(requestState);
      if (entry === undefined) {
        emit(reject(rid, "mcps.continuation_malformed"));
        continue;
      }
      mrt.delete(requestState);
      continuation = {
        continuationPreviousRequestHash: entry[0],
        continuationInputRequiredResponseHash: entry[1],
      };
    }

    try {
      const now = Math.floor(Date.now() / 1000);
      const signed = core.signRequestWithSigner(
        JSON.stringify(rid),
        method,
        JSON.stringify(params),
        {
          onBehalfOf: args.onBehalfOf,
          audience,
          bindingDigestAlg: "sha256",
          bindingDigestValue: AUTHZ_DIGEST,
          nonce: randomNonce(),
          issuedAt: rfc3339(now),
          expiresAt: rfc3339(now + 300),
          ...continuation,
        },
        signer,
        policy,
      );
      const body = await post(Buffer.from(signed.wireBytes));
      const result = core.verifyResponse(body, resolver, {
        expectedRequestHash: signed.requestHash,
        expectedServerSigner: args.serverSigner,
        enforcementMode: "require_mcps",
      });
      if (result.accepted) {
        const plain = stripEnvelope(JSON.parse(body.toString("utf-8")));
        // A verified, NON-TERMINAL InputRequiredResult (D7): record the continuation
        // binding keyed by the server's opaque requestState so the answer leg can bind
        // it. The elicitation is delivered to the harness either way.
        if (result.inputRequired) {
          const inner = plain.result as Record<string, unknown> | undefined;
          const state = inner && typeof inner === "object" ? inner.requestState : undefined;
          if (typeof state === "string") {
            mrt.set(state, [signed.requestHash, result.responseHash as string]);
          }
        }
        emit(plain);
      } else {
        emit(reject(rid, result.reason));
      }
    } catch (exc) {
      emit(reject(rid, `mcps.driver_error: ${exc instanceof Error ? exc.message : exc}`));
    }
  }
  return 0;
}

function randomNonce(): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require("node:crypto").randomBytes(16).toString("base64url");
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(String(err) + "\n");
      process.exit(1);
    },
  );
}
