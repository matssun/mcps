/**
 * High-level entry points: build an MCP-S-secured `Transport` for an MCP `Client`.
 *
 * Unlike the Python SDK (whose `connect` yields a `ClientSession`), the MCP TypeScript
 * SDK's idiom is `await new Client(...).connect(transport)`. These helpers build the
 * secured transport the app connects — every request is signed and every response
 * verified, with application code otherwise unchanged from ordinary MCP.
 *
 * - {@link connectStdio} builds a byte channel from a subprocess (the common MCP stdio
 *   case): the subprocess must speak the MCP-S wire (a server-side MCP-S proxy/server).
 * - {@link connectMtlsHttp} builds the request/response transport whose every request
 *   is one MCP-S-signed mTLS POST to the production `mcps-proxy`.
 */

import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { spawn } from "node:child_process";
import type { Readable } from "node:stream";
import { McpsConfig, McpsTransport, TransportHooks } from "./transport.js";
import { McpsHttpTransport, type PostFn } from "./httpTransport.js";

/** Split a byte `Readable` (stdout) into newline-delimited lines (MCP stdio framing). */
async function* byteLines(stream: Readable): AsyncGenerator<Buffer> {
  let buffer = Buffer.alloc(0);
  for await (const chunk of stream) {
    buffer = Buffer.concat([buffer, chunk as Buffer]);
    let nl: number;
    while ((nl = buffer.indexOf(0x0a)) !== -1) {
      yield buffer.subarray(0, nl);
      buffer = buffer.subarray(nl + 1);
    }
  }
  if (buffer.length > 0) yield buffer;
}

/**
 * Spawn an MCP-S endpoint subprocess and build a secured transport over its stdio.
 *
 * The subprocess must speak the MCP-S wire (a server-side MCP-S proxy/server). The
 * returned transport owns the child process: `transport.close()` terminates it. Hand it
 * to `await new Client(...).connect(transport)`.
 */
export function connectStdio(
  command: string,
  args: string[],
  config: McpsConfig,
  opts: { env?: NodeJS.ProcessEnv; hooks?: TransportHooks } = {},
): McpsTransport {
  const child = spawn(command, args, {
    stdio: ["pipe", "pipe", "inherit"],
    // Merge over the parent environment so callers that set a few vars don't drop PATH
    // and other required defaults (spawn REPLACES the whole env when `env` is given).
    env: opts.env ? { ...process.env, ...opts.env } : undefined,
  });
  const byteSend = (data: Buffer): Promise<void> =>
    new Promise((resolve, reject) => {
      child.stdin.write(data, (err) => (err ? reject(err) : resolve()));
    });
  const transport = new McpsTransport(byteSend, byteLines(child.stdout), config, opts.hooks);
  const close = transport.close.bind(transport);
  transport.close = async (): Promise<void> => {
    child.kill();
    await close();
  };
  return transport;
}

/**
 * Build a transport whose every request is one MCP-S-signed mTLS POST to the production
 * `mcps-proxy` (verified server-signed response).
 *
 * The proxy serves one HTTP/1.1 POST per mTLS connection (`Connection: close`), so each
 * `Client` request opens its own connection. `initialize` round-trips as a normal
 * signed request; client->server notifications are dropped (the transport has no
 * fire-and-forget channel and the minimal proxy never pushes).
 *
 * The client authenticates with `clientCert` / `clientKey` (the cert's URI SAN is the
 * MCP-S signer DID) and verifies the proxy's server certificate against `serverCa` for
 * `serverName`.
 */
export function connectMtlsHttp(
  host: string,
  port: number,
  config: McpsConfig,
  tls: {
    serverCa: string | Buffer;
    clientCert: string | Buffer;
    clientKey: string | Buffer;
    serverName: string;
    timeoutMs?: number;
  },
  hooks?: TransportHooks,
): McpsHttpTransport {
  const timeoutMs = tls.timeoutMs ?? 15000;
  const post: PostFn = (body: Buffer) => oneMtlsPost(host, port, body, tls, timeoutMs);
  return new McpsHttpTransport(post, config, hooks);
}

/** One mTLS HTTP/1.1 POST; resolves `{ contentType, body }`. */
function oneMtlsPost(
  host: string,
  port: number,
  body: Buffer,
  tls: { serverCa: string | Buffer; clientCert: string | Buffer; clientKey: string | Buffer; serverName: string },
  timeoutMs: number,
): Promise<{ contentType: string; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const socket: TLSSocket = tlsConnect({
      host,
      port,
      ca: tls.serverCa,
      cert: tls.clientCert,
      key: tls.clientKey,
      servername: tls.serverName,
      timeout: timeoutMs,
    });
    const chunks: Buffer[] = [];
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    socket.on("secureConnect", () => {
      const head = Buffer.from(
        `POST / HTTP/1.1\r\nHost: ${tls.serverName}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
      );
      socket.write(Buffer.concat([head, body]));
    });
    socket.on("data", (d: Buffer) => chunks.push(d));
    socket.on("timeout", () => fail(new Error("mcps.transport_error: mTLS POST timed out")));
    socket.on("error", fail);
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks);
      const sep = raw.indexOf("\r\n\r\n");
      const headBytes = sep >= 0 ? raw.subarray(0, sep) : Buffer.alloc(0);
      const respBody = sep >= 0 ? raw.subarray(sep + 4) : raw;
      let contentType = "";
      for (const line of headBytes.toString("latin1").split("\r\n")) {
        const colon = line.indexOf(":");
        if (colon > 0 && line.slice(0, colon).trim().toLowerCase() === "content-type") {
          contentType = line.slice(colon + 1).trim();
          break;
        }
      }
      resolve({ contentType, body: respBody });
    });
  });
}
