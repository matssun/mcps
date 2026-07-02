/**
 * MCP-S request/response transport — one signed POST per `Client` request.
 *
 * A dedicated transport that maps the MCP `Client`'s persistent-stream model onto the
 * production `mcps-proxy`'s wire, which is **one HTTP/1.1 POST per (mTLS) connection,
 * `Connection: close`** — a pure request/response channel with NO server push
 * (`mcps-proxy/src/tls.rs::serve_once`).
 *
 * The byte-level security is the SAME audited pipeline the stdio {@link McpsTransport}
 * uses — {@link signOutbound} (sign + register correlation) and
 * {@link verifyInboundMessages} (correlate + verify + strip). What differs is the
 * *shape*: every outbound **request** becomes exactly one `post(requestBytes) ->
 * response` round trip, and that response is the only inbound message for it.
 *
 * Lifecycle over a no-server-push request/response transport:
 *
 * - `initialize` is an ordinary request (it has an `id`): signed, POSTed, the
 *   server-signed `InitializeResult` verified + stripped, delivered to the `Client` —
 *   which negotiates the protocol version normally.
 * - `notifications/initialized` (and every other client->server **notification**) is
 *   fire-and-forget: no `id`, no response. This transport has no channel to deliver a
 *   fire-and-forget message — the proxy treats every POST as a signed request that MUST
 *   verify and MUST get a response — so notifications are **dropped**.
 * - A **fail-closed** verification is delivered as a **JSON-RPC error correlated to the
 *   request id**, carrying the frozen `mcps.*` reason — so the awaiting `Client` call
 *   rejects cleanly rather than hanging.
 *
 * The TLS/socket specifics live OUTSIDE this module: the caller supplies an async
 * `post(requestBytes) -> { contentType, body }` (mirroring how {@link McpsTransport}
 * takes `byteSend` / `byteLines`). See {@link connectMtlsHttp} for the mTLS wiring.
 */

import * as core from "../native/binding.js";
import type { CorrelationStore } from "../native/binding.js";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { randomBytes } from "node:crypto";
import { McpsConfig, MrtStore, signOutbound, TransportHooks } from "./transport.js";
import { verifyInboundMessages } from "./streamable.js";

/**
 * A request/response round trip: signed request bytes in, the response `contentType` +
 * `body` out. One call == one mTLS connection + POST in the production wiring. The
 * content type lets the multi-path decoder distinguish a direct-JSON response from a
 * (single) SSE-framed one.
 */
export type PostFn = (requestBytes: Buffer) => Promise<{ contentType: string; body: Buffer }>;

/**
 * JSON-RPC server-error code carrying a fail-closed MCP-S rejection back to the awaiting
 * `Client` call (reserved server-error range, -32000..-32099).
 */
export const MCPS_REJECTED_CODE = -32099;

const DEFAULT_TTL = 300;

/**
 * Maps a `Client` onto one signed POST per request.
 *
 * `post` is an async `requestBytes -> { contentType, body }` callable (the production
 * wiring opens one mTLS connection and POSTs). Outbound notifications are dropped (no
 * fire-and-forget channel); a rejected response is delivered as a JSON-RPC error
 * correlated to the request id so the awaiting call rejects.
 */
export class McpsHttpTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  private readonly post: PostFn;
  private readonly config: McpsConfig;
  private readonly correlation: CorrelationStore;
  private readonly clock: () => number;
  private readonly nonceFactory: () => string;
  // ADR-MCPS-047 multi-round-trip state: requestState handle -> recorded continuation
  // binding, shared across POSTs so a verified InputRequiredResult (recorded on its
  // round trip) can be answered with a bound continuation on a later request. Without
  // this, an answer leg would throw `mcps.continuation_malformed`.
  private readonly mrt: MrtStore = new Map();
  private closed = false;

  constructor(post: PostFn, config: McpsConfig, hooks: TransportHooks = {}) {
    this.post = post;
    this.config = config;
    this.correlation = hooks.correlation ?? new core.CorrelationStore();
    this.clock = hooks.clock ?? (() => Math.floor(Date.now() / 1000));
    this.nonceFactory = hooks.nonceFactory ?? (() => randomBytes(16).toString("base64url"));
  }

  async start(): Promise<void> {
    // Nothing to start: each request opens its own connection on send().
  }

  async send(message: JSONRPCMessage, _options?: TransportSendOptions): Promise<void> {
    const m = message as Record<string, unknown>;
    const isRequest = m.id !== undefined && typeof m.method === "string";
    if (!isRequest) {
      // A notification (or a response to a server-initiated request). The
      // request/response transport has no fire-and-forget channel and the minimal proxy
      // never pushes, so there is nowhere to send it — drop it. `initialize` already
      // negotiated; the stateless fileserver does not consume `notifications/initialized`.
      return;
    }
    // One independent POST per request. Do NOT await the round trip here — each request
    // owns its own correlation entry (distinct JSON-RPC ids), and the Client awaits its
    // response via onmessage; a slow round trip must not head-of-line block other calls.
    void this.roundTrip(message, m.id).catch((err) => {
      this.onerror?.(err instanceof Error ? err : new Error(String(err)));
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    this.onclose?.();
  }

  private async roundTrip(message: JSONRPCMessage, rid: unknown): Promise<void> {
    const now = this.clock();
    let wire: Buffer;
    try {
      wire = signOutbound(message, this.config, this.correlation, {
        nowUnix: now,
        nonce: this.nonceFactory(),
        expiresUnix: now + (this.config.ttlSeconds ?? DEFAULT_TTL),
        mrt: this.mrt,
      });
    } catch (err) {
      this.onmessage?.(this.rejectMessage(rid, err instanceof Error ? err.message : String(err)));
      return;
    }

    let contentType: string;
    let body: Buffer;
    try {
      ({ contentType, body } = await this.post(wire));
    } catch (err) {
      // signOutbound already registered correlation; a transport failure must not leak it.
      this.correlation.cancel(String(rid));
      this.onmessage?.(this.rejectMessage(rid, `mcps.transport_error: ${err instanceof Error ? err.message : err}`));
      return;
    }
    if (this.closed) {
      this.correlation.cancel(String(rid));
      return;
    }
    // Route the response through the multi-path decoder so a direct-JSON OR a (single)
    // SSE-framed response is verified the same way. The one-POST-per-request proxy
    // contract yields exactly one response, so a reject binds to this request's id (the
    // awaiting call rejects, not hangs); an accepted/passed-through message is delivered.
    for (const outcome of verifyInboundMessages(contentType, body, this.config, this.correlation, {
      nowUnix: this.clock(),
      mrt: this.mrt,
    })) {
      if (outcome.kind === "accept" || outcome.kind === "passthrough") {
        this.onmessage?.(outcome.message as JSONRPCMessage);
      } else {
        this.correlation.cancel(String(rid));
        this.onmessage?.(this.rejectMessage(rid, outcome.reason));
      }
    }
  }

  private rejectMessage(rid: unknown, reason: string | undefined): JSONRPCMessage {
    return {
      jsonrpc: "2.0",
      id: rid as string | number,
      error: { code: MCPS_REJECTED_CODE, message: reason ?? "mcps.verification_failed" },
    } as unknown as JSONRPCMessage;
  }
}
