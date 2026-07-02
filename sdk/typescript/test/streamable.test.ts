/**
 * Streamable-HTTP multi-path inbound decode + uniform verification (mirrors Python
 * `test_streamable.py`).
 *
 * Covers the SSE framing parser, the content-type-aware decodeInbound, and that EVERY
 * decode site (direct JSON and SSE) routes through the same MCP-S verification and
 * server-initiated policy.
 */
import { describe, expect, it } from "vitest";
import {
  CorrelationStore,
  Signer,
  SignerPolicy,
  TrustResolver,
  decodeInbound,
  sseDataEvents,
  verifyInboundMessages,
  type McpsConfig,
} from "../dist/index.js";
import { RESPONSE_VECTORS, SIGN_VECTOR, scenario } from "./fixtures.js";

const REQ = SIGN_VECTOR.inputs;
const SERVER = RESPONSE_VECTORS.server;
const NOW = Math.floor(Date.parse("2026-06-30T20:00:00Z") / 1000);
const TTL = 300;

function config(overrides: Partial<McpsConfig> = {}): McpsConfig {
  const resolver = new TrustResolver();
  resolver.insertPublicKey(SERVER.signer_id, SERVER.key_id, Buffer.from(SERVER.public_key_hex, "hex"));
  return {
    signer: Signer.software(Buffer.from(REQ.seed_hex, "hex"), REQ.signer, REQ.key_id),
    policy: new SignerPolicy(REQ.signer, "dev-test", true),
    resolver,
    audience: REQ.audience,
    onBehalfOf: REQ.on_behalf_of,
    bindingDigestAlg: REQ.binding_digest_alg,
    bindingDigestValue: REQ.binding_digest_value,
    expectedServerSigner: SERVER.signer_id,
    ttlSeconds: TTL,
    ...overrides,
  };
}

const validResponse = (): string => scenario("valid").response_bytes;

function registered(): CorrelationStore {
  const corr = new CorrelationStore();
  corr.register({
    correlationId: "req-1",
    requestHash: RESPONSE_VECTORS.client_request_hash,
    nonce: "n1",
    deadlineUnix: NOW + TTL,
    nowUnix: NOW,
  });
  return corr;
}

/** Frame each JSON payload as one SSE `data` event (multi-line safe). */
function sse(...payloads: string[]): Buffer {
  let out = "";
  for (const payload of payloads) {
    out += payload.split("\n").map((line) => `data: ${line}\n`).join("") + "\n";
  }
  return Buffer.from(out);
}

describe("SSE framing parser", () => {
  it("single event", () => expect(sseDataEvents("data: hello\n\n").map((b) => b.toString())).toEqual(["hello"]));
  it("multiple events", () =>
    expect(sseDataEvents("data: a\n\ndata: b\n\n").map((b) => b.toString())).toEqual(["a", "b"]));
  it("multiline data joined with newline", () =>
    expect(sseDataEvents("data: line1\ndata: line2\n\n").map((b) => b.toString())).toEqual(["line1\nline2"]));
  it("ignores comments and other fields", () =>
    expect(
      sseDataEvents(": keep-alive\nevent: message\nid: 7\ndata: payload\nretry: 1000\n\n").map((b) => b.toString()),
    ).toEqual(["payload"]));
  it("CRLF terminators", () =>
    expect(sseDataEvents("data: x\r\n\r\ndata: y\r\n\r\n").map((b) => b.toString())).toEqual(["x", "y"]));
  it("trailing event without blank line", () =>
    expect(sseDataEvents("data: tail").map((b) => b.toString())).toEqual(["tail"]));
  it("event without data yields nothing", () => expect(sseDataEvents("event: ping\n\n")).toEqual([]));
  it("strips only one leading space", () =>
    expect(sseDataEvents("data:  two-spaces\n\n").map((b) => b.toString())).toEqual([" two-spaces"]));
});

describe("content-type dispatch", () => {
  it("direct JSON", () => expect(decodeInbound("application/json", '{"a":1}').map((b) => b.toString())).toEqual(['{"a":1}']));
  it("unspecified content type is direct JSON", () =>
    expect(decodeInbound("", '{"a":1}').map((b) => b.toString())).toEqual(['{"a":1}']));
  it("event-stream with charset param", () =>
    expect(decodeInbound("text/event-stream; charset=utf-8", "data: {}\n\n").map((b) => b.toString())).toEqual(["{}"]));
  it("empty body yields nothing", () => expect(decodeInbound("application/json", "   ")).toEqual([]));
});

describe("uniform verification across decode sites", () => {
  it("direct JSON response verifies and strips", () => {
    const outcomes = verifyInboundMessages("application/json", validResponse(), config(), registered(), {
      nowUnix: NOW + 1,
    });
    expect(outcomes.map((o) => o.kind)).toEqual(["accept"]);
    expect("_meta" in ((outcomes[0].message as any).result ?? {})).toBe(false);
  });

  it("SSE-framed response verifies identically", () => {
    const outcomes = verifyInboundMessages("text/event-stream", sse(validResponse()), config(), registered(), {
      nowUnix: NOW + 1,
    });
    expect(outcomes.map((o) => o.kind)).toEqual(["accept"]);
  });

  it("skips empty SSE events (heartbeats) instead of failing them closed", () => {
    // An empty `data:` event yields a zero-length payload — a heartbeat, not a message.
    // It must be skipped (parity with Python), so only the real response is verified.
    const outcomes = verifyInboundMessages("text/event-stream", sse("", validResponse(), ""), config(), registered(), {
      nowUnix: NOW + 1,
    });
    expect(outcomes.map((o) => o.kind)).toEqual(["accept"]);
  });

  it("SSE server-initiated notification fails closed", () => {
    const notif = JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: {} });
    const outcomes = verifyInboundMessages("text/event-stream", sse(notif), config(), new CorrelationStore(), {
      nowUnix: NOW,
    });
    expect(outcomes[0].kind).toBe("reject");
    expect(outcomes[0].reason).toBe("mcps.notification_forbidden");
  });

  it("SSE interleaved response and server message", () => {
    const notif = JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: {} });
    const outcomes = verifyInboundMessages("text/event-stream", sse(validResponse(), notif), config(), registered(), {
      nowUnix: NOW + 1,
    });
    expect(outcomes.map((o) => o.kind)).toEqual(["accept", "reject"]);
    expect(outcomes[1].reason).toBe("mcps.notification_forbidden");
  });

  it("SSE server-initiated passthrough when allowed", () => {
    const notif = JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: {} });
    const outcomes = verifyInboundMessages(
      "text/event-stream",
      sse(notif),
      config({ allowUnverifiedServerInitiated: true }),
      new CorrelationStore(),
      { nowUnix: NOW },
    );
    expect(outcomes[0].kind).toBe("passthrough");
  });

  it("SSE server-initiated request fails closed", () => {
    const req = JSON.stringify({ jsonrpc: "2.0", id: "s-9", method: "sampling/createMessage", params: {} });
    const outcomes = verifyInboundMessages("text/event-stream", sse(req), config(), new CorrelationStore(), {
      nowUnix: NOW,
    });
    expect(outcomes[0].kind).toBe("reject");
    expect(outcomes[0].reason).toBe("mcps.missing_envelope");
  });
});
