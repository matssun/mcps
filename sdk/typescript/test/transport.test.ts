/**
 * Transport-adapter tests (mirrors Python `test_transport.py`).
 *
 * The adapter's security core is two sync functions: signOutbound (sign + register) and
 * verifyInbound (correlate + verify + strip). These are tested against the same golden
 * vectors as the bindings, proving the adapter writes byte-identical signed requests and
 * verifies responses exactly. Two async tests drive the McpsTransport pumps over an
 * in-memory byte channel (no live subprocess, no MCP SDK needed — the transport speaks
 * plain JSON-RPC objects).
 */
import { describe, expect, it } from "vitest";
import {
  CorrelationStore,
  McpsTransport,
  McpsVerificationError,
  Signer,
  SignerPolicy,
  TrustResolver,
  signOutbound,
  verifyInbound,
  type McpsConfig,
} from "../dist/index.js";
import { RESPONSE_VECTORS, SIGN_VECTOR, scenario } from "./fixtures.js";
import { pushableStream } from "./helpers.js";

const REQ = SIGN_VECTOR.inputs;
const REQ_EXPECTED_WIRE = SIGN_VECTOR.expected_wire_bytes;
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

const request = (id: unknown, method: string, params: unknown): any => ({ jsonrpc: "2.0", id, method, params });
const validResponse = (): Buffer => Buffer.from(scenario("valid").response_bytes);
const registerForValid = (corr: CorrelationStore): void =>
  corr.register({
    correlationId: "req-1",
    requestHash: RESPONSE_VECTORS.client_request_hash,
    nonce: "n1",
    deadlineUnix: NOW + TTL,
    nowUnix: NOW,
  });

describe("sync security core", () => {
  it("signOutbound matches the request vector + registers correlation", () => {
    const corr = new CorrelationStore();
    const wire = signOutbound(
      request("req-1", "tools/call", { name: "echo", arguments: { text: "hello" } }),
      config(),
      corr,
      { nowUnix: NOW, nonce: REQ.nonce, expiresUnix: NOW + TTL },
    );
    expect(wire.toString("utf-8")).toBe(REQ_EXPECTED_WIRE);
    expect(corr.outstanding).toBe(1);
  });

  it("signOutbound passes a notification through unsigned + uncorrelated", () => {
    const corr = new CorrelationStore();
    const wire = signOutbound({ jsonrpc: "2.0", method: "notifications/cancelled" } as any, config(), corr, {
      nowUnix: NOW,
      nonce: "n",
      expiresUnix: NOW + TTL,
    });
    expect(wire.toString("utf-8")).toContain("notifications/cancelled");
    expect(corr.outstanding).toBe(0);
  });

  it("verifyInbound accepts and strips the envelope", () => {
    const corr = new CorrelationStore();
    registerForValid(corr);
    const out = verifyInbound(validResponse(), config(), corr, { nowUnix: NOW + 1 });
    expect(out.kind).toBe("accept");
    const msg = out.message as any;
    expect("_meta" in (msg.result ?? {})).toBe(false);
    expect(corr.outstanding).toBe(0);
  });

  it("verifyInbound rejects a tampered signature", () => {
    const corr = new CorrelationStore();
    registerForValid(corr);
    const out = verifyInbound(Buffer.from(scenario("tampered_signature").response_bytes), config(), corr, {
      nowUnix: NOW + 1,
    });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.response_sig_invalid");
  });

  it("verifyInbound is uncorrelatable without a pending request", () => {
    const out = verifyInbound(validResponse(), config(), new CorrelationStore(), { nowUnix: NOW + 1 });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.response_hash_mismatch");
  });

  it("rejects a server notification by default", () => {
    const notif = Buffer.from(JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: { x: 1 } }));
    const out = verifyInbound(notif, config(), new CorrelationStore(), { nowUnix: NOW });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.notification_forbidden");
  });

  it("rejects a server request by default", () => {
    const req = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: "s-1", method: "sampling/createMessage", params: {} }));
    const out = verifyInbound(req, config(), new CorrelationStore(), { nowUnix: NOW });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.missing_envelope");
  });

  it("passes a server notification through when allowed", () => {
    const notif = Buffer.from(JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: { x: 1 } }));
    const out = verifyInbound(notif, config({ allowUnverifiedServerInitiated: true }), new CorrelationStore(), {
      nowUnix: NOW,
    });
    expect(out.kind).toBe("passthrough");
    expect((out.message as any).method).toBe("notifications/message");
  });

  it("passes a server request through when allowed", () => {
    const req = Buffer.from(
      JSON.stringify({ jsonrpc: "2.0", id: "s-7", method: "sampling/createMessage", params: { m: 1 } }),
    );
    const out = verifyInbound(req, config({ allowUnverifiedServerInitiated: true }), new CorrelationStore(), {
      nowUnix: NOW,
    });
    expect(out.kind).toBe("passthrough");
    expect((out.message as any).method).toBe("sampling/createMessage");
    expect(String((out.message as any).id)).toBe("s-7");
  });
});

describe("async pump wiring", () => {
  it("the writer pump signs to the wire", async () => {
    const sent: Buffer[] = [];
    const byteSend = async (b: Buffer): Promise<void> => {
      sent.push(b);
    };
    const lines = pushableStream();
    const corr = new CorrelationStore();
    const transport = new McpsTransport(byteSend, lines.iterable, config(), {
      correlation: corr,
      clock: () => NOW,
      nonceFactory: () => REQ.nonce,
    });
    await transport.start();
    await transport.send(request("req-1", "tools/call", { name: "echo", arguments: { text: "hello" } }));
    lines.close();
    await transport.close();
    expect(sent.length).toBeGreaterThan(0);
    expect(sent[0].subarray(0, sent[0].length - 1).toString("utf-8")).toBe(REQ_EXPECTED_WIRE);
    expect(corr.outstanding).toBe(1);
  });

  it("the reader pump verifies and delivers", async () => {
    const lines = pushableStream();
    const corr = new CorrelationStore();
    registerForValid(corr);
    const transport = new McpsTransport(async () => {}, lines.iterable, config(), {
      correlation: corr,
      clock: () => NOW + 1,
    });
    const received = new Promise<any>((resolve) => {
      transport.onmessage = resolve;
    });
    await transport.start();
    lines.push(validResponse());
    const msg = await received;
    expect(String(msg.id)).toBe("req-1");
    lines.close();
    await transport.close();
  });

  it("the reader pump surfaces a rejection via onerror", async () => {
    const lines = pushableStream();
    const corr = new CorrelationStore();
    registerForValid(corr);
    const transport = new McpsTransport(async () => {}, lines.iterable, config(), {
      correlation: corr,
      clock: () => NOW + 1,
    });
    const errored = new Promise<Error>((resolve) => {
      transport.onerror = resolve;
    });
    await transport.start();
    lines.push(Buffer.from(scenario("tampered_signature").response_bytes));
    const err = await errored;
    expect(err).toBeInstanceOf(McpsVerificationError);
    expect((err as McpsVerificationError).reason).toBe("mcps.response_sig_invalid");
    lines.close();
    await transport.close();
  });
});
