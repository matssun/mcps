/**
 * ADR-MCPS-047 multi-round-trip driving through the async SDK transport (mirrors Python
 * `test_continuation_transport.py`).
 *
 * The primitives are covered by continuation.test.ts. THIS file proves the transport
 * GLUE actually drives the elicitation round trip end to end, and that the
 * server-initiated boundary stays fail-closed.
 */
import { describe, expect, it } from "vitest";
import {
  CorrelationStore,
  McpsHttpTransport,
  McpsTransport,
  Signer,
  SignerPolicy,
  TrustResolver,
  signOutbound,
  verifyInbound,
  type McpsConfig,
  type MrtStore,
} from "../dist/index.js";
import { RESPONSE_VECTORS, SIGN_VECTOR, scenario } from "./fixtures.js";
import { pushableStream } from "./helpers.js";

const REQUEST_META_KEY = "se.syncom/mcps.request";
const REQ = SIGN_VECTOR.inputs;
const SERVER = RESPONSE_VECTORS.server;
const H1 = RESPONSE_VECTORS.client_request_hash; // the first-round hash the IRR binds
const NOW = Math.floor(Date.parse("2026-06-30T20:00:00Z") / 1000);
const TTL = 300;
const STATE = "eyJzdGVwIjoxfQ"; // the requestState the generator's IRR carries

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

const inputRequiredBytes = (): Buffer => Buffer.from(scenario("input_required").response_bytes);
const irrResponseHash = (): string => scenario("input_required").expected.response_hash as string;

const answer = (id = "req-2", requestState = STATE): any => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: {
    name: "delete_files",
    arguments: { paths: ["a", "b", "c"] },
    inputResponses: { confirm: true },
    requestState,
  },
});

function registerFirst(corr: CorrelationStore): void {
  corr.register({ correlationId: "req-1", requestHash: H1, nonce: "n1", deadlineUnix: NOW + TTL, nowUnix: NOW });
}

function receiveElicitation(corr: CorrelationStore, mrt: MrtStore): ReturnType<typeof verifyInbound> {
  registerFirst(corr);
  return verifyInbound(inputRequiredBytes(), config(), corr, { nowUnix: NOW + 1, mrt });
}

function envelope(wire: Buffer): Record<string, any> {
  return JSON.parse(wire.toString("utf-8")).params._meta[REQUEST_META_KEY];
}

describe("delivered plain + retained (not consumed)", () => {
  it("delivers the InputRequiredResult as plain MCP and retains it", () => {
    const corr = new CorrelationStore();
    const mrt: MrtStore = new Map();
    const out = receiveElicitation(corr, mrt);
    expect(out.kind).toBe("accept");
    const msg = out.message as any;
    expect(msg.result.resultType).toBe("inputRequired");
    expect("_meta" in msg.result).toBe(false);
    expect(corr.outstanding).toBe(0);
    expect(corr.nonTerminalOutstanding).toBe(1);
    expect(mrt.has(STATE)).toBe(true);
  });
});

describe("the answer leg is signed with the continuation binding", () => {
  it("binds both hashes and consumes the handle", () => {
    const corr = new CorrelationStore();
    const mrt: MrtStore = new Map();
    receiveElicitation(corr, mrt);
    const wire = signOutbound(answer(), config(), corr, {
      nowUnix: NOW + 2,
      nonce: "answernoncefresh1",
      expiresUnix: NOW + 2 + TTL,
      mrt,
    });
    const cont = envelope(wire).continuation;
    expect(cont.type).toBe("mcp-mrt");
    expect(cont.previous_request_hash).toBe(H1);
    expect(cont.input_required_response_hash).toBe(irrResponseHash());
    expect(mrt.has(STATE)).toBe(false); // single-use
    expect(corr.outstanding).toBe(1); // a fresh outstanding request
  });
});

describe("fail-closed boundaries", () => {
  it("a first-round response cannot be replayed as the continuation terminal", () => {
    const corr = new CorrelationStore();
    const mrt: MrtStore = new Map();
    receiveElicitation(corr, mrt);
    expect(corr.nonTerminalOutstanding === 1 && corr.outstanding === 0).toBe(true);
    const out = verifyInbound(Buffer.from(scenario("valid").response_bytes), config(), corr, { nowUnix: NOW + 2 });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.response_hash_mismatch");
  });

  it("a tampered requestState fails closed", () => {
    const corr = new CorrelationStore();
    const mrt: MrtStore = new Map();
    receiveElicitation(corr, mrt);
    expect(() =>
      signOutbound(answer("req-2", "dGFtcGVyZWQ"), config(), corr, {
        nowUnix: NOW + 2,
        nonce: "answernoncefresh1",
        expiresUnix: NOW + 2 + TTL,
        mrt,
      }),
    ).toThrow(/continuation_malformed/);
  });

  it("an answer without recorded state fails closed", () => {
    const corr = new CorrelationStore();
    expect(() =>
      signOutbound(answer(), config(), corr, {
        nowUnix: NOW + 2,
        nonce: "answernoncefresh1",
        expiresUnix: NOW + 2 + TTL,
        mrt: new Map(),
      }),
    ).toThrow(/no recorded multi-round-trip state/);
  });

  it("a replayed continuation fails closed (single-use)", () => {
    const corr = new CorrelationStore();
    const mrt: MrtStore = new Map();
    receiveElicitation(corr, mrt);
    signOutbound(answer(), config(), corr, {
      nowUnix: NOW + 2,
      nonce: "answernoncefresh1",
      expiresUnix: NOW + 2 + TTL,
      mrt,
    });
    expect(() =>
      signOutbound(answer("req-3"), config(), corr, {
        nowUnix: NOW + 3,
        nonce: "answernoncefresh2",
        expiresUnix: NOW + 3 + TTL,
        mrt,
      }),
    ).toThrow(/no recorded multi-round-trip state/);
  });

  it("arbitrary server push (a method-bearing elicitation request) still fails closed", () => {
    const push = Buffer.from(
      JSON.stringify({ jsonrpc: "2.0", id: "s-1", method: "elicitation/create", params: { message: "hi" } }),
    );
    const out = verifyInbound(push, config(), new CorrelationStore(), { nowUnix: NOW });
    expect(out.kind).toBe("reject");
    expect(out.reason).toBe("mcps.missing_envelope");
  });
});

describe("async transport drives the round trip", () => {
  it("reader records, writer binds (shared MRT state)", async () => {
    const sent: Buffer[] = [];
    const byteSend = async (b: Buffer): Promise<void> => {
      sent.push(b);
    };
    const lines = pushableStream();
    const corr = new CorrelationStore();
    registerFirst(corr);
    const transport = new McpsTransport(byteSend, lines.iterable, config(), {
      correlation: corr,
      clock: () => NOW + 1,
      nonceFactory: () => "asyncanswernonce1",
    });
    const elicited = new Promise<any>((resolve) => {
      transport.onmessage = resolve;
    });
    await transport.start();
    lines.push(inputRequiredBytes());
    const elicit = await elicited;
    expect(elicit.result.resultType).toBe("inputRequired");

    await transport.send(answer());
    lines.close();
    await transport.close();

    expect(sent.length).toBeGreaterThan(0);
    const cont = envelope(sent[sent.length - 1].subarray(0, sent[sent.length - 1].length - 1)).continuation;
    expect(cont.previous_request_hash).toBe(H1);
    expect(cont.input_required_response_hash).toBe(irrResponseHash());
  });
});

describe("request/response (mTLS/HTTP) transport drives the round trip", () => {
  it("records on the elicit POST, binds on the answer POST (shared MRT state)", async () => {
    // ADR-047 continuation through McpsHttpTransport — the one-POST-per-request wire the
    // production connectMtlsHttp uses. Proves the transport's own MRT threading (the
    // `this.mrt` map recorded on the InputRequiredResult leg, bound on the answer leg);
    // without it the answer POST fails closed as `mcps.continuation_malformed`.
    //
    // The push-based transport has no channel to inject an unsolicited response, so a fake
    // `post` returns the (pre-signed) IRR for the first leg and captures the answer leg's
    // wire. As in the stdio test the first-round hash is stood in for by the pre-registered
    // H1 (the fixture IRR binds it); the first leg carries a DISTINCT id so its own
    // correlation entry does not clobber that pre-registration.
    const posted: Buffer[] = [];
    let resolveSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      resolveSettled = resolve;
    });
    const post = async (wire: Buffer): Promise<{ contentType: string; body: Buffer }> => {
      posted.push(wire);
      if (posted.length === 2) resolveSettled(); // the answer wire has been captured
      // Leg 1: the server-signed InputRequiredResult (bound to H1). Leg 2: any well-formed
      // body — we assert on the captured wire, and its fail-closed delivery is drained.
      return { contentType: "application/json", body: posted.length === 1 ? inputRequiredBytes() : Buffer.from("{}") };
    };

    const corr = new CorrelationStore();
    registerFirst(corr); // the pre-registered first-round (H1) the fixture IRR binds
    let nonce = 0;
    const transport = new McpsHttpTransport(post, config(), {
      correlation: corr,
      clock: () => NOW + 1,
      nonceFactory: () => `httpnonce${nonce++}`, // distinct per leg (both legs sign here)
    });

    const gotElicit = new Promise<any>((resolve) => {
      transport.onmessage = resolve;
    });
    await transport.start();
    // A DISTINCT id (not req-1) so this leg's own entry can't overwrite H1's.
    await transport.send({
      jsonrpc: "2.0",
      id: "req-0",
      method: "tools/call",
      params: { name: "delete_files", arguments: { paths: ["a", "b", "c"] } },
    } as any);
    const elicit = await gotElicit;
    expect(elicit.result.resultType).toBe("inputRequired");

    // The answer: the transport must pick up the recorded MRT state and bind it. On a
    // regression signOutbound throws before posting; onmessage delivers the reject, so
    // either path settles and the posted.length assertion fails fast rather than hanging.
    transport.onmessage = () => resolveSettled();
    await transport.send(answer());
    await settled;
    await transport.close();

    expect(posted.length).toBe(2);
    const cont = JSON.parse(posted[1].toString("utf-8")).params._meta[REQUEST_META_KEY].continuation;
    expect(cont.type).toBe("mcp-mrt");
    expect(cont.previous_request_hash).toBe(H1);
    expect(cont.input_required_response_hash).toBe(irrResponseHash());
  });
});
