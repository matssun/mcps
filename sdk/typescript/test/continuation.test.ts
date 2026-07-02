/**
 * ADR-MCPS-047 continuation-binding tests (mirrors Python `test_continuation.py`).
 *
 * Covers the three SDK surfaces the multi-round-trip flow needs:
 *   1. signRequest(..., continuation*) embeds the signed `continuation` binding;
 *   2. verifyResponse classifies a signed `InputRequiredResult`;
 *   3. CorrelationStore.recordInputRequired associates-without-consuming and returns the
 *      binding to sign the answer leg.
 */
import { describe, expect, it } from "vitest";
import {
  CorrelationStore,
  TrustResolver,
  signRequest,
  verifyResponse,
  type SignRequestOptions,
  type SignedRequest,
} from "../dist/index.js";
import { RESPONSE_VECTORS, scenario } from "./fixtures.js";

const REQUEST_META_KEY = "se.syncom/mcps.request";
const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const SERVER = RESPONSE_VECTORS.server;
const CLIENT_RH = RESPONSE_VECTORS.client_request_hash;

function sign(continuation: Partial<SignRequestOptions> = {}): SignedRequest {
  return signRequest('"req-1"', "tools/call", '{"name":"echo","arguments":{}}', {
    signer: "did:example:client",
    keyId: "k1",
    onBehalfOf: "user:alice",
    audience: "did:example:server",
    nonce: "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
    issuedAt: "2026-06-30T20:00:00Z",
    expiresAt: "2026-06-30T20:05:00Z",
    seed: SEED,
    bindingDigestAlg: "sha256",
    bindingDigestValue: DIGEST,
    ...continuation,
  });
}

function envelope(signed: SignedRequest): Record<string, any> {
  return JSON.parse(signed.wireBytes.toString("utf-8")).params._meta[REQUEST_META_KEY];
}

function resolver(): TrustResolver {
  const r = new TrustResolver();
  r.insertPublicKey(SERVER.signer_id, SERVER.key_id, Buffer.from(SERVER.public_key_hex, "hex"));
  return r;
}

describe("signing the continuation binding", () => {
  it("an ordinary request omits continuation", () => {
    expect("continuation" in envelope(sign())).toBe(false);
  });

  it("a continuation request binds both hashes", () => {
    const signed = sign({
      continuationPreviousRequestHash: CLIENT_RH,
      continuationInputRequiredResponseHash: "sha256:" + DIGEST,
    });
    const cont = envelope(signed).continuation;
    expect(cont.type).toBe("mcp-mrt");
    expect(cont.previous_request_hash).toBe(CLIENT_RH);
    expect(cont.input_required_response_hash).toBe("sha256:" + DIGEST);
  });

  it("a one-sided continuation is rejected", () => {
    expect(() => sign({ continuationPreviousRequestHash: CLIENT_RH })).toThrow(/continuation requires BOTH/);
  });
});

describe("classifying a verified InputRequiredResult", () => {
  it("classifies input_required", () => {
    const s = scenario("input_required");
    const res = verifyResponse(Buffer.from(s.response_bytes), resolver(), {
      expectedRequestHash: s.params.expected_request_hash,
      expectedServerSigner: s.params.expected_server_signer ?? undefined,
    });
    expect(res.accepted).toBe(true);
    expect(res.inputRequired).toBe(true);
    expect(res.resultClass).toBe("input_required");
    expect(res.responseHash).toBe(s.expected.response_hash);
  });

  it("a terminal response is not input_required", () => {
    const valid = scenario("valid");
    const res = verifyResponse(Buffer.from(valid.response_bytes), resolver(), {
      expectedRequestHash: valid.params.expected_request_hash,
      expectedServerSigner: valid.params.expected_server_signer ?? undefined,
    });
    expect(res.accepted).toBe(true);
    expect(res.inputRequired).toBe(false);
    expect(res.resultClass).toBe("terminal");
  });
});

describe("correlation store: associate-without-consume", () => {
  it("recordInputRequired retains and returns the binding", () => {
    const store = new CorrelationStore();
    store.register({ correlationId: "c1", requestHash: CLIENT_RH, nonce: "n1", deadlineUnix: 2000, nowUnix: 1000 });
    const binding = store.recordInputRequired("c1", "sha256:" + DIGEST, 1500);
    expect(binding.previousRequestHash).toBe(CLIENT_RH);
    expect(binding.inputRequiredResponseHash).toBe("sha256:" + DIGEST);
    expect(store.outstanding).toBe(0);
    expect(store.nonTerminalOutstanding).toBe(1);
  });
});

describe("end to end: verify -> record -> sign the continuation", () => {
  it("round trips", () => {
    const s = scenario("input_required");
    const res = verifyResponse(Buffer.from(s.response_bytes), resolver(), {
      expectedRequestHash: CLIENT_RH,
      expectedServerSigner: SERVER.signer_id,
    });
    expect(res.inputRequired).toBe(true);

    const store = new CorrelationStore();
    store.register({ correlationId: "c1", requestHash: CLIENT_RH, nonce: "n1", deadlineUnix: 2000, nowUnix: 1000 });
    const binding = store.recordInputRequired("c1", res.responseHash as string, 1500);

    const signed = sign({
      continuationPreviousRequestHash: binding.previousRequestHash,
      continuationInputRequiredResponseHash: binding.inputRequiredResponseHash,
    });
    const cont = envelope(signed).continuation;
    expect(cont.previous_request_hash).toBe(CLIENT_RH);
    expect(cont.input_required_response_hash).toBe(res.responseHash);
  });
});
