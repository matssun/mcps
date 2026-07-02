/**
 * Response-verification parity tests (mirrors Python `test_response.py`).
 *
 * `verifyResponse` runs the proxy's return-leg chain: verify_signed_response ->
 * classify_response_result -> decide -> audit_for_decision. A fail-closed verification
 * is a *result* (carrying the frozen `mcps.*` wire reason), not a thrown error. Each
 * scenario asserts the TS binding reproduces the oracle's decision exactly.
 */
import { describe, expect, it } from "vitest";
import { TrustResolver, verifyResponse, type VerifyResult } from "../dist/index.js";
import { RESPONSE_VECTORS, scenario, type ResponseScenario } from "./fixtures.js";

const SERVER = RESPONSE_VECTORS.server;

function resolverPublicKey(): TrustResolver {
  const r = new TrustResolver();
  r.insertPublicKey(SERVER.signer_id, SERVER.key_id, Buffer.from(SERVER.public_key_hex, "hex"));
  return r;
}

function run(s: ResponseScenario, resolver: TrustResolver): VerifyResult {
  return verifyResponse(Buffer.from(s.response_bytes), resolver, {
    expectedRequestHash: s.params.expected_request_hash,
    expectedCanonicalizationId: s.params.expected_canonicalization_id ?? undefined,
    expectedServerSigner: s.params.expected_server_signer ?? undefined,
    enforcementMode: s.params.enforcement_mode,
    legacyAllowed: s.params.legacy_allowed,
  });
}

describe("verifyResponse matches the oracle", () => {
  for (const s of RESPONSE_VECTORS.scenarios) {
    it(s.name, () => {
      const res = run(s, resolverPublicKey());
      const exp = s.expected;
      expect(res.decision).toBe(exp.decision);
      expect(res.path).toBe(exp.path);
      expect(res.outcome).toBe(exp.outcome);
      expect(res.reason ?? null).toBe(exp.reason);
      expect(res.serverSigner ?? null).toBe(exp.server_signer);
      expect(res.keyId ?? null).toBe(exp.key_id);
      expect(res.requestHash ?? null).toBe(exp.request_hash);
      expect(res.accepted).toBe(exp.accepted);
    });
  }
});

describe("verifyResponse edge cases", () => {
  it("valid response is accepted and binds the request", () => {
    const res = run(scenario("valid"), resolverPublicKey());
    expect(res.accepted && res.decision === "accept").toBe(true);
    expect(res.path).toBe("mcps-verified");
    expect(res.serverSigner).toBe(SERVER.signer_id);
    expect(res.requestHash).toBe(RESPONSE_VECTORS.client_request_hash);
  });

  it("insertDevSeed derives the same public key as insertPublicKey", () => {
    const r = new TrustResolver();
    r.insertDevSeed(SERVER.signer_id, SERVER.key_id, Buffer.from(SERVER.seed_hex, "hex"));
    const res = run(scenario("valid"), r);
    expect(res.accepted).toBe(true);
    expect(res.serverSigner).toBe(SERVER.signer_id);
  });

  it("an empty resolver fails closed on the server signer", () => {
    const res = run(scenario("valid"), new TrustResolver());
    expect(res.decision).toBe("fail-closed");
    expect(res.reason).toBe("mcps.actor_binding_failed");
  });

  it("rejects a bad public key length", () => {
    const r = new TrustResolver();
    expect(() => r.insertPublicKey("did:example:server", "k", Buffer.alloc(16))).toThrow(
      /public_key must be exactly 32 bytes/,
    );
  });

  it("rejects a bad enforcement mode", () => {
    const valid = scenario("valid");
    expect(() =>
      verifyResponse(Buffer.from(valid.response_bytes), resolverPublicKey(), {
        expectedRequestHash: valid.params.expected_request_hash,
        enforcementMode: "bogus",
      }),
    ).toThrow(/enforcement_mode must be/);
  });
});
