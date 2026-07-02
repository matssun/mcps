/**
 * Parity tests — the acceptance gate (mirrors Python `test_parity_stdio.py`).
 *
 * The TypeScript SDK MUST produce a byte-identical signed request to the Rust path for
 * the same input. Byte parity is the whole point of binding to `mcps-client-core`
 * instead of reimplementing it — and it ties the TS SDK to the SAME oracle vector the
 * Python SDK and the proxy are checked against.
 */
import { describe, expect, it } from "vitest";
import { canonicalizationId, coreVersion, signRequest, type SignedRequest } from "../dist/index.js";
import { SIGN_VECTOR } from "./fixtures.js";

const INP = SIGN_VECTOR.inputs;

function signFromFixture(seed?: Buffer): SignedRequest {
  return signRequest(INP.id_json, INP.method, INP.params_json, {
    signer: INP.signer,
    keyId: INP.key_id,
    onBehalfOf: INP.on_behalf_of,
    audience: INP.audience,
    nonce: INP.nonce,
    issuedAt: INP.issued_at,
    expiresAt: INP.expires_at,
    seed: seed ?? Buffer.from(INP.seed_hex, "hex"),
    bindingDigestAlg: INP.binding_digest_alg,
    bindingDigestValue: INP.binding_digest_value,
  });
}

describe("core link", () => {
  it("reports protocol constants (native core reachable)", () => {
    expect(coreVersion()).toBeTruthy();
    expect(typeof canonicalizationId()).toBe("string");
  });
});

describe("signed request byte parity", () => {
  it("produces identical wireBytes + requestHash as the oracle", () => {
    const signed = signFromFixture();
    expect(signed.wireBytes.toString("utf-8")).toBe(SIGN_VECTOR.expected_wire_bytes);
    expect(signed.requestHash).toBe(SIGN_VECTOR.expected_request_hash);
  });

  it("requestHash is the documented sha256:<b64url-no-pad> shape", () => {
    const signed = signFromFixture();
    expect(signed.requestHash.startsWith("sha256:")).toBe(true);
    expect(signed.requestHash.includes("=")).toBe(false);
  });

  it("is deterministic (signature excluded from the hashed preimage)", () => {
    const a = signFromFixture();
    const b = signFromFixture();
    expect(a.wireBytes.equals(b.wireBytes)).toBe(true);
    expect(a.requestHash).toBe(b.requestHash);
  });

  it("rejects a seed that is not 32 bytes", () => {
    expect(() => signFromFixture(Buffer.alloc(16))).toThrow(/seed must be exactly 32 bytes/);
  });
});
