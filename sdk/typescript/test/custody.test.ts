/**
 * Custody / signer-policy binding tests (mirrors Python `test_custody.py`).
 *
 * `signRequestWithSigner` authorizes the signer against the policy BEFORE signing
 * (identity match, revocation, hardening profile, and the production dev-file rule),
 * then binds the evidence to the signer's actual identity. These assert the gate
 * behaves identically to the Rust core, and that the signed bytes still match the
 * parity golden vector.
 */
import { describe, expect, it } from "vitest";
import { Signer, SignerPolicy, SigningDevice, signRequestWithSigner, type SignedRequest } from "../dist/index.js";
import { SIGN_VECTOR } from "./fixtures.js";

const INP = SIGN_VECTOR.inputs;
const SEED = Buffer.from(INP.seed_hex, "hex");
const SIGNER_ID = INP.signer;
const KEY_ID = INP.key_id;

function signWith(signer: Signer, policy: SignerPolicy): SignedRequest {
  return signRequestWithSigner(
    INP.id_json,
    INP.method,
    INP.params_json,
    {
      onBehalfOf: INP.on_behalf_of,
      audience: INP.audience,
      nonce: INP.nonce,
      issuedAt: INP.issued_at,
      expiresAt: INP.expires_at,
      bindingDigestAlg: INP.binding_digest_alg,
      bindingDigestValue: INP.binding_digest_value,
    },
    signer,
    policy,
  );
}

const softwareSigner = (): Signer => Signer.software(SEED, SIGNER_ID, KEY_ID);
const devFileSigner = (): Signer => Signer.devFile(SEED, SIGNER_ID, KEY_ID);
const policy = (opts: { environment?: string; requireMcps?: boolean; expected?: string } = {}): SignerPolicy =>
  new SignerPolicy(opts.expected ?? SIGNER_ID, opts.environment ?? "production", opts.requireMcps ?? true);

describe("signer metadata", () => {
  it("reports identity + custody class", () => {
    const sw = softwareSigner();
    expect(sw.signerId).toBe(SIGNER_ID);
    expect(sw.keyId).toBe(KEY_ID);
    expect(sw.custody).toBe("software-held-private");
    expect(devFileSigner().custody).toBe("dev-file-unprotected");
  });
});

describe("custody gate", () => {
  it("the signer path produces the SAME bytes/hash as the raw oracle vector", () => {
    const signed = signWith(softwareSigner(), policy());
    expect(signed.wireBytes.toString("utf-8")).toBe(SIGN_VECTOR.expected_wire_bytes);
    expect(signed.requestHash).toBe(SIGN_VECTOR.expected_request_hash);
  });

  it("software custody is accepted under production require_mcps", () => {
    expect(signWith(softwareSigner(), policy()).requestHash.startsWith("sha256:")).toBe(true);
  });

  it("dev-file is rejected under production require_mcps", () => {
    expect(() => signWith(devFileSigner(), policy())).toThrow(/ActorBindingFailed/);
  });

  it("dev-file is accepted in an explicit dev-test env (identical bytes)", () => {
    const signed = signWith(devFileSigner(), policy({ environment: "dev-test" }));
    expect(signed.wireBytes.toString("utf-8")).toBe(SIGN_VECTOR.expected_wire_bytes);
  });

  it("signer identity mismatch is rejected", () => {
    expect(() => signWith(softwareSigner(), policy({ expected: "did:example:someone-else" }))).toThrow(
      /ActorBindingFailed/,
    );
  });

  it("a revoked key id is rejected", () => {
    expect(() => signWith(softwareSigner(), policy().revokeKeyId(KEY_ID))).toThrow(/ActorBindingFailed/);
  });

  it("the hardening profile rejects a software key", () => {
    expect(() => signWith(softwareSigner(), policy().requireNonExporting())).toThrow(/ActorBindingFailed/);
  });
});

describe("non-exporting custody (hardening ACCEPT side)", () => {
  const device = (): SigningDevice => SigningDevice.fromSeed(SEED, SIGNER_ID, KEY_ID);
  const nonExportingSigner = (signCallback?: (p: Buffer) => string): Signer =>
    Signer.nonExporting(SIGNER_ID, KEY_ID, signCallback ?? ((p: Buffer) => device().sign(p)));

  it("reports non-exporting custody", () => {
    expect(nonExportingSigner().custody).toBe("non-exporting");
  });

  it("the hardening profile accepts the non-exporting signer", () => {
    expect(signWith(nonExportingSigner(), policy().requireNonExporting()).requestHash.startsWith("sha256:")).toBe(
      true,
    );
  });

  it("delegation is byte-identical to the direct software path", () => {
    const signed = signWith(nonExportingSigner(), policy().requireNonExporting());
    expect(signed.wireBytes.toString("utf-8")).toBe(SIGN_VECTOR.expected_wire_bytes);
    expect(signed.requestHash).toBe(SIGN_VECTOR.expected_request_hash);
  });

  it("hardening still excludes the dev-file class", () => {
    expect(() => signWith(devFileSigner(), policy().requireNonExporting())).toThrow(/ActorBindingFailed/);
  });

  it("a device that cannot sign fails closed (no placeholder)", () => {
    const offline = (): string => {
      throw new Error("device unreachable");
    };
    expect(() => signWith(nonExportingSigner(offline), policy().requireNonExporting())).toThrow(
      /ActorBindingFailed/,
    );
  });

  it("the device exposes only sign (no key getter)", () => {
    const d = device();
    // Instance methods: only `sign` (fromSeed is a static factory on the class).
    const proto = Object.getPrototypeOf(d);
    const instanceMembers = Object.getOwnPropertyNames(proto).filter((n) => n !== "constructor");
    expect(instanceMembers).toEqual(["sign"]);
  });
});

describe("policy construction", () => {
  it("rejects an unknown environment", () => {
    expect(() => new SignerPolicy(SIGNER_ID, "staging", true)).toThrow(/environment must be/);
  });
});
