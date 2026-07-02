/**
 * Authorization-binding providers (mirrors Python `test_authorization.py`).
 *
 * The point of the hardening: `authorizationBinding.digestValue` is computed by the
 * audited core over the ACTUAL artifact bytes, not handed in as a constant. The key
 * check is an INDEPENDENT oracle — Node's crypto SHA-256 + base64url-no-pad must equal
 * the Rust-computed digest — plus the per-route policy fail-closed behaviour and that a
 * provider-built binding actually lands in the signed preimage.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AuthorizationBinding,
  AuthorizationBindingPolicy,
  AuthzSystemReferenceProvider,
  CorrelationStore,
  OpaqueBytesProvider,
  Signer,
  SignerPolicy,
  StaticAuthorizationProvider,
  TrustResolver,
  signOutbound,
  type BindingRequestContext,
  type McpsConfig,
} from "../dist/index.js";
import { SIGN_VECTOR } from "./fixtures.js";

/** base64url-no-pad(SHA-256(bytes)) — the ADR-MCPS-039 opaque digest, computed here. */
function expectedOpaque(data: Buffer): string {
  return createHash("sha256").update(data).digest("base64url");
}

const ctx = (): BindingRequestContext => ({
  audience: "did:example:server-1",
  routeId: "default",
  method: "tools/call",
  toolId: "read_file",
  deadlineUnix: 1_900_000_000,
});

describe("the binding digest is REAL (independent SHA-256 oracle)", () => {
  it("opaque digest matches independent SHA-256", () => {
    const data = Buffer.from("a-real-bearer-token's-decoded-bytes");
    const binding = AuthorizationBinding.opaqueBytes(data);
    expect(binding.bindingType).toBe("opaque-bytes");
    expect(binding.digestAlg).toBe("sha256");
    expect(binding.digestValue).toBe(expectedOpaque(data));
  });

  it("opaque digest of empty bytes", () => {
    expect(AuthorizationBinding.opaqueBytes(Buffer.alloc(0)).digestValue).toBe(expectedOpaque(Buffer.alloc(0)));
  });

  it("different bytes yield different digests", () => {
    expect(AuthorizationBinding.opaqueBytes(Buffer.from("token-A")).digestValue).not.toBe(
      AuthorizationBinding.opaqueBytes(Buffer.from("token-B")).digestValue,
    );
  });

  it("authz-system-reference fields", () => {
    const binding = AuthorizationBinding.authzSystemReference("sys-1", "scheme-1", "grant-1", "c29tZS1kaWdlc3Q");
    expect(binding.bindingType).toBe("authz-system-reference");
    expect(binding.digestAlg).toBe("sha256");
    expect(binding.digestValue).toBe("c29tZS1kaWdlc3Q");
    expect(binding.authorizationSystemId).toBe("sys-1");
    expect(binding.referenceValue).toBe("grant-1");
  });

  it("opaque binding has no reference fields", () => {
    const binding = AuthorizationBinding.opaqueBytes(Buffer.from("x"));
    expect(binding.authorizationSystemId).toBeNull();
    expect(binding.referenceValue).toBeNull();
  });
});

describe("per-route policy fails closed", () => {
  it("both forms permits and enforces", () => {
    const opaque = AuthorizationBinding.opaqueBytes(Buffer.from("x"));
    const ref = AuthorizationBinding.authzSystemReference("s", "sc", "r", "d");
    const both = AuthorizationBindingPolicy.bothBaseForms();
    expect(both.permits(opaque) && both.permits(ref)).toBe(true);
    both.enforce(opaque);
    both.enforce(ref);
  });

  it("opaque-only rejects a reference", () => {
    const ref = AuthorizationBinding.authzSystemReference("s", "sc", "r", "d");
    const policy = AuthorizationBindingPolicy.opaqueOnly();
    expect(policy.permits(ref)).toBe(false);
    expect(() => policy.enforce(ref)).toThrow(/mcps.authorization_binding_type_unsupported/);
  });

  it("closed rejects everything", () => {
    const opaque = AuthorizationBinding.opaqueBytes(Buffer.from("x"));
    expect(() => AuthorizationBindingPolicy.closed().enforce(opaque)).toThrow();
  });
});

describe("providers", () => {
  it("opaque provider from static bytes", () => {
    const binding = new OpaqueBytesProvider(Buffer.from("token-bytes")).provide(ctx());
    expect(binding.digestValue).toBe(expectedOpaque(Buffer.from("token-bytes")));
  });

  it("opaque provider callable sees the context", () => {
    const seen: Record<string, unknown> = {};
    const fetch = (c: BindingRequestContext): Buffer => {
      seen.tool = c.toolId;
      seen.audience = c.audience;
      return Buffer.from("fresh-token-for-" + c.toolId);
    };
    const binding = new OpaqueBytesProvider(fetch).provide(ctx());
    expect(seen).toEqual({ tool: "read_file", audience: "did:example:server-1" });
    expect(binding.digestValue).toBe(expectedOpaque(Buffer.from("fresh-token-for-read_file")));
  });

  it("reference provider without a resolver fails closed", () => {
    expect(() => new AuthzSystemReferenceProvider().provide(ctx())).toThrow(
      /mcps.authorization_binding_missing/,
    );
  });

  it("reference provider with a resolver", () => {
    const binding = new AuthzSystemReferenceProvider((): {
      authorizationSystemId: string;
      referenceSchemeId: string;
      referenceValue: string;
      digestValue: string;
    } => ({
      authorizationSystemId: "sys-1",
      referenceSchemeId: "scheme-1",
      referenceValue: "grant-7",
      digestValue: "ZGln",
    })).provide(ctx());
    expect(binding.bindingType).toBe("authz-system-reference");
    expect(binding.referenceValue).toBe("grant-7");
  });

  it("static provider returns the prebuilt binding", () => {
    const binding = AuthorizationBinding.opaqueBytes(Buffer.from("y"));
    expect(new StaticAuthorizationProvider(binding).provide(ctx())).toBe(binding);
  });
});

describe("the provider digest lands in the signed preimage", () => {
  it("signOutbound embeds the provider-computed digest, not the legacy constant", () => {
    const req = SIGN_VECTOR.inputs;
    const token = Buffer.from("the-actual-capability-bytes");
    const config: McpsConfig = {
      signer: Signer.software(Buffer.from(req.seed_hex, "hex"), req.signer, req.key_id),
      policy: new SignerPolicy(req.signer, "dev-test", true),
      resolver: new TrustResolver(),
      audience: req.audience,
      onBehalfOf: req.on_behalf_of,
      authorization: new OpaqueBytesProvider(token),
      authorizationPolicy: AuthorizationBindingPolicy.opaqueOnly(),
    };
    const now = Math.floor(Date.parse("2026-06-30T20:00:00Z") / 1000);
    const message = {
      jsonrpc: "2.0" as const,
      id: "req-1",
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "x" } },
    };
    const wire = signOutbound(message, config, new CorrelationStore(), {
      nowUnix: now,
      nonce: "n",
      expiresUnix: now + 300,
    });
    const envelope = JSON.parse(wire.toString("utf-8")).params._meta["se.syncom/mcps.request"];
    const binding = envelope.authorization_binding;
    expect(binding.binding_type).toBe("opaque-bytes");
    expect(binding.digest_value).toBe(expectedOpaque(token));
    expect(binding.digest_value).not.toBe("RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
  });
});
