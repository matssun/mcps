/**
 * Authorization-binding providers — bind real evidence, never a magic constant.
 *
 * MCP-S **binds, never interprets** authorization evidence (bind-not-interpret): the
 * client includes a typed `authorizationBinding` in the signed request preimage so a
 * later verifier can tie the request to the authorization artifact, without MCP-S ever
 * reading the artifact's meaning. The cryptographic digest MUST be computed over the
 * *actual* artifact — handing in a precomputed `digestValue` defeats the point.
 *
 * These providers mirror `mcps-client-core::authz` and delegate digest computation to
 * the audited core (`AuthorizationBinding`), so the binding is produced in one place,
 * identically to the proxy and the Python SDK:
 *
 * - {@link OpaqueBytesProvider} — binds the EXACT decoded artifact bytes (e.g. a bearer
 *   token already base64url-decoded off the transport): `digestValue =
 *   base64url-no-pad(SHA-256(bytes))`, computed in Rust.
 * - {@link AuthzSystemReferenceProvider} — binds an external authorization system's
 *   self-contained digest plus its cross-audit reference, via a resolver.
 * - {@link StaticAuthorizationProvider} — wraps one prebuilt binding.
 *
 * Wire one into `McpsConfig.authorization`; the transport calls `provide(ctx)` per
 * request with a real {@link BindingRequestContext}, then enforces the optional
 * `McpsConfig.authorizationPolicy` (fails closed on a disallowed binding type).
 */

import * as core from "../native/binding.js";
import type { AuthorizationBinding } from "../native/binding.js";
import type { AuthorizationBindingProvider, BindingRequestContext } from "./transport.js";

export type { AuthorizationBindingProvider, BindingRequestContext } from "./transport.js";

/**
 * An external authorization system's reference + its self-contained digest. The digest
 * (not the reference) is the cryptographic binding, so the record stays verifiable
 * independent of the external system.
 */
export interface AuthzReference {
  authorizationSystemId: string;
  referenceSchemeId: string;
  referenceValue: string;
  digestValue: string;
}

/**
 * Artifact source: fixed decoded bytes, or a callable producing them per request (e.g.
 * to fetch a fresh grant within the deadline). The callable receives the context.
 */
export type ArtifactSource = Buffer | Uint8Array | ((ctx: BindingRequestContext) => Buffer | Uint8Array);

/**
 * Bind the EXACT decoded authorization-artifact bytes as `opaque-bytes`.
 *
 * `artifact` is the decoded bytes, or a callable `ctx -> bytes` that yields them per
 * request. The SHA-256 digest is computed by the audited core
 * (`AuthorizationBinding.opaqueBytes`), never by this layer.
 */
export class OpaqueBytesProvider implements AuthorizationBindingProvider {
  private readonly artifact: ArtifactSource;
  constructor(artifact: ArtifactSource) {
    this.artifact = artifact;
  }
  provide(ctx: BindingRequestContext): AuthorizationBinding {
    const data = typeof this.artifact === "function" ? this.artifact(ctx) : this.artifact;
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("OpaqueBytesProvider artifact must be bytes (the decoded artifact)");
    }
    return core.AuthorizationBinding.opaqueBytes(Buffer.from(data));
  }
}

/**
 * Bind an external authz system's digest + reference (`authz-system-reference`).
 *
 * `resolver` is a callable `ctx -> AuthzReference`. With no resolver this fails closed
 * (the mandatory binding cannot be produced), mirroring the Rust
 * `AuthzSystemReferenceProvider::without_resolver`.
 */
export class AuthzSystemReferenceProvider implements AuthorizationBindingProvider {
  private readonly resolver?: (ctx: BindingRequestContext) => AuthzReference;
  constructor(resolver?: (ctx: BindingRequestContext) => AuthzReference) {
    this.resolver = resolver;
  }
  provide(ctx: BindingRequestContext): AuthorizationBinding {
    if (this.resolver === undefined) {
      // No resolver: the mandatory binding is missing — fail closed with the frozen
      // taxonomy reason (matches the Rust provider's posture).
      throw new Error("mcps.authorization_binding_missing");
    }
    const ref = this.resolver(ctx);
    return core.AuthorizationBinding.authzSystemReference(
      ref.authorizationSystemId,
      ref.referenceSchemeId,
      ref.referenceValue,
      ref.digestValue,
    );
  }
}

/** Wrap one prebuilt `AuthorizationBinding` (reused across requests). */
export class StaticAuthorizationProvider implements AuthorizationBindingProvider {
  private readonly binding: AuthorizationBinding;
  constructor(binding: AuthorizationBinding) {
    this.binding = binding;
  }
  provide(_ctx: BindingRequestContext): AuthorizationBinding {
    return this.binding;
  }
}
