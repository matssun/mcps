/**
 * MCP-S transport adapter — signs outbound / verifies inbound at the byte boundary.
 *
 * The MCP TypeScript SDK serializes JSON-RPC *inside* each transport (the `Protocol`
 * layer hands the transport parsed `JSONRPCMessage` objects, and each transport does
 * its own `JSON.stringify`/framing), so the only seam with exact-byte control is the
 * transport itself — exactly as the Python spike (#199) found for the Python SDK.
 * This adapter therefore OWNS the wire: a `Client` talks plain MCP through the
 * `Transport` interface, and the adapter signs every outbound request and verifies
 * every inbound response against the audited `mcps-client-core` binding.
 *
 * The security core is two synchronous, deterministic functions — {@link signOutbound}
 * (steps 1-4 of the proxy pipeline: sign + register correlation) and
 * {@link verifyInbound} (steps 5-9: correlate + verify + strip envelope). The
 * {@link McpsTransport} class is thin async glue that pumps those over a byte channel.
 */

import * as core from "../native/binding.js";
import type {
  AuthorizationBinding,
  AuthorizationBindingPolicy,
  CorrelationStore,
  Signer,
  SignerPolicy,
  TrustResolver,
} from "../native/binding.js";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { randomBytes } from "node:crypto";

/**
 * Raised/surfaced when an inbound response fails closed. Carries the frozen `mcps.*`
 * wire reason. For a correlated response the adapter instead delivers a JSON-RPC error
 * bound to the request id (so the awaiting `Client` call rejects); this error type is
 * surfaced via `transport.onerror` for uncorrelatable/server-initiated rejections.
 */
export class McpsVerificationError extends Error {
  readonly reason: string | undefined;
  constructor(reason: string | undefined) {
    super(`MCP-S response rejected: ${reason}`);
    this.name = "McpsVerificationError";
    this.reason = reason;
  }
}

/** An authorization-binding provider (mirrors `mcps_sdk.authorization`). */
export interface AuthorizationBindingProvider {
  provide(ctx: BindingRequestContext): AuthorizationBinding;
}

/** What a provider may use to LOCATE/produce the right artifact for a request. */
export interface BindingRequestContext {
  readonly audience: string;
  readonly routeId: string;
  readonly method: string | null;
  readonly toolId: string | null;
  readonly deadlineUnix: number;
}

/** Per-connection MCP-S policy + identity the adapter signs/verifies under. */
export interface McpsConfig {
  signer: Signer;
  policy: SignerPolicy;
  resolver: TrustResolver;
  audience: string;
  onBehalfOf: string;
  /**
   * Authorization-evidence binding. PREFER a provider: set `authorization` to an
   * {@link AuthorizationBindingProvider} (e.g. `OpaqueBytesProvider`) or a prebuilt
   * `AuthorizationBinding` — the digest is then computed in the audited core from the
   * real artifact bytes, not supplied as a constant. `authorizationPolicy` fails a
   * route closed to its permitted binding types. The raw `bindingDigest*` shortcut is
   * the dev/test fallback used only when `authorization` is undefined.
   */
  authorization?: AuthorizationBindingProvider | AuthorizationBinding;
  authorizationPolicy?: AuthorizationBindingPolicy;
  bindingDigestAlg?: string;
  bindingDigestValue?: string;
  expectedServerSigner?: string;
  enforcementMode?: string;
  legacyAllowed?: boolean;
  ttlSeconds?: number;
  routeId?: string;
  /**
   * Inbound policy for SERVER-INITIATED messages (a server->client request or
   * notification — NOT a response to one of our signed requests). The MCP-S evidence
   * model binds a server's signature to the client's `request_hash`; a server-initiated
   * message has none, so `mcps-client-core` cannot verify it. STRICT MCP-S is the
   * client-initiated request/response subset (extended to signed multi-round-trip
   * continuation by ADR-MCPS-047; ARBITRARY server push stays out of scope): the safe
   * default FAILS CLOSED.
   *
   * `true` is a DEGRADED / MIGRATION policy ONLY — an explicit operator opt-OUT of the
   * guarantee for the server-initiated channel. The message is then delivered but
   * audited as NO-EVIDENCE. It is NOT strict enterprise MCP-S. Leave it off for strict
   * deployments.
   */
  allowUnverifiedServerInitiated?: boolean;
}

const DEFAULT_TTL = 300;
const DEFAULT_ROUTE = "default";

function ttlSeconds(config: McpsConfig): number {
  return config.ttlSeconds ?? DEFAULT_TTL;
}
function routeId(config: McpsConfig): string {
  return config.routeId ?? DEFAULT_ROUTE;
}

/**
 * Recorded multi-round-trip state for one verified `InputRequiredResult`
 * (ADR-MCPS-047). The SECURITY binding is these two hashes — both taken from the
 * verified, signed elicitation response — plus the route/audience context. The
 * server-provided `requestState` is only the opaque LOOKUP handle used to match the
 * answer leg; it is never the security key.
 */
interface MrtEntry {
  previousRequestHash: string;
  inputRequiredResponseHash: string;
  routeId: string;
  audience: string;
}

/** The shared multi-round-trip map: `requestState` handle -> recorded binding. */
export type MrtStore = Map<string, MrtEntry>;

/**
 * If `params` is a continuation answer (carries `inputResponses` AND an echoed
 * `requestState`, SEP-2322), return the `requestState` handle; else null.
 */
function continuationAnswer(params: unknown): string | null {
  if (typeof params !== "object" || params === null) return null;
  const p = params as Record<string, unknown>;
  if ("inputResponses" in p && "requestState" in p) {
    return typeof p.requestState === "string" ? p.requestState : null;
  }
  return null;
}

function rfc3339(unix: number): string {
  return new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

interface RequestFields {
  isRequest: boolean;
  id: unknown;
  method: string | undefined;
  params: unknown;
}

function requestFields(message: JSONRPCMessage): RequestFields {
  const m = message as Record<string, unknown>;
  const id = m.id;
  const method = typeof m.method === "string" ? m.method : undefined;
  // A request needs a string/number id (not null/undefined): verifyInbound treats a
  // null id as uncorrelatable, so signing one would register a correlation entry whose
  // response can never correlate. Keep the outbound predicate consistent with that.
  const hasId = typeof id === "string" || typeof id === "number";
  return { isRequest: hasId && method !== undefined, id, method, params: m.params };
}

/**
 * Resolve the authorization-binding signing arguments for this request.
 *
 * With `config.authorization` set, call the provider (or accept a prebuilt binding)
 * under a real {@link BindingRequestContext}, so the digest is computed by the audited
 * core from the actual artifact — then enforce the optional route policy (fails closed
 * on a disallowed type). With no provider, fall back to the raw `bindingDigest*` opaque
 * shortcut (dev/test).
 */
function bindingArgs(
  config: McpsConfig,
  method: string,
  params: unknown,
  deadlineUnix: number,
): { options: Partial<core.SignWithSignerOptions>; binding?: AuthorizationBinding } {
  if (config.authorization === undefined) {
    return {
      options: {
        bindingDigestAlg: config.bindingDigestAlg ?? "sha256",
        bindingDigestValue: config.bindingDigestValue ?? "",
      },
    };
  }
  const provider = config.authorization;
  let binding: AuthorizationBinding;
  if (typeof (provider as AuthorizationBindingProvider).provide === "function") {
    const toolId =
      method === "tools/call" && typeof params === "object" && params !== null
        ? ((params as Record<string, unknown>).name as string | undefined) ?? null
        : null;
    binding = (provider as AuthorizationBindingProvider).provide({
      audience: config.audience,
      routeId: routeId(config),
      method,
      toolId,
      deadlineUnix,
    });
  } else {
    binding = provider as AuthorizationBinding; // a prebuilt AuthorizationBinding
  }
  if (config.authorizationPolicy !== undefined) {
    config.authorizationPolicy.enforce(binding); // throws on a disallowed type
  }
  return { options: {}, binding };
}

/** Options controlling one {@link signOutbound} call (clock/nonce/deadline + MRT). */
export interface SignOutboundOptions {
  nowUnix: number;
  nonce: string;
  expiresUnix: number;
  mrt?: MrtStore;
}

/**
 * Sign an outbound request and register it for correlation; return wire bytes.
 *
 * A non-request (notification / a response to a server-initiated request) is passed
 * through plain (serialized verbatim).
 *
 * ADR-MCPS-047 answer leg: a request carrying `inputResponses` + an echoed
 * `requestState` is a continuation. Its recorded multi-round-trip state (from the
 * verified `InputRequiredResult` — see {@link verifyInbound}) is looked up in `mrt` by
 * the `requestState` handle and the fresh request is bound to the verified
 * elicitation's `previousRequestHash` / `inputRequiredResponseHash`. A continuation
 * with NO matching recorded state — or a route/audience mismatch — FAILS CLOSED (we
 * never sign an unbound continuation).
 */
export function signOutbound(
  message: JSONRPCMessage,
  config: McpsConfig,
  correlation: CorrelationStore,
  opts: SignOutboundOptions,
): Buffer {
  const { isRequest, id, method, params } = requestFields(message);
  if (!isRequest) {
    return Buffer.from(JSON.stringify(message));
  }

  let continuation: Partial<core.SignWithSignerOptions> = {};
  const requestState = continuationAnswer(params);
  if (requestState !== null) {
    const entry = opts.mrt?.get(requestState);
    if (entry === undefined) {
      throw new Error(
        "mcps.continuation_malformed: no recorded multi-round-trip state for the " +
          "answered InputRequiredResult (unknown or already-used requestState)",
      );
    }
    opts.mrt?.delete(requestState);
    // The binding is to the verified elicitation's hashes; validate the exchange
    // context too so a continuation cannot be replayed onto another route/audience.
    if (entry.routeId !== routeId(config) || entry.audience !== config.audience) {
      throw new Error(
        "mcps.continuation_malformed: continuation route/audience does not match the " +
          "recorded InputRequiredResult exchange",
      );
    }
    continuation = {
      continuationPreviousRequestHash: entry.previousRequestHash,
      continuationInputRequiredResponseHash: entry.inputRequiredResponseHash,
    };
  }

  const { options: bindingOptions, binding } = bindingArgs(config, method as string, params, opts.expiresUnix);
  const signed = core.signRequestWithSigner(
    JSON.stringify(id),
    method as string,
    JSON.stringify(params ?? {}),
    {
      onBehalfOf: config.onBehalfOf,
      audience: config.audience,
      nonce: opts.nonce,
      issuedAt: rfc3339(opts.nowUnix),
      expiresAt: rfc3339(opts.expiresUnix),
      ...bindingOptions,
      ...continuation,
    },
    config.signer,
    config.policy,
    binding,
  );
  correlation.register({
    correlationId: String(id),
    requestHash: signed.requestHash,
    nonce: opts.nonce,
    deadlineUnix: opts.expiresUnix,
    nowUnix: opts.nowUnix,
    audience: config.audience,
    routeId: routeId(config),
    expectedServerSigners: config.expectedServerSigner ? [config.expectedServerSigner] : [],
  });
  return Buffer.from(signed.wireBytes);
}

/** Result of verifying one inbound line. `kind` is accept / reject / passthrough. */
export interface InboundOutcome {
  kind: "accept" | "reject" | "passthrough";
  message?: JSONRPCMessage; // a plain message on accept/passthrough
  reason?: string; // the mcps.* wire reason on reject
}

/** Remove the MCP-S response envelope from `result._meta` so the app sees plain MCP. */
function stripEnvelope(obj: Record<string, unknown>): Record<string, unknown> {
  const result = obj.result as Record<string, unknown> | undefined;
  const meta = result && typeof result === "object" ? (result._meta as Record<string, unknown> | undefined) : undefined;
  if (meta && typeof meta === "object") {
    delete meta[core.responseMetaKey()];
    if (Object.keys(meta).length === 0) {
      delete result!._meta;
    }
  }
  return obj;
}

/** Options controlling one {@link verifyInbound} call (clock + MRT). */
export interface VerifyInboundOptions {
  nowUnix: number;
  mrt?: MrtStore;
}

/**
 * Correlate + verify one inbound line.
 *
 * A response to one of our requests (has `id`, no `method`) is correlated and verified;
 * on accept the MCP-S envelope is stripped and a plain message is returned. A
 * late/uncorrelatable/expired correlation or a failed verification is a fail-closed
 * reject.
 *
 * ADR-MCPS-047: a verified response is classified. A TERMINAL result consumes the
 * correlation slot (`takeForResponse`). A non-terminal `InputRequiredResult` does NOT —
 * it is recorded (`recordInputRequired`, associate-without-consume) and, when `mrt` is
 * provided, its verified `(previousRequestHash, inputRequiredResponseHash)` is stashed
 * keyed by the response's opaque `requestState` so the answer leg can bind a signed
 * continuation. The plain elicitation is delivered to the session either way.
 *
 * A SERVER-INITIATED message (it carries a `method`) is NOT a response to one of our
 * requests, so there is no `request_hash` to bind it and the core cannot verify it. The
 * `allowUnverifiedServerInitiated` policy decides: fail closed under the safe default
 * (`mcps.missing_envelope` for an id-bearing server request, `mcps.notification_forbidden`
 * for a notification), or pass it through unverified (audited as no-evidence).
 */
export function verifyInbound(
  line: Buffer | string,
  config: McpsConfig,
  correlation: CorrelationStore,
  opts: VerifyInboundOptions,
): InboundOutcome {
  const raw = typeof line === "string" ? line : line.toString("utf-8");
  const obj = JSON.parse(raw) as Record<string, unknown>;
  const hasMethod = "method" in obj;
  const rid = obj.id;

  if (hasMethod) {
    // Server-initiated request/notification — no request_hash binding exists, so the
    // core cannot verify it. Apply the inbound policy. NOTE: a legitimate elicitation
    // arrives as a RESPONSE (InputRequiredResult, no method); a method-bearing server
    // push is arbitrary push and stays out (D9).
    if (config.allowUnverifiedServerInitiated) {
      return { kind: "passthrough", message: obj as unknown as JSONRPCMessage };
    }
    const reason = rid !== undefined && rid !== null ? "mcps.missing_envelope" : "mcps.notification_forbidden";
    return { kind: "reject", reason };
  }

  if (rid === undefined || rid === null) {
    // Neither a method nor an id: not a correlatable JSON-RPC response. Fail closed
    // rather than deliver an uncorrelatable, unverifiable message.
    return { kind: "reject", reason: "mcps.missing_envelope" };
  }

  // A response to one of our outstanding requests. PEEK (do not consume yet): the
  // terminal-vs-InputRequiredResult decision is made only after verification.
  let entry: core.PendingRequest;
  try {
    entry = correlation.peekForResponse(String(rid), opts.nowUnix);
  } catch (exc) {
    // late / uncorrelatable / expired -> fail closed. Normalize to the bare mcps.*
    // wire code so reject reasons are consistent with the verify path.
    return { kind: "reject", reason: lastWireCode(exc) };
  }

  const result = core.verifyResponse(Buffer.from(raw), config.resolver, {
    expectedRequestHash: entry.requestHash,
    expectedServerSigner: config.expectedServerSigner,
    enforcementMode: config.enforcementMode ?? "require_mcps",
    legacyAllowed: config.legacyAllowed ?? false,
  });

  if (result.accepted) {
    if (result.inputRequired) {
      // Non-terminal (D7): retain the exchange and record the verified linkage.
      const binding = correlation.recordInputRequired(String(rid), result.responseHash as string, opts.nowUnix);
      const plain = stripEnvelope(obj);
      const inner = plain.result as Record<string, unknown> | undefined;
      const requestState = inner && typeof inner === "object" ? inner.requestState : undefined;
      if (opts.mrt && typeof requestState === "string") {
        opts.mrt.set(requestState, {
          previousRequestHash: binding.previousRequestHash,
          inputRequiredResponseHash: binding.inputRequiredResponseHash,
          routeId: routeId(config),
          audience: config.audience,
        });
      }
      return { kind: "accept", message: plain as unknown as JSONRPCMessage };
    }
    // Terminal: consume the correlation slot (cleanup-on-completion).
    correlation.takeForResponse(String(rid), opts.nowUnix);
    return { kind: "accept", message: stripEnvelope(obj) as unknown as JSONRPCMessage };
  }
  if (result.decision === "fallback") {
    // Config-permitted legacy/plaintext pass-through (audited as no-evidence).
    correlation.takeForResponse(String(rid), opts.nowUnix);
    return { kind: "accept", message: obj as unknown as JSONRPCMessage };
  }
  // Fail closed: consume the slot so a rejected response cannot be retried.
  correlation.cancel(String(rid));
  return { kind: "reject", reason: result.reason };
}

/** Extract the bare `mcps.*` wire code from a thrown correlation `Error` message. */
export function lastWireCode(exc: unknown): string {
  const msg = exc instanceof Error ? exc.message : String(exc);
  const idx = msg.lastIndexOf(": ");
  return idx >= 0 ? msg.slice(idx + 2) : msg;
}

/** A byte-channel sink the async transport pumps framed wire bytes into. */
export type ByteSend = (bytes: Buffer) => Promise<void>;

function defaultNonce(): string {
  return randomBytes(16).toString("base64url");
}
function defaultClock(): number {
  return Math.floor(Date.now() / 1000);
}

/** Hooks for injecting a deterministic clock / nonce (tests) into a transport. */
export interface TransportHooks {
  clock?: () => number;
  nonceFactory?: () => string;
  correlation?: CorrelationStore;
}

/**
 * Thin async glue implementing the MCP TypeScript SDK `Transport`: pumps
 * {@link signOutbound} / {@link verifyInbound} between a byte channel (the real wire)
 * and the `Client`'s `send` / `onmessage` callbacks.
 *
 * `byteSend` writes framed bytes to the wire; `byteLines` is an async iterator of
 * inbound raw lines (newline-delimited JSON, the MCP stdio framing). Inject these from
 * a subprocess (stdio) — or, in tests, from an in-memory pipe. A fail-closed correlated
 * response is delivered as a JSON-RPC error bound to the request id (so the awaiting
 * `Client` call rejects, not hangs); an uncorrelatable/server-initiated rejection is
 * surfaced via `onerror`.
 */
export class McpsTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  private readonly byteSend: ByteSend;
  private readonly byteLines: AsyncIterable<Buffer>;
  private readonly config: McpsConfig;
  private readonly correlation: CorrelationStore;
  private readonly clock: () => number;
  private readonly nonceFactory: () => string;
  // ADR-MCPS-047 multi-round-trip state: requestState handle -> recorded continuation
  // binding, shared between the reader (records it) and send (consumes it on the answer).
  private readonly mrt: MrtStore = new Map();
  private started = false;
  private closed = false;

  constructor(byteSend: ByteSend, byteLines: AsyncIterable<Buffer>, config: McpsConfig, hooks: TransportHooks = {}) {
    this.byteSend = byteSend;
    this.byteLines = byteLines;
    this.config = config;
    this.correlation = hooks.correlation ?? new core.CorrelationStore();
    this.clock = hooks.clock ?? defaultClock;
    this.nonceFactory = hooks.nonceFactory ?? defaultNonce;
  }

  async start(): Promise<void> {
    if (this.started) throw new Error("McpsTransport already started");
    this.started = true;
    void this.readerLoop();
  }

  async send(message: JSONRPCMessage, _options?: TransportSendOptions): Promise<void> {
    const now = this.clock();
    const wire = signOutbound(message, this.config, this.correlation, {
      nowUnix: now,
      nonce: this.nonceFactory(),
      expiresUnix: now + ttlSeconds(this.config),
      mrt: this.mrt,
    });
    await this.byteSend(Buffer.concat([wire, Buffer.from("\n")]));
  }

  async close(): Promise<void> {
    this.closed = true;
    this.onclose?.();
  }

  private async readerLoop(): Promise<void> {
    try {
      for await (const line of this.byteLines) {
        if (this.closed) break;
        if (!line || line.length === 0) continue;
        const outcome = verifyInbound(line, this.config, this.correlation, {
          nowUnix: this.clock(),
          mrt: this.mrt,
        });
        if (outcome.kind === "accept" || outcome.kind === "passthrough") {
          this.onmessage?.(outcome.message as JSONRPCMessage);
        } else {
          // Fail closed: surface via onerror. (For a request/response transport prefer
          // McpsHttpTransport, which binds the reject to the request id so the call
          // rejects.)
          this.onerror?.(new McpsVerificationError(outcome.reason));
        }
      }
    } catch (err) {
      this.onerror?.(err instanceof Error ? err : new Error(String(err)));
    }
  }
}
