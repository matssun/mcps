/**
 * In-flight correlation tests (mirrors Python `test_correlation.py`).
 *
 * CorrelationStore binds an outgoing signed request to exactly ONE acceptable returning
 * response, and rejects late, replayed, uncorrelatable, nonce-reused, or expired
 * responses — fail-closed with the frozen mcps.* wire code. The clock is the caller's:
 * every method takes nowUnix. Wire codes come from the oracle fixture, never hard-coded.
 */
import { describe, expect, it } from "vitest";
import { CorrelationStore, type RegisterOptions } from "../dist/index.js";
import { CORRELATION_CODES } from "./fixtures.js";

const RH = "sha256:AAAA";

function register(store: CorrelationStore, overrides: Partial<RegisterOptions> = {}): void {
  store.register({
    correlationId: "c1",
    requestHash: RH,
    nonce: "n1",
    deadlineUnix: 2000,
    nowUnix: 1000,
    ...overrides,
  });
}

describe("register + correlate", () => {
  it("round trips", () => {
    const store = new CorrelationStore();
    register(store);
    expect(store.outstanding).toBe(1);
    const entry = store.takeForResponse("c1", 1500);
    expect(entry.requestHash).toBe(RH);
    expect(entry.nonce).toBe("n1");
    expect(entry.version).toBe("draft-02");
    expect(store.outstanding).toBe(0);
  });

  it("duplicate correlation id fails closed", () => {
    const store = new CorrelationStore();
    register(store, { correlationId: "c1", nonce: "n1" });
    expect(() => register(store, { correlationId: "c1", nonce: "n2" })).toThrow(
      CORRELATION_CODES.duplicate_correlation_id,
    );
  });

  it("nonce reuse within the window fails closed", () => {
    const store = new CorrelationStore();
    register(store, { correlationId: "c1", nonce: "shared", nowUnix: 1000 });
    expect(() => register(store, { correlationId: "c2", nonce: "shared", nowUnix: 1500 })).toThrow(
      CORRELATION_CODES.nonce_reuse,
    );
  });

  it("nonce reusable after the window closes", () => {
    const store = new CorrelationStore();
    register(store, { correlationId: "c1", nonce: "shared", nowUnix: 1000 });
    store.takeForResponse("c1", 1500);
    store.sweepExpired(2001);
    register(store, { correlationId: "c2", nonce: "shared", deadlineUnix: 3000, nowUnix: 2001 });
    expect(store.outstanding).toBe(1);
  });

  it("late response after cleanup is uncorrelatable", () => {
    const store = new CorrelationStore();
    register(store);
    expect(store.sweepExpired(2001)).toBe(1);
    expect(() => store.takeForResponse("c1", 2002)).toThrow(CORRELATION_CODES.uncorrelatable);
  });

  it("response past the deadline is expired", () => {
    const store = new CorrelationStore();
    register(store);
    expect(() => store.takeForResponse("c1", 2001)).toThrow(CORRELATION_CODES.expired);
    expect(store.outstanding).toBe(0);
  });

  it("unknown correlation id is uncorrelatable", () => {
    const store = new CorrelationStore();
    expect(() => store.takeForResponse("nope", 1000)).toThrow(CORRELATION_CODES.uncorrelatable);
  });

  it("cancel removes the entry", () => {
    const store = new CorrelationStore();
    register(store);
    expect(store.cancel("c1")).toBe(true);
    expect(store.cancel("c1")).toBe(false);
    expect(store.outstanding).toBe(0);
    expect(() => store.takeForResponse("c1", 1500)).toThrow(CORRELATION_CODES.uncorrelatable);
  });

  it("sweep removes only expired", () => {
    const store = new CorrelationStore();
    register(store, { correlationId: "c1", nonce: "n1", deadlineUnix: 1500 });
    register(store, { correlationId: "c2", nonce: "n2", deadlineUnix: 3000 });
    expect(store.sweepExpired(2000)).toBe(1);
    expect(store.outstanding).toBe(1);
    expect(store.takeForResponse("c2", 2000).requestHash).toBe(RH);
  });

  it("pending entry carries metadata", () => {
    const store = new CorrelationStore();
    store.register({
      correlationId: "c1",
      requestHash: RH,
      nonce: "n1",
      deadlineUnix: 2000,
      nowUnix: 1000,
      routeId: "route-a",
      audience: "did:example:server",
      expectedServerSigners: ["did:example:server"],
      authzDigest: "digest123",
    });
    const e = store.takeForResponse("c1", 1500);
    expect(e.routeId).toBe("route-a");
    expect(e.audience).toBe("did:example:server");
    expect(e.expectedServerSigners).toEqual(["did:example:server"]);
    expect(e.authzDigest).toBe("digest123");
  });
});
