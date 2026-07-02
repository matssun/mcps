/**
 * Streamable-HTTP multi-path inbound decode — every decode site routes through MCP-S.
 *
 * The MCP streamable-HTTP transport admits JSON-RPC messages at THREE inbound decode
 * sites, and a secure adapter must run EVERY one through the same verification +
 * server-initiated policy:
 *
 * 1. **direct JSON** — a `POST` answered with `Content-Type: application/json` carrying
 *    one JSON-RPC response (the correlated, `request_hash`-bound case).
 * 2. **POST-SSE** — a `POST` answered with `Content-Type: text/event-stream`: the
 *    correlated response, possibly interleaved with server-initiated messages, each
 *    delivered as one SSE `data` event.
 * 3. **standalone GET-SSE** — a separate `GET` opening a `text/event-stream` of purely
 *    server-initiated messages.
 *
 * This module is the single decode choke point: {@link decodeInbound} turns a
 * `(contentType, body)` pair from ANY site into a list of raw JSON-RPC payloads, and
 * {@link verifyInboundMessages} runs each through {@link verifyInbound} — so the
 * correlated-response verification AND the server-initiated inbound policy (fail-closed
 * by default) apply uniformly at all three sites.
 *
 * The SSE parser operates on a fully-read body (bytes already buffered). True
 * incremental SSE streaming belongs to a dedicated streaming transport; this layer is
 * the verification-correct decoder such a transport plugs into.
 */

import type { CorrelationStore } from "../native/binding.js";
import { InboundOutcome, McpsConfig, MrtStore, verifyInbound } from "./transport.js";

/**
 * Parse a `text/event-stream` body into the `data` payload of each event.
 *
 * Implements the W3C SSE framing the MCP transport relies on: events are separated by a
 * blank line; `data:` field lines accumulate and are joined with `\n`; comment lines
 * (leading `:`) and non-`data` fields (`event` / `id` / `retry`) are ignored; a single
 * leading space after the field colon is stripped. Accepts CRLF, LF, or bare-CR
 * terminators. Each returned payload is one JSON-RPC message. An event with no `data`
 * field yields nothing.
 */
export function sseDataEvents(raw: Buffer | string): Buffer[] {
  const text = (typeof raw === "string" ? raw : raw.toString("utf-8")).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const events: Buffer[] = [];
  let dataLines: string[] = [];

  const dispatch = (): void => {
    if (dataLines.length > 0) {
      events.push(Buffer.from(dataLines.join("\n"), "utf-8"));
      dataLines = [];
    }
  };

  for (const line of text.split("\n")) {
    if (line === "") {
      dispatch();
      continue;
    }
    if (line.startsWith(":")) continue; // comment
    const colon = line.indexOf(":");
    let field: string;
    let value: string;
    if (colon === -1) {
      field = line;
      value = "";
    } else {
      field = line.slice(0, colon);
      value = line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
    }
    if (field === "data") dataLines.push(value);
    // event / id / retry (and unknown fields) are not security-relevant here.
  }
  dispatch(); // a final event need not be followed by a blank line
  return events;
}

/**
 * Decode one inbound HTTP body into its JSON-RPC payload(s), by content type.
 *
 * `text/event-stream` is parsed into one payload per SSE `data` event; anything else
 * (`application/json` or unspecified) is treated as a single direct JSON-RPC message.
 * An empty body yields no payloads.
 */
export function decodeInbound(contentType: string, body: Buffer | string): Buffer[] {
  const mediaType = (contentType || "").split(";", 1)[0].trim().toLowerCase();
  if (mediaType === "text/event-stream") {
    return sseDataEvents(body);
  }
  const buf = typeof body === "string" ? Buffer.from(body, "utf-8") : body;
  // Treat a whitespace-only body as empty, but do not re-encode or otherwise mutate bytes.
  for (const b of buf) {
    if (b !== 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) return [buf];
  }
  return [];
}

/**
 * Decode an inbound body (any of the three sites) and verify EVERY message.
 *
 * Each decoded JSON-RPC payload is run through {@link verifyInbound}, so a correlated
 * response is `request_hash`-verified and a server-initiated message is subjected to
 * the fail-closed inbound policy — uniformly, whichever decode site the body came from.
 * `mrt` (optional) threads the ADR-MCPS-047 multi-round-trip state so a verified
 * `InputRequiredResult` decoded here is recorded for the continuation answer leg.
 */
export function verifyInboundMessages(
  contentType: string,
  body: Buffer | string,
  config: McpsConfig,
  correlation: CorrelationStore,
  opts: { nowUnix: number; mrt?: MrtStore },
): InboundOutcome[] {
  return decodeInbound(contentType, body).map((payload) => {
    try {
      return verifyInbound(payload, config, correlation, { nowUnix: opts.nowUnix, mrt: opts.mrt });
    } catch {
      // Fail closed on any decode/parse failure.
      return { kind: "reject", reason: "mcps.missing_envelope" };
    }
  });
}
