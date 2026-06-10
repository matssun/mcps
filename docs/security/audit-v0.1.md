# MCP-S Code Audit — Findings Report (v0.1)

> **Note for public-repo readers.** This is the original audit report as produced
> by the multi-agent review workflow, sanitized lightly for public release. Bare
> `#NNNN` references in the body (e.g. `#4030`) are author-private monorepo
> issue/PR numbers, **not** GitHub issues in this repository; they are preserved
> here for fidelity with the original report. The remediation status for every
> finding is tracked in [`remediation-v0.2.md`](remediation-v0.2.md).

**Audit date:** 2026-06-01  
**Subject:** MCP-S Rust workspace (Zero-Trust security profile for the Model Context Protocol)  
**Revision audited:** `main` at commit immediately after PR #3973 merge (2026-06-01, build green)  
**Auditor (engine):** Claude Opus 4.8 multi-agent review workflow `wf_0d84f4bb-ca0` — 165 agents, 8.24M tokens, 33 min wall-clock  
**Standard applied:** high-assurance / military-grade scrutiny; assume hostile client AND hostile inner server  
**Overall residual-risk rating:** `MODERATE`

> This report is generated deterministically from machine-validated structured findings. Severity counts and traceability statuses are computed from agent output, not narrated. Every security/critical/high finding survived an independent 3-skeptic adversarial verification panel (≥2 of 3 had to confirm the defect from the source code, defaulting to *invalid* when unconfirmable); refuted findings are listed in §8 to evidence that the verification gate is load-bearing.

---

## 1. Scope and Method

### 1.1 Scope

| Crate | Role | Classification |
|---|---|---|
| `mcps-core` | Pure verification (canonicalization, signing, hashing, replay, envelope). No I/O. | **Production-critical** |
| `mcps-host` | Transport-free request signing / response verification. Compile-time guard forbids networking. | **Production-critical** |
| `mcps-transport` | Client-side mTLS; verifies server certificate. | **Production-critical** |
| `mcps-proxy` | Server-side PEP/sidecar; subprocess inner; production CLI (`mcps_proxy_cli`). | **Production-critical** |
| `mcps-policy` | Phase-5 reference authorization profile. | **Production-critical** |
| `mcps-conformance` | Drift guards + conformance harness + traceability manifest guard. | Non-production (demo/conformance) |
| `mcps-demo` | Demonstration harness + e2e binaries. | Non-production (demo/conformance) |
| `mcps-demo-server` | Long-lived demonstration MCP server. | Non-production (demo/conformance) |
| `mcps-demo-fileserver` | One-shot demonstration MCP server. | Non-production (demo/conformance) |

Total reviewed: **9 crates, ~17.9k LoC src + ~12.9k LoC tests**. Every crate was reviewed under all three lenses.

### 1.2 Method

Three lenses applied per crate, then synthesized:

1. **General code review** — correctness, idiomatic Rust, error handling, resource/concurrency safety, boundary discipline.
2. **Spec-conformance & completeness** — each normative property traced to code + test; stub/panic/fallback ledger triaged.
3. **Security review (high-assurance)** — cryptography, mTLS verification, replay/nonce/clock, canonicalization bypass, fail-closed posture, deny-before-dispatch, authorization scoping, secret handling, injection, DoS.

**Verification gate:** every finding rated security/critical/high was independently re-examined by a 3-agent skeptic panel (lenses: exploitability, spec-correctness, false-positive). A finding was kept only if ≥2 of 3 confirmed it from the source; otherwise dropped as a false positive (see §8).

**Normative baseline:** a property catalog of **197 requirements** was extracted from `mcps-core-spec.md`, `security-boundary.md`, the project/upstream briefs, the P6.x epic/findings, and the `security_traceability_manifest.json` before any code was read.

---

## 2. Executive Summary

The MCP-S Rust workspace is a zero-trust security layer for the Model Context Protocol, built to a high-assurance bar: an in-house JCS canonicalizer, Ed25519 object-signing over the complete JSON-RPC object, a fail-closed twelve-step verification pipeline, mutual-TLS transport binding, durable single-node replay protection, and a Phase-5 delegated-authorization reference profile. The core security architecture is sound and, in the sanctioned end-to-end pipeline, behaves as specified: every reviewed positive control (real server-cert verification, deny-before-dispatch, replay-after-signature ordering, response-to-request hash binding, fault paths gated off by default) was confirmed present and load-bearing, and no signature-bypass, identity-spoof, or fail-open admission path was found through the integrated flow.

The findings cluster in three honest categories. First, denial-of-service hardening gaps at trust boundaries: the public canonicalize/parse primitive recurses with no depth bound (stack-exhaustion abort on deeply-nested untrusted JSON), the client transport sets no socket timeouts and reads responses unbounded (slow-loris and OOM against a hostile-but-authenticated peer), and the proxy's inner-subprocess pipe I/O has no timeout (a wedged-but-alive inner hangs the single-threaded serve loop, contradicting the module's explicit "never hang" promise). These are real availability defects against in-scope hostile peers; none of them admits an unauthorized request. Second, spec-conformance deviations that are fail-closed but emit the wrong taxonomy token or rest on an unproven claim: absent on_behalf_of / authorization_hash map to canonicalization_failed rather than their dedicated missing-token (P005/P007), the OnBehalfOfMissing variant is dead with a false "asserted reachable" comment, and the conformance drift-guard under-covers (it claims to enumerate every mcps target but silently omits 17-18 rust_test targets across four packages, and two of the six P182 cross-transport vectors are not run cross-transport). Third, defense-in-depth and structural-contract weaknesses: the RevocationSource bool-only API cannot express an indeterminate verdict so its mandated fail-closed-on-outage behavior is unenforceable, the policy reference profile's duplicate-key safety lives in one evaluator-ordering step rather than locally in authorize(), the host signs caller-supplied foreign_meta keys (the proxy's strip of caller .verified is the only thing that contains this), and several demo evidence fields overclaim (mtls_verified / server_cert_verified are tautologies or application-layer proxies, not independent transport oracles). No critical (admission-bypass) finding survived verification.

### 2.1 Findings by severity (post-verification)

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 14 |
| Low | 36 |
| Info | 53 |
| **Total kept** | **106** |
| *Refuted by skeptic panel* | *16* |

### 2.2 Findings by crate (kept)

| Crate | Crit | High | Med | Low | Info | Total |
|---|---|---|---|---|---|---|
| `mcps-core` | 0 | 2 | 2 | 3 | 6 | 13 |
| `mcps-host` | 0 | 0 | 0 | 3 | 4 | 7 |
| `mcps-transport` | 0 | 0 | 4 | 3 | 8 | 15 |
| `mcps-proxy` | 0 | 1 | 3 | 3 | 6 | 13 |
| `mcps-policy` | 0 | 0 | 1 | 7 | 4 | 12 |
| `mcps-conformance` | 0 | 0 | 3 | 7 | 4 | 14 |
| `mcps-demo` | 0 | 0 | 1 | 4 | 6 | 11 |
| `mcps-demo-server` | 0 | 0 | 0 | 4 | 7 | 11 |
| `mcps-demo-fileserver` | 0 | 0 | 0 | 2 | 8 | 10 |

### 2.3 Spec-conformance rollup

| Property status | Count |
|---|---|
| Implemented | 109 |
| Partial | 21 |
| Missing | 0 |
| Not assessed by rollup* | 67 |
| **Total normative properties** | **197** |

> \* **Not-assessed is a rollup-matching artifact, not an implementation gap.** The traceability rollup joins a crate's coverage rows to catalog properties by exact title match; where a finder phrased a coverage row differently from the catalog title, the join missed. **Zero properties were found *missing*** (no spec requirement is unimplemented), and the 67 not-matched properties are predominantly Core crypto/envelope invariants that the security lens confirmed in narrative. This is called out as audit limitation L-1 in §9 and §10.

---

## 3. High-Severity Findings

All 3 survived adversarial verification. Note: findings H-1 and H-2 are the **same defect** in the Core JCS canonicalizer, independently surfaced by the general and security lenses — treat as one issue with corroboration.

### H-1 — Unbounded recursion in public canonicalize/parse → stack overflow / process abort (DoS) on deeply-nested JSON

- **Crate:** `mcps-core`  
- **Location:** `mcps-core/src/canonical.rs:298-389`  
- **Category:** boundary  
- **Lens:** general  
- **Verification:** confirmed by 3/3 skeptics

**Description.** The in-house JSON parser recurses per nesting level with no depth limit: parse_value -> parse_object/parse_array -> parse_value. canonicalize and parse are public, crate-root-exported APIs intended to run on untrusted wire bytes (the module docstring calls this 'the most security-critical unit'). Deeply-nested input (e.g. a long run of '[') exhausts the thread stack and aborts the whole process via SIGABRT — a remote, unauthenticated denial of service for any consumer that calls canonicalize/parse directly on attacker bytes. Within verify_request/verify_response the prior serde_json::from_slice (default 128-depth limit) rejects such input first, so the pipeline entry points are guarded; but the public primitive is not, and downstream crates (host/proxy) may legitimately call it directly. A high-assurance crate must bound recursion explicitly rather than rely on a callers' incidental serde guard.

**Evidence.**

```
fn parse_value(&mut self) { match self.peek() { Some('{') => self.parse_object(), Some('[') => self.parse_array(), ... } } with parse_object/parse_array calling self.parse_value() recursively and no depth counter anywhere. Reproduced: a test feeding 200_000 nested '[' to mcps_core::canonicalize aborted with 'has overflowed its stack / fatal runtime error: stack overflow, aborting' (SIGABRT).
```

### H-2 — Hand-rolled JCS parser has no recursion-depth limit; public canonicalize/parse can be stack-exhausted by deeply nested untrusted JSON

- **Crate:** `mcps-core`  
- **Location:** `src/canonical.rs:298-308,336-390`  
- **Category:** DoS  
- **Lens:** security  
- **Verification:** confirmed by 3/3 skeptics

**Description.** Parser::parse_value / parse_object / parse_array recurse with no depth counter or iterative bound. canonicalize() and parse() are part of the crate's public API (re-exported at lib.rs:36-39) and are documented for use by the signing layer and any caller on raw wire bytes. A caller (e.g. mcps-host/mcps-proxy) that invokes canonicalize() directly on attacker-controlled bytes can be driven to stack overflow (process abort) with a deeply nested array/object such as '[[[[...]]]]'. Inside verify_request the input first passes serde_json::from_slice (pipeline.rs:156), which enforces serde_json's default 128-level recursion limit and returns Err on deeper input, so the in-pipeline path is bounded; but the public canonicalize/parse functions carry no such guard for direct callers, and a pure 'verification' crate aborting on hostile input is a fail-closed-violating crash rather than a clean CanonicalizationFailed.

**Evidence.**

```
fn parse_value(&mut self) -> Result<JcsValue, McpsError> { match self.peek() { Some('{') => self.parse_object(), Some('[') => self.parse_array(), ... } }  // parse_object/parse_array call parse_value again with no depth bound
```

### H-3 — Persistent inner: unbounded blocking on inner stdin/stdout pipes can hang the single-threaded serve loop (contradicts "never hangs")

- **Crate:** `mcps-proxy`  
- **Location:** `mcps-proxy/src/persistent_inner.rs:286-324`  
- **Category:** resource-handling  
- **Lens:** general  
- **Verification:** confirmed by 3/3 skeptics

**Description.** PersistentSubprocessInner::write_line_read_matching writes the request to ChildStdin with blocking write_all (lines 290-298) and reads the response with BufRead::read_line (line 307). Neither the child's stdin nor stdout pipe has any timeout. A child that stays ALIVE but stops draining its stdin while the OS pipe buffer is full will block write_all indefinitely; a child that neither emits a line nor closes stdout will block read_line indefinitely. The module-level docs (lines 40-45) and dispatch contract (lines 206-207) claim 'never hangs' and the failure tests only cover EOF/crash (read returns 0), not a wedged-but-alive child. Because main.rs runs a single-threaded blocking serve loop (one connection at a time) and the socket-level read/write timeouts in tls.rs apply only to the TLS socket — never to the inner pipe — one stalled inner wedges the entire proxy (DoS). The Drop impl (lines 367-371) has the same blocking-write exposure on the shutdown frame.

**Evidence.**

```
self.stdin.write_all(request)... self.stdout.read_line(&mut line)... with no set_*_timeout / nonblocking anywhere in persistent_inner.rs; tests/persistent_inner_test.rs:258 covers crash/EOF only.
```

---

## 4. Medium-Severity Findings

### M-1 — Missing on_behalf_of maps to mcps.canonicalization_failed, not mcps.on_behalf_of_missing (P005)

- **Crate:** `mcps-core` · **Location:** `mcps-core/src/constraints.rs:140-154 + src/pipeline.rs:301-306` · **Category:** error-handling · **Lens:** conformance

P005 requires that an ABSENT on_behalf_of yields mcps.on_behalf_of_missing. But RequestEnvelope.on_behalf_of is a non-optional String, so a missing field fails serde deserialization in deserialize_envelope and (not matching the 'unknown field' prefix) maps to McpsError::CanonicalizationFailed. check_on_behalf_of in the pipeline only ever sees a present value, so it can only emit OnBehalfOfInvalidFormat (empty), never OnBehalfOfMissing. The McpsError::OnBehalfOfMissing variant is therefore DEAD in the pipeline: grep shows it is defined and its wire token unit-tested, but no code path produces it and no test exercises its production. The pipeline module doc (pipeline.rs:48-52) explicitly claims it is 'asserted reachable in the unit tests by feeding an envelope-shaped value that omits it through the field check directly' — that test does not exist. This is both a spec-conformance deviation (wrong error token for the absent case) and a false comment.

> *Evidence:* src/envelope.rs:46-47 `pub on_behalf_of: String,` (required). src/constraints.rs:147-151 maps any non-'unknown field' serde error to CanonicalizationFailed. src/pipeline.rs:301-306 `fn check_on_behalf_of(... ) { if on_behalf_of.is_empty() { return Err(OnBehalfOfInvalidFormat) } }`. grep: OnBehalfOfMissing appears only in error.rs (def + wire_code + token test) and a pipeline.rs doc comment — never raised.

### M-2 — Missing authorization_hash maps to mcps.canonicalization_failed, not mcps.authorization_hash_missing (P007)

- **Crate:** `mcps-core` · **Location:** `mcps-core/src/constraints.rs:140-154 + src/pipeline.rs:290-295` · **Category:** error-handling · **Lens:** conformance

P007 requires an ABSENT authorization_hash to yield mcps.authorization_hash_missing. RequestEnvelope.authorization_hash is a required String, so true absence is rejected during deserialization as CanonicalizationFailed (same mechanism as on_behalf_of above). check_authorization_hash only runs on a deserialized envelope where the field is present; it correctly maps empty/wrong-prefix to AuthorizationHashMissing but can never see a truly-absent field. The pipeline doc (lines 41-44, 287-289) claims 'an absent ... value all map to AuthorizationHashMissing', which is not what happens for a field that is structurally omitted from the JSON. Lower severity than P005 because fail-closed is preserved (still an error), but the emitted token is wrong for the absent case.

> *Evidence:* src/envelope.rs:50-52 `pub authorization_hash: String,`. src/pipeline.rs:290-294 checks is_empty()\|\|!starts_with('sha256:'). A JSON envelope omitting the key never reaches this function; it errors at extract_request_envelope -> deserialize_envelope -> CanonicalizationFailed.

### M-3 — Client sets no socket timeouts: a stalled/malicious proxy hangs the client indefinitely (handshake and response read)

- **Crate:** `mcps-transport` · **Location:** `src/lib.rs:235-265` · **Category:** resource-handling · **Lens:** general

round_trip opens a raw TcpStream and never calls set_read_timeout/set_write_timeout (nor a connect timeout). complete_io (handshake), the write_all calls, and read_to_end all block with no upper bound. In a zero-trust model the proxy may be compromised or impersonated up to the point of cert verification; a peer that completes TCP but stalls the TLS handshake, or that completes the handshake then trickles/never finishes the response, pins the calling thread forever. The symmetric server side (mcps-proxy) explicitly defends this exact slow-loris vector with ServerLimits.read_timeout/write_timeout defaulting to 30s (mcps-proxy/src/tls.rs:55-72, applied in apply_socket_timeouts). The client transport has no equivalent, so this is a one-sided hardening gap against the very peer it is verifying.

> *Evidence:* let tcp = TcpStream::connect(addr)?; let conn = ClientConnection::new(...); let mut stream = StreamOwned::new(conn, tcp); stream.conn.complete_io(&mut stream.sock).map_err(handshake_error)?;  // no tcp.set_read_timeout / set_write_timeout anywhere

### M-4 — Response read is unbounded (read_to_end): a verified-but-hostile or buggy proxy can OOM the client

- **Crate:** `mcps-transport` · **Location:** `src/lib.rs:257-265` · **Category:** resource-handling · **Lens:** general

The response is consumed with read_to_end into a growable Vec with no size cap. The proxy server caps both request Content-Length and actual bytes read via ServerLimits.max_body_bytes (mcps-proxy/src/tls.rs:381-391, with a comment 'Defend against a Content-Length that under-states a flood of body bytes'). The client applies no symmetric ceiling, so a proxy that passes cert verification (e.g. a legitimately-issued but compromised proxy, or one whose inner server floods output) can drive the client to allocate unbounded memory. For high-assurance client software this should mirror the server's bounded-read discipline.

> *Evidence:* let mut response = Vec::new(); match stream.read_to_end(&mut response) { Ok(_) => {} Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {} Err(e) => return Err(io_or_handshake(e)), }

### M-5 — round_trip reads response with unbounded read_to_end — hostile server can exhaust client memory (DoS)

- **Crate:** `mcps-transport` · **Location:** `mcps-transport/src/lib.rs:260` · **Category:** DoS · **Lens:** security

The response body is read with stream.read_to_end(&mut response) with no size cap. The threat model includes a hostile inner server / hostile proxy peer (the thing this client talks to). A malicious or compromised server that the handshake legitimately authenticates (or any server reached before a higher layer rejects it) can stream an effectively unbounded HTTP response, growing the Vec until the client process is OOM-killed. There is no Content-Length enforcement on the read path (Content-Length is only set on the outbound request) and no maximum-response ceiling. This is the symmetric client to the proxy's serve loop and is reused per ADR for the client bin and multi-process tests, so the exposure is in long-lived/repeated client usage.

> *Evidence:* let mut response = Vec::new(); // A peer that closes without close_notify surfaces as UnexpectedEof; match stream.read_to_end(&mut response) {     Ok(_) => {}     Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}     Err(e) => return Err(io_or_handshake(e)), }

### M-6 — No connect / handshake / read timeout — hostile or slowloris server can hang the client indefinitely

- **Crate:** `mcps-transport` · **Location:** `mcps-transport/src/lib.rs:235` · **Category:** DoS · **Lens:** security

TcpStream::connect(addr) is used with no connect timeout, and the resulting stream has no read or write timeout set (no set_read_timeout/set_write_timeout). complete_io for the handshake and the subsequent read_to_end will block forever if the peer accepts the TCP connection but never completes the handshake or never sends/closes the response (classic slowloris). A hostile server (in-scope per the review's hostile-inner/hostile-peer model) can therefore pin client threads/resources indefinitely. The proxy side bounds its work; this client side does not bound time.

> *Evidence:* let tcp = TcpStream::connect(addr)?;  // no connect_timeout, no set_read_timeout/set_write_timeout afterward ... stream.conn.complete_io(&mut stream.sock).map_err(handshake_error)?;  // can block forever

### M-7 — One-shot inner: blocking stdin write_all to a non-draining child can hang dispatch

- **Crate:** `mcps-proxy` · **Location:** `mcps-proxy/src/cli.rs:609-615` · **Category:** resource-handling · **Lens:** general

SubprocessInner::run writes the full request to child stdin via write_all (line 613) before wait_with_output. If the inner command does not drain stdin and the request exceeds the OS pipe buffer, write_all blocks indefinitely; the inner could simultaneously never close stdout. There is no timeout on the child pipes (the stderr drain is on a separate thread, but the main thread's stdin write and wait_with_output are unbounded). Same single-threaded-serve-loop DoS consequence as the persistent path, though smaller blast radius since each request is a fresh process.

> *Evidence:* .stdin.take()...write_all(request)?; let output = child.wait_with_output()?; — no timeout or nonblocking on the child pipes.

### M-8 — DurableReplayCache persist() does not fsync data file or directory — a crash can lose just-accepted nonces and reopen a replay window

- **Crate:** `mcps-proxy` · **Location:** `mcps-proxy/src/durable_replay.rs:124-142` · **Category:** replay · **Lens:** general

persist() writes the temp file with std::fs::write and renames it with std::fs::rename, but never fsyncs the temp file before rename nor fsyncs the containing directory after rename. std::fs::write+rename guarantees that a concurrent READER sees either the old or new complete file (the atomicity the docs rely on), but it does NOT guarantee crash durability: after check_and_insert returns Fresh and the proxy has already accepted/forwarded the request, a kernel panic or power loss before the page cache is flushed can lose the rename or the file contents, so on restart the nonce is absent and the same request replays successfully. The replay cache is the proxy's anti-replay security property and the type is named/documented 'durable'; the docs scope the claim to 'process restarts' and external rollback but do not disclose the missing fsync, overstating crash-consistency.

> *Evidence:* std::fs::write(&tmp, &bytes)?; std::fs::rename(&tmp, path) — no File::sync_all / sync_data / directory fsync.

### M-9 — Persistent inner stdout read has no timeout — a hostile/stalled inner hangs the single-threaded proxy (P179 "never hang" violated)

- **Crate:** `mcps-proxy` · **Location:** `mcps-proxy/src/persistent_inner.rs:303` · **Category:** fail-closed · **Lens:** security

write_line_read_matching loops up to MAX_SKIPPED_LINES (64) calling BufReader::read_line on the child's stdout pipe. The pipe has NO read timeout (unlike the TLS socket, which gets ServerLimits::read_timeout). The MAX_SKIPPED_LINES bound only caps the number of COMPLETE lines read; it does not bound a single line that never terminates with \n, nor an inner that accepts the request and then emits nothing. A hostile or wedged inner that withholds the newline blocks read_line forever while holding the session Mutex, permanently wedging the proxy. main.rs runs a blocking single-threaded serve_once loop, so one stuck inner stalls the entire proxy (no new connection is ever accepted). The module docstring explicitly promises 'fail closed, never panic / never hang' and the brief lists P179 (persistent inner must not hang); this path can hang.

> *Evidence:* const MAX_SKIPPED_LINES: usize = 64; for _in 0..=MAX_SKIPPED_LINES { ... self.stdout.read_line(&mut line).map_err(...)?; ... } — no per-read deadline; ChildStdout pipe is never given a timeout. Contrast tls.rs apply_socket_timeouts which sets read/write timeouts on the TCP socket.

### M-10 — RevocationSource bool-only API cannot express an indeterminate/unavailable verdict, making fail-closed an unenforced convention

- **Crate:** `mcps-policy` · **Location:** `mcps-policy/src/revocation.rs:13-19` · **Category:** fail-closed · **Lens:** security

The RevocationSource trait is `fn is_revoked(&self, revocation_id: &str) -> bool`. The doc comment (lines 13-15) MANDATES that implementations fail closed (return true when status is indeterminate / backend unavailable), but the bool return type cannot distinguish 'definitely not revoked' from 'could not determine'. This contrasts with mcps-core, which surfaces backend trouble through distinct error types (TrustResolverError / ReplayCacheError → trust_resolver_unavailable / replay_cache_unavailable) so the proxy can fail closed AND report the outage distinctly. Here, a concrete production source (e.g. a Redis/CRL feed) whose backend is down and which returns `false` on error — a very common implementation mistake — would fail OPEN: a revoked grant would be honored, with no type-level or compile-time guard preventing it, and no distinct mcps.authorization_revocation_unavailable token to surface the outage. The spec's fail-closed-on-outage requirement (P040/P118 spirit) is thus reduced to a documentation note for the one dependency that has no error channel.

> *Evidence:* revocation.rs:16-19 `pub trait RevocationSource { fn is_revoked(&self, revocation_id: &str) -> bool; }` with doc 'Implementations MUST fail closed: if revocation status cannot be determined (backend unavailable), return true'. No Result/error variant exists; PolicyError has no revocation_unavailable variant (error.rs:16-65).

### M-11 — Drift-guard conformance manifest silently omits 18 rust_test targets across 4 packages while its prose claims to cover EVERY //... target

- **Crate:** `mcps-conformance` · **Location:** `mcps-conformance/conformance_manifest.json:3` · **Category:** drift-guard / completeness · **Lens:** conformance

The conformance_manifest.json description states it is the 'Drift-guarded enumeration of ... every //... Bazel rust_test target' and 'The single source of truth for conformance counts'. The drift_guard_test BUILD comment repeats this ('every vector + every //... rust_test target'). But the manifest's bazel_test_targets array enumerates only 23 targets from 5 packages (mcps-conformance 7, mcps-core 2, mcps-host 2, mcps-policy 2, mcps-proxy 10). The mcps monorepo has 4 further packages with rust_test targets that are NEITHER listed NOR scanned: mcps-demo (12), mcps-demo-server (3), mcps-transport (2), mcps-demo-fileserver (1) = 18 unguarded targets. on_disk_test_targets() in drift_guard_test.rs only reads 5 BUILD env vars (CONFORMANCE/CORE/HOST/POLICY/PROXY), so the count assertion (23==23) passes vacuously for the omitted packages: a target could be added/removed/renamed in mcps-demo / mcps-transport / mcps-demo-server / mcps-demo-fileserver with the guard staying green. This directly violates P128 (manifest must be single source of truth for ALL target enumeration) and P194 (guard must be load-bearing) for those packages. Note the SECURITY traceability guard DOES scan all 8 of those packages (it has MCPS_BUILD_DEMO/DEMO_SERVER/TRANSPORT), so the omission is specific to the conformance drift guard and is an inconsistency, not a wiring impossibility.

> *Evidence:* conformance_manifest.json line 3: '...every //... Bazel rust_test target. The single source of truth for conformance counts.' / drift_guard_test.rs on_disk_test_targets() iterates only [("MCPS_BUILD_CONFORMANCE",..),("MCPS_BUILD_CORE",..),("MCPS_BUILD_HOST",..),("MCPS_BUILD_POLICY",..),("MCPS_BUILD_PROXY",..)] — no DEMO/DEMO_SERVER/TRANSPORT/FILESERVER. Shell confirms mcps-demo=12, mcps-demo-server=3, mcps-transport=2, mcps-demo-fileserver=1 nt_rust_test targets, none recorded.

### M-12 — Cross-transport parity test omits two of the six P182-mandated vectors (tampered_id and missing_envelope)

- **Crate:** `mcps-conformance` · **Location:** `mcps-conformance/tests/http_harness_test.rs:182` · **Category:** boundary / completeness · **Lens:** conformance

P182 requires that the committed core vectors 'tampered id/argument, replay, expiry, audience, missing envelope MUST produce identical actual==expected outcomes across object, stdio, and http harnesses'. The three parity loops (http_harness_test.rs:182, stdio_harness_test.rs:175, acceptance_test.rs:105) all iterate the SAME fixed array [V1, V2_TAMPERED, REPLAY, EXPIRED, WRONG_AUDIENCE]. tampered_id.json and missing_envelope_request.json are explicitly named by P182 but are NOT run cross-transport — they are only exercised in the in-process object_suite_test (object target only). So cross-transport parity is proven for argument-tamper/replay/expiry/audience but NOT for id-tamper or missing-envelope. The object suite covers all vectors but does not establish object==stdio==http for those two.

> *Evidence:* http_harness_test.rs:182 `for raw in [V1, V2_TAMPERED, REPLAY, EXPIRED, WRONG_AUDIENCE] {` — identical array in stdio_harness_test.rs:175 and acceptance_test.rs:105. Neither tampered_id.json nor missing_envelope_request.json is among the include_str! consts in those three test files (they only embed V1/V2_TAMPERED/REPLAY/EXPIRED/WRONG_AUDIENCE).

### M-13 — Conformance drift guard silently under-covers: 17 security test targets in mcps-demo/demo-server/transport are unguarded despite 'every rust_test target' claim

- **Crate:** `mcps-conformance` · **Location:** `mcps-conformance/conformance_manifest.json:58` · **Category:** test-assurance · **Lens:** security

The conformance_manifest.json description (line 3) and the drift_guard_test module doc both assert the manifest is the single source of truth for 'every //... Bazel rust_test target', and condition (4) (bazel_test_targets_match_build_files_exactly) asserts the recorded set EXACTLY matches what BUILD files declare. But on_disk_test_targets() only scans 5 packages (conformance/core/host/policy/proxy) via the 5 MCPS_BUILD_* env vars; mcps-demo (12 nt_rust_test), mcps-demo-server (3), and mcps-transport (2) are never scanned, and none of their 17 targets appear in the manifest. The guard's 'exactly match' therefore compares a self-consistent subset and passes, while the most security-critical end-to-end targets (demo_negative_e2e_test, demo_mtls_client_test, mtls_client_test, received_log_test, demo_posture_e2e_test) are NOT drift-protected. A future rename/deletion of e.g. mtls_client_test or demo_negative_e2e_test would NOT trip the conformance drift guard. The security_traceability_guard provides only partial, one-directional mitigation (manifest->build existence of specific test_fns it lists), not build->manifest completeness. This is exactly the false-assurance the single-source-of-truth/anti-gaming posture is meant to forbid: the assurance mechanism claims more coverage than it delivers.

> *Evidence:* conformance_manifest.json:3 'every //... Bazel rust_test target'; bazel_test_targets list (lines 58-82) contains NO //mcps-demo*, //mcps-transport entries. drift_guard_test.rs:100-106 scans only MCPS_BUILD_{CONFORMANCE,CORE,HOST,POLICY,PROXY}. Disk reality: mcps-demo BUILD has 12 nt_rust_test, mcps-demo-server 3, mcps-transport 2.

### M-14 — Persistent-evidence field names overclaim what they attest (proxy_process_started / mtls_verified / server_cert_verified)

- **Crate:** `mcps-demo` · **Location:** `mcps-demo/src/e2e_persistent_flow.rs:635-637` · **Category:** anti-gaming · **Lens:** general

PersistentE2eAssertions.proxy_process_started and .mtls_verified are both computed as `authorized_calls > 0` (lines 636-637), i.e. they merely restate that the flow returned >0 authorized calls — they are NOT independently sourced from the proxy spawn lifecycle or a TLS-handshake signal, despite the struct docstring (lines 516-520) claiming 'Every field is sourced from a signal INDEPENDENT of the bin's own printed OK'. Worse, server_cert_verified is aliased to response_hash_verified (line 627), which is a Ed25519 RESPONSE-SIGNATURE check against the server's signing key — it proves nothing about the TLS server CERTIFICATE, yet the field name and its doc comment (line 529 'Every authorized response was signed by the proxy's server signer') invite a reader/auditor to treat 'server_cert_verified' as TLS server-cert attestation. The genuinely independent oracles (inner_spawn_count from stderr, denied_reached_inner / *_received from the inner received-log, response_hash_verified from the direct pubkey check) are sound; the three weak fields dilute the evidence object and could mask a regression where the named property silently stops holding. The proxy DOES emit an independent `inner_spawned` signal already consumed at line 639, so proxy_process_started could be grounded in real evidence instead of a tautology.

> *Evidence:* proxy_process_started: authorized_calls > 0,             mtls_verified: authorized_calls > 0,             server_cert_verified,  // == response_hash_verified (line 627)

---

## 5. Low-Severity and Informational Findings

Presented compactly by crate. These are hardening opportunities and observations, not defects that block an assurance claim.

### 5.1 Low (36)

| # | Crate | Title | Location | Category |
|---|---|---|---|---|
| 1 | `mcps-core` | Unbounded recursion in serde-Value canonicalization path (from_serde_value) | `mcps-core/src/canonical.rs:109-146` | boundary |
| 2 | `mcps-core` | Unknown-field discrimination relies on matching the serde_json error message string prefix | `mcps-core/src/constraints.rs:140-154` | error-handling |
| 3 | `mcps-core` | json_rpc_error_object silent fallback emits wrong code and drops the mcps taxonomy (P044/P109) | `mcps-core/src/wire.rs:36-38` | fail-closed |
| 4 | `mcps-host` | Unchecked i64 addition for expires_at; request_lifetime_secs unvalidated (negative/zero accepted) | `mcps-host/src/session.rs:109` | boundary |
| 5 | `mcps-host` | Raw HostSigner is publicly exported and directly usable in a client flow, partially weakening P137 | `mcps-host/src/lib.rs:19` | idiom |
| 6 | `mcps-host` | Host signs caller-supplied _meta keys other than .request, allowing the sidecar verified-context key to be smuggled into the signed preimage | `mcps-host/src/signer.rs:94` | canonicalization / verified-context |
| 7 | `mcps-transport` | round_trip ignores the HTTP status line and Content-Length: any response framing is accepted as a 'body' | `src/lib.rs:312-320` | correctness |
| 8 | `mcps-transport` | server_name_host silently maps unknown ServerName variants to the literal "localhost" Host header | `src/lib.rs:279-288` | idiom |
| 9 | `mcps-transport` | extract_body silently returns the entire buffer when no CRLFCRLF header terminator is found | `mcps-transport/src/lib.rs:312` | boundary |
| 10 | `mcps-proxy` | Inner responses whose result is a non-object (array/scalar) are forwarded UNSIGNED | `mcps-proxy/src/proxy.rs:328-332` | crypto |
| 11 | `mcps-proxy` | Public SubprocessInner::new / with_log_sink panic on an empty inner_command slice | `mcps-proxy/src/cli.rs:535-545` | boundary |
| 12 | `mcps-proxy` | Persistent inner with a null/absent caller id returns the first non-empty line, enabling response cross-talk on degenerate ids | `mcps-proxy/src/persistent_inner.rs:286-325` | correctness |
| 13 | `mcps-policy` | Issuer-signature preimage is built via serde_json (no JCS-safe domain / duplicate-key detection), diverging from the hash-binding canonicalization | `mcps-policy/src/reference.rs:131` | crypto |
| 14 | `mcps-policy` | Artifact's internal `profile` field is never validated against REFERENCE_PROFILE_ID | `mcps-policy/src/reference.rs:66` | boundary |
| 15 | `mcps-policy` | Argument-constraint scope matching does not reject extra (unconstrained) request arguments | `mcps-policy/src/reference.rs:252` | boundary |
| 16 | `mcps-policy` | RevocationSource fail-closed contract is documented but unenforced and unverified by the only concrete impl | `mcps-policy/src/revocation.rs:13-19,41-45` | fail-closed |
| 17 | `mcps-policy` | Phase-5 authorization vectors are not re-run over stdio / Streamable HTTP harnesses | `mcps-policy/tests/vectors_test.rs:59-98` | boundary |
| 18 | `mcps-policy` | Direct ReferenceProfile::authorize bypasses the raw-bytes JCS/duplicate-key gate; only the evaluator's hash-binding step enforces it | `mcps-policy/src/reference.rs:131-138` | canonicalization |
| 19 | `mcps-policy` | Artifact's internal `profile` field is not cross-checked against the selecting authorization-block profile | `mcps-policy/src/reference.rs:66-77` | authorization |
| 20 | `mcps-conformance` | HTTP harness leaks the server thread and bound socket when a POST fails mid-loop | `mcps-conformance/src/http_target.rs:65` | resource-handling |
| 21 | `mcps-conformance` | read_http_body silently truncates the body when the peer closes before Content-Length is satisfied | `mcps-conformance/src/http.rs:33` | error-handling |
| 22 | `mcps-conformance` | Drift-guard BUILD-file parsers are fragile hand-rolled scanners (sound for the current corpus) | `mcps-conformance/tests/drift_guard_test.rs:116` | maintainability |
| 23 | `mcps-conformance` | Guard non-empty sanity checks use weak lower bounds that do not catch partial parser/wiring regressions | `mcps-conformance/tests/drift_guard_test.rs:301` | anti-gaming |
| 24 | `mcps-conformance` | Hand-rolled nt_rust_test BUILD scanner can misparse if 'name' is not the rule's first attribute | `mcps-conformance/tests/drift_guard_test.rs:116` | drift-guard / idiom |
| 25 | `mcps-conformance` | outcome_token trusts response error.message verbatim with no signature verification (self-reported negative outcome) | `mcps-conformance/src/stdio_target.rs:128` | test-assurance |
| 26 | `mcps-conformance` | BUILD-file target-name parser keys on substring 'name', will mis-extract if crate_name precedes name | `mcps-conformance/tests/drift_guard_test.rs:116` | test-assurance |
| 27 | `mcps-demo` | Cert/material generation panics via expect() in library src, contradicting the crate's documented 'never panic' contract | `mcps-demo/src/demo_fixtures.rs:107-147` | error-handling |
| 28 | `mcps-demo` | demo_e2e (one-shot) bin captures no proxy stderr / inner oracle, unlike its persistent sibling — weaker evidence for the same boundary claims | `mcps-demo/src/bin/demo_e2e.rs:225-227` | boundary |
| 29 | `mcps-demo` | Persistent-demo evidence: server_cert_verified is aliased to response_hash_verified, not an independent cert/handshake fact | `src/e2e_persistent_flow.rs:627` | anti-gaming |
| 30 | `mcps-demo` | mtls_verified / proxy_process_started derived from authorized_calls>0, not from a transport-layer signal | `src/e2e_persistent_flow.rs:636-637` | anti-gaming |
| 31 | `mcps-demo-server` | `initialize` flips the lifecycle gate before any request validation, so a malformed initialize still unlocks the server | `src/server.rs:178-181` | correctness |
| 32 | `mcps-demo-server` | CRLF-terminated lines leave a trailing \r in the JSON-RPC payload | `src/stdio.rs:38-43` | boundary |
| 33 | `mcps-demo-server` | Received-log write/flush failures are silently swallowed | `src/server.rs:112-121` | error-handling |
| 34 | `mcps-demo-server` | No JSON-RPC notification handling — notifications (no id) get a response with id:null, and notifications/initialized is treated as method-not-found | `mcps-demo-server/src/server.rs:136-192` | idiom |
| 35 | `mcps-demo-fileserver` | JSON-RPC notifications receive a response, violating JSON-RPC 2.0 (notifications/initialized handshake) | `mcps-demo-fileserver/src/server.rs:49` | boundary |
| 36 | `mcps-demo-fileserver` | Comment claims file_type() is used to avoid following symlinks, but code calls entry.metadata() which follows symlinks | `mcps-demo-fileserver/src/server.rs:175-181` | idiom |

### 5.2 Informational (53)

| # | Crate | Title | Location | Category |
|---|---|---|---|---|
| 1 | `mcps-core` | wire::json_rpc_error_object has no tests and emits a hardcoded null-id fallback that drops the request id | `mcps-core/src/wire.rs:20-39` | error-handling |
| 2 | `mcps-core` | Parser materializes entire input as Vec<char> (4x memory amplification) | `mcps-core/src/canonical.rs:256-261` | idiom |
| 3 | `mcps-core` | canonicalize_json_value cannot detect duplicate object keys (P088/P026 boundary) | `mcps-core/src/canonical.rs:91-104 + src/signing.rs:73-80` | crypto |
| 4 | `mcps-core` | reject_notification documentation overstates safety for non-object inputs | `mcps-core/src/constraints.rs:68-73` | idiom |
| 5 | `mcps-core` | Missing signature.alg/key_id maps to canonicalization_failed at step 4, not invalid_signature at step 7 | `src/constraints.rs:90-97,140-154; src/envelope.rs:23-33; src/pipeline.rs:168-173` | error-handling |
| 6 | `mcps-core` | OnBehalfOfMissing error variant is unreachable through the pipeline (absent on_behalf_of yields canonicalization_failed) | `src/pipeline.rs:301-306; src/error.rs:62-63; src/envelope.rs:46-47` | idiom |
| 7 | `mcps-host` | request_hash recomputed via serialize->parse->canonicalize round-trip instead of reusing the just-built request Value | `mcps-host/src/session.rs:127` | idiom |
| 8 | `mcps-host` | id_key collapses all unserializable JSON-RPC ids to the empty-string key | `mcps-host/src/session.rs:227` | error-handling |
| 9 | `mcps-host` | HostSigner performs no well-formedness validation of on_behalf_of / authorization_hash before signing | `mcps-host/src/signer.rs:82-92` | boundary |
| 10 | `mcps-host` | SystemClock reports negative seconds for a pre-epoch clock rather than failing | `mcps-host/src/clock.rs:32-42` | fail-closed |
| 11 | `mcps-transport` | from_pem maps PrivateKeyDer parse error through BadClientMaterial but client-cert PEM parse error closure double-wraps redundantly | `src/lib.rs:112-120` | error-handling |
| 12 | `mcps-transport` | io_or_handshake error classification relies on undocumented rustls io::Error wrapping and may misclassify post-handshake errors | `src/lib.rs:299-308` | error-handling |
| 13 | `mcps-transport` | Host header falls back to literal "localhost" for non-DNS/non-IP server names (silent, cosmetic) | `mcps-transport/src/lib.rs:286` | silent_fallback |
| 14 | `mcps-transport` | Client permits TLS 1.2 (safe defaults), not pinned to TLS 1.3 | `mcps-transport/src/lib.rs:178-179` | crypto |
| 15 | `mcps-transport` | UnexpectedEof tolerated when reading response (matches proxy framing) — verified not exploitable | `mcps-transport/src/lib.rs:260-265` | boundary |
| 16 | `mcps-transport` | Server-cert verification is genuinely real in the default build (no accept-any leakage) | `mcps-transport/src/lib.rs:162-182` | fail-closed |
| 17 | `mcps-transport` | Server-certificate verification is genuinely enforced with a real WebPkiServerVerifier (positive finding) | `mcps-transport/src/lib.rs:148` | crypto |
| 18 | `mcps-transport` | Fault-injection accept-any verifier is correctly gated and absent from the default build (positive finding) | `mcps-transport/src/lib.rs:328` | fail-closed |
| 19 | `mcps-proxy` | Threaded serve() is exported but unused and untested; incompatible with the RefCell-based Proxy | `mcps-proxy/src/tls.rs:288-313` | idiom |
| 20 | `mcps-proxy` | now_unix() silently coerces a pre-epoch clock to 0 | `mcps-proxy/src/main.rs:33-38` | error-handling |
| 21 | `mcps-proxy` | Over-long client certificate rejection is surfaced as mcps.transport_binding_failed (not a dedicated revocation/expiry token) | `mcps-proxy/src/tls.rs:223-242` | error-handling |
| 22 | `mcps-proxy` | build_signed_response passes inner error/non-object results through unsigned | `mcps-proxy/src/proxy.rs:328-332` | fail-closed |
| 23 | `mcps-proxy` | Synthesized-_meta branch in build_forwarded_request relies on serde_json IndexMut semantics that would panic on a non-object params | `mcps-proxy/src/proxy.rs:305-309` | boundary |
| 24 | `mcps-proxy` | EnvKeySource is gated behind an explicit dev/CI opt-in with a startup warning | `mcps-proxy/src/cli.rs:350-356; src/main.rs:69-78` | secret-handling |
| 25 | `mcps-policy` | Scope matching keys tool/resource solely on params.name; non-name-keyed methods collapse to empty-string tool | `mcps-policy/src/reference.rs:218` | correctness |
| 26 | `mcps-policy` | Unreachable error fallback in json_rpc_authorization_error emits the wrong JSON-RPC code (-32603 vs MCPS -32003) | `mcps-policy/src/wire.rs:33` | error-handling |
| 27 | `mcps-policy` | Signature verification uses the serde canonicalization path (no duplicate-key detection); safety depends entirely on the prior hash-binding gate | `mcps-policy/src/reference.rs:131-187` | crypto |
| 28 | `mcps-policy` | check_scope reads method/tool via unwrap_or(""), so a malformed request degrades silently to scope-denied rather than malformed | `mcps-policy/src/reference.rs:218-235` | error-handling |
| 29 | `mcps-conformance` | outcome_token trusts the unsigned JSON-RPC error.message field as the verdict token | `mcps-conformance/src/stdio_target.rs:128` | crypto |
| 30 | `mcps-conformance` | plain_echo_inner maps malformed/non-JSON input to Value::Null rather than surfacing an error | `mcps-conformance/src/fixtures.rs:81` | error-handling |
| 31 | `mcps-conformance` | Hardcoded duplicate of preimage-stable _meta identifier in now_unix_for_case | `mcps-conformance/src/target.rs:203` | idiom |
| 32 | `mcps-conformance` | Unbounded Content-Length read in conformance HTTP harness (test-scope DoS) | `mcps-conformance/src/http.rs:33` | dos |
| 33 | `mcps-demo` | Dead computation: request_hash result discarded in negative case 9 | `mcps-demo/src/bin/demo_negative.rs:445` | idiom |
| 34 | `mcps-demo` | mtls_client bin failure path prints a structured line then returns Err — duplicate/garbled reporting on stdout+stderr | `mcps-demo/src/bin/demo_mtls_client.rs:166-172` | error-handling |
| 35 | `mcps-demo` | now_unix() silently floors to 0 on a pre-epoch clock (silent fallback in grant/freshness window sizing) | `src/bin/demo_e2e.rs:65-70` | fail-closed |
| 36 | `mcps-demo` | demo_e2e.rs (one-shot positive bin) does not capture proxy stderr, so it asserts no inner-reach / machine evidence | `src/bin/demo_e2e.rs:225-227` | idiom |
| 37 | `mcps-demo` | Self-issued grant in the multi-process flow vs separate ISSUER in the in-process demos — intentional but undocumented divergence | `src/e2e_flow.rs:136-154` | idiom |
| 38 | `mcps-demo` | demo_e2e proxy is spawned with stdout=null, discarding the inner-launch/lifecycle diagnostic channel (positive bin only) | `src/bin/demo_e2e.rs:225-227` | fail-closed |
| 39 | `mcps-demo-server` | Field doc says "append-only" but the log is truncated on attach — minor doc/behavior wording mismatch | `src/server.rs:70-77` | idiom |
| 40 | `mcps-demo-server` | Request is JSON-parsed twice per line (handle_should_stop then handle) — minor redundancy | `src/stdio.rs:44-45` | idiom |
| 41 | `mcps-demo-server` | `echo` with bad arguments is recorded as a served call even though it returns isError:true | `src/server.rs:260-289` | correctness |
| 42 | `mcps-demo-server` | Received-log write failures are silently dropped, weakening the anti-gaming oracle under I/O pressure | `mcps-demo-server/src/server.rs:112-121` | fail-closed |
| 43 | `mcps-demo-server` | Each inbound line is JSON-parsed twice (handle_should_stop then handle) | `mcps-demo-server/src/stdio.rs:44-45` | idiom |
| 44 | `mcps-demo-server` | Received-log write/flush errors are silently swallowed (acceptable for instrumentation, but the anti-gaming signal could under-record on disk-full) | `src/server.rs:112-121` | fail-closed |
| 45 | `mcps-demo-server` | shutdown is processed before initialize and from any lifecycle state (intentional, low impact on a demo inner) | `src/server.rs:182-191` | boundary |
| 46 | `mcps-demo-fileserver` | Symlink-confinement check is skipped when the joined path does not canonicalize (defense-in-depth gap) | `mcps-demo-fileserver/src/server.rs:228` | crypto |
| 47 | `mcps-demo-fileserver` | canonicalize failure of the demo root is reported as ReadDir(".") regardless of the requested path | `mcps-demo-fileserver/src/server.rs:227` | error-handling |
| 48 | `mcps-demo-fileserver` | initialize silently ignores the client's requested protocolVersion | `mcps-demo-fileserver/src/server.rs:100` | idiom |
| 49 | `mcps-demo-fileserver` | main: unknown-argument handling rejects but argv parsing stops scanning value-position tokens correctly only for the single known flag | `mcps-demo-fileserver/src/main.rs:21` | idiom |
| 50 | `mcps-demo-fileserver` | Symlink-escape refusal is not exhaustive: a symlink whose target does not (yet) exist bypasses the canonical containment check | `mcps-demo-fileserver/src/server.rs:224-235` | boundary |
| 51 | `mcps-demo-fileserver` | TOCTOU between canonicalize() containment check and read_dir() | `mcps-demo-fileserver/src/server.rs:228-167` | boundary |
| 52 | `mcps-demo-fileserver` | No DoS bound on directory entry count / response size (unbounded read) | `mcps-demo-fileserver/src/server.rs:170-192` | dos |
| 53 | `mcps-demo-fileserver` | stdio line reader has no per-line length bound (unbounded input) | `mcps-demo-fileserver/src/stdio.rs:25-30` | dos |

---

## 6. Stub, Panic, and Fallback Ledger

Machine-grep found **11** `unwrap`/`expect`/`panic!` markers and **zero** `todo!`/`unimplemented!`/`unreachable!` in production `src` (see Appendix A). The finders triaged a wider set of 141 call-sites (incl. demo/test-adjacent), classifying each **safe** (startup-only, test-only, provably-unreachable, invariant-guarded) or **risky** (reachable in production with attacker-influenced input).

| Verdict | Count |
|---|---|
| Safe | 134 |
| **Risky** | **7** |

### 6.1 Risky markers (require remediation or explicit acceptance)

| # | Crate | Kind | Location | Description |
|---|---|---|---|---|
| 1 | `mcps-core` | partial_impl | `mcps-core/src/canonical.rs:298-389` | Recursive-descent parser (parse_value/parse_object/parse_array) has no recursion-depth guard. Reachable from the public canonicalize/parse with attacker-controlled bytes; deeply-nested input overflows the stack and aborts the process (reproduced via SIGABRT). The verify_request/verify_response pipeline is incidentally protected because serde_json::from_slice (128-depth limit) runs first, but the public primitive itself is unguarded. |
| 2 | `mcps-host` | silent_fallback | `mcps-host/src/clock.rs:39` | SystemClock pre-epoch branch returns negative seconds, which HostSession stamps into issued_at/expires_at via unix_to_rfc3339_utc producing a non-strict-RFC3339 (negative-year) timestamp that the host still signs. Reachable if the host RTC is set before 1970. Not a forgery vector (signature is honest), but the host emits a malformed signed envelope and relies entirely on the remote verifier to reject it. See low-severity finding; a host-side sanity floor would close it. |
| 3 | `mcps-transport` | silent_fallback | `mcps-transport/src/lib.rs:318` | extract_body uses .unwrap_or(0) when no CRLFCRLF terminator is found, returning the entire buffer as body instead of rejecting malformed framing. Reachable with a hostile server's malformed response. Downstream object-signature verification (host) would reject injected bytes, so not a direct bypass, but it is a lenient (non-fail-closed) transport-edge behavior. |
| 4 | `mcps-transport` | silent_fallback | `mcps-transport/src/lib.rs:260` | read_to_end ignores UnexpectedEof and uses whatever was read; combined with no size cap this is unbounded and accepts a truncated response without error. Reachable with a hostile/compromised server peer (memory DoS + silent truncation). |
| 5 | `mcps-proxy` | panic | `mcps-proxy/src/cli.rs:535` | SubprocessInner::with_log_sink/new index inner_command[0] without an emptiness guard. Production path is guarded by parse_args (cli.rs:357), but the pub constructors panic on an empty slice if called directly (inconsistent with the persistent variant's is_empty() check). See finding. |
| 6 | `mcps-proxy` | partial_impl | `mcps-proxy/src/persistent_inner.rs:303-324` | write_line_read_matching reads the inner stdout pipe with no per-read timeout; the MAX_SKIPPED_LINES bound caps complete lines only, not a never-terminated line or a silent inner. A hostile/wedged inner can block read_line indefinitely while holding the session Mutex, wedging the single-threaded blocking proxy. Contradicts the module's 'never hang' (P179) claim. |
| 7 | `mcps-demo-fileserver` | partial_impl | `mcps-demo-fileserver/src/server.rs:228-235` | Canonical containment check only executes when joined.canonicalize() succeeds (target exists); a non-existent leaf returns Ok(joined) with lexical-only validation. Attacker-influenced input reaches this path. Practical impact is limited (read_dir of a non-existent resolved path errors out rather than leaking a listing), and demo is non-production, but the invariant is asymmetric. See finding. |

> No `todo!`/`unimplemented!`/`unreachable!` exists in `src`. There are **no NotImplementedError-equivalent stubs**; the codebase implements what it claims. The risky items above are unguarded `unwrap`/silent-fallback paths, not missing features.

---

## 7. Spec Traceability

Full property → status rollup. Properties marked *partial* or *not-matched* are listed; *implemented* properties are summarized by count (see note in §2.3 on the not-matched artifact).

### 7.1 Partial properties (21) — implemented but incomplete

| ID | Lens | Sev-if-violated | Property | Evidence |
|---|---|---|---|---|
| P005 | conformance | high | on_behalf_of is REQUIRED-present in Core | mcps-core:partial |
| P007 | conformance | high | authorization_hash present and sha256-prefixed format | mcps-core:partial |
| P025 | conformance | high | JSON-RPC id typing — string preferred, integer only if safe | mcps-core:implemented; mcps-host:partial; mcps-proxy:not_applicable |
| P031 | security | high | Freshness window with symmetric clock skew | mcps-host:partial |
| P043 | conformance | high | Frozen error taxonomy tokens | mcps-core:partial; mcps-policy:not_applicable; mcps-demo:implemented |
| P044 | conformance | medium | JSON-RPC error object shape on the wire | mcps-core:partial; mcps-policy:implemented |
| P052 | conformance | medium | Vectors re-run transport-agnostically over stdio and Streamable HTTP | mcps-core:not_applicable; mcps-policy:partial; mcps-conformance:partial |
| P053 | conformance | high | Vector family coverage minimum | mcps-core:implemented; mcps-policy:partial; mcps-conformance:not_applicable |
| P074 | security | high | v1 revocation posture: enforce maximum client-cert lifetime; no online CRL/OCSP claim | mcps-proxy:implemented; mcps-demo:partial |
| P086 | conformance | critical | Transport-agnostic security envelope (stdio and Streamable HTTP) | mcps-host:implemented; mcps-transport:partial; mcps-proxy:implemented; mcps-demo:partial |
| P109 | conformance | medium | Standardized JSON-RPC error objects with mcps error taxonomy | mcps-core:partial; mcps-policy:implemented; mcps-demo-fileserver:not_applicable |
| P120 | security | high | KeySource favors sign-over-export; no public key-export API | mcps-host:partial |
| P124 | security | critical | Transport binding required: reject signer/peer mismatch and plaintext downgrade | mcps-proxy:partial |
| P126 | security | critical | Durable replay cache atomic check-and-insert; shared cache is true atomic primitive | mcps-proxy:partial |
| P128 | conformance | medium | Drift-guarded conformance manifest is single source of truth for counts/targets | mcps-policy:implemented; mcps-conformance:partial |
| P137 | conformance | high | HostSession signs every request (no raw HostSigner in client flow) | mcps-host:partial; mcps-proxy:not_applicable; mcps-conformance:not_applicable; mcps-demo:implemented |
| P155 | security | high | Authorization grant binds full tuple | mcps-policy:partial |
| P179 | security | high | Persistent inner fails closed on crash / malformed line / handshake failure | mcps-demo-server:partial; mcps-demo-fileserver:partial |
| P182 | conformance | high | Cross-transport / object parity of core conformance vectors | mcps-policy:partial; mcps-conformance:partial; mcps-demo:implemented |
| P187 | security | high | Anti-gaming: assert externally observable facts, never a printed OK | mcps-conformance:partial; mcps-demo:implemented; mcps-demo-server:implemented |
| P194 | conformance | high | Anti-gaming: guards are load-bearing (go red when control breaks) | mcps-transport:implemented; mcps-conformance:partial |

### 7.2 Properties not matched by automated rollup (67)

Listed for auditor completeness. These are catalog requirements whose coverage row did not exact-title-match; **none are confirmed unimplemented** (zero properties rolled up as *missing*). Most are Core crypto/envelope invariants whose enforcement is asserted in the §6 ledger and the security narrative in §9.

| ID | Lens | Sev | Property |
|---|---|---|---|
| P002 | security | high | Identifier strings are preimage-stable (part of signed _meta) |
| P011 | security | critical | Unknown envelope fields rejected (fail closed), including extensions |
| P012 | security | critical | Sign the complete JSON-RPC object |
| P013 | security | critical | Signing preimage construction (remove value, retain alg+key_id, JCS, no pre-hash) |
| P020 | security | critical | JCS domain validation precedes signature verification |
| P021 | security | critical | Duplicate object member names rejected |
| P022 | security | high | Valid UTF-8, no unpaired surrogates |
| P023 | security | high | Numbers restricted to safe integers |
| P024 | security | high | No Unicode normalization, no parser repair/coercion |
| P027 | conformance | high | Canonical integer serialization (shortest decimal, no leading zeros, no +, -0→0) |
| P030 | general | high | Canonicalization implemented in-house, not via external JCS crate |
| P033 | security | critical | Replay check invoked ONLY after signature verification succeeds |
| P034 | security | critical | Replay decision mapping to errors |
| P035 | security | high | Replay entry retention until expires_at + max_clock_skew |
| P036 | general | medium | InMemoryReplayCache reference impl is deterministic and prunes |
| P038 | security | high | TrustResolver trait signature, authoritative at verify time |
| P039 | security | high | Trust resolver error mapping |
| P041 | security | high | JSON-RPC batch forbidden |
| P042 | security | high | Security-relevant notification forbidden |
| P045 | security | critical | verify_request canonical step order (normative, fail-closed at first failure) |
| P046 | security | high | audience must equal expected verifier audience |
| P048 | security | critical | verify_response canonical step order |
| P056 | general | high | No unwrap/expect/panic in non-test library code |
| P058 | security | high | Verified-context _meta is sidecar→inner only and never signed |
| P062 | security | critical | Fail-closed message constraints: reject batches, security-relevant notifications, unknown envelope fields |
| P067 | security | high | Freshness window enforcement (issued_at/expires_at ± skew) |
| P077 | general | medium | Inner-server launch hygiene: explicit working directory, stdout/stderr separation, lifecycle logging, setrlimit |
| P084 | conformance | low | Two hardening boundaries are orthogonal and independent |
| P093 | security | critical | Signed responses required for all verified request/response methods |
| P095 | security | critical | Replay protection via nonce + freshness window, replay check after signature |
| P096 | security | high | Expired request rejection |
| P097 | security | high | Audience binding enforcement |
| P099 | security | critical | Tampered argument invalidates signature |
| P100 | security | high | Reject all JSON-RPC batch messages |
| P101 | security | high | Security-relevant notifications forbidden |
| P102 | security | high | Fail-closed on unknown envelope fields |
| P103 | security | critical | Fail-closed JCS-safe value domain: duplicate-key rejection |
| P104 | security | high | Fail-closed JCS-safe value domain: safe-integer-only / strings for big values |
| P105 | security | high | Fail-closed JCS-safe value domain: no Unicode normalization / no parser repair |
| P106 | security | critical | Twelve-step verification pipeline, fail-closed at first failing step, cheap checks before crypto |
| P111 | general | high | mcps-core has zero networking/async/filesystem/MCP-server dependencies |
| P112 | general | medium | Protocol extension name decoupled from crate name; controlled non-official namespace |
| P116 | security | critical | Verified context via headers only on loopback/Unix socket, overwritten by sidecar |
| P117 | security | critical | Sidecar fail-closed: unsigned/tampered/replayed never reach inner server |
| P118 | security | critical | Sidecar fails closed on trust resolver or replay cache outage |
| P121 | security | critical | Three separate proofs — mTLS peer vs object signer vs authorization, none substitutes |
| P125 | security | high | v1 revocation posture = max client-cert lifetime, NOT online revocation |
| P130 | general | medium | Build reproducible WITH network access, NOT offline-hermetic |
| P131 | security | high | Single sanctioned positive claim: production-hardened for single-node Rust-native deployments |
| P145 | security | critical | Proxy verifies the MCP-S Core envelope before any downstream action |
| P146 | security | high | Signed JSON-RPC id binding enforced |
| P147 | security | critical | Freshness window enforced (expired request rejected) |
| P148 | security | critical | Replay protection across connections (nonce cache) |
| P150 | security | high | Wrong-audience request rejected |
| P151 | security | high | Missing MCP-S request envelope rejected |
| P152 | security | critical | Caller-supplied .verified metadata is stripped (proxy is sole writer) |
| P153 | security | critical | Sidecar-owned verified context injected fresh per request |
| P167 | security | critical | Client without a client cert rejected at TLS handshake (T1) |
| P168 | security | critical | Client cert from untrusted CA rejected at TLS handshake (T2) |
| P171 | security | critical | Valid transport does NOT rescue an invalid request-object signature (layer separation) |
| P174 | security | high | Inner server launched with hardened launch policy |
| P181 | general | low | Denial logs are structured and include a reason code |
| P183 | general | high | ADR-MCPS-001/012 firewall: no dependency outside components/mcps |
| P184 | general | medium | mcps-host is transport-free (no networking/async/socket) |
| P185 | general | medium | mcps-transport carries bytes only (does no signing) |
| P195 | general | medium | No production code changed to make demos pass (additive-only evidence) |
| P197 | general | medium | Demos must not overclaim deferred Phase-7 properties |

---

## 8. Refuted Findings (verification gate evidence)

These 16 findings were raised by a finder but **rejected** by the adversarial skeptic panel (<2 of 3 confirmed). Recorded to demonstrate the gate discards false positives rather than rubber-stamping.

| Crate | Claimed sev | Title | Location |
|---|---|---|---|
| `mcps-core` | low | Signed preimage is canonicalized via serde_json::Value path, not the audited raw-bytes JCS canonicalizer; relies on cross-path equivalence | `src/signing.rs:73-80; src/canonical.rs:101-146` |
| `mcps-core` | info | verify_request re-canonicalizes the object three times per request (step3 raw + step11 preimage + final request_hash) | `src/pipeline.rs:165,194,216` |
| `mcps-host` | low | SystemClock pre-epoch fallback can emit a malformed RFC3339 issued_at/expires_at (negative year) rather than failing at the host | `mcps-host/src/clock.rs:39` |
| `mcps-transport` | info | server_name_host falls back to "localhost" for non-DNS/non-IP ServerName variants | `mcps-transport/src/lib.rs:286` |
| `mcps-transport` | info | Transport binding (mTLS peer == object signer) is NOT performed in this crate — confirm it is enforced at the proxy | `mcps-transport/src/lib.rs:230` |
| `mcps-proxy` | low | Inner-produced error responses are forwarded UNSIGNED (P093 deviation) | `mcps-proxy/src/proxy.rs:328` |
| `mcps-proxy` | low | Hostile inner can inject a forged .verified / response envelope inside result._meta that is relayed to the host | `mcps-proxy/src/proxy.rs:334` |
| `mcps-proxy` | info | Verified-context injected to inner omits an explicit policy-decision field | `mcps-proxy/src/proxy.rs:285` |
| `mcps-policy` | low | Argument scope is a subset-equality constraint; unconstrained request arguments are always permitted | `mcps-policy/src/reference.rs:240-255` |
| `mcps-demo` | low | DemoFixtures public API exposes raw 32-byte private signing-key seeds (signer_seed/server_seed) | `src/demo_fixtures.rs:264,270` |
| `mcps-demo` | low | demo_mtls_client deterministic mode uses a FIXED clock + hardcoded nonce seed, reachable via a runtime --deterministic flag | `src/bin/demo_mtls_client.rs:120-126,177-179,218` |
| `mcps-demo` | info | Inner-launch hardening relies entirely on mcps-proxy InnerLaunchConfig; demo only sets coarse rlimits and is honest about non-containment | `src/demo_proxy.rs:65-84` |
| `mcps-demo` | info | BUILD.bazel deps reference only in-workspace mcps-* crates and audited @crates_mcps — firewall intact | `BUILD.bazel:25-34,124-131,358-361` |
| `mcps-demo-server` | info | tools/call records receipt BEFORE executing, but a malformed-argument echo still records — record reflects dispatch, not successful execution | `src/server.rs:260-277` |
| `mcps-demo-fileserver` | low | Non-existent canonicalization target bypasses canonical containment (lexical-only fallback) | `mcps-demo-fileserver/src/server.rs:228-235` |
| `mcps-demo-fileserver` | info | read_dir follows symlinks for entry classification despite comment claiming otherwise | `mcps-demo-fileserver/src/server.rs:176-181` |

---

## 9. Per-Crate Assessment

### `mcps-core` — production-critical

The pure verification crate is the most security-critical unit and is, in its sanctioned pipeline, well-constructed: a frozen field set and error taxonomy, in-house JCS canonicalization pinned by committed vectors, Ed25519 over the complete object with no pre-hash, JCS-domain and duplicate-key rejection on raw wire bytes before any preimage is computed, replay-after-signature ordering, and resolver/replay-cache outages that fail closed and are reported distinctly from a deny verdict. The dominant concern is a DoS class: the hand-rolled recursive-descent parser (parse_value -> parse_object/parse_array) has no recursion-depth limit, and canonicalize/parse are public, crate-root-exported APIs intended for untrusted wire bytes. We confirmed by reading canonical.rs:298-308 that parse_value recurses with no depth counter; deeply-nested input stack-exhausts and aborts the process. Inside verify_request the prior serde_json::from_slice (default 128-depth) incidentally rejects such input first, so the integrated pipeline is bounded — but a high-assurance primitive must bound recursion itself rather than rely on a caller's incidental serde guard, and downstream crates may legitimately call the primitive directly. Secondary items are conformance-token deviations that remain fail-closed: an absent on_behalf_of (P005) or authorization_hash (P007) is rejected at deserialization as canonicalization_failed rather than the dedicated missing token, because both fields are required Strings; the OnBehalfOfMissing variant is consequently dead and the pipeline doc's claim that it is 'asserted reachable in the unit tests' is false (no such test exists). The wire.rs error-object fallback and the Vec<char> 4x memory amplification are informational. We treat P002/P011/P012/P013/P020-P024/P033/P034/P041/P042/P045 etc. as static-reasoning-only, not dynamically exercised by this review.

**Top risks:**

- Unbounded recursion in public canonicalize/parse — stack-exhaustion process abort (DoS) on deeply-nested untrusted JSON; reproduced as a class via SIGABRT; pipeline is only incidentally guarded by serde's 128-depth limit (canonical.rs:298-389)
- P005/P007 token deviation: absent on_behalf_of / authorization_hash yield canonicalization_failed, not the dedicated *_missing token; OnBehalfOfMissing is dead and the module doc falsely claims it is test-reachable
- Public signing-preimage and request_hash helpers can be invoked directly on attacker bytes without the raw-bytes duplicate-key gate that the pipeline runs first (info-level; no in-crate misuse exists today)

### `mcps-host` — production-critical

The transport-free signing/response-verification client meets its structural contract: no networking, no key accessor exposed to the model, nonce via injected RNG and timestamps via injected clock, response verified against the hash the session STORED at sign time, and rejection of wrong-binding, forged-signature, unknown-id and duplicate-id responses. The notable finding is that HostSigner::sign_request preserves every caller-supplied params._meta key and overwrites only the .request sub-key, so a hostile or buggy model can smuggle the sidecar verified-context key (.verified) — or any foreign se.syncom/mcps.* key — into the canonicalized, Ed25519-signed object. P058/P115 require .verified to be sidecar-to-inner only and never part of any signing preimage; here the host mints a signed message embedding a forged verified-context block. Blast radius is contained because the proxy is required to strip caller-supplied .verified before dispatch (P152), so this is a defense-in-depth / invariant violation rather than a full identity-spoof bypass — but the host should be the sole author of the _meta namespace it controls and the existing overwrite test only proves the .request key is replaced, not that sibling keys are rejected. Lower-severity items: request_lifetime_secs is unvalidated with an unchecked i64 add (born-expired or overflow foot-gun, not reachable with the production clock and default 300s), and the raw HostSigner is publicly re-exported and usable outside HostSession, partially weakening P137 (by design per ADR-MCPS-015, but no type-level constraint forces the session). The getrandom expect is a deliberate, correct fail-loud on CSPRNG unavailability.

**Top risks:**

- Host signs caller-supplied foreign _meta keys; a hostile model can inject the .verified sidecar key into the signed preimage, contained only by the proxy's mandatory strip (P152) — invariant violation, not a standalone bypass (signer.rs:94)
- Raw HostSigner is publicly exported and usable without HostSession, so freshness/nonce/correlation guarantees can be bypassed by a direct caller (P137 partial)
- Unvalidated request_lifetime_secs with unchecked i64 addition — negative/zero yields a born-expired request, large values risk overflow; not reachable on the production path

### `mcps-transport` — production-critical

The client-side mTLS transport gets the security-critical part right and we positively confirmed it: the default build uses a real WebPkiServerVerifier with the explicit RustCrypto ring provider (no process-global default), drives the handshake to completion BEFORE any request body is written, fails closed on an empty server CA, and the accept-any fault verifier is strictly behind #[cfg(feature = "fault_accept_any_server")], default-off, compiled only by a separate manual-tagged target — so default bazel test never builds the faulted path. Trusted/untrusted/wrong-SAN/expired cases all assert handshake rejection and an unreached server handler (P162-P166). The defects are all availability/robustness on the read path against an in-scope hostile-but-authenticated peer, and they are one-sided: the proxy server defends the symmetric slow-loris and flood vectors (read/write timeouts, max_body_bytes) but the client does not. round_trip opens a raw TcpStream with no connect/read/write timeout (a peer that completes TCP but stalls the handshake or trickles the response pins the calling thread forever) and reads the response with unbounded read_to_end (a flooding server drives the client to OOM). extract_body is also lenient: with no CRLFCRLF terminator it returns the whole buffer as 'body', and it ignores the HTTP status line and Content-Length, pushing error discrimination onto every caller — not a signature bypass (the host re-verifies the object signature over whatever bytes arrive), but non-fail-closed framing at the transport edge. TLS 1.2 is permitted (deliberate parity with the proxy, not a deviation).

**Top risks:**

- No connect/handshake/read/write timeout — a hostile or slow-loris server can pin client threads indefinitely; asymmetric with the proxy which bounds this (lib.rs:235)
- Unbounded read_to_end on the response — a verified-but-hostile or flooding server can exhaust client memory (no Content-Length ceiling on the read path) (lib.rs:257-265)
- Lenient framing: extract_body returns the entire buffer when no CRLFCRLF terminator is found and ignores HTTP status/Content-Length, surfacing header garbage as a body (lib.rs:312)

### `mcps-proxy` — production-critical

The server-side PEP/sidecar enforces the security model correctly in the reviewed paths: object-envelope verification before any downstream action, three independent proofs (mTLS peer vs object signer vs authorization) with none substituting for another, deny-before-dispatch, durable replay survival across restart, env-keysource gated behind an explicit opt-in with a startup warning and no secret leakage in errors, and the v1 short-cert-lifetime revocation posture (no forbidden online CRL/OCSP). The headline defect contradicts an explicit promise: the persistent-inner path performs blocking pipe I/O to the child with no timeout. We confirmed at persistent_inner.rs:286-324 that write_line_read_matching writes with blocking write_all and reads with read_line, and that the MAX_SKIPPED_LINES=64 bound caps only the number of COMPLETE lines — it does not bound a single never-terminated line nor an inner that accepts the request and then emits nothing. Because main.rs runs a single-threaded blocking serve loop and the TLS socket timeouts never apply to the inner pipe, a wedged-but-alive inner holds the session Mutex and permanently wedges the whole proxy, violating the module's documented 'fail closed, never hang' contract and P179; the one-shot path and the Drop shutdown frame share the same blocking exposure. Two more: DurableReplayCache.persist() uses write+rename without fsync of the file or directory, so a crash/power-loss after a Fresh verdict can lose a just-accepted nonce and reopen a replay window — the type is named 'durable' and the docs scope the claim to process restarts without disclosing the missing crash-consistency fsync. Lower: non-object inner results (JSON-RPC errors, arrays, scalars) are forwarded UNSIGNED (by design but the crate doc's blanket 'signs the inner result' overstates), SubprocessInner::new panics on an empty command slice (inconsistent with the persistent variant's guard), and the threaded serve() is exported but unused and incompatible with the RefCell-based Proxy.

**Top risks:**

- Persistent (and one-shot) inner pipe I/O has no timeout — a hostile/wedged-but-alive inner blocks read_line/write_all indefinitely and hangs the single-threaded proxy while holding the session Mutex; violates the documented 'never hang' contract and P179 (persistent_inner.rs:286-324)
- DurableReplayCache.persist() does not fsync the data file or directory — a crash after a Fresh verdict can lose the nonce and reopen a single-node replay window; 'durable' naming overstates crash-consistency (durable_replay.rs:124-142)
- Non-object inner results forwarded unsigned, so a caller cannot bind an inner error/array/scalar to its request_hash (documented but the crate doc overstates the response-signing guarantee) (proxy.rs:328-332)

### `mcps-policy` — production-critical

The Phase-5 reference authorization profile evaluates deny-before-dispatch, binds the authorization decision to the signed request, and through the sanctioned PolicyEvaluator path is safe: the evaluator computes expected_authorization_hash via the raw-bytes canonicalize() (which rejects duplicate keys and enforces the JCS-safe domain) BEFORE authorize() runs, so a duplicate-key or unsafe-number artifact is rejected as AuthorizationMalformed before signature verification. The structural weakness is that this safety is an ordering invariant, not a local property: ReferenceProfile::authorize is a public trait method whose doc tells callers they 'may assume artifact_bytes hashes to the verified authorization_hash', yet authorize() itself parses with serde_json (last-wins on duplicates) and rebuilds the preimage with canonicalize_json_value, which by design cannot detect duplicate members — so a future profile or refactor that calls authorize() without the raw-bytes hash gate in front would signature-verify an ambiguous artifact. The most consequential contract gap is the RevocationSource trait: it returns a bare bool, the doc mandates fail-closed-on-indeterminate, but the type cannot express 'could not determine', so a future networked source whose backend is down and returns false would fail OPEN with no type-level or test guard — and there is no distinct authorization_revocation_unavailable token, unlike core which surfaces resolver/replay outages distinctly. The only shipped impl is in-memory and always-available, so live risk is low within this firewalled release. Lower items: the artifact's own profile field is never cross-checked against REFERENCE_PROFILE_ID, argument-constraint matching does not reject extra unconstrained request arguments (no 'only these arguments' expressivity), scope keys solely on params.name (resource-URI methods collapse to empty-tool), and the Phase-5 vectors are replayed only in-process, not cross-transport.

**Top risks:**

- RevocationSource bool-only API cannot express an indeterminate verdict, so the mandated fail-closed-on-outage is an unenforceable documentation convention — a future Redis/CRL source returning false on error fails open with no guard (revocation.rs:13-19)
- Duplicate-key / JCS-domain safety for the authorization artifact lives only in the evaluator's hash-gate ordering, not in ReferenceProfile::authorize itself; a direct authorize() caller bypasses the raw-bytes gate (reference.rs:131-138)
- Argument-constraint scope matching permits extra unconstrained request arguments and never validates the artifact's own profile field against the selecting profile id (defense-in-depth gaps)

### `mcps-conformance` — non-production

The conformance harness and drift guards are the assurance backbone, and the most important finding here is meta: the assurance mechanism claims more coverage than it delivers. The conformance_manifest.json description and the drift_guard_test module doc both assert the manifest enumerates 'every //... rust_test target' and that condition (4) asserts an EXACT match to BUILD files — but on_disk_test_targets() scans only five packages (conformance/core/host/policy/proxy) via five env vars, while mcps-demo (12), mcps-demo-server (3), mcps-transport (2), and mcps-demo-fileserver (1) — 17-18 targets including the security-critical end-to-end demo_negative_e2e_test, demo_mtls_client_test, and mtls_client_test — are neither listed nor scanned. The 'exactly match' therefore compares a self-consistent subset and passes vacuously: a rename or deletion in those packages would not trip the conformance drift guard. This violates P128 (single source of truth) and P194 (load-bearing guard) for those packages; the separate security_traceability_guard does scan all eight packages, so the omission is a specific inconsistency, not a wiring impossibility. Second, cross-transport parity (P182) is incomplete: the three parity loops iterate the same five-vector array and omit tampered_id and missing_envelope, so object==stdio==http is unproven for two of the six P182-named vectors (they run only in the in-process object suite). Lower: the hand-rolled nt_rust_test BUILD scanner keys on the substring 'name' and would misparse if crate_name preceded name (correct for today's BUILD files only), the guard non-empty floors (>=10 / >=20) are too loose to catch a partial-scan regression, the harness HTTP body read is unbounded (test-scope only), and outcome_token trusts the unsigned error.message verbatim for negative cases (acceptable under P093 since the success path re-verifies, but negative outcomes are self-reported rather than proven at the inner). The positive conformance vectors, fixed-keypair reproducibility, and the received-log oracle are sound.

**Top risks:**

- Drift-guard under-coverage: the manifest/guard claim 'every mcps rust_test target' but silently omit 17-18 targets across 4 packages (including security-critical e2e/mTLS tests), so the exact-match assertion passes vacuously — false assurance against P128/P194 (conformance_manifest.json:3 + drift_guard_test.rs)
- Cross-transport parity (P182) omits tampered_id and missing_envelope — object==stdio==http is unproven for two of the six mandated vectors (http_harness_test.rs:182 et al.)
- Hand-rolled BUILD-file name scanner and loose non-empty floors weaken a guard that is itself the single source of truth (drift_guard_test.rs:116, :301)

### `mcps-demo` — non-production

Non-production demo harness and multi-process e2e bins; the security boundary is the proxy, not these binaries. The genuinely independent anti-gaming oracles are sound — inner_spawn_count from proxy stderr, denied/authorized reachability from the inner received-log, and response_hash_verified from a direct Ed25519 pubkey check — and independently_verify_response fails closed on any malformed/forged input. The concern is evidence honesty: the PersistentE2eAssertions struct docstring claims every field is sourced from a signal independent of the bin's printed OK, but proxy_process_started and mtls_verified are both computed as authorized_calls > 0 (a restatement of the call outcome, not an independent transport signal), and server_cert_verified is aliased to response_hash_verified — an application-layer Ed25519 RESPONSE-signature check that proves nothing about the TLS server CERTIFICATE, despite a field name and doc that invite an auditor to read it as cert/handshake attestation. The real handshake verification does occur in mcps-transport, so the facts are not false, but three nominally-distinct booleans collapse to one underlying signal and dilute the evidence object; notably the proxy already emits an independent inner_spawned signal that proxy_process_started could be grounded in. Lower: demo_fixtures cert generation uses expect() at runtime (panics rather than the bins' clean fail-closed path on an rcgen failure — demo-only, deterministic inputs), the one-shot demo_e2e bin captures no proxy stderr/inner oracle (weaker than its persistent sibling), and demo_negative case 9 discards a computed request_hash as misleading dead code. No production code is changed to make demos pass.

**Top risks:**

- Evidence overclaim: proxy_process_started / mtls_verified are tautologies (authorized_calls>0) and server_cert_verified is an application-layer Ed25519 signature proxy, not an independent TLS-cert/handshake oracle, despite a struct doc claiming full independence (e2e_persistent_flow.rs:627-637)
- Cert/material generation panics via expect() in library src at runtime, contradicting the crate's documented 'never panic / fail closed with a typed error' contract (demo_fixtures.rs:107-147)
- One-shot demo_e2e bin captures no independent inner-reach oracle, an asymmetry with the hardened persistent demo (demo_e2e.rs:225-227)

### `mcps-demo-server` — non-production

Non-production, deliberately MCP-S-unaware long-lived demo MCP server fronted by the proxy. It holds no keys and is never fed unverified envelopes (the proxy strips and verifies first), so the items are correctness/spec-fidelity notes rather than security defects. The lifecycle gate flips initialized=true on any method=="initialize" before validating params or distinguishing request from notification, so a malformed initialize still unlocks the server. JSON-RPC notifications are not handled — a no-id message (e.g. the standard notifications/initialized) is routed like a request and produces a MethodNotFound response with id:null, which a spec-correct server must not emit; grep finds zero senders in the workspace, so the integrated flow never exercises it. CRLF-framed lines leave a trailing \r that serde tolerates rather than the documented strict-newline invariant being enforced. The received-log oracle (load-bearing for anti-gaming deny-not-reached assertions) swallows write/flush errors via let _=; this can only UNDER-record (the safe direction for a denial proof — over-recording would be the dangerous one and cannot happen), but a disk-full truncation is undetectable, so surfacing the error to stderr is advisable. Each inbound line is parsed twice (handle_should_stop then handle), a minor inefficiency.

**Top risks:**

- Lifecycle gate unlocks on any method==initialize before validating params or request/notification shape (server.rs:178-181) — demo-scope correctness gap
- No JSON-RPC notification handling — notifications get an id:null response, violating JSON-RPC 2.0; not reached by the integrated flow (server.rs:136-192)
- Received-log write/flush errors silently swallowed; the anti-gaming oracle can under-record on disk-full without surfacing the failure (server.rs:112-121)

### `mcps-demo-fileserver` — non-production

Non-production one-shot demo MCP fileserver; per ADR the proxy is the trust boundary and the inner is explicitly non-hardened (launch hygiene only, not containment). Read confinement to the demo root is enforced through a lexical layer (rejecting .. and absolute components) plus a canonical-containment check, and P177 path-escape refusal holds in the committed fixture. The defense-in-depth caveat is that resolve_within_root only enforces canonical containment when joined.canonicalize() succeeds; for a non-existent or dangling-symlink target it returns the uncanonicalized path and defers to read_dir, so the second layer is conditional on existence rather than unconditional — safe for this read-only directory-listing server (read_dir of a missing/broken target yields a benign NotFound, not an out-of-root listing) but a trap if the pattern were copied to a server that opens files. A documentation defect compounds this: the comment claims file_type() is used to avoid following symlinks, but the code calls entry.metadata(), which follows symlinks (file_type() is never called) — so entries are classified by their target, and the comment must not be trusted. There is also a classic canonicalize-then-read_dir TOCTOU window and no DoS bound on entry count, response size, or per-line input length — all info-level for a single-call non-production demo with no concurrent attacker on the demo_root filesystem. JSON-RPC notifications again receive a spurious id:null response.

**Top risks:**

- Symlink-confinement is conditional: containment is checked only when canonicalize() succeeds; a dangling/non-existent target bypasses the canonical check and defers to read_dir — safe for read-only listing here, dangerous if copied to a file-opening server (server.rs:224-235)
- Comment claims file_type() avoids following symlinks but code uses entry.metadata() which follows them; factually wrong comment that must not be trusted (server.rs:175-181)
- No DoS bound on directory entry count, response size, or per-line stdin input; TOCTOU window between canonicalize() and read_dir (info-level, non-production) (server.rs:170-192, 228)

---

## 10. What Was NOT Reviewed (residual-risk ledger)

Honest disclosure of audit boundaries. Each item is residual risk an auditor must weigh or commission separately.

- **L-1.** Dependency / supply-chain CVE audit: no cargo-audit/RUSTSEC scan, no review of transitive crate versions, advisories, or yanked-crate exposure for rustls, ring, ed25519-dalek, serde_json, getrandom, rcgen, or their dependency trees
- **L-2.** Formal or cryptographic correctness proofs: no proof of the Ed25519 / SHA-256 / JCS canonicalization implementations' cryptographic soundness; correctness is assumed from the audited RustCrypto/ring ecosystem and the committed conformance vectors, not independently proven
- **L-3.** Fuzzing / property-based testing: the unbounded-recursion DoS was reasoned and spot-confirmed by static read, not driven by a fuzzer; no coverage-guided fuzzing of the JCS parser, envelope deserialization, or HTTP framing was performed
- **L-4.** Dynamic execution and runtime verification: this was a static source/test review; bazel test //... was not executed, no targets were run, and no findings (including the DoS reproductions described in the source findings) were re-triggered live in this pass
- **L-5.** Runtime / deployment configuration: TLS cipher-suite policy in production, certificate issuance and lifetime-ceiling provisioning, key custody (file permissions, env-keysource operational use), setrlimit values, and OS-level inner-process sandboxing as actually deployed
- **L-6.** Concurrency / multi-node behavior under load: the single-node replay-cache ceiling is taken at its documented word; no stress, race, or multi-process contention testing of the durable replay cache or proxy serve loop was done
- **L-7.** Phase-7 and other deferred surfaces: capabilities explicitly deferred (online revocation/CRL-OCSP, multi-node replay, kernel/filesystem/network containment of the inner, P6.6 multi-process mTLS, Phase-7) were verified as NOT-claimed/NOT-implemented but their future designs were not assessed
- **L-8.** Side-channel and timing analysis: no constant-time / timing-side-channel review of signature verification, hash comparison, or nonce handling
- **L-9.** The non-production demo crates (mcps-demo, mcps-demo-server, mcps-demo-fileserver) were reviewed only for evidence honesty and spec fidelity, not as hardened production surfaces, consistent with their stated non-production status

---

## 11. Completeness Critic — gaps in this audit

An independent critic agent examined the audit's own coverage and identified the following gaps for a military-standard assurance claim:

### G-1 — No fuzzing or property-based testing of the in-house JCS canonicalizer / JSON parser (mcps-core/src/canonical.rs). The entire signature scheme rests on a byte-identical preimage produced by a hand-written recursive-descent parser (Parser in canonical.rs) and serializer, yet every test is a hand-picked golden vector (jcs_01..08 plus ~20 goldens). There is no proptest/quickcheck/cargo-fuzz/arbitrary anywhere in the workspace (confirmed by grep across all *.rs/*.toml).

- **Why it matters:** For a military-standard claim the canonicalizer is the crown jewel: any input where the raw-bytes parse path and the serde_json::Value path disagree, or where canonicalize() is non-idempotent or accepts a value it should reject, is a potential signature-forgery / preimage-confusion vector. Hand-picked vectors cannot cover the input space; the two parallel parse paths (parse() over raw bytes vs from_serde_value() over serde_json::Value, documented as intentionally divergent on duplicate keys) are exactly the kind of dual-implementation that differential fuzzing exists to break.
- **Suggested follow-up:** Add a cargo-fuzz / proptest target that (a) asserts canonicalize(canonicalize(x)) == canonicalize(x) (idempotence) for arbitrary bytes, (b) differentially compares the raw-bytes parse path against the serde_json::Value path and asserts they agree on every input both accept, and (c) round-trips signer.sign over canonicalize output and asserts no two semantically-distinct inputs share a preimage. Run it in CI with a fixed corpus + time budget.

### G-2 — The recursive JCS parser (canonical.rs Parser::parse_value/parse_object/parse_array) has NO nesting-depth bound, and the full pipeline parses untrusted wire bytes through both this parser and serde_json before any auth check. grep for depth/recursion/MAX_DEPTH/stack in canonical.rs returns nothing.

- **Why it matters:** A deeply-nested JSON document ([[[[...]]]] tens of thousands deep) drives unbounded recursion and can abort the verifier process via stack overflow BEFORE signature/replay checks run. That is a pre-authentication, remote denial-of-service against the proxy (which feeds raw client bytes straight into verify_request). The proxy bounds header/body BYTES (ServerLimits) but byte-size does not bound nesting depth, and an aborting stack overflow is not a fail-closed rejection — it is a crash.
- **Suggested follow-up:** Add an explicit recursion/nesting-depth limit to the in-house parser (and confirm serde_json's recursion_limit is engaged on the verify_request serde path) with a CanonicalizationFailed mapping, plus a regression test feeding a pathologically nested document and asserting a clean error rather than a crash.

### G-3 — No constant-time / side-channel discipline and no key-zeroization for secret material. grep shows zero use of zeroize or subtle anywhere. The Ed25519 SigningKey seed is read from a Base64URL string (key_source.rs signing_key_from_seed_b64url) into a [u8;32] and from env via EnvKeySource (std::env::var) / files, with no Drop/zeroize; HostSigner holds the key with no scrubbing. The audience/expected_audience and request_hash equality checks use plain != / String comparison.

- **Why it matters:** For a high-assurance security product, secret seeds lingering in freed heap/stack and in process environment (EnvKeySource pulls the seed through std::env::var, which is world-readable via /proc and inherited by children — note the inner-launch code env_clears the CHILD but the proxy's own env still holds the seed) are real exfiltration surfaces. The replay/audience/hash comparisons being non-constant-time is lower-severity (ed25519-dalek's verify_strict is already CT) but the secret-at-rest-in-memory and secret-in-env posture is not asserted anywhere.
- **Suggested follow-up:** Wrap the 32-byte seed and any decoded secret in a zeroize::Zeroizing / implement Drop that scrubs, audit that no secret transits std::env in production (prefer file/STDIN/secret-manager over EnvKeySource, or document EnvKeySource as dev-only), and add a test asserting the seed buffer is zeroed on drop. Document the constant-time posture of equality checks explicitly.

### G-4 — No automated supply-chain / dependency-vulnerability gate (cargo-audit, cargo-deny) in the firewalled crate. The module vendors security-critical crates (ed25519-dalek, rustls+ring, x509-parser, libc, getrandom) and the workspace explicitly notes 'build reproducible WITH network access, NOT offline-hermetic', but there is no deny.toml/audit.toml and no CI advisory check found.

- **Why it matters:** A zero-trust security product that pins a crate with a later-disclosed RUSTSEC advisory (e.g. a past x509-parser DoS, a ring/rustls issue) has no mechanism to detect it. For a military-standard claim, the absence of a license/advisory/yanked-crate gate over the exact dependency set is a process gap, especially since the crate is destined for standalone public extraction.
- **Suggested follow-up:** Add cargo-deny (advisories + bans + licenses) and/or cargo-audit as a Bazel-runnable check over Cargo.lock, wired into the module's test/CI flow, and pin the RustCrypto/rustls versions with an explicit allow/deny policy.

### G-5 — x509-parser certificate-parsing robustness in tls.rs is not adversarially tested. extract_identity / leaf_cert_lifetime_secs / cert_lifetime_rejection parse attacker-influenced leaf-certificate DER (URI SAN, DNS SAN, CN, validity) AFTER rustls accepts the chain, but tests exercise only well-formed rdcsl-minted certs. There is no test for a cert that passes WebPkiClientVerifier yet carries a malformed/multi-valued/UTF-8-tricky SAN, a missing validity, or a not_after < not_before (which would make leaf_cert_lifetime_secs return a negative span that silently satisfies 'lifetime <= max').

- **Why it matters:** The identity extracted here is bound to the request signer (transport binding, MCPS-026), so a parsing quirk — e.g. picking the wrong SAN among several, accepting an embedded-NUL or homoglyph URI, or a negative-lifetime cert sliding under the max-lifetime check — directly undermines the 'three separate proofs' separation and the v1 revocation posture. negative not_after-not_before is a concrete logic bug worth a targeted test.
- **Suggested follow-up:** Add tests minting client certs with: (a) multiple URI SANs, (b) URI SAN containing NUL/control/unicode, (c) not_after < not_before, (d) no validity / no SAN under each IdentityPolicy. Assert deterministic identity selection and that a negative or unparseable lifetime is rejected (fail closed), not admitted.

### G-6 — The mtls handshake-rejection negative tests (untrusted-CA / no-client-cert / wrong-identity / expired server cert) are validated only against the broken-control fault-injection feature in the transport crate, not for a corresponding compromised-CONTROL fault on the PROXY's server side. The transport crate has fault_accept_any_server proving the client-side server-auth tests are load-bearing, but I found no symmetric 'accept-any-client' fault feature on the proxy's WebPkiClientVerifier to prove the proxy's T1/T2 client-cert-rejection tests are themselves load-bearing.

- **Why it matters:** The whole point of the fault-injection technique (MCPS-071) is to prove a security control's tests would fail if the control were neutered. The client-side has it; the server-side client-cert verification (the proxy rejecting unauthenticated/untrusted clients — arguably the more important boundary, since the proxy guards the inner server) does not, so 'T1/T2 reject at handshake' rests on tests of unproven load-bearingness.
- **Suggested follow-up:** Add a symmetric, default-off fault feature on the proxy that swaps WebPkiClientVerifier for an accept-any client verifier, and run the existing T1/T2 proxy tests under it in the periodic fault harness to prove they flip to failing when the control is broken.

### G-7 — No test/assertion that the proxy never emits secret-bearing diagnostics, and the bounded-stderr capture is explicitly NOT secrets-redacted. InnerLogEvent / StderrLogSink write inner stderr via String::from_utf8_lossy(captured) and event Debug to the proxy's stderr; the code comments concede 'an inner server may write a secret to its own stderr'. Denial logs include reason codes (covered) but there is no negative test that a denial/log path never includes the signing seed, authorization artifact bytes, or full request payload.

- **Why it matters:** For a military-standard claim, log-channel exfiltration is a recognized attack class. The audit asserts 'denial logs are structured and include a reason code' (positive) but nothing asserts the complementary negative — that no log line in any error path carries secret material. The resolve_allowlist error is carefully proven to name only the variable not its value (good, in inner_launch tests), but that discipline is not verified for the proxy's request/response error and stderr-capture paths.
- **Suggested follow-up:** Add tests that drive a request carrying a known-sentinel secret (seed, authorization artifact, argument value) through every proxy error/denial/log path and assert the sentinel never appears in captured proxy stderr or in the JSON-RPC error object returned to the caller.

---

## 12. Auditor Statement

Scope: a static security and conformance review of the firewalled components/mcps Rust workspace (nine crates: mcps-core, mcps-host, mcps-transport, mcps-proxy, mcps-policy, mcps-conformance, and three non-production demo crates), held to a high-assurance / zero-trust standard for the MCP-S security extension. Method: manual source and test reading across the crate set, combined with adversarial verification — the security and critical findings were subjected to a three-skeptic adversarial panel, and the structured findings, property-traceability rollup, and stub/panic ledger underlying this narrative were machine-validated; the reviewer additionally spot-confirmed the two highest-severity availability findings against source (the unbounded JCS parser recursion at canonical.rs:298-308 and the timeout-free, count-bounded-only persistent-inner pipe loop at persistent_inner.rs:286-324). What was verified: that the integrated verification pipeline fails closed and admits no unauthorized request through any reviewed path; that server-certificate verification is real and enforced in the default build with the fault verifier gated off by default; that deny-before-dispatch, replay-after-signature ordering, response-to-request hash binding, and the three independent identity proofs hold as specified; and that the audited findings are fail-closed deviations (wrong taxonomy tokens, DoS/availability gaps, defense-in-depth and assurance-coverage weaknesses) rather than admission or signature bypasses — no critical bypass survived verification. Residual risk: this review did not include dependency/supply-chain CVE scanning, fuzzing, formal cryptographic proofs, dynamic execution (no tests were run), timing/side-channel analysis, deployment-configuration review, or multi-node/concurrency stress; the unbounded-recursion and pipe-hang DoS classes are real availability exposures against in-scope hostile peers and should be remediated before any single-node deployment is relied upon for availability, and the conformance drift-guard under-coverage should be corrected so the assurance mechanism's coverage claim matches its actual enumeration. Within the stated scope and assumptions, the workspace's core security posture is sound and the residual risk is assessed as moderate, driven by denial-of-service hardening gaps and assurance-coverage inconsistencies rather than by any confidentiality- or integrity-admission defect.

---

## Appendix A — Machine-truth signals (independently reproducible)

Captured by grep over `*/src/*.rs` (excluding tests) on the audited revision:

```
Stub markers todo!/unimplemented!/unreachable! in src : 0
unwrap()/expect()/panic! markers in src              : 11
  by crate: mcps-core 7, mcps-proxy 2, mcps-demo-server 1, mcps-demo-fileserver 1
Risk-keyword feature gates                           : 1
  mcps-transport `fault_accept_any_server` (OFF by default — intentional fault-injection control)
```

## Appendix B — Audit engine provenance

```
Workflow run id : wf_0d84f4bb-ca0
Agents spawned  : 165
Subagent tokens : 8,238,187
Tool uses       : 1,660
Wall-clock      : ~33 min
Phases          : Map(4) -> Review(27 finders) -> Verify(skeptic panels) -> Synthesize -> Critique
Normative props : 197
Findings raised : 122 (kept 106, refuted 16)
```

*End of report.*
