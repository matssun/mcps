//! MCPS-033 — `HostSession` end-to-end happy path.
//!
//! A stateful session layered on the UNCHANGED [`HostSigner`]: it owns nonce
//! generation (injected RNG), `issued_at`/`expires_at` (injected Clock +
//! configured lifetime), and `request_hash` correlation by JSON-RPC id. A signed
//! server response is verified against the STORED request hash — never a
//! caller-supplied expected hash.
//!
//! These tests pin DETERMINISTIC behaviour under a fixed clock + seeded RNG.

use mcps_core::request_hash;
use mcps_core::response_signing_preimage;
use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_host::FixedClock;
use mcps_host::HostSession;
use mcps_host::HostSigner;
use mcps_host::SeededNonceSource;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const SKEW: i64 = 300;

// Fixed clock: 2026-05-28T20:00:00Z (see mcps-core time tests).
const NOW_UNIX: i64 = 1_779_998_400;
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
// Default lifetime is the conservative 5-minute window (300s) -> 20:05:00Z.
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

fn host_signer() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// A session at the fixed clock, with a seeded (deterministic) nonce source and
/// the default request lifetime.
fn session() -> HostSession<FixedClock, SeededNonceSource> {
    HostSession::with_defaults(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
}

fn inbound_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    resolver
}

fn server_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    resolver
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

/// Build a server-signed response bound to `request_hash` (server side; the host
/// only VERIFIES this).
fn signed_response(id: &Value, bound_hash: &str) -> Vec<u8> {
    let mut response = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "result": {
            "content": [ { "type": "text", "text": "hello" } ],
            "_meta": {
                RESPONSE_META_KEY: {
                    "request_hash": bound_hash,
                    "server_signer": SERVER,
                    "issued_at": ISSUED_AT,
                    "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID }
                }
            }
        }
    });
    let preimage = response_signing_preimage(&response).expect("response preimage");
    let signature = server_key().sign(&preimage);
    response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
        Value::String(signature);
    serde_json::to_vec(&response).expect("serialize response")
}

// ---------------------------------------------------------------------------

#[test]
fn sign_request_uses_injected_clock_and_rng() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let bytes = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");

    let value: Value = serde_json::from_slice(&bytes).expect("parse signed request");
    let envelope = &value["params"]["_meta"]["se.syncom/mcps.request"];

    // issued_at/expires_at come from the injected clock + default lifetime.
    assert_eq!(envelope["issued_at"], json!(ISSUED_AT));
    assert_eq!(envelope["expires_at"], json!(EXPIRES_AT));

    // The nonce is the deterministic Base64URL-no-pad encoding of the seeded
    // RNG's 16-byte output. With seed [0xAB; 32] the first 16 bytes are all
    // 0xAB -> base64url("\xAB" * 16) (no padding).
    let nonce = envelope["nonce"].as_str().expect("nonce string");
    assert_eq!(nonce, mcps_core::b64url_encode(&[0xABu8; 16]));
    // >= 128 bits of entropy and Base64URL-safe (no +, /, =).
    assert!(!nonce.contains('+') && !nonce.contains('/') && !nonce.contains('='));
}

#[test]
fn signed_request_is_accepted_by_the_verifier() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let bytes = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");

    let mut replay = InMemoryReplayCache::new(SKEW);
    let verified = verify_request(&bytes, &inbound_resolver(), &mut replay, &config(), NOW_UNIX + 60)
        .expect("verifier accepts the session-signed request");
    assert_eq!(verified.verified_signer, SIGNER);
    assert_eq!(verified.on_behalf_of, ON_BEHALF_OF);
    assert_eq!(verified.audience, AUDIENCE);
    assert_eq!(verified.authorization_hash, AUTH_HASH);
}

#[test]
fn session_is_deterministic_for_same_providers() {
    let id = Value::String("req-1".to_string());
    let a = session()
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("a");
    let b = session()
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("b");
    assert_eq!(a, b, "same clock + same seeded RNG => identical wire bytes");
}

#[test]
fn stored_request_hash_matches_cores_request_hash() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let bytes = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");

    let value: Value = serde_json::from_slice(&bytes).expect("parse");
    let core_hash = request_hash(&value).expect("core request_hash");

    // The session stored exactly Core's request_hash, keyed by JSON-RPC id.
    assert_eq!(session.stored_request_hash(&id), Some(core_hash.as_str()));
}

#[test]
fn verify_response_uses_stored_hash_not_a_caller_value() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let request = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");
    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let expected_hash = request_hash(&request_value).expect("request_hash");

    // A response correctly bound to the stored request hash verifies. Note the
    // session API takes NO caller-supplied expected hash — it uses the one it
    // stored when signing the request with this id.
    let good = signed_response(&id, &expected_hash);
    let verified = session
        .verify_response(&good, &server_resolver())
        .expect("session verifies bound response against the stored hash");
    assert_eq!(verified.server_signer, SERVER);
    assert_eq!(verified.request_hash, expected_hash);
}

#[test]
fn verify_response_rejects_wrong_binding() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");

    // Server-signed but bound to a DIFFERENT request hash than the stored one.
    let response = signed_response(&id, "sha256:some-other-request-hash");
    let result = session.verify_response(&response, &server_resolver());
    assert_eq!(result.err(), Some(McpsError::ResponseHashMismatch));
}

#[test]
fn verify_response_for_unknown_id_is_missing_envelope() {
    // No request was signed for this id, so there is no stored hash to bind
    // against. The session must refuse to verify rather than trust the response.
    let mut session = session();
    let id = Value::String("never-sent".to_string());
    let response = signed_response(&id, "sha256:whatever");
    let result = session.verify_response(&response, &server_resolver());
    assert_eq!(result.err(), Some(McpsError::MissingEnvelope));
}

// --- #3854 (MCPS-034): correlation + cleanup hardening ----------------------

#[test]
fn signing_a_duplicate_in_flight_id_is_rejected() {
    // The first sign under `id` stores a pending entry. A second sign reusing the
    // SAME in-flight id is a replay of that id — refuse it rather than silently
    // clobber the first request's stored hash (which would let a response bind to
    // the wrong request).
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let first = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("first sign succeeds");
    let stored_after_first = session
        .stored_request_hash(&id)
        .expect("first sign stored a hash")
        .to_string();

    let result =
        session.sign_tool_call(&id, "echo", json!({ "text": "world" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH);
    assert_eq!(result.err(), Some(McpsError::ReplayDetected));

    // The duplicate sign did NOT replace the stored hash for the in-flight id.
    assert_eq!(session.stored_request_hash(&id), Some(stored_after_first.as_str()));
    let _ = first;
}

#[test]
fn an_id_is_signable_again_after_its_response_is_verified() {
    // Once a verified response evicts the pending entry, the id is free again.
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let request = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("first sign");
    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let hash = request_hash(&request_value).expect("hash");
    let response = signed_response(&id, &hash);
    session
        .verify_response(&response, &server_resolver())
        .expect("verify evicts pending");

    // Pending is now empty, so re-signing the same id is allowed.
    assert_eq!(session.pending_count(), 0);
    session
        .sign_tool_call(&id, "echo", json!({ "text": "again" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("re-sign after eviction succeeds");
}

#[test]
fn verified_response_removes_its_pending_entry() {
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let request = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("sign");
    assert_eq!(session.pending_count(), 1);

    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let hash = request_hash(&request_value).expect("hash");
    let response = signed_response(&id, &hash);
    session
        .verify_response(&response, &server_resolver())
        .expect("verify");

    // Success-path eviction: the pending entry is gone.
    assert_eq!(session.pending_count(), 0);
    assert_eq!(session.stored_request_hash(&id), None);
}

#[test]
fn a_failed_verification_does_not_evict_the_pending_entry() {
    // Eviction is a SUCCESS-path action. A wrong-hash response must not clear the
    // pending entry, so a later correctly-bound response can still verify.
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let request = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("sign");
    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let hash = request_hash(&request_value).expect("hash");

    let bad = signed_response(&id, "sha256:not-the-stored-hash");
    assert_eq!(
        session.verify_response(&bad, &server_resolver()).err(),
        Some(McpsError::ResponseHashMismatch)
    );
    // Entry survives the failed attempt.
    assert_eq!(session.pending_count(), 1);

    let good = signed_response(&id, &hash);
    session
        .verify_response(&good, &server_resolver())
        .expect("the correctly-bound response still verifies");
    assert_eq!(session.pending_count(), 0);
}

#[test]
fn expire_pending_drops_entries_past_expiry() {
    // Default lifetime is 300s; the pending entry expires at NOW_UNIX + 300.
    let mut session = session();
    let id = Value::String("req-1".to_string());
    session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("sign");
    assert_eq!(session.pending_count(), 1);

    // Strictly before expiry: nothing dropped.
    assert_eq!(session.expire_pending(NOW_UNIX + 299), 0);
    assert_eq!(session.pending_count(), 1);

    // At/after expiry: the entry is cleaned up.
    let dropped = session.expire_pending(NOW_UNIX + 300);
    assert_eq!(dropped, 1);
    assert_eq!(session.pending_count(), 0);
    assert_eq!(session.stored_request_hash(&id), None);
}

#[test]
fn expire_pending_is_id_selective_after_a_partial_cleanup() {
    // Two pending requests at the same fixed clock + lifetime expire together.
    // Cancel one first, then expire: only the surviving entry is dropped, proving
    // expire_pending operates over the live entry set (not a stale snapshot).
    let mut session = HostSession::new(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
        100,
    );
    let a = Value::String("a".to_string());
    let b = Value::String("b".to_string());
    session
        .sign_tool_call(&a, "echo", json!({ "text": "a" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("a sign");
    session
        .sign_tool_call(&b, "echo", json!({ "text": "b" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("b sign");
    assert_eq!(session.pending_count(), 2);

    // Before expiry: nothing dropped.
    assert_eq!(session.expire_pending(NOW_UNIX + 50), 0);

    // Cancel one, then expire past the window: only the one remaining is dropped.
    assert!(session.cancel_request(&a));
    assert_eq!(session.expire_pending(NOW_UNIX + 100), 1);
    assert_eq!(session.pending_count(), 0);
}

#[test]
fn cancel_request_drops_one_entry_by_id() {
    let mut session = session();
    let keep = Value::String("keep".to_string());
    let drop = Value::String("drop".to_string());
    session
        .sign_tool_call(&keep, "echo", json!({ "text": "a" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("keep");
    session
        .sign_tool_call(&drop, "echo", json!({ "text": "b" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("drop");
    assert_eq!(session.pending_count(), 2);

    assert!(session.cancel_request(&drop), "cancel returns true for a known id");
    assert_eq!(session.pending_count(), 1);
    assert_eq!(session.stored_request_hash(&drop), None);
    assert!(session.stored_request_hash(&keep).is_some());

    // Cancelling an unknown / already-cancelled id returns false (no-op).
    assert!(!session.cancel_request(&drop));
    assert!(!session.cancel_request(&Value::String("never".to_string())));
}

#[test]
fn cancelled_id_refuses_response_correlation() {
    // After cancellation there is no stored hash, so a response for that id is
    // refused (unknown-id == missing envelope), proving cancel really evicts.
    let mut session = session();
    let id = Value::String("req-1".to_string());
    let request = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("sign");
    let request_value: Value = serde_json::from_slice(&request).expect("parse");
    let hash = request_hash(&request_value).expect("hash");
    assert!(session.cancel_request(&id));

    let response = signed_response(&id, &hash);
    assert_eq!(
        session.verify_response(&response, &server_resolver()).err(),
        Some(McpsError::MissingEnvelope)
    );
}

#[test]
fn pending_count_tracks_outstanding_requests() {
    let mut session = session();
    assert_eq!(session.pending_count(), 0);
    for n in 1..=3 {
        let id = Value::String(format!("req-{n}"));
        session
            .sign_tool_call(&id, "echo", json!({ "text": "x" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
            .expect("sign");
        assert_eq!(session.pending_count(), n);
    }
}

#[test]
fn custom_lifetime_drives_expires_at() {
    // A 60-second lifetime yields expires_at = issued_at + 60s.
    let mut session = HostSession::new(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
        60,
    );
    let id = Value::String("req-1".to_string());
    let bytes = session
        .sign_tool_call(&id, "echo", json!({ "text": "hello" }), ON_BEHALF_OF, AUDIENCE, AUTH_HASH)
        .expect("session signs");
    let value: Value = serde_json::from_slice(&bytes).expect("parse");
    let envelope = &value["params"]["_meta"]["se.syncom/mcps.request"];
    assert_eq!(envelope["issued_at"], json!(ISSUED_AT));
    assert_eq!(envelope["expires_at"], json!("2026-05-28T20:01:00Z"));
}

// --- transport-free guard (ADR-MCPS-015 "Compliance and Enforcement") --------

/// The committed crate manifest and BUILD file, baked in at COMPILE time from
/// the source tree (delivered via `compile_data` in BUILD.bazel). Reading them
/// directly makes the guard run fully inside the bazel test sandbox with no
/// runfiles wiring.
const CARGO_TOML: &str = include_str!("../Cargo.toml");
const BUILD_BAZEL: &str = include_str!("../BUILD.bazel");

/// Networking/async crate substrings that must NEVER appear in `mcps-host`'s
/// declared dependencies. `mcps-host` is transport-free (ADR-MCPS-015): the
/// transport (stdio / Streamable HTTP / mTLS) is the caller's concern, deferred
/// to a future `mcps-host-transport` crate. Matching is on whole crate-name
/// tokens so an innocuous substring (e.g. "core") cannot false-positive.
const FORBIDDEN_TRANSPORT_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "async_std",
    "smol",
    "mio",
    "reqwest",
    "hyper",
    "axum",
    "actix",
    "actix-web",
    "warp",
    "tower",
    "tower-http",
    "tonic",
    "rustls",
    "native-tls",
    "openssl",
    "h2",
    "h3",
    "quinn",
    "socket2",
    "trust-dns",
    "futures",
    "futures-util",
    "tungstenite",
    "tokio-tungstenite",
    // Boundary direction (P6.6): the client-side transport adapters live in
    // `mcps-transport`, which may depend on `mcps-host` — never the reverse.
    // Forbidding the name here makes "mcps-host stays transport-free" enforceable,
    // not merely documented.
    "mcps-transport",
    "mcps-host-transport",
];

/// Split text into crate-name tokens (alphanumerics plus `-` / `_`), lowercased.
/// A forbidden crate is flagged only on a WHOLE-token match, so `getrandom` or
/// `serde_json` can never trip a substring like "rand" or "async".
fn name_tokens(text: &str) -> std::collections::BTreeSet<String> {
    let mut tokens = std::collections::BTreeSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.insert(current);
    }
    tokens
}

#[test]
fn mcps_host_carries_no_networking_or_async_dependencies() {
    // Guard inputs are non-empty (a renamed/empty file cannot silently pass).
    assert!(CARGO_TOML.contains("[dependencies]"), "Cargo.toml has a [dependencies] section");
    assert!(BUILD_BAZEL.contains("nt_rust_library"), "BUILD.bazel declares the library");

    let cargo_tokens = name_tokens(CARGO_TOML);
    let build_tokens = name_tokens(BUILD_BAZEL);

    let mut offenders: Vec<String> = Vec::new();
    for forbidden in FORBIDDEN_TRANSPORT_CRATES {
        let token = forbidden.to_ascii_lowercase();
        if cargo_tokens.contains(&token) {
            offenders.push(format!("{forbidden} (Cargo.toml)"));
        }
        if build_tokens.contains(&token) {
            offenders.push(format!("{forbidden} (BUILD.bazel)"));
        }
    }

    assert!(
        offenders.is_empty(),
        "mcps-host must stay transport-free (ADR-MCPS-015): forbidden networking/async \
         crate(s) found in its dependency declarations: {offenders:?}. The transport belongs \
         in a future mcps-host-transport crate, not here."
    );

    // Positive sanity: the legitimate, transport-free deps ARE present, proving
    // the tokenizer actually parsed the dependency declarations.
    assert!(cargo_tokens.contains("mcps-core"), "mcps-core dep present");
    assert!(cargo_tokens.contains("getrandom"), "getrandom dep present");
    assert!(cargo_tokens.contains("serde_json"), "serde_json dep present");
}
