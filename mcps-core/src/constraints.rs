//! Fail-closed message-shape constraints + envelope extraction
//! (MCPS_SPEC §7 / §9 steps 1, 2, 4, 5, 6).
//!
//! Every function here operates on an already-parsed `&serde_json::Value`
//! top-level JSON-RPC message. Raw-bytes JCS validation (duplicate-key
//! detection, unsafe-integer rejection, UTF-8 checks — §9 step 3) lives in
//! `canonical` (MCPS-004) and is invoked earlier by the verify pipeline; it is
//! deliberately NOT re-performed here.
//!
//! These are the cheap structural checks the pipeline runs before the expensive
//! crypto (MCPS_SPEC §9 notes "steps 1-2 and 4-7 are cheap structural checks
//! before the expensive crypto; this ordering is normative"):
//!
//! - [`reject_batch`] — §9 step 1: a top-level JSON array is a JSON-RPC batch and
//!   is forbidden (`mcps.batch_forbidden`).
//! - [`reject_notification`] — §9 step 2: a JSON-RPC notification (no `id`) is
//!   forbidden for the security path (`mcps.notification_forbidden`).
//! - [`extract_request_envelope`] / [`extract_response_envelope`] — §9 steps 4-6:
//!   locate the envelope under the appropriate `_meta` key (absent ->
//!   `mcps.missing_envelope`), deserialize against the `deny_unknown_fields`
//!   struct (an unknown field -> `mcps.unknown_envelope_field`; a wrong-type or
//!   missing required field -> `mcps.canonicalization_failed`), then version-check
//!   the request envelope (`!= "draft-01"` -> `mcps.unsupported_version`).
//!
//! All functions are pure: no networking, async, or filesystem, and no
//! `unwrap`/`expect`/`panic!` in library code.

use serde_json::Value;

use crate::envelope::Draft02RequestEnvelope;
use crate::envelope::Draft02ResponseEnvelope;
use crate::envelope::RequestEnvelope;
use crate::envelope::ResponseEnvelope;
use crate::error::McpsError;
use crate::ids::CANONICALIZATION_ID_INT53_V1;
use crate::ids::DRAFT_02_CANONICALIZATION_ALLOWLIST;
use crate::ids::REQUEST_META_KEY;
use crate::ids::RESPONSE_META_KEY;
use crate::ids::VERSION_DRAFT_01;
use crate::ids::VERSION_DRAFT_02;

/// Every canonicalization scheme id the verifier RECOGNIZES as a real scheme,
/// across all profile versions (ADR-MCPS-038 / decision B.2). It is a SUPERSET
/// of any single profile's allowlist and is the seam that distinguishes an
/// *unknown* id (names no scheme at all → `mcps.canonicalization_id_unknown`)
/// from a *recognized-but-disallowed* id (a real scheme not admitted by the
/// active profile → `mcps.canonicalization_id_not_allowed`). In v0.6 exactly one
/// scheme exists, so this equals the draft-02 allowlist; a future float-capable
/// `…-v2` scheme ([ADR-MCPS-037](../adr)) is added HERE first, then to a profile
/// allowlist when proven — never the reverse.
pub const KNOWN_CANONICALIZATION_SCHEMES: [&str; 1] = [CANONICALIZATION_ID_INT53_V1];

/// §9 step 1 — reject a JSON-RPC batch (top-level array).
///
/// MCP-S Core forbids batches outright (MCPS_SPEC §7): a top-level JSON array
/// maps to [`McpsError::BatchForbidden`]. Any non-array top-level value passes.
pub fn reject_batch(msg: &Value) -> Result<(), McpsError> {
    if msg.is_array() {
        return Err(McpsError::BatchForbidden);
    }
    Ok(())
}

/// §9 step 2 — reject a JSON-RPC notification (a message with no `id`).
///
/// A JSON-RPC notification is a request object that omits the `id` member. Every
/// message passing through MCP-S verification is security-relevant by definition
/// (MCPS_SPEC §7: "operations with security consequences MUST be id-bearing
/// requests"), so an absent `id` -> [`McpsError::NotificationForbidden`].
///
/// Design choice (documented per the spec's request): an explicit `"id": null`
/// is treated as ALSO forbidden on the security path. JSON-RPC reserves `null`
/// for the id of an error response when the request id could not be determined;
/// a *request* carrying a null id is indistinguishable from "no addressable
/// request" for our purposes and cannot be safely correlated, so we fail closed.
/// A present id of any other JSON type (string or number — the JSON-RPC-legal
/// kinds) passes; correctness of an integer id's magnitude is enforced separately
/// by the JCS-safe-integer domain check (§9 step 3), not here.
///
/// A non-object top-level value (e.g. an array) has no `id` member either; such
/// inputs should already have been rejected by [`reject_batch`] at step 1, but
/// for safety any value that is not an object with a present, non-null `id` is
/// treated as a forbidden notification.
pub fn reject_notification(msg: &Value) -> Result<(), McpsError> {
    match msg.get("id") {
        Some(Value::Null) | None => Err(McpsError::NotificationForbidden),
        Some(_) => Ok(()),
    }
}

/// §9 steps 4-6 — locate, deserialize, and version-check the request envelope.
///
/// 1. Step 4: locate the envelope value at
///    `msg["params"]["_meta"][REQUEST_META_KEY]`. Absent (any missing segment)
///    -> [`McpsError::MissingEnvelope`].
/// 2. Step 5: deserialize into [`RequestEnvelope`]. Because the struct is
///    `#[serde(deny_unknown_fields)]`, an unknown field surfaces as a serde
///    error classified as "unknown field" and maps to
///    [`McpsError::UnknownEnvelopeField`]. A structurally absent `on_behalf_of`
///    maps to [`McpsError::OnBehalfOfMissing`] (P005) and a structurally absent
///    `authorization_hash` to [`McpsError::AuthorizationHashMissing`] (P007).
///    Any other deserialization failure (wrong type, any OTHER missing required
///    field) maps to [`McpsError::CanonicalizationFailed`] — a structural
///    rejection that fails closed without claiming a more specific verdict.
/// 3. Step 6: enforce `version == "draft-01"`; any other value ->
///    [`McpsError::UnsupportedVersion`]. Folding step 6 in here means extraction
///    always yields a version-checked envelope.
pub fn extract_request_envelope(msg: &Value) -> Result<RequestEnvelope, McpsError> {
    let raw = locate_envelope(msg, "params", REQUEST_META_KEY)?;
    let envelope: RequestEnvelope =
        deserialize_envelope(raw).map_err(|err| classify_request_envelope_error(raw, err))?;
    if envelope.version != VERSION_DRAFT_01 {
        return Err(McpsError::UnsupportedVersion);
    }
    Ok(envelope)
}

/// Re-classify a request-envelope deserialization error so that a structurally
/// absent dedicated field surfaces its dedicated token (P007 / P005) regardless
/// of serde's first-missing-field message ordering (MCPS-094, audit M-2/M-1
/// residual).
///
/// serde reports only the FIRST missing required field, so when an EARLIER field
/// is co-omitted alongside `authorization_hash` (or `on_behalf_of`) the serde
/// message names that earlier field and a message-prefix discriminator
/// mis-routes to [`McpsError::CanonicalizationFailed`]. We instead presence-check
/// the located envelope value explicitly, in a fixed priority, when (and only
/// when) the underlying error is a generic structural rejection that did not
/// already resolve to a more specific token.
///
/// Priority is `authorization_hash` (P007) before `on_behalf_of` (P005); the
/// present-but-malformed paths are untouched because a present key is not
/// re-classified here (the field IS present, so the original verdict stands).
/// Fails closed: any path that is not an explicit absence keeps its original
/// verdict.
fn classify_request_envelope_error(raw: &Value, original: McpsError) -> McpsError {
    // Only a generic structural rejection is eligible for upgrade to a dedicated
    // absence token; an already-specific verdict (unknown field, or the dedicated
    // tokens resolved directly by the serde message) is authoritative.
    if original != McpsError::CanonicalizationFailed {
        return original;
    }
    let Some(obj) = raw.as_object() else {
        return original;
    };
    if !obj.contains_key("authorization_hash") {
        McpsError::AuthorizationHashMissing
    } else if !obj.contains_key("on_behalf_of") {
        McpsError::OnBehalfOfMissing
    } else {
        original
    }
}

/// §9 (verify_response steps 2-3) — locate and deserialize the response envelope.
///
/// Locates the envelope value at `msg["result"]["_meta"][RESPONSE_META_KEY]`
/// (absent -> [`McpsError::MissingEnvelope`]) and deserializes into
/// [`ResponseEnvelope`]. The `deny_unknown_fields` struct surfaces an unknown
/// field (e.g. the removed `trust_label`) as [`McpsError::UnknownEnvelopeField`];
/// other deserialization failures map to [`McpsError::CanonicalizationFailed`].
/// The response envelope carries no `version` field, so there is no §6-style
/// version check here.
pub fn extract_response_envelope(msg: &Value) -> Result<ResponseEnvelope, McpsError> {
    let raw = locate_envelope(msg, "result", RESPONSE_META_KEY)?;
    deserialize_envelope(raw)
}

/// Locate an envelope value under `msg[outer]["_meta"][meta_key]`.
///
/// Any missing segment along the path yields [`McpsError::MissingEnvelope`].
fn locate_envelope<'a>(
    msg: &'a Value,
    outer: &str,
    meta_key: &str,
) -> Result<&'a Value, McpsError> {
    msg.get(outer)
        .and_then(|outer_val| outer_val.get("_meta"))
        .and_then(|meta| meta.get(meta_key))
        .ok_or(McpsError::MissingEnvelope)
}

/// Deserialize an already-located envelope value into `T`, mapping serde errors
/// to the frozen taxonomy.
///
/// Discrimination rule:
///   * `unknown field \`<name>\``  -> [`McpsError::UnknownEnvelopeField`]
///     (the `deny_unknown_fields` violation);
///   * every other failure (type mismatch, any missing required field) ->
///     [`McpsError::CanonicalizationFailed`] — a structural rejection that fails
///     closed without claiming a more specific verdict.
///
/// The dedicated absence tokens P005 ([`McpsError::OnBehalfOfMissing`]) and P007
/// ([`McpsError::AuthorizationHashMissing`]) are **NOT** classified here from
/// serde's message wording (M-01 / M-02). A structurally absent `on_behalf_of` or
/// `authorization_hash` lands on the generic [`McpsError::CanonicalizationFailed`]
/// branch and is then upgraded to its dedicated token by an explicit
/// presence check in [`classify_request_envelope_error`]. That keeps the
/// security-relevant taxonomy independent of serde_json's human-readable
/// phrasing, and also fixes the co-omission case serde's first-missing-field
/// ordering cannot express.
///
/// The one remaining reliance on serde wording is the `unknown field` prefix;
/// the `serde_unknown_field_wording_is_pinned` test fails CI if a serde_json bump
/// ever rephrases it, rather than letting the mapping silently degrade.
fn deserialize_envelope<T>(raw: &Value) -> Result<T, McpsError>
where
    T: serde::de::DeserializeOwned,
{
    match serde_json::from_value::<T>(raw.clone()) {
        Ok(envelope) => Ok(envelope),
        Err(err) => {
            if err.to_string().starts_with("unknown field") {
                Err(McpsError::UnknownEnvelopeField)
            } else {
                Err(McpsError::CanonicalizationFailed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Draft-02 (v0.6) envelope extraction — ADR-MCPS-038 / decision B.2, D.1.
// ---------------------------------------------------------------------------

/// Draft-02 request-envelope extraction in the ADR-MCPS-038 verification ORDER:
/// read `version` and `canonicalization_id` from the raw object as UNTRUSTED
/// selectors first, require `version == "draft-02"`, require
/// `canonicalization_id` ∈ the profile allowlist, THEN deserialize the full
/// `deny_unknown_fields` struct. The fields are read before the signature
/// verifies (the caller does that next) and trusted only after — the same
/// read-untrusted/trust-after-verify pattern `alg`/`key_id` already follow.
///
/// Fail-closed mapping:
/// - missing/absent envelope → [`McpsError::MissingEnvelope`];
/// - `version != "draft-02"` (or absent) → [`McpsError::UnsupportedVersion`];
/// - `canonicalization_id` absent → [`McpsError::CanonicalizationIdMissing`];
/// - unrecognized scheme → [`McpsError::CanonicalizationIdUnknown`];
/// - recognized but not allowlisted → [`McpsError::CanonicalizationIdNotAllowed`];
/// - unknown field → [`McpsError::UnknownEnvelopeField`];
/// - other structural failure → [`McpsError::CanonicalizationFailed`], with a
///   structurally-absent `authorization_hash`/`on_behalf_of` upgraded to its
///   dedicated token (same priority as draft-01).
pub fn extract_draft02_request_envelope(
    msg: &Value,
) -> Result<Draft02RequestEnvelope, McpsError> {
    let raw = locate_envelope(msg, "params", REQUEST_META_KEY)?;
    require_draft02_version(raw)?;
    check_canonicalization_id(raw)?;
    deserialize_envelope(raw).map_err(|err| classify_request_envelope_error(raw, err))
}

/// Draft-02 response-envelope extraction. Unlike draft-01, the draft-02 response
/// DOES carry `version` and `canonicalization_id`, so it runs the same untrusted
/// selector reads as the request: the response is an independently signed record
/// and must be self-describing standalone (decision B.2). Same fail-closed
/// mapping as [`extract_draft02_request_envelope`] minus the request-only
/// dedicated-field upgrades.
pub fn extract_draft02_response_envelope(
    msg: &Value,
) -> Result<Draft02ResponseEnvelope, McpsError> {
    let raw = locate_envelope(msg, "result", RESPONSE_META_KEY)?;
    require_draft02_version(raw)?;
    check_canonicalization_id(raw)?;
    deserialize_envelope(raw)
}

/// Require the raw envelope's `version` member to be exactly `"draft-02"`. Absent
/// or any other value → [`McpsError::UnsupportedVersion`] (the profile cannot be
/// selected). Read from the raw JSON as an untrusted selector before the
/// signature verifies.
fn require_draft02_version(raw: &Value) -> Result<(), McpsError> {
    match raw.get("version").and_then(Value::as_str) {
        Some(VERSION_DRAFT_02) => Ok(()),
        _ => Err(McpsError::UnsupportedVersion),
    }
}

/// Validate the raw envelope's protected `canonicalization_id` against the
/// draft-02 profile (ADR-MCPS-038 step 4). Absent/non-string →
/// [`McpsError::CanonicalizationIdMissing`]; present value classified by
/// [`classify_canonicalization_id`].
fn check_canonicalization_id(raw: &Value) -> Result<(), McpsError> {
    match raw.get("canonicalization_id").and_then(Value::as_str) {
        Some(id) => classify_canonicalization_id(
            id,
            &DRAFT_02_CANONICALIZATION_ALLOWLIST,
            &KNOWN_CANONICALIZATION_SCHEMES,
        ),
        None => Err(McpsError::CanonicalizationIdMissing),
    }
}

/// Classify a presented `canonicalization_id` against the active profile.
///
/// `allowlist` = the schemes the active profile admits; `known` = every scheme
/// the verifier recognizes as real (a superset). The order matters: an allowed
/// id passes; a recognized-but-unallowlisted id is a disallowed-scheme probe
/// ([`McpsError::CanonicalizationIdNotAllowed`]); anything else names no scheme
/// at all ([`McpsError::CanonicalizationIdUnknown`]). The verifier NEVER selects
/// the canonicalizer from this field — membership is checked, the scheme is then
/// chosen from the profile (no `alg`-confusion).
fn classify_canonicalization_id(
    id: &str,
    allowlist: &[&str],
    known: &[&str],
) -> Result<(), McpsError> {
    if allowlist.contains(&id) {
        Ok(())
    } else if known.contains(&id) {
        Err(McpsError::CanonicalizationIdNotAllowed)
    } else {
        Err(McpsError::CanonicalizationIdUnknown)
    }
}

#[cfg(test)]
mod tests {
    use super::classify_canonicalization_id;
    use super::extract_draft02_request_envelope;
    use super::extract_draft02_response_envelope;
    use super::extract_request_envelope;
    use super::extract_response_envelope;
    use super::reject_batch;
    use super::reject_notification;
    use crate::error::McpsError;
    use serde_json::json;
    use serde_json::Value;

    // --- Fixture `message` payloads, mirroring the committed conformance vectors
    // in tests/vectors/. Embedded inline (rather than include_str!) because the
    // library unit-test target has no fixture compile_data; the conformance test
    // crate (tests/vectors_test.rs) owns the on-disk fixtures.

    /// Mirrors tests/vectors/batch.json `message`.
    fn batch_message() -> Value {
        json!([
            {"id": "a", "jsonrpc": "2.0", "method": "tools/call", "params": {}},
            {"id": "b", "jsonrpc": "2.0", "method": "tools/call", "params": {}}
        ])
    }

    /// Mirrors tests/vectors/security_notification.json `message` (no `id`).
    fn security_notification_message() -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"arguments": {"text": "hello"}, "name": "echo"}
        })
    }

    /// Mirrors tests/vectors/missing_envelope_request.json `message`.
    fn missing_envelope_message() -> Value {
        json!({
            "id": "req-missing",
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"arguments": {"text": "hello"}, "name": "echo"}
        })
    }

    /// A valid request envelope value, frozen §2 vocabulary.
    fn valid_request_envelope() -> Value {
        json!({
            "audience": "did:example:server-1",
            "authorization_hash": "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
            "expires_at": "2026-05-28T20:05:00Z",
            "issued_at": "2026-05-28T20:00:00Z",
            "nonce": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
            "on_behalf_of": "did:example:user-1",
            "signature": {
                "alg": "Ed25519",
                "key_id": "key-1",
                "value": "ym-rRufDoMUZEs_63Dfk2P7LDiXez80v306zB3CenfsA7lQkhyP3TDykmucCI0Lm8HYurVPfhn7yzScEfiAWBw"
            },
            "signer": "did:example:agent-1",
            "version": "draft-01"
        })
    }

    /// Wrap an envelope value into a full request message under the request
    /// `_meta` key (mirrors tests/vectors/v1_valid_request.json shape).
    fn request_message_with_envelope(envelope: Value) -> Value {
        json!({
            "id": "req-1",
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "_meta": {"se.syncom/mcps.request": envelope},
                "arguments": {"text": "hello"},
                "name": "echo"
            }
        })
    }

    /// A valid response envelope value, frozen §2 vocabulary.
    fn valid_response_envelope() -> Value {
        json!({
            "request_hash": "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
            "server_signer": "did:example:server-1",
            "issued_at": "2026-05-28T20:00:01Z",
            "signature": {"alg": "Ed25519", "key_id": "server-key-1", "value": "c2ln"}
        })
    }

    fn response_message_with_envelope(envelope: Value) -> Value {
        json!({
            "id": "req-1",
            "jsonrpc": "2.0",
            "result": {
                "_meta": {"se.syncom/mcps.response": envelope},
                "content": []
            }
        })
    }

    // ---- Draft-02 (v0.6) fixtures — ADR-MCPS-038 / decision B.2 ---------------

    /// A valid draft-02 request envelope value (draft-01 fields + the two
    /// protected identifiers).
    fn valid_draft02_request_envelope() -> Value {
        let mut env = valid_request_envelope();
        let obj = env.as_object_mut().unwrap();
        obj.insert("version".into(), json!("draft-02"));
        obj.insert(
            "canonicalization_id".into(),
            json!("mcps-jcs-int53-json-v1"),
        );
        env
    }

    /// A valid draft-02 response envelope value (draft-01 response + both
    /// protected identifiers).
    fn valid_draft02_response_envelope() -> Value {
        let mut env = valid_response_envelope();
        let obj = env.as_object_mut().unwrap();
        obj.insert("version".into(), json!("draft-02"));
        obj.insert(
            "canonicalization_id".into(),
            json!("mcps-jcs-int53-json-v1"),
        );
        env
    }

    // ---- extract_draft02_request_envelope ------------------------------------

    #[test]
    fn draft02_request_extracts_with_both_identifiers() {
        let msg = request_message_with_envelope(valid_draft02_request_envelope());
        let env = extract_draft02_request_envelope(&msg).expect("valid draft-02 request");
        assert_eq!(env.version, "draft-02");
        assert_eq!(env.canonicalization_id, "mcps-jcs-int53-json-v1");
    }

    #[test]
    fn draft02_request_wrong_version_is_unsupported() {
        let mut env = valid_draft02_request_envelope();
        env["version"] = json!("draft-01");
        let msg = request_message_with_envelope(env);
        assert_eq!(
            extract_draft02_request_envelope(&msg),
            Err(McpsError::UnsupportedVersion)
        );
    }

    #[test]
    fn draft02_request_missing_canonicalization_id() {
        let mut env = valid_draft02_request_envelope();
        env.as_object_mut().unwrap().remove("canonicalization_id");
        let msg = request_message_with_envelope(env);
        assert_eq!(
            extract_draft02_request_envelope(&msg),
            Err(McpsError::CanonicalizationIdMissing)
        );
    }

    #[test]
    fn draft02_request_unknown_canonicalization_id() {
        let mut env = valid_draft02_request_envelope();
        env["canonicalization_id"] = json!("nope-not-a-scheme");
        let msg = request_message_with_envelope(env);
        assert_eq!(
            extract_draft02_request_envelope(&msg),
            Err(McpsError::CanonicalizationIdUnknown)
        );
    }

    #[test]
    fn draft02_request_unknown_field_is_rejected() {
        let mut env = valid_draft02_request_envelope();
        env.as_object_mut()
            .unwrap()
            .insert("bogus".into(), json!(true));
        let msg = request_message_with_envelope(env);
        assert_eq!(
            extract_draft02_request_envelope(&msg),
            Err(McpsError::UnknownEnvelopeField)
        );
    }

    // ---- extract_draft02_response_envelope -----------------------------------

    #[test]
    fn draft02_response_extracts_with_both_identifiers() {
        let msg = response_message_with_envelope(valid_draft02_response_envelope());
        let env = extract_draft02_response_envelope(&msg).expect("valid draft-02 response");
        assert_eq!(env.version, "draft-02");
        assert_eq!(env.canonicalization_id, "mcps-jcs-int53-json-v1");
    }

    #[test]
    fn draft02_response_missing_canonicalization_id() {
        let mut env = valid_draft02_response_envelope();
        env.as_object_mut().unwrap().remove("canonicalization_id");
        let msg = response_message_with_envelope(env);
        assert_eq!(
            extract_draft02_response_envelope(&msg),
            Err(McpsError::CanonicalizationIdMissing)
        );
    }

    // ---- classify_canonicalization_id ----------------------------------------

    /// The recognized-but-unallowlisted path: a real future scheme presented
    /// under a profile that does not admit it → `not_allowed` (distinct from an
    /// `unknown` id that names no scheme). Tested at the classifier so the
    /// forward-compat path is pinned without minting an undecided v0.6 wire name.
    #[test]
    fn classify_recognized_but_disallowed_is_not_allowed() {
        let allowlist = ["mcps-jcs-int53-json-v1"];
        let known = ["mcps-jcs-int53-json-v1", "mcps-jcs-future-floats-v2"];
        assert_eq!(
            classify_canonicalization_id("mcps-jcs-future-floats-v2", &allowlist, &known),
            Err(McpsError::CanonicalizationIdNotAllowed)
        );
        assert_eq!(
            classify_canonicalization_id("mcps-jcs-int53-json-v1", &allowlist, &known),
            Ok(())
        );
        assert_eq!(
            classify_canonicalization_id("totally-unknown", &allowlist, &known),
            Err(McpsError::CanonicalizationIdUnknown)
        );
    }

    // ---- reject_batch --------------------------------------------------------

    #[test]
    fn batch_fixture_is_forbidden() {
        assert_eq!(
            reject_batch(&batch_message()),
            Err(McpsError::BatchForbidden)
        );
    }

    #[test]
    fn non_array_object_passes_batch_check() {
        assert_eq!(reject_batch(&missing_envelope_message()), Ok(()));
    }

    // ---- reject_notification -------------------------------------------------

    #[test]
    fn security_notification_fixture_is_forbidden() {
        assert_eq!(
            reject_notification(&security_notification_message()),
            Err(McpsError::NotificationForbidden)
        );
    }

    #[test]
    fn id_bearing_request_passes_notification_check() {
        let msg = request_message_with_envelope(valid_request_envelope());
        assert_eq!(reject_notification(&msg), Ok(()));
    }

    #[test]
    fn explicit_null_id_is_forbidden() {
        let msg = json!({"id": null, "jsonrpc": "2.0", "method": "tools/call"});
        assert_eq!(
            reject_notification(&msg),
            Err(McpsError::NotificationForbidden)
        );
    }

    #[test]
    fn numeric_id_passes_notification_check() {
        let msg = json!({"id": 7, "jsonrpc": "2.0", "method": "tools/call"});
        assert_eq!(reject_notification(&msg), Ok(()));
    }

    // ---- extract_request_envelope --------------------------------------------

    #[test]
    fn missing_envelope_fixture_yields_missing_envelope() {
        assert_eq!(
            extract_request_envelope(&missing_envelope_message()),
            Err(McpsError::MissingEnvelope)
        );
    }

    #[test]
    fn unknown_envelope_field_yields_unknown_envelope_field() {
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .insert("unexpected".to_string(), json!("x"));
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::UnknownEnvelopeField)
        );
    }

    #[test]
    fn valid_request_envelope_extracts_with_frozen_fields() {
        let msg = request_message_with_envelope(valid_request_envelope());
        let env = extract_request_envelope(&msg).expect("valid envelope extracts");
        assert_eq!(env.version, "draft-01");
        assert_eq!(env.signer, "did:example:agent-1");
        assert_eq!(env.on_behalf_of, "did:example:user-1");
        assert_eq!(env.audience, "did:example:server-1");
        assert_eq!(
            env.authorization_hash,
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        );
        assert_eq!(env.nonce, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA");
        assert_eq!(env.signature.alg, "Ed25519");
        assert_eq!(env.signature.key_id, "key-1");
    }

    #[test]
    fn unsupported_version_yields_unsupported_version() {
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .insert("version".to_string(), json!("draft-99"));
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::UnsupportedVersion)
        );
    }

    #[test]
    fn wrong_type_field_is_not_unknown_envelope_field() {
        // `audience` as a number is a TYPE error, not an unknown field. It must
        // map to CanonicalizationFailed, proving the unknown-field discriminator
        // does not over-match.
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .insert("audience".to_string(), json!(123));
        let msg = request_message_with_envelope(envelope);
        let result = extract_request_envelope(&msg);
        assert_eq!(result, Err(McpsError::CanonicalizationFailed));
        assert_ne!(result, Err(McpsError::UnknownEnvelopeField));
    }

    #[test]
    fn missing_required_field_is_not_unknown_envelope_field() {
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .remove("audience");
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::CanonicalizationFailed)
        );
    }

    #[test]
    fn missing_on_behalf_of_yields_on_behalf_of_missing() {
        // P005 (audit M-1): a STRUCTURALLY absent on_behalf_of must surface its
        // dedicated token, not the generic CanonicalizationFailed.
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .remove("on_behalf_of");
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::OnBehalfOfMissing)
        );
    }

    #[test]
    fn missing_authorization_hash_yields_authorization_hash_missing() {
        // P007 (audit M-2): a STRUCTURALLY absent authorization_hash must surface
        // its dedicated token, not the generic CanonicalizationFailed.
        let mut envelope = valid_request_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .remove("authorization_hash");
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::AuthorizationHashMissing)
        );
    }

    #[test]
    fn missing_authorization_hash_with_earlier_field_also_absent_yields_authorization_hash_missing()
    {
        // MCPS-094 (audit M-2 residual): serde reports only the FIRST missing
        // required field. When an EARLIER field (`audience`) is ALSO omitted,
        // serde's message names that field, so a message-prefix discriminator
        // re-routes to CanonicalizationFailed. The presence-check classifier
        // must still emit the dedicated P007 token for the absent
        // authorization_hash regardless of co-omission.
        let mut envelope = valid_request_envelope();
        let obj = envelope.as_object_mut().expect("envelope is an object");
        obj.remove("audience");
        obj.remove("authorization_hash");
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::AuthorizationHashMissing)
        );
    }

    #[test]
    fn missing_on_behalf_of_with_earlier_field_also_absent_yields_on_behalf_of_missing() {
        // MCPS-094 (audit M-1 residual, same exposure as M-2): with an earlier
        // required field (`version`) ALSO absent, the dedicated P005 token must
        // still be emitted for the absent on_behalf_of. authorization_hash is
        // kept present so the only absent dedicated-token field is on_behalf_of.
        let mut envelope = valid_request_envelope();
        let obj = envelope.as_object_mut().expect("envelope is an object");
        obj.remove("version");
        obj.remove("on_behalf_of");
        let msg = request_message_with_envelope(envelope);
        assert_eq!(
            extract_request_envelope(&msg),
            Err(McpsError::OnBehalfOfMissing)
        );
    }

    #[test]
    fn serde_wording_pins_guard_against_silent_taxonomy_drift() {
        // M-01 / M-02 guard. The P005/P007 absence tokens no longer depend on
        // serde_json's phrasing — they are resolved by an explicit presence check
        // in `classify_request_envelope_error`. The `unknown field` ->
        // UnknownEnvelopeField mapping in `deserialize_envelope` IS still wording-
        // dependent. Pin both wordings so a serde_json bump that rephrases either
        // fails CI loudly instead of silently degrading the taxonomy.
        use crate::envelope::RequestEnvelope;

        // (a) The `unknown field` wording `deserialize_envelope` still relies on.
        let mut unknown = valid_request_envelope();
        unknown
            .as_object_mut()
            .expect("envelope is an object")
            .insert("rogue_field".to_string(), Value::String("x".to_string()));
        let unknown_err =
            serde_json::from_value::<RequestEnvelope>(unknown).expect_err("unknown field fails");
        assert!(
            unknown_err.to_string().starts_with("unknown field"),
            "serde_json `unknown field` wording changed: {unknown_err}"
        );

        // (b) The `missing field` wording we DELIBERATELY no longer rely on for
        // P005/P007. Pinned as a tripwire so a maintainer re-checking this path
        // notices if serde's phrasing — and thus the rationale for the presence-
        // check — ever shifts.
        let mut missing = valid_request_envelope();
        missing
            .as_object_mut()
            .expect("envelope is an object")
            .remove("on_behalf_of");
        let missing_err =
            serde_json::from_value::<RequestEnvelope>(missing).expect_err("missing field fails");
        assert!(
            missing_err.to_string().starts_with("missing field"),
            "serde_json `missing field` wording changed: {missing_err}"
        );
    }

    // ---- extract_response_envelope -------------------------------------------

    #[test]
    fn valid_response_envelope_extracts() {
        let msg = response_message_with_envelope(valid_response_envelope());
        let env = extract_response_envelope(&msg).expect("valid response extracts");
        assert_eq!(env.server_signer, "did:example:server-1");
        assert_eq!(
            env.request_hash,
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        );
    }

    #[test]
    fn missing_response_envelope_yields_missing_envelope() {
        let msg = json!({"id": "req-1", "jsonrpc": "2.0", "result": {"content": []}});
        assert_eq!(
            extract_response_envelope(&msg),
            Err(McpsError::MissingEnvelope)
        );
    }

    #[test]
    fn response_trust_label_is_unknown_envelope_field() {
        // trust_label is REMOVED from Core; it must surface as an unknown field.
        let mut envelope = valid_response_envelope();
        envelope
            .as_object_mut()
            .expect("envelope is an object")
            .insert("trust_label".to_string(), json!("high"));
        let msg = response_message_with_envelope(envelope);
        assert_eq!(
            extract_response_envelope(&msg),
            Err(McpsError::UnknownEnvelopeField)
        );
    }
}
