//! Signed tool-manifest data types + minting (issue #3866).
//!
//! A [`ToolManifest`] is the serde-serializable artifact a server publishes and
//! signs so a client can cryptographically verify the exact set of tools the
//! server exposes — their names, versions, and input/output schemas — and later
//! detect a "rug pull" (a silent schema/behaviour change under an unchanged
//! identity).
//!
//! ## Signed shape (frozen JSON object)
//!
//! ```text
//! {
//!   "signer":     "<issuer / signing-authority identity>",
//!   "key_id":     "<key id used to resolve the verification key>",
//!   "manifest_id":"<opaque manifest identity (revocation handle)>",
//!   "version":    "<manifest version>",
//!   "issued_at":  <unix secs, optional>,
//!   "expires_at": <unix secs, optional>,
//!   "tools": [
//!     { "name": "...", "version": "...",
//!       "input_schema": { ... }, "output_schema": { ... },
//!       "schema_hash": "sha256:<b64url>" }
//!   ],
//!   "signature": { "alg": "Ed25519", "key_id": "...", "value": "<b64url>" }
//! }
//! ```
//!
//! Each tool's `schema_hash` is `sha256_hash_id(canonicalize(combined schema))`,
//! where the combined schema is the JCS canonicalization of
//! `{ "input": <input_schema>, "output": <output_schema> }`. The manifest
//! signature covers the JCS canonicalization of the WHOLE object with
//! `signature.value` removed — the identical recipe Core / the reference profile
//! use (clone → drop `signature.value` → `canonicalize_json_value` → sign).
//!
//! These are tightly-coupled serde DTOs for one artifact; like `envelope.rs`
//! (RequestEnvelope/ResponseEnvelope/SignatureBlock) and `reference.rs` (its
//! grant DTOs + `mint_reference_grant`) they live in one module.

use mcps_core::canonicalize_json_value;
use mcps_core::parse;
use mcps_core::sha256_hash_id;
use mcps_core::SigningKey;
use mcps_core::SIG_ALG_ED25519;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

use crate::manifest_error::ManifestError;

/// The signature block carried at the manifest's top level. Mirrors the Core
/// `SignatureBlock` shape (`alg` / `key_id` / `value`); `value` is the
/// Base64URL-no-pad Ed25519 signature over the canonical manifest minus
/// `signature.value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// Signature algorithm; MUST be `Ed25519`.
    pub alg: String,
    /// The key id used to resolve the verification key via the `TrustResolver`.
    pub key_id: String,
    /// The Base64URL-no-pad Ed25519 signature value.
    pub value: String,
}

/// One tool's identity + schemas + per-tool schema hash.
///
/// `(name, version)` is the tool identity; `schema_hash` is the integrity binding
/// over the input/output schemas (recomputed and compared at verify time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    /// The tool name (identity component).
    pub name: String,
    /// The tool version (identity component — part of the rug-pull pin key).
    pub version: String,
    /// The tool's input schema (an arbitrary JSON value).
    pub input_schema: Value,
    /// The tool's output schema (an arbitrary JSON value).
    pub output_schema: Value,
    /// `sha256_hash_id(canonicalize({ "input": input_schema, "output":
    /// output_schema }))`. Recomputed and compared during verification.
    pub schema_hash: String,
}

impl ToolEntry {
    /// Build a [`ToolEntry`], computing `schema_hash` from the supplied schemas via
    /// the in-house JCS canonicalization + SHA-256 hash id. A schema that is not a
    /// JCS-safe value (non-integer numbers, etc.) is [`ManifestError::ManifestMalformed`].
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        input_schema: Value,
        output_schema: Value,
    ) -> Result<Self, ManifestError> {
        let schema_hash = compute_schema_hash(&input_schema, &output_schema)?;
        Ok(ToolEntry {
            name: name.into(),
            version: version.into(),
            input_schema,
            output_schema,
            schema_hash,
        })
    }

    /// Recompute this entry's schema hash from its own `input_schema` /
    /// `output_schema`. Used by the verifier to compare against the recorded
    /// `schema_hash` (reject on mismatch).
    pub fn recompute_schema_hash(&self) -> Result<String, ManifestError> {
        compute_schema_hash(&self.input_schema, &self.output_schema)
    }
}

/// Compute the per-tool schema hash: canonicalize the combined
/// `{ "input": <input>, "output": <output> }` object with the in-house JCS and
/// hash the canonical bytes with `sha256_hash_id`. Wrapping both schemas in one
/// object binds them together so neither can be swapped independently.
pub fn compute_schema_hash(
    input_schema: &Value,
    output_schema: &Value,
) -> Result<String, ManifestError> {
    let combined = json!({ "input": input_schema, "output": output_schema });
    let canon =
        canonicalize_json_value(&combined).map_err(|_| ManifestError::ManifestMalformed)?;
    Ok(sha256_hash_id(&canon))
}

/// The signed tool manifest: manifest-level identity, the tool list, and the
/// signature block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// The signing-authority / issuer identity. Resolves a verification key via
    /// the injected `TrustResolver` together with `signature.key_id`.
    pub signer: String,
    /// The key id used to resolve the verification key (mirrors `signature.key_id`;
    /// the verifier resolves on the signature's `key_id`).
    pub key_id: String,
    /// The opaque manifest identity — the handle used for manifest revocation.
    pub manifest_id: String,
    /// The manifest version.
    pub version: String,
    /// Optional issue time, integer unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    /// Optional expiry time, integer unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The tools this manifest attests to.
    pub tools: Vec<ToolEntry>,
    /// The Ed25519 signature over the canonical manifest minus `signature.value`.
    pub signature: ManifestSignature,
}

/// The claims used to mint a signed manifest (test/host support). Holds tools as
/// `(name, version, input_schema, output_schema)`; the minter computes each
/// `schema_hash` and the manifest signature.
#[derive(Debug, Clone)]
pub struct ManifestSpec {
    /// The signing-authority identity.
    pub signer: String,
    /// The opaque manifest identity (revocation handle).
    pub manifest_id: String,
    /// The manifest version.
    pub version: String,
    /// Optional issue time, integer unix seconds.
    pub issued_at: Option<i64>,
    /// Optional expiry time, integer unix seconds.
    pub expires_at: Option<i64>,
    /// The tools, each `(name, version, input_schema, output_schema)`.
    pub tools: Vec<ToolSpec>,
}

/// One tool's claims for minting (name + version + the two schemas; the
/// `schema_hash` is derived).
#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// The tool name.
    pub name: String,
    /// The tool version.
    pub version: String,
    /// The tool's input schema.
    pub input_schema: Value,
    /// The tool's output schema.
    pub output_schema: Value,
}

/// Mint a signed [`ToolManifest`]: compute each tool's `schema_hash`, build the
/// object, sign the canonical preimage (object minus `signature.value`) with the
/// issuer key, and return the populated manifest. Pure — signing has no side
/// effects (matches `mint_reference_grant`). Used by tests and the host.
pub fn mint_signed_manifest(
    spec: &ManifestSpec,
    signing_key: &SigningKey,
    key_id: &str,
) -> Result<ToolManifest, ManifestError> {
    let mut tools = Vec::with_capacity(spec.tools.len());
    for tool in &spec.tools {
        tools.push(ToolEntry::new(
            tool.name.clone(),
            tool.version.clone(),
            tool.input_schema.clone(),
            tool.output_schema.clone(),
        )?);
    }

    // Build the unsigned manifest with a placeholder (empty) signature value, then
    // sign the canonicalization of the object with `signature.value` removed.
    let mut manifest = ToolManifest {
        signer: spec.signer.clone(),
        key_id: key_id.to_string(),
        manifest_id: spec.manifest_id.clone(),
        version: spec.version.clone(),
        issued_at: spec.issued_at,
        expires_at: spec.expires_at,
        tools,
        signature: ManifestSignature {
            alg: SIG_ALG_ED25519.to_string(),
            key_id: key_id.to_string(),
            value: String::new(),
        },
    };

    let preimage = manifest_signing_preimage(&manifest)?;
    manifest.signature.value = signing_key.sign(&preimage);
    Ok(manifest)
}

/// Build the canonical signing preimage for a manifest: serialize to a
/// `serde_json::Value`, remove `signature.value`, and canonicalize via the
/// in-house JCS — the identical "canonicalize object minus signature.value"
/// recipe Core / the reference profile use. Serialization or canonicalization
/// failure (e.g. a non-JCS-safe schema number) → [`ManifestError::ManifestMalformed`].
pub fn manifest_signing_preimage(manifest: &ToolManifest) -> Result<Vec<u8>, ManifestError> {
    let mut value =
        serde_json::to_value(manifest).map_err(|_| ManifestError::ManifestMalformed)?;
    match value.get_mut("signature").and_then(Value::as_object_mut) {
        Some(sig) => {
            sig.remove("value");
        }
        None => return Err(ManifestError::ManifestMalformed),
    }
    canonicalize_json_value(&value).map_err(|_| ManifestError::ManifestMalformed)
}

/// Parse raw manifest wire bytes into a [`ToolManifest`], rejecting bytes that
/// carry a duplicate JSON object member anywhere in the structure (#85 finding 1).
///
/// This is the ONLY correct seam for turning untrusted manifest bytes into a
/// `ToolManifest`: `serde_json::from_slice` alone CANNOT detect duplicate object
/// members because `serde_json::Value`/`Map` collapses them last-wins, so a
/// signed manifest whose RAW bytes carry duplicate members would be silently
/// canonicalized last-wins on the signing/verify path rather than rejected — the
/// exact MCPS-02 / ADR-MCPS-005 semantic-divergence class the Core request path
/// guards against. We therefore first run the raw-bytes, dup-key-REJECTING
/// `mcps_core::parse` over the original bytes (it parses with the in-house value
/// model that surfaces duplicate members and the full JCS-safe domain). `parse`
/// — not `canonicalize` — is the right primitive here: we only need the
/// fail-closed VALIDATION, not the canonical output bytes, so this avoids
/// building (and discarding) the canonical string on every parse. Only on
/// success do we deserialize into the typed `ToolManifest`. Any duplicate member,
/// JCS-domain violation, or shape mismatch → [`ManifestError::ManifestMalformed`].
///
/// Complementarily, the signed-object structs ([`ToolManifest`],
/// [`ManifestSignature`], [`ToolEntry`]) carry `#[serde(deny_unknown_fields)]`, so
/// a wire manifest carrying an EXTRA/unknown object member on the signed object is
/// REJECTED at deserialize time rather than silently dropped (#85 review). Were it
/// dropped, that member would be excluded from the signature preimage recomputed
/// from the typed manifest, so a verifier and a re-serializer would disagree about
/// the "frozen JSON object" — exactly the divergence the dup-key guard above
/// prevents for duplicate members. The per-tool `input_schema` / `output_schema`
/// are free-form `serde_json::Value`s and are unaffected: `deny_unknown_fields`
/// constrains only the named fields of these DTOs, never the JSON held inside a
/// `Value`.
pub fn parse_manifest_bytes(bytes: &[u8]) -> Result<ToolManifest, ManifestError> {
    // (1) Reject duplicate object members (and the rest of the JCS-safe domain) on
    // the ORIGINAL wire bytes, BEFORE any serde_json::Value collapses duplicates.
    // `parse` performs the full validation without allocating the canonical output.
    parse(bytes).map_err(|_| ManifestError::ManifestMalformed)?;
    // (2) Now safe to deserialize into the typed manifest; `deny_unknown_fields`
    // on the signed-object structs rejects any extra/unknown member here.
    serde_json::from_slice(bytes).map_err(|_| ManifestError::ManifestMalformed)
}

#[cfg(test)]
mod tests {
    use super::compute_schema_hash;
    use super::manifest_signing_preimage;
    use super::mint_signed_manifest;
    use super::ManifestSpec;
    use super::ToolEntry;
    use super::ToolSpec;
    use mcps_core::canonicalize_json_value;
    use mcps_core::sha256_hash_id;
    use mcps_core::SigningKey;
    use serde_json::json;
    use serde_json::Value;

    fn input_schema() -> Value {
        json!({ "type": "object", "properties": { "text": { "type": "string" } } })
    }

    fn output_schema() -> Value {
        json!({ "type": "string" })
    }

    fn spec() -> ManifestSpec {
        ManifestSpec {
            signer: "did:example:server-1".to_string(),
            manifest_id: "manifest-1".to_string(),
            version: "1".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: "1.0.0".to_string(),
                input_schema: input_schema(),
                output_schema: output_schema(),
            }],
        }
    }

    #[test]
    fn schema_hash_is_sha256_of_canonical_combined_schema() {
        let combined = json!({ "input": input_schema(), "output": output_schema() });
        let canon = canonicalize_json_value(&combined).unwrap();
        assert_eq!(
            compute_schema_hash(&input_schema(), &output_schema()).unwrap(),
            sha256_hash_id(&canon)
        );
    }

    #[test]
    fn schema_hash_changes_when_schema_changes() {
        let baseline = compute_schema_hash(&input_schema(), &output_schema()).unwrap();
        let changed = compute_schema_hash(
            &json!({ "type": "object", "properties": { "text": { "type": "number" } } }),
            &output_schema(),
        )
        .unwrap();
        assert_ne!(baseline, changed);
    }

    #[test]
    fn tool_entry_new_records_the_computed_hash() {
        let entry = ToolEntry::new("echo", "1.0.0", input_schema(), output_schema()).unwrap();
        assert_eq!(
            entry.schema_hash,
            compute_schema_hash(&input_schema(), &output_schema()).unwrap()
        );
        assert_eq!(entry.recompute_schema_hash().unwrap(), entry.schema_hash);
    }

    #[test]
    fn minted_manifest_carries_a_nonempty_signature_and_hashes() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        assert!(!manifest.signature.value.is_empty());
        assert_eq!(manifest.signature.alg, "Ed25519");
        assert_eq!(manifest.tools.len(), 1);
        assert!(manifest.tools[0].schema_hash.starts_with("sha256:"));
    }

    #[test]
    fn preimage_excludes_signature_value() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let preimage = manifest_signing_preimage(&manifest).unwrap();
        let text = String::from_utf8(preimage).unwrap();
        assert!(!text.contains(&manifest.signature.value));
        // alg + key_id are retained in the preimage.
        assert!(text.contains("Ed25519"));
        assert!(text.contains("server-key-1"));
    }

    #[test]
    fn preimage_is_independent_of_signature_value() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let mut manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let baseline = manifest_signing_preimage(&manifest).unwrap();
        manifest.signature.value = "ZGlmZmVyZW50".to_string();
        assert_eq!(baseline, manifest_signing_preimage(&manifest).unwrap());
    }

    #[test]
    fn round_trips_through_serde_json() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let back: super::ToolManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn parse_manifest_bytes_accepts_clean_wire_bytes() {
        // A well-formed manifest's own serialization round-trips through the
        // dup-key-rejecting parse seam unchanged.
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let back = super::parse_manifest_bytes(&bytes).expect("clean bytes must parse");
        assert_eq!(back, manifest);
    }

    #[test]
    fn parse_manifest_bytes_rejects_duplicate_top_level_member() {
        // #85 finding 1: raw bytes carrying a DUPLICATE top-level object member
        // must be rejected — `serde_json::from_slice` alone would silently collapse
        // the duplicate last-wins, so the dup-key-rejecting raw-bytes canonicalize
        // is what guards the signed manifest bytes. Hand-built bytes with two
        // `manifest_id` members; this is impossible to produce via serde
        // serialization, so we assemble it textually.
        let raw = br#"{"signer":"did:example:server-1","key_id":"server-key-1","manifest_id":"a","manifest_id":"b","version":"1","tools":[],"signature":{"alg":"Ed25519","key_id":"server-key-1","value":""}}"#;
        assert_eq!(
            super::parse_manifest_bytes(raw).unwrap_err(),
            ManifestError::ManifestMalformed
        );
    }

    #[test]
    fn parse_manifest_bytes_rejects_duplicate_nested_member() {
        // A duplicate member NESTED inside a tool's schema must also be rejected —
        // the guard runs over the whole structure, not just the top level.
        let raw = br#"{"signer":"did:example:server-1","key_id":"server-key-1","manifest_id":"a","version":"1","tools":[{"name":"echo","version":"1.0.0","input_schema":{"type":"object","type":"array"},"output_schema":{"type":"string"},"schema_hash":"sha256:x"}],"signature":{"alg":"Ed25519","key_id":"server-key-1","value":""}}"#;
        assert_eq!(
            super::parse_manifest_bytes(raw).unwrap_err(),
            ManifestError::ManifestMalformed
        );
    }

    #[test]
    fn parse_manifest_bytes_rejects_unknown_top_level_member() {
        // #85 review: a wire manifest carrying an EXTRA/unknown top-level object
        // member must be REJECTED at deserialize time (`deny_unknown_fields`),
        // not silently dropped. A dropped member would be excluded from the
        // signature preimage recomputed from the typed manifest, undermining the
        // frozen-JSON-object contract. The bytes are otherwise a clean, unique-key
        // object so this isolates the unknown-member path from the dup-key path.
        let raw = br#"{"signer":"did:example:server-1","key_id":"server-key-1","manifest_id":"a","version":"1","tools":[],"signature":{"alg":"Ed25519","key_id":"server-key-1","value":""},"smuggled":"x"}"#;
        assert_eq!(
            super::parse_manifest_bytes(raw).unwrap_err(),
            ManifestError::ManifestMalformed
        );
    }

    #[test]
    fn parse_manifest_bytes_rejects_unknown_member_in_signature_block() {
        // The guard must also reject an unknown member NESTED in a signed
        // sub-object (the signature block), not just at the top level.
        let raw = br#"{"signer":"did:example:server-1","key_id":"server-key-1","manifest_id":"a","version":"1","tools":[],"signature":{"alg":"Ed25519","key_id":"server-key-1","value":"","extra":"y"}}"#;
        assert_eq!(
            super::parse_manifest_bytes(raw).unwrap_err(),
            ManifestError::ManifestMalformed
        );
    }

    #[test]
    fn parse_manifest_bytes_allows_free_form_members_inside_tool_schemas() {
        // `deny_unknown_fields` must NOT leak into the free-form schema `Value`s:
        // arbitrary members inside `input_schema` / `output_schema` are legitimate
        // JSON Schema content and must be preserved, not rejected.
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let entry = ToolEntry::new(
            "echo",
            "1.0.0",
            json!({ "type": "object", "x-vendor-ext": { "anything": [1, 2, 3] } }),
            output_schema(),
        )
        .unwrap();
        let spec = ManifestSpec {
            signer: "did:example:server-1".to_string(),
            manifest_id: "manifest-1".to_string(),
            version: "1".to_string(),
            issued_at: None,
            expires_at: None,
            tools: vec![ToolSpec {
                name: entry.name.clone(),
                version: entry.version.clone(),
                input_schema: entry.input_schema.clone(),
                output_schema: entry.output_schema.clone(),
            }],
        };
        let manifest = mint_signed_manifest(&spec, &key, "server-key-1").unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let back = super::parse_manifest_bytes(&bytes)
            .expect("free-form schema members must be preserved, not rejected");
        assert_eq!(back, manifest);
    }

    use crate::manifest_error::ManifestError;
}
