//! Transport-binding abstraction (MCPS-024, ADR-MCPS-014).
//!
//! Phase 6 binds the MCP-S signing identity to the transport channel: an mTLS
//! client certificate proves *which channel* a request arrived on, and the
//! transport-binding policy asserts that channel identity is consistent with the
//! request's verified `signer`. A mismatch — or a required-but-absent verified
//! client identity — fails closed with `mcps.transport_binding_failed`.
//!
//! This module is std-only: it defines the identity type, the provider seam
//! (`RustlsDirectProvider` produces identity functionally in MCPS-025;
//! [`ReverseProxyMtlsProvider`] reads it from a trusted upstream header), and the
//! binding policy. `mcps-core` stays pure — the `transport_binding_failed` code
//! lives in its taxonomy but is emitted here, at the proxy, which is the only
//! component holding the connection.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use mcps_core::b64url_decode;
use mcps_core::parse_hash_id;
use mcps_core::verify_ed25519_with;
use mcps_core::McpsError;
use mcps_core::VerificationKey;

/// Where a verified transport identity was read from in the client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// A URI Subject Alternative Name (SPIFFE-style).
    UriSan,
    /// A DNS Subject Alternative Name.
    DnsSan,
    /// The subject Common Name (last resort).
    CommonName,
}

/// Which certificate field is the AUTHORITATIVE source of the transport identity.
///
/// This is a deployment policy, not a heuristic: the proxy reads exactly the
/// configured field and NEVER silently falls through to a weaker one. If the
/// selected field is absent from the client certificate, identity extraction
/// returns `None` and the (required) transport binding fails closed — a missing
/// URI SAN must never be quietly downgraded to a DNS SAN or a Common Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityPolicy {
    /// URI Subject Alternative Name (SPIFFE-style). The recommended default:
    /// URI SANs are unambiguous, namespaced, and the SPIFFE/workload-identity
    /// convention.
    #[default]
    UriSan,
    /// DNS Subject Alternative Name. Use only when the deployment's client
    /// identities are genuinely DNS names and this is an explicit choice.
    DnsSan,
    /// Subject Common Name. LEGACY ONLY — the CN is unstructured and deprecated
    /// for identity by the CA/Browser Forum. Selecting it emits a startup
    /// warning; prefer a URI or DNS SAN.
    CnLegacy,
}

/// A verified client identity extracted from a successfully-verified mTLS client
/// certificate (the leaf of the chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    /// The identity string (e.g. `spiffe://example.org/agent-1`).
    pub value: String,
    /// Which certificate field it came from.
    pub source: IdentitySource,
}

impl TransportIdentity {
    /// Construct a transport identity.
    pub fn new(value: impl Into<String>, source: IdentitySource) -> Self {
        TransportIdentity {
            value: value.into(),
            source,
        }
    }
}

/// The parsed HTTP request headers of an inbound connection, the only request
/// context a [`TransportBindingProvider`] is given. This is a thin, case-
/// insensitive view over the already-parsed header block — providers never see
/// the socket, the body, or the TLS connection, so a header-reading provider
/// cannot accidentally reach for connection state it must not trust.
///
/// Header names compare ASCII-case-insensitively (per RFC 7230). The FIRST
/// occurrence of a name wins; this is deliberate for the reverse-proxy trust
/// model — a trusted upstream sets the forwarded header, and a duplicate injected
/// further downstream cannot override the first (the provider additionally fails
/// closed on a header whose own value is internally ambiguous, see
/// [`ReverseProxyMtlsProvider`]).
#[derive(Debug, Clone, Default)]
pub struct RequestHeaders {
    /// `(lowercased-name, raw-value)` pairs in wire order.
    headers: Vec<(String, String)>,
}

impl RequestHeaders {
    /// Parse an HTTP/1.1 header block (the bytes up to and including the
    /// terminating `\r\n\r\n`, or any prefix of it) into a header view. The
    /// request line (first line) is skipped; malformed lines without a `:` are
    /// ignored. Values are trimmed of surrounding whitespace.
    pub fn parse(header_block: &str) -> Self {
        let mut headers = Vec::new();
        for (index, line) in header_block.lines().enumerate() {
            // Skip the request line (`POST / HTTP/1.1`) and blank lines.
            if index == 0 || line.trim().is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        RequestHeaders { headers }
    }

    /// Construct directly from `(name, value)` pairs (used in tests). Names are
    /// lowercased so lookup stays case-insensitive.
    pub fn from_pairs<I, N, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let headers = pairs
            .into_iter()
            .map(|(name, value)| (name.into().to_ascii_lowercase(), value.into()))
            .collect();
        RequestHeaders { headers }
    }

    /// The first value for `name` (case-insensitive), or `None` if absent.
    pub fn first(&self, name: &str) -> Option<&str> {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(header_name, _)| *header_name == lowered)
            .map(|(_, value)| value.as_str())
    }

    /// The number of values present for `name` (case-insensitive). Used to fail
    /// closed on a duplicated trust header.
    pub fn count(&self, name: &str) -> usize {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(header_name, _)| *header_name == lowered)
            .count()
    }
}

/// Produces the verified client identity for an inbound request, or `None` when
/// no identity is available (fail closed: a binding that requires identity then
/// rejects). The request headers are the ONLY context — direct-TLS identity is
/// extracted functionally by the serve loop (see `tls::connection_identity`) and
/// does not go through this trait, so the request-bearing signature exists for
/// the header-reading [`ReverseProxyMtlsProvider`]. `StaticIdentityProvider`
/// ignores the request and is used in tests.
pub trait TransportBindingProvider {
    /// The verified client identity for this request, if any.
    fn verified_identity(&self, request: &RequestHeaders) -> Option<TransportIdentity>;
}

/// A fixed identity (or none). Useful in tests and as a degenerate provider; it
/// ignores the request entirely and always yields the identity it was built with.
#[derive(Debug, Clone, Default)]
pub struct StaticIdentityProvider {
    identity: Option<TransportIdentity>,
}

impl StaticIdentityProvider {
    /// A provider that yields `identity` (or `None`).
    pub fn new(identity: Option<TransportIdentity>) -> Self {
        StaticIdentityProvider { identity }
    }
}

impl TransportBindingProvider for StaticIdentityProvider {
    fn verified_identity(&self, _request: &RequestHeaders) -> Option<TransportIdentity> {
        self.identity.clone()
    }
}

/// A [`TransportBindingProvider`] that reads the verified client identity from a
/// Maximum accepted length (bytes) of an asserted trusted-ingress identity value
/// (ADR-MCPS-023: asserted-identity metadata MUST be length-bounded — oversized
/// values fail closed). Generous enough for SPIFFE URIs / RFC2253 DNs, small
/// enough to bound parse/log cost and reject smuggling payloads.
pub const MAX_ASSERTED_IDENTITY_LEN: usize = 8192;

/// Why a trusted-ingress asserted-identity value was rejected (ADR-MCPS-023).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertedIdentityRejection {
    /// Empty after trimming.
    Empty,
    /// Longer than [`MAX_ASSERTED_IDENTITY_LEN`].
    TooLong,
    /// Contains a control character (CR / LF / NUL / …) — a header-smuggling and
    /// log-injection risk; a well-formed identity value has none.
    Malformed,
}

/// Validate a single asserted trusted-ingress identity value against the
/// ADR-MCPS-023 strict rules: **well-formed** (no control characters),
/// **length-bounded** ([`MAX_ASSERTED_IDENTITY_LEN`]), and non-empty. Returns the
/// trimmed value on success, or the reason it fails closed.
///
/// The **single-valued** rule is enforced by the caller via
/// [`RequestHeaders::count`] (a duplicated trust header fails closed before the
/// value is ever read); this function validates the lone value's shape.
pub fn validate_asserted_identity_value(value: &str) -> Result<&str, AssertedIdentityRejection> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AssertedIdentityRejection::Empty);
    }
    if trimmed.len() > MAX_ASSERTED_IDENTITY_LEN {
        return Err(AssertedIdentityRejection::TooLong);
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(AssertedIdentityRejection::Malformed);
    }
    Ok(trimmed)
}

/// The SEP-2243 transport routing header naming the JSON-RPC method (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_METHOD_HEADER: &str = "mcp-method";

/// The SEP-2243 transport routing header naming the tool/resource (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_NAME_HEADER: &str = "mcp-name";

/// Why a SEP-2243 routing header was rejected (ADR-MCPS-025).
///
/// Routing headers (`Mcp-Method` / `Mcp-Name`) are untrusted hints: the signed
/// body is authoritative and the proxy never routes on them. But ADR-MCPS-025
/// rule 4 applies the ADR-MCPS-023 strict-header rules to them too — a duplicated
/// or malformed routing header is a header-smuggling / log-injection vector and
/// fails closed at the transport boundary before the handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingHeaderRejection {
    /// The header appeared more than once (a downstream-injected duplicate must
    /// not be able to shadow or confuse the first).
    Duplicate {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
    /// The header's lone value failed the strict shape rules (empty, oversized, or
    /// containing a control character) — see [`validate_asserted_identity_value`].
    Malformed {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
}

/// Apply the ADR-MCPS-023 strict-header rules to the SEP-2243 routing headers
/// (`Mcp-Method` / `Mcp-Name`) per ADR-MCPS-025 rule 4: each MUST be single-valued
/// and well-formed (non-empty, length-bounded, no control characters). Absent
/// headers pass — they are optional routing hints, not required. Present-but-bad
/// headers fail closed; the proxy never trusts a routing header for any security
/// decision, so this is hygiene (anti-smuggling), not a routing check.
pub fn validate_routing_headers(headers: &RequestHeaders) -> Result<(), RoutingHeaderRejection> {
    for header in [MCP_METHOD_HEADER, MCP_NAME_HEADER] {
        match headers.count(header) {
            0 => continue,
            1 => {
                let value = headers.first(header).unwrap_or("");
                if validate_asserted_identity_value(value).is_err() {
                    return Err(RoutingHeaderRejection::Malformed { header });
                }
            }
            _ => return Err(RoutingHeaderRejection::Duplicate { header }),
        }
    }
    Ok(())
}

/// TRUSTED header set by an upstream mTLS-terminating reverse proxy (e.g. Envoy /
/// nginx forwarding `X-Forwarded-Client-Cert`). This lets MCP-S run behind
/// enterprise ingress that already terminates mTLS, instead of terminating mTLS
/// itself.
///
/// # SECURITY — trust assumption (operator-asserted)
///
/// Trusting a forwarded header is ONLY safe if the link from the upstream proxy
/// is itself trusted. A naive header read lets anyone who can reach the listening
/// socket spoof any identity. Enabling this provider is therefore an explicit
/// operator assertion that **the listening socket is reachable ONLY by the
/// trusted upstream** (loopback, a private network segment, or the upstream's own
/// mTLS link) and that the upstream STRIPS any inbound copy of the trusted header
/// from external clients before re-setting its own. The CLI gates this behind an
/// opt-in flag and emits a loud startup notice. When this provider is in use the
/// proxy MUST NOT also do local client-cert mTLS identity extraction for the same
/// connection — the two identity sources are mutually exclusive (the serve path
/// chooses one).
///
/// # Fail-closed parsing
///
/// Every defect maps to `None` (no identity), which the downstream
/// [`TransportBindingPolicy`] turns into a closed rejection when a binding
/// requires identity. Specifically `None` is returned when the header is:
/// absent, empty/whitespace, present more than once, or (for XFCC) malformed,
/// missing the field selected by the [`IdentityPolicy`], or carrying conflicting
/// values for that field across multiple cert elements. Identity is NEVER
/// defaulted to an attacker-influenceable value.
#[derive(Debug, Clone)]
pub struct ReverseProxyMtlsProvider {
    /// The trusted header name to read (case-insensitive), e.g.
    /// `x-forwarded-client-cert` or a plain `x-client-identity`.
    header_name: String,
    /// Header wire format: a plain identity string or Envoy XFCC.
    format: ReverseProxyHeaderFormat,
    /// Which identity field is authoritative — mirrors the direct-TLS
    /// [`IdentityPolicy`] so the downstream binding policy is unchanged.
    policy: IdentityPolicy,
}

/// The wire format of the trusted reverse-proxy identity header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseProxyHeaderFormat {
    /// The header value IS the identity string verbatim (e.g. a single SPIFFE
    /// URI in a custom `X-Client-Identity` header). The configured
    /// [`IdentityPolicy`] names the [`IdentitySource`] this value is reported as.
    Plain,
    /// Envoy `X-Forwarded-Client-Cert` (XFCC): a comma-separated list of cert
    /// elements, each a semicolon-separated list of `Key=Value` pairs
    /// (`By=`, `Hash=`, `Subject=`, `URI=`, `DNS=`, …). The field selected by the
    /// [`IdentityPolicy`] (`URI`/`DNS`/`Subject`→CN) is extracted.
    Xfcc,
}

impl ReverseProxyMtlsProvider {
    /// Build a provider reading `header_name` in `format`, reporting the field
    /// chosen by `policy` as the transport identity.
    pub fn new(
        header_name: impl Into<String>,
        format: ReverseProxyHeaderFormat,
        policy: IdentityPolicy,
    ) -> Self {
        ReverseProxyMtlsProvider {
            header_name: header_name.into(),
            format,
            policy,
        }
    }

    /// The [`IdentitySource`] that the configured [`IdentityPolicy`] resolves to.
    fn source(&self) -> IdentitySource {
        match self.policy {
            IdentityPolicy::UriSan => IdentitySource::UriSan,
            IdentityPolicy::DnsSan => IdentitySource::DnsSan,
            IdentityPolicy::CnLegacy => IdentitySource::CommonName,
        }
    }

    /// Parse a PLAIN identity header value into an identity, or `None`. The value
    /// must satisfy the ADR-MCPS-023 strict rules
    /// ([`validate_asserted_identity_value`]): non-empty, length-bounded, and
    /// well-formed (no control characters). Any violation fails closed (`None`).
    fn parse_plain(&self, value: &str) -> Option<TransportIdentity> {
        let validated = validate_asserted_identity_value(value).ok()?;
        Some(TransportIdentity::new(validated.to_string(), self.source()))
    }

    /// Parse an Envoy XFCC header value, extracting the field named by the policy.
    ///
    /// XFCC is a comma-separated list of cert elements; each element is a
    /// semicolon-separated list of `Key=Value` pairs. We extract the configured
    /// field (`URI`/`DNS`/`Subject`/`CN`) from EVERY element and fail closed if
    /// the elements disagree (more than one distinct value), if the field is
    /// absent everywhere, or if the extracted value is empty. A single
    /// consistent value (the field repeated identically, or present once) is
    /// accepted. Quoted values (`Subject="..."`) have their surrounding double
    /// quotes stripped.
    ///
    /// # Cross-strategy identity parity (M23, audit 0.2 / #4080)
    ///
    /// Under [`IdentityPolicy::CnLegacy`] the extracted component must be the SAME
    /// one the direct-TLS path ([`crate::tls::extract_identity`]) extracts: the
    /// bare Common Name. Envoy forwards the leaf subject as a FULL RFC2253 DN in
    /// the `Subject=` field (`Subject="CN=agent-1,OU=agents,O=example"`), whereas
    /// the direct-TLS path reads ONLY the CN attribute (`agent-1`). Returning the
    /// whole DN here would make the SAME client certificate resolve to a DIFFERENT
    /// identity string depending solely on the transport strategy, so one
    /// `IdentityPolicy` would resolve two identities for one cert and the binding
    /// policy could not be configured to admit both. We therefore parse the CN out
    /// of a `Subject=` DN; an explicit `CN=` pair is used verbatim (it is already
    /// the bare CN).
    fn parse_xfcc(&self, value: &str) -> Option<TransportIdentity> {
        // The XFCC field keys for each policy. CommonName accepts either
        // `Subject=` (a full RFC2253 DN, from which we extract the CN to match the
        // direct-TLS path) or an explicit `CN=` pair (already the bare CN).
        let wanted: &[&str] = match self.policy {
            IdentityPolicy::UriSan => &["uri"],
            IdentityPolicy::DnsSan => &["dns"],
            IdentityPolicy::CnLegacy => &["subject", "cn"],
        };

        // Explicit element-selection policy (ADR-MCPS-023, issue #21 cluster 2).
        // XFCC is a comma-separated list of cert ELEMENTS, each a semicolon-
        // separated list of `Key=Value` pairs. We parse element-by-element (NOT
        // flattened): the asserted identity may ONLY come from an element that
        // itself carries the selected field, and the value MUST be consistent
        // across every element that carries it (any disagreement fails closed).
        //
        // v0.3's trusted-ingress posture expects the configured ingress to emit
        // sanitized single-hop XFCC — i.e. exactly one usable identity element.
        // Identical repetition of the same value across hops is tolerated as a
        // benign artifact; a non-selected element (one without the field) is never
        // a source of identity. We deliberately do NOT assume "first element ==
        // leaf": XFCC element ordering is not a guaranteed invariant across
        // deployments, so positional leaf selection would be its own footgun.
        let mut found: Option<String> = None;
        // An unterminated quote anywhere in the header is malformed and fails
        // closed (issue #21 residual): otherwise a stray `"` would collapse cert
        // elements together and hide a conflicting element from the check below.
        for element in split_xfcc_elements(value)? {
            // Within an element, `;` delimits pairs (outside quotes). Envoy quotes
            // any value containing a reserved character (`,`, `;`, `=`), so a
            // quoted Subject DN such as `Subject="CN=a,OU=b"` stays a single pair.
            for pair in split_xfcc_element_pairs(element)? {
                let Some((key, raw_value)) = pair.split_once('=') else {
                    continue;
                };
                let key = key.trim().to_ascii_lowercase();
                if !wanted.contains(&key.as_str()) {
                    continue;
                }
                let stripped = strip_optional_quotes(raw_value.trim());
                // M23 parity: under CnLegacy a `Subject=` DN is reduced to its CN
                // so it equals the direct-TLS extraction; a `CN=` pair (and URI/DNS
                // fields) are taken verbatim. A `Subject=` DN that carries NO CN
                // attribute fails closed rather than yielding a weaker/whole-DN
                // identity.
                let extracted: Option<String> = if key == "subject" {
                    common_name_from_rfc2253(stripped)
                } else {
                    Some(stripped.to_string())
                };
                let Some(extracted) = extracted else {
                    // The selected field is present but carries no usable component
                    // (e.g. a Subject DN with no CN): fail closed.
                    return None;
                };
                if extracted.is_empty() {
                    // A present-but-empty selected field is a malformed element:
                    // fail closed rather than yield an empty identity.
                    return None;
                }
                match &found {
                    // Conflicting values across elements → fail closed.
                    Some(existing) if *existing != extracted => return None,
                    Some(_) => {}
                    None => found = Some(extracted),
                }
            }
        }

        // ADR-MCPS-023 strict value rules on the SELECTED identity — length-bound
        // and no control characters — mirroring the plain path. This is the gap
        // closed by issue #21: the XFCC-derived value was previously returned
        // without these checks. Fail closed (`None`) on any violation, and on
        // zero usable identity elements (`found == None`).
        let identity = validate_asserted_identity_value(found.as_deref()?).ok()?;
        Some(TransportIdentity::new(identity.to_string(), self.source()))
    }
}

impl TransportBindingProvider for ReverseProxyMtlsProvider {
    fn verified_identity(&self, request: &RequestHeaders) -> Option<TransportIdentity> {
        // Fail closed on a duplicated trust header: an upstream sets it exactly
        // once, so two copies signal a downstream injection attempt.
        if request.count(&self.header_name) != 1 {
            return None;
        }
        let value = request.first(&self.header_name)?;
        match self.format {
            ReverseProxyHeaderFormat::Plain => self.parse_plain(value),
            ReverseProxyHeaderFormat::Xfcc => self.parse_xfcc(value),
        }
    }
}

/// Split an XFCC header value into its cert ELEMENTS on `,` occurring outside a
/// double-quoted value (issue #21 cluster 2: element-aware, not flattened).
/// Envoy quotes any value containing a reserved character (`,`, `;`, `=`), so a
/// quoted Subject DN such as `Subject="CN=a,OU=b"` is NOT split at its internal
/// comma. Each returned element is then split into its `Key=Value` pairs by
/// [`split_xfcc_element_pairs`].
fn split_xfcc_elements(value: &str) -> Option<Vec<&str>> {
    split_outside_quotes(value, ',')
}

/// Split a single XFCC cert element into its `Key=Value` pairs on `;` occurring
/// outside a double-quoted value (a quoted Subject DN stays one pair).
fn split_xfcc_element_pairs(element: &str) -> Option<Vec<&str>> {
    split_outside_quotes(element, ';')
}

/// Split `value` on every occurrence of `sep` that falls OUTSIDE a double-quoted
/// span. Shared by the XFCC element and pair splitters so both honour Envoy's
/// quoting rule identically.
///
/// Fails closed (`None`) on an UNTERMINATED quote (issue #21 residual): a stray
/// opening `"` with no closing `"` would otherwise leave the scan "inside a quote"
/// for the rest of the value, swallowing every following `sep` and COLLAPSING
/// multiple cert elements (or pairs) into one. An attacker could use that to hide
/// a conflicting/forged element behind the first and bypass the cross-element
/// conflict detection in [`ReverseProxyMtlsProvider::parse_xfcc`]. Envoy always
/// emits balanced quotes, so an unterminated quote is malformed — reject it.
fn split_outside_quotes(value: &str, sep: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (index, ch) in value.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c == sep && !in_quotes => {
                parts.push(&value[start..index]);
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    if in_quotes {
        // Unterminated quote → malformed; fail closed rather than collapse spans.
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

/// Strip a single pair of surrounding ASCII double quotes from `value`, if both
/// are present; otherwise return `value` unchanged. Envoy quotes XFCC values that
/// contain reserved characters (`,`, `;`, `=`), e.g. `Subject="CN=a,OU=b"`.
fn strip_optional_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

/// Extract the Common Name (`CN`) attribute value from an RFC2253 Distinguished
/// Name string, or `None` if the DN carries no `CN` attribute (M23, #4080).
///
/// This is the reverse-proxy mirror of the direct-TLS path's CN extraction
/// ([`crate::tls::extract_identity`] under [`IdentityPolicy::CnLegacy`], which
/// reads the leaf subject's CN attribute): an upstream proxy forwards the leaf
/// subject as a full RFC2253 DN in the XFCC `Subject=` field
/// (`CN=agent-1,OU=agents,O=example`), and to keep the SAME certificate resolving
/// to the SAME identity across strategies we must reduce that DN to the SAME bare
/// CN the direct path yields.
///
/// RFC2253 parsing scope (sufficient for the CN component): the DN is a sequence
/// of `Type=Value` Relative Distinguished Names separated by unescaped commas. A
/// value may be escaped (`\,` `\=` `\+` `\"` `\\` `\<hex>`-style) or surrounded by
/// double quotes; commas/plus signs inside a quoted value or after a backslash do
/// NOT separate RDNs. The FIRST `CN` attribute (case-insensitive type) wins,
/// matching the direct-TLS path's `iter_common_name().next()`. Multi-valued RDNs
/// (`CN=a+OU=b`) are split on unescaped `+`. A `CN` with an empty value yields
/// `Some("")`, which the caller treats as a malformed (fail-closed) element.
fn common_name_from_rfc2253(dn: &str) -> Option<String> {
    for rdn in split_unescaped(dn, ',') {
        for attr in split_unescaped(rdn, '+') {
            let Some((attr_type, attr_value)) = attr.split_once('=') else {
                continue;
            };
            if attr_type.trim().eq_ignore_ascii_case("cn") {
                // First CN wins (matches the direct-TLS `iter_common_name().next()`).
                // A CN whose value is a malformed escape / non-UTF-8 yields `None`
                // here, which the caller treats as fail-closed (no usable CN).
                return unescape_rfc2253_value(attr_value.trim());
            }
        }
    }
    None
}

/// Split `input` on occurrences of `sep` that are neither backslash-escaped nor
/// inside a double-quoted span (RFC2253 quoting). Returns the raw (still-escaped,
/// still-quoted) segments; value unescaping happens in [`unescape_rfc2253_value`].
fn split_unescaped(input: &str, sep: char) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            c if c == sep && !in_quotes => {
                segments.push(&input[start..index]);
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    segments.push(&input[start..]);
    segments
}

/// Unescape an RFC2253 attribute value: drop surrounding double quotes (if the
/// whole value is quoted) and resolve `\` backslash escapes. A backslash followed
/// by exactly two hex digits is a `\<hexpair>` BYTE escape and is decoded to that
/// byte (per RFC2253 §2.4); any other `\<char>` is a literal-character escape and
/// resolves to that character. Returns `None` (fail closed) on a dangling trailing
/// backslash or when the decoded bytes are not valid UTF-8 — never silently drops
/// a backslash or yields a corrupted identity (issue #21, cluster 2).
fn unescape_rfc2253_value(value: &str) -> Option<String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    // Operate on bytes: `\` (0x5C) and ASCII hex digits are never UTF-8
    // continuation bytes, so byte indexing across them is sound; non-escaped
    // multi-byte characters are copied through verbatim.
    let bytes = inner.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // `\` must be followed by at least one character.
        let Some(&next) = bytes.get(i + 1) else {
            return None; // dangling backslash → malformed, fail closed
        };
        match bytes.get(i + 2) {
            // `\<hexpair>` byte escape: decode the two hex digits to one byte.
            Some(&after) if next.is_ascii_hexdigit() && after.is_ascii_hexdigit() => {
                let hi = (next as char).to_digit(16)?;
                let lo = (after as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            // `\<char>` literal-character escape: keep the literal following byte.
            _ => {
                out.push(next);
                i += 2;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Decides whether a request's verified `signer` is bound to the transport
/// identity. A failure is always [`McpsError::TransportBindingFailed`].
pub trait TransportBindingPolicy {
    /// `Ok(())` iff `signer` is bound to `identity`; otherwise
    /// [`McpsError::TransportBindingFailed`].
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpsError>;
}

/// The strongest default: the request `signer` must equal the verified transport
/// identity (the key-holder is the cert-holder). A required identity that is
/// absent fails closed.
#[derive(Debug, Clone, Default)]
pub struct ExactMatchBinding;

impl ExactMatchBinding {
    /// Construct the exact-match policy.
    pub fn new() -> Self {
        ExactMatchBinding
    }
}

impl TransportBindingPolicy for ExactMatchBinding {
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpsError> {
        match identity {
            Some(identity) if identity.value == signer => Ok(()),
            _ => Err(McpsError::TransportBindingFailed),
        }
    }
}

/// Cross-namespace binding: each `signer` maps to a set of allowed transport
/// identities (e.g. a DID signer permitted over one or more SPIFFE IDs). A signer
/// with no mapping, or an identity outside its set (or absent), fails closed.
///
/// This is a STRICT, EXPLICIT allowlist: matches are by exact string equality
/// only. There are deliberately no wildcards, no globs, and no regular
/// expressions — every permitted `(signer, identity)` pair is enumerated and
/// auditable, and any pair not enumerated is denied. A literal `"*"` is just an
/// ordinary string with no special meaning.
#[derive(Debug, Clone, Default)]
pub struct MappedBinding {
    allowed: BTreeMap<String, BTreeSet<String>>,
}

impl MappedBinding {
    /// An empty mapping (every signer fails closed until permitted).
    pub fn new() -> Self {
        MappedBinding {
            allowed: BTreeMap::new(),
        }
    }

    /// Permit `signer` to arrive over the transport identity `identity`.
    pub fn permit(&mut self, signer: impl Into<String>, identity: impl Into<String>) {
        self.allowed
            .entry(signer.into())
            .or_default()
            .insert(identity.into());
    }
}

impl TransportBindingPolicy for MappedBinding {
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpsError> {
        let identity = identity.ok_or(McpsError::TransportBindingFailed)?;
        match self.allowed.get(signer) {
            Some(set) if set.contains(&identity.value) => Ok(()),
            _ => Err(McpsError::TransportBindingFailed),
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 3 (ADR-MCPS-023, future-boundary, issue #71): LB-signed, request-bound
// ingress assertion.
// ---------------------------------------------------------------------------

/// The frozen domain-separation tag prefixed to every Tier-3 assertion preimage.
/// It namespaces the signature so an LB key reused for some other purpose cannot
/// produce bytes that an attacker can re-frame as an MCP-S ingress assertion. The
/// trailing version byte (`v1`) lets the preimage format evolve without ambiguity.
const LB_ASSERTION_DOMAIN_TAG: &[u8] = b"mcps/lb-ingress-assertion/v1";

/// The default freshness window (seconds) for a Tier-3 LB assertion: how far the
/// assertion's `validation_time` may lag behind the node's `now_unix` and still be
/// accepted. Small by design — the LB signs the assertion at the moment it admits
/// the request, so a legitimate assertion reaches the node within seconds.
pub const DEFAULT_LB_ASSERTION_MAX_AGE_SECS: i64 = 30;

/// A trusted LB verification key, addressed by its key id, used to verify Tier-3
/// LB-signed assertions. The key id is the opaque label the LB stamps into the
/// assertion's `key_id` field; the node looks the verification key up by it.
#[derive(Debug, Clone)]
struct LbKeyEntry {
    /// The LB key id (matches the assertion's `key_id` field byte-for-byte).
    key_id: String,
    /// The Ed25519 verification (public) key for this key id.
    key: VerificationKey,
}

/// The parsed fields of a Tier-3 LB-signed ingress assertion (ADR-MCPS-023).
///
/// The assertion ties a **specific MCP-S request** (by its `request_hash`) to the
/// asserted client identity, signed by the load balancer. Unlike the Tier-2
/// trusted-ingress header — which the node trusts solely over the authenticated
/// LB↔node hop — a Tier-3 assertion lets the node CRYPTOGRAPHICALLY verify that
/// the ingress bound its assertion to the exact request the node holds in hand.
///
/// # Honesty boundary
///
/// This is **request-bound ingress assertion**, NOT end-to-end client↔node
/// binding. The LB still terminates the client's mTLS and re-asserts the client
/// identity; the node verifies the LB's signature and the request binding, not the
/// client's own key. It MUST NOT be presented as equivalent to `end_to_end_mtls`
/// (Tier 1). See [`LbAssertionBinding::GUARANTEE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LbAssertion {
    /// The LB key id naming the verification key that signed this assertion.
    pub key_id: String,
    /// The asserted client identity (e.g. `spiffe://example.org/agent-1`).
    pub asserted_client_identity: String,
    /// The MCP-S request hash the assertion is bound to, as the
    /// `sha256:<base64url>` hash identifier (MCPS_SPEC §3).
    pub request_hash: String,
    /// The LB's assertion time as a Unix timestamp (seconds). Freshness is checked
    /// against the node's `now_unix`.
    pub validation_time: i64,
}

impl LbAssertion {
    /// The deterministic, UNAMBIGUOUS canonical preimage the LB signs and the node
    /// re-derives to verify.
    ///
    /// Encoding is **length-prefixed framing**, NOT delimiter-joining, so no field
    /// value can ever collide with a delimiter to forge a different field split
    /// (the classic `a|b` vs `a` + `|b` ambiguity). The layout is:
    ///
    /// ```text
    /// LB_ASSERTION_DOMAIN_TAG
    /// || len(key_id)                    as u64 big-endian || key_id bytes
    /// || len(asserted_client_identity)  as u64 big-endian || identity bytes
    /// || len(request_hash)              as u64 big-endian || request_hash bytes
    /// || validation_time                as i64 big-endian (fixed 8 bytes)
    /// ```
    ///
    /// Every variable-length field is preceded by its exact byte length, so the
    /// byte stream parses to exactly one field tuple — two distinct field tuples
    /// can never produce the same preimage. The fixed-width integer needs no
    /// length prefix.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(LB_ASSERTION_DOMAIN_TAG);
        for field in [
            self.key_id.as_bytes(),
            self.asserted_client_identity.as_bytes(),
            self.request_hash.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.validation_time.to_be_bytes());
        out
    }
}

/// A node-side verifier for Tier-3 LB-signed, request-bound ingress assertions
/// (ADR-MCPS-023 future boundary, issue #71).
///
/// It holds a small in-proxy trust map of LB verification keys (keyed by key id)
/// and, given a presented assertion + the request hash the node already holds in
/// hand + the current time, yields a VERIFIED [`TransportIdentity`] only after a
/// strict, ordered, fail-closed sequence of checks (see [`Self::verify`]). The
/// resulting identity then flows into the SAME [`TransportBindingPolicy`] the
/// direct-TLS / Tier-2 paths use — this type does the cryptographic request-
/// binding; the binding policy ties the verified identity to the request signer.
///
/// # SECURITY — what this does and does NOT prove
///
/// This is **request-bound ingress assertion**, NOT end-to-end client↔node mTLS.
/// The node verifies the LB's signature over the (identity, request-hash, time)
/// tuple — proving the trusted LB asserted *this* client identity for *this*
/// request — but the client's own key never reaches the node. The LB remains in
/// the trusted computing base. The guarantee MUST NOT be surfaced as equivalent
/// to `end_to_end_mtls` (Tier 1); see [`Self::GUARANTEE`].
#[derive(Debug, Clone)]
pub struct LbAssertionBinding {
    /// Trusted LB verification keys, addressed by key id.
    keys: Vec<LbKeyEntry>,
    /// The identity source reported on the yielded [`TransportIdentity`].
    source: IdentitySource,
    /// Maximum accepted assertion age (seconds) relative to `now_unix`.
    max_age_secs: i64,
}

/// Why a Tier-3 LB assertion was rejected. Every variant fails closed (no identity
/// is yielded). Surfaced for tests and audit; the proxy maps any rejection to
/// [`McpsError::TransportBindingFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbAssertionRejection {
    /// The assertion bytes are malformed (bad framing / not valid UTF-8 / bad
    /// base64) or a field violates the strict asserted-identity shape rules.
    Malformed,
    /// The assertion names a `key_id` not present in the trust map (fail closed —
    /// an unknown LB key is never admitted).
    UnknownKeyId,
    /// The Ed25519 signature does not verify under the named LB key.
    BadSignature,
    /// The assertion's bound `request_hash` does not equal the in-hand request hash
    /// (a cross-request / wrong-hash assertion).
    RequestHashMismatch,
    /// The assertion's `validation_time` is outside the freshness window (too old,
    /// or implausibly far in the future).
    Stale,
}

impl LbAssertionBinding {
    /// The honest Tier-3 guarantee string. Deliberately NOT `end_to_end_mtls`: the
    /// node cryptographically verifies that the trusted ingress bound its assertion
    /// to THIS request, but the client's own key never reaches the node, so this is
    /// request-bound ingress assertion, not end-to-end client↔node channel binding.
    pub const GUARANTEE: &'static str = "request_bound_ingress_assertion";

    /// Build a verifier with no trusted keys yet (every assertion fails closed
    /// until a key is added) and the default freshness window
    /// ([`DEFAULT_LB_ASSERTION_MAX_AGE_SECS`]). `source` is the [`IdentitySource`]
    /// stamped on the yielded identity (mirrors the configured identity policy).
    pub fn new(source: IdentitySource) -> Self {
        LbAssertionBinding {
            keys: Vec::new(),
            source,
            max_age_secs: DEFAULT_LB_ASSERTION_MAX_AGE_SECS,
        }
    }

    /// Override the freshness window (seconds).
    pub fn with_max_age_secs(mut self, max_age_secs: i64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    /// Add a trusted LB verification key addressed by `key_id`. A duplicate
    /// `key_id` REPLACES the prior key for that id (last write wins) so a rotating
    /// deployment cannot end up with two live keys for one id.
    pub fn add_key(&mut self, key_id: impl Into<String>, key: VerificationKey) {
        let key_id = key_id.into();
        self.keys.retain(|entry| entry.key_id != key_id);
        self.keys.push(LbKeyEntry { key_id, key });
    }

    /// Look up a trusted LB verification key by key id.
    fn key_for(&self, key_id: &str) -> Option<&VerificationKey> {
        self.keys
            .iter()
            .find(|entry| entry.key_id == key_id)
            .map(|entry| &entry.key)
    }

    /// Parse a presented Tier-3 assertion header value into its fields.
    ///
    /// Wire form (single header value): four `.`-separated base64url-no-pad fields
    /// — `key_id . asserted_client_identity . request_hash . validation_time` —
    /// followed by the base64url-no-pad Ed25519 `signature` as a fifth field:
    /// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>`. Each
    /// textual field is base64url-encoded so it can never contain the `.`
    /// separator; this is a TRANSPORT encoding only — the SIGNATURE preimage is the
    /// length-prefixed [`LbAssertion::signing_preimage`], which is what defeats the
    /// delimiter-collision class. Any framing / decoding / shape violation fails
    /// closed as [`LbAssertionRejection::Malformed`].
    fn parse(value: &str) -> Result<(LbAssertion, String), LbAssertionRejection> {
        let trimmed = value.trim();
        // Bound total length up front (anti-DoS / smuggling), reusing the asserted-
        // identity ceiling generously across the whole assertion.
        if trimmed.is_empty() || trimmed.len() > MAX_ASSERTED_IDENTITY_LEN {
            return Err(LbAssertionRejection::Malformed);
        }
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 5 {
            return Err(LbAssertionRejection::Malformed);
        }
        let key_id = decode_b64url_field(parts[0])?;
        let asserted_client_identity = decode_b64url_field(parts[1])?;
        let request_hash = decode_b64url_field(parts[2])?;
        let validation_time_bytes = b64url_decode(parts[3]).map_err(|_| LbAssertionRejection::Malformed)?;
        // Fixed 8-byte big-endian i64.
        let validation_time = i64::from_be_bytes(
            validation_time_bytes
                .as_slice()
                .try_into()
                .map_err(|_| LbAssertionRejection::Malformed)?,
        );
        // The signature is carried as the raw base64url string (verify_ed25519_with
        // decodes + length-checks it); a non-base64url signature fails closed there.
        let signature_b64url = parts[4].to_string();
        if signature_b64url.is_empty() {
            return Err(LbAssertionRejection::Malformed);
        }
        // Strict shape on the asserted identity (length-bound, no control chars,
        // non-empty), mirroring the Tier-2 header path.
        if validate_asserted_identity_value(&asserted_client_identity).is_err() {
            return Err(LbAssertionRejection::Malformed);
        }
        // key_id and request_hash must be non-empty and control-char-free too.
        if key_id.is_empty()
            || request_hash.is_empty()
            || key_id.chars().any(|c| c.is_control())
            || request_hash.chars().any(|c| c.is_control())
        {
            return Err(LbAssertionRejection::Malformed);
        }
        Ok((
            LbAssertion {
                key_id,
                asserted_client_identity,
                request_hash,
                validation_time,
            },
            signature_b64url,
        ))
    }

    /// Verify a presented Tier-3 assertion against the in-hand request hash and the
    /// current time, yielding the VERIFIED client identity on success.
    ///
    /// Ordered, fail-closed checks (ADR-MCPS-023 future boundary, issue #71):
    /// 1. **Parse** the assertion; malformed framing/shape ⇒ `Malformed`.
    /// 2. **Key lookup** — an unknown `key_id` ⇒ `UnknownKeyId` (fail closed; never
    ///    admit an assertion signed by a key the node does not trust).
    /// 3. **Signature** — Ed25519-verify the LB signature over the length-prefixed
    ///    [`LbAssertion::signing_preimage`]; mismatch ⇒ `BadSignature`.
    /// 4. **Request binding** — the assertion's `request_hash` MUST equal the
    ///    in-hand request hash; mismatch (cross-request / wrong hash) ⇒
    ///    `RequestHashMismatch`.
    /// 5. **Freshness** — `validation_time` MUST be within the window
    ///    `[now - max_age, now + max_age]`; outside ⇒ `Stale`.
    ///
    /// # Replay
    ///
    /// An assertion replayed against a DIFFERENT request fails check 4 (its bound
    /// hash will not match the new request's hash). An assertion replayed against
    /// the SAME request is caught by that request's OWN replay protection
    /// (`verify_request` runs the replay cache BEFORE this binding ever executes),
    /// and additionally ages out of the freshness window (check 5). The assertion
    /// therefore carries no independent nonce — request-hash binding plus freshness
    /// plus the request's replay cache cover it.
    pub fn verify(
        &self,
        assertion_value: &str,
        in_hand_request_hash: &str,
        now_unix: i64,
    ) -> Result<TransportIdentity, LbAssertionRejection> {
        // 1. Parse (framing + strict field shape).
        let (assertion, signature_b64url) = Self::parse(assertion_value)?;
        // 2. Key lookup — unknown key id fails closed.
        let key = self
            .key_for(&assertion.key_id)
            .ok_or(LbAssertionRejection::UnknownKeyId)?;
        // 3. Signature over the length-prefixed canonical preimage.
        let preimage = assertion.signing_preimage();
        verify_ed25519_with(
            &preimage,
            &signature_b64url,
            key,
            McpsError::TransportBindingFailed,
        )
        .map_err(|_| LbAssertionRejection::BadSignature)?;
        // 4. Request binding — compare the bound hash to the in-hand hash. Compare
        //    the parsed 32-byte digests so two encodings of the same digest match
        //    and a malformed bound hash fails closed.
        let bound = parse_hash_id(&assertion.request_hash)
            .map_err(|_| LbAssertionRejection::RequestHashMismatch)?;
        let in_hand = parse_hash_id(in_hand_request_hash)
            .map_err(|_| LbAssertionRejection::RequestHashMismatch)?;
        if bound != in_hand {
            return Err(LbAssertionRejection::RequestHashMismatch);
        }
        // 5. Freshness window (symmetric: reject implausibly-future timestamps too).
        let age = now_unix.saturating_sub(assertion.validation_time);
        if age > self.max_age_secs || age < -self.max_age_secs {
            return Err(LbAssertionRejection::Stale);
        }
        Ok(TransportIdentity::new(
            assertion.asserted_client_identity,
            self.source,
        ))
    }
}

/// Decode one base64url-no-pad assertion field to a UTF-8 string; any decode or
/// UTF-8 error fails closed as [`LbAssertionRejection::Malformed`].
fn decode_b64url_field(field: &str) -> Result<String, LbAssertionRejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionRejection::Malformed)?;
    String::from_utf8(bytes).map_err(|_| LbAssertionRejection::Malformed)
}

#[cfg(test)]
mod tests {
    use super::ExactMatchBinding;
    use super::IdentityPolicy;
    use super::IdentitySource;
    use super::LbAssertion;
    use super::LbAssertionBinding;
    use super::LbAssertionRejection;
    use super::MappedBinding;
    use super::RequestHeaders;
    use super::ReverseProxyHeaderFormat;
    use super::ReverseProxyMtlsProvider;
    use super::StaticIdentityProvider;
    use super::TransportBindingPolicy;
    use super::TransportBindingProvider;
    use super::TransportIdentity;
    use mcps_core::b64url_encode;
    use mcps_core::sha256_hash_id;
    use mcps_core::McpsError;
    use mcps_core::SigningKey;

    fn spiffe(value: &str) -> TransportIdentity {
        TransportIdentity::new(value, IdentitySource::UriSan)
    }

    /// A request carrying a single header (the common reverse-proxy fixture).
    fn req_with(name: &str, value: &str) -> RequestHeaders {
        RequestHeaders::from_pairs([(name, value)])
    }

    #[test]
    fn static_provider_yields_its_identity_ignoring_request() {
        let id = spiffe("spiffe://example.org/agent-1");
        let provider = StaticIdentityProvider::new(Some(id.clone()));
        // The request argument is ignored: same identity regardless of headers.
        let empty = RequestHeaders::default();
        let populated = req_with("x-forwarded-client-cert", "URI=spiffe://other");
        assert_eq!(provider.verified_identity(&empty), Some(id.clone()));
        assert_eq!(provider.verified_identity(&populated), Some(id));
        assert_eq!(
            StaticIdentityProvider::new(None).verified_identity(&empty),
            None
        );
    }

    // --- MCPS-3840 reverse-proxy header identity extraction -------------------

    #[test]
    fn plain_header_yields_identity_with_configured_source() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-client-identity",
            ReverseProxyHeaderFormat::Plain,
            IdentityPolicy::UriSan,
        );
        let req = req_with("x-client-identity", "spiffe://example.org/agent-1");
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new(
                "spiffe://example.org/agent-1",
                IdentitySource::UriSan
            ))
        );
    }

    #[test]
    fn plain_header_lookup_is_case_insensitive_and_trims() {
        let provider = ReverseProxyMtlsProvider::new(
            "X-Client-Identity",
            ReverseProxyHeaderFormat::Plain,
            IdentityPolicy::DnsSan,
        );
        // Mixed-case header name on the wire, surrounding whitespace in value.
        let req = req_with("x-CLIENT-identity", "  agent-1.example.org  ");
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent-1.example.org", IdentitySource::DnsSan))
        );
    }

    #[test]
    fn xfcc_uri_field_yields_uri_san() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "By=spiffe://example.org/ingress;Hash=abc123;URI=spiffe://example.org/agent-1",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new(
                "spiffe://example.org/agent-1",
                IdentitySource::UriSan
            ))
        );
    }

    #[test]
    fn xfcc_dns_field_yields_dns_san() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::DnsSan,
        );
        let req = req_with("x-forwarded-client-cert", "Hash=abc;DNS=agent-1.example.org");
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent-1.example.org", IdentitySource::DnsSan))
        );
    }

    #[test]
    fn xfcc_subject_field_yields_common_name() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        // Envoy quotes the Subject DN because it contains commas.
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"CN=agent-1,OU=agents,O=example\"",
        );
        // M23 (#4080): the CN is extracted from the Subject DN so it equals the
        // direct-TLS CnLegacy extraction (the bare CN), NOT the whole RFC2253 DN.
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent-1", IdentitySource::CommonName))
        );
    }

    #[test]
    fn xfcc_subject_cn_is_extracted_regardless_of_attribute_order() {
        // The CN may appear after other RDNs; it is still the extracted component.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"O=example,OU=agents,CN=agent-1\"",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent-1", IdentitySource::CommonName))
        );
    }

    #[test]
    fn xfcc_subject_with_escaped_comma_in_cn_is_extracted() {
        // An RFC2253-escaped comma inside the CN value must not split the RDN; the
        // unescaped CN is returned (parity with how a real cert's CN reads).
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"CN=agent\\,one,OU=agents\"",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent,one", IdentitySource::CommonName))
        );
    }

    #[test]
    fn xfcc_subject_without_cn_yields_none() {
        // A Subject DN that carries no CN attribute has no CN to bind to: fail
        // closed rather than fall back to the whole DN or another attribute.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"OU=agents,O=example\"",
        );
        assert_eq!(provider.verified_identity(&req), None);
    }

    #[test]
    fn xfcc_explicit_cn_field_yields_common_name() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with("x-forwarded-client-cert", "Hash=abc;CN=agent-1");
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new("agent-1", IdentitySource::CommonName))
        );
    }

    #[test]
    fn absent_header_yields_none() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        // A different header is present, but not the trusted one.
        let req = req_with("content-type", "application/json");
        assert_eq!(provider.verified_identity(&req), None);
        assert_eq!(provider.verified_identity(&RequestHeaders::default()), None);
    }

    #[test]
    fn empty_header_yields_none() {
        let plain = ReverseProxyMtlsProvider::new(
            "x-client-identity",
            ReverseProxyHeaderFormat::Plain,
            IdentityPolicy::UriSan,
        );
        assert_eq!(
            plain.verified_identity(&req_with("x-client-identity", "   ")),
            None
        );
        let xfcc = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        assert_eq!(
            xfcc.verified_identity(&req_with("x-forwarded-client-cert", "")),
            None
        );
    }

    #[test]
    fn xfcc_missing_selected_field_yields_none() {
        // The policy wants a URI SAN, but the header carries only DNS/Subject.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;DNS=agent-1.example.org;Subject=\"CN=agent-1\"",
        );
        assert_eq!(
            provider.verified_identity(&req),
            None,
            "a missing URI SAN must NOT silently downgrade to DNS or Subject"
        );
    }

    #[test]
    fn xfcc_malformed_value_yields_none() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        // No key=value pairs at all.
        assert_eq!(
            provider.verified_identity(&req_with("x-forwarded-client-cert", "garbage-not-xfcc")),
            None
        );
        // The selected field is present but empty.
        assert_eq!(
            provider.verified_identity(&req_with("x-forwarded-client-cert", "Hash=abc;URI=")),
            None
        );
    }

    #[test]
    fn xfcc_conflicting_entries_yield_none() {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        // Two cert elements present DIFFERENT URI SANs: ambiguous → fail closed.
        let req = req_with(
            "x-forwarded-client-cert",
            "URI=spiffe://example.org/agent-1,URI=spiffe://example.org/agent-2",
        );
        assert_eq!(provider.verified_identity(&req), None);
    }

    #[test]
    fn xfcc_repeated_identical_field_is_accepted() {
        // The SAME value repeated across elements is not a conflict.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "URI=spiffe://example.org/agent-1,URI=spiffe://example.org/agent-1",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new(
                "spiffe://example.org/agent-1",
                IdentitySource::UriSan
            ))
        );
    }

    // --- Issue #21 (cluster 2): ADR-MCPS-023 strict rules on the XFCC value -----

    #[test]
    fn xfcc_oversized_value_yields_none() {
        // ADR-MCPS-023: the XFCC-derived identity must be length-bounded, exactly
        // as the plain path is. An over-long URI SAN must fail closed (the gap
        // before #21: only parse_plain validated length).
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let huge = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN + 1);
        let req = req_with("x-forwarded-client-cert", &format!("Hash=abc;URI={huge}"));
        assert_eq!(
            provider.verified_identity(&req),
            None,
            "an oversized XFCC identity must fail closed, not be returned unbounded"
        );
        // The inclusive boundary is still accepted (proves it's a bound, not a
        // blanket rejection).
        let at_bound = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN);
        let ok = req_with("x-forwarded-client-cert", &format!("URI={at_bound}"));
        assert_eq!(
            provider.verified_identity(&ok),
            Some(TransportIdentity::new(at_bound, IdentitySource::UriSan))
        );
    }

    #[test]
    fn xfcc_control_character_value_yields_none() {
        // A control character in the XFCC-derived identity (header-smuggling /
        // log-injection risk) must fail closed — previously only parse_plain ran
        // this check.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;URI=spiffe://example.org/age\x07nt-1",
        );
        assert_eq!(provider.verified_identity(&req), None);
    }

    #[test]
    fn xfcc_subject_cn_rfc2253_hex_byte_escape_is_decoded() {
        // RFC2253 §2.4 `\<hexpair>` byte escape: `\41` is the byte 0x41 = 'A'.
        // It must be DECODED (not silently backslash-dropped to "41").
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"CN=\\41gent-1,OU=agents\"",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new(
                "Agent-1",
                IdentitySource::CommonName
            )),
            "\\41 must decode to the byte 'A', not collapse to literal '41'"
        );
    }

    #[test]
    fn xfcc_subject_cn_invalid_utf8_byte_escape_yields_none() {
        // A lone continuation byte (`\80`) cannot start a valid UTF-8 sequence;
        // decoding it yields invalid UTF-8 → fail closed rather than emit a
        // corrupted identity.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "Hash=abc;Subject=\"CN=\\80,OU=agents\"",
        );
        assert_eq!(provider.verified_identity(&req), None);
    }

    #[test]
    fn xfcc_identity_sourced_only_from_element_carrying_the_field() {
        // Element-aware selection: one cert element lacks the URI field entirely,
        // a second element carries it. The single usable element supplies the
        // identity; a non-selected element is never the source of a conflict.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "By=spiffe://example.org/ingress;Hash=deadbeef,\
             Hash=abc123;URI=spiffe://example.org/agent-1",
        );
        assert_eq!(
            provider.verified_identity(&req),
            Some(TransportIdentity::new(
                "spiffe://example.org/agent-1",
                IdentitySource::UriSan
            ))
        );
    }

    #[test]
    fn xfcc_unterminated_quote_fails_closed() {
        // Issue #21 residual: a stray opening quote with no close would leave the
        // splitter "inside a quote" for the rest of the value, swallowing the comma
        // and COLLAPSING two cert elements into one — so a conflicting/forged
        // element hides behind the first and the cross-element conflict check never
        // fires. With balanced quotes the same two URIs are a conflict (fail
        // closed); the unterminated-quote form must ALSO fail closed, never resolve
        // to the first identity.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with(
            "x-forwarded-client-cert",
            "URI=\"spiffe://example.org/agent-1,URI=spiffe://example.org/evil",
        );
        assert_eq!(
            provider.verified_identity(&req),
            None,
            "an unterminated XFCC quote must fail closed, never collapse elements"
        );

        // A stray quote inside an otherwise single element must also fail closed.
        let req2 = req_with("x-forwarded-client-cert", "Hash=abc;URI=spiffe://x\"");
        assert_eq!(provider.verified_identity(&req2), None);
    }

    #[test]
    fn duplicated_trust_header_yields_none() {
        // A second copy of the trusted header (e.g. injected downstream) is a
        // spoofing signal: fail closed rather than pick one.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = RequestHeaders::from_pairs([
            ("x-forwarded-client-cert", "URI=spiffe://example.org/agent-1"),
            ("x-forwarded-client-cert", "URI=spiffe://example.org/evil"),
        ]);
        assert_eq!(provider.verified_identity(&req), None);
    }

    #[test]
    fn request_headers_parse_skips_request_line_and_is_case_insensitive() {
        let block = "POST /mcp HTTP/1.1\r\nHost: proxy\r\nX-Forwarded-Client-Cert: URI=spiffe://x\r\n\r\n";
        let headers = RequestHeaders::parse(block);
        assert_eq!(headers.first("host"), Some("proxy"));
        assert_eq!(headers.first("X-Forwarded-Client-Cert"), Some("URI=spiffe://x"));
        assert_eq!(headers.first("POST"), None, "the request line is not a header");
        assert_eq!(headers.count("x-forwarded-client-cert"), 1);
    }

    #[test]
    fn reverse_proxy_identity_feeds_the_binding_policy_unchanged() {
        // End-to-end intent: the extracted identity flows into the SAME
        // ExactMatchBinding the direct-TLS path uses — the policy is unaware of
        // where the identity came from.
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::UriSan,
        );
        let req = req_with("x-forwarded-client-cert", "URI=spiffe://example.org/agent-1");
        let identity = provider.verified_identity(&req);
        let policy = ExactMatchBinding::new();
        assert!(policy
            .check("spiffe://example.org/agent-1", identity.as_ref())
            .is_ok());
        // A signer that does not match the header-derived identity is rejected.
        assert_eq!(
            policy
                .check("spiffe://example.org/other", identity.as_ref())
                .unwrap_err(),
            McpsError::TransportBindingFailed
        );
    }

    #[test]
    fn exact_match_binds_equal_signer_and_identity() {
        let policy = ExactMatchBinding::new();
        let id = spiffe("did:example:agent-1");
        assert!(policy.check("did:example:agent-1", Some(&id)).is_ok());
    }

    #[test]
    fn exact_match_rejects_mismatch_and_absence() {
        let policy = ExactMatchBinding::new();
        let id = spiffe("did:example:other");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&id)).unwrap_err(),
            McpsError::TransportBindingFailed
        );
        assert_eq!(
            policy.check("did:example:agent-1", None).unwrap_err(),
            McpsError::TransportBindingFailed
        );
    }

    #[test]
    fn mapped_binding_honours_the_allow_set() {
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "spiffe://example.org/agent-1");
        let ok = spiffe("spiffe://example.org/agent-1");
        assert!(policy.check("did:example:agent-1", Some(&ok)).is_ok());

        // Identity outside the set.
        let bad = spiffe("spiffe://example.org/evil");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&bad)).unwrap_err(),
            McpsError::TransportBindingFailed
        );
        // Signer with no mapping.
        assert_eq!(
            policy.check("did:example:unmapped", Some(&ok)).unwrap_err(),
            McpsError::TransportBindingFailed
        );
        // Absent identity.
        assert_eq!(
            policy.check("did:example:agent-1", None).unwrap_err(),
            McpsError::TransportBindingFailed
        );
    }

    #[test]
    fn mapped_binding_has_no_wildcard_semantics() {
        // A literal "*" is an ordinary string, not a wildcard: permitting "*"
        // for a signer must NOT permit some other concrete identity.
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "*");
        let star = spiffe("*");
        assert!(
            policy.check("did:example:agent-1", Some(&star)).is_ok(),
            "the literal '*' identity matches the literal '*' entry"
        );
        let concrete = spiffe("spiffe://example.org/agent-1");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&concrete)).unwrap_err(),
            McpsError::TransportBindingFailed,
            "'*' must NOT act as a wildcard over concrete identities"
        );
    }

    #[test]
    fn mapped_binding_matches_are_exact_and_case_sensitive() {
        // Matching is byte-exact: no case folding, no trimming, no normalization.
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "spiffe://example.org/agent-1");
        let differing_case = spiffe("spiffe://example.org/AGENT-1");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&differing_case)).unwrap_err(),
            McpsError::TransportBindingFailed,
            "identity match is case-sensitive"
        );
        // Signer is matched exactly too.
        let ok = spiffe("spiffe://example.org/agent-1");
        assert_eq!(
            policy.check("DID:EXAMPLE:AGENT-1", Some(&ok)).unwrap_err(),
            McpsError::TransportBindingFailed,
            "signer match is case-sensitive"
        );
    }

    // ADR-MCPS-023: strict asserted-identity header validation.
    #[test]
    fn asserted_identity_accepts_a_well_formed_value_and_trims() {
        assert_eq!(
            super::validate_asserted_identity_value("  spiffe://example.org/agent-1  "),
            Ok("spiffe://example.org/agent-1")
        );
    }

    #[test]
    fn asserted_identity_rejects_empty() {
        assert_eq!(
            super::validate_asserted_identity_value("   "),
            Err(super::AssertedIdentityRejection::Empty)
        );
    }

    #[test]
    fn asserted_identity_rejects_oversized() {
        let huge = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN + 1);
        assert_eq!(
            super::validate_asserted_identity_value(&huge),
            Err(super::AssertedIdentityRejection::TooLong)
        );
        // Exactly at the bound is accepted.
        let at_bound = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN);
        assert!(super::validate_asserted_identity_value(&at_bound).is_ok());
    }

    #[test]
    fn asserted_identity_rejects_control_characters() {
        // CR/LF (header smuggling / log injection), NUL, and a bare control char.
        for bad in ["agent\r\nX-Spoof: y", "agent\nid", "agent\0id", "ag\u{7}ent"] {
            assert_eq!(
                super::validate_asserted_identity_value(bad),
                Err(super::AssertedIdentityRejection::Malformed),
                "control characters must fail closed: {bad:?}"
            );
        }
    }

    // ---- ADR-MCPS-025 routing-header hygiene ----------------------------------

    #[test]
    fn routing_headers_absent_pass() {
        // Mcp-Method / Mcp-Name are optional hints; absent is fine.
        let headers = super::RequestHeaders::default();
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn routing_headers_well_formed_pass() {
        let headers = super::RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "echo"),
        ]);
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn duplicate_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Duplicate {
                header: super::MCP_METHOD_HEADER
            })
        );
    }

    #[test]
    fn malformed_routing_header_fails_closed() {
        // A CRLF-laced routing header is a smuggling vector — fail closed even
        // though the proxy never routes on it.
        let headers =
            super::RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_NAME_HEADER
            })
        );
    }

    #[test]
    fn empty_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([("Mcp-Method", "   ")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_METHOD_HEADER
            })
        );
    }

    #[test]
    fn reverse_proxy_plain_provider_fails_closed_on_malformed_value() {
        // The provider's plain path now enforces the ADR-023 rules: a CRLF-laced
        // value yields no identity (fail closed), not a smuggled one.
        let provider = super::ReverseProxyMtlsProvider::new(
            "x-client-identity",
            super::ReverseProxyHeaderFormat::Plain,
            super::IdentityPolicy::UriSan,
        );
        let headers = super::RequestHeaders::from_pairs([(
            "x-client-identity",
            "spiffe://example.org/a\r\nX-Spoof: evil",
        )]);
        assert!(
            super::TransportBindingProvider::verified_identity(&provider, &headers).is_none(),
            "a control-char-laced plain identity header must fail closed"
        );
    }

    // ---- ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound assertion ----

    /// A fixed LB signing seed so the minted assertions are reproducible in-test.
    const LB_SEED: [u8; 32] = [42u8; 32];

    /// The request hash the node holds in hand for the request under test.
    fn in_hand_request_hash() -> String {
        sha256_hash_id(br#"{"jsonrpc":"2.0","method":"tools/call","id":1}"#)
    }

    /// Mint a wire-form Tier-3 assertion: the five `.`-separated base64url fields
    /// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>`, signed by
    /// `signer` over the length-prefixed canonical preimage.
    fn mint_assertion(
        signer: &SigningKey,
        key_id: &str,
        identity: &str,
        request_hash: &str,
        validation_time: i64,
    ) -> String {
        let assertion = LbAssertion {
            key_id: key_id.to_string(),
            asserted_client_identity: identity.to_string(),
            request_hash: request_hash.to_string(),
            validation_time,
        };
        let signature = signer.sign(&assertion.signing_preimage());
        format!(
            "{}.{}.{}.{}.{}",
            b64url_encode(key_id.as_bytes()),
            b64url_encode(identity.as_bytes()),
            b64url_encode(request_hash.as_bytes()),
            b64url_encode(&validation_time.to_be_bytes()),
            signature,
        )
    }

    /// A verifier trusting the LB key `lb-1` under the given seed.
    fn binding_with_lb_key(seed: &[u8; 32]) -> LbAssertionBinding {
        let mut binding = LbAssertionBinding::new(IdentitySource::UriSan);
        binding.add_key("lb-1", SigningKey::from_seed_bytes(seed).public_key());
        binding
    }

    #[test]
    fn lb_assertion_bound_to_in_hand_request_is_accepted() {
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(
            &lb,
            "lb-1",
            "spiffe://example.org/agent-1",
            &rh,
            now,
        );
        // The verified identity is yielded, then binds to the matching signer via
        // the SAME ExactMatchBinding the direct-TLS / Tier-2 paths use.
        let identity = binding
            .verify(&assertion, &rh, now)
            .expect("a valid request-bound assertion must be accepted");
        assert_eq!(
            identity,
            TransportIdentity::new("spiffe://example.org/agent-1", IdentitySource::UriSan)
        );
        let policy = ExactMatchBinding::new();
        assert!(
            policy
                .check("spiffe://example.org/agent-1", Some(&identity))
                .is_ok(),
            "the verified Tier-3 identity must bind to its signer"
        );
    }

    #[test]
    fn lb_assertion_cross_request_is_rejected() {
        // A valid signature, but the assertion is bound to a DIFFERENT request hash
        // than the one the node holds in hand: cross-request replay must fail.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let other_request_hash = sha256_hash_id(b"a totally different request body");
        let assertion = mint_assertion(
            &lb,
            "lb-1",
            "spiffe://example.org/agent-1",
            &other_request_hash,
            now,
        );
        assert_eq!(
            binding
                .verify(&assertion, &in_hand_request_hash(), now)
                .unwrap_err(),
            LbAssertionRejection::RequestHashMismatch,
            "an assertion bound to another request must not bind to this one"
        );
    }

    #[test]
    fn lb_assertion_wrong_in_hand_hash_is_rejected() {
        // The assertion is internally consistent and bound to request hash A, but
        // the node presents a DIFFERENT in-hand hash B (e.g. the request was
        // tampered after the LB signed): the binding must fail closed.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion =
            mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        let tampered_in_hand = sha256_hash_id(b"node holds a different request");
        assert_eq!(
            binding.verify(&assertion, &tampered_in_hand, now).unwrap_err(),
            LbAssertionRejection::RequestHashMismatch
        );
    }

    #[test]
    fn lb_assertion_unknown_key_id_is_rejected() {
        // The assertion names a key id the node's trust map does not contain: fail
        // closed (never admit an assertion signed by an untrusted/unknown key).
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED); // trusts only "lb-1"
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(
            &lb,
            "lb-99-unknown",
            "spiffe://example.org/agent-1",
            &rh,
            now,
        );
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::UnknownKeyId
        );
    }

    #[test]
    fn lb_assertion_bad_signature_is_rejected() {
        // Signed by a DIFFERENT LB key than the one the node trusts for "lb-1":
        // the signature does not verify under the trusted key → fail closed.
        let attacker = SigningKey::from_seed_bytes(&[7u8; 32]);
        let binding = binding_with_lb_key(&LB_SEED); // trusts the lb-1 == LB_SEED key
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(
            &attacker,
            "lb-1",
            "spiffe://example.org/agent-1",
            &rh,
            now,
        );
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::BadSignature
        );
    }

    #[test]
    fn lb_assertion_tampered_identity_breaks_signature() {
        // Take a valid assertion and swap the identity field for a higher-privilege
        // one WITHOUT re-signing. The length-prefixed preimage covers the identity,
        // so the signature no longer verifies → fail closed (no privilege escalation).
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion =
            mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        let mut parts: Vec<&str> = assertion.split('.').collect();
        let forged_identity = b64url_encode(b"spiffe://example.org/admin");
        parts[1] = &forged_identity;
        let forged = parts.join(".");
        assert_eq!(
            binding.verify(&forged, &rh, now).unwrap_err(),
            LbAssertionRejection::BadSignature
        );
    }

    #[test]
    fn lb_assertion_stale_is_rejected() {
        // validation_time is far outside the freshness window relative to now.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED); // default 30s window
        let signed_at = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion =
            mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, signed_at);
        // The node evaluates it a full hour later.
        let now = signed_at + 3600;
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Stale
        );
        // The inclusive boundary (exactly max_age old) is still accepted, proving
        // it is a bounded window and not a blanket rejection.
        let at_bound = signed_at + super::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
        assert!(binding.verify(&assertion, &rh, at_bound).is_ok());
    }

    #[test]
    fn lb_assertion_implausibly_future_is_rejected() {
        // A timestamp far in the FUTURE (clock-skew / forgery attempt) is also
        // outside the symmetric window → fail closed.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let rh = in_hand_request_hash();
        let signed_at = 1_000_000;
        let assertion =
            mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, signed_at);
        let now = signed_at - 3600; // assertion claims to be from the future
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Stale
        );
    }

    #[test]
    fn lb_assertion_malformed_framing_is_rejected() {
        let binding = binding_with_lb_key(&LB_SEED);
        let rh = in_hand_request_hash();
        let now = 1_000_000;
        // Wrong field count.
        assert_eq!(
            binding.verify("only.three.fields", &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
        // Empty.
        assert_eq!(
            binding.verify("", &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
        // Non-base64url field.
        assert_eq!(
            binding
                .verify("!!!.!!!.!!!.!!!.!!!", &rh, now)
                .unwrap_err(),
            LbAssertionRejection::Malformed
        );
    }

    #[test]
    fn lb_assertion_malformed_identity_shape_is_rejected() {
        // A CRLF-laced asserted identity (header-smuggling / log-injection) fails
        // the strict shape check even with an otherwise valid signature.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(
            &lb,
            "lb-1",
            "agent\r\nX-Spoof: evil",
            &rh,
            now,
        );
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
    }

    #[test]
    fn lb_assertion_signing_preimage_is_length_prefixed_and_unambiguous() {
        // The length-prefixed framing defeats the delimiter-collision class: moving
        // a byte across a field boundary yields a DIFFERENT preimage, so the two
        // distinct field tuples can never share a signature.
        let a = LbAssertion {
            key_id: "lb".to_string(),
            asserted_client_identity: "ab".to_string(),
            request_hash: "c".to_string(),
            validation_time: 1,
        };
        let b = LbAssertion {
            key_id: "lb".to_string(),
            asserted_client_identity: "a".to_string(),
            request_hash: "bc".to_string(),
            validation_time: 1,
        };
        assert_ne!(
            a.signing_preimage(),
            b.signing_preimage(),
            "shifting a byte across a field boundary MUST change the preimage"
        );
        // Domain-separation tag is present and leads the preimage.
        assert!(a
            .signing_preimage()
            .starts_with(b"mcps/lb-ingress-assertion/v1"));
    }

    #[test]
    fn lb_assertion_guarantee_is_not_end_to_end_mtls() {
        // HONESTY: the Tier-3 guarantee is request-bound ingress assertion and MUST
        // NOT be surfaced as end-to-end client↔node mTLS (Tier 1).
        assert_eq!(
            LbAssertionBinding::GUARANTEE,
            "request_bound_ingress_assertion"
        );
        assert_ne!(LbAssertionBinding::GUARANTEE, "end_to_end_mtls");
        assert!(
            !LbAssertionBinding::GUARANTEE.contains("end_to_end"),
            "the Tier-3 guarantee must not claim end-to-end binding"
        );
    }
}
