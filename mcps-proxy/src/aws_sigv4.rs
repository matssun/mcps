//! Minimal, audited AWS Signature Version 4 signer (ADR-MCPS-028).
//!
//! This is a DELIBERATELY TINY SigV4 implementation — enough to sign the two AWS
//! KMS requests the Ed25519 response signer makes (`GetPublicKey`, `Sign`), and
//! nothing more. It is NOT a general AWS client: no query signing, no presigning,
//! no chunked/streaming payloads, no STS/credential-discovery. The async
//! `aws-sdk-kms`/tokio/Smithy stack is intentionally NOT used — the ADR-MCPS-018
//! lean-sync firewall is a hard architectural constraint, so the proxy stays
//! async-runtime-free (the OCSP path's blocking-`ureq` precedent is the model).
//!
//! Crypto is standard RustCrypto: SHA-256 (`sha2`, already in-closure) and
//! HMAC-SHA256 (`hmac`). No custom cryptography. The signing algorithm is verified
//! against AWS's published `get-vanilla` test vector (see the `tests` module).

use hmac::Hmac;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The SigV4 algorithm label and the credential-scope terminator.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINATOR: &str = "aws4_request";

/// Lowercase hex (SigV4 requires lowercase) — kept local to avoid a `hex` dep.
fn to_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble"));
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    to_hex_lower(&h.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// A single request header (name, value). Names are matched case-insensitively and
/// emitted lowercased in the canonical request.
#[derive(Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Static AWS credentials. Credential DISCOVERY (profiles, IMDS, IRSA, the SDK
/// chain) is deliberately NOT supported here (ADR-MCPS-028): the adapter takes
/// explicit keys (env-sourced by the caller) so there is no hidden network or
/// credential-resolution trap.
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    /// Present only for temporary credentials (STS). When set it is signed in and
    /// sent as `X-Amz-Security-Token`.
    pub session_token: Option<String>,
}

/// The minimal SigV4 signer, bound to a region + service (always `kms` here).
pub struct SigV4Signer {
    credentials: AwsCredentials,
    region: String,
    service: String,
}

/// The headers a signed request must carry, in addition to the caller's own
/// (host, content-type, x-amz-target). Returned by [`SigV4Signer::sign`].
pub struct SignedAuth {
    /// The full `Authorization` header value.
    pub authorization: String,
    /// `X-Amz-Date` (`YYYYMMDDTHHMMSSZ`).
    pub amz_date: String,
    /// `X-Amz-Security-Token` value iff temporary credentials were used.
    pub security_token: Option<String>,
}

impl SigV4Signer {
    pub fn new(credentials: AwsCredentials, region: String, service: String) -> Self {
        SigV4Signer {
            credentials,
            region,
            service,
        }
    }

    /// The `YYYYMMDD` credential-scope date carved from an `amz_date`.
    fn datestamp(amz_date: &str) -> &str {
        &amz_date[..8]
    }

    fn scope(&self, amz_date: &str) -> String {
        format!(
            "{}/{}/{}/{}",
            Self::datestamp(amz_date),
            self.region,
            self.service,
            TERMINATOR
        )
    }

    /// Derive the SigV4 signing key (the HMAC chain kSecret→kDate→kRegion→
    /// kService→kSigning).
    fn signing_key(&self, amz_date: &str) -> [u8; 32] {
        let k_secret = format!("AWS4{}", self.credentials.secret_access_key.as_str());
        let k_date = hmac_sha256(k_secret.as_bytes(), Self::datestamp(amz_date).as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.service.as_bytes());
        hmac_sha256(&k_service, TERMINATOR.as_bytes())
    }

    /// Build the canonical request (POST, path `/`, no query) for the given signed
    /// headers and payload, returning `(canonical_request, signed_headers_list)`.
    /// `headers` are the headers to sign; they are lowercased, trimmed, and sorted.
    fn canonical_request(headers: &[Header], payload: &[u8]) -> (String, String) {
        let mut sorted: Vec<(String, String)> = headers
            .iter()
            .map(|h| (h.name.to_ascii_lowercase(), h.value.trim().to_string()))
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = sorted.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
        let signed_headers: String = sorted
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let payload_hash = sha256_hex(payload);
        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        (canonical_request, signed_headers)
    }

    /// Sign a request: given the headers to sign (must include `host`; for KMS also
    /// `content-type` and `x-amz-target`) plus the body and timestamp, produce the
    /// `Authorization` header. `amz_date` is `YYYYMMDDTHHMMSSZ`; the caller is
    /// responsible for also sending `host`, `content-type`, `x-amz-target`,
    /// `x-amz-date`, and (if returned) `x-amz-security-token`.
    pub fn sign(&self, mut headers: Vec<Header>, payload: &[u8], amz_date: &str) -> SignedAuth {
        // x-amz-date is always signed.
        headers.push(Header {
            name: "x-amz-date".to_string(),
            value: amz_date.to_string(),
        });
        // Temporary-credential session token is signed when present.
        if let Some(token) = &self.credentials.session_token {
            headers.push(Header {
                name: "x-amz-security-token".to_string(),
                value: token.clone(),
            });
        }

        let (canonical_request, signed_headers) = Self::canonical_request(&headers, payload);
        let scope = self.scope(amz_date);
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = to_hex_lower(&hmac_sha256(
            &self.signing_key(amz_date),
            string_to_sign.as_bytes(),
        ));
        let authorization = format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.credentials.access_key_id
        );
        SignedAuth {
            authorization,
            amz_date: amz_date.to_string(),
            security_token: self.credentials.session_token.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vanilla_signer() -> SigV4Signer {
        // AWS-published example credentials (the `aws-sig-v4-test-suite` defaults).
        SigV4Signer::new(
            AwsCredentials {
                access_key_id: "AKIDEXAMPLE".to_string(),
                secret_access_key: Zeroizing::new(
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                ),
                session_token: None,
            },
            "us-east-1".to_string(),
            "service".to_string(),
        )
    }

    /// GOLDEN: AWS's published `get-vanilla` test vector. The signing chain
    /// (canonical request → string to sign → signing key → signature) must match
    /// AWS byte-for-byte. The expected signature is the published value for that
    /// vector. We exercise the same private signing primitives `sign()` uses; the
    /// vector is a GET with `host` + `x-amz-date` only and an empty payload.
    #[test]
    fn sigv4_matches_published_get_vanilla_vector() {
        let signer = vanilla_signer();
        let amz_date = "20150830T123600Z";

        // get-vanilla canonical headers: host + x-amz-date, empty body.
        let mut sorted: Vec<(String, String)> = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), amz_date.to_string()),
        ];
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers: String = sorted.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
        let signed_headers = "host;x-amz-date";
        // Reproduce the canonical request for a GET (the suite's method) so the
        // hash matches; `sign()` itself only ever issues POSTs, but the signing
        // MATH below is identical and is what we are proving.
        let canonical_request = format!(
            "GET\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
            sha256_hex(b"")
        );

        let scope = signer.scope(amz_date);
        assert_eq!(scope, "20150830/us-east-1/service/aws4_request");
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = to_hex_lower(&hmac_sha256(
            &signer.signing_key(amz_date),
            string_to_sign.as_bytes(),
        ));

        assert_eq!(
            signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            "SigV4 signature must match AWS's published get-vanilla vector"
        );
    }

    /// The empty-payload hash is the well-known SHA-256 of the empty string — a
    /// guard that our hex/SHA wiring is correct independent of the HMAC chain.
    #[test]
    fn empty_payload_hash_is_well_known() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// GOLDEN (KMS request shape): a `Sign` request's canonical request and
    /// Authorization header are well-formed and stable — POST `/`, sorted lowercase
    /// signed headers including `x-amz-target`, body hash bound in. This pins the
    /// exact request the live KMS lane will send.
    #[test]
    fn kms_sign_request_canonical_shape_is_stable() {
        let signer = vanilla_signer();
        let amz_date = "20150830T123600Z";
        let body = br#"{"KeyId":"k","Message":"AA==","MessageType":"RAW","SigningAlgorithm":"ED25519_SHA_512"}"#;
        let headers = vec![
            Header {
                name: "content-type".to_string(),
                value: "application/x-amz-json-1.1".to_string(),
            },
            Header {
                name: "host".to_string(),
                value: "kms.us-east-1.amazonaws.com".to_string(),
            },
            Header {
                name: "x-amz-target".to_string(),
                value: "TrentService.Sign".to_string(),
            },
        ];
        let mut to_sign = headers.clone();
        to_sign.push(Header {
            name: "x-amz-date".to_string(),
            value: amz_date.to_string(),
        });
        let (canonical_request, signed_headers) = SigV4Signer::canonical_request(&to_sign, body);

        assert_eq!(signed_headers, "content-type;host;x-amz-date;x-amz-target");
        assert!(canonical_request.starts_with("POST\n/\n\n"));
        assert!(canonical_request.contains("x-amz-target:TrentService.Sign\n"));
        assert!(canonical_request.ends_with(&sha256_hex(body)));

        // The end-to-end sign() must produce a SigV4 Authorization header naming the
        // same signed headers and credential scope.
        let auth = signer.sign(headers, body, amz_date);
        assert!(auth
            .authorization
            .contains("SignedHeaders=content-type;host;x-amz-date;x-amz-target"));
        assert!(auth.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
        ));
    }

    /// A session token is signed in and surfaced for sending.
    #[test]
    fn session_token_is_signed_and_returned() {
        let signer = SigV4Signer::new(
            AwsCredentials {
                access_key_id: "AKIDEXAMPLE".to_string(),
                secret_access_key: Zeroizing::new("secret".to_string()),
                session_token: Some("tok123".to_string()),
            },
            "us-east-1".to_string(),
            "kms".to_string(),
        );
        let auth = signer.sign(
            vec![Header {
                name: "host".to_string(),
                value: "kms.us-east-1.amazonaws.com".to_string(),
            }],
            b"{}",
            "20150830T123600Z",
        );
        assert_eq!(auth.security_token.as_deref(), Some("tok123"));
        assert!(auth.authorization.contains("x-amz-security-token"));
    }
}
