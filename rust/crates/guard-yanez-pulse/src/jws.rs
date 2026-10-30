//! The outer Pulse receipt: a compact JWS signed by Yanez with Ed25519.
//!
//! `alg` is pinned to `EdDSA` and the key is chosen by `kid`, never by
//! algorithm. The JWK set holds current and retired Yanez keys; an unknown
//! `kid` is reported separately so the caller can refresh the set once.

use base64ct::{Base64UrlUnpadded, Encoding};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::{Map, Value};

use crate::PulseError;

/// Largest receipt Guard will parse.
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024;
/// Largest JWK set Guard will accept from Pulse.
pub const MAX_JWKS_KEYS: usize = 32;

/// One Yanez Ed25519 signing key from `GET /api/authz/public-keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    pub kid: String,
    pub public_key: [u8; 32],
}

/// Yanez signing keys, current and retired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    pub keys: Vec<SigningKey>,
}

impl JwkSet {
    /// Parse a JWK set. Entries with a missing or wrong `kty`, `crv`, `alg`
    /// or `kid`, or a key that is not 32 bytes, are skipped.
    pub fn parse(value: &Value) -> Option<Self> {
        let entries = value.get("keys")?.as_array()?;
        let mut keys = Vec::new();
        for entry in entries.iter().take(MAX_JWKS_KEYS) {
            let field = |name: &str| entry.get(name).and_then(Value::as_str);
            if field("kty") != Some("OKP") || field("crv") != Some("Ed25519") {
                continue;
            }
            if field("alg") != Some("EdDSA") {
                continue;
            }
            let Some(kid) = field("kid").filter(|k| !k.is_empty()) else {
                continue;
            };
            let Some(x) = field("x") else { continue };
            let Ok(raw) = Base64UrlUnpadded::decode_vec(x) else {
                continue;
            };
            let Ok(public_key) = <[u8; 32]>::try_from(raw.as_slice()) else {
                continue;
            };
            if keys.iter().any(|k: &SigningKey| k.kid == kid) {
                // Two keys under one kid make selection ambiguous.
                return None;
            }
            keys.push(SigningKey {
                kid: kid.to_owned(),
                public_key,
            });
        }
        Some(Self { keys })
    }

    pub fn find(&self, kid: &str) -> Option<&SigningKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// A JWS whose Yanez signature verified. Claims are not yet checked.
#[derive(Debug, Clone)]
pub struct VerifiedJws {
    pub kid: String,
    pub claims: Map<String, Value>,
}

/// Read the `kid` without verifying anything, so the caller can decide
/// whether to refresh the JWK set.
pub fn peek_kid(artifact: &str) -> Result<String, PulseError> {
    let (header, _, _) = split(artifact)?;
    Ok(parse_header(header)?.1)
}

/// Verify the compact JWS against `keys`.
pub fn verify(artifact: &str, keys: &JwkSet) -> Result<VerifiedJws, PulseError> {
    let (header_b64, claims_b64, signature_b64) = split(artifact)?;
    let (_, kid) = parse_header(header_b64)?;
    let key = keys.find(&kid).ok_or(PulseError::UnknownSigningKey)?;
    let signature = Base64UrlUnpadded::decode_vec(signature_b64)
        .map_err(|_| PulseError::ReceiptInvalid("signature_encoding"))?;
    let signing_input_len = header_b64.len() + 1 + claims_b64.len();
    let signing_input = &artifact.as_bytes()[..signing_input_len];
    UnparsedPublicKey::new(&ED25519, key.public_key)
        .verify(signing_input, &signature)
        .map_err(|_| PulseError::ReceiptInvalid("signature"))?;
    let claims_bytes = Base64UrlUnpadded::decode_vec(claims_b64)
        .map_err(|_| PulseError::ReceiptInvalid("claims_encoding"))?;
    let claims = crate::strict_json::parse_no_duplicates(&claims_bytes)
        .and_then(|v| match v {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .ok_or(PulseError::ReceiptInvalid("claims_json"))?;
    Ok(VerifiedJws { kid, claims })
}

fn split(artifact: &str) -> Result<(&str, &str, &str), PulseError> {
    if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(PulseError::ReceiptInvalid("size"));
    }
    let mut parts = artifact.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(c), Some(s), None) if !h.is_empty() && !c.is_empty() && !s.is_empty() => {
            Ok((h, c, s))
        }
        _ => Err(PulseError::ReceiptInvalid("compact_form")),
    }
}

fn parse_header(header_b64: &str) -> Result<(Map<String, Value>, String), PulseError> {
    let bytes = Base64UrlUnpadded::decode_vec(header_b64)
        .map_err(|_| PulseError::ReceiptInvalid("header_encoding"))?;
    let header = match crate::strict_json::parse_no_duplicates(&bytes) {
        Some(Value::Object(map)) => map,
        _ => return Err(PulseError::ReceiptInvalid("header_json")),
    };
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(PulseError::ReceiptInvalid("alg"));
    }
    // Guard understands no JWS extensions, so it must refuse any it is told
    // are critical.
    if header.contains_key("crit") {
        return Err(PulseError::ReceiptInvalid("crit"));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(PulseError::ReceiptInvalid("kid"))?
        .to_owned();
    Ok((header, kid))
}
