//! The DPoP proof (RFC 9449) one Guard Cloud request carries.
//!
//! The stored OAuth credential's P-256 key signs a compact JWS whose header
//! names the public JWK and whose claims bind the request: its URL, method,
//! issue time, a fresh `jti`, the server's nonce when it sent one and, beside
//! an access token, that token's SHA-256 (`ath`). Both segments are written
//! the way the Python signer wrote them, sorted and without insignificant
//! space, and the signature is the fixed-width `r || s` pair JWS requires.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::write_canonical_json;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::policy_bundle_crypto::pem_body;
use crate::policy_bundle_op::{field, optional_text, text_field, Fail, Handled};
use crate::policy_bundle_py::{py_strip, Obj};

const INVALID_PRIVATE_KEY: &str = "invalid_dpop_private_key";
const INVALID_ACCESS_TOKEN: &str = "invalid_dpop_access_token";
const SIGNING_FAILED: &str = "dpop_signing_failed";

/// The `dpop_proof` kind: the signed proof for one request.
pub(crate) fn proof(input: &Obj) -> Handled {
    let public_jwk = field(input, "public_jwk")?;
    if !public_jwk.is_object() {
        return Err(Fail::Invalid);
    }
    let issued_at = field(input, "issued_at")?.as_i64().ok_or(Fail::Invalid)?;
    let request = Request {
        private_key_pem: text_field(input, "private_key_pem")?,
        algorithm: text_field(input, "algorithm")?,
        public_jwk,
        request_url: text_field(input, "request_url")?,
        method: text_field(input, "method")?,
        issued_at,
        access_token: optional_text(input, "access_token")?,
        nonce: optional_text(input, "nonce")?,
    };
    let rng = SystemRandom::new();
    let proof = sign(&request, &jti(&rng)?, &rng)?;
    Ok(json!({ "proof": proof }))
}

struct Request<'a> {
    private_key_pem: &'a str,
    algorithm: &'a str,
    public_jwk: &'a Value,
    request_url: &'a str,
    method: &'a str,
    issued_at: i64,
    access_token: Option<&'a str>,
    nonce: Option<&'a str>,
}

fn sign(request: &Request<'_>, jti: &str, rng: &SystemRandom) -> Result<String, Fail> {
    let (label, der) = pem_body(request.private_key_pem).ok_or(INVALID_PRIVATE_KEY)?;
    if label != "PRIVATE KEY" {
        return Err(INVALID_PRIVATE_KEY.into());
    }
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, rng)
        .map_err(|_| INVALID_PRIVATE_KEY)?;
    let header = json!({
        "alg": request.algorithm,
        "jwk": request.public_jwk,
        "typ": "dpop+jwt",
    });
    let signing_input = format!(
        "{}.{}",
        segment(&header)?,
        segment(&Value::Object(claims(request, jti)?))?
    );
    let signature = pair
        .sign(rng, signing_input.as_bytes())
        .map_err(|_| SIGNING_FAILED)?;
    Ok(format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(signature.as_ref())
    ))
}

fn claims(request: &Request<'_>, jti: &str) -> Result<Map<String, Value>, Fail> {
    let mut claims = Map::new();
    claims.insert("htu".to_owned(), json!(request.request_url));
    claims.insert("htm".to_owned(), json!(request.method.to_uppercase()));
    claims.insert("iat".to_owned(), json!(request.issued_at));
    claims.insert("jti".to_owned(), json!(jti));
    if let Some(token) = request.access_token.filter(|token| !token.is_empty()) {
        // The token must be ASCII, as the Python signer encoded it.
        if !token.is_ascii() {
            return Err(INVALID_ACCESS_TOKEN.into());
        }
        let digest = Sha256::digest(token.as_bytes());
        claims.insert(
            "ath".to_owned(),
            json!(Base64UrlUnpadded::encode_string(digest.as_slice())),
        );
    }
    if let Some(nonce) = request
        .nonce
        .map(py_strip)
        .filter(|nonce| !nonce.is_empty())
    {
        claims.insert("nonce".to_owned(), json!(nonce));
    }
    Ok(claims)
}

/// `json.dumps(sort_keys=True, separators=(",", ":"))`, base64url, unpadded.
fn segment(value: &Value) -> Result<String, Fail> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out).map_err(|_| Fail::Invalid)?;
    Ok(Base64UrlUnpadded::encode_string(&out))
}

/// A random (version 4) UUID in its hyphenated lowercase spelling.
fn jti(rng: &SystemRandom) -> Result<String, Fail> {
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).map_err(|_| SIGNING_FAILED)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
#[path = "policy_bundle_dpop_proof_tests.rs"]
mod tests;
