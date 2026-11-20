//! The DPoP device-binding verdict.
//!
//! A stored OAuth credential carries a P-256 private key, the public JWK the
//! server was told about, and that JWK's thumbprint. Only the private key
//! settles whether the other two still describe the live keypair, so the
//! thumbprint is derived from the private key's own public half and the stored
//! JWK has to match it exactly before any of it is handed back.

use base64ct::{Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy_bundle_crypto::pem_body;
use crate::policy_bundle_py::Obj;

const INVALID_PRIVATE_KEY: &str = "invalid_dpop_private_key";
const MISMATCH: &str = "dpop_public_private_key_mismatch";

/// Returns the RFC 7638 JWK thumbprint of `public_jwk`, and only when the
/// active P-256 keypair in `private_key_pem` is consistent with it.
pub(crate) fn jwk_thumbprint(
    private_key_pem: &str,
    public_jwk: &Obj,
) -> Result<String, &'static str> {
    let (x, y) = public_coordinates(private_key_pem)?;
    if !describes(public_jwk, &x, &y) {
        return Err(MISMATCH);
    }
    Ok(thumbprint_of(&x, &y))
}

/// The RFC 7638 thumbprint of the P-256 public key at those coordinates: the
/// required members, lexicographic, with no insignificant space.
fn thumbprint_of(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Base64UrlUnpadded::encode_string(Sha256::digest(canonical.as_bytes()).as_slice())
}

/// The base64url affine coordinates of the private key's own public half.
fn public_coordinates(private_key_pem: &str) -> Result<(String, String), &'static str> {
    let (label, der) = pem_body(private_key_pem).ok_or(INVALID_PRIVATE_KEY)?;
    if label != "PRIVATE KEY" {
        return Err(INVALID_PRIVATE_KEY);
    }
    let rng = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &rng)
        .map_err(|_| INVALID_PRIVATE_KEY)?;
    let point = pair.public_key().as_ref();
    // An uncompressed SEC1 point: the 0x04 tag then the two 32-byte coordinates.
    if point.len() != 65 || point[0] != 0x04 {
        return Err(INVALID_PRIVATE_KEY);
    }
    Ok((
        Base64UrlUnpadded::encode_string(&point[1..33]),
        Base64UrlUnpadded::encode_string(&point[33..65]),
    ))
}

/// Whether `public_jwk` is exactly the public JWK of those coordinates.
fn describes(public_jwk: &Obj, x: &str, y: &str) -> bool {
    let text = |name: &str| public_jwk.get(name).and_then(Value::as_str);
    public_jwk.len() == 4
        && text("crv") == Some("P-256")
        && text("kty") == Some("EC")
        && text("x") == Some(x)
        && text("y") == Some(y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Base64;
    use ring::signature::{EcdsaSigningAlgorithm, ECDSA_P384_SHA384_ASN1_SIGNING};
    use serde_json::json;

    // A recorded public P-256 JWK and the thumbprint it has to yield. These are
    // public values: the canonicalization is pinned without a key in the source,
    // and every test that needs a private key makes a throwaway one instead.
    const X: &str = "JM85riTS8B_FEn4wIt5V5dbjqUdhj2gMcNd4QOTAeT0";
    const Y: &str = "lpCn1t3ypeAp18QwJbWgF_yuiIgpZRtluT34NDPyw6w";
    const JKT: &str = "WJ0P8PX8vKaWYF3CySCQz5Rj9hlu9E5FPPLB68b96ZU";

    // Split so that no PEM frame is ever spelled out in the source.
    const BEGIN: &str = concat!("-----BEGIN PRIVATE", " KEY-----");
    const END: &str = concat!("-----END PRIVATE", " KEY-----");

    /// A fresh key on `algorithm`, written the way every Guard producer writes
    /// one: a PKCS#8 `PRIVATE KEY` block.
    fn generated_pem(algorithm: &'static EcdsaSigningAlgorithm) -> String {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("generated key");
        let body = Base64::encode_string(pkcs8.as_ref());
        format!("{BEGIN}\n{body}\n{END}\n")
    }

    /// A throwaway P-256 key and the public JWK that describes it.
    fn keypair() -> (String, Obj) {
        let pem = generated_pem(&ECDSA_P256_SHA256_ASN1_SIGNING);
        let (x, y) = public_coordinates(&pem).expect("the generated key parses");
        let Value::Object(map) = json!({"crv": "P-256", "kty": "EC", "x": x, "y": y}) else {
            unreachable!("object literal")
        };
        (pem, map)
    }

    #[test]
    fn canonicalizes_the_recorded_jwk_to_its_recorded_thumbprint() {
        assert_eq!(thumbprint_of(X, Y), JKT);
    }

    #[test]
    fn derives_the_live_keypairs_thumbprint() {
        let (pem, jwk) = keypair();
        let x = jwk["x"].as_str().expect("text");
        let y = jwk["y"].as_str().expect("text");
        assert_eq!(jwk_thumbprint(&pem, &jwk).unwrap(), thumbprint_of(x, y));
    }

    #[test]
    fn a_jwk_from_another_key_is_a_mismatch() {
        let (pem, mut jwk) = keypair();
        let y = jwk["y"].clone();
        jwk.insert("x".to_owned(), y);
        assert_eq!(jwk_thumbprint(&pem, &jwk), Err(MISMATCH));
    }

    #[test]
    fn an_extra_member_is_a_mismatch() {
        let (pem, mut jwk) = keypair();
        jwk.insert("use".to_owned(), json!("sig"));
        assert_eq!(jwk_thumbprint(&pem, &jwk), Err(MISMATCH));
    }

    #[test]
    fn a_missing_member_is_a_mismatch() {
        let (pem, mut jwk) = keypair();
        jwk.remove("y");
        assert_eq!(jwk_thumbprint(&pem, &jwk), Err(MISMATCH));
    }

    #[test]
    fn a_non_text_member_is_a_mismatch() {
        let (pem, mut jwk) = keypair();
        jwk.insert("x".to_owned(), json!(7));
        assert_eq!(jwk_thumbprint(&pem, &jwk), Err(MISMATCH));
    }

    #[test]
    fn another_curve_is_not_a_dpop_key() {
        let (_, jwk) = keypair();
        let p384 = generated_pem(&ECDSA_P384_SHA384_ASN1_SIGNING);
        assert_eq!(jwk_thumbprint(&p384, &jwk), Err(INVALID_PRIVATE_KEY));
    }

    #[test]
    fn a_public_key_block_is_not_a_private_key() {
        let (pem, jwk) = keypair();
        let public = pem.replace("PRIVATE KEY", "PUBLIC KEY");
        assert_eq!(jwk_thumbprint(&public, &jwk), Err(INVALID_PRIVATE_KEY));
    }

    #[test]
    fn a_malformed_block_is_not_a_private_key() {
        let (_, jwk) = keypair();
        for pem in [
            "".to_owned(),
            "not a pem at all".to_owned(),
            format!("{BEGIN}\nAAAA\n{END}\n"),
        ] {
            assert_eq!(jwk_thumbprint(&pem, &jwk), Err(INVALID_PRIVATE_KEY));
        }
    }
}
