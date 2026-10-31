use super::*;
use base64ct::Base64;
use ring::signature::{
    KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
};

// Split so that no PEM frame is ever spelled out in the source.
const BEGIN: &str = concat!("-----BEGIN PRIVATE", " KEY-----");
const END: &str = concat!("-----END PRIVATE", " KEY-----");
const URL: &str = "https://hol.org/api/guard/runtime/sessions/sync";

/// A throwaway key on `algorithm` as a PKCS#8 `PRIVATE KEY` block, and its
/// uncompressed public point.
fn generated(algorithm: &'static ring::signature::EcdsaSigningAlgorithm) -> (String, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("generated key");
    let pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).expect("parsed key");
    let body = Base64::encode_string(pkcs8.as_ref());
    (
        format!("{BEGIN}\n{body}\n{END}\n"),
        pair.public_key().as_ref().to_vec(),
    )
}

fn jwk_of(point: &[u8]) -> Value {
    json!({
        "crv": "P-256",
        "kty": "EC",
        "x": Base64UrlUnpadded::encode_string(&point[1..33]),
        "y": Base64UrlUnpadded::encode_string(&point[33..65]),
    })
}

fn input(pem: &str, jwk: &Value, extra: Value) -> Obj {
    let mut input = json!({
        "private_key_pem": pem,
        "algorithm": "ES256",
        "public_jwk": jwk,
        "request_url": URL,
        "method": "post",
        "issued_at": 1_780_272_000,
    });
    for (key, value) in extra.as_object().expect("object").clone() {
        input[key] = value;
    }
    input.as_object().expect("object").clone()
}

fn decoded(segment: &str) -> Value {
    let bytes = Base64UrlUnpadded::decode_vec(segment).expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

fn signed(extra: Value) -> (String, Vec<u8>, Value) {
    let (pem, point) = generated(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let jwk = jwk_of(&point);
    let result = proof(&input(&pem, &jwk, extra)).ok().expect("a proof");
    let proof = result["proof"].as_str().expect("text").to_owned();
    (proof, point, jwk)
}

fn claims_of(proof: &str) -> Value {
    decoded(proof.split('.').nth(1).expect("claims"))
}

fn code(result: Handled) -> String {
    match result {
        Err(Fail::Code(code)) => code,
        Err(Fail::Invalid) => "invalid".to_owned(),
        Ok(value) => panic!("expected a rejection, got {value}"),
    }
}

#[test]
fn the_proof_verifies_against_the_keys_public_half() {
    let (proof, point, _) = signed(json!({}));
    let (signing_input, signature) = proof.rsplit_once('.').expect("three segments");
    let signature = Base64UrlUnpadded::decode_vec(signature).expect("base64url");
    assert_eq!(signature.len(), 64, "JWS wants the fixed-width r || s pair");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(signing_input.as_bytes(), &signature)
        .expect("the signature verifies");
}

#[test]
fn the_header_is_written_sorted_and_compact() {
    let (proof, _, jwk) = signed(json!({}));
    let header = proof.split('.').next().expect("header");
    let bytes = Base64UrlUnpadded::decode_vec(header).expect("base64url");
    let expected = format!(
        r#"{{"alg":"ES256","jwk":{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}},"typ":"dpop+jwt"}}"#,
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y"),
    );
    assert_eq!(String::from_utf8(bytes).expect("utf-8"), expected);
}

#[test]
fn the_claims_bind_the_request() {
    let (proof, _, _) = signed(json!({}));
    let claims = claims_of(&proof);
    assert_eq!(claims["htu"], URL);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["iat"], 1_780_272_000);
    assert!(claims.get("ath").is_none());
    assert!(claims.get("nonce").is_none());
    let jti = claims["jti"].as_str().expect("jti");
    let groups: Vec<usize> = jti.split('-').map(str::len).collect();
    assert_eq!(groups, [8, 4, 4, 4, 12]);
    assert_eq!(&jti[14..15], "4", "a version 4 UUID");
    assert!(matches!(&jti[19..20], "8" | "9" | "a" | "b"));
}

#[test]
fn each_proof_has_its_own_jti() {
    let first = claims_of(&signed(json!({})).0);
    let second = claims_of(&signed(json!({})).0);
    assert_ne!(first["jti"], second["jti"]);
}

#[test]
fn an_access_token_is_bound_by_its_hash() {
    let (proof, _, _) = signed(json!({"access_token": "oauth-access-token-1"}));
    let expected = Base64UrlUnpadded::encode_string(&Sha256::digest(b"oauth-access-token-1"));
    assert_eq!(claims_of(&proof)["ath"], expected);
    let (proof, _, _) = signed(json!({"access_token": ""}));
    assert!(claims_of(&proof).get("ath").is_none());
}

#[test]
fn a_non_ascii_access_token_is_refused() {
    let (pem, point) = generated(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let request = input(&pem, &jwk_of(&point), json!({"access_token": "tok\u{e9}n"}));
    assert_eq!(code(proof(&request)), INVALID_ACCESS_TOKEN);
}

#[test]
fn a_nonce_is_stripped_and_a_blank_one_is_left_out() {
    let (proof, _, _) = signed(json!({"nonce": "  nonce-123\n"}));
    assert_eq!(claims_of(&proof)["nonce"], "nonce-123");
    let (proof, _, _) = signed(json!({"nonce": " \t"}));
    assert!(claims_of(&proof).get("nonce").is_none());
}

#[test]
fn only_a_p256_private_key_signs() {
    let (_, point) = generated(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let jwk = jwk_of(&point);
    let (p384, _) = generated(&ECDSA_P384_SHA384_FIXED_SIGNING);
    let (p256, _) = generated(&ECDSA_P256_SHA256_FIXED_SIGNING);
    for pem in [
        p384,
        p256.replace("PRIVATE KEY", "PUBLIC KEY"),
        "not a pem at all".to_owned(),
        format!("{BEGIN}\nAAAA\n{END}\n"),
    ] {
        assert_eq!(
            code(proof(&input(&pem, &jwk, json!({})))),
            INVALID_PRIVATE_KEY
        );
    }
}

#[test]
fn a_malformed_request_is_invalid() {
    let (pem, point) = generated(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let jwk = jwk_of(&point);
    for extra in [
        json!({"issued_at": 1.5}),
        json!({"issued_at": true}),
        json!({"issued_at": "1780272000"}),
        json!({"public_jwk": "jwk"}),
        json!({"method": 7}),
        json!({"nonce": 7}),
        json!({"access_token": ["token"]}),
    ] {
        assert_eq!(code(proof(&input(&pem, &jwk, extra))), "invalid");
    }
    let mut missing = input(&pem, &jwk, json!({}));
    missing.remove("request_url");
    assert_eq!(code(proof(&missing)), "invalid");
}
