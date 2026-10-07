use super::*;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};
use std::sync::OnceLock;

const NOW: u64 = 2_000_000_000;
const ACCESS: &str = "synthetic-access-token-not-a-credential";

struct Signer {
    key: RsaKeyPair,
    jwk: Value,
}
fn signer() -> &'static Signer {
    static SIGNER: OnceLock<Signer> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let jwk = json!({"kid":"synthetic-key","kty":"RSA","alg":"RS256","use":"sig",
            "n":Base64UrlUnpadded::encode_string(&key.n().to_bytes_be()),
            "e":Base64UrlUnpadded::encode_string(&key.e().to_bytes_be())});
        let key = RsaKeyPair::from_pkcs8(key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
        Signer { key, jwk }
    })
}
pub(super) fn keys() -> KeySet {
    serde_json::from_value(json!({"keys":[signer().jwk]})).unwrap()
}
fn challenge(key: u8) -> GoogleLoginChallenge {
    GoogleLoginChallenge {
        client_id: "approved-client".into(),
        hosted_domains: BTreeSet::from(["work.example".into(), "other.example".into()]),
        nonce: "synthetic-nonce".into(),
        namespace_key: [key; 32],
        created_at: NOW - 1,
        expected_account_binding: None,
    }
}
fn claims() -> Value {
    json!({"iss":ISSUER,"aud":"approved-client","sub":"synthetic-subject","hd":"work.example",
        "nonce":"synthetic-nonce","at_hash":Base64UrlUnpadded::encode_string(&Sha256::digest(ACCESS.as_bytes())[..16]),
        "iat":NOW-1,"exp":NOW+3600})
}
fn signed_bytes(header: &[u8], claims: &[u8]) -> String {
    let unsigned = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(header),
        Base64UrlUnpadded::encode_string(claims)
    );
    let mut signature = vec![0; signer().key.public().modulus_len()];
    signer()
        .key
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            unsigned.as_bytes(),
            &mut signature,
        )
        .unwrap();
    format!(
        "{unsigned}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    )
}
pub(super) fn signed(header: &Value, claims: &Value) -> String {
    signed_bytes(
        &serde_json::to_vec(header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
    )
}
fn token(claims: &Value) -> String {
    signed(
        &json!({"alg":"RS256","kid":"synthetic-key","typ":"JWT"}),
        claims,
    )
}
fn verify(claims: &Value, namespace: u8) -> Result<GoogleIdentityEvidence, IdentityError> {
    let raw = token(claims);
    challenge(namespace).verify_with_keys(Token::parse(&raw, ACCESS)?, ACCESS, &keys(), NOW)
}

#[test]
fn issuer_variants_and_email_changes_keep_scoped_subject_identity() {
    let original = verify(&claims(), 9).unwrap();
    let mut changed = claims();
    changed["iss"] = json!("accounts.google.com");
    changed["email"] = json!("changed@example.test");
    let other = verify(&changed, 9).unwrap();
    assert_eq!(original.account_binding(), other.account_binding());
    assert_eq!(original.tenant_binding(), other.tenant_binding());
    assert_eq!(original.expires_at(), NOW + 299);
    assert_eq!(original.account_binding().len(), 64);
}

#[test]
fn subject_tenant_namespace_and_client_changes_cannot_reuse_bindings() {
    let original = verify(&claims(), 9).unwrap();
    let mut changed = claims();
    changed["sub"] = json!("another-subject");
    let other = verify(&changed, 9).unwrap();
    assert_ne!(original.account_binding(), other.account_binding());
    assert_eq!(original.tenant_binding(), other.tenant_binding());
    changed["hd"] = json!("other.example");
    let other = verify(&changed, 9).unwrap();
    assert_ne!(original.tenant_binding(), other.tenant_binding());
    let namespace = verify(&claims(), 10).unwrap();
    assert_ne!(original.account_binding(), namespace.account_binding());
    assert_ne!(original.tenant_binding(), namespace.tenant_binding());
    let mut c = challenge(9);
    c.client_id = "second-client".into();
    changed = claims();
    changed["aud"] = json!("second-client");
    let raw = token(&changed);
    let other = c
        .verify_with_keys(Token::parse(&raw, ACCESS).unwrap(), ACCESS, &keys(), NOW)
        .unwrap();
    assert_ne!(original.account_binding(), other.account_binding());
}

#[test]
fn pinned_account_rejects_another_valid_google_subject_in_the_same_domain() {
    let original = verify(&claims(), 9).unwrap();
    let mut changed = claims();
    changed["sub"] = json!("another-subject");
    for value in [claims(), changed] {
        let raw = token(&value);
        let result = challenge(9)
            .with_expected_account(original.account_binding())
            .unwrap()
            .verify_with_keys(Token::parse(&raw, ACCESS).unwrap(), ACCESS, &keys(), NOW);
        assert_eq!(result.is_ok(), value["sub"] == "synthetic-subject");
    }
    for value in ["", &"a".repeat(63), &"A".repeat(64), &"g".repeat(64)] {
        assert!(challenge(9).with_expected_account(value).is_err());
    }
}

#[test]
fn wrong_issuer_audience_presenter_nonce_domain_token_or_subject_is_rejected() {
    for (field, value) in [
        ("iss", json!("https://attacker.example")),
        ("aud", json!("wrong-client")),
        ("aud", json!(["approved-client", "another-client"])),
        ("azp", json!("wrong-client")),
        ("azp", Value::Null),
        ("nonce", json!("other-nonce")),
        ("hd", json!("gmail.com")),
        ("hd", json!("WORK.EXAMPLE")),
        ("sub", json!("")),
        ("sub", json!("x".repeat(256))),
        ("sub", json!("nonascii-π")),
        ("at_hash", json!("invalid")),
    ] {
        let mut value_set = claims();
        value_set[field] = value;
        assert!(verify(&value_set, 9).is_err(), "{field}");
    }
    let raw = token(&claims());
    assert!(challenge(9)
        .verify_with_keys(
            Token::parse(&raw, "different-access-token").unwrap(),
            "different-access-token",
            &keys(),
            NOW
        )
        .is_err());
}

#[test]
fn missing_required_claims_expiry_future_issue_and_old_issue_are_rejected() {
    for name in ["iss", "aud", "sub", "hd", "nonce", "at_hash", "iat", "exp"] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(name);
        assert!(verify(&value, 9).is_err(), "{name}");
    }
    for (field, value) in [
        ("iat", NOW + 31),
        ("iat", NOW - 301),
        ("exp", NOW),
        ("exp", NOW - 1),
    ] {
        let mut c = claims();
        c[field] = json!(value);
        assert!(verify(&c, 9).is_err(), "{field}");
    }
    let raw = token(&claims());
    assert_eq!(
        challenge(9)
            .verify_with_keys(
                Token::parse(&raw, ACCESS).unwrap(),
                ACCESS,
                &keys(),
                NOW + 299
            )
            .err(),
        Some(IdentityError::Expired)
    );
    assert_eq!(
        challenge(9)
            .verify_with_keys(
                Token::parse(&raw, ACCESS).unwrap(),
                ACCESS,
                &keys(),
                NOW - 2
            )
            .err(),
        Some(IdentityError::Expired)
    );
}

#[test]
fn forged_signature_untrusted_key_and_key_confusion_are_rejected() {
    let raw = token(&claims());
    let mut parsed = Token::parse(&raw, ACCESS).unwrap();
    parsed.signature[0] ^= 1;
    assert!(challenge(9)
        .verify_with_keys(parsed, ACCESS, &keys(), NOW)
        .is_err());
    for (field, value) in [
        ("kid", json!("unknown-key")),
        ("kty", json!("EC")),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("n", json!("AA")),
        ("e", json!("Aw")),
    ] {
        let mut set = json!({"keys":[signer().jwk]});
        set["keys"][0][field] = value;
        let set: KeySet = serde_json::from_value(set).unwrap();
        assert!(
            challenge(9)
                .verify_with_keys(Token::parse(&raw, ACCESS).unwrap(), ACCESS, &set, NOW)
                .is_err(),
            "{field}"
        );
    }
    let duplicate: KeySet =
        serde_json::from_value(json!({"keys":[signer().jwk,signer().jwk]})).unwrap();
    assert!(duplicate.validate().is_err());
}

#[test]
fn algorithms_key_urls_critical_headers_duplicate_fields_and_encoding_fail_closed() {
    for header in [
        json!({"alg":"none","kid":"synthetic-key"}),
        json!({"alg":"HS256","kid":"synthetic-key"}),
        json!({"alg":"RS256","kid":"synthetic-key","typ":null}),
        json!({"alg":"RS256","kid":"synthetic-key","jku":"https://attacker.example"}),
        json!({"alg":"RS256","kid":"synthetic-key","crit":["b64"],"b64":false}),
    ] {
        assert!(Token::parse(&signed(&header, &claims()), ACCESS).is_err());
    }
    let header = br#"{"alg":"RS256","alg":"RS256","kid":"synthetic-key"}"#;
    assert!(Token::parse(
        &signed_bytes(header, &serde_json::to_vec(&claims()).unwrap()),
        ACCESS
    )
    .is_err());
    let duplicate =
        serde_json::to_string(&claims())
            .unwrap()
            .replacen("{", "{\"aud\":\"approved-client\",", 1);
    assert!(Token::parse(
        &signed_bytes(
            br#"{"alg":"RS256","kid":"synthetic-key"}"#,
            duplicate.as_bytes()
        ),
        ACCESS
    )
    .is_err());
    for raw in ["", "a.b.c.d", "a.b.c", &"a".repeat(MAX_TOKEN + 1)] {
        assert!(Token::parse(raw, ACCESS).is_err());
    }
    let raw = token(&claims());
    let (signed, signature) = raw.rsplit_once('.').unwrap();
    assert!(Token::parse(&format!("{signed}.{signature}="), ACCESS).is_err());
}

#[test]
#[ignore = "read-only public Google HTTPS endpoint; not account qualification"]
fn public_google_key_endpoint_uses_valid_tls_and_supported_rsa_keys() {
    let (keys, _) = fetch_keys().unwrap();
    keys.validate().unwrap();
    for key in keys.keys {
        key.validate().unwrap();
    }
}

#[test]
fn unrelated_algorithms_do_not_block_a_valid_selected_key() {
    let set: KeySet = serde_json::from_value(json!({"keys":[
        signer().jwk, {"kid":"unrelated-key","kty":"EC","alg":"ES256","crv":"P-256"}
    ]}))
    .unwrap();
    let raw = token(&claims());
    assert!(challenge(9)
        .verify_with_keys(Token::parse(&raw, ACCESS).unwrap(), ACCESS, &set, NOW)
        .is_ok());
    let raw = signed(&json!({"alg":"RS256","kid":"unrelated-key"}), &claims());
    assert!(challenge(9)
        .verify_with_keys(Token::parse(&raw, ACCESS).unwrap(), ACCESS, &set, NOW)
        .is_err());
}

#[test]
fn public_key_cache_reuses_only_fresh_keys_and_bounds_rotation_refresh() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let fetch = || {
        calls.set(calls.get() + 1);
        Ok((keys(), Duration::from_secs(60)))
    };
    let start = Instant::now();
    let mut cache = KeyCache::default();
    cache.get(start, "synthetic-key", fetch).unwrap();
    cache
        .get(start + Duration::from_secs(1), "synthetic-key", fetch)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(cache
        .get(start + Duration::from_secs(2), "unknown", fetch)
        .is_err());
    assert_eq!(calls.get(), 1);
    cache
        .get(start + Duration::from_secs(30), "unknown", fetch)
        .unwrap();
    assert_eq!(calls.get(), 2);
    assert!(cache
        .get(start + Duration::from_secs(31), "unknown", fetch)
        .is_err());
    assert!(cache
        .get(start + Duration::from_secs(90), "synthetic-key", || Err(
            IdentityError::KeyFetchUnavailable
        ))
        .is_err());
    // An expired entry never becomes an outage fallback.
    assert!(cache
        .get(start + Duration::from_secs(91), "synthetic-key", || Err(
            IdentityError::KeyFetchUnavailable
        ))
        .is_err());
    assert_eq!(calls.get(), 2);
    cache
        .get(start + Duration::from_secs(92), "synthetic-key", fetch)
        .unwrap();
    assert_eq!(calls.get(), 3);
    let mut uncached = KeyCache::default();
    for _ in 0..2 {
        uncached
            .get(start, "synthetic-key", || Ok((keys(), Duration::ZERO)))
            .unwrap();
    }
}

#[test]
fn cache_directives_age_and_local_ceiling_bound_key_lifetime() {
    for (control, age, expected) in [
        ("public, max-age=120", None, 120),
        ("public, max-age=120", Some("20"), 100),
        ("max-age=120", Some("121"), 0),
        ("max-age=120", Some("invalid"), 0),
        ("max-age=99999", None, 3600),
        ("max-age=120, no-store", None, 0),
        ("max-age=120, no-cache", None, 0),
        ("max-age=120, no-cache=\"field\"", None, 0),
        ("max-age=120, max-age=120", None, 0),
        ("max-age=invalid", None, 0),
        ("public", None, 0),
    ] {
        assert_eq!(cache_lifetime(control, age), Duration::from_secs(expected));
    }
}

#[test]
fn challenges_are_random_bounded_and_cannot_be_reconstructed_from_caller_nonce() {
    for domains in [
        vec![],
        vec!["work.example".into(), "work.example".into()],
        vec!["WORK.example".into()],
        vec!["work.example\n".into()],
        vec!["local".into()],
    ] {
        assert!(GoogleLoginChallenge::new("approved-client".into(), domains, [9; 32]).is_err());
    }
    assert!(GoogleLoginChallenge::new(
        "approved-client".into(),
        vec!["work.example".into()],
        [0; 32]
    )
    .is_err());
    let first = GoogleLoginChallenge::new(
        "approved-client".into(),
        vec!["work.example".into()],
        [9; 32],
    )
    .unwrap();
    let second = GoogleLoginChallenge::new(
        "approved-client".into(),
        vec!["work.example".into()],
        [9; 32],
    )
    .unwrap();
    assert_ne!(first.nonce(), second.nonce());
    assert_eq!(
        Base64UrlUnpadded::decode_vec(first.nonce()).unwrap().len(),
        32
    );
}
