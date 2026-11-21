use super::*;

#[test]
fn garbage_pem_is_rejected() {
    assert_eq!(parse_public_key("nope"), Err(KeyError::Pem));
    assert_eq!(
        parse_public_key("-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----"),
        Err(KeyError::Pem)
    );
    assert_eq!(
        parse_public_key("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
        Err(KeyError::Pem)
    );
}

#[test]
fn mgf1_matches_known_length() {
    assert_eq!(mgf1(b"seed", 70).len(), 70);
    assert_eq!(mgf1(b"seed", 70)[..32], mgf1(b"seed", 32)[..]);
}
