use super::stable_digest_hex_len;

/// The stable digest is HMAC-SHA512 under a fixed domain key, truncated to
/// 64 hex characters, and Python computes the same value for the same
/// payload. Pin it so a change of primitive cannot move it silently.
#[test]
fn the_stable_digest_matches_hmac_sha512_under_the_domain_key() {
    assert_eq!(
        stable_digest_hex_len(b"hol-guard", None),
        "85dac1608cc7641bcb5b3bf58676d02fc0db5e74368dad0cd1d72323004c0d4a"
    );
    assert_eq!(
        stable_digest_hex_len(b"hol-guard", Some(16)),
        "85dac1608cc7641b"
    );
}
