use super::hmac_sha256_raw;

fn tag_hex(key: &[u8], message: &[u8]) -> String {
    hmac_sha256_raw(key, message)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// RFC 4231 test cases 1, 2 and 6. The discovery tag authenticates what the
/// daemon is willing to answer with, so it has to stay byte-identical to
/// HMAC-SHA256 whichever implementation computes it; case 6 covers a key
/// longer than the 64-byte block.
#[test]
fn the_tag_matches_the_published_hmac_sha256_vectors() {
    assert_eq!(
        tag_hex(&[0x0b; 20], b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        tag_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        tag_hex(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}
