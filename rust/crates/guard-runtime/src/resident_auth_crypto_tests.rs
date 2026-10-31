//! RFC 4231 vectors for the resident authentication proof.
//!
//! The proof these produce authenticates every resident request, so it has to
//! stay byte-identical to HMAC-SHA256 no matter which implementation computes
//! it. The vectors below are RFC 4231 test cases 1, 2 and 6, with case 6
//! covering a key longer than the 64-byte block.
use super::{constant_time_eq, hmac_sha256};

fn proof_hex(key: &[u8], label: &[u8], nonce: &[u8]) -> String {
    hmac_sha256(key, label, nonce)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn the_proof_matches_the_published_hmac_sha256_vectors() {
    assert_eq!(
        proof_hex(&[0x0b; 20], b"Hi ", b"There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        proof_hex(b"Jefe", b"what do ya want ", b"for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        proof_hex(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key",
            b" - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn the_label_and_the_nonce_are_separate_inputs_to_one_message() {
    // Splitting the message differently must not change the proof: the pair is
    // authenticated as the concatenation, exactly as the peer computes it.
    assert_eq!(
        proof_hex(b"resident-key", b"label", b"nonce"),
        "493ae43a29c70476af6c436b83cf305659c82552a0aec8d9878d1f2a38f67b92"
    );
    assert_eq!(
        proof_hex(b"resident-key", b"labelnon", b"ce"),
        proof_hex(b"resident-key", b"label", b"nonce")
    );
}

#[test]
fn a_different_key_or_message_produces_a_different_proof() {
    let proof = hmac_sha256(b"resident-key", b"label", b"nonce");
    assert_ne!(proof, hmac_sha256(b"resident-kex", b"label", b"nonce"));
    assert_ne!(proof, hmac_sha256(b"resident-key", b"label", b"nonc3"));
}

#[test]
fn the_comparison_rejects_a_different_length_or_a_different_byte() {
    assert!(constant_time_eq(b"proof", b"proof"));
    assert!(!constant_time_eq(b"proof", b"proofs"));
    assert!(!constant_time_eq(b"proof", b"proo6"));
}
