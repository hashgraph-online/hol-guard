//! Authentication primitives shared by resident framing and peer tests.
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

pub(crate) fn hmac_sha256(key: &[u8], label: &[u8], nonce: &[u8]) -> [u8; crate::AUTH_PROOF_BYTES] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(label);
    mac.update(nonce);
    let digest = mac.finalize().into_bytes();
    let mut proof = [0u8; crate::AUTH_PROOF_BYTES];
    proof.copy_from_slice(&digest);
    proof
}

#[cfg(test)]
#[path = "resident_auth_crypto_tests.rs"]
mod tests;
