//! Bounded lazy decode for the packaged command JSON artifacts.
use sha2::{Digest, Sha256};
use std::io::Read;

/// Decode a build-time zstd blob, bounded to `expected_len` bytes, and verify
/// the result against its build-time SHA-256; any mismatch returns an empty
/// slice so callers fail closed exactly like the bootstrap empty slices.
pub(crate) fn decode(
    compressed: &'static [u8],
    expected_len: &str,
    expected_sha256: &str,
) -> Box<[u8]> {
    let Ok(expected_len) = expected_len.parse::<usize>() else {
        return Box::default();
    };
    let decoder = match ruzstd::decoding::StreamingDecoder::new(compressed) {
        Ok(decoder) => decoder,
        Err(_) => return Box::default(),
    };
    let mut bytes = Vec::new();
    if decoder
        .take(expected_len as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() != expected_len
        || hex::encode(Sha256::digest(&bytes)) != expected_sha256
    {
        return Box::default();
    }
    bytes.into_boxed_slice()
}
