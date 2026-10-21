#![forbid(unsafe_code)]

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Hashes a runtime executable with ring's SHA-256, which uses the CPU's SHA
/// instructions where available. Resident startup hashes the whole binary
/// before it serves, so the portable fallback would sit on the recovery path.
pub(crate) fn sha256_hex_from_reader(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(hex_bytes(context.finish().as_ref()))
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native_resident_state_hex_invalid".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| "native_resident_state_hex_invalid".to_owned())?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| "native_resident_state_hex_invalid".to_owned())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reader_digest_matches_portable_sha256_across_buffer_boundaries() {
        use sha2::{Digest, Sha256};

        let bytes: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
        let expected = super::hex_bytes(&Sha256::digest(bytes.as_slice()));
        let actual = super::sha256_hex_from_reader(&mut bytes.as_slice()).unwrap();
        assert_eq!(actual, expected);
    }
}
