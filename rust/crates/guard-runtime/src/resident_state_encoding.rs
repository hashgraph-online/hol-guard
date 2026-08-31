#![forbid(unsafe_code)]

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native_resident_state_hex_invalid".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = crate::hex_nibble(pair[0])
                .ok_or_else(|| "native_resident_state_hex_invalid".to_owned())?;
            let low = crate::hex_nibble(pair[1])
                .ok_or_else(|| "native_resident_state_hex_invalid".to_owned())?;
            Ok((high << 4) | low)
        })
        .collect()
}
