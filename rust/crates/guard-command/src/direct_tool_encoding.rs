//! Native direct-tool validation helpers.

/// `base64.b64decode(value, validate=True)` — strict alphabet, correct
/// padding; any deviation returns `None` (Python raises `binascii.Error`).
pub(super) fn strict_base64_decode(value: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode = [0xFFu8; 256];
    for (index, byte) in TABLE.iter().enumerate() {
        decode[*byte as usize] = index as u8;
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.len() / 4;
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == chunks - 1;
        let pad = chunk.iter().filter(|b| **b == b'=').count();
        if pad > 2 || (!last && pad > 0) {
            return None;
        }
        if pad > 0 && chunk.iter().position(|b| *b == b'=') != Some(4 - pad) {
            return None;
        }
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        for byte in chunk {
            if *byte == b'=' {
                continue;
            }
            let digit = decode[*byte as usize];
            if digit == 0xFF {
                return None;
            }
            acc = (acc << 6) | digit as u32;
            bits += 6;
        }
        let _ = bits;
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Python `json.dumps(records, separators=(",", ":"), ensure_ascii=True)` for
/// `[(str, str)]` — verbatim byte output for the digest preimage.
pub(super) fn py_json_tuple_list(records: &[(String, String)]) -> Vec<u8> {
    let mut out = String::with_capacity(records.len() * 64 + 2);
    out.push('[');
    for (index, (key, value)) in records.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('[');
        push_py_json_str(&mut out, key);
        out.push(',');
        push_py_json_str(&mut out, value);
        out.push(']');
    }
    out.push(']');
    out.into_bytes()
}

/// Python `json.dumps` string escape (`ensure_ascii=True`): control escapes,
/// `"`, `\\`, and `\uXXXX` for every non-ASCII code point.
pub(super) fn push_py_json_str(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let code = c as u32;
                if code > 0xffff {
                    // Surrogate pair encoding to match CPython ensure_ascii.
                    let adjusted = code - 0x1_0000;
                    let high = 0xd800 + (adjusted >> 10);
                    let low = 0xdc00 + (adjusted & 0x3ff);
                    out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
        }
    }
    out.push('"');
}
