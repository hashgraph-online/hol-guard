//! Byte/text codecs matching the CPython behaviours used by `safe_decode`.

use super::inflate::{gzip_read, zlib_decompress, GzipFailure};
use super::{surrogate_char, DecodeError, MAX_DECODED_BYTES};

/// `_bytes_to_text`: transparent gzip/zlib decompression, then lossy UTF-8.
pub(super) fn bytes_to_text(raw: &[u8]) -> Result<String, DecodeError> {
    let limit = MAX_DECODED_BYTES + 1;
    let mut owned: Option<Vec<u8>> = None;
    if raw.starts_with(&[0x1f, 0x8b]) {
        match gzip_read(raw, limit) {
            Ok(out) => owned = Some(out),
            Err(GzipFailure::Suppressed) => {}
            Err(GzipFailure::Eof) => return Err(DecodeError::Eof),
        }
    } else if raw.first() == Some(&0x78) {
        if let Ok(out) = zlib_decompress(raw, limit) {
            owned = Some(out);
        }
    }
    let bytes = owned.as_deref().unwrap_or(raw);
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// `binascii.a2b_base64(data, strict_mode=False)` for ASCII input.
fn a2b_base64(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let (mut quad, mut pads, mut left) = (0u8, 0usize, 0u8);
    for &ch in data {
        if ch == b'=' {
            if quad >= 2 {
                pads += 1;
                if usize::from(quad) + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = value;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    if quad != 0 {
        return None;
    }
    Some(out)
}

fn pad_to(data: &str, multiple: usize) -> String {
    let len = data.chars().count();
    let mut padded = String::from(data);
    for _ in 0..(multiple - len % multiple) % multiple {
        padded.push('=');
    }
    padded
}

/// Shared by `base64.b64decode(padded, validate=False)` (after the ASCII check).
fn b64decode_str(data: &str) -> Option<Vec<u8>> {
    let padded = pad_to(data, 4);
    if !padded.is_ascii() {
        return None;
    }
    a2b_base64(padded.as_bytes())
}

pub(super) fn try_base64(data: &str) -> Result<Option<String>, DecodeError> {
    match b64decode_str(data) {
        Some(raw) => bytes_to_text(&raw).map(Some),
        None => Ok(None),
    }
}

pub(super) fn try_base64_urlsafe(data: &str) -> Result<Option<String>, DecodeError> {
    let padded = pad_to(data, 4);
    if !padded.is_ascii() {
        return Ok(None);
    }
    let translated: Vec<u8> = padded
        .bytes()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    match a2b_base64(&translated) {
        Some(raw) => bytes_to_text(&raw).map(Some),
        None => Ok(None),
    }
}

/// `base64.b32decode(padded.upper())`.
pub(super) fn try_base32(data: &str) -> Option<String> {
    let upper = pad_to(data, 8).to_uppercase();
    if !upper.is_ascii() {
        return None;
    }
    let bytes = upper.as_bytes();
    let trimmed_len = bytes.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
    let padchars = bytes.len() - trimmed_len;
    let body = &bytes[..trimmed_len];
    let mut decoded: Vec<u8> = Vec::new();
    let mut acc: u64 = 0;
    for quanta in body.chunks(8) {
        acc = 0;
        for &c in quanta {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return None,
            };
            acc = (acc << 5) + u64::from(v);
        }
        decoded.extend_from_slice(&acc.to_be_bytes()[3..]);
    }
    if bytes.len() % 8 != 0 || !matches!(padchars, 0 | 1 | 3 | 4 | 6) {
        return None;
    }
    if padchars != 0 && !decoded.is_empty() {
        acc <<= 5 * padchars;
        let last = &acc.to_be_bytes()[3..];
        let leftover = (43 - 5 * padchars) / 8;
        let start = decoded.len() - 5;
        decoded.truncate(start);
        decoded.extend_from_slice(&last[..leftover]);
    }
    Some(String::from_utf8_lossy(&decoded).into_owned())
}

pub(super) fn try_hex(data: &str) -> Option<String> {
    let cleaned = data.strip_prefix("0x").unwrap_or(data);
    let mut digits: Vec<u8> = Vec::with_capacity(cleaned.len() + 1);
    if cleaned.len() % 2 != 0 {
        digits.push(b'0');
    }
    digits.extend_from_slice(cleaned.as_bytes());
    let mut raw = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        raw.push((hi * 16 + lo) as u8);
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

fn unquote_to_bytes(chunk: &str) -> Vec<u8> {
    let bytes = chunk.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                char::from(bytes[i + 1]).to_digit(16),
                char::from(bytes[i + 2]).to_digit(16),
            ) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// `urllib.parse.unquote(data, errors="replace")`.
pub(super) fn try_url_percent(data: &str) -> String {
    let mut out = String::with_capacity(data.len());
    let mut run = String::new();
    let mut run_ascii = true;
    let flush = |run: &mut String, ascii: bool, out: &mut String| {
        if run.is_empty() {
            return;
        }
        if ascii {
            out.push_str(&String::from_utf8_lossy(&unquote_to_bytes(run)));
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in data.chars() {
        if ch.is_ascii() != run_ascii {
            flush(&mut run, run_ascii, &mut out);
            run_ascii = ch.is_ascii();
        }
        run.push(ch);
    }
    flush(&mut run, run_ascii, &mut out);
    out
}

/// `data.encode("utf-8").decode("unicode_escape", errors="replace")`.
///
/// `\N{name}` lookups are not available (no Unicode name database); every well-formed
/// name is treated as unknown and replaced with U+FFFD.
pub(super) fn try_unicode_escape(data: &str) -> String {
    const FFFD: char = '\u{fffd}';
    let b = data.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c != b'\\' {
            out.push(char::from(c));
            continue;
        }
        let Some(&e) = b.get(i) else {
            out.push(FFFD);
            break;
        };
        i += 1;
        match e {
            b'\n' => {}
            b'\\' => out.push('\\'),
            b'\'' => out.push('\''),
            b'"' => out.push('"'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b't' => out.push('\t'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b'v' => out.push('\u{b}'),
            b'a' => out.push('\u{7}'),
            b'0'..=b'7' => {
                let mut value = u32::from(e - b'0');
                for _ in 0..2 {
                    match b.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            value = (value << 3) + u32::from(d - b'0');
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push(char::from_u32(value).unwrap_or(FFFD));
            }
            b'x' | b'u' | b'U' => {
                let count = match e {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let mut value = 0u32;
                let mut ok = true;
                for _ in 0..count {
                    match b.get(i).and_then(|&d| char::from(d).to_digit(16)) {
                        Some(d) => {
                            value = (value << 4) + d;
                            i += 1;
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok || value > 0x10ffff {
                    out.push(FFFD);
                } else if (0xd800..=0xdfff).contains(&value) {
                    out.push(surrogate_char(value));
                } else {
                    out.push(char::from_u32(value).unwrap_or(FFFD));
                }
            }
            b'N' => {
                if i >= b.len() {
                    out.push(FFFD);
                } else if b[i] == b'{' {
                    i += 1;
                    let start = i;
                    while i < b.len() && b[i] != b'}' {
                        i += 1;
                    }
                    if i >= b.len() {
                        out.push(FFFD);
                    } else {
                        if i > start {
                            i += 1;
                        }
                        out.push(FFFD);
                    }
                } else {
                    out.push(FFFD);
                }
            }
            other => {
                out.push('\\');
                out.push(char::from(other));
            }
        }
    }
    out
}

/// `raw.decode("utf-16-le", errors="replace")`; lone surrogates become U+FFFD.
pub(super) fn utf16le_lossy(raw: &[u8]) -> String {
    const FFFD: char = '\u{fffd}';
    let unit = |at: usize| u32::from(raw[at]) | (u32::from(raw[at + 1]) << 8);
    let mut out = String::with_capacity(raw.len() / 2);
    let mut q = 0usize;
    while q + 2 <= raw.len() {
        let ch = unit(q);
        q += 2;
        if !(0xd800..=0xdfff).contains(&ch) {
            out.push(char::from_u32(ch).unwrap_or(FFFD));
            continue;
        }
        if q + 2 > raw.len() {
            out.push(FFFD);
            return out;
        }
        if ch < 0xdc00 {
            let ch2 = unit(q);
            if (0xdc00..=0xdfff).contains(&ch2) {
                q += 2;
                let cp = 0x10000 + ((ch - 0xd800) << 10) + (ch2 - 0xdc00);
                out.push(char::from_u32(cp).unwrap_or(FFFD));
                continue;
            }
        }
        out.push(FFFD);
    }
    if q < raw.len() {
        out.push(FFFD);
    }
    out
}

pub(super) fn try_base64_utf16le(data: &str) -> Option<String> {
    b64decode_str(data).map(|raw| utf16le_lossy(&raw))
}
