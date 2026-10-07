//! CPython-exact canonical JSON for digest material.
//!
//! Approval tokens and configured-value digests were historically produced by
//! Python's `json.dumps(..., sort_keys=True, separators=(",", ":"),
//! ensure_ascii=True, allow_nan=False)`. Persisted approvals bind the exact
//! bytes that call produced, so this codec reimplements CPython's output —
//! including its `ensure_ascii` escapes and `repr`-style float spelling —
//! byte for byte. The shared snapshot canonical encoder deliberately does not
//! match this contract, which is why it is not reused here.
//!
//! Lifted from `guard-runtime/src/context_digest_json.rs` so `guard-command`
//! (binding digests in `_explicit_permission_allow_factors` et al.) and
//! `guard-runtime` share a single byte-parity codec. The error is a static
//! string; callers map it onto their own error surfaces.

use serde_json::Value;

/// Write `value` exactly as CPython
/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
/// allow_nan=False)` would, rejecting anything that mapping cannot encode.
/// `limit` bounds the material the encoder will emit; `err` is the error
/// surfaced on limit/encodability failure.
pub fn write_canonical_json_with_limit(
    value: &Value,
    out: &mut Vec<u8>,
    limit: usize,
    err: &'static str,
) -> Result<(), &'static str> {
    write_sorted_json::<false, true>(value, out, limit, err)
}

fn write_sorted_json<const SPACED: bool, const ENSURE_ASCII: bool>(
    value: &Value,
    out: &mut Vec<u8>,
    limit: usize,
    err: &'static str,
) -> Result<(), &'static str> {
    if out.len() > limit {
        return Err(err);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(flag) => out.extend_from_slice(if *flag { b"true" } else { b"false" }),
        Value::Number(number) => {
            let raw = number.as_str();
            if !raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                out.extend_from_slice(if raw == "-0" { b"0" } else { raw.as_bytes() });
            } else if let Some(float) = number.as_f64() {
                if !float.is_finite() {
                    return Err(err);
                }
                out.extend_from_slice(python_float_repr(float).as_bytes());
            } else {
                return Err(err);
            }
        }
        Value::String(text) => write_json_string_with_ascii::<ENSURE_ASCII>(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                    if SPACED {
                        out.push(b' ');
                    }
                }
                write_sorted_json::<SPACED, ENSURE_ASCII>(item, out, limit, err)?;
            }
            out.push(b']');
        }
        Value::Object(entries) => {
            out.push(b'{');
            let mut first = true;
            // serde_json maps are already key-ordered; sorting is codepoint
            // order, identical to Python's str ordering for valid UTF-8.
            for (key, item) in entries.iter() {
                if !first {
                    out.push(b',');
                    if SPACED {
                        out.push(b' ');
                    }
                }
                first = false;
                write_json_string_with_ascii::<ENSURE_ASCII>(key, out);
                out.push(b':');
                if SPACED {
                    out.push(b' ');
                }
                write_sorted_json::<SPACED, ENSURE_ASCII>(item, out, limit, err)?;
            }
            out.push(b'}');
        }
    }
    // A single leaf write can overshoot without hitting another node check.
    if out.len() > limit {
        return Err(err);
    }
    Ok(())
}

/// Unbounded canonical JSON (for producers that already bound input size).
pub fn write_canonical_json(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
    write_canonical_json_with_limit(value, out, usize::MAX, "canonical_json_unencodable")
}

/// Sorted compact JSON with non-ASCII characters encoded as UTF-8.
/// The producer must bound input size, as with the compact unbounded writer.
pub fn write_canonical_json_utf8(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
    write_sorted_json::<false, false>(value, out, usize::MAX, "canonical_json_unencodable")
}

/// Sorted, ASCII-escaped JSON with CPython's default comma/colon spacing.
/// The producer must bound input size, as with the compact unbounded writer.
pub fn write_python_default_json(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
    write_sorted_json::<true, true>(value, out, usize::MAX, "canonical_json_unencodable")
}

/// Escape a string body the way CPython's `ensure_ascii` encoder does:
/// printable ASCII passes through except `"` and `\`; short escapes cover
/// the usual controls; every other code point becomes a lowercase `\uXXXX`
/// sequence with non-BMP points emitted as UTF-16 surrogate pairs.
pub fn write_json_string(text: &str, out: &mut Vec<u8>) {
    write_json_string_with_ascii::<true>(text, out);
}

fn write_json_string_with_ascii<const ENSURE_ASCII: bool>(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            ch if (ch as u32) < 0x20 || (ENSURE_ASCII && (ch as u32) > 0x7e) => {
                let code = ch as u32;
                if code > 0xffff {
                    let shifted = code - 0x1_0000;
                    let high = 0xd800 + (shifted >> 10);
                    let low = 0xdc00 + (shifted & 0x3ff);
                    out.extend_from_slice(format!("\\u{high:04x}\\u{low:04x}").as_bytes());
                } else {
                    out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
                }
            }
            ch => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Format a finite float exactly as CPython `repr()`/`json.dumps` does:
/// shortest round-trip digits, fixed notation when the decimal point sits in
/// (-4, 16], and a signed two-digit-minimum exponent otherwise.
pub fn python_float_repr(value: f64) -> String {
    let negative = value.is_sign_negative();
    let mut formatted = format!("{:e}", value.abs());
    let exponent_marker = formatted.find('e').unwrap_or(formatted.len());
    let exponent: i32 = formatted[exponent_marker + 1..].parse().unwrap_or(0);
    formatted.truncate(exponent_marker);
    let digits: String = formatted.chars().filter(|ch| *ch != '.').collect();
    let digit_count = digits.len() as i32;
    // digits represent 0.d1d2...dn * 10^decpt.
    let decpt = exponent + 1;

    let sign = if negative { "-" } else { "" };
    if decpt > -4 && decpt <= 16 {
        if decpt <= 0 {
            return format!("{sign}0.{}{}", "0".repeat((-decpt) as usize), digits);
        }
        if decpt >= digit_count {
            return format!(
                "{sign}{}{}.0",
                digits,
                "0".repeat((decpt - digit_count) as usize)
            );
        }
        let split = decpt as usize;
        return format!("{sign}{}.{}", &digits[..split], &digits[split..]);
    }
    let mantissa = if digit_count > 1 {
        format!("{}.{}", &digits[..1], &digits[1..])
    } else {
        digits
    };
    let exponent_value = decpt - 1;
    let exponent_sign = if exponent_value < 0 { "-" } else { "+" };
    format!(
        "{sign}{mantissa}e{exponent_sign}{:02}",
        exponent_value.abs()
    )
}
