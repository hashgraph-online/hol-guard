//! The encodings a health lease carries: its UTC timestamps, read as
//! `datetime.fromisoformat` reads them, and the DER ECDSA P-256 signature
//! whose `r` and `s` must lie in range and whose `s` must be low.

use super::MICROS_PER_SECOND;

/// The P-256 group order and half of it, big-endian.
pub(super) const P256_ORDER: [u8; 32] =
    hex_literal(*b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
pub(super) const P256_HALF_ORDER: [u8; 32] =
    hex_literal(*b"7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

/// Microseconds since the epoch for `YYYY-MM-DDTHH:MM:SSZ`, with any number
/// of fraction digits when `fraction` allows them, as `fromisoformat` reads
/// them (truncated to microseconds).
pub(super) fn utc_instant(text: &str, fraction: bool) -> Option<i64> {
    let bytes = text.as_bytes();
    let (body, last) = bytes.split_last().map(|(last, body)| (body, *last))?;
    if last != b'Z' || body.len() < 19 {
        return None;
    }
    let (whole, rest) = body.split_at(19);
    let micros = match rest {
        [] => 0,
        [b'.', digits @ ..] if fraction && !digits.is_empty() => {
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            digits
                .iter()
                .chain(std::iter::repeat(&b'0'))
                .take(6)
                .fold(0_i64, |total, digit| total * 10 + i64::from(digit - b'0'))
        }
        _ => return None,
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(index, byte)| whole[*index] != *byte)
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<i64> {
        whole[start..end].iter().try_fold(0_i64, |total, byte| {
            if byte.is_ascii_digit() {
                Some(total * 10 + i64::from(byte - b'0'))
            } else {
                None
            }
        })
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let valid = year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59;
    if !valid {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(seconds * MICROS_PER_SECOND + micros)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `r` and `s` of a canonical DER ECDSA signature with both in `1..n`.
pub(super) fn der_signature(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let [0x30, length, body @ ..] = der else {
        return None;
    };
    if *length >= 0x80 || usize::from(*length) != body.len() {
        return None;
    }
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    let in_range = rest.is_empty()
        && scalar_in_range(&r, &P256_ORDER, false)
        && scalar_in_range(&s, &P256_ORDER, false);
    in_range.then_some((r, s))
}

/// One minimally encoded, non-negative DER INTEGER of at most 32 bytes.
fn der_integer(bytes: &[u8]) -> Option<([u8; 32], &[u8])> {
    let [0x02, length, rest @ ..] = bytes else {
        return None;
    };
    let length = usize::from(*length);
    if length == 0 || length > 33 || rest.len() < length {
        return None;
    }
    let (content, rest) = rest.split_at(length);
    let padded = content[0] == 0;
    if content[0] & 0x80 != 0 || (padded && (length == 1 || content[1] & 0x80 == 0)) {
        return None;
    }
    let magnitude = if padded { &content[1..] } else { content };
    if magnitude.len() > 32 {
        return None;
    }
    let mut scalar = [0_u8; 32];
    scalar[32 - magnitude.len()..].copy_from_slice(magnitude);
    Some((scalar, rest))
}

pub(super) fn der_encode(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let integer = |scalar: &[u8; 32]| {
        let start = scalar.iter().position(|byte| *byte != 0).unwrap_or(31);
        let magnitude = &scalar[start..];
        let mut encoded = vec![0x02];
        if magnitude[0] & 0x80 != 0 {
            encoded.push(u8::try_from(magnitude.len() + 1).unwrap_or(u8::MAX));
            encoded.push(0);
        } else {
            encoded.push(u8::try_from(magnitude.len()).unwrap_or(u8::MAX));
        }
        encoded.extend_from_slice(magnitude);
        encoded
    };
    let body = [integer(r), integer(s)].concat();
    let mut der = vec![0x30, u8::try_from(body.len()).unwrap_or(u8::MAX)];
    der.extend_from_slice(&body);
    der
}

/// `1 <= scalar < bound`, or `<= bound` when `inclusive`.
pub(super) fn scalar_in_range(scalar: &[u8; 32], bound: &[u8; 32], inclusive: bool) -> bool {
    scalar.iter().any(|byte| *byte != 0) && (scalar < bound || (inclusive && scalar == bound))
}

const fn hex_literal(text: [u8; 64]) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("hex literal"),
        }
    }
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = (nibble(text[2 * index]) << 4) | nibble(text[2 * index + 1]);
        index += 1;
    }
    out
}
