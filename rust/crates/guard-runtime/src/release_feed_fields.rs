//! Field-level validators for the release feed projection.
//!
//! Every string, number and link the projection keeps passes through one of
//! these bounds first. They are deliberately strict and deliberately boring:
//! the projector next door decides which fields a release has, this module
//! decides what a field is allowed to contain.

use serde_json::{Map, Value};

use super::{FeedError, MAX_URL_CHARS};

pub(super) fn json_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// Control-character bound for every string that reaches the dashboard: no
/// C0/C1 controls, no bidi/format marks, and no line/paragraph separators.
pub(super) fn is_safe_control(value: &str) -> bool {
    value.chars().all(|c| {
        !matches!(c,
            '\u{0000}'..='\u{0008}'
                | '\u{000b}'..='\u{001f}'
                | '\u{007f}'..='\u{009f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}')
    })
}

/// Plain-text bound for identifiers, links and paths: the control bound plus
/// the markup-significant code points, which have no business in a slug, a
/// tag, a login or a URL.
pub(super) fn is_safe_text(value: &str) -> bool {
    is_safe_control(value) && !value.contains(['<', '>'])
}

/// Prose the dashboard renders as React text. Release notes legitimately say
/// "under <1ms" or name a `Vec<u8>`; rejecting an angle bracket here fails the
/// whole document and takes the release off the screen, so prose keeps the
/// control bound only. React escapes the text it renders, and no prose field
/// is ever interpolated into markup or a URL.
pub(super) fn is_safe_prose(value: &str) -> bool {
    is_safe_control(value)
}

/// A single-line field: safe text with no newlines or tabs either.
pub(super) fn single_line(value: &str, limit: usize) -> Option<String> {
    if value.is_empty()
        || value.chars().count() > limit
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('\t')
        || !is_safe_text(value)
    {
        return None;
    }
    Some(value.to_owned())
}

/// A multi-line prose field: newlines allowed, every other control rejected.
pub(super) fn multi_line(value: &str, limit: usize) -> Option<String> {
    if value.chars().count() > limit || !is_safe_prose(value) {
        return None;
    }
    Some(value.to_owned())
}

/// A one-line prose field, such as a release title.
pub(super) fn prose_line(value: &str, limit: usize) -> Option<String> {
    if value.is_empty()
        || value.chars().count() > limit
        || value.contains(['\n', '\r', '\t'])
        || !is_safe_prose(value)
    {
        return None;
    }
    Some(value.to_owned())
}

pub(super) fn required_prose_line(
    object: &Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<String, FeedError> {
    field_str(object, key)
        .and_then(|value| prose_line(value, limit))
        .ok_or(FeedError::Payload)
}

pub(super) fn field_str<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

pub(super) fn required_line(
    object: &Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<String, FeedError> {
    field_str(object, key)
        .and_then(|value| single_line(value, limit))
        .ok_or(FeedError::Payload)
}

pub(super) fn object_at(value: &Value) -> Result<&Map<String, Value>, FeedError> {
    value.as_object().ok_or(FeedError::Payload)
}

/// Dates travel as UTC ISO-8601 instants. The projection keeps the upstream
/// text verbatim once it parses; the dashboard formats it locally.
pub(super) fn iso_instant(value: &str) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.len() > 32 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let digits =
        |mut range: std::ops::Range<usize>| range.all(|index| bytes[index].is_ascii_digit());
    if !digits(0..4)
        || !digits(5..7)
        || !digits(8..10)
        || !digits(11..13)
        || !digits(14..16)
        || !digits(17..19)
    {
        return None;
    }
    let two =
        |index: usize| i64::from(bytes[index] - b'0') * 10 + i64::from(bytes[index + 1] - b'0');
    let (month, day, hour, minute, second) = (two(5), two(8), two(11), two(14), two(17));
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        // A leap second is a real instant upstream may publish.
        || second > 60
    {
        return None;
    }
    // The instant must carry a zone: `Z`, or a numeric ±HH:MM offset, after an
    // optional fractional second. Anything else — a local-looking timestamp, a
    // trailing word — is not an instant, and the dashboard would print it
    // verbatim rather than a date.
    let mut tail = &value[19..];
    if let Some(fraction) = tail.strip_prefix('.') {
        let places = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if places == 0 || places > 9 {
            return None;
        }
        tail = &fraction[places..];
    }
    if tail == "Z" {
        return Some(value.to_owned());
    }
    let zone = tail.as_bytes();
    if zone.len() != 6
        || !matches!(zone[0], b'+' | b'-')
        || zone[3] != b':'
        || !zone[1..3].iter().all(u8::is_ascii_digit)
        || !zone[4..6].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let zone_hour = i64::from(zone[1] - b'0') * 10 + i64::from(zone[2] - b'0');
    let zone_minute = i64::from(zone[4] - b'0') * 10 + i64::from(zone[5] - b'0');
    if zone_hour > 23 || zone_minute > 59 {
        return None;
    }
    Some(value.to_owned())
}

pub(super) fn required_instant(
    object: &Map<String, Value>,
    key: &str,
) -> Result<String, FeedError> {
    field_str(object, key)
        .and_then(iso_instant)
        .ok_or(FeedError::Payload)
}

/// Links the dashboard may open: https only, bounded, and free of whitespace
/// or markup. Anything else is dropped rather than rendered.
pub(super) fn https_url(value: &str) -> Option<String> {
    if !value.starts_with("https://")
        || value.chars().count() > MAX_URL_CHARS
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
        || !is_safe_text(value)
    {
        return None;
    }
    Some(value.to_owned())
}

/// Optional https link: a present-but-unusable link reads as "no evidence"
/// rather than failing the whole release.
pub(super) fn optional_https(object: &Map<String, Value>, key: &str) -> Value {
    match object.get(key) {
        Some(Value::String(raw)) => match https_url(raw) {
            Some(url) => Value::String(url),
            None => Value::Null,
        },
        _ => Value::Null,
    }
}

/// Site-relative portal path. Never absolute, never scheme-bearing, never
/// protocol-relative: the dashboard resolves it against the portal origin.
pub(super) fn release_path(value: &str) -> Option<String> {
    if !value.starts_with("/guard/")
        || value.starts_with("//")
        || value.chars().count() > 512
        || !value.is_ascii()
        || value.contains("..")
        || value.chars().any(char::is_whitespace)
        || !is_safe_text(value)
    {
        return None;
    }
    Some(value.to_owned())
}

pub(super) fn enum_value(
    object: &Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<String, FeedError> {
    let value = field_str(object, key).ok_or(FeedError::Payload)?;
    if !allowed.contains(&value) {
        return Err(FeedError::Payload);
    }
    Ok(value.to_owned())
}

pub(super) fn bounded_count(object: &Map<String, Value>, key: &str) -> Result<i64, FeedError> {
    let value = object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(FeedError::Payload)?;
    if !(0..=1_000_000).contains(&value) {
        return Err(FeedError::Payload);
    }
    Ok(value)
}
