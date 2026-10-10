//! Python-compatible JSON and text helpers for stored guard.db values.
//!
//! The store persists JSON text produced by `json.dumps`; payload hashes are
//! HMACs over those exact bytes, so serialization must match byte for byte:
//! `ensure_ascii=True`, `sort_keys`, and compact `(",", ":")` separators.

use guard_contracts::write_canonical_json;
use serde_json::Value;

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))` with
/// `ensure_ascii`, delegated to the shared CPython-exact canonical encoder so
/// escaping and float spelling have a single owner. Returns `None` for values
/// Python could not encode (non-finite numbers).
pub(crate) fn dumps_sorted(value: &Value) -> Option<String> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out).ok()?;
    String::from_utf8(out).ok()
}

/// `str.strip()` — Unicode whitespace including the C0 separators Python
/// treats as whitespace.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(|character: char| {
        character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
    })
}

/// `text[:limit]` by code points.
pub(crate) fn py_prefix(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// `datetime.fromisoformat(...)` subset plus `+ timedelta(...)` and
/// `.isoformat()`. Returns `None` when the text is not a recognized ISO-8601
/// instant, matching the callers' "fall back to now" branch.
pub(crate) fn add_seconds_isoformat(text: &str, delta_micros: i64) -> Option<String> {
    let normalized = text.replace('Z', "+00:00");
    let parsed = parse_iso(&normalized)?;
    Some(format_iso(parsed, delta_micros))
}

struct Parsed {
    micros_since_epoch: i128,
    offset_seconds: Option<i64>,
}

fn digits(text: &str, start: usize, length: usize) -> Option<(i64, usize)> {
    let slice = text.get(start..start + length)?;
    if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((slice.parse().ok()?, start + length))
}

fn parse_iso(text: &str) -> Option<Parsed> {
    let (year, at) = digits(text, 0, 4)?;
    let at = (text.as_bytes().get(at) == Some(&b'-')).then_some(at + 1)?;
    let (month, at) = digits(text, at, 2)?;
    let at = (text.as_bytes().get(at) == Some(&b'-')).then_some(at + 1)?;
    let (day, mut at) = digits(text, at, 2)?;
    let (mut hour, mut minute, mut second, mut micro) = (0, 0, 0, 0);
    let mut offset = None;
    if at < text.len() {
        let separator = text.as_bytes()[at];
        if separator != b'T' && separator != b' ' {
            return None;
        }
        at += 1;
        let (value, next) = digits(text, at, 2)?;
        hour = value;
        at = next;
        for slot in [&mut minute, &mut second] {
            if text.as_bytes().get(at) == Some(&b':') {
                let (value, next) = digits(text, at + 1, 2)?;
                *slot = value;
                at = next;
            } else {
                break;
            }
        }
        if text.as_bytes().get(at) == Some(&b'.') {
            let mut end = at + 1;
            while text.as_bytes().get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            let fraction = &text[at + 1..end];
            if fraction.is_empty() || fraction.len() > 6 {
                return None;
            }
            micro = format!("{fraction:0<6}").parse().ok()?;
            at = end;
        }
        if at < text.len() {
            let sign = match text.as_bytes()[at] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (zone_hour, next) = digits(text, at + 1, 2)?;
            let mut zone_minute = 0;
            let mut next = next;
            if text.as_bytes().get(next) == Some(&b':') {
                let (value, after) = digits(text, next + 1, 2)?;
                zone_minute = value;
                next = after;
            }
            if next != text.len() || zone_hour > 23 || zone_minute > 59 {
                return None;
            }
            offset = Some(sign * (zone_hour * 3600 + zone_minute * 60));
        }
    }
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 || year < 1 {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(Parsed {
        micros_since_epoch: i128::from(seconds) * 1_000_000 + i128::from(micro),
        offset_seconds: offset,
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shifted + 2) / 5 + 1;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn format_iso(parsed: Parsed, delta_micros: i64) -> String {
    let total = parsed.micros_since_epoch + i128::from(delta_micros);
    let micros = total.rem_euclid(1_000_000) as i64;
    let seconds = total.div_euclid(1_000_000) as i64;
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let mut text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        day_seconds / 3600,
        day_seconds % 3600 / 60,
        day_seconds % 60
    );
    if micros != 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    if let Some(offset) = parsed.offset_seconds {
        let sign = if offset < 0 { '-' } else { '+' };
        let magnitude = offset.abs();
        text.push_str(&format!(
            "{sign}{:02}:{:02}",
            magnitude / 3600,
            magnitude % 3600 / 60
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dumps_match_python_ensure_ascii() {
        let value = json!({"b": "é\u{1F600}\n", "a": [1, null, true]});
        assert_eq!(
            dumps_sorted(&value).unwrap(),
            r#"{"a":[1,null,true],"b":"\u00e9\ud83d\ude00\n"}"#
        );
    }

    #[test]
    fn dumps_floats_like_python_repr() {
        let parsed: Value =
            serde_json::from_str(r#"{"a":0.1,"b":1e-7,"c":1.5e300,"d":-0.0,"e":2.0,"f":1e16,"g":123456789012345680.0,"h":[0.0001,0.00001]}"#).unwrap();
        assert_eq!(
            dumps_sorted(&parsed).unwrap(),
            r#"{"a":0.1,"b":1e-07,"c":1.5e+300,"d":-0.0,"e":2.0,"f":1e+16,"g":1.2345678901234568e+17,"h":[0.0001,1e-05]}"#
        );
    }

    #[test]
    fn isoformat_roundtrip_adds_delta() {
        assert_eq!(
            add_seconds_isoformat("2026-08-24T12:00:00+00:00", 500_000).unwrap(),
            "2026-08-24T12:00:00.500000+00:00"
        );
        assert_eq!(
            add_seconds_isoformat("2026-08-24T23:59:59Z", 2_000_000).unwrap(),
            "2026-08-25T00:00:01+00:00"
        );
        assert_eq!(
            add_seconds_isoformat("2026-08-24T12:00:00", 1_000_000).unwrap(),
            "2026-08-24T12:00:01"
        );
        assert!(add_seconds_isoformat("garbage", 1).is_none());
    }
}
