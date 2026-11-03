//! Validation of stored ISO-8601 timestamps, matching the subset of
//! `datetime.fromisoformat` that every supported CPython (3.10+) parses.
//!
//! Supported: extended `YYYY-MM-DD`, optionally followed by a one character
//! separator and `HH:MM[:SS[.fff|.ffffff]]`, then optionally a
//! `+HH:MM[:SS[.fff|.ffffff]]` / `-HH:MM[:SS[.fff|.ffffff]]` offset (a trailing
//! `Z` is read as `+00:00`). Fractions only follow seconds. Basic forms, comma
//! fractions, hour-only times, ISO week dates and a space before the offset are
//! treated as invalid: the loader is the single authority, so it never admits a
//! stamp that any supported CPython would reject.

fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn valid_date(year: u32, month: u32, day: u32) -> bool {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=days).contains(&day)
}

/// The microseconds of a `.fff` or `.ffffff` fraction after the seconds
/// field.
fn fraction_micros(text: &str) -> Option<i64> {
    let value = i64::from(digits(text)?);
    match text.len() {
        3 => Some(value * 1_000),
        6 => Some(value),
        _ => None,
    }
}

/// The microseconds `HH:MM[:SS[.f]]` spans, with every field two digits and
/// in range.
fn clock_micros(text: &str) -> Option<i64> {
    let (body, fraction) = match text.split_once('.') {
        Some((body, fraction)) => (body, Some(fraction)),
        None => (text, None),
    };
    let fields: Vec<&str> = body.split(':').collect();
    if !(2..=3).contains(&fields.len()) || fields.iter().any(|field| field.len() != 2) {
        return None;
    }
    if fraction.is_some() && fields.len() != 3 {
        return None;
    }
    let fraction = match fraction {
        Some(fraction) => fraction_micros(fraction)?,
        None => 0,
    };
    let mut seconds = 0;
    for (field, limit) in fields.iter().zip([24, 60, 60]) {
        let value = digits(field).filter(|value| *value < limit)?;
        seconds = seconds * 60 + i64::from(value);
    }
    if fields.len() == 2 {
        seconds *= 60;
    }
    Some(seconds * 1_000_000 + fraction)
}

/// Days from 1970-01-01 to a valid proleptic Gregorian date.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The instant a stored stamp names, in microseconds since the Unix epoch.
/// A stamp without an offset is read as UTC.
pub(crate) fn iso_epoch_micros(value: &str) -> Option<i64> {
    let text = value.replace('Z', "+00:00");
    if !text.is_ascii() || text.len() < 10 {
        return None;
    }
    let bytes = text.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let (year, month, day) = (
        digits(&text[..4])?,
        digits(&text[5..7])?,
        digits(&text[8..10])?,
    );
    if !valid_date(year, month, day) {
        return None;
    }
    let date = days_from_civil(year, month, day) * 86_400 * 1_000_000;
    let rest = &text[10..];
    if rest.is_empty() {
        return Some(date);
    }
    let time_text = &rest[1..];
    let (clock, offset) = match time_text.find(['+', '-']) {
        Some(at) => (&time_text[..at], Some(&time_text[at..])),
        None => (time_text, None),
    };
    let local = date + clock_micros(clock)?;
    let Some(zone) = offset else {
        return Some(local);
    };
    let shift = clock_micros(&zone[1..])?;
    Some(if zone.starts_with('-') {
        local + shift
    } else {
        local - shift
    })
}

pub(crate) fn is_valid_iso_datetime(value: &str) -> bool {
    iso_epoch_micros(value).is_some()
}

#[cfg(test)]
mod tests {
    use super::{is_valid_iso_datetime, iso_epoch_micros};

    #[test]
    fn accepts_forms_every_supported_cpython_parses() {
        for stamp in [
            "2026-01-01",
            "2026-01-01T10:30",
            "2026-01-01T10:30:15",
            "2026-01-01T10:30:15.123",
            "2026-01-01T10:30:15.123456Z",
            "2026-01-01 10:30:15+05:30",
            "2026-01-01T10:30:15-05:00:30",
        ] {
            assert!(is_valid_iso_datetime(stamp), "{stamp}");
        }
    }

    #[test]
    fn rejects_forms_some_supported_cpython_rejects() {
        for stamp in [
            "2026-01-01T10.5",
            "2026-01-01T10:30.5",
            "2026-01-01T10:30:15+05.5",
            "20260101",
            "20260101T103015",
            "2026-01-01T10:30:15,123",
            "2026-01-01T10:30:15.12",
            "2026-01-01T10",
            "2026-01-01T25:00",
            "2026-02-30",
        ] {
            assert!(!is_valid_iso_datetime(stamp), "{stamp}");
        }
    }

    #[test]
    fn stamps_resolve_to_the_instant_they_name() {
        const HOUR: i64 = 3_600_000_000;
        let midnight = 1_767_225_600_000_000;
        for (stamp, micros) in [
            ("1970-01-01", 0),
            ("1969-12-31T23:59:59.999999", -1),
            ("2026-01-01", midnight),
            ("2026-01-01T00:00", midnight),
            ("2026-01-01T00:00:00Z", midnight),
            ("2026-01-01T05:30:00+05:30", midnight),
            ("2025-12-31T19:00:00-05:00", midnight),
            ("2026-01-01T00:00:00.500", midnight + 500_000),
            ("2026-01-01T01:00:00.000001+01:00", midnight + 1),
            ("2026-01-01T00:00:00-00:00:30.500", midnight + 30_500_000),
            ("2024-03-01", 1_709_251_200_000_000),
            ("2000-02-29T12:00", 951_782_400_000_000 + 12 * HOUR),
            ("0001-01-01", -62_135_596_800_000_000),
        ] {
            assert_eq!(iso_epoch_micros(stamp), Some(micros), "{stamp}");
        }
        assert_eq!(iso_epoch_micros("not-a-timestamp"), None);
        assert_eq!(iso_epoch_micros("2026-01-01T24:00"), None);
    }
}
