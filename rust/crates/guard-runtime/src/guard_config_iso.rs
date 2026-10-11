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

/// `.fff` or `.ffffff` after the seconds field.
fn valid_fraction(text: &str) -> bool {
    matches!(text.len(), 3 | 6) && digits(text).is_some()
}

/// `HH:MM[:SS[.f]]` with every field two digits and in range.
fn valid_clock(text: &str, limits: [u32; 3]) -> bool {
    let (body, fraction) = match text.split_once('.') {
        Some((body, fraction)) => (body, Some(fraction)),
        None => (text, None),
    };
    let fields: Vec<&str> = body.split(':').collect();
    if !(2..=3).contains(&fields.len()) || fields.iter().any(|field| field.len() != 2) {
        return false;
    }
    if fraction.is_some() && fields.len() != 3 {
        return false;
    }
    if fraction.is_some_and(|fraction| !valid_fraction(fraction)) {
        return false;
    }
    fields
        .iter()
        .zip(limits)
        .all(|(field, limit)| digits(field).is_some_and(|value| value < limit))
}

pub(crate) fn is_valid_iso_datetime(value: &str) -> bool {
    let text = value.replace('Z', "+00:00");
    if !text.is_ascii() || text.len() < 10 {
        return false;
    }
    let bytes = text.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (
        digits(&text[..4]),
        digits(&text[5..7]),
        digits(&text[8..10]),
    ) else {
        return false;
    };
    if !valid_date(year, month, day) {
        return false;
    }
    let rest = &text[10..];
    if rest.is_empty() {
        return true;
    }
    let time_text = &rest[1..];
    let (clock, offset) = match time_text.find(['+', '-']) {
        Some(at) => (&time_text[..at], Some(&time_text[at + 1..])),
        None => (time_text, None),
    };
    if !valid_clock(clock, [24, 60, 60]) {
        return false;
    }
    offset.is_none_or(|zone| valid_clock(zone, [24, 60, 60]))
}

#[cfg(test)]
mod tests {
    use super::is_valid_iso_datetime;

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
}
