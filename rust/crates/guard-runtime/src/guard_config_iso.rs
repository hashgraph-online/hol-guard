//! Validation of stored ISO-8601 timestamps, matching the subset of
//! `datetime.fromisoformat` that Guard ever produces or reads back.
//!
//! Supported: `YYYY-MM-DD` and `YYYYMMDD`, optionally followed by a one
//! character separator and an extended (`HH[:MM[:SS[.f+]]]`) or basic
//! (`HH[MM[SS[.f+]]]`) time and a `+HH[:MM[:SS]]` / `-HH[MM]` offset. ISO week
//! dates and a space before the offset are not supported and are treated as
//! invalid: the loader is the single authority, so it accepts only forms that
//! every supported CPython (3.10+) parses the same way.

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

fn split_fraction(text: &str) -> Option<&str> {
    match text.find(['.', ',']) {
        None => Some(text),
        Some(at) => {
            let fraction = &text[at + 1..];
            digits(fraction)?;
            Some(&text[..at])
        }
    }
}

/// `HH[:MM[:SS]]` or `HH[MM[SS]]` with every field in range.
fn valid_clock(text: &str, allow_fraction: bool) -> bool {
    let body = if allow_fraction {
        match split_fraction(text) {
            Some(body) => body,
            None => return false,
        }
    } else {
        text
    };
    let fields: Vec<&str> = if body.contains(':') {
        body.split(':').collect()
    } else if matches!(body.len(), 2 | 4 | 6) {
        (0..body.len())
            .step_by(2)
            .map(|at| &body[at..at + 2])
            .collect()
    } else {
        return false;
    };
    if fields.is_empty() || fields.len() > 3 || fields.iter().any(|field| field.len() != 2) {
        return false;
    }
    let limits = [24, 60, 60];
    fields
        .iter()
        .zip(limits)
        .all(|(field, limit)| digits(field).is_some_and(|value| value < limit))
}

pub(crate) fn is_valid_iso_datetime(value: &str) -> bool {
    let text = value.replace('Z', "+00:00");
    if !text.is_ascii() {
        return false;
    }
    let (date, rest) =
        if text.len() >= 10 && text.as_bytes()[4] == b'-' && text.as_bytes()[7] == b'-' {
            (&text[..10], &text[10..])
        } else if text.len() >= 8 {
            (&text[..8], &text[8..])
        } else {
            return false;
        };
    let compact: String = date.chars().filter(|c| *c != '-').collect();
    if compact.len() != 8 {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (
        digits(&compact[..4]),
        digits(&compact[4..6]),
        digits(&compact[6..8]),
    ) else {
        return false;
    };
    if !valid_date(year, month, day) {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    let time_text = &rest[1..];
    let (clock, offset) = match time_text.find(['+', '-']) {
        Some(at) => (&time_text[..at], Some(&time_text[at + 1..])),
        None => (time_text, None),
    };
    if !valid_clock(clock, true) {
        return false;
    }
    offset.is_none_or(|zone| valid_clock(zone, true))
}
