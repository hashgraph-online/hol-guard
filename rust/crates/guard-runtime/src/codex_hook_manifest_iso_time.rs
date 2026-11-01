//! Whether a manifest's `generated_at` names an aware point in time.
//!
//! Ported from the `datetime.fromisoformat(...)` and `tzinfo is None` checks
//! in `_verify_manifest_header`. The interpreters Guard supports disagree on
//! which ISO 8601 spellings `fromisoformat` reads - 3.10 takes only what
//! `isoformat()` writes, 3.11 added the basic forms, week dates and `Z` - so
//! this accepts the widest of them: a calendar or week date in basic or
//! extended form, any single separator character, a time of hours with
//! optional minutes, seconds and a `.` or `,` fraction, and a UTC offset
//! spelled `Z` or `+HH[:MM[:SS[.f]]]` in either form. A date alone, or a time
//! with no offset, is naive and therefore refused, as it is in Python.

/// Whether `text` parses as a timezone-aware ISO 8601 date and time.
pub(crate) fn is_aware_iso_datetime(text: &str) -> bool {
    let Some((date_len, date_ok)) = date_part(text.as_bytes()) else {
        return false;
    };
    if !date_ok {
        return false;
    }
    // Any single character separates the date from the time.
    let mut rest = text[date_len..].chars();
    if rest.next().is_none() {
        return false;
    }
    let rest = rest.as_str().as_bytes();
    let Some(offset_at) = rest
        .iter()
        .position(|byte| matches!(byte, b'+' | b'-' | b'Z'))
    else {
        return false;
    };
    let Some(time) = clock(&rest[..offset_at]) else {
        return false;
    };
    let (hour, minute, second) = time;
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    offset(&rest[offset_at..])
}

/// The date's length and whether it names a real day, or `None` when the
/// text does not start with a date at all.
fn date_part(bytes: &[u8]) -> Option<(usize, bool)> {
    let year = digits(bytes.get(..4)?)?;
    if year == 0 {
        return Some((4, false));
    }
    let extended = bytes.get(4) == Some(&b'-');
    let at = if extended { 5 } else { 4 };
    if bytes.get(at) == Some(&b'W') {
        let week = digits(bytes.get(at + 1..at + 3)?)?;
        let day_at = at + 3 + usize::from(extended);
        let has_day = (!extended || bytes.get(at + 3) == Some(&b'-'))
            && bytes.get(day_at).is_some_and(u8::is_ascii_digit);
        let (len, day) = if has_day {
            (day_at + 1, u32::from(bytes[day_at] - b'0'))
        } else {
            (at + 3, 1)
        };
        return Some((
            len,
            (1..=7).contains(&day) && week >= 1 && week <= iso_weeks(year),
        ));
    }
    let month = digits(bytes.get(at..at + 2)?)?;
    let day_at = at + 2 + usize::from(extended);
    if extended && bytes.get(at + 2) != Some(&b'-') {
        return None;
    }
    let day = digits(bytes.get(day_at..day_at + 2)?)?;
    let valid = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month);
    Some((day_at + 2, valid))
}

/// Hours, minutes and seconds, in basic or extended form, with an optional
/// fraction after the seconds.
fn clock(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    let hour = digits(bytes.get(..2)?)?;
    let mut rest = &bytes[2..];
    let mut parts = [0_u32; 2];
    let extended = rest.first() == Some(&b':');
    for part in &mut parts {
        if rest.is_empty() {
            return Some((hour, parts[0], parts[1]));
        }
        if extended {
            rest = rest.strip_prefix(b":")?;
        }
        *part = digits(rest.get(..2)?)?;
        rest = &rest[2..];
    }
    if !rest.is_empty() {
        let fraction = rest
            .strip_prefix(b".")
            .or_else(|| rest.strip_prefix(b","))?;
        if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
            return None;
        }
    }
    Some((hour, parts[0], parts[1]))
}

/// A UTC offset, which Python accepts while it is under a day either way.
fn offset(bytes: &[u8]) -> bool {
    if bytes == b"Z" {
        return true;
    }
    let Some((_, magnitude)) = bytes.split_first() else {
        return false;
    };
    let Some((hours, minutes, seconds)) = clock(magnitude) else {
        return false;
    };
    hours * 3600 + minutes * 60 + seconds < 24 * 3600
}

fn digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0, |value, byte| value * 10 + u32::from(byte - b'0')),
    )
}

fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// How many ISO weeks a year has: 53 when it starts on a Thursday, or on a
/// Wednesday in a leap year.
fn iso_weeks(year: u32) -> u32 {
    let previous = year - 1;
    // Monday is 0: the weekday of 1 January in the proleptic Gregorian
    // calendar, counted from 1 January of year 1, a Monday.
    let weekday = (previous * 365 + previous / 4 - previous / 100 + previous / 400) % 7;
    if weekday == 3 || (weekday == 2 && is_leap(year)) {
        53
    } else {
        52
    }
}

#[cfg(test)]
mod tests {
    use super::is_aware_iso_datetime;

    #[test]
    fn the_spellings_python_reads_as_aware_are_accepted() {
        for text in [
            "2026-10-27T12:34:56.123456+00:00",
            "2026-10-27T12:34:56+05:30",
            "2026-10-27 12:34:56Z",
            "2026-10-27T12:34Z",
            "2026-10-27T12Z",
            "20261027T123456,5-0800",
            "2026-W44-2T00:00:00+00:00",
            "2026W442T000000Z",
            "2026-10-27T12:34:56+23:59:59.999999",
            "2024-02-29T00:00:00+00:00",
            "2026-W53-1T00:00:00Z",
        ] {
            assert!(is_aware_iso_datetime(text), "{text}");
        }
    }

    #[test]
    fn naive_malformed_or_impossible_times_are_refused() {
        for text in [
            "",
            "2026-10-27",
            "2026-10-27T12:34:56",
            "2026-10-27T12:34:56.+00:00",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-10-27T24:00:00Z",
            "2026-10-27T12:60:00Z",
            "2026-10-27T12:34:60Z",
            "2026-10-27T12:34:56+24:00",
            "2026-W54-1T00:00:00Z",
            "2027-W53-1T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "not a time",
        ] {
            assert!(!is_aware_iso_datetime(text), "{text}");
        }
    }
}
