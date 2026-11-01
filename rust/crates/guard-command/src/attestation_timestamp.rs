//! `_parse_attestation_timestamp` from `runtime/trust_attestation.py`.
//!
//! A trust claim is rejected when its `capturedAt` is not a timezone-aware
//! instant, so the gate is only as good as the agreement between the two
//! runtimes about which strings are instants at all.
//!
//! Python used to ask `datetime.fromisoformat` alone, and that answer moves
//! with the interpreter: 3.10 refuses the week dates and basic formats 3.11
//! accepts, 3.10 reads a few doubled-offset spellings no later release does,
//! and only 3.14 reads `24:00` as the next midnight. No port could agree with
//! all of them, so both runtimes now hold one shape first,
//! `_ATTESTATION_TIMESTAMP_SHAPE`:
//!
//! ```text
//! YYYY-MM-DD(T|t| )HH:MM[:SS[.fff|.ffffff]](+|-)HH:MM[:SS]
//! ```
//!
//! after a trailing `Z` becomes `+00:00`, with the hour below 24. Every
//! timestamp Guard writes has that shape. Inside it every supported
//! interpreter reads the same instant, and `from_isoformat` computes it.
//!
//! An offset carries no fraction for the same reason. The reader behind
//! `fromisoformat` used to ask only whether the offset's whole seconds were
//! zero, so `+00:00:00.999999` was UTC itself; newer interpreters read it as a
//! microsecond east. Neither RFC 3339 nor ISO 8601 admits the spelling, so the
//! shape refuses it and both runtimes call it no instant at all, rather than a
//! different instant per interpreter.
//!
//! Python strips the input with `str.strip`, which also removes the four
//! ASCII separators U+001C..U+001F that `char::is_whitespace` keeps;
//! [`python_strip`] removes them too. The vectors in
//! `tests/fixtures/guard-trust-claim.v1.json` are recorded from CPython and
//! replayed on both sides.

/// A `capturedAt` that parsed: microseconds from the Unix epoch, in UTC.
pub type AttestationInstant = i64;

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
const MAX_OFFSET_MICROS: i64 = 24 * 3_600 * MICROS_PER_SECOND;
/// `_FRACTION_CORRECTION`: scales a fraction shorter than six digits.
const FRACTION_CORRECTION: [u32; 5] = [100_000, 10_000, 1_000, 100, 10];
const DAYS_IN_MONTH: [u32; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
/// `_ymd2ord(1970, 1, 1)`: the proleptic ordinal of the Unix epoch.
const EPOCH_ORDINAL: i64 = 719_163;
/// `_ymd2ord(9999, 12, 31)`: the last date `datetime` holds.
const MAX_ORDINAL: i64 = 3_652_059;

/// `_parse_attestation_timestamp(value)` for a string that is already a string.
#[must_use]
pub fn parse_attestation_timestamp(value: &str) -> Option<AttestationInstant> {
    let trimmed = python_strip(value);
    if trimmed.is_empty() {
        return None;
    }
    let normalized = match trimmed.as_bytes().last() {
        Some(b'Z' | b'z') => format!("{}+00:00", &trimmed[..trimmed.len() - 1]),
        _ => trimmed.to_owned(),
    };
    if !has_attestation_shape(&normalized) {
        return None;
    }
    let parsed = from_isoformat(&normalized)?;
    // A naive datetime has no instant to compare, and Python rejects it.
    let offset_micros = parsed.offset_micros?;
    let days = days_from_civil(parsed.year, parsed.month, parsed.day);
    let seconds = days * SECONDS_PER_DAY
        + i64::from(parsed.hour) * 3_600
        + i64::from(parsed.minute) * 60
        + i64::from(parsed.second);
    let micros = seconds * MICROS_PER_SECOND + i64::from(parsed.microsecond) - offset_micros;
    // The shift to UTC has to land on a date `datetime` can still hold.
    let ordinal = micros.div_euclid(MICROS_PER_SECOND * SECONDS_PER_DAY) + EPOCH_ORDINAL;
    if !(1..=MAX_ORDINAL).contains(&ordinal) {
        return None;
    }
    Some(micros)
}

/// Python's `str.strip()`: Unicode white space, plus the four ASCII
/// separators U+001C..U+001F that `str.isspace` counts and
/// `char::is_whitespace` does not.
#[must_use]
pub fn python_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

fn take_digits(bytes: &[u8], at: &mut usize, count: usize) -> bool {
    let end = *at + count;
    match bytes.get(*at..end) {
        Some(run) if run.iter().all(u8::is_ascii_digit) => {
            *at = end;
            true
        }
        _ => false,
    }
}

fn take_byte(bytes: &[u8], at: &mut usize, allowed: &[u8]) -> bool {
    match bytes.get(*at) {
        Some(byte) if allowed.contains(byte) => {
            *at += 1;
            true
        }
        _ => false,
    }
}

/// `_ATTESTATION_TIMESTAMP_SHAPE.fullmatch(value)`, after the `Z` fold.
fn has_attestation_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut at = 0;
    let date = take_digits(bytes, &mut at, 4)
        && take_byte(bytes, &mut at, b"-")
        && take_digits(bytes, &mut at, 2)
        && take_byte(bytes, &mut at, b"-")
        && take_digits(bytes, &mut at, 2)
        && take_byte(bytes, &mut at, b"Tt ");
    if !date {
        return false;
    }
    let hour_at = at;
    if !(take_digits(bytes, &mut at, 2) && &bytes[hour_at..at] <= b"23".as_slice()) {
        return false;
    }
    if !(take_byte(bytes, &mut at, b":") && take_digits(bytes, &mut at, 2)) {
        return false;
    }
    if take_byte(bytes, &mut at, b":") {
        if !take_digits(bytes, &mut at, 2) {
            return false;
        }
        if take_byte(bytes, &mut at, b".") {
            let fraction = bytes[at..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if fraction != 3 && fraction != 6 {
                return false;
            }
            at += fraction;
        }
    }
    let offset = take_byte(bytes, &mut at, b"+-")
        && take_digits(bytes, &mut at, 2)
        && take_byte(bytes, &mut at, b":")
        && take_digits(bytes, &mut at, 2);
    if !offset {
        return false;
    }
    // An offset carries no fraction: see the note on the module.
    if take_byte(bytes, &mut at, b":") && !take_digits(bytes, &mut at, 2) {
        return false;
    }
    at == bytes.len()
}

struct IsoDateTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    microsecond: u32,
    /// `None` is a naive datetime; `Some` is the offset to subtract for UTC.
    offset_micros: Option<i64>,
}

/// `datetime.fromisoformat(value)`, returning `None` where it raises.
fn from_isoformat(value: &str) -> Option<IsoDateTime> {
    // The C parser rejects a non-ASCII string before it reads a digit.
    if !value.is_ascii() || value.len() < 7 {
        return None;
    }
    let bytes = value.as_bytes();
    let separator = find_datetime_separator(bytes)?;
    let date_part = &bytes[..separator.min(bytes.len())];
    let time_part = bytes.get(separator + 1..).unwrap_or(&[]);
    let (mut year, mut month, mut day) = parse_isoformat_date(date_part)?;
    let (hour, minute, second, microsecond, offset_micros) = if time_part.is_empty() {
        (0, 0, 0, 0, None)
    } else {
        let time = parse_isoformat_time(time_part)?;
        if time.error_from_components {
            return None;
        }
        if time.became_next_day && month <= 12 && day <= days_in_month(year, month) {
            // `24:00` is midnight of the next day, wrapped only from a date
            // that was already valid.
            day += 1;
            if day > days_in_month(year, month) {
                day = 1;
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
            }
        }
        (
            time.hour,
            time.minute,
            time.second,
            time.microsecond,
            time.offset_micros,
        )
    };
    // The constructor's own range checks.
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
        || microsecond > 999_999
    {
        return None;
    }
    Some(IsoDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
        offset_micros,
    })
}

/// `_find_isoformat_datetime_separator`: where the date stops.
fn find_datetime_separator(dtstr: &[u8]) -> Option<usize> {
    let len = dtstr.len();
    if len == 7 {
        return Some(7);
    }
    if dtstr[4] == b'-' {
        if dtstr[5] != b'W' {
            // YYYY-MM-DD
            return Some(10);
        }
        if len > 8 && dtstr[8] == b'-' {
            if len == 9 {
                return None;
            }
            // `YYYY-Www-##` is ambiguous; a digit at 10 still reads the dash
            // at 8 as the separator, as CPython does.
            return Some(if len > 10 && dtstr[10].is_ascii_digit() {
                8
            } else {
                10
            });
        }
        // YYYY-Www
        return Some(8);
    }
    if dtstr[4] != b'W' {
        // YYYYMMDD
        return Some(8);
    }
    // YYYYWww or YYYYWwwD, told apart by how many digits run on.
    let mut idx = 7;
    while idx < len && dtstr[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx < 9 {
        return Some(idx);
    }
    Some(if idx % 2 == 0 { 7 } else { 8 })
}

/// `_parse_isoformat_date`.
fn parse_isoformat_date(dtstr: &[u8]) -> Option<(i64, u32, u32)> {
    if !matches!(dtstr.len(), 7 | 8 | 10) {
        return None;
    }
    let year = i64::from(digits(dtstr, 0, 4)?);
    let has_sep = dtstr[4] == b'-';
    let mut pos = 4 + usize::from(has_sep);
    if dtstr.get(pos) == Some(&b'W') {
        pos += 1;
        let week = slice_int(dtstr, pos, 2)?;
        pos += 2;
        let mut weekday = 1;
        if dtstr.len() > pos {
            if (dtstr.get(pos) == Some(&b'-')) != has_sep {
                return None;
            }
            pos += usize::from(has_sep);
            weekday = slice_int(dtstr, pos, 1)?;
        }
        return isoweek_to_gregorian(year, week, weekday);
    }
    let month = slice_int(dtstr, pos, 2)?;
    pos += 2;
    if (dtstr.get(pos) == Some(&b'-')) != has_sep {
        return None;
    }
    pos += usize::from(has_sep);
    let day = slice_int(dtstr, pos, 2)?;
    Some((year, month, day))
}

struct IsoTime {
    hour: u32,
    minute: u32,
    second: u32,
    microsecond: u32,
    offset_micros: Option<i64>,
    became_next_day: bool,
    error_from_components: bool,
}

/// `_parse_isoformat_time`.
fn parse_isoformat_time(tstr: &[u8]) -> Option<IsoTime> {
    let len = tstr.len();
    if len < 2 {
        return None;
    }
    // The first of `-`, `+`, `Z` opens the timezone, one past its index.
    let tz_pos = [b'-', b'+', b'Z']
        .into_iter()
        .find_map(|marker| tstr.iter().position(|c| *c == marker).map(|at| at + 1))
        .unwrap_or(0);
    let time_core = if tz_pos > 0 {
        &tstr[..tz_pos - 1]
    } else {
        tstr
    };
    let mut comps = parse_hh_mm_ss_ff(time_core)?;
    let mut became_next_day = false;
    let mut error_from_components = false;
    if comps[0] == 24 {
        if comps[1..].iter().all(|part| *part == 0) {
            comps[0] = 0;
            became_next_day = true;
        } else {
            error_from_components = true;
        }
    }
    let mut offset_micros = None;
    if tz_pos == len && tstr[len - 1] == b'Z' {
        offset_micros = Some(0);
    } else if tz_pos > 0 {
        let tzstr = &tstr[tz_pos..];
        if matches!(tzstr.len(), 0 | 1 | 3) || tstr[tz_pos - 1] == b'Z' {
            return None;
        }
        let tz_comps = parse_hh_mm_ss_ff(tzstr)?;
        // `tzinfo_from_isoformat_results` asks only whether the whole seconds
        // are zero and drops the fraction, which is the reading interpreters
        // have since changed. The shape admits no fraction to drop, so this
        // agrees with every one of them.
        if tz_comps[..3].iter().all(|part| *part == 0) {
            offset_micros = Some(0);
        } else {
            let magnitude = i64::from(tz_comps[0]) * 3_600 * MICROS_PER_SECOND
                + i64::from(tz_comps[1]) * 60 * MICROS_PER_SECOND
                + i64::from(tz_comps[2]) * MICROS_PER_SECOND
                + i64::from(tz_comps[3]);
            // `timezone()` holds the offset strictly inside a day.
            if magnitude >= MAX_OFFSET_MICROS {
                return None;
            }
            offset_micros = Some(if tstr[tz_pos - 1] == b'-' {
                -magnitude
            } else {
                magnitude
            });
        }
    }
    Some(IsoTime {
        hour: comps[0],
        minute: comps[1],
        second: comps[2],
        microsecond: comps[3],
        offset_micros,
        became_next_day,
        error_from_components,
    })
}

/// `_parse_hh_mm_ss_ff`: `HH[:?MM[:?SS[{.,}fff[fff]]]]`.
fn parse_hh_mm_ss_ff(tstr: &[u8]) -> Option<[u32; 4]> {
    let len = tstr.len();
    let mut comps = [0u32; 4];
    let mut pos = 0usize;
    let mut has_sep = false;
    for (comp, slot) in comps.iter_mut().enumerate().take(3) {
        if len.checked_sub(pos)? < 2 {
            return None;
        }
        *slot = digits(tstr, pos, 2)?;
        pos += 2;
        let next = tstr.get(pos).copied();
        if comp == 0 {
            has_sep = next == Some(b':');
        }
        if next.is_none() || comp >= 2 {
            break;
        }
        if has_sep && next != Some(b':') {
            return None;
        }
        pos += usize::from(has_sep);
    }
    if pos < len {
        if tstr[pos] != b'.' && tstr[pos] != b',' {
            return None;
        }
        pos += 1;
        if !tstr[pos..].iter().all(u8::is_ascii_digit) {
            return None;
        }
        // A separator with no digits after it is a zero fraction, which is
        // what CPython's C parser reads it as.
        let remainder = len - pos;
        if remainder > 0 {
            let to_parse = remainder.min(6);
            let mut fraction = digits(tstr, pos, to_parse)?;
            if to_parse < 6 {
                fraction *= FRACTION_CORRECTION[to_parse - 1];
            }
            comps[3] = fraction;
        }
    }
    Some(comps)
}

/// `int(s[at:at + width])` for a slice that may be shorter than `width`.
fn slice_int(bytes: &[u8], at: usize, width: usize) -> Option<u32> {
    let end = (at + width).min(bytes.len());
    let available = end.checked_sub(at)?;
    if available == 0 {
        return None;
    }
    digits(bytes, at, available)
}

/// Exactly `count` ASCII digits read as one number.
fn digits(bytes: &[u8], at: usize, count: usize) -> Option<u32> {
    let slice = bytes.get(at..at + count)?;
    let mut value: u32 = 0;
    for byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    if month == 2 && is_leap(year) {
        return 29;
    }
    DAYS_IN_MONTH.get(month as usize).copied().unwrap_or(0)
}

/// `_isoweek_to_gregorian`.
fn isoweek_to_gregorian(year: i64, week: u32, weekday: u32) -> Option<(i64, u32, u32)> {
    if !(1..=9999).contains(&year) {
        return None;
    }
    if !(1..53).contains(&week) {
        // Week 53 exists only in a year whose 1 January is a Thursday, or a
        // leap year whose 1 January is a Wednesday.
        let first_weekday = ymd_to_ordinal(year, 1, 1) % 7;
        let has_week_53 = first_weekday == 4 || (first_weekday == 3 && is_leap(year));
        if week != 53 || !has_week_53 {
            return None;
        }
    }
    if !(1..8).contains(&weekday) {
        return None;
    }
    let day_offset = i64::from(week - 1) * 7 + i64::from(weekday - 1);
    let ordinal = isoweek1_monday(year) + day_offset;
    let (y, m, d) = civil_from_days(ordinal - EPOCH_ORDINAL);
    if !(1..=9999).contains(&y) {
        return None;
    }
    Some((y, m, d))
}

/// `_isoweek1monday`: the ordinal of the Monday opening ISO week 1.
fn isoweek1_monday(year: i64) -> i64 {
    const THURSDAY: i64 = 3;
    let first_day = ymd_to_ordinal(year, 1, 1);
    let first_weekday = (first_day + 6).rem_euclid(7);
    let monday = first_day - first_weekday;
    if first_weekday > THURSDAY {
        monday + 7
    } else {
        monday
    }
}

fn ymd_to_ordinal(year: i64, month: u32, day: u32) -> i64 {
    days_from_civil(year, month, day) + EPOCH_ORDINAL
}

/// Days from 1970-01-01 — Hinnant's algorithm on the proleptic Gregorian
/// calendar, which is the one CPython counts on.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * i64::from(shifted_month) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = (if days >= 0 { days } else { days - 146_096 }) / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let month = month as u32;
    (year + i64::from(month <= 2), month, day)
}
