//! CPython 3.12 `datetime.fromisoformat` and the UTC projections the policy
//! bundle contract derives from it. The parser mirrors the C implementation
//! byte-for-byte (including its NUL-terminated reads) so every accepted and
//! rejected spelling matches the recorded reference vectors.

const MICROS_PER_SECOND: i64 = 1_000_000;
const MICROS_PER_DAY: i64 = 86_400 * MICROS_PER_SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Parsed {
    local_micros: i64,
    /// `None` for a naive timestamp (callers treat it as UTC when they must).
    offset_micros: Option<i64>,
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

fn days_before_year(year: i64) -> i64 {
    let y = year - 1;
    y * 365 + y / 4 - y / 100 + y / 400
}

fn days_before_month(year: i64, month: i64) -> i64 {
    (1..month).map(|m| days_in_month(year, m)).sum()
}

/// Proleptic Gregorian ordinal (0001-01-01 is 1).
fn ymd_to_ord(year: i64, month: i64, day: i64) -> i64 {
    days_before_year(year) + days_before_month(year, month) + day
}

fn ord_to_ymd(ordinal: i64) -> (i64, i64, i64) {
    let n400 = (ordinal - 1) / 146_097;
    let mut n = (ordinal - 1) % 146_097;
    let mut year = n400 * 400 + 1;
    let n100 = n / 36_524;
    n %= 36_524;
    let n4 = n / 1_461;
    n %= 1_461;
    let n1 = n / 365;
    n %= 365;
    year += n100 * 100 + n4 * 4 + n1;
    if n1 == 4 || n100 == 4 {
        return (year - 1, 12, 31);
    }
    let mut remaining = n;
    let mut month = 1;
    while remaining >= days_in_month(year, month) {
        remaining -= days_in_month(year, month);
        month += 1;
    }
    (year, month, remaining + 1)
}

/// Day-of-week with Monday as 0.
fn weekday(year: i64, month: i64, day: i64) -> i64 {
    (ymd_to_ord(year, month, day) + 6) % 7
}

fn iso_week_1_start(year: i64) -> i64 {
    let first = ymd_to_ord(year, 1, 1);
    let first_weekday = (first + 6) % 7;
    let monday = first - first_weekday;
    if first_weekday > 3 {
        monday + 7
    } else {
        monday
    }
}

fn iso_to_ymd(year: i64, week: i64, day: i64) -> Option<(i64, i64, i64)> {
    if week <= 0 || week >= 53 {
        let mut out_of_range = true;
        if week == 53 {
            let first = weekday(year, 1, 1);
            if first == 3 || (first == 2 && is_leap(year)) {
                out_of_range = false;
            }
        }
        if out_of_range {
            return None;
        }
    }
    if day <= 0 || day >= 8 {
        return None;
    }
    let offset = (week - 1) * 7 + day - 1;
    Some(ord_to_ymd(iso_week_1_start(year) + offset))
}

struct Buf<'a> {
    bytes: &'a [u8],
}

impl Buf<'_> {
    fn at(&self, index: usize) -> u8 {
        self.bytes.get(index).copied().unwrap_or(0)
    }

    fn digits(&self, start: usize, count: usize) -> Option<(usize, i64)> {
        let mut value = 0i64;
        for offset in 0..count {
            let byte = self.at(start + offset);
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + i64::from(byte - b'0');
        }
        Some((start + count, value))
    }
}

fn find_separator(buf: &Buf, len: usize) -> Option<usize> {
    if len == 7 {
        return Some(7);
    }
    if buf.at(4) == b'-' {
        if buf.at(5) == b'W' {
            if len < 8 {
                return None;
            }
            if len > 8 && buf.at(8) == b'-' {
                return Some(if len > 10 && buf.at(10).is_ascii_digit() {
                    8
                } else {
                    10
                });
            }
            return Some(8);
        }
        return Some(10);
    }
    if buf.at(4) == b'W' {
        let mut index = 7;
        while index < len && buf.at(index).is_ascii_digit() {
            index += 1;
        }
        if index < 9 {
            return Some(index);
        }
        return Some(if index % 2 == 0 { 7 } else { 8 });
    }
    Some(8)
}

fn parse_date(buf: &Buf, date_len: usize) -> Option<(i64, i64, i64)> {
    let (mut p, year) = buf.digits(0, 4)?;
    let uses_separator = buf.at(p) == b'-';
    if uses_separator {
        p += 1;
    }
    if buf.at(p) == b'W' {
        p += 1;
        let (next, week) = buf.digits(p, 2)?;
        p = next;
        let day = if p < date_len {
            if uses_separator {
                let byte = buf.at(p);
                p += 1;
                if byte != b'-' {
                    return None;
                }
            }
            let (_, day) = buf.digits(p, 1)?;
            day
        } else {
            1
        };
        return iso_to_ymd(year, week, day);
    }
    let (next, month) = buf.digits(p, 2)?;
    p = next;
    if uses_separator {
        let byte = buf.at(p);
        p += 1;
        if byte != b'-' {
            return None;
        }
    }
    let (_, day) = buf.digits(p, 2)?;
    Some((year, month, day))
}

struct Clock {
    status: i32,
    fields: [i64; 3],
    micros: i64,
}

fn parse_hh_mm_ss_ff(buf: &Buf, start: usize, end: usize) -> Clock {
    let mut clock = Clock {
        status: 0,
        fields: [0; 3],
        micros: 0,
    };
    let mut p = start;
    let mut has_separator = true;
    for index in 0..3 {
        let Some((next, value)) = buf.digits(p, 2) else {
            clock.status = -3;
            return clock;
        };
        clock.fields[index] = value;
        p = next;
        let byte = buf.at(p);
        p += 1;
        if index == 0 {
            has_separator = byte == b':';
        }
        if p >= end {
            clock.status = i32::from(byte != 0);
            return clock;
        } else if has_separator && byte == b':' {
            continue;
        } else if byte == b'.' || byte == b',' {
            break;
        } else if !has_separator {
            p -= 1;
        } else {
            clock.status = -4;
            return clock;
        }
    }
    let remaining = end.saturating_sub(p);
    let to_parse = remaining.min(6);
    let Some((next, micros)) = buf.digits(p, to_parse) else {
        clock.status = -3;
        return clock;
    };
    p = next;
    clock.micros = micros;
    if to_parse > 0 && to_parse < 6 {
        clock.micros *= [100_000, 10_000, 1_000, 100, 10][to_parse - 1];
    }
    while buf.at(p).is_ascii_digit() {
        p += 1;
    }
    clock.status = i32::from(buf.at(p) != 0);
    clock
}

struct TimePart {
    fields: [i64; 3],
    micros: i64,
    offset_micros: Option<i64>,
}

fn parse_time(buf: &Buf, start: usize, length: usize) -> Option<TimePart> {
    let end = start + length;
    let mut tz = start;
    loop {
        if matches!(buf.at(tz), b'Z' | b'+' | b'-') {
            break;
        }
        tz += 1;
        if tz >= end {
            break;
        }
    }
    let clock = parse_hh_mm_ss_ff(buf, start, tz);
    if clock.status < 0 {
        return None;
    }
    let naive = TimePart {
        fields: clock.fields,
        micros: clock.micros,
        offset_micros: None,
    };
    if tz == end {
        return if clock.status == 1 { None } else { Some(naive) };
    }
    if buf.at(tz) == b'Z' {
        return if buf.at(tz + 1) != 0 {
            None
        } else {
            Some(TimePart {
                offset_micros: Some(0),
                ..naive
            })
        };
    }
    let sign: i64 = if buf.at(tz) == b'-' { -1 } else { 1 };
    let offset = parse_hh_mm_ss_ff(buf, tz + 1, end);
    if offset.status != 0 {
        return None;
    }
    let seconds = sign * (offset.fields[0] * 3600 + offset.fields[1] * 60 + offset.fields[2]);
    let micros = sign * offset.micros;
    let offset_micros = if seconds == 0 {
        0
    } else {
        let total = seconds * MICROS_PER_SECOND + micros;
        if total.abs() >= MICROS_PER_DAY {
            return None;
        }
        total
    };
    Some(TimePart {
        offset_micros: Some(offset_micros),
        ..naive
    })
}

/// `datetime.fromisoformat(value)`; `None` where Python raises `ValueError`.
pub(crate) fn from_isoformat(value: &str) -> Option<Parsed> {
    let buf = Buf {
        bytes: value.as_bytes(),
    };
    let mut len = value.len();
    if value.chars().count() < 7 {
        return None;
    }
    let separator = find_separator(&buf, len)?;
    let (year, month, day) = parse_date(&buf, separator)?;
    let mut time = TimePart {
        fields: [0; 3],
        micros: 0,
        offset_micros: None,
    };
    if len > separator {
        let lead = buf.at(separator);
        let width = if lead & 0x80 == 0 {
            1
        } else {
            match lead & 0xf0 {
                0xe0 => 3,
                0xf0 => 4,
                _ => 2,
            }
        };
        let start = separator + width;
        len = len.checked_sub(start)?;
        time = parse_time(&buf, start, len)?;
    }
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || time.fields[0] > 23
        || time.fields[1] > 59
        || time.fields[2] > 59
    {
        return None;
    }
    let days = ymd_to_ord(year, month, day) - 719_163;
    let local_micros = days * MICROS_PER_DAY
        + (time.fields[0] * 3600 + time.fields[1] * 60 + time.fields[2]) * MICROS_PER_SECOND
        + time.micros;
    Some(Parsed {
        local_micros,
        offset_micros: time.offset_micros,
    })
}

const MIN_MICROS: i64 = -719_162 * MICROS_PER_DAY;
const MAX_MICROS: i64 = 2_932_896 * MICROS_PER_DAY + MICROS_PER_DAY - 1;

impl Parsed {
    pub(crate) fn is_aware(&self) -> bool {
        self.offset_micros.is_some()
    }

    /// `utcoffset() == timedelta(0)`: aware and exactly UTC.
    pub(crate) fn is_utc(&self) -> bool {
        self.offset_micros == Some(0)
    }

    /// Microseconds since the Unix epoch after `astimezone(utc)` (naive is UTC);
    /// `None` where Python raises `OverflowError`.
    pub(crate) fn utc_micros(&self) -> Option<i64> {
        let utc = self.local_micros - self.offset_micros.unwrap_or(0);
        (MIN_MICROS..=MAX_MICROS).contains(&utc).then_some(utc)
    }

    /// `astimezone(utc).timestamp()` with Python's correctly rounded division.
    pub(crate) fn timestamp(&self) -> Option<f64> {
        micros_to_seconds(self.utc_micros()?)
    }

    /// `astimezone(utc).isoformat()` with `+00:00` rewritten to `Z`.
    pub(crate) fn utc_isoformat_z(&self) -> Option<String> {
        let utc = self.utc_micros()?;
        let days = utc.div_euclid(MICROS_PER_DAY);
        let rest = utc.rem_euclid(MICROS_PER_DAY);
        let (year, month, day) = ord_to_ymd(days + 719_163);
        let seconds = rest / MICROS_PER_SECOND;
        let micros = rest % MICROS_PER_SECOND;
        let mut text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        );
        if micros != 0 {
            text.push_str(&format!(".{micros:06}"));
        }
        text.push('Z');
        Some(text)
    }
}

pub(crate) fn micros_to_seconds(micros: i64) -> Option<f64> {
    let magnitude = micros.unsigned_abs();
    let text = format!(
        "{}{}.{:06}",
        if micros < 0 { "-" } else { "" },
        magnitude / 1_000_000,
        magnitude % 1_000_000
    );
    text.parse().ok()
}

/// `value[:-1] + "+00:00"` when it ends with `Z`/`z`, as the v1 parser does.
pub(crate) fn v1_timestamp(value: &str) -> Option<f64> {
    let candidate = match value.strip_suffix(['Z', 'z']) {
        Some(prefix) => format!("{prefix}+00:00"),
        None => value.to_owned(),
    };
    from_isoformat(&candidate)?.timestamp()
}

/// `value.replace("Z", "+00:00")` projection shared by key validity windows and
/// the supply-chain bundle parser.
pub(crate) fn replaced_timestamp(value: &str) -> Option<f64> {
    from_isoformat(&value.replace('Z', "+00:00"))?.timestamp()
}

/// v2 `_strict_utc_timestamp`: must end with `Z`; returns UTC microseconds.
pub(crate) fn strict_utc_micros(value: &str) -> Option<i64> {
    let prefix = value.strip_suffix('Z')?;
    let parsed = from_isoformat(&format!("{prefix}+00:00"))?;
    // Python: `tzinfo is None or utcoffset() != timezone.utc.utcoffset(...)`.
    // A trailing `Z` is not proof of UTC: the parser can stop at an embedded
    // character and keep an explicit non-zero offset typed before it.
    if !parsed.is_aware() || !parsed.is_utc() {
        return None;
    }
    parsed.utc_micros()
}

/// `_normalized_observed_at`: UTC `Z` spelling, the input when unparsable, and
/// `None` where Python raises `OverflowError` (callers fail closed).
pub(crate) fn normalized_observed_at(value: &str) -> Option<String> {
    match from_isoformat(&value.replace('Z', "+00:00")) {
        Some(parsed) => parsed.utc_isoformat_z(),
        None => Some(value.to_owned()),
    }
}

#[cfg(test)]
#[path = "policy_bundle_time_tests.rs"]
mod tests;
