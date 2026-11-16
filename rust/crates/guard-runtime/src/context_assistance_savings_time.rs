//! Reads the RFC 3339 times app records stamp on each line, such as
//! `2026-11-14T16:22:00.842Z` or `2026-11-14T11:22:00-05:00`, as seconds
//! since 1970. Anything else reads as no time at all.

fn number(text: &str) -> Option<i64> {
    text.bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| text.parse().ok())
        .flatten()
}

/// Days since 1970-01-01 for a date on the proleptic Gregorian calendar.
fn days(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    era * 146_097 + of_cycle - 719_468
}

pub(super) fn parse(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') || bytes[16] != b':' {
        return None;
    }
    let part = |from: usize, to: usize| number(text.get(from..to)?);
    let (year, month, day) = (part(0, 4)?, part(5, 7)?, part(8, 10)?);
    let (hour, minute, second) = (part(11, 13)?, part(14, 16)?, part(17, 19)?);
    let valid = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 61;
    if !valid {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            sign * (number(&rest[1..3])? * 3_600 + number(&rest[4..6])? * 60)
        }
        _ => return None,
    };
    let seconds = days(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn app_record_times_read_as_seconds() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse("2026-11-14T09:00:00Z"), Some(1_794_646_800));
        assert_eq!(parse("2026-11-14T09:00:00.842Z"), Some(1_794_646_800));
        assert_eq!(parse("2026-11-14T04:00:00-05:00"), Some(1_794_646_800));
        assert_eq!(parse("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "",
            "2026-11-14",
            "2026-13-01T00:00:00Z",
            "2026-11-14T09:00:00",
            "2026-11-14T09:00:00.Z",
            "x026-11-14T09:00:00Z",
            "2026-11-14T09:00:00+0500",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
