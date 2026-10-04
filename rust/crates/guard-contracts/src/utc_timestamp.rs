//! `store_base.py` `_parse_utc_timestamp` / `_canonical_utc_timestamp`
//! (`store_base.py:1670-1686`) plus SQLite `julianday` equality used by the
//! `guard_local_once_approvals` claim/expire filters
//! (`store_event_receipts.py:91,155`).
//!
//! Two surfaces:
//!  - `sqlite_julianday(value)` — parses the ISO-8601 subset SQLite accepts
//!    (`YYYY-MM-DD[ HH:MM[:SS[.fff]]]` with optional `Z`/`±HH:MM`) and returns
//!    the same JDN `f64`. `None` on unparseable input mirrors `julianday()`
//!    returning NULL (comparisons then filter the row = expired-equivalent).
//!  - `canonical_utc_timestamp(value)` — the stored-text normalizer: strip,
//!    parse, re-emit UTC with `timespec="microseconds"`.

/// Days from civil epoch (1970-01-01) — Hinnant's algorithm, no leap-second
/// correction (proleptic Gregorian, matching both SQLite and CPython).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_p = (month + 9) % 12;
    let day_of_year = (153 * month_p as i64 + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

/// JDN offset. `days_from_civil` counts noon-anchored Julian days; at
/// 1970-01-01T00:00Z `(hour-12)/24` contributes -0.5, so the constant is the
/// JDN at *noon* of the epoch day: 2440588.0.
const JDN_UNIX_EPOCH: f64 = 2_440_588.0;

struct Parsed {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    /// Nanosecond fraction (0..1e9); carries the sub-second digits.
    fraction_ns: u32,
    /// Signed offset minutes applied to reach UTC.
    offset_minutes: i64,
    /// Whether a timezone designator was present (naive → UTC).
    aware: bool,
}

fn take_digits(s: &[u8], at: &mut usize, count: usize) -> Option<u32> {
    if *at + count > s.len() {
        return None;
    }
    let mut v: u32 = 0;
    for _ in 0..count {
        let c = s[*at];
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
        *at += 1;
    }
    Some(v)
}

fn parse_iso8601(raw: &str) -> Option<Parsed> {
    let s = raw.trim().as_bytes();
    if s.is_empty() {
        return None;
    }
    let mut at = 0usize;
    let year = take_digits(s, &mut at, 4)? as i64;
    if s.get(at) != Some(&b'-') {
        return None;
    }
    at += 1;
    let month = take_digits(s, &mut at, 2)?;
    if s.get(at) != Some(&b'-') {
        return None;
    }
    at += 1;
    let day = take_digits(s, &mut at, 2)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut hour = 0;
    let mut minute = 0;
    let mut second = 0;
    let mut fraction_ns = 0u32;
    let mut aware = false;
    let mut offset_minutes: i64 = 0;

    // Separator: 'T', ' ', or end.
    if at < s.len() {
        if s[at] == b'T' || s[at] == b' ' {
            at += 1;
            hour = take_digits(s, &mut at, 2)?;
            if s.get(at) == Some(&b':') {
                at += 1;
                minute = take_digits(s, &mut at, 2)?;
                if s.get(at) == Some(&b':') {
                    at += 1;
                    second = take_digits(s, &mut at, 2)?;
                }
            }
            if hour > 23 || minute > 59 || second > 59 {
                return None;
            }
            if s.get(at) == Some(&b'.') {
                at += 1;
                let frac_start = at;
                let mut frac: u64 = 0;
                while at < s.len() && s[at].is_ascii_digit() {
                    frac = frac * 10 + u64::from(s[at] - b'0');
                    at += 1;
                }
                let digits = at - frac_start;
                if digits == 0 {
                    return None;
                }
                // Truncate/pad to nanoseconds (9 digits).
                let ns = if digits >= 9 {
                    (frac / 10u64.pow(digits as u32 - 9)) as u32
                } else {
                    (frac * 10u64.pow(9 - digits as u32)) as u32
                };
                fraction_ns = ns;
            }
        }
        // Timezone.
        if at < s.len() {
            aware = true;
            if s[at] == b'Z' || s[at] == b'z' {
                at += 1;
            } else if s[at] == b'+' || s[at] == b'-' {
                let sign = if s[at] == b'+' { 1i64 } else { -1i64 };
                at += 1;
                let hh = take_digits(s, &mut at, 2)? as i64;
                let mut mm = 0i64;
                if s.get(at) == Some(&b':') {
                    at += 1;
                    mm = take_digits(s, &mut at, 2)? as i64;
                } else if at + 2 <= s.len() && s[at].is_ascii_digit() && s[at + 1].is_ascii_digit()
                {
                    mm = take_digits(s, &mut at, 2)? as i64;
                }
                if hh > 23 || mm > 59 {
                    return None;
                }
                offset_minutes = sign * (hh * 60 + mm);
            } else {
                return None;
            }
        }
        if at != s.len() {
            return None;
        }
    }

    Some(Parsed {
        year,
        month,
        day,
        hour,
        minute,
        second,
        fraction_ns,
        offset_minutes,
        aware,
    })
}

/// `julianday(value)` for ISO-8601 text, `None` where SQLite returns NULL.
///
/// Naive timestamps are interpreted as UTC (SQLite's documented behavior for
/// the localtime-less case, and matching `_parse_utc_timestamp`'s naive→UTC).
pub fn sqlite_julianday(value: &str) -> Option<f64> {
    let parsed = parse_iso8601(value)?;
    let days = days_from_civil(parsed.year, parsed.month, parsed.day);
    let mut day_fraction = (parsed.hour as f64 - 12.0) / 24.0 + parsed.minute as f64 / 1440.0;
    day_fraction += (parsed.second as f64 + parsed.fraction_ns as f64 / 1e9) / 86400.0;
    let jdn = days as f64 + JDN_UNIX_EPOCH + day_fraction;
    if parsed.aware {
        Some(jdn - parsed.offset_minutes as f64 / 1440.0)
    } else {
        Some(jdn)
    }
}

/// `_parse_utc_timestamp` → microseconds since epoch. `None` on parse failure
/// (callers map that to "expired" per `_timestamp_has_expired`).
pub fn utc_timestamp_micros(value: &str) -> Option<i64> {
    let parsed = parse_iso8601(value)?;
    let days = days_from_civil(parsed.year, parsed.month, parsed.day);
    let mut micros = days
        .checked_mul(86_400)?
        .checked_add(
            (parsed.hour as i64) * 3600 + (parsed.minute as i64) * 60 + parsed.second as i64,
        )?
        .checked_mul(1_000_000)?
        .checked_add(i64::from(parsed.fraction_ns / 1_000))?;
    if parsed.aware {
        micros = micros.checked_sub(parsed.offset_minutes.checked_mul(60_000_000)?)?;
    }
    Some(micros)
}

/// `_canonical_utc_timestamp` (:1681-1684): parse + re-emit UTC
/// `isoformat(timespec="microseconds")`. `None` on parse failure.
pub fn canonical_utc_timestamp(value: &str) -> Option<String> {
    let micros = utc_timestamp_micros(value)?;
    let days = micros.div_euclid(86_400_000_000);
    let within = micros.rem_euclid(86_400_000_000);
    let (year, month, day) = civil_from_days(days);
    let hour = (within / 3_600_000_000) as u32;
    let minute = ((within % 3_600_000_000) / 60_000_000) as u32;
    let second = ((within % 60_000_000) / 1_000_000) as u32;
    let us = (within % 1_000_000) as u32;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{us:06}+00:00"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let day_of_era = z - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_p = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_p + 2) / 5 + 1) as u32;
    let month = (if month_p < 10 {
        month_p + 3
    } else {
        month_p - 9
    }) as u32;
    // March-start calendar: Jan/Feb belong to the following civil year.
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

/// `_timestamp_has_expired` (:1689-1694): `expires_at <= now`, parse failure →
/// expired (true). Equivalent to the `julianday(expires_at) > julianday(?)`
/// NOT holding.
pub fn timestamp_has_expired(expires_at: &str, now: &str) -> bool {
    match (utc_timestamp_micros(expires_at), utc_timestamp_micros(now)) {
        (Some(e), Some(n)) => e <= n,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Python `_canonical_utc_timestamp` + SQLite `julianday` parity grid
    /// (`/tmp/rtm009_ts_oracle.json` regenerated by the session script).
    /// `julianday` compared to 1e-6 abs tolerance (f64 vs CPython double both
    /// IEEE-754; last-ULP differs on some inputs).
    #[test]
    fn python_sqlite_oracle_parity() {
        // (input, canonical, julianday_or_null, expired_vs_now)
        let rows: &[(&str, Option<&str>, Option<f64>, bool)] = &[
            (
                "2026-10-02T00:00:00+00:00",
                Some("2026-10-02T00:00:00.000000+00:00"),
                Some(2461315.5),
                true,
            ),
            (
                "2026-10-02T00:00:00Z",
                Some("2026-10-02T00:00:00.000000+00:00"),
                Some(2461315.5),
                true,
            ),
            (
                "2026-10-02 04:30:00+04:30",
                Some("2026-10-02T00:00:00.000000+00:00"),
                Some(2461315.5),
                true,
            ),
            (
                "2026-10-02",
                Some("2026-10-02T00:00:00.000000+00:00"),
                Some(2461315.5),
                true,
            ),
            (
                "2026-10-02T12:34:56.123456+00:00",
                Some("2026-10-02T12:34:56.123456+00:00"),
                Some(2461316.024260683),
                false,
            ),
            (
                "2026-10-02T12:34:56.999999Z",
                Some("2026-10-02T12:34:56.999999+00:00"),
                Some(2461316.024270822),
                false,
            ),
            (
                "1970-01-01T00:00:00+00:00",
                Some("1970-01-01T00:00:00.000000+00:00"),
                Some(2440587.5),
                true,
            ),
            (
                "2026-02-28T23:59:59+00:00",
                Some("2026-02-28T23:59:59.000000+00:00"),
                Some(2461100.499988426),
                true,
            ),
            (
                "2024-02-29T12:00:00+00:00",
                Some("2024-02-29T12:00:00.000000+00:00"),
                Some(2460370.0),
                true,
            ),
            (
                "2026-10-02T00:00:00-05:00",
                Some("2026-10-02T05:00:00.000000+00:00"),
                Some(2461315.7083333335),
                false,
            ),
            (
                "2026-10-02 12:00:00",
                Some("2026-10-02T12:00:00.000000+00:00"),
                Some(2461316.0),
                false,
            ),
            ("not-a-date", None, None, true),
            ("", None, None, true),
            ("2026-13-01T00:00:00+00:00", None, None, true),
            (
                "2026-10-02T12:00:00.5Z",
                Some("2026-10-02T12:00:00.500000+00:00"),
                Some(2461316.0000057872),
                false,
            ),
            (
                "2026-10-02T12:00:00.123+00:00",
                Some("2026-10-02T12:00:00.123000+00:00"),
                Some(2461316.0000014235),
                false,
            ),
        ];
        let now = "2026-10-02T00:00:00+00:00";
        for (input, canonical, jd, expired) in rows {
            assert_eq!(
                canonical_utc_timestamp(input).as_deref(),
                *canonical,
                "canonical {input:?}"
            );
            match jd {
                Some(want) => {
                    let got =
                        sqlite_julianday(input).unwrap_or_else(|| panic!("julianday {input:?}"));
                    assert!(
                        (got - want).abs() < 1e-6,
                        "julianday {input:?}: {got} vs {want}"
                    );
                }
                None => assert_eq!(sqlite_julianday(input), None, "julianday {input:?}"),
            }
            assert_eq!(
                timestamp_has_expired(input, now),
                *expired,
                "expired {input:?}"
            );
        }
    }

    #[test]
    fn canonical_normalizes_offset_and_z() {
        assert_eq!(
            canonical_utc_timestamp("2026-10-02 04:30:00+04:30").unwrap(),
            "2026-10-02T00:00:00.000000+00:00"
        );
        assert_eq!(
            canonical_utc_timestamp("2026-10-02T12:00:00Z").unwrap(),
            "2026-10-02T12:00:00.000000+00:00"
        );
        assert_eq!(
            canonical_utc_timestamp("2026-10-02").unwrap(),
            "2026-10-02T00:00:00.000000+00:00"
        );
    }

    #[test]
    fn expired_semantics_match_python() {
        assert!(timestamp_has_expired(
            "2026-10-02T00:00:00+00:00",
            "2026-10-02T00:00:00+00:00"
        ));
        assert!(timestamp_has_expired(
            "2026-10-01T00:00:00+00:00",
            "2026-10-02T00:00:00+00:00"
        ));
        assert!(!timestamp_has_expired(
            "2026-10-03T00:00:00+00:00",
            "2026-10-02T00:00:00+00:00"
        ));
        // Malformed → expired.
        assert!(timestamp_has_expired(
            "not-a-date",
            "2026-10-02T00:00:00+00:00"
        ));
        assert!(timestamp_has_expired("", "2026-10-02T00:00:00+00:00"));
    }

    /// Consumes the language-neutral `expiry-boundaries.v1.json` corpus landed
    /// under `tests/fixtures/guard-expiry-boundaries/` (RM-011/RTM-006 gap-003):
    /// pins `canonical_utc_timestamp`, SQLite `julianday`, and the
    /// `timestamp_has_expired` `<=`/fail-closed contract against a checked-in
    /// expectation record rather than a recomputed Python oracle.
    #[test]
    fn expiry_boundaries_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/fixtures/guard-expiry-boundaries/expiry-boundaries.v1.json"
        );
        let text = std::fs::read_to_string(path).expect("expiry-boundaries fixture");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("valid fixture json");

        for v in doc["canonical_utc_timestamp_vectors"].as_array().unwrap() {
            let input = v["input"].as_str().unwrap();
            let expected = v["expected"].as_str();
            assert_eq!(
                canonical_utc_timestamp(input).as_deref(),
                expected,
                "canonical {input:?}"
            );
        }

        for v in doc["julianday_vectors"].as_array().unwrap() {
            let input = v["input"].as_str().unwrap();
            match v.get("expected") {
                Some(serde_json::Value::Null) | None => {
                    assert_eq!(sqlite_julianday(input), None, "julianday {input:?}")
                }
                Some(serde_json::Value::Number(want)) => {
                    let got =
                        sqlite_julianday(input).unwrap_or_else(|| panic!("julianday {input:?}"));
                    assert!(
                        (got - want.as_f64().unwrap()).abs() < 1e-6,
                        "julianday {input:?}: {got} vs {want}"
                    );
                }
                _ => panic!("unexpected julianday expected for {input:?}"),
            }
        }

        for v in doc["timestamp_has_expired_vectors"].as_array().unwrap() {
            let expires_at = v["expires_at"].as_str().unwrap();
            let now = v["now"].as_str().unwrap();
            let expected = v["expected"].as_bool().unwrap();
            assert_eq!(
                timestamp_has_expired(expires_at, now),
                expected,
                "{}: expires_at={expires_at:?} now={now:?}",
                v["label"].as_str().unwrap_or("")
            );
        }
    }
}
