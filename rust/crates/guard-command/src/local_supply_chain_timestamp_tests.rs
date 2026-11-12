use crate::local_supply_chain::{parse_timestamp, utc_now_iso, Timestamp};

/// `datetime.isoformat()` writes six fractional digits whenever the instant
/// carries microseconds, and leaves the fraction out only on an exact second.
#[test]
fn isoformat_writes_the_fraction_exactly_as_python_does() {
    assert_eq!(
        Timestamp::from_unix_micros(1_760_800_088_000_000).isoformat(),
        "2025-10-18T15:08:08+00:00"
    );
    assert_eq!(
        Timestamp::from_unix_micros(1_760_800_088_221_982).isoformat(),
        "2025-10-18T15:08:08.221982+00:00"
    );
    assert_eq!(
        Timestamp::from_unix_micros(1_760_800_088_000_007).isoformat(),
        "2025-10-18T15:08:08.000007+00:00"
    );
}

/// Rows stamped by this helper are filtered with SQLite text comparisons
/// against windows Python opens with its own clock. `+` (0x2B) sorts below
/// `.` (0x2E), so a second-precision stamp would read as older than every
/// microsecond-precision instant in the same second and fall out of a
/// `>= since` window it belongs to.
#[test]
fn a_stamp_sorts_after_an_earlier_instant_inside_the_same_second() {
    let since = Timestamp::from_unix_micros(1_760_800_088_221_982).isoformat();
    let stamped = Timestamp::from_unix_micros(1_760_800_088_221_983).isoformat();
    assert!(stamped.as_str() >= since.as_str(), "{stamped} < {since}");

    let same_second = Timestamp::from_unix_micros(1_760_800_088_900_000).isoformat();
    assert!(
        same_second.as_str() >= since.as_str(),
        "{same_second} < {since}"
    );
}

/// The clock helper the evidence writer stamps rows with carries the fraction.
#[test]
fn the_now_helper_keeps_microsecond_precision() {
    let now = utc_now_iso();
    let time = now
        .strip_suffix("+00:00")
        .and_then(|rest| rest.split_once('T'))
        .map(|(_, time)| time.to_owned())
        .unwrap_or_else(|| panic!("{now}"));
    assert!(
        time.len() == 8 || (time.len() == 15 && time.as_bytes()[8] == b'.'),
        "{now}"
    );
}

/// `datetime.fromisoformat` knows how long each month is; this mirror used to
/// accept any day up to 31 and roll the surplus into the next month, so a
/// signed document could carry a date that never existed and still pass a
/// freshness window.
#[test]
fn an_impossible_calendar_day_is_not_an_instant() {
    assert!(parse_timestamp("2026-02-31T00:00:00Z").is_none());
    assert!(parse_timestamp("2026-04-31T00:00:00Z").is_none());
    assert!(parse_timestamp("2025-02-29T00:00:00Z").is_none());
    assert!(parse_timestamp("2026-00-10T00:00:00Z").is_none());

    assert!(parse_timestamp("2024-02-29T00:00:00Z").is_some());
    assert!(parse_timestamp("2000-02-29T00:00:00Z").is_some());
    assert!(parse_timestamp("2026-01-31T00:00:00Z").is_some());
}

/// Python reads the whole string or raises. Text after the instant used to be
/// ignored here, which let one value read as two different times depending on
/// who parsed it.
#[test]
fn text_after_the_instant_is_not_an_instant() {
    assert!(parse_timestamp("2026-10-21T12:00:00Z and later").is_none());
    assert!(parse_timestamp("2026-10-21T12:00:00+00:00Z").is_none());
    assert!(parse_timestamp("2026-10-21T12:00:00!").is_none());
    assert!(parse_timestamp("2026-10-21T25:00:00Z").is_none());
    assert!(parse_timestamp("2026-10-21T12:61:00Z").is_none());
}

/// The shapes Guard's own producers write keep parsing.
#[test]
fn the_shapes_guard_writes_still_parse() {
    for value in [
        "2026-10-21",
        "2026-10-21T12:00",
        "2026-10-21T12:00:00",
        "2026-10-21 12:00:00",
        "2026-10-21T12:00:00Z",
        "2026-10-21T12:00:00.000Z",
        "2026-10-21T12:00:00.221982+00:00",
        "2026-10-21T12:00:00-07:00",
        "2026-10-21T12:00:00+0530",
    ] {
        assert!(parse_timestamp(value).is_some(), "{value}");
    }
    assert_eq!(
        parse_timestamp("2026-10-21T12:00:00-07:00"),
        parse_timestamp("2026-10-21T19:00:00Z")
    );
}
