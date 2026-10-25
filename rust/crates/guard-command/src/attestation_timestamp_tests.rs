//! The one timestamp shape an attestation may carry, and the instant it names.

use super::attestation_timestamp::parse_attestation_timestamp;

const NOON: i64 = 1_792_756_800_000_000;

#[test]
fn a_trailing_zulu_is_an_utc_instant() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00Z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23t12:00:00z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("  2026-10-23T12:00:00Z  "),
        Some(NOON)
    );
    assert_eq!(parse_attestation_timestamp("2026-10-23 12:00Z"), Some(NOON));
}

#[test]
fn padding_python_strips_is_stripped() {
    // `str.strip` removes U+001C..U+001F; `char::is_whitespace` does not.
    assert_eq!(
        parse_attestation_timestamp("\u{1f}2026-10-23T12:00:00Z\u{1c}"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("\u{3000}2026-10-23T12:00:00Z\u{85}"),
        Some(NOON)
    );
    assert_eq!(parse_attestation_timestamp("\u{1d}\u{1e}"), None);
}

#[test]
fn a_naive_instant_is_rejected() {
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23"), None);
    assert_eq!(parse_attestation_timestamp(""), None);
    assert_eq!(parse_attestation_timestamp("   "), None);
}

#[test]
fn spellings_outside_the_shape_are_refused() {
    // Each of these parses on some interpreter and not on another.
    for spelling in [
        "20261023T120000Z",
        "2026-10-23T1200Z",
        "2026-10-23T12Z",
        "2026-W43-5T12:00:00Z",
        "2026-10-23X12:00:00Z",
        "2026-10-23\u{2603}12:00:00+00:00",
        "2026-10-23T12:00.5Z",
        "2026-10-23T12:00:00,5Z",
        "2026-10-23T12:00:00.5Z",
        "2026-10-23T12:00:00.1234Z",
        "2026-10-23T12:00:00+0530",
        "2026-10-23T12:00:00+05",
        "2026-10-23T12:00:00Z+00:00",
        "2026-10-23T24:00:00Z",
    ] {
        assert_eq!(parse_attestation_timestamp(spelling), None, "{spelling:?}");
    }
}

#[test]
fn a_fraction_has_three_or_six_digits() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00.500Z"),
        Some(NOON + 500_000)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00.123456Z"),
        Some(NOON + 123_456)
    );
}

#[test]
fn an_offset_may_carry_seconds() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+00:00:30"),
        Some(NOON - 30_000_000)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+05:30"),
        Some(NOON - 19_800_000_000)
    );
    // A fraction of a second of offset is not an offset either. Interpreters
    // disagree about what one means — the older reading dropped it and called
    // the result UTC, the newer one honours it — so the shape refuses it and
    // the string is no instant.
    for spelling in [
        "2026-10-23T12:00:00-00:00:00.000001",
        "2026-10-23T12:00:00+00:00:00.999999",
        "2026-10-23T12:00:00-00:00:01.000001",
        "2026-10-23T12:00:00+05:30:15.500000",
    ] {
        assert_eq!(parse_attestation_timestamp(spelling), None, "{spelling}");
    }
    // A whole day of offset is not an offset.
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+24:00"),
        None
    );
}

#[test]
fn a_date_that_does_not_exist_is_rejected() {
    assert_eq!(parse_attestation_timestamp("2026-02-30T00:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-13-01T00:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:60Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:60:00Z"), None);
    assert!(parse_attestation_timestamp("2024-02-29T00:00:00Z").is_some());
}

#[test]
fn a_non_ascii_digit_is_not_a_digit() {
    assert_eq!(parse_attestation_timestamp("٢٠٢٦-10-23T12:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00ğ"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00ZZ"), None);
    assert_eq!(parse_attestation_timestamp("not-a-time"), None);
}

#[test]
fn an_instant_outside_the_calendar_is_refused() {
    // Python catches the `OverflowError` the shift to UTC raises here, so
    // neither side yields an instant.
    assert_eq!(
        parse_attestation_timestamp("0001-01-01T00:00:00+01:00"),
        None
    );
    assert!(parse_attestation_timestamp("0001-01-01T00:00:00+00:00").is_some());
    assert!(parse_attestation_timestamp("9999-12-31T23:59:59.999999Z").is_some());
}
