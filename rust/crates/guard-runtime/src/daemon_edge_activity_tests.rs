use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::*;

const TOKEN: &[u8] = b"activity-test-key";

fn rejected<T: std::fmt::Debug>(parsed: Parsed<T>) -> &'static str {
    parsed.expect("answered").expect_err("rejected")
}

#[test]
fn rejects_list_queries_with_the_code_the_daemon_raises_first() {
    for (query, code) in [
        ("color=red", "unknown_query_parameter"),
        ("limit=5&limit=6", "invalid_query_parameter"),
        ("harness=", "invalid_query_parameter"),
        ("harness", "invalid_query_parameter"),
        ("prompted=yes&limit=0", "invalid_prompted"),
        ("limit=0&occurred_from=bad", "invalid_occurred_from"),
        ("occurred_through=2026-02-30", "invalid_occurred_through"),
        ("limit=101", "limit_out_of_range"),
        ("harness=nope", "invalid_harness"),
        ("execution_status=done", "invalid_execution_status"),
        ("proof_level=hook", "invalid_proof_level"),
        (
            "approval_reuse_status=maybe",
            "invalid_approval_reuse_status",
        ),
        ("extension_id=Git", "invalid_extension_id"),
        ("rule_id=a..b", "invalid_rule_id"),
        (
            "occurred_from=2026-02-02&occurred_through=2026-02-01",
            "invalid_date_range",
        ),
        (
            "occurred_from=2025-01-01&occurred_through=2026-02-02",
            "date_range_out_of_range",
        ),
        ("cursor=gca1.e30.AAAA", "invalid_cursor"),
        ("cursor=nope", "invalid_cursor"),
    ] {
        assert_eq!(rejected(list_query(query, TOKEN)), code, "{query}");
    }
    assert_eq!(
        rejected(list_query(&"a".repeat(8_193), TOKEN)),
        "query_too_long"
    );
}

#[test]
fn relays_list_queries_the_daemon_reads_its_own_way() {
    for query in ["limit=%zz", "limit=%C3%A9", "occurred_through=9999-12-31"] {
        assert!(list_query(query, TOKEN).is_none(), "{query}");
    }
}

#[test]
fn reads_list_filters_and_maps_dates_to_store_bounds() {
    let (filters, cursor) = list_query(
        "limit=10&harness=codex&prompted=false&extension_id=git.core-1\
         &occurred_from=2024-02-28&occurred_through=2024-02-29",
        TOKEN,
    )
    .unwrap()
    .unwrap();
    assert!(cursor.is_none());
    assert_eq!(filters.limit, 10);
    let store = filters.store_filters();
    assert_eq!(store["occurred_from"], json!("2024-02-28T00:00:00+00:00"));
    assert_eq!(store["occurred_until"], json!("2024-03-01T00:00:00+00:00"));
    assert_eq!(store["prompted"], json!(false));
    assert_eq!(
        filters.binding(),
        json!([
            "codex",
            null,
            null,
            false,
            null,
            "git.core-1",
            null,
            "2024-02-28",
            "2024-02-29"
        ])
    );
}

#[test]
fn a_signed_cursor_reads_back_only_for_the_same_filters_and_key() {
    let (filters, _) = list_query("harness=codex", TOKEN).unwrap().unwrap();
    let cursor = signed_cursor(
        "2026-01-01T00:00:00+00:00",
        "act-1",
        &filters.binding(),
        TOKEN,
    )
    .unwrap();
    assert!(cursor.starts_with("gca1."));
    let encoded = cursor.replace('=', "%3D");
    let (_, read) = list_query(&format!("harness=codex&cursor={encoded}"), TOKEN)
        .unwrap()
        .unwrap();
    assert_eq!(
        read,
        Some(("2026-01-01T00:00:00+00:00".to_owned(), "act-1".to_owned()))
    );
    assert_eq!(
        rejected(list_query(
            &format!("harness=cursor&cursor={encoded}"),
            TOKEN
        )),
        "invalid_cursor"
    );
    assert_eq!(
        rejected(list_query(
            &format!("harness=codex&cursor={encoded}"),
            b"other"
        )),
        "invalid_cursor"
    );
}

#[test]
fn signs_cursors_byte_for_byte_as_the_daemon_does() {
    // `_signed_cursor` in Python, for this payload and key.
    let binding = json!([null, null, null, null, null, null, null, null, null]);
    let cursor = signed_cursor("t", "a", &binding, b"k").unwrap();
    let encoded = cursor.split('.').nth(1).unwrap();
    let raw = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    assert_eq!(
        String::from_utf8(raw).unwrap(),
        "{\"activity_id\":\"a\",\"binding\":[null,null,null,null,null,null,null,null,null],\
         \"occurred_at\":\"t\",\"version\":\"guard.command-activity-api.v1\"}"
    );
}

#[test]
fn rejects_analytics_queries_in_the_daemon_order() {
    for (query, code) in [
        ("days=0", "days_out_of_range"),
        ("days=398", "days_out_of_range"),
        ("top_limit=51", "top_limit_out_of_range"),
        ("dimension=harness", "incomplete_dimension_filter"),
        ("dimension=os&dimension_value=mac", "invalid_dimension"),
        (
            "dimension=rule&dimension_value=Bad",
            "invalid_dimension_value",
        ),
        ("dimension=harness&dimension_value=nope", "invalid_harness"),
        ("limit=1", "unknown_query_parameter"),
    ] {
        assert_eq!(rejected(analytics_query(query)), code, "{query}");
    }
    assert_eq!(
        analytics_query("dimension=harness&dimension_value=codex"),
        Some(Ok((
            90,
            10,
            Some("harness".to_owned()),
            Some("codex".to_owned())
        )))
    );
}

#[test]
fn civil_days_round_trip_and_stay_canonical() {
    for date in [
        "1970-01-01",
        "2000-02-29",
        "2024-12-31",
        "0001-01-01",
        "9999-12-31",
    ] {
        assert_eq!(iso_date(parse_date(date).unwrap()).as_deref(), Some(date));
    }
    for date in [
        "2023-02-29",
        "1900-02-29",
        "0000-01-01",
        "20240101",
        "2024-1-01",
        "２０２４-01-01",
    ] {
        assert_eq!(parse_date(date), None, "{date}");
    }
    assert_eq!(days_from_civil(1970, 1, 1), 0);
}

#[test]
fn only_numbers_python_prints_the_same_way_are_answered() {
    assert!(prints_alike(&json!({"a": [1, 0.5, 0.0, -2.25, 12345.678]})));
    for value in [json!(1e16), json!(0.00001), json!([1.5e20])] {
        assert!(!prints_alike(&value), "{value}");
    }
}

#[test]
fn reads_integers_as_python_int_reads_them() {
    for (text, expected) in [
        ("5", Some(Ok(5))),
        ("+5", Some(Ok(5))),
        ("-0", Some(Ok(0))),
        (" 1_0\t", Some(Ok(10))),
        ("007", Some(Ok(7))),
        ("x", Some(Err("invalid_integer"))),
        ("1__0", Some(Err("invalid_integer"))),
        ("_1", Some(Err("invalid_integer"))),
        ("1.5", Some(Err("invalid_integer"))),
        ("+", Some(Err("invalid_integer"))),
        ("\u{0661}", None),
        ("99999999999999999999", None),
    ] {
        assert_eq!(bounded_int(Some(text.to_owned()), 1), expected, "{text}");
    }
}
