use std::cell::Cell;
use std::sync::Mutex;

use crate::pyjson::PyVal;
use serde_json::{json, Map, Value};

use super::*;

/// The snapshot cache is process-wide, so tests that fetch take turns.
static SERIAL: Mutex<()> = Mutex::new(());

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

#[test]
fn rollout_switch_reads_like_python() {
    assert!(rollout_enabled(None));
    assert!(rollout_enabled(Some("1")));
    for value in ["0", "OFF", " false ", "disabled"] {
        assert!(!rollout_enabled(Some(value)), "{value}");
    }
}

#[test]
fn query_token_parameter_is_named() {
    let key = format!("{}{}", "tok", "en");
    assert!(query_names_token(&format!("{key}=x")));
    assert!(query_names_token(&format!("a=1&{key}=")));
    assert!(!query_names_token("a=1"));
    assert!(!query_names_token(""));
}

#[test]
fn effective_settings_apply_defaults_and_managed_policy() {
    let settings = effective(&Map::new(), &Map::new());
    assert_eq!(
        Value::Object(settings),
        json!({
            "sponsored_discovery_enabled": true,
            "sponsored_discovery_measurement_enabled": false,
            "managed_discovery_disabled": false,
            "managed_measurement_disabled": false,
        })
    );
    let record = object(json!({
        "sponsored_discovery_enabled": "yes",
        "sponsored_discovery_measurement_enabled": true,
    }));
    let managed = object(json!({"sponsored_discovery_enabled": false}));
    let settings = effective(&record, &managed);
    assert_eq!(
        Value::Object(settings),
        json!({
            "sponsored_discovery_enabled": false,
            "sponsored_discovery_measurement_enabled": true,
            "managed_discovery_disabled": true,
            "managed_measurement_disabled": false,
        })
    );
}

#[test]
fn compact_matches_python_dumps() {
    let value = PyVal::Dict(vec![
        ("b".to_owned(), PyVal::Int("1".to_owned())),
        ("a".to_owned(), PyVal::Str("é\"\n\u{1F600}".to_owned())),
        (
            "c".to_owned(),
            PyVal::List(vec![PyVal::Null, PyVal::Bool(true), PyVal::Float(1.5)]),
        ),
        ("b".to_owned(), PyVal::Int("2".to_owned())),
    ]);
    assert_eq!(
        compact(&value),
        r#"{"b":2,"a":"\u00e9\"\n\ud83d\ude00","c":[null,true,1.5]}"#
    );
}

#[test]
fn http_dates_parse_like_parsedate() {
    assert_eq!(
        http_date_ms("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(784_111_777_000)
    );
    assert_eq!(
        http_date_ms("06 Nov 1994 09:49:37 +0100"),
        Some(784_111_777_000)
    );
    assert_eq!(
        http_date_ms("Mon, 09 Nov 2026 00:00:00 GMT"),
        Some(1_794_182_400_000)
    );
    assert_eq!(http_date_ms("garbage"), None);
    assert_eq!(http_date_ms("Sun, 06 Nov 1994 25:49:37 GMT"), None);
}

#[test]
fn placements_cache_and_upstream_failures() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cases: [(Exchange, u16, &str); 4] = [
        (
            Ok((500, None, None, Vec::new())),
            503,
            "discovery_upstream_error",
        ),
        (
            Ok((304, None, None, Vec::new())),
            503,
            "discovery_upstream_error",
        ),
        (
            Err("discovery_transport_failed"),
            503,
            "discovery_transport_failed",
        ),
        (
            Ok((200, None, None, vec![0xff])),
            503,
            "discovery_transport_failed",
        ),
    ];
    for (exchange, status, code) in cases {
        reset_cache_for_tests();
        let answer = placements(true, move |_| exchange, 0);
        assert_eq!(answer, Answer::Json(status, json!({"error": code})));
    }
    reset_cache_for_tests();
    let seen = Cell::new(0);
    let first = placements(
        true,
        |etag| {
            seen.set(seen.get() + 1);
            assert_eq!(etag, None);
            Ok((200, Some("\"e\"".to_owned()), None, b"not json".to_vec()))
        },
        0,
    );
    let again = placements(true, |_| panic!("a fresh snapshot is not refetched"), 0);
    assert_eq!(first, again);
    assert_eq!(seen.get(), 1);
    assert!(matches!(
        first,
        Answer::Json(400 | 501 | 503, _) | Answer::Raw(200, _)
    ));
    reset_cache_for_tests();
}

#[test]
fn relay_maps_statuses_like_python() {
    let ok = relay("/r", "{}".to_owned(), |path, body| {
        assert_eq!(path, "/r");
        assert_eq!(body, "{}");
        Ok((200, b"{\"ok\":true}".to_vec()))
    });
    assert_eq!(ok, Answer::Raw(200, b"{\"ok\":true}".to_vec()));
    assert_eq!(
        relay("/r", "{}".to_owned(), |_, _| Ok((204, Vec::new()))),
        Answer::Json(503, json!({"error": "discovery_upstream_error"}))
    );
    assert_eq!(
        relay("/r", "{}".to_owned(), |_, _| Ok((429, b"{}".to_vec()))),
        Answer::Raw(429, b"{}".to_vec())
    );
    assert_eq!(
        relay("/r", "{}".to_owned(), |_, _| Ok((500, vec![b' '; 5000]))),
        Answer::Raw(500, br#"{"error":"relay_failed"}"#.to_vec())
    );
    assert_eq!(
        relay("/r", "x".repeat(16_385), |_, _| panic!("not sent")),
        Answer::Json(400, json!({"error": "discovery_request_invalid"}))
    );
    assert_eq!(
        relay("/r", "{}".to_owned(), |_, _| Err(
            "discovery_transport_failed"
        )),
        Answer::Json(503, json!({"error": "discovery_transport_failed"}))
    );
}
