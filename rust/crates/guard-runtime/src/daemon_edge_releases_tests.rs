use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::json;

use super::*;

/// The cache is process-wide, so tests that fetch take turns.
static SERIAL: Mutex<()> = Mutex::new(());

fn params(query: &str) -> BTreeMap<String, Vec<String>> {
    parse_params(query).expect("decodable query")
}

fn index_document() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": "guard-release-client-index/v1",
        "page": 1,
        "pageSize": 50,
        "total": 0,
        "totalPages": 0,
        "generatedAt": "2026-11-01T00:00:00Z",
        "releases": [],
    }))
    .unwrap()
}

#[test]
fn rollout_switch_reads_like_python() {
    assert!(rollout_enabled(None));
    assert!(rollout_enabled(Some("on")));
    for value in ["off", "0", "false", " Disabled "] {
        assert!(!rollout_enabled(Some(value)), "{value}");
    }
}

#[test]
fn index_target_defaults_and_bounds() {
    let target = target_for(Kind::Index, &params("")).unwrap();
    assert_eq!(target.path, "/api/guard/releases/v1/index");
    assert_eq!(target.query, "page=1&pageSize=50");
    let target = target_for(Kind::Index, &params("page=3&pageSize=10")).unwrap();
    assert_eq!(target.query, "page=3&pageSize=10");
    for query in [
        "page=0",
        "page=1001",
        "pageSize=51",
        "page=1234567",
        "page=-1",
        "page=%C2%B2",
        "page=1&page=2",
        "page=x",
    ] {
        assert_eq!(
            target_for(Kind::Index, &params(query)),
            Err("release_feed_request_invalid"),
            "{query}"
        );
    }
}

#[test]
fn blank_values_are_dropped_as_parse_qs_drops_them() {
    let target = target_for(Kind::Index, &params("page=&pageSize=")).unwrap();
    assert_eq!(target.query, "page=1&pageSize=50");
}

#[test]
fn detail_target_needs_exactly_one_valid_slug() {
    let target = target_for(Kind::Detail, &params("slug=v3.16.3")).unwrap();
    assert_eq!(target.path, "/api/guard/releases/v1/release");
    assert_eq!(target.query, "slug=v3.16.3");
    for query in [
        "",
        "slug=a&slug=b",
        "slug=Upper",
        "slug=-lead",
        "slug=a%2Fb",
    ] {
        assert_eq!(
            target_for(Kind::Detail, &params(query)),
            Err("release_feed_request_invalid"),
            "{query}"
        );
    }
    assert!(valid_slug(&"a".repeat(128)));
    assert!(!valid_slug(&"a".repeat(129)));
}

#[test]
fn projects_a_fetched_index_and_serves_it_fresh_from_cache() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_cache_for_tests();
    let target = target_for(Kind::Index, &params("page=7")).unwrap();
    let seen = Cell::new(0);
    let answer = project(&target, |url, etag| {
        seen.set(seen.get() + 1);
        assert_eq!(
            url,
            "https://hol.org/api/guard/releases/v1/index?page=7&pageSize=50"
        );
        assert_eq!(etag, None);
        Ok((200, Some("\"v1\"".to_owned()), index_document()))
    });
    let Answer::Body(body) = answer else {
        panic!("expected a body, got {answer:?}");
    };
    assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    let again = project(&target, |_, _| panic!("a fresh document is not refetched"));
    assert_eq!(again, Answer::Body(body));
    assert_eq!(seen.get(), 1);
    reset_cache_for_tests();
}

#[test]
fn maps_upstream_statuses_and_transport_failures() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let target = target_for(Kind::Detail, &params("slug=v1.0.0")).unwrap();
    let cases: [(Exchange, u16, &str); 5] = [
        (Ok((404, None, Vec::new())), 404, "release_not_found"),
        (
            Ok((500, None, Vec::new())),
            502,
            "release_feed_upstream_error",
        ),
        // A 304 with nothing cached is an upstream that answered wrongly.
        (
            Ok((304, None, Vec::new())),
            502,
            "release_feed_upstream_error",
        ),
        (Err(()), 503, "release_feed_transport_failed"),
        (
            Ok((200, None, vec![0xff, 0xfe])),
            503,
            "release_feed_transport_failed",
        ),
    ];
    for (exchange, status, code) in cases {
        reset_cache_for_tests();
        let answer = project(&target, move |_, _| exchange);
        assert_eq!(answer, Answer::Error(status, json!({"error": code})));
    }
    reset_cache_for_tests();
}

#[test]
fn a_document_the_projector_refuses_is_its_typed_error() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_cache_for_tests();
    let target = target_for(Kind::Index, &params("page=9")).unwrap();
    let answer = project(&target, |_, _| Ok((200, None, b"not json".to_vec())));
    assert_eq!(
        answer,
        Answer::Error(400, json!({"error": "release_feed_body_invalid"}))
    );
    reset_cache_for_tests();
    let answer = project(&target, |_, _| Ok((200, None, b"{}".to_vec())));
    assert_eq!(
        answer,
        Answer::Error(502, json!({"error": "release_feed_payload_invalid"}))
    );
    reset_cache_for_tests();
}
