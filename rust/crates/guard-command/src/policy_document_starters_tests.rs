//! Replays `starter_vectors.json`, recorded from the original Python
//! `policy_starters.render_starter_yaml`, through the native queries.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{list, quote, render, STARTERS};
use crate::policy_document::evaluate;

const VECTORS: &str = include_str!("../testdata/policy_starters/starter_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

#[test]
fn the_listing_matches_the_python_gallery() {
    assert_eq!(list(), vectors()["starters"]);
}

#[test]
fn every_starter_renders_the_python_text() {
    let vectors = vectors();
    let created_at = vectors["created_at"].as_str().expect("created_at");
    let rendered = vectors["rendered"].as_object().expect("rendered");
    assert_eq!(rendered.len(), STARTERS.len());
    for (id, expected) in rendered {
        let answer = render(&json!({"id":id,"created_at":created_at})).expect("answer");
        assert_eq!(&answer, expected, "{id}");
    }
}

#[test]
fn the_queries_answer_through_the_document_evaluator() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let listing = evaluate("starters", &json!({}), deadline).expect("listing");
    assert_eq!(listing, json!({"ok":vectors()["starters"]}));
    let unknown = evaluate(
        "starter",
        &json!({"id":"nonsense","created_at":"2026-01-02T03:04:05Z"}),
        deadline,
    )
    .expect("unknown");
    assert_eq!(unknown, json!({"ok":null}));
}

#[test]
fn malformed_requests_are_refused() {
    let stamp = "2026-01-02T03:04:05Z";
    for request in [
        json!({"id":"blank"}),
        json!({"created_at":stamp}),
        json!({"id":1,"created_at":stamp}),
        json!({"id":"blank","created_at":1}),
        json!({"id":"blank","created_at":stamp,"extra":true}),
        json!(["blank", stamp]),
    ] {
        let error = render(&request).expect_err("refused");
        assert_eq!(error["type"], "TypeError", "{request}");
    }
    for stamp in [
        "",
        "2026-01-02T03:04:05",
        "2026-01-02 03:04:05Z",
        "2026-01-02T03:04:05.000Z",
        "2026-1-02T03:04:05Z0",
        "２０２６-01-02T03:04:05Z",
        "2026-99-99T99:99:99Z",
        "2026-02-30T03:04:05Z",
        "2025-02-29T03:04:05Z",
        "2026-01-02T24:00:00Z",
        "2026-01-02T03:60:05Z",
        "0000-01-02T03:04:05Z",
    ] {
        let error = render(&json!({"id":"blank","created_at":stamp})).expect_err("refused");
        assert_eq!(error["type"], "ValueError", "{stamp}");
    }
}

#[test]
fn starter_text_is_quoted_as_ascii_json() {
    assert_eq!(quote("a \"b\" \\ c"), r#""a \"b\" \\ c""#);
    assert_eq!(quote("\n\t\u{1}\u{7f}~"), r#""\n\t\u0001\u007f~""#);
    assert_eq!(quote("é😀"), "\"\\u00e9\\ud83d\\ude00\"");
    for starter in STARTERS {
        assert!(starter.name.is_ascii() && starter.summary.is_ascii());
        for rule in starter.rules {
            assert!(rule.description.is_ascii() && rule.example_name.is_ascii());
        }
    }
}

#[test]
fn starter_summaries_do_not_promise_approval_prompts_their_block_rules_do_not_give() {
    for starter in STARTERS.iter().filter(|starter| !starter.rules.is_empty()) {
        assert!(starter.rules.iter().all(|rule| rule.effect == "block"));
        assert!(!starter.summary.to_lowercase().contains("ask"));
        assert!(!starter
            .rules
            .iter()
            .any(|rule| rule.description.contains("approving")));
    }
}

#[test]
fn every_starter_carries_two_example_tests() {
    for starter in STARTERS {
        let text =
            render(&json!({"id":starter.id,"created_at":"2026-01-02T03:04:05Z"})).expect("answer");
        let text = text.as_str().expect("text");
        assert_eq!(text.matches("expect:").count(), 2, "{}", starter.id);
    }
}
