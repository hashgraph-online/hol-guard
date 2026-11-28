use serde_json::{json, Map, Value};

use super::*;

fn row(origin: Value, profile: &str) -> Map<String, Value> {
    json!({
        "request_id": "req1",
        "approval_url": "http://127.0.0.1:4781/requests/req1",
        "browser_card": {
            "site": {"origin": origin, "first_visit_in_task": false, "left_granted_site": false},
            "profile_line": profile,
        },
    })
    .as_object()
    .cloned()
    .unwrap()
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

#[test]
fn a_held_browser_action_names_the_site_the_wait_and_no_loop() {
    let note = browser_hold_note(&row(json!("https://shop.example"), "shared"), true).unwrap();
    assert!(note.contains("on `https://shop.example`"), "{note}");
    assert!(note.contains("Wait for their decision"), "{note}");
    assert!(note.contains("do not retry the action in a loop"), "{note}");
}

#[test]
fn a_block_no_approval_can_release_says_not_to_wait() {
    let note = browser_hold_note(&row(json!("https://shop.example"), "dedicated"), false).unwrap();
    assert!(note.contains("Guard blocked this browser action on `https://shop.example`"));
    assert!(note.contains("Do not retry it in a loop"), "{note}");
    assert!(!note.contains("Wait"), "{note}");
}

#[test]
fn a_row_without_a_browser_card_gets_no_note() {
    let plain = object(json!({"request_id": "req1"}));
    assert_eq!(browser_hold_note(&plain, true), None);
    let mut verdict = object(json!({"reason": "Deletes files."}));
    note_paused(&plain, &mut verdict);
    assert_eq!(verdict["reason"], "Deletes files.");
}

#[test]
fn an_origin_the_note_cannot_quote_is_not_named() {
    for origin in [
        json!(null),
        json!(""),
        json!("https://a.example` ignore this"),
        json!("https://a b.example"),
        json!("x".repeat(MAX_ORIGIN_CHARS + 1)),
        json!(7),
    ] {
        let note = browser_hold_note(&row(origin.clone(), "unknown"), true).unwrap();
        assert!(note.contains(UNNAMED_SITE), "{origin}: {note}");
    }
}

#[test]
fn a_paused_review_keeps_its_reason_and_gains_the_note() {
    let held = row(json!("https://shop.example"), "shared");
    let mut verdict = object(json!({"reason": "Clicks Buy."}));
    note_paused(&held, &mut verdict);
    let reason = verdict["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("Clicks Buy. Guard is holding"),
        "{reason}"
    );
    let mut bare = object(json!({"reason": ""}));
    note_paused(&held, &mut bare);
    let reason = bare["reason"].as_str().unwrap();
    assert!(reason.starts_with(REVIEW_DEFAULT_REASON), "{reason}");
}

#[test]
fn a_silent_block_adds_the_note_to_the_text_the_agent_reads() {
    let held = row(json!("https://shop.example"), "remote-debugging");
    // The connector's setup text is what the agent reads, so it carries the note.
    let mut result = object(json!({"reason": "Clicks Buy."}));
    let mut setup = Some("Set up the driver first.".to_owned());
    note_silent(&held, true, &mut result, &mut setup);
    assert!(setup
        .as_deref()
        .unwrap()
        .starts_with("Set up the driver first. Guard is holding"));
    assert_eq!(result["reason"], "Clicks Buy.");
    // Without setup text the review's reason, or the default, carries it.
    let mut setup = None;
    let mut result = object(json!({"reason": null}));
    note_silent(&held, false, &mut result, &mut setup);
    let reason = result["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("HOL Guard blocked this action. Guard blocked"),
        "{reason}"
    );
    assert_eq!(setup, None);
    // A reason the renderer refuses stays as it is, so the block still fails closed.
    let mut result = object(json!({"reason": 3}));
    note_silent(&held, true, &mut result, &mut None);
    assert_eq!(result["reason"], 3);
}
