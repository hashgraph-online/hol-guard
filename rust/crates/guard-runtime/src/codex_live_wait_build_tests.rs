use serde_json::{json, Map, Value};

use super::{prepare, FACTS_KEY, NOT_LIVE_KEY, PAYLOAD_KEY};
use crate::codex_hook_identity::current_process_identity;
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_outbox_identity::correlation_id;

const NOW: &str = "2026-10-29T12:00:00+00:00";

fn live_process() -> Value {
    let (pid, token) = current_process_identity().expect("this process has a start token");
    json!({"pid": pid, "startToken": token})
}

fn home(tag: &str, config: &str) -> std::path::PathBuf {
    let home = temp_home(tag);
    std::fs::write(home.join("config.toml"), config).unwrap();
    home
}

fn args(harness: &str, facts: Value) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert(
        "request".to_owned(),
        json!({"request_id": "r-1", "harness": harness}),
    );
    args.insert("now".to_owned(), Value::from(NOW));
    args.insert(FACTS_KEY.to_owned(), facts);
    args
}

fn payload_args(harness: &str, payload: Value, workspace: Value) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert(
        "request".to_owned(),
        json!({"request_id": "r-raw", "harness": harness, "workspace": workspace}),
    );
    args.insert("now".to_owned(), Value::from(NOW));
    args.insert(PAYLOAD_KEY.to_owned(), payload);
    args
}

fn facts(timeout_seconds: Value, workspace: Value) -> Value {
    json!({"process": live_process(), "timeout_seconds": timeout_seconds, "workspace": workspace})
}

/// The prepared arguments' link metadata and the request's snapshot.
fn built(prepared: &Map<String, Value>) -> Option<(Value, Value)> {
    let link = prepared.get("codex_live_wait")?;
    let metadata = serde_json::from_str(link["metadata_json"].as_str()?).ok()?;
    let snapshot = prepared["request"].get("continuation_snapshot")?.clone();
    Some((metadata, snapshot))
}

#[test]
fn a_live_bridge_gets_its_wait_and_suspended_response_snapshot() {
    let guard_home = home("live-wait-build", "approval_wait_timeout_seconds = 30\n");
    let prepared = prepare(
        "add_approval_request",
        &args("codex", facts(json!(90), json!("/work/project"))),
        &guard_home,
    )
    .unwrap();
    assert!(!prepared.contains_key(FACTS_KEY));
    assert_eq!(
        prepared["codex_live_wait"]["workspace"],
        json!("/work/project")
    );
    assert!(!prepared.contains_key(NOT_LIVE_KEY));
    let (metadata, snapshot) = built(&prepared).expect("the wait is built");
    assert_eq!(
        metadata,
        json!({
            "codex_hook_waits_for_browser_approval": true,
            "codex_browser_wait_started_at": NOW,
            "codex_browser_wait_deadline_at": "2026-10-29T12:00:30+00:00",
            "codex_browser_wait_timeout_seconds": 30,
            "codex_browser_wait_process": live_process(),
            "hook_event_name": "PreToolUse",
            "workspace": "/work/project",
        })
    );
    assert_eq!(
        snapshot,
        json!({
            "correlationId": correlation_id("r-1").unwrap(),
            "capability": "suspended-response",
            "hookAttached": true,
            "opaqueTargetId": null,
            "waitDeadline": "2026-10-29T12:00:30+00:00",
        })
    );
}

#[test]
fn the_bridges_shorter_budget_bounds_the_wait() {
    let guard_home = home("live-wait-outer", "approval_wait_timeout_seconds = 300\n");
    let prepared = prepare(
        "add_approval_request",
        &args("codex", facts(json!(45), Value::Null)),
        &guard_home,
    )
    .unwrap();
    assert_eq!(prepared["codex_live_wait"]["workspace"], Value::Null);
    let (metadata, snapshot) = built(&prepared).expect("the wait is built");
    assert_eq!(metadata["codex_browser_wait_timeout_seconds"], 45);
    assert!(metadata.get("workspace").is_none());
    assert_eq!(snapshot["waitDeadline"], "2026-10-29T12:00:45+00:00");
}

#[test]
fn a_bridge_that_cannot_wait_is_queued_as_a_manual_retry() {
    let guard_home = home("live-wait-refused", "approval_wait_timeout_seconds = 30\n");
    let no_wait = home("live-wait-zero", "approval_wait_timeout_seconds = 0\n");
    let mut dead = facts(json!(90), Value::Null);
    dead["process"]["startToken"] = Value::from("not-the-start-token");
    let cases = [
        (args("codex", dead), &guard_home),
        (
            args("claude-code", facts(json!(90), Value::Null)),
            &guard_home,
        ),
        (args("codex", facts(json!(0), Value::Null)), &guard_home),
        (args("codex", facts(json!(601), Value::Null)), &guard_home),
        (args("codex", facts(json!(true), Value::Null)), &guard_home),
        (args("codex", facts(json!(90), json!(7))), &guard_home),
        (args("codex", facts(json!(90), Value::Null)), &no_wait),
    ];
    for (mut args, guard_home) in cases {
        // A snapshot the caller sent along cannot make the request resumable.
        args.get_mut("request").unwrap()["continuation_snapshot"] = json!({
            "capability": "suspended-response",
            "hookAttached": true,
            "waitDeadline": "2026-10-29T12:10:00+00:00",
        });
        let prepared = prepare("add_approval_request", &args, guard_home).unwrap();
        assert!(!prepared.contains_key(FACTS_KEY), "{args:?}");
        assert!(
            prepared["request"].get("continuation_snapshot").is_none(),
            "{args:?}"
        );
        assert!(built(&prepared).is_none(), "{args:?}");
        assert!(!prepared.contains_key("codex_live_wait"), "{args:?}");
        assert_eq!(prepared[NOT_LIVE_KEY], true, "{args:?}");
    }
}

#[test]
fn only_a_queue_write_with_facts_is_prepared() {
    let guard_home = home("live-wait-none", "");
    let mut without = args("codex", Value::Null);
    without.remove(FACTS_KEY);
    assert!(prepare("add_approval_request", &without, &guard_home).is_none());
    let with = args("codex", facts(json!(90), Value::Null));
    assert!(prepare("add_native_review_approval_request", &with, &guard_home).is_some());
    // A silent block that links its approval holds the bridge's wait too.
    assert!(prepare(
        "add_silent_native_review_approval_request",
        &with,
        &guard_home
    )
    .is_some());
}

#[test]
fn raw_codex_payload_facts_are_extracted_before_the_queue_write() {
    let guard_home = home(
        "live-wait-raw-payload",
        "approval_wait_timeout_seconds = 30\n",
    );
    let prepared = prepare(
        "add_native_review_approval_request",
        &payload_args(
            "codex",
            json!({
                "guard_codex_browser_wait_process": live_process(),
                "guard_codex_browser_wait_timeout_seconds": 90,
            }),
            json!("/work/project"),
        ),
        &guard_home,
    )
    .unwrap();
    assert!(!prepared.contains_key(PAYLOAD_KEY));
    assert_eq!(
        prepared["codex_live_wait"]["workspace"],
        json!("/work/project")
    );
    assert_eq!(
        built(&prepared).unwrap().0["codex_browser_wait_timeout_seconds"],
        30
    );
}

#[test]
fn raw_codex_payload_without_wait_facts_clears_a_supplied_snapshot() {
    let guard_home = home("live-wait-raw-none", "approval_wait_timeout_seconds = 30\n");
    let mut args = payload_args("Codex", json!({}), Value::Null);
    args.get_mut("request").unwrap()["continuation_snapshot"] = json!({
        "capability": "suspended-response",
        "hookAttached": true,
    });
    let prepared = prepare("add_native_review_approval_request", &args, &guard_home).unwrap();
    assert!(!prepared.contains_key(NOT_LIVE_KEY));
    assert!(!prepared.contains_key(PAYLOAD_KEY));
    assert!(prepared["request"].get("continuation_snapshot").is_none());
}

#[test]
fn non_codex_raw_payloads_are_left_for_the_daemon() {
    let guard_home = home(
        "live-wait-raw-non-codex",
        "approval_wait_timeout_seconds = 30\n",
    );
    let args = payload_args(
        "claude-code",
        json!({"guard_codex_browser_wait_timeout_seconds": 90}),
        Value::Null,
    );
    assert!(prepare("add_native_review_approval_request", &args, &guard_home).is_none());
}

#[test]
fn an_unusable_raw_payload_is_removed_before_the_manual_retry_write() {
    let guard_home = home("live-wait-raw-unusable", "");
    let args = payload_args("codex", json!({"event": "PreToolUse"}), Value::Null);
    let prepared = prepare(
        "add_silent_native_review_approval_request",
        &args,
        &guard_home,
    )
    .expect("the queue write still proceeds");
    assert!(!prepared.contains_key(PAYLOAD_KEY));
    assert!(!prepared.contains_key(NOT_LIVE_KEY));
}

#[test]
fn a_non_live_raw_payload_cannot_keep_a_suspended_response() {
    let guard_home = home(
        "live-wait-raw-not-live",
        "approval_wait_timeout_seconds = 30\n",
    );
    let mut args = payload_args(
        "codex",
        json!({"guard_codex_browser_wait_timeout_seconds": 0}),
        Value::Null,
    );
    args.get_mut("request").unwrap()["continuation_snapshot"] = json!({
        "capability": "suspended-response",
        "hookAttached": true,
    });
    let prepared = prepare(
        "add_silent_native_review_approval_request",
        &args,
        &guard_home,
    )
    .expect("the queue write still proceeds");
    assert!(!prepared.contains_key(PAYLOAD_KEY));
    assert_eq!(prepared[NOT_LIVE_KEY], true);
    assert!(prepared["request"].get("continuation_snapshot").is_none());
}
