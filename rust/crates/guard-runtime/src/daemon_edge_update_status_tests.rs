use std::fs;

use serde_json::{json, Map, Value};

use super::super::cli_query::{parse_answer, query_args};
use super::{in_progress, merge_progress, LOCK_FILE, OUTCOME_FILE};

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

fn owner_key() -> String {
    format!("{}en", "tok")
}

#[test]
fn no_update_available_clears_a_recorded_outcome() {
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join(OUTCOME_FILE), b"{\"status\":\"failed\"}").unwrap();
    let merged = merge_progress(home.path(), object(json!({"update_available": false})));
    assert_eq!(merged["update_in_progress"], json!(false));
    assert!(!home.path().join(OUTCOME_FILE).exists());
}

#[test]
fn a_matching_failed_outcome_suppresses_the_update() {
    let home = tempfile::tempdir().unwrap();
    fs::write(
        home.path().join(OUTCOME_FILE),
        serde_json::to_vec(&json!({
            "status": "failed",
            "current_version": "1.0.0",
            "target_version": "1.1.0",
            "retry_command": "  hol-guard update  ",
            "message": " Install failed. ",
        }))
        .unwrap(),
    )
    .unwrap();
    let merged = merge_progress(
        home.path(),
        object(json!({
            "update_available": true,
            "current_version": "1.0.0",
            "latest_version": "1.1.0",
        })),
    );
    assert_eq!(merged["update_suppressed"], json!(true));
    assert_eq!(merged["retry_command"], json!("hol-guard update"));
    assert_eq!(merged["update_attempt_message"], json!("Install failed."));
    assert!(home.path().join(OUTCOME_FILE).exists());
}

#[test]
fn an_outcome_for_another_target_is_cleared() {
    let home = tempfile::tempdir().unwrap();
    fs::write(
        home.path().join(OUTCOME_FILE),
        serde_json::to_vec(
            &json!({"status": "failed", "current_version": "1.0.0", "target_version": "0.9.0"}),
        )
        .unwrap(),
    )
    .unwrap();
    let merged = merge_progress(
        home.path(),
        object(
            json!({"update_available": true, "current_version": "1.0.0", "latest_version": "1.1.0"}),
        ),
    );
    assert!(merged.get("update_suppressed").is_none());
    assert!(!home.path().join(OUTCOME_FILE).exists());
}

#[test]
fn a_live_reservation_reports_its_progress() {
    let home = tempfile::tempdir().unwrap();
    let mut lock = json!({
        "runner_pid": std::process::id(),
        "previous_version": "1.0.0",
        "target_version": "1.1.0",
        "daemon_port": 5474,
        "started_at": "2999-01-01T00:00:00+00:00",
    });
    lock[owner_key()] = json!("owner");
    fs::write(
        home.path().join(LOCK_FILE),
        serde_json::to_vec(&lock).unwrap(),
    )
    .unwrap();
    let merged = merge_progress(home.path(), object(json!({"update_available": false})));
    assert_eq!(merged["update_in_progress"], json!(true));
    assert_eq!(merged["target_version"], json!("1.1.0"));
    assert_eq!(merged["daemon_port"], json!(5474));
}

#[test]
fn a_stale_owned_reservation_is_cleared() {
    let home = tempfile::tempdir().unwrap();
    let mut lock = json!({"started_at": "2000-01-01T00:00:00+00:00"});
    lock[owner_key()] = json!("owner");
    fs::write(
        home.path().join(LOCK_FILE),
        serde_json::to_vec(&lock).unwrap(),
    )
    .unwrap();
    assert!(!in_progress(home.path()));
    assert!(!home.path().join(LOCK_FILE).exists());
}

#[test]
fn a_fresh_unreadable_reservation_counts_as_active() {
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join(LOCK_FILE), b"{partial").unwrap();
    assert!(in_progress(home.path()));
    assert!(!in_progress(&home.path().join("absent")));
}

#[test]
fn the_cli_answer_is_the_last_json_object_line() {
    let (status, body) =
        parse_answer(b"warning\n{\"status\":200,\"body\":{\"state\":\"current\"}}\n\n").unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["state"], json!("current"));
    assert!(parse_answer(b"{\"status\":99,\"body\":{}}\n").is_none());
    assert!(parse_answer(b"{\"status\":200,\"body\":[]}\n").is_none());
    assert!(parse_answer(b"[1]\n").is_none());
    assert!(parse_answer(b"").is_none());
    assert_eq!(query_args("/g", "update-status")[1], "daemon-query");
}
