use std::path::Path;

use super::*;
use crate::local_store_read::STORE_FILE_NAME;

const NOW: &str = "2026-09-27T12:00:00+00:00";
const SOON: &str = "2026-09-27T17:59:59+00:00";
const LATER: &str = "2026-09-27T18:00:00+00:00";

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute_batch(
            "create table sync_state (state_key text primary key, \
             payload_json text not null, updated_at text not null);",
        )
        .unwrap();
    home
}

fn call(home: &Path, op: &str, now: &str, fields: Value) -> Result<Value, String> {
    let mut request = json!({"schema": SCHEMA, "guard_home": home, "op": op, "now": now});
    let object = request.as_object_mut().unwrap();
    for (key, value) in fields.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    handle(&serde_json::from_value(request).unwrap())
}

fn state(home: &Path) -> Value {
    let raw: String = Connection::open(home.join(STORE_FILE_NAME))
        .unwrap()
        .query_row(
            "SELECT payload_json FROM sync_state WHERE state_key = ?1",
            [STATE_KEY],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn put(home: &Path, payload: &str) {
    Connection::open(home.join(STORE_FILE_NAME))
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO sync_state VALUES (?1, ?2, ?3)",
            rusqlite::params![STATE_KEY, payload, NOW],
        )
        .unwrap();
}

fn available() -> Value {
    json!({
        "update_mode": "automatic",
        "auto_updatable": true,
        "blocked_reason": null,
        "update_available": true,
        "latest_version": "3.61.0",
    })
}

#[test]
fn begin_claims_the_check_and_throttles_six_hours() {
    let home = home();
    assert_eq!(
        call(home.path(), "begin", NOW, json!({})),
        Ok(json!({"due": true}))
    );
    assert_eq!(state(home.path())["last_check_at"], NOW);
    assert_eq!(
        call(home.path(), "begin", SOON, json!({})),
        Ok(json!({"due": false}))
    );
    assert_eq!(
        call(home.path(), "begin", LATER, json!({})),
        Ok(json!({"due": true}))
    );
    assert_eq!(state(home.path())["last_check_at"], LATER);
}

#[test]
fn begin_keeps_the_other_saved_fields() {
    let home = home();
    put(home.path(), r#"{"failed_version": "3.60.0", "extra": 1}"#);
    call(home.path(), "begin", NOW, json!({})).unwrap();
    let saved = state(home.path());
    assert_eq!(saved["failed_version"], "3.60.0");
    assert_eq!(saved["extra"], 1);
}

#[test]
fn begin_is_due_for_a_stamp_python_could_not_compare() {
    for stamp in [
        r#"{"last_check_at": "not a time"}"#,
        r#"{"last_check_at": "2026-09-27T11:00:00"}"#,
        r#"{"last_check_at": "2026-09-27"}"#,
        r#"{"last_check_at": 5}"#,
        r#"[1, 2]"#,
        "not json",
    ] {
        let home = home();
        put(home.path(), stamp);
        assert_eq!(
            call(home.path(), "begin", NOW, json!({})),
            Ok(json!({"due": true})),
            "{stamp}"
        );
    }
}

#[test]
fn begin_skips_a_stamp_in_the_future_and_reads_other_offsets() {
    let home = home();
    put(home.path(), r#"{"last_check_at": "2026-09-27T13:00:00Z"}"#);
    assert_eq!(
        call(home.path(), "begin", NOW, json!({})),
        Ok(json!({"due": false}))
    );
    put(
        home.path(),
        r#"{"last_check_at": "2026-09-27T08:00:00-03:00"}"#,
    );
    assert_eq!(
        call(home.path(), "begin", NOW, json!({})),
        Ok(json!({"due": false}))
    );
}

#[test]
fn record_check_applies_an_available_automatic_update() {
    let home = home();
    let result = call(
        home.path(),
        "record_check",
        NOW,
        json!({"status": available()}),
    );
    assert_eq!(
        result,
        Ok(json!({"apply": true, "latest_version": "3.61.0"}))
    );
    let saved = state(home.path());
    assert_eq!(saved["last_status"], available());
    assert_eq!(saved["last_check_at"], NOW);
}

#[test]
fn record_check_holds_back_each_python_condition() {
    let cases = [
        ("update_mode", json!("manual")),
        ("update_mode", json!(null)),
        ("auto_updatable", json!(false)),
        ("auto_updatable", json!("")),
        ("blocked_reason", json!("source_install")),
        ("update_available", json!(0)),
    ];
    for (key, value) in cases {
        let home = home();
        let mut status = available();
        status[key] = value.clone();
        let result = call(home.path(), "record_check", NOW, json!({"status": status})).unwrap();
        assert_eq!(result["apply"], false, "{key}={value}");
        assert_eq!(state(home.path())["last_status"], status);
    }
}

#[test]
fn record_check_defaults_a_missing_mode_to_automatic() {
    let home = home();
    let mut status = available();
    status.as_object_mut().unwrap().remove("update_mode");
    let result = call(home.path(), "record_check", NOW, json!({"status": status})).unwrap();
    assert_eq!(result["apply"], true);
}

#[test]
fn record_check_does_not_retry_the_version_that_failed() {
    let home = home();
    put(home.path(), r#"{"failed_version": "3.61.0"}"#);
    let result = call(
        home.path(),
        "record_check",
        NOW,
        json!({"status": available()}),
    )
    .unwrap();
    assert_eq!(result["apply"], false);
    put(home.path(), r#"{"failed_version": "3.60.0"}"#);
    let result = call(
        home.path(),
        "record_check",
        NOW,
        json!({"status": available()}),
    )
    .unwrap();
    assert_eq!(result["apply"], true);
}

#[test]
fn record_check_without_a_status_marks_the_failed_fetch() {
    let home = home();
    let result = call(home.path(), "record_check", NOW, json!({})).unwrap();
    assert_eq!(result["apply"], false);
    let saved = state(home.path());
    assert_eq!(saved["last_check_error"], true);
    assert_eq!(saved["last_check_at"], NOW);
    assert!(saved.get("last_status").is_none());
}

#[test]
fn record_update_clears_the_failed_version_after_a_clean_run() {
    let home = home();
    put(home.path(), r#"{"failed_version": "3.60.0"}"#);
    let payload = json!({"status": "updated"});
    call(
        home.path(),
        "record_update",
        NOW,
        json!({"latest_version": "3.61.0", "update_payload": payload, "exit_code": 0}),
    )
    .unwrap();
    let saved = state(home.path());
    assert!(saved.get("failed_version").is_none());
    assert_eq!(saved["last_update_result"], payload);
    assert_eq!(saved["last_update_exit_code"], 0);
    assert_eq!(saved["last_update_at"], NOW);
}

#[test]
fn record_update_remembers_a_failed_run() {
    for (payload, exit_code) in [
        (json!({"status": "failed"}), json!(0)),
        (json!({"status": "updated"}), json!(1)),
    ] {
        let home = home();
        call(
            home.path(),
            "record_update",
            NOW,
            json!({"latest_version": "3.61.0", "update_payload": payload, "exit_code": exit_code}),
        )
        .unwrap();
        assert_eq!(state(home.path())["failed_version"], "3.61.0");
    }
}

#[test]
fn record_update_without_a_payload_marks_the_raised_run() {
    let home = home();
    call(
        home.path(),
        "record_update",
        NOW,
        json!({"latest_version": "3.61.0"}),
    )
    .unwrap();
    let saved = state(home.path());
    assert_eq!(saved["last_update_error"], true);
    assert_eq!(saved["failed_version"], "3.61.0");
    assert!(saved.get("last_update_at").is_none());
}

#[test]
fn a_missing_store_is_unavailable_and_stays_missing() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        call(home.path(), "begin", NOW, json!({})),
        Err(UNAVAILABLE.to_owned())
    );
    assert!(!home.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn bad_requests_are_refused() {
    let home = home();
    assert_eq!(
        call(home.path(), "other", NOW, json!({})),
        Err(INVALID.to_owned())
    );
    assert_eq!(
        call(home.path(), "begin", "yesterday", json!({})),
        Err("invalid_current_time".to_owned())
    );
    let wrong_schema = json!({"schema": "x", "guard_home": home.path(), "op": "begin", "now": NOW});
    assert_eq!(
        handle(&serde_json::from_value(wrong_schema).unwrap()),
        Err(INVALID.to_owned())
    );
}

#[test]
fn the_stdin_envelope_answers_and_refuses() {
    let home = home();
    let request = json!({"schema": SCHEMA, "guard_home": home.path(), "op": "begin", "now": NOW});
    let answer: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(answer, json!({"ok": true, "result": {"due": true}}));
    let other = json!({"schema": SCHEMA, "guard_home": home.path(), "op": "other", "now": NOW});
    let refused: Value =
        serde_json::from_slice(&run_command(other.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(refused, json!({"ok": false, "error": INVALID}));
    assert_eq!(run_command(&b"{}"[..]), Err(INVALID.to_owned()));
    assert_eq!(
        run_command(&b"{\"unknown\": 1}"[..]),
        Err(INVALID.to_owned())
    );
}

#[test]
fn python_truthiness_matches() {
    for falsy in [
        json!(null),
        json!(false),
        json!(0),
        json!(0.0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert!(!py_truthy(&falsy), "{falsy}");
    }
    for truthy in [
        json!(true),
        json!(1),
        json!(-0.5),
        json!("x"),
        json!([0]),
        json!({"a": 0}),
    ] {
        assert!(py_truthy(&truthy), "{truthy}");
    }
}
