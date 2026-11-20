use std::fs;

use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;

fn claim(home: &std::path::Path, now: f64) -> Value {
    dispatch(&json!({"now": now}), home.to_str().expect("utf-8 home")).expect("claim answer")
}

fn stored_attempt(home: &std::path::Path) -> Value {
    let text = fs::read_to_string(home.join("package-firewall-refresh.json")).expect("state");
    serde_json::from_str::<Value>(&text).expect("state json")["last_refresh_attempt_at"].clone()
}

#[test]
fn the_first_claim_refreshes_and_records_the_attempt() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path().join("guard-home");
    assert_eq!(claim(&home, 1_000.5), json!({"refresh": true}));
    assert_eq!(stored_attempt(&home), json!(1_000.5));
}

#[test]
fn a_claim_inside_the_interval_is_refused_and_keeps_the_recorded_attempt() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path();
    assert_eq!(claim(home, 1_000.0), json!({"refresh": true}));
    assert_eq!(claim(home, 1_299.9), json!({"refresh": false}));
    assert_eq!(stored_attempt(home), json!(1_000.0));
    assert_eq!(claim(home, 1_300.0), json!({"refresh": true}));
    assert_eq!(stored_attempt(home), json!(1_300.0));
}

#[test]
fn an_integer_attempt_written_by_an_older_runtime_still_throttles() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path();
    fs::write(
        home.join("package-firewall-refresh.json"),
        br#"{"last_refresh_attempt_at":1000}"#,
    )
    .expect("state");
    assert_eq!(claim(home, 1_100.0), json!({"refresh": false}));
}

#[test]
fn an_unreadable_or_foreign_state_does_not_block_the_refresh() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path();
    for body in [
        "not json",
        "[]",
        r#"{"last_refresh_attempt_at":"1000"}"#,
        "{}",
    ] {
        fs::write(home.join("package-firewall-refresh.json"), body).expect("state");
        assert_eq!(claim(home, 1_100.0), json!({"refresh": true}), "{body}");
    }
}

#[test]
fn a_home_that_cannot_record_the_attempt_never_refreshes() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path().join("blocked");
    fs::write(&home, b"a file, not a directory").expect("blocker");
    assert_eq!(claim(&home, 1_000.0), json!({"refresh": false}));
}

#[test]
fn malformed_requests_are_invalid() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path().to_str().expect("utf-8 home");
    for (args, guard_home) in [
        (json!([]), home),
        (json!({}), home),
        (json!({"now": "1"}), home),
        (json!({"now": 1.0}), "relative/home"),
        (json!({"now": 1.0}), ""),
    ] {
        assert_eq!(dispatch(&args, guard_home), Err(ERR_INVALID), "{args}");
    }
}

#[test]
fn overlapping_claims_for_one_home_refresh_once() {
    let dir = TempDir::new().expect("temp dir");
    let home = dir.path();
    let refreshed = std::thread::scope(|scope| {
        let claims: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| claim(home, 1_000.0)))
            .collect();
        claims
            .into_iter()
            .map(|handle| handle.join().expect("claim thread"))
            .filter(|answer| answer == &json!({"refresh": true}))
            .count()
    });
    assert_eq!(refreshed, 1);
    assert_eq!(stored_attempt(home), json!(1_000.0));
}
