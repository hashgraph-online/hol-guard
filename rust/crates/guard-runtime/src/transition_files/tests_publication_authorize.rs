use serde_json::{json, Value};

use super::dispatch;

const EXPIRES: &str = "2026-11-17T12:00:00Z";
const EXPIRES_EPOCH: f64 = 1_794_916_800.0;

fn ask(request: Value) -> Result<Value, String> {
    let answer = dispatch(&request).map_err(|error| error.to_string())?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

fn deadline(deadline: Value, now: f64) -> Result<Value, String> {
    ask(json!({"op": "publication_deadline", "deadline": deadline, "now": now}))
}

fn plan(kind: &str, deadline: f64, wall: f64) -> Result<Value, String> {
    ask(json!({
        "op": "publication_authorize",
        "kind": kind,
        "expires_at": EXPIRES,
        "deadline": deadline,
        "now": 100.0,
        "wall": wall,
    }))
}

#[test]
fn a_deadline_must_be_a_number_still_ahead() {
    assert!(deadline(json!(10.5), 10.0).is_ok());
    for (value, now) in [
        (json!(10.0), 10.0),
        (json!(9.0), 10.0),
        (json!(true), 0.0),
        (json!("10"), 0.0),
        (Value::Null, 0.0),
    ] {
        let error = deadline(value.clone(), now).unwrap_err();
        assert!(error.contains("deadline_exceeded"), "{value}: {error}");
    }
}

#[test]
fn the_forward_deadline_is_the_earliest_of_the_caller_the_cap_and_the_grant() {
    // A grant with a long life: the cap (60s) is the earliest.
    let long = plan("repair", 1_000.0, EXPIRES_EPOCH - 3_600.0).unwrap();
    assert_eq!(long["deadline"], json!(160.0));
    assert_eq!(long["retirement_seconds"], json!(3_600.0));
    assert_eq!(long["retirement"], json!(3_700.0));
    // The caller's own deadline is earlier than the cap.
    let near = plan("inverse", 130.0, EXPIRES_EPOCH - 3_600.0).unwrap();
    assert_eq!(near["deadline"], json!(130.0));
    // A grant about to expire wins over both.
    let short = plan("inverse", 1_000.0, EXPIRES_EPOCH - 5.0).unwrap();
    assert_eq!(short["deadline"], json!(105.0));
    assert_eq!(short["retirement_seconds"], json!(5.0));
}

#[test]
fn an_expired_grant_retires_at_once() {
    let expired = plan("repair", 1_000.0, EXPIRES_EPOCH + 10.0).unwrap();
    assert_eq!(expired["retirement_seconds"], json!(0.0));
    assert_eq!(expired["retirement"], json!(100.0));
    assert_eq!(expired["deadline"], json!(100.0));
}

#[test]
fn an_unreadable_grant_expiry_or_kind_is_refused() {
    let bad = ask(json!({
        "op": "publication_authorize", "kind": "repair", "expires_at": "tomorrow",
        "deadline": 1_000.0, "now": 100.0, "wall": 0.0,
    }))
    .unwrap_err();
    assert!(bad.contains("approval_grant_invalid"), "{bad}");
    let kind = plan("other", 1_000.0, 0.0).unwrap_err();
    assert!(kind.contains("files_invalid"), "{kind}");
}
