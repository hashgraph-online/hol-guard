use serde_json::{json, Value};

use super::dispatch;

fn ask(request: Value) -> Result<Value, String> {
    let answer = dispatch(&request).map_err(|error| error.to_string())?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

fn policy(stage: &str, fields: Value) -> Result<Value, String> {
    let mut request = json!({"op": "publication_request_policy", "stage": stage});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    ask(request)
}

#[test]
fn an_artifact_lives_five_minutes_from_the_moment_it_is_written() {
    let stamp = policy("stamp", json!({"now": 12.5})).unwrap();
    assert_eq!(stamp, json!({"created": 12.5, "expires": 312.5}));
    assert!(policy("stamp", json!({"now": "12"})).is_err());
}

#[test]
fn a_loaded_artifact_must_name_the_plan_it_authorizes() {
    let fields = |signed: &str, subject: &str| json!({"signed_at": signed, "operation_id": "op-1", "subject": subject, "plan_subject": "s:1"});
    assert!(policy("plan", fields("op-1", "s:1")).is_ok());
    for (signed, subject) in [("op-2", "s:1"), ("op-1", "s:2")] {
        assert!(policy("plan", fields(signed, subject))
            .unwrap_err()
            .contains("authority_repair_request_plan_invalid"));
    }
    assert!(policy("plan", json!({"signed_at": "op-1"})).is_err());
}

#[test]
fn the_review_window_is_open_from_creation_up_to_expiry() {
    let window = |now: f64| {
        policy(
            "window",
            json!({"created": 10.0, "expires": 20.0, "now": now}),
        )
    };
    assert!(window(10.0).is_ok());
    assert!(window(19.9).is_ok());
    for now in [9.9, 20.0, 40.0] {
        assert!(window(now)
            .unwrap_err()
            .contains("authority_repair_request_expired"));
    }
}

#[test]
fn an_unknown_stage_is_refused() {
    assert!(policy("other", json!({}))
        .unwrap_err()
        .contains("files_invalid"));
}
