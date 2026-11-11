use serde_json::{json, Value};

use crate::harness_backup_restore::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn plan(backup: Value, target_exists: bool) -> Value {
    dispatch(&json!({"backup": backup, "target_exists": target_exists})).expect("answer")
}

#[test]
fn a_saved_config_is_written_back() {
    let backup = json!(r#"{"existed": true, "content": "{\"a\": 1}\n"}"#);
    for exists in [false, true] {
        assert_eq!(
            plan(backup.clone(), exists),
            json!({"action": "write", "content": "{\"a\": 1}\n", "restored": true})
        );
    }
}

#[test]
fn a_config_guard_created_is_removed() {
    for backup in [
        r#"{"existed": false, "content": null}"#,
        r#"{"existed": "yes"}"#,
        r#"{}"#,
    ] {
        assert_eq!(
            plan(json!(backup), true),
            json!({"action": "unlink", "content": null, "restored": true}),
            "{backup}"
        );
        assert_eq!(
            plan(json!(backup), false),
            json!({"action": "keep", "content": null, "restored": true}),
            "{backup}"
        );
    }
}

#[test]
fn an_unusable_backup_leaves_the_target_alone() {
    for backup in [
        json!(null),
        json!("not json"),
        json!("[1]"),
        json!(r#"{"existed": NaN}"#),
        json!(r#"{"existed": true, "content": 1}"#),
        json!(r#"{"existed": true}"#),
    ] {
        assert_eq!(
            plan(backup.clone(), true),
            json!({"action": "keep", "content": null, "restored": false}),
            "{backup}"
        );
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"backup": null}),
        json!({"backup": 1, "target_exists": true}),
        json!({"backup": null, "target_exists": "yes"}),
        json!({"backup": null, "target_exists": true, "extra": 1}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
