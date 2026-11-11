use serde_json::{json, Value};

use crate::harness_backup_restore::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn plan(envelope: Value, target_exists: bool) -> Value {
    dispatch(&json!({"envelope": envelope, "target_exists": target_exists})).expect("answer")
}

#[test]
fn a_saved_config_is_written_back() {
    for exists in [false, true] {
        assert_eq!(
            plan(json!({"existed": true, "has_content": true}), exists),
            json!({"action": "write", "restored": true})
        );
    }
}

#[test]
fn a_config_guard_created_is_removed() {
    for has_content in [false, true] {
        let envelope = json!({"existed": false, "has_content": has_content});
        assert_eq!(
            plan(envelope.clone(), true),
            json!({"action": "unlink", "restored": true})
        );
        assert_eq!(
            plan(envelope, false),
            json!({"action": "keep", "restored": true})
        );
    }
}

#[test]
fn an_unusable_backup_leaves_the_target_alone() {
    for envelope in [json!(null), json!({"existed": true, "has_content": false})] {
        for exists in [false, true] {
            assert_eq!(
                plan(envelope.clone(), exists),
                json!({"action": "keep", "restored": false}),
                "{envelope}"
            );
        }
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"envelope": null}),
        json!({"envelope": "{}", "target_exists": true}),
        json!({"envelope": {"existed": true}, "target_exists": true}),
        json!({"envelope": {"existed": 1, "has_content": true}, "target_exists": true}),
        json!({"envelope": {"existed": true, "has_content": true, "x": 1}, "target_exists": true}),
        json!({"envelope": null, "target_exists": "yes"}),
        json!({"envelope": null, "target_exists": true, "extra": 1}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
