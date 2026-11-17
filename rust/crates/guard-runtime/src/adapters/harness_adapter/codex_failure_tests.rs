use serde_json::{json, Value};

use super::with_raise;

fn raised(answer: Value) -> Option<Value> {
    with_raise(answer).get("raise").cloned()
}

#[test]
fn a_settled_answer_raises_nothing() {
    assert_eq!(raised(json!({ "files": [], "events": [] })), None);
}

#[test]
fn a_conflict_is_the_generation_conflict() {
    assert_eq!(
        raised(json!({ "conflict": true })),
        Some(json!({ "fault": { "transition": "adapter_preparation_generation_conflict" } }))
    );
    assert_eq!(raised(json!({ "conflict": false })), None);
}

#[test]
fn a_fault_outranks_a_publication_error() {
    let fault = json!({ "transition": "files_invalid" });
    assert_eq!(
        raised(json!({ "fault": fault, "error": { "runtime": "x" } })),
        Some(json!({ "fault": fault }))
    );
}

#[test]
fn a_failed_rollback_rides_beside_the_publication_error() {
    let error = json!({ "runtime": "publish failed" });
    let rollback = json!({ "transition": "restore_failed" });
    assert_eq!(
        raised(json!({ "error": error, "rollback_error": rollback })),
        Some(json!({ "fault": error, "rollback": rollback }))
    );
    assert_eq!(
        raised(json!({ "error": error })),
        Some(json!({ "fault": error }))
    );
}

#[test]
fn a_retirement_failure_names_the_repair_only_when_nothing_was_withdrawn() {
    let retire = json!({ "os": "disk full" });
    assert_eq!(
        raised(json!({ "retire_error": retire, "withdrawn": true })),
        Some(json!({ "fault": retire }))
    );
    let stranded = raised(json!({ "retire_error": retire, "withdrawn": false })).unwrap();
    assert_eq!(stranded["cause"], retire);
    assert!(stranded["runtime"]
        .as_str()
        .unwrap()
        .starts_with("codex_hook_migration_rollback_failed: "));
}
