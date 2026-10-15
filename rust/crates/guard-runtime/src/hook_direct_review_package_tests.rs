use super::*;
use serde_json::json;

const VECTORS: &str = include_str!("../testdata/hook_direct_review/package_review_vectors.json");

/// Each recorded review is left to the queue exactly when the daemon's
/// `native_package_review_response` returned `None` without a filesystem
/// probe or an evaluation.
#[test]
fn recorded_package_reviews_replay() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let vectors = document["vectors"].as_array().expect("vector list");
    assert!(vectors.len() > 100, "{}", vectors.len());
    let mut queued = 0;
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let windows = vector["windows"].as_bool().expect("windows");
        let payload = vector["payload"].as_object().expect("payload");
        let result = vector["result"].as_object().expect("result");
        let expected = vector["python_none"].as_bool() == Some(true)
            && vector["probed"].as_bool() == Some(false);
        assert_eq!(left_to_queue(windows, payload, result), expected, "{name}");
        queued += usize::from(expected);
    }
    // Both outcomes are covered.
    assert!(queued > 0 && queued < vectors.len(), "{queued}");
}

/// Python lowercases `K` (U+212A) to `k`, so for the daemon this name sets
/// an npm setting that may move the fetch; the resident leaves it there.
#[test]
fn a_name_outside_ascii_stays_with_the_daemon() {
    let payload = json!({
        "tool_input": {"command": "npm install left-pad"},
        "guard_execution_environment": {
            "path": "/usr/bin",
            "environment_names": ["NPM_CONFIG_\u{212a}EY"],
        },
    });
    let result = json!({"reason_code": PACKAGE_REVIEW_REASON, "minimum_action": "review"});
    let (payload, result) = (payload.as_object().unwrap(), result.as_object().unwrap());
    assert!(!left_to_queue(false, payload, result));
    assert!(left_to_queue(true, payload, result));
}

/// A command whose blank test Python could read differently stays with the
/// daemon.
#[test]
fn an_ambiguous_command_stays_with_the_daemon() {
    let payload = json!({"tool_input": {"command": "\u{1c}"}});
    let result = json!({"reason_code": PACKAGE_REVIEW_REASON, "minimum_action": "review"});
    assert!(!left_to_queue(
        false,
        payload.as_object().unwrap(),
        result.as_object().unwrap()
    ));
}
