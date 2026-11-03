use serde_json::json;

use super::{current_process_identity, process_identity_matches};

#[test]
fn this_live_process_matches_its_own_identity() {
    let (pid, token) = current_process_identity().expect("this process has a start token");
    assert!(process_identity_matches(
        &json!({"pid": pid, "startToken": token})
    ));
}

#[test]
fn only_the_exact_identity_shape_is_proof() {
    let (pid, token) = current_process_identity().expect("this process has a start token");
    for value in [
        json!({"pid": pid, "startToken": "not-the-start-token"}),
        json!({"pid": pid, "startToken": ""}),
        json!({"pid": pid, "startToken": token, "extra": true}),
        json!({"pid": pid}),
        json!({"pid": true, "startToken": token}),
        json!({"pid": f64::from(pid), "startToken": token}),
        json!({"pid": pid.to_string(), "startToken": token}),
        json!({"pid": 0, "startToken": token}),
        json!({"pid": -1, "startToken": token}),
        json!({"pid": u64::from(u32::MAX) + 1, "startToken": token}),
        json!([pid, token]),
        json!(null),
    ] {
        assert!(!process_identity_matches(&value), "{value}");
    }
}
