use serde_json::{json, Value};

use super::*;

fn headline(pending_count: u64, runtime_state_present: bool, protection_state: &str) -> Value {
    dispatch(&json!({
        "pending_count": pending_count,
        "runtime_state_present": runtime_state_present,
        "protection_state": protection_state,
    }))
    .unwrap()
}

#[test]
fn headline_state_follows_runtime_then_queue_then_protection() {
    let cases = [
        (3, false, "protected", "setup"),
        (2, true, "protected", "needs_decision"),
        (0, true, "protected", "protected"),
        (0, true, "partial", "partial"),
        (0, true, "degraded", "degraded"),
        (0, true, "unknown", "degraded"),
        // An unavailable report is never rendered as protection.
        (0, true, "", "degraded"),
    ];
    for (pending, present, protection, expected) in cases {
        assert_eq!(
            headline(pending, present, protection)["headline_state"],
            expected,
            "{pending} {present} {protection}"
        );
    }
}

#[test]
fn headline_copy_names_the_state() {
    let setup = headline(0, false, "");
    assert_eq!(setup["headline_label"], "Setup required");
    assert_eq!(
        setup["headline_detail"],
        "The local Guard runtime is offline. Start the daemon or rerun hol-guard bootstrap."
    );
    let protected = headline(0, true, "protected");
    assert_eq!(protected["headline_label"], "Protected");
    assert_eq!(
        protected["headline_detail"],
        "This machine is protected and the local queue is clear."
    );
    assert_eq!(headline(0, true, "partial")["headline_label"], "Partial");
    assert_eq!(headline(1, true, "")["headline_label"], "Decision needed");
    let degraded = headline(0, true, "");
    assert_eq!(degraded["headline_label"], "Degraded");
    assert_eq!(
        degraded["headline_detail"],
        "One or more required protection checks failed or remain unproven."
    );
}

#[test]
fn malformed_arguments_are_refused() {
    let base = json!({
        "pending_count": 0,
        "runtime_state_present": true,
        "protection_state": "protected",
    });
    let mut cases = vec![json!([]), json!({})];
    for key in ["pending_count", "runtime_state_present", "protection_state"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        cases.push(missing);
    }
    for (key, bad) in [
        ("pending_count", json!(-1)),
        ("pending_count", json!("1")),
        ("runtime_state_present", json!(1)),
        ("protection_state", json!(null)),
    ] {
        let mut case = base.clone();
        case[key] = bad;
        cases.push(case);
    }
    for case in cases {
        assert_eq!(dispatch(&case), Err(ERR_INVALID), "{case}");
    }
}
