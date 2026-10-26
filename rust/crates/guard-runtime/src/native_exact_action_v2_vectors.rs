//! Explicit contract deltas from the preserved retired-Python recordings.
//! These fakes provide metadata strings, not verified launch/code evidence.
//! V2 must reject them; real closed-runner positive coverage lives separately.
use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde_json::{json, Value};

fn rejections() -> &'static BTreeSet<String> {
    static NAMES: OnceLock<BTreeSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let names: Vec<String> = serde_json::from_str(include_str!(
            "../tests/fixtures/native_exact_action_v2_runner_rejections.json"
        ))
        .unwrap();
        let unique = names.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), names.len(), "duplicate versioned expectation");
        unique
    })
}

pub(super) fn validate(cases: &[Value]) {
    for name in rejections() {
        let case = cases
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .expect("versioned case must exist");
        assert_eq!(
            case["expected"]["token_present"], true,
            "recorded v1 outcome must stay preserved"
        );
        assert_eq!(case["expected"]["once_only_reason"], Value::Null);
        assert!(
            !case["intent"].as_array().unwrap().is_empty(),
            "runner metadata must be present"
        );
    }
}

pub(super) fn expected(case: &Value) -> Value {
    if rejections().contains(case["name"].as_str().unwrap()) {
        json!({"token_present":false,"once_only_reason":"runner_code_closure_unproven"})
    } else {
        case["expected"].clone()
    }
}
