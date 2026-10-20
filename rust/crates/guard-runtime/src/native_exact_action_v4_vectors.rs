//! Named delivery-contract changes; old inventory outcomes remain checked.
use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

fn rejections() -> &'static BTreeMap<String, Value> {
    static CASES: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    CASES.get_or_init(|| {
        let rows: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/native_exact_action_v4_delivery_rejections.json"
        ))
        .unwrap();
        assert_eq!(rows.len(), 70, "delivery migration must stay explicit");
        let result = rows
            .iter()
            .map(|row| {
                (
                    row["name"].as_str().unwrap().to_owned(),
                    row["previous_reason"].clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(result.len(), rows.len(), "duplicate delivery migration");
        result
    })
}

pub(super) fn migrated(case: &Value, previous: &Value) -> bool {
    let Some(reason) = rejections().get(case["name"].as_str().unwrap()) else {
        return false;
    };
    assert_eq!(
        &previous["once_only_reason"], reason,
        "prior outcome changed"
    );
    true
}

pub(super) fn validate(cases: &[Value]) {
    for name in rejections().keys() {
        assert!(cases.iter().any(|case| case["name"].as_str() == Some(name)));
    }
}
