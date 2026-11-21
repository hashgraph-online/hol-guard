use serde_json::{json, Value};

use super::dispatch;

fn ask(fields: Value) -> Result<Value, String> {
    let mut request = json!({"op": "publication_artifact_generation"});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    let answer = dispatch(&request).map_err(|error| error.to_string())?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

#[test]
fn a_repair_proves_itself_under_its_subjects_last_segment() {
    let value = ask(json!({"kind": "repair", "subject": "a:b:token", "bound": true}));
    assert_eq!(value.unwrap(), json!("codex-authority-repair-token"));
    let unbound = ask(json!({"kind": "repair", "subject": "a:b", "bound": false}));
    assert!(unbound
        .unwrap_err()
        .contains("authority_repair_native_binding_missing"));
}

#[test]
fn an_inverse_is_verified_only_once_all_three_files_are_restored() {
    let inverse = |restored: Value, bound: bool| {
        ask(json!({"kind": "inverse", "subject": "x:tok", "bound": bound, "restored": restored}))
    };
    for order in [json!([1, 2, 0]), json!([0, 1, 2]), json!([0, 1, 2, 2])] {
        assert_eq!(
            inverse(order, true).unwrap(),
            json!("codex-publication-inverse-tok")
        );
    }
    for restored in [
        json!([0, 1]),
        json!([0, 1, 2, 3]),
        json!([]),
        json!(["0", 1, 2]),
        Value::Null,
    ] {
        assert!(inverse(restored, true)
            .unwrap_err()
            .contains("publication_inverse_not_restored"));
    }
    assert!(inverse(json!([0, 1, 2]), false)
        .unwrap_err()
        .contains("publication_inverse_not_restored"));
}

#[test]
fn a_subject_without_a_segment_or_an_unknown_kind_is_refused() {
    assert!(ask(json!({"kind": "repair", "subject": "nosegment", "bound": true})).is_err());
    assert!(ask(json!({"kind": "other", "subject": "a:b", "bound": true})).is_err());
}
