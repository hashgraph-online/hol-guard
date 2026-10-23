use gauntlet_evidence::verify_cancel_reported_relation;
use serde_json::Value;

fn key(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn apply_merge_delta(base: &mut Value, patch: &Value) {
    let Some(entries) = patch.as_object() else {
        *base = patch.clone();
        return;
    };
    if !base.is_object() {
        *base = Value::Object(Default::default());
    }
    let current = base.as_object_mut().unwrap();
    for (name, value) in entries {
        if value.is_null() {
            current.remove(name);
        } else {
            apply_merge_delta(current.entry(name).or_insert(Value::Null), value);
        }
    }
}

#[test]
fn python_cancel_relations_match_without_claiming_a_verdict() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_cancel_reported_v1.json")).unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (field, path) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/local_executor_controls.py",
        ),
        ("custody_sha256", "ci/gauntlet/benchmark/product_custody.py"),
    ] {
        let source = baseline["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture[field], source["sha256"]);
    }
    assert_eq!(fixture["schema"], "gauntlet-cancel-reported-fixtures.v1");
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 17);
    let base = &fixture["base"];
    let outside_key = key(base["public_key_hex"].as_str().unwrap());
    for case in fixture["cases"].as_array().unwrap() {
        let mut control = base["control"].clone();
        apply_merge_delta(&mut control, &case["control_patch"]);
        let result = verify_cancel_reported_relation(
            &serde_json::to_vec(&control).unwrap(),
            &outside_key,
            &base["expected"],
            &fixture["outside_review_summary"],
        );
        if case["accepted"] == true {
            let relation = result.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert_eq!(relation.sample_count, 1, "{}", case["name"]);
            assert!(!relation.execution_eligible);
        } else {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("{} accepted", case["name"]));
            assert_eq!(error.to_string(), case["error"], "{}", case["name"]);
        }
    }
}

#[test]
fn changed_outside_review_summary_refuses() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_cancel_reported_v1.json")).unwrap();
    let base = &fixture["base"];
    let changed = serde_json::json!({"missing_required_post_call_ids": []});
    let result = verify_cancel_reported_relation(
        &serde_json::to_vec(&base["control"]).unwrap(),
        &key(base["public_key_hex"].as_str().unwrap()),
        &base["expected"],
        &changed,
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "cancelled sink became complete or lost missing Post"
    );
}
