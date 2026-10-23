use gauntlet_evidence::verify_contained_output_custody;
use serde_json::Value;

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
fn exact_python_contained_output_and_native_post_relations_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_contained_output_custody_v1.json")).unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (field, path) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/contained_output_custody.py",
        ),
        (
            "output_binding_sha256",
            "ci/gauntlet/benchmark/contained_output_binding.py",
        ),
        (
            "product_custody_sha256",
            "ci/gauntlet/benchmark/product_custody.py",
        ),
        ("json_data_sha256", "ci/gauntlet/benchmark/json_data.py"),
    ] {
        let row = baseline["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture[field], row["sha256"]);
    }
    assert_eq!(
        fixture["schema"],
        "gauntlet-contained-output-custody-fixtures.v1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let mut builtin = fixture["base"].clone();
        apply_merge_delta(&mut builtin, &case["patch"]);
        let result = verify_contained_output_custody(&builtin);
        if case["accepted"] == true {
            assert_eq!(
                result.unwrap_or_else(|error| panic!("{}: {error}", case["name"])),
                case["result"].as_u64().unwrap() as usize,
                "{}",
                case["name"]
            );
        } else {
            let error = match result {
                Ok(_) => panic!("{} expected refusal", case["name"]),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), case["error"], "{}", case["name"]);
        }
    }
}
