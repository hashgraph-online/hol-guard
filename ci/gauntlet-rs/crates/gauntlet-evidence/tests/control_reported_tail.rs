use gauntlet_evidence::{captured_contained_output, verify_control_reported_tail};
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
fn python_reported_role_checks_match_without_granting_eligibility() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_control_reported_tail_v1.json")).unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (field, path) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/local_executor_controls.py",
        ),
        (
            "custody_sha256",
            "ci/gauntlet/benchmark/developer_product_custody.py",
        ),
        (
            "output_binding_sha256",
            "ci/gauntlet/benchmark/contained_output_binding.py",
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
        "gauntlet-control-reported-tail-fixtures.v1"
    );
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 44);
    assert_eq!(
        fixture["stubs"],
        serde_json::json!(["verify_private_cell_runtime", "_cancel"])
    );
    for role in ["success", "timeout", "input-binding", "boundary"] {
        let base = &fixture["bases"][role];
        assert_eq!(
            captured_contained_output(&base["control"]["plane"]["executions"][0]).unwrap(),
            base["captured_output"],
            "{role}"
        );
    }
    for case in fixture["cases"].as_array().unwrap() {
        let role = case["role"].as_str().unwrap();
        let base = &fixture["bases"][role];
        let mut control = base["control"].clone();
        apply_merge_delta(&mut control, &case["control_patch"]);
        let raw = serde_json::to_vec(&control).unwrap();
        let result = verify_control_reported_tail(
            &raw,
            role,
            &key(base["public_key_hex"].as_str().unwrap()),
            &base["expected"],
        );
        if case["accepted"] == true {
            let opened = result.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert_eq!(opened.role, role);
            assert_eq!(opened.session.session_id, case["result"]["session_id"]);
            assert!(!opened.execution_eligible);
        } else {
            let error = match result {
                Ok(_) => panic!("{} expected refusal", case["name"]),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), case["error"], "{}", case["name"]);
        }
    }
}

#[test]
fn captured_output_refuses_changed_stream_digest() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_control_reported_tail_v1.json")).unwrap();
    let base = &fixture["bases"]["success"];
    let mut execution = base["control"]["plane"]["executions"][0].clone();
    execution["stdout_sha256"] = Value::String("0".repeat(64));
    let result = captured_contained_output(&execution);
    assert_eq!(
        result.unwrap_err().to_string(),
        "captured contained output differs from its byte digest"
    );
}
