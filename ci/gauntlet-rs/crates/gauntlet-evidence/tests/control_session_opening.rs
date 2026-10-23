use gauntlet_evidence::verify_control_session_opening;
use serde_json::Value;

fn key(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn exact_python_session_allocation_and_sdk_gate_opening_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_control_session_v1.json")).unwrap();
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
    ] {
        let row = baseline["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture[field], row["sha256"]);
    }
    assert_eq!(fixture["schema"], "gauntlet-control-session-fixtures.v1");
    assert_eq!(fixture["ast_statements"], "verify_control body[1:28]");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let raw = serde_json::to_vec(&case["control"]).unwrap();
        let result = verify_control_session_opening(
            &raw,
            case["role"].as_str().unwrap(),
            &key(case["public_key_hex"].as_str().unwrap()),
            &case["expected"],
        );
        if case["accepted"] == true {
            let actual = result.unwrap();
            let expected = &case["result"];
            assert_eq!(
                actual.session_id, expected["session_id"],
                "{}",
                case["name"]
            );
            assert_eq!(
                actual.workspace_source, expected["workspace_source"],
                "{}",
                case["name"]
            );
            assert_eq!(
                serde_json::to_value(&actual.provider_mounts).unwrap(),
                expected["provider_mounts"],
                "{}",
                case["name"]
            );
            assert_eq!(
                actual.sdk_observation, expected["sdk_observation"],
                "{}",
                case["name"]
            );
            assert_eq!(
                actual.agent_identity, expected["agent_identity"],
                "{}",
                case["name"]
            );
            assert_eq!(
                actual.public_prompt_digest, expected["public_prompt_digest"],
                "{}",
                case["name"]
            );
            assert_eq!(actual.signed.plane, case["control"]["plane"]);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["error"],
                "{}",
                case["name"]
            );
        }
    }
}
