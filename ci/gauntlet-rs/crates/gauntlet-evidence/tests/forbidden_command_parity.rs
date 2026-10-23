use gauntlet_evidence::reduce_forbidden_command;
use serde_json::Value;

#[test]
fn reachable_effect_and_negative_command_decisions_match_pinned_python() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_forbidden_command_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/deterministic.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-forbidden-command-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    for case in cases {
        let mut command = fixture["base"].clone();
        let object = command.as_object_mut().unwrap();
        for (key, value) in case["fields"].as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        for key in case["remove_fields"].as_array().unwrap() {
            object.remove(key.as_str().unwrap());
        }
        let decision = object["native_pre_decision"].as_object_mut().unwrap();
        for (key, value) in case["decision_fields"].as_object().unwrap() {
            decision.insert(key.clone(), value.clone());
        }
        for key in case["remove_decision"].as_array().unwrap() {
            decision.remove(key.as_str().unwrap());
        }
        match reduce_forbidden_command(&command) {
            Ok(actual) => {
                assert_eq!(case["accepted"], true, "{}", case["name"]);
                assert_eq!(actual, command["native_pre_decision"], "{}", case["name"]);
            }
            Err(error) => {
                assert_eq!(case["accepted"], false, "{}", case["name"]);
                assert_eq!(error.to_string(), case["error"], "{}", case["name"]);
            }
        }
    }
}
