use super::{audit_controller_invocations, ControllerInvocationBytes};
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn python_controller_invocation_accounting_matches() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_controller_invocations_v1.json"
    ))
    .unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (name, expected) in frozen["source_sha256"].as_object().unwrap() {
        let source_path = format!("ci/gauntlet/benchmark/{name}");
        let source = baseline["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == source_path)
            .unwrap();
        assert_eq!(*expected, source["sha256"]);
    }
    assert_eq!(
        frozen["schema"],
        "gauntlet-controller-invocations-fixtures.v1"
    );
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let records = case["records"].as_array().map(|rows| {
            rows.iter()
                .map(|row| ControllerInvocationBytes {
                    name: row["name"].as_str().unwrap().to_owned(),
                    files: row["files"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(name, raw)| {
                            (name.to_owned(), raw.as_str().unwrap().as_bytes().to_vec())
                        })
                        .collect::<BTreeMap<_, _>>(),
                })
                .collect::<Vec<_>>()
        });
        let result = audit_controller_invocations(
            records.as_deref(),
            frozen["config_digest"].as_str().unwrap(),
            frozen["manifest_digest"].as_str().unwrap(),
            &frozen["provider_pins"],
            frozen["shard_count"].as_u64().unwrap() as usize,
            case["charged_tokens"].as_u64().unwrap(),
        );
        if case.get("errors").is_some() {
            let result = result.unwrap();
            assert_eq!(result["errors"], case["errors"], "{name}");
            assert_eq!(result["qualification_eligible"], false, "{name}");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["python_refusal"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
