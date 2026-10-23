use gauntlet_evidence::reduce_pilot_terminal;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/pilot_terminal_v1.json")).unwrap()
}

#[test]
fn pilot_terminal_decision_matches_pinned_python_branch() {
    let fixture = fixture();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == "ci/gauntlet/benchmark/pilot.py")
        .unwrap();
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-pilot-terminal-fixtures.v1"
    );
    assert_eq!(fixture["python_source_sha256"], source["sha256"]);
    assert_eq!(
        fixture["branch_ast_sha256"],
        "4980ccf63b8c41d4b8894549f3da225b4450e2a76cfde4a7c00641fa639347f8"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    for case in cases {
        let actual = reduce_pilot_terminal(&case["input"]).unwrap();
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn malformed_or_unbounded_inputs_refuse() {
    let fixture = fixture();
    let valid = fixture["cases"][0]["input"].clone();
    let mut extra = valid.clone();
    extra["success"] = json!(true);
    assert!(reduce_pilot_terminal(&extra).is_err());
    let mut bad_active = valid.clone();
    bad_active["active"]["active_workers"] = json!(-1);
    assert!(reduce_pilot_terminal(&bad_active).is_err());
    let mut bad_event = valid.clone();
    bad_event["events"] = json!([{"type": 1}]);
    assert!(reduce_pilot_terminal(&bad_event).is_err());
    let mut too_many = valid.clone();
    too_many["events"] = Value::Array(vec![json!({"type":"episode_start"}); 50_001]);
    assert!(reduce_pilot_terminal(&too_many).is_err());
    let mut invalid_isolation = valid;
    invalid_isolation["isolated"] = json!(true);
    invalid_isolation["isolation"] = json!({"record": {"isolation_observed": true}});
    assert!(reduce_pilot_terminal(&invalid_isolation).is_err());
}
