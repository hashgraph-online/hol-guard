use super::*;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/workspace_grant_plan/parity_vectors.json");

fn expected(value: &Value) -> Option<ExpectedGrant> {
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    (!value.is_null()).then(|| ExpectedGrant {
        identity_hash: value["identity_hash"].as_str().unwrap().to_owned(),
        capabilities: strings(&value["capabilities"]),
        state_dir: value["state_dir"].as_str().map(str::to_owned),
    })
}

#[test]
fn parity_vectors_hold() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let got = grant_script_roots(
            case["plan"].as_object().unwrap(),
            expected(&case["expected"]).as_ref(),
        );
        assert_eq!(
            got.unwrap_or(Value::Null),
            case["result"],
            "{}",
            case["name"]
        );
    }
}
