use serde_json::Value;

#[test]
fn replay_original_python_decision_authority_outcomes() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/decision_authority_vectors.json"
    ))
    .unwrap();
    assert_eq!(corpus["schema"], "decision-authority-reference.v1");
    let vectors = corpus["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 2500);
    let mut differences = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let kind = vector["kind"].as_str().unwrap();
        let actual = crate::runner_authority_op::dispatch(kind, &vector["args"]);
        if actual.as_ref().ok() != Some(&vector["expected"]) {
            differences.push(format!(
                "{index} {kind}: expected {:?}, got {actual:?}",
                vector["expected"]
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "{} differences:\n{}",
        differences.len(),
        differences.join("\n")
    );
}

#[test]
fn a_caller_allow_projection_cannot_supply_missing_native_authority_fields() {
    let result = crate::decision_authority_op::dispatch(
        "decision_authoritative_decode",
        &serde_json::json!({
            "payload": {"action": "allow", "launch_permitted": true},
        }),
    )
    .unwrap();
    assert_eq!(result["status"], "error");
    assert!(result.get("value").is_none());
}

#[test]
fn oversized_validation_error_is_a_healthy_bound_refusal() {
    let key = "unexpected_field".repeat(500);
    let payload = serde_json::json!({key: "allow"});
    let result = crate::decision_authority_op::dispatch(
        "decision_enforcement_decode",
        &serde_json::json!({"payload": payload}),
    );
    assert_eq!(
        result,
        Err("native_runner_authority_decision_error_too_large")
    );
}
