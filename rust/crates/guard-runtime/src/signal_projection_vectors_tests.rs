use serde_json::{json, Value};

#[test]
fn replay_pinned_python_persistence_projection_outcomes() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/signal_projection_vectors.json"
    ))
    .unwrap();
    assert_eq!(corpus["schema"], "signal-projection-reference.v1");
    let vectors = corpus["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 2500);
    let differences: Vec<_> = vectors
        .iter()
        .enumerate()
        .filter_map(|(index, vector)| {
            let kind = vector["kind"].as_str().unwrap();
            let actual = crate::runner_authority_op::dispatch(kind, &vector["args"]);
            (actual.as_ref().ok() != Some(&vector["expected"])).then(|| {
                format!(
                    "{index} {kind}: expected {:?}, got {actual:?}",
                    vector["expected"]
                )
            })
        })
        .collect();
    assert!(
        differences.is_empty(),
        "{} differences; first20:\n{}",
        differences.len(),
        differences
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn native_page_batch_matches_individual_surface_projection() {
    let rows = json!([{"action":"block","decision":null,"envelope":{"futureAction":"allow"}},
        {"action":"allow","decision":null,"envelope":null}]);
    let actual = crate::signal_projection_op::dispatch(
        "projection_surfaces_batch",
        &json!({"rows":rows,"reject":false}),
    )
    .unwrap();
    let expected: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            crate::signal_projection_receipt::surfaces(
                &row["action"],
                &row["decision"],
                &row["envelope"],
                false,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(actual["value"], json!(expected));
    assert_eq!(actual["value"][0]["policy_action"], "block");
}

#[test]
fn strict_receipt_rejects_aliases_that_differ_only_beyond_float_precision() {
    let envelope = json!({"action_id": 9007199254740993_u64, "actionId": 9007199254740992.0});
    assert!(crate::signal_projection_receipt::receipt(&json!("allow"), &envelope, true).is_err());
    let same = json!({"action_id": 7, "actionId": 7.0});
    assert!(crate::signal_projection_receipt::receipt(&json!("allow"), &same, true).is_ok());
}

#[test]
fn a_non_boolean_strict_flag_is_refused() {
    let args = json!({"action":"allow","envelope":null,"reject":"true"});
    assert!(crate::signal_projection_op::dispatch("projection_receipt", &args).is_err());
}
