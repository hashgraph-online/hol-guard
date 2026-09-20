use super::*;

fn expression(id: u64, value: &str) -> Value {
    json!({"decision_id":id,"expression":{"combinator":"all","conditions":[
        {"field":"command","operator":"startsWith","value":value,"caseSensitive":true}
    ]}})
}

fn with_expressions(mut policy: PolicySnapshotV4, expressions: Vec<Value>) -> PolicySnapshotV4 {
    let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
    authority["command_expressions"] = json!(expressions);
    policy.scoped_authority = serde_json::from_value(authority).unwrap();
    policy.effective_policy.unknown_publisher_action = "allow".to_owned();
    policy
}

#[test]
fn broad_older_expression_block_survives_newer_specific_allows_and_has_exact_provenance() {
    let policy = with_expressions(
        snapshot(
            "review",
            vec![
                row(1, "global", "block", "signed-bundle"),
                row(7, "artifact", "allow", "signed-bundle"),
                row(8, "artifact", "allow", "signed-bundle"),
            ],
        ),
        vec![expression(1, "printf"), expression(8, "printf")],
    );
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.decision, "deny");
    assert_eq!(result.result.policy_action, "block");
    assert_eq!(result.selected_decision_id, Some(1));
    // Both expressions match, but specificity/recency cannot erase the block.
    let request = derive_scoped_policy_request(&envelope(COMMAND), "codex").unwrap();
    let command = NormalizedCommand::new(COMMAND).unwrap();
    assert_eq!(
        policy
            .scoped_authority
            .matching_command_rows(&request, &command, 100)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn nonmatching_expression_does_not_become_a_global_rule_or_attributed_winner() {
    for mismatch in ["expression", "harness", "expiry", "artifact"] {
        let mut restriction = row(1, "artifact", "block", "signed-bundle");
        let mut value = "printf";
        match mismatch {
            "expression" => value = "echo",
            "harness" => restriction["harness"] = json!("claude-code"),
            "expiry" => restriction["expires_at_ms"] = json!(100),
            "artifact" => restriction["artifact_id"] = json!("codex:project:other"),
            _ => unreachable!(),
        }
        let policy = with_expressions(
            snapshot(
                "review",
                vec![restriction, row(7, "artifact", "allow", "signed-bundle")],
            ),
            vec![expression(1, value)],
        );
        let result = evaluate(&policy, &envelope(COMMAND));
        assert_eq!(result.result.policy_action, "allow", "{mismatch}");
        assert_eq!(result.selected_decision_id, Some(7), "{mismatch}");
    }
}

#[test]
fn observe_keeps_expression_would_enforce_and_frozen_winner_before_projection() {
    let mut policy = with_expressions(
        snapshot("warn", vec![row(1, "global", "block", "signed-bundle")]),
        vec![expression(1, "printf")],
    );
    policy.mode = "observe".to_owned();
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.decision, "allow");
    assert_eq!(result.result.policy_action, "warn");
    assert_eq!(result.observed_policy_action, Some("block"));
    assert_eq!(result.selected_decision_id, Some(1));
}

#[test]
fn expression_allow_cannot_lower_current_reapproval_sandbox_or_block_floors() {
    for floor in ["require-reapproval", "sandbox-required", "block"] {
        let policy = with_expressions(
            snapshot(floor, vec![row(1, "global", "allow", "signed-bundle")]),
            vec![expression(1, "printf")],
        );
        let result = evaluate(&policy, &envelope(COMMAND));
        assert_eq!(result.result.policy_action, floor);
        assert_eq!(result.selected_decision_id, None);
    }
}

#[test]
fn equal_expression_and_current_floor_do_not_invent_canonical_attribution() {
    let policy = with_expressions(
        snapshot("block", vec![row(1, "global", "block", "signed-bundle")]),
        vec![expression(1, "printf")],
    );
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.policy_action, "block");
    assert_eq!(result.selected_decision_id, None);
}
