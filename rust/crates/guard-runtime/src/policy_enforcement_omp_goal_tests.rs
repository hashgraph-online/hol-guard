use super::*;

fn secret_read_reapproval() -> EffectiveNativePolicyV3 {
    let mut installed = policy("allow");
    installed
        .risk_actions
        .insert("local_secret_read".into(), "require-reapproval".into());
    installed
}

fn review(payload: &serde_json::Value) -> PreToolResultV1 {
    let native = guard_command::pretool::evaluate_pre_tool_envelope("omp", "PreToolUse", payload);
    apply_pre_tool_policy(&snapshot(secret_read_reapproval()), payload, native)
        .expect("goal fixture")
}

#[test]
fn omp_goal_token_budget_is_a_count_not_a_credential() {
    for budget in [0u64, 1, 200_000] {
        for input in [
            json!({"op": "create", "objective": "Add the regression case", "token_budget": budget}),
            json!({"op": "resume", "token_budget": budget}),
            json!({"op": "get", "token_budget": budget}),
        ] {
            let payload = json!({"tool_name": "goal", "tool_input": input});
            let result = review(&payload);
            assert_eq!(
                result.decision, "allow",
                "{payload}: {}",
                result.reason_code
            );
            assert_eq!(result.minimum_action, "allow", "{payload}");
        }
    }
}

#[test]
fn omp_goal_without_a_budget_stays_allowed() {
    for input in [
        json!({"op": "complete"}),
        json!({"op": "get"}),
        json!({"op": "create", "objective": "Open the pull request"}),
    ] {
        let payload = json!({"tool_name": "goal", "tool_input": input});
        let result = review(&payload);
        assert_eq!(
            result.decision, "allow",
            "{payload}: {}",
            result.reason_code
        );
    }
}

#[test]
fn omp_goal_budget_metadata_does_not_hide_sensitive_inputs() {
    for payload in [
        // A credential-shaped value under the budget name is not a count.
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": "synthetic-secret"}}),
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": -1}}),
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": true}}),
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": 1.5}}),
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": null}}),
        // Another sensitive name alongside the budget still counts.
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": 2000,
            "access_token": "synthetic-secret"}}),
        // A nested copy is not the exact argument object.
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": 2000,
            "nested": {"token_budget": 2000}}}),
        // An input outside the published shape is not a goal input.
        json!({"tool_name": "goal", "tool_input": {"op": "launch", "token_budget": 2000}}),
        json!({"tool_name": "goal", "tool_input": {"token_budget": 2000}}),
        // The envelope's own budget name is not an argument of the call.
        json!({"tool_name": "goal", "token_budget": 2000, "tool_input": {"op": "create"}}),
        // Another tool carrying the same name keeps its review.
        json!({"tool_name": "learn", "tool_input": {"op": "create", "token_budget": 2000}}),
    ] {
        let result = review(&payload);
        assert_eq!(result.decision, "deny", "{payload}");
        assert_eq!(result.minimum_action, "require-reapproval", "{payload}");
    }
}

#[test]
fn omp_goal_budget_exception_does_not_apply_to_other_harnesses() {
    let payload =
        json!({"tool_name": "goal", "tool_input": {"op": "create", "token_budget": 2000}});
    for harness in ["claude-code", "codex", "cursor"] {
        let mut native = generic_result("allow");
        native.action.harness = harness.into();
        let result = apply_pre_tool_policy(&snapshot(secret_read_reapproval()), &payload, native)
            .expect("other harness fixture");
        assert_eq!(result.decision, "deny", "{harness}");
        assert_eq!(result.minimum_action, "require-reapproval", "{harness}");
    }
}

#[test]
fn omp_goal_budget_keeps_a_private_key_path_reviewed() {
    let payload = json!({"tool_name": "goal", "tool_input": {
        "op": "create", "objective": "Read the key", "token_budget": 2000,
        "path": "/home/tester/.ssh/id_rsa"
    }});
    let result = review(&payload);
    assert_eq!(result.decision, "deny", "{}", result.reason_code);
}
