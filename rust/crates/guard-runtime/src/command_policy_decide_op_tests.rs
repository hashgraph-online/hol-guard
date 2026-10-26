use super::evaluate;
use guard_contracts::{
    CommandConditionV1, CommandExpressionV1, CommandPolicyDecisionRequestV1, CommandPolicyRuleV1,
    COMMAND_POLICY_DECISION_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

const NOW: &str = "2026-10-17T00:00:00Z";

fn rule(rule_id: &str, action: &str, operator: &str, value: &str) -> CommandPolicyRuleV1 {
    CommandPolicyRuleV1 {
        rule_id: rule_id.to_owned(),
        action: action.to_owned(),
        expression: CommandExpressionV1 {
            combinator: "all".to_owned(),
            conditions: vec![CommandConditionV1 {
                operator: operator.to_owned(),
                value: value.to_owned(),
                case_sensitive: false,
            }],
        },
    }
}

fn request(rules: Vec<CommandPolicyRuleV1>, command: &str) -> CommandPolicyDecisionRequestV1 {
    CommandPolicyDecisionRequestV1 {
        schema: COMMAND_POLICY_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "command-policy-decision-test".to_owned(),
        rules,
        command: command.to_owned(),
        now: NOW.to_owned(),
    }
}

fn states(decision: &Value) -> Vec<(String, String)> {
    decision["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| {
            (
                candidate["ruleId"].as_str().unwrap_or_default().to_owned(),
                candidate["state"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_command_no_rule_matches_leaves_the_effect_to_the_harness() {
    let decision = evaluate(&request(
        vec![rule("no-force", "block", "contains", "--force")],
        "git status",
    ))
    .expect("decided");
    assert_eq!(decision["effect"], "default");
    assert_eq!(decision["ruleId"], Value::Null);
    assert_eq!(decision["ambiguous"], false);
    assert!(decision.get("action").is_none());
    assert_eq!(
        states(&decision),
        vec![("no-force".to_owned(), "unmatched".to_owned())]
    );
}

#[test]
fn a_block_outranks_an_allow_whatever_order_they_are_written_in() {
    let rules = vec![
        rule("allow-git", "allow", "startsWith", "git"),
        rule("no-force", "block", "contains", "--force"),
    ];
    let decision = evaluate(&request(rules, "git push --force")).expect("decided");
    assert_eq!(decision["effect"], "block");
    assert_eq!(decision["ruleId"], "no-force");
    assert_eq!(decision["action"], "block");
    assert_eq!(decision["ambiguous"], false);
    assert_eq!(
        states(&decision),
        vec![
            ("allow-git".to_owned(), "outranked".to_owned()),
            ("no-force".to_owned(), "selected".to_owned()),
        ]
    );
    assert_eq!(decision["candidates"][0]["reason"], "block_wins");
}

#[test]
fn rules_asking_for_the_same_action_tie_with_the_first_of_them() {
    let rules = vec![
        rule("no-force", "block", "contains", "--force"),
        rule("no-push", "block", "startsWith", "git push"),
    ];
    let decision = evaluate(&request(rules, "git push --force")).expect("decided");
    assert_eq!(decision["ruleId"], "no-force");
    assert_eq!(decision["ambiguous"], true);
    assert_eq!(decision["tiedRuleIds"], json!(["no-push"]));
    assert_eq!(decision["candidates"][1]["reason"], "tie");
}

#[test]
fn a_review_matches_without_deciding_the_effect() {
    let decision = evaluate(&request(
        vec![rule("look-at-rm", "review", "startsWith", "rm")],
        "rm -rf build",
    ))
    .expect("decided");
    // `review` and `warn` are not effects a document enforces; the action is
    // still reported so the caller can raise it with the harness default.
    assert_eq!(decision["effect"], "default");
    assert_eq!(decision["action"], "review");
    assert_eq!(decision["ruleId"], "look-at-rm");
}

#[test]
fn the_ladder_ranks_every_action_a_document_can_carry() {
    let rules = vec![
        rule("warn-git", "warn", "startsWith", "git"),
        rule("review-push", "review", "contains", "push"),
        rule("allow-all", "allow", "glob", "*"),
    ];
    let decision = evaluate(&request(rules, "git push")).expect("decided");
    assert_eq!(decision["action"], "review");
    assert_eq!(decision["ruleId"], "review-push");
    assert_eq!(decision["effect"], "default");
}

#[test]
fn a_rule_the_dialect_rejects_refuses_the_whole_decision() {
    let error = evaluate(&request(
        vec![
            rule("allow-git", "allow", "startsWith", "git"),
            rule("broken", "block", "regex", "git ("),
        ],
        "git push",
    ))
    .expect_err("refused");
    assert_eq!(
        error,
        "native_command_policy_decision_invalid_command_regex"
    );
}

#[test]
fn an_action_the_lattice_does_not_name_is_refused() {
    let error = evaluate(&request(
        vec![rule("odd", "escalate", "startsWith", "git")],
        "git push",
    ))
    .expect_err("refused");
    assert_eq!(error, "native_command_policy_decision_rule_action_unknown");
}

#[test]
fn a_request_naming_another_schema_decides_nothing() {
    let mut other = request(vec![rule("allow-git", "allow", "startsWith", "git")], "git");
    other.schema = "guard-policy-document-decision-request.v1".to_owned();
    let error = evaluate(&other).expect_err("schema mismatch");
    assert_eq!(error, "native_command_policy_decision_schema_mismatch");
}

#[test]
fn an_empty_command_is_refused_rather_than_matched_against_nothing() {
    let error = evaluate(&request(
        vec![rule("allow-git", "allow", "startsWith", "git")],
        "   ",
    ))
    .expect_err("refused");
    assert_eq!(
        error,
        "native_command_policy_decision_command_value_required"
    );
}

#[test]
fn the_lookup_reports_the_evaluation_time_and_no_artifact() {
    let decision = evaluate(&request(
        vec![rule("allow-git", "allow", "startsWith", "git")],
        "git status",
    ))
    .expect("decided");
    assert_eq!(decision["lookup"]["at"], NOW);
    assert_eq!(decision["lookup"]["artifactId"], Value::Null);
    assert_eq!(decision["lookup"]["familyKey"], Value::Null);
    assert_eq!(decision["matchLimitExceeded"], false);
}
