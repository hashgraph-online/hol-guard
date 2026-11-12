use serde_json::{json, Value};

use super::*;

fn plan(request: Value, receipt: Value, verdict: Value, evaluation: Value) -> Value {
    dispatch(&json!({
        "request": request,
        "receipt": receipt,
        "verdict": verdict,
        "supply_chain_evaluation": evaluation,
    }))
    .unwrap()
}

fn review_plan(verdict_action: &str, supply_action: &str, envelope: Value) -> Value {
    plan(
        json!({
            "package_manager": "npm",
            "targets": [{"package_name": "left-pad"}, {"raw_spec": "left-pad"}, {"raw_spec": " lodash@4 "}, "x"],
        }),
        json!({
            "artifact_id": "npm:project:package-request",
            "artifact_hash": " sha256:abc ",
            "action_envelope_json": envelope,
        }),
        json!({"action": verdict_action, "reason": "  ", "risk_signals": [" changed ", "", 3]}),
        json!({
            "policy_action": supply_action,
            "user_copy": {"summary": "Package provenance requires review."},
            "reasons": [{"code": "cloud_timeout"}, {"code": " cloud_auth_error "}],
        }),
    )
}

#[test]
fn request_shape_is_exact() {
    assert_eq!(dispatch(&json!({})), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!([])), Err(ERR_INVALID));
    let mut args = json!({
        "request": null, "receipt": null, "verdict": null, "supply_chain_evaluation": null,
    });
    assert!(dispatch(&args).is_ok());
    args["extra"] = json!(1);
    assert_eq!(dispatch(&args), Err(ERR_INVALID));
}

#[test]
fn empty_response_neither_queues_nor_builds_an_item() {
    let answer = plan(Value::Null, Value::Null, Value::Null, Value::Null);
    assert_eq!(
        answer,
        json!({
            "harness": "guard-cli",
            "display_harness": "guard-cli",
            "artifact": null,
            "policy_action": null,
            "queue": false,
            "review_reason_code": "native_package_review",
            "item": null,
        })
    );
}

#[test]
fn harness_and_display_harness_read_their_own_key_orders() {
    let answer = plan(
        json!({"harness": " codex ", "package_manager": "pnpm"}),
        json!({"harness": "cursor"}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(answer["harness"], "codex");
    assert_eq!(answer["display_harness"], "pnpm");
    let receipt_only = plan(
        json!({"executor": " "}),
        json!({"harness": "cursor"}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(receipt_only["harness"], "cursor");
    assert_eq!(receipt_only["display_harness"], "cursor");
}

#[test]
fn request_artifact_falls_back_field_by_field() {
    let answer = plan(
        json!({"command": ["npm", "install", "left pad", 7, ""], "executor": "npm"}),
        json!({"artifact_id": " npm:req "}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(
        answer["artifact"],
        json!({
            "artifact_id": "npm:req",
            "name": "npm:req",
            "source_scope": "project",
            "package_manager": "npm",
            "intent_kind": "install",
            "redacted_command": "npm install 'left pad' ''",
        })
    );
    let redacted = plan(
        json!({"redacted_command": "npm i ***", "command": ["npm"], "install_kind": "update"}),
        json!({"artifact_id": "a", "artifact_name": "left-pad", "source_scope": "global"}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(redacted["artifact"]["redacted_command"], "npm i ***");
    assert_eq!(redacted["artifact"]["name"], "left-pad");
    assert_eq!(redacted["artifact"]["source_scope"], "global");
    assert_eq!(redacted["artifact"]["package_manager"], "package");
    assert_eq!(redacted["artifact"]["intent_kind"], "update");
    let no_command = plan(
        json!({"command": [1]}),
        json!({"artifact_id": "a"}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(no_command["artifact"]["redacted_command"], Value::Null);
    let no_id = plan(
        json!({}),
        json!({"artifact_id": "  "}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(no_id["artifact"], Value::Null);
}

#[test]
fn policy_action_is_the_most_restrictive_candidate() {
    let cases = [
        ("review", "review", json!(null), "review", false),
        (
            "review",
            "require-reapproval",
            json!(null),
            "require-reapproval",
            true,
        ),
        ("block", "review", json!(null), "block", true),
        ("review", "block", json!(null), "block", true),
        ("ask", "review", json!(null), "review", false),
        (
            "review",
            "review",
            json!({"policyAction": "allow"}),
            "review",
            false,
        ),
        // An unrecognized envelope action reads as block.
        (
            "review",
            "review",
            json!({"pre_execution_result": "maybe"}),
            "block",
            false,
        ),
        (
            "review",
            "review",
            json!({"preExecutionResult": "ask"}),
            "review",
            false,
        ),
    ];
    for (verdict, supply, envelope, expected, disagree) in cases {
        let answer = review_plan(verdict, supply, envelope.clone());
        assert_eq!(
            answer["policy_action"], expected,
            "{verdict} {supply} {envelope}"
        );
        assert_eq!(
            answer["item"]["actions_disagree"], disagree,
            "{verdict} {supply}"
        );
    }
    let envelope_only = plan(
        Value::Null,
        json!({"action_envelope_json": {"policy_action": null, "policyAction": "warn"}}),
        Value::Null,
        Value::Null,
    );
    assert_eq!(envelope_only["policy_action"], "warn");
}

#[test]
fn queue_needs_a_review_without_a_saved_package_block() {
    assert_eq!(review_plan("review", "review", Value::Null)["queue"], true);
    assert_eq!(
        review_plan("require-reapproval", "review", Value::Null)["queue"],
        true
    );
    assert_eq!(review_plan("block", "review", Value::Null)["queue"], false);
    let saved = plan(
        Value::Null,
        Value::Null,
        json!({"action": "review"}),
        json!({"reasons": [{"code": " saved_package_block "}]}),
    );
    assert_eq!(saved["queue"], false);
}

#[test]
fn approval_item_carries_the_package_review_fields() {
    let answer = review_plan("review", "review", json!({"policy_action": "review"}));
    assert_eq!(
        answer["review_reason_code"],
        "native_package_cloud_unavailable"
    );
    assert_eq!(
        answer["item"],
        json!({
            "changed_fields": ["left-pad", "lodash@4"],
            "risk_summary": "Package provenance requires review.",
            "decision_reason": "Package provenance requires review.",
            // The item reads codes untrimmed, so the padded auth code is skipped.
            "cloud_reason_code": "cloud_timeout",
            "risk_signals": ["changed"],
            "artifact_hash": "sha256:abc",
            "actions_disagree": false,
            "envelope": {"drop": [], "set": ["policy_action"]},
        })
    );
}

#[test]
fn approval_item_needs_every_member_and_an_approvable_action() {
    let warn = plan(
        json!({}),
        json!({}),
        json!({"action": "warn"}),
        json!({"policy_action": "warn"}),
    );
    assert_eq!(warn["policy_action"], "warn");
    assert_eq!(warn["item"], Value::Null);
    let no_evaluation = plan(
        json!({}),
        json!({}),
        json!({"action": "block"}),
        Value::Null,
    );
    assert_eq!(no_evaluation["policy_action"], "block");
    assert_eq!(no_evaluation["item"], Value::Null);
    let bare = plan(
        json!({}),
        json!({}),
        json!({"action": "require-reapproval"}),
        json!({}),
    );
    assert_eq!(bare["item"]["risk_summary"], Value::Null);
    assert_eq!(
        bare["item"]["decision_reason"],
        "package_supply_chain_require_reapproval"
    );
    assert_eq!(bare["item"]["envelope"], Value::Null);
    assert_eq!(bare["item"]["artifact_hash"], Value::Null);
}

#[test]
fn observe_mode_envelope_is_kept_unless_it_observed_the_policy_action() {
    let observed_other = review_plan(
        "review",
        "review",
        json!({"observe_mode": true, "observed_policy_action": "allow", "policy_action": "allow"}),
    );
    assert_eq!(
        observed_other["item"]["envelope"],
        json!({"drop": [], "set": []})
    );
    let observed_same = review_plan(
        "review",
        "review",
        json!({"observe_mode": true, "observed_policy_action": " review ", "preExecutionResult": "allow"}),
    );
    assert_eq!(
        observed_same["item"]["envelope"],
        json!({"drop": ["observe_mode", "observed_policy_action"], "set": ["preExecutionResult"]})
    );
    let not_observing = review_plan(
        "review",
        "review",
        json!({"observe_mode": 1, "observed_policy_action": "allow"}),
    );
    assert_eq!(
        not_observing["item"]["envelope"],
        json!({"drop": [], "set": []})
    );
}
