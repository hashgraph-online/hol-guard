//! `_validated_lineage` parity: every rejection the Python function could
//! raise, plus the one shape it accepts.

use serde_json::{json, Value};

use crate::github_workflow_approval_record::GitHubWorkflowApprovalRecord;
use crate::github_workflow_descriptor::framed_digest;
use crate::github_workflow_lineage::{
    approval_record_from_approval_request, validated_workflow_lineage,
};

const WORKSPACE: &str = "/srv/workspace";
const SESSION_ID: &str = "sess-1";
const OPERATION_ID: &str = "op-1";
const REQUEST_ID: &str = "req-1";

fn sha(label: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(label.as_bytes()))
}

fn workspace_digest() -> String {
    framed_digest("github-workspace", &Value::String(WORKSPACE.to_owned())).unwrap()
}

fn record_value() -> Value {
    json!({
        "schema_version": "guard.github-workflow-approval-record.v1",
        "operation_kind": "resolve-review-thread",
        "resource_type": "github-review-thread",
        "command_identity_sha256": sha("command-identity"),
        "operation_digest_sha256": sha("operation-digest"),
        "binding": {
            "operation_id": "github.resolve-review-thread.v1",
            "resource_type": "github-review-thread",
            "resource_sha256": sha("resource"),
            "repository_sha256": sha("repository"),
            "workspace_sha256": workspace_digest(),
            "executable_sha256": sha("executable"),
            "launch_sha256": sha("launch"),
            "policy_id": "guard.policy",
            "policy_version": "policy.v1",
            "effect_id": "guard.effect",
            "effect_version": "effect.v1",
            "decision_id": "guard.decision",
            "decision_version": "decision.v1",
            "rules": [{"rule_id": "guard.workflow", "rule_version": "v1"}],
        },
    })
}

fn approval_request() -> Value {
    json!({
        "request_id": REQUEST_ID,
        "harness": "claude-code",
        "artifact_type": "tool_action_request",
        "scanner_evidence": [
            {"source": "other_scanner", "record": {"unrelated": true}},
            {"source": "github_workflow_approval_record", "record": record_value()},
        ],
    })
}

fn operation() -> Value {
    json!({
        "operation_id": OPERATION_ID,
        "session_id": SESSION_ID,
        "harness": "claude-code",
        "operation_type": "tool_call",
        "status": "waiting_on_approval",
        "approval_request_ids": [REQUEST_ID],
        "metadata": {
            "hook_event_name": "PreToolUse",
            "command_text": "gh api graphql -f query=...",
            "workspace": WORKSPACE,
        },
    })
}

fn session() -> Value {
    json!({
        "session_id": SESSION_ID,
        "harness": "claude-code",
        "surface": "harness-adapter",
        "capabilities": ["approval-resolution"],
        "workspace": WORKSPACE,
    })
}

/// The workspace exists and the persisted command still derives the record.
fn validate(request: &Value, operation: &Value, session: &Value) -> Result<String, String> {
    let resolve = |workspace: &str| Some(workspace.to_owned());
    let matches = |_: &str, _: &GitHubWorkflowApprovalRecord| true;
    validated_workflow_lineage(request, operation, session, &resolve, &matches)
        .map(|lineage| lineage.operation_id)
}

#[test]
fn an_unbroken_lineage_yields_its_three_identities() {
    let resolve = |workspace: &str| Some(workspace.to_owned());
    let matches = |_: &str, _: &GitHubWorkflowApprovalRecord| true;
    let lineage = validated_workflow_lineage(
        &approval_request(),
        &operation(),
        &session(),
        &resolve,
        &matches,
    )
    .unwrap();

    assert_eq!(lineage.request_id, REQUEST_ID);
    assert_eq!(lineage.operation_id, OPERATION_ID);
    assert_eq!(lineage.session_id, SESSION_ID);
    assert_eq!(lineage.record.binding.workspace_sha256, workspace_digest());
    // The two identities Python used to derive for itself, pinned to the bytes
    // `_capability_id` and `_digest` produced for this request id. A capability
    // already issued under the Python spelling has to resolve to the same row.
    assert_eq!(
        lineage.capability_id,
        "gwc-04caee1311432ac664fb0049886efc8542650745e0ae8d1f196e9d59e679d2e3"
    );
    assert_eq!(
        lineage.nonce,
        "8181504e4207c78e7a25469f287b65a4d76ba8efd47133cac27a0335be52ccee"
    );
}

#[test]
fn every_operation_state_a_resolved_approval_can_be_read_back_in_is_accepted() {
    for state in ["waiting_on_approval", "completed", "resumed"] {
        let mut row = operation();
        row["status"] = json!(state);
        assert!(
            validate(&approval_request(), &row, &session()).is_ok(),
            "{state}"
        );
    }
    let mut row = operation();
    row["status"] = json!("pending");
    assert_eq!(
        validate(&approval_request(), &row, &session()),
        Err("invalid Guard workflow operation state".to_string())
    );
}

#[test]
fn each_harness_spelling_of_the_pre_tool_event_is_accepted() {
    for name in ["PreToolUse", "beforeShellExecution", "preToolUse"] {
        let mut row = operation();
        row["metadata"]["hook_event_name"] = json!(name);
        assert!(
            validate(&approval_request(), &row, &session()).is_ok(),
            "{name}"
        );
    }
    let mut row = operation();
    row["metadata"]["hook_event_name"] = json!("PostToolUse");
    assert_eq!(
        validate(&approval_request(), &row, &session()),
        Err("invalid Guard workflow hook event".to_string())
    );
}

#[test]
fn the_request_must_be_linked_to_the_operation_exactly_once() {
    for linkage in [json!([]), json!([REQUEST_ID, REQUEST_ID]), json!("req-1")] {
        let mut row = operation();
        row["approval_request_ids"] = linkage.clone();
        assert_eq!(
            validate(&approval_request(), &row, &session()),
            Err("invalid Guard operation approval linkage".to_string()),
            "{linkage}"
        );
    }
}

#[test]
fn the_session_must_resolve_approvals_from_a_harness_adapter() {
    let mut without_capability = session();
    without_capability["capabilities"] = json!(["policy-read"]);
    let mut wrong_surface = session();
    wrong_surface["surface"] = json!("cli");

    for row in [without_capability, wrong_surface] {
        assert_eq!(
            validate(&approval_request(), &operation(), &row),
            Err("invalid Guard workflow session".to_string())
        );
    }
}

#[test]
fn the_request_operation_and_session_must_name_one_harness() {
    let mut operation_row = operation();
    operation_row["harness"] = json!("codex");
    assert_eq!(
        validate(&approval_request(), &operation_row, &session()),
        Err("Guard operation harness mismatch".to_string())
    );

    let mut session_row = session();
    session_row["harness"] = json!("codex");
    assert_eq!(
        validate(&approval_request(), &operation(), &session_row),
        Err("Guard operation harness mismatch".to_string())
    );
}

#[test]
fn a_command_that_no_longer_derives_the_record_is_a_mismatch() {
    let resolve = |workspace: &str| Some(workspace.to_owned());
    let rejects = |_: &str, _: &GitHubWorkflowApprovalRecord| false;
    assert_eq!(
        validated_workflow_lineage(
            &approval_request(),
            &operation(),
            &session(),
            &resolve,
            &rejects
        )
        .unwrap_err(),
        "Guard operation command mismatch"
    );

    let mut row = operation();
    row["metadata"]["command_text"] = json!("");
    assert_eq!(
        validate(&approval_request(), &row, &session()),
        Err("Guard operation command mismatch".to_string())
    );
}

#[test]
fn the_workspace_must_match_the_session_and_bind_to_the_record() {
    let mut elsewhere = operation();
    elsewhere["metadata"]["workspace"] = json!("/srv/other");
    assert_eq!(
        validate(&approval_request(), &elsewhere, &session()),
        Err("Guard operation workspace mismatch".to_string())
    );

    // Same path on both rows, but not the one the record was bound to.
    let mut session_row = session();
    session_row["workspace"] = json!("/srv/other");
    assert_eq!(
        validate(&approval_request(), &elsewhere, &session_row),
        Err("Guard operation workspace mismatch".to_string())
    );
}

#[test]
fn a_workspace_that_does_not_resolve_cannot_bind() {
    let unresolvable = |_: &str| -> Option<String> { None };
    let matches = |_: &str, _: &GitHubWorkflowApprovalRecord| true;
    assert_eq!(
        validated_workflow_lineage(
            &approval_request(),
            &operation(),
            &session(),
            &unresolvable,
            &matches
        )
        .unwrap_err(),
        "Guard operation workspace mismatch"
    );
}

#[test]
fn only_a_tool_action_request_carries_workflow_authority() {
    let mut request = approval_request();
    request["artifact_type"] = json!("tool_decision");
    assert_eq!(
        validate(&request, &operation(), &session()),
        Err("invalid GitHub workflow approval type".to_string())
    );
}

#[test]
fn exactly_one_approval_record_row_counts_as_a_record() {
    let none = json!({"request_id": REQUEST_ID, "scanner_evidence": []});
    assert!(approval_record_from_approval_request(&none).is_none());

    let two = json!({
        "scanner_evidence": [
            {"source": "github_workflow_approval_record", "record": record_value()},
            {"source": "github_workflow_approval_record", "record": record_value()},
        ],
    });
    assert!(approval_record_from_approval_request(&two).is_none());

    let not_a_mapping = json!({
        "scanner_evidence": [
            {"source": "github_workflow_approval_record", "record": "nope"},
        ],
    });
    assert!(approval_record_from_approval_request(&not_a_mapping).is_none());

    assert!(approval_record_from_approval_request(&approval_request()).is_some());
}

#[test]
fn a_record_that_fails_its_own_validation_is_no_record() {
    let mut broken = record_value();
    broken["operation_kind"] = json!("delete-repository");
    let request = json!({
        "request_id": REQUEST_ID,
        "harness": "claude-code",
        "artifact_type": "tool_action_request",
        "scanner_evidence": [{"source": "github_workflow_approval_record", "record": broken}],
    });

    assert_eq!(
        validate(&request, &operation(), &session()),
        Err("missing GitHub workflow approval record".to_string())
    );
}

#[test]
fn a_missing_identifier_names_the_key_it_wanted() {
    let mut request = approval_request();
    request["request_id"] = json!("");
    assert_eq!(
        validate(&request, &operation(), &session()),
        Err("missing request_id".to_string())
    );

    let mut row = operation();
    row["session_id"] = json!("");
    assert_eq!(
        validate(&approval_request(), &row, &session()),
        Err("missing session_id".to_string())
    );
}

#[test]
fn the_session_row_must_be_the_one_the_operation_named() {
    let mut other = session();
    other["session_id"] = json!("sess-2");
    assert_eq!(
        validate(&approval_request(), &operation(), &other),
        Err("missing Guard session".to_string())
    );
}
