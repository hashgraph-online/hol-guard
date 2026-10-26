//! Policy-write handlers: `POST /v1/policy/decisions` and `/v1/policy/clear`.
//!
//! The order of the checks is the order of the error replies the daemon sends.

use crate::daemon_handler_fields::{optional_bool, optional_string};
use crate::daemon_handler_op::Reply;
use guard_contracts::DaemonFieldV1;
use serde_json::{json, Value};

const DECISION_SCOPES: [&str; 5] = ["global", "harness", "workspace", "artifact", "publisher"];
const GUARD_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

pub(crate) struct PolicyUpsertInput<'a> {
    pub harness: &'a DaemonFieldV1,
    pub scope: &'a DaemonFieldV1,
    pub action: &'a DaemonFieldV1,
    pub artifact_id: &'a DaemonFieldV1,
    pub workspace: &'a DaemonFieldV1,
    pub publisher: &'a DaemonFieldV1,
    pub reason: &'a DaemonFieldV1,
}

fn failed(error: &str) -> Reply {
    Reply::reject(400, json!({"saved": false, "error": error}))
}

fn scope_target_is_valid(
    scope: &str,
    artifact_id: &Option<String>,
    workspace: &Option<String>,
    publisher: &Option<String>,
) -> bool {
    match scope {
        "global" | "harness" => true,
        "artifact" => artifact_id.is_some(),
        "workspace" => workspace.is_some(),
        "publisher" => publisher.is_some(),
        _ => false,
    }
}

pub(crate) fn policy_upsert(input: &PolicyUpsertInput<'_>) -> Reply {
    let (Some(harness), Some(scope), Some(action)) = (
        optional_string(input.harness),
        optional_string(input.scope),
        optional_string(input.action),
    ) else {
        return failed("missing_required_fields");
    };
    if !DECISION_SCOPES.contains(&scope.as_str()) || !GUARD_ACTIONS.contains(&action.as_str()) {
        return failed("unsupported_policy_value");
    }
    if scope == "global" && action == "allow" {
        return failed("broad_allow_requires_narrow_scope");
    }
    let artifact_id = optional_string(input.artifact_id);
    let workspace = optional_string(input.workspace);
    let publisher = optional_string(input.publisher);
    if !scope_target_is_valid(&scope, &artifact_id, &workspace, &publisher) {
        return failed("missing_scope_target");
    }
    let record = json!({
        "harness": harness,
        "scope": scope,
        "action": action,
        "artifact_id": artifact_id,
        "workspace": workspace,
        "publisher": publisher,
        "reason": optional_string(input.reason),
    });
    Reply::proceed(json!({"saved": true, "decision": record}), record)
}

pub(crate) struct PolicyClearInput<'a> {
    pub harness: &'a DaemonFieldV1,
    pub source: &'a DaemonFieldV1,
    pub scope: &'a DaemonFieldV1,
    pub artifact_id: &'a DaemonFieldV1,
    pub artifact_hash: &'a DaemonFieldV1,
    pub workspace: &'a DaemonFieldV1,
    pub publisher: &'a DaemonFieldV1,
    pub all: &'a DaemonFieldV1,
    pub artifact_id_is_null: &'a DaemonFieldV1,
    pub artifact_hash_is_null: &'a DaemonFieldV1,
}

pub(crate) fn policy_clear(input: &PolicyClearInput<'_>) -> Reply {
    let harness = optional_string(input.harness);
    let source = optional_string(input.source);
    let scope = optional_string(input.scope);
    let flags = (
        optional_bool(input.all, false),
        optional_bool(input.artifact_id_is_null, false),
        optional_bool(input.artifact_hash_is_null, false),
    );
    let (Ok(clear_all), Ok(artifact_id_is_null), Ok(artifact_hash_is_null)) = flags else {
        return Reply::reject(400, json!({"error": "invalid_clear_payload", "cleared": 0}));
    };
    if let Some(scope) = &scope {
        if !DECISION_SCOPES.contains(&scope.as_str()) {
            return Reply::reject(
                400,
                json!({"error": "invalid_scope", "cleared": 0, "scope": scope}),
            );
        }
    }
    if clear_all && harness.is_some() {
        return Reply::reject(
            400,
            json!({
                "error": "choose_all_or_harness",
                "cleared": 0,
                "harness": harness,
                "source": source,
            }),
        );
    }
    if !clear_all && harness.is_none() {
        return Reply::reject(
            400,
            json!({"error": "missing_harness_or_all", "cleared": 0}),
        );
    }
    let fields: Value = json!({
        "harness": if clear_all { None } else { harness },
        "source": source,
        "scope": scope,
        "artifact_id": optional_string(input.artifact_id),
        "artifact_hash": optional_string(input.artifact_hash),
        "artifact_id_is_null": artifact_id_is_null,
        "artifact_hash_is_null": artifact_hash_is_null,
        "workspace": optional_string(input.workspace),
        "publisher": optional_string(input.publisher),
    });
    Reply::proceed(fields.clone(), fields)
}
