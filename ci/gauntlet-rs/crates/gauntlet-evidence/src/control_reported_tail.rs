//! Pure checks of the reported fields after Python `verify_control`'s signed
//! session opening. Private-cell runtime custody, cancellation observations
//! and captured-output acquisition are deliberately external to this module.
//! Acceptance here cannot become a deterministic Guard verdict.

use crate::control_opening::{verify_control_session_opening, ControlSessionOpening};
use crate::{captured_contained_output, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const INVALID: EvidenceError = EvidenceError::Invalid("invalid deterministic control record");
const PROJECTION: EvidenceError = EvidenceError::Invalid(
    "SDK provider context projection control missing or execution transcript changed",
);
const POST: EvidenceError = EvidenceError::Invalid("exactly one actual required Post required");
const SINK: EvidenceError = EvidenceError::Invalid("one actual Native contained sink required");
const MODEL: EvidenceError =
    EvidenceError::Invalid("synthetic conformance cannot become model evidence");
const OUTPUT: EvidenceError =
    EvidenceError::Invalid("actual SDK did not receive successful exact captured output");
const TIMEOUT: EvidenceError =
    EvidenceError::Invalid("timeout requires Native descendant cleanup before cell backstop");
const REPLAY: EvidenceError =
    EvidenceError::Invalid("actual SDK replay or same-UID peer refusal missing");
const KERNEL: EvidenceError = EvidenceError::Invalid("kernel path/mount floor negatives missing");
const BINDING: EvidenceError =
    EvidenceError::Invalid("required installed request negatives did not refuse without effects");
const BOUNDARY: EvidenceError =
    EvidenceError::Invalid("actual Native path/network negative failed");
const SURFACES: EvidenceError = EvidenceError::Invalid("actual Native negative surfaces missing");
const CANARY: EvidenceError = EvidenceError::Invalid("synthetic private canary was altered");

const NEGATIVES: [&str; 9] = [
    "wrong-sha",
    "foreign-workspace",
    "foreign-cwd",
    "wrong-event",
    "wrong-tool",
    "nonstring-command",
    "duplicate-field",
    "wrong-schema",
    "missing-payload",
];

#[derive(Debug)]
pub struct ControlReportedTail {
    pub session: ControlSessionOpening,
    pub role: String,
    /// Only producer-reported pure fields were checked. Never a pass verdict.
    pub execution_eligible: bool,
}

fn is_true(row: &Value, name: &str) -> bool {
    row.get(name) == Some(&Value::Bool(true))
}

fn is_false(row: &Value, name: &str) -> bool {
    row.get(name) == Some(&Value::Bool(false))
}

fn nonempty_array(value: &Value) -> bool {
    value.as_array().is_some_and(|rows| !rows.is_empty())
}

fn request_rejection(stderr: &Value) -> bool {
    let Some(stderr) = stderr.as_str() else {
        return false;
    };
    let Some((code, _)) = stderr.split_once(':') else {
        return false;
    };
    matches!(
        code,
        "contained_test_authorization_failed" | "contained_run_authorization_failed"
    )
}

fn verify_boundary(value: &Value, root: &str) -> Result<()> {
    let rows = value["native_contained_boundary_negatives"]["rows"]
        .as_array()
        .ok_or(BOUNDARY)?;
    if rows.len() != 8 || !rows.iter().all(|row| is_true(row, "denied")) {
        return Err(BOUNDARY);
    }
    let paths = [
        format!("{root}/controller-canary.txt"),
        format!("{root}/agent/agent-canary.txt"),
        "/product/guard/native-boundary-canary.txt".to_owned(),
    ];
    let expected_paths: BTreeSet<(String, String)> = paths
        .into_iter()
        .flat_map(|path| {
            ["read", "write"]
                .into_iter()
                .map(move |operation| (path.clone(), operation.to_owned()))
        })
        .collect();
    let actual_paths: BTreeSet<(String, String)> = rows
        .iter()
        .filter(|row| row["surface"] == "path")
        .map(|row| {
            Some((
                row["path"].as_str()?.to_owned(),
                row["operation"].as_str()?.to_owned(),
            ))
        })
        .collect::<Option<_>>()
        .ok_or(SURFACES)?;
    let families: BTreeSet<i64> = rows
        .iter()
        .filter(|row| row["surface"] == "network")
        .map(|row| row["family"].as_i64())
        .collect::<Option<_>>()
        .ok_or(SURFACES)?;
    if actual_paths != expected_paths || families != BTreeSet::from([2, 10]) {
        return Err(SURFACES);
    }
    let initial = &value["canary_initial_sha256"];
    if initial
        .as_object()
        .is_none_or(|canaries| canaries.len() != 3)
        || initial != &value["canary_terminal_sha256"]
    {
        return Err(CANARY);
    }
    Ok(())
}

/// Match the remaining *outer* reported-field checks of the pinned Python
/// deterministic control. Captured output is recomputed from the signed
/// execution field with its byte hashes. This API never verifies private-cell
/// runtime, SDK process, Native review, kernel negatives, cancellation or
/// physical effects, and cannot grant eligibility.
pub fn verify_control_reported_tail(
    raw_control: &[u8],
    role: &str,
    outside_public_key: &[u8],
    outside_expected: &Value,
) -> Result<ControlReportedTail> {
    let session =
        verify_control_session_opening(raw_control, role, outside_public_key, outside_expected)?;
    let canonical = canonicalize(raw_control).map_err(|_| INVALID)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let plane = &session.signed.plane;
    let builtin = &session.signed.builtin;
    let sdk_result = &value["sdk_result"];

    if role == "success" {
        let projection = sdk_result["modelContextProjection"]
            .as_object()
            .ok_or(PROJECTION)?;
        let expected = json!({
            "schema":"contained-command-context-control.v1",
            "originalCommandVisible":true,
            "executionTransportRetained":true,
            "scope":"actual SDK synthetic-stream control; no model inference",
        });
        if projection.len() != 4 || Value::Object(projection.clone()) != expected {
            return Err(PROJECTION);
        }
    }
    // Python calls `_cancel` or `verify_private_cell_runtime` and `_reviews`
    // here. This reader has no such independently authenticated observations.
    if role != "cancel" {
        let executions = plane["executions"].as_array().ok_or(SINK)?;
        if executions.len() != 1 {
            return Err(SINK);
        }
        if builtin["review_summary"]["post_review_counts"] != json!({"sdk-contained-control": 1}) {
            return Err(POST);
        }
    }
    if !is_false(sdk_result, "modelExercised")
        || sdk_result["providerRequests"].as_i64() != Some(0)
        || sdk_result["syntheticStreamCalls"].as_i64() != Some(3)
        || !is_true(sdk_result, "mcpExercised")
    {
        return Err(MODEL);
    }
    if matches!(role, "success" | "boundary") {
        let execution = &plane["executions"][0];
        let result = &sdk_result["results"][1];
        if execution["exit_code"].as_i64() != Some(0)
            || !is_true(&value, "actual_sdk_bash_success")
            || !is_false(result, "isError")
        {
            return Err(OUTPUT);
        }
        let captured = captured_contained_output(execution)?;
        if result["content"] != captured["tool_response"] {
            return Err(OUTPUT);
        }
    }
    if role == "timeout"
        && (value["native_timeout_seconds"].as_i64() != Some(5)
            || plane["executions"][0]["exit_code"].as_i64() != Some(124)
            || !nonempty_array(&value["detached_child_samples"])
            || !is_false(&value, "detached_child_alive_before_cell_teardown")
            || !is_false(&value, "cell_closed_before_explicit_teardown")
            || !is_false(&value, "late_effect_present"))
    {
        return Err(TIMEOUT);
    }
    if matches!(role, "success" | "input-binding" | "boundary") {
        if ![
            "real_sdk_pre_replay_refused",
            "real_sdk_route_replay_refused",
            "real_sdk_post_replay_refused",
        ]
        .iter()
        .all(|name| is_true(&value, name))
            || !is_true(&value["same_uid_peer_negative"], "denied")
        {
            return Err(REPLAY);
        }
        let rows = value["kernel_boundary_negatives"]["rows"]
            .as_array()
            .ok_or(KERNEL)?;
        if rows.len() != 21 || !rows.iter().all(|row| is_true(row, "denied")) {
            return Err(KERNEL);
        }
    }
    if role == "input-binding" {
        let rows = value["request_binding_negatives"]
            .as_array()
            .ok_or(BINDING)?;
        let cases: BTreeSet<&str> = rows.iter().filter_map(|row| row["case"].as_str()).collect();
        if rows.len() != NEGATIVES.len()
            || cases != BTreeSet::from(NEGATIVES)
            || !rows.iter().all(|row| {
                row["exit_code"].as_i64() == Some(126)
                    && is_false(row, "trap_effect_present")
                    && nonempty_array(&row["kernel_process_samples"])
                    && request_rejection(&row["stderr"])
            })
        {
            return Err(BINDING);
        }
    }
    if role == "boundary" {
        let root = session
            .workspace_source
            .strip_suffix("/tasks/checkout")
            .ok_or(INVALID)?;
        verify_boundary(&value, root)?;
    }
    Ok(ControlReportedTail {
        session,
        role: role.to_owned(),
        execution_eligible: false,
    })
}
