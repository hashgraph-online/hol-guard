//! `workspace_audit_sync` runner-authority kind: turns the per-workspace
//! outcomes of a Guard Cloud audit sync into the persisted summary. Ported
//! from the row and status logic of `sync_managed_workspace_audits`.
//!
//! Python still enqueues and polls the cloud jobs, since this runtime has no
//! HTTP client, and ships one outcome per managed workspace:
//!
//! - `{"outcome": "skipped", "workspace"}` for a workspace with no inventory;
//! - `{"outcome": "failed", "workspace", "message"}` for a local or cloud error;
//! - `{"outcome": "job", "workspace", "workspace_fingerprint", "job_id",
//!   "package_count", "enqueue_status", "final", "manifest_paths",
//!   "lockfile_paths"}` for a job the cloud accepted, where `final` is the last
//!   polled job response.
//!
//! The answer is the summary the caller persists, rows in outcome order.

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SKIPPED_MESSAGE: &str =
    "No supported package inventory was detected for workspace audit sync.";

#[derive(Default)]
struct Counts {
    completed: u64,
    failed: u64,
    incomplete: u64,
    queued: u64,
    skipped: u64,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let synced_at = args
        .get("synced_at")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let outcomes = args
        .get("workspaces")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut counts = Counts::default();
    let rows = outcomes
        .iter()
        .map(|outcome| workspace_row(outcome, &mut counts))
        .collect::<Result<Vec<Value>, _>>()?;
    let status = if counts.failed > 0
        && counts.completed == 0
        && counts.queued == 0
        && counts.incomplete == 0
    {
        "failed"
    } else if counts.failed > 0 || counts.incomplete > 0 {
        "partial"
    } else if counts.completed > 0 || counts.queued > 0 {
        "synced"
    } else {
        "idle"
    };
    Ok(json!({
        "synced_at": synced_at,
        "status": status,
        "workspace_count": rows.len(),
        "completed_jobs": counts.completed,
        "queued_jobs": counts.queued,
        "failed_jobs": counts.failed,
        "incomplete_jobs": counts.incomplete,
        "skipped_workspaces": counts.skipped,
        "workspaces": rows,
    }))
}

fn workspace_row(outcome: &Value, counts: &mut Counts) -> Result<Value, &'static str> {
    let workspace = outcome
        .get("workspace")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    match outcome.get("outcome").and_then(Value::as_str) {
        Some("skipped") => {
            counts.skipped += 1;
            Ok(json!({
                "workspace": workspace,
                "status": "skipped",
                "message": SKIPPED_MESSAGE,
                "package_count": 0,
            }))
        }
        Some("failed") => {
            let message = outcome
                .get("message")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?;
            counts.failed += 1;
            Ok(json!({
                "workspace": workspace,
                "status": "failed",
                "message": message,
                "package_count": 0,
            }))
        }
        Some("job") => job_row(workspace, outcome, counts),
        _ => Err(ERR_INVALID),
    }
}

fn job_row(workspace: &str, outcome: &Value, counts: &mut Counts) -> Result<Value, &'static str> {
    let final_response = outcome
        .get("final")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let job_id = outcome
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let package_count = outcome
        .get("package_count")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let paths = |key: &str| match outcome.get(key) {
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => Ok(items.clone()),
        _ => Err(ERR_INVALID),
    };
    let (manifest_paths, lockfile_paths) = (paths("manifest_paths")?, paths("lockfile_paths")?);
    // `str(final.get("status") or enqueue.get("status") or "queued")`.
    let reported = [final_response.get("status"), outcome.get("enqueue_status")]
        .into_iter()
        .flatten()
        .find(|value| py_truthy(value));
    let reported = reported.map_or_else(|| "queued".to_owned(), py_str);
    let final_status = py_strip(&reported).to_lowercase();
    let final_status = final_status.as_str();
    let visible = int_value(final_response.get("totalPackages"));
    let processed = int_value(final_response.get("processedCount"));
    let incomplete = final_status == "completed"
        && visible.is_some_and(|count| int_number(count) < i128::from(package_count));
    let (status, message) = if incomplete {
        counts.incomplete += 1;
        let visible = visible.map(py_str).unwrap_or_default();
        let message = format!(
            "Guard Cloud accepted fewer package rows than hol-guard discovered \
             ({visible} of {package_count} visible)."
        );
        ("partial", json!(message))
    } else {
        match final_status {
            "completed" => counts.completed += 1,
            "failed" => counts.failed += 1,
            _ => counts.queued += 1,
        }
        let message = final_response.get("error").cloned().unwrap_or(Value::Null);
        (final_status, message)
    };
    Ok(json!({
        "workspace": workspace,
        "workspace_fingerprint": outcome.get("workspace_fingerprint").cloned().unwrap_or(Value::Null),
        "job_id": job_id,
        "status": status,
        "package_count": package_count,
        "cloud_processed_count": processed.cloned().unwrap_or(Value::Null),
        "cloud_visible_count": visible.cloned().unwrap_or(Value::Null),
        "manifest_paths": manifest_paths,
        "lockfile_paths": lockfile_paths,
        "message": message,
    }))
}

/// `isinstance(value, int)`: a JSON integer or, as in Python, a boolean.
fn int_value(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| value.is_boolean() || value.is_i64() || value.is_u64())
}

fn int_number(value: &Value) -> i128 {
    match value {
        Value::Bool(flag) => i128::from(*flag),
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .unwrap_or_default(),
        _ => 0,
    }
}

fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `str(value)` for the scalars a status or count carries. A container falls
/// back to its JSON text; Python would print its repr, and either way it is
/// not a status the summary recognizes.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "workspace_audit_sync_tests.rs"]
mod tests;
