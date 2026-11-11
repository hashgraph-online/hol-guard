//! `guard-repair-report --stdin`: what `hol-guard repair` and the daemon's
//! artifact reconciliation report (`repair_engine.py` and
//! `runtime_artifact_reconciliation.py` before the decisions moved here).
//!
//! Python still runs each repair, because the harness adapters, the shim
//! writer and the daemon restart live there. It hands this command what each
//! one returned, and the command decides the rest:
//!
//! - `report`: each step's status and summary, the run's overall status, and
//!   the text `hol-guard repair` prints. A collapse of older durable runtime
//!   copies is folded into the native-runtime step.
//! - `reconcile`: which harnesses the reconciliation pass repaired, and every
//!   error it reports, from the launcher refresh, the hook reinstalls, the
//!   Cursor rebind and the package-shim status before and after its repair.

use std::io::Read;

use serde_json::{json, Map, Value};

#[path = "guard_repair_reconcile.rs"]
mod reconcile;
#[path = "guard_repair_steps.rs"]
mod steps;

use reconcile::reconcile;
use steps::*;

const COMMAND: &str = "guard-repair-report";
const SCHEMA: &str = "guard-repair-report.v1";
const REPORT_SCHEMA: &str = "guard.repair.v1";
const MAX_REQUEST_BYTES: u64 = 512 * 1024;
const MAX_ERROR_CHARS: usize = 160;
const INVALID: &str = "guard_repair_report_request_invalid";

const STEPS: [(&str, &str); 7] = [
    ("daemon", "Guard daemon"),
    ("native_runtime", "Stale native runtime state"),
    ("native_install", "Native runtime install"),
    ("onefile_leaks", "Leaked extraction folders"),
    ("hooks", "Harness hooks"),
    ("package_shims", "Package-manager shims"),
    ("command_queue", "Command queue"),
];

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_repair_report_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_repair_report_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
    let request = request.as_object().ok_or(INVALID)?;
    if request.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(INVALID.to_owned());
    }
    let answer = match request.get("op").and_then(Value::as_str) {
        Some("report") => report(request)?,
        Some("reconcile") => reconcile(request)?,
        _ => return Err(INVALID.to_owned()),
    };
    serde_json::to_vec(&answer).map_err(|_| "guard_repair_report_response_unencodable".to_owned())
}

fn report(request: &Map<String, Value>) -> Result<Value, String> {
    let dry_run = request
        .get("dry_run")
        .and_then(Value::as_bool)
        .ok_or(INVALID)?;
    let results = request
        .get("results")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    let steps = results
        .iter()
        .map(|result| step_from_result(result, dry_run))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(build_report(steps, dry_run))
}

/// Text for an exception Python caught: `Type: message`, the message cut to
/// 160 characters.
fn error_text(object: &Map<String, Value>) -> String {
    let kind = text(object.get("error_type"));
    let message: String = text(object.get("error_message"))
        .chars()
        .take(MAX_ERROR_CHARS)
        .collect();
    format!("{kind}: {message}").trim().to_owned()
}

fn text(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn step(name: &str, status: &str, summary: &str, detail: Map<String, Value>) -> Value {
    let title = STEPS
        .iter()
        .find(|(step, _)| *step == name)
        .map(|(_, title)| *title)
        .unwrap_or(name);
    let mut object = Map::new();
    object.insert("step".into(), name.into());
    object.insert("title".into(), title.into());
    object.insert("status".into(), status.into());
    object.insert("summary".into(), summary.into());
    for (key, value) in detail {
        object.entry(key).or_insert(value);
    }
    Value::Object(object)
}

fn plain(name: &str, status: &str, summary: &str) -> Value {
    step(name, status, summary, Map::new())
}

fn with(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn error_step(name: &str, error: String) -> Value {
    step(
        name,
        "error",
        &format!("Could not complete: {error}"),
        with(&[("error", Value::String(error))]),
    )
}

fn step_from_result(result: &Value, dry_run: bool) -> Result<Value, String> {
    let object = result.as_object().ok_or(INVALID)?;
    let name = object.get("step").and_then(Value::as_str).ok_or(INVALID)?;
    if !STEPS.iter().any(|(step, _)| *step == name) {
        return Err(INVALID.to_owned());
    }
    if object.contains_key("error_type") {
        let step = error_step(name, error_text(object));
        return Ok(if name == "native_runtime" {
            fold_collapse(step, object.get("durable_runtimes"))
        } else {
            step
        });
    }
    Ok(match name {
        "daemon" => daemon_step(object),
        "native_runtime" => fold_collapse(
            native_runtime_step(object, dry_run),
            object.get("durable_runtimes"),
        ),
        "native_install" => native_install_step(object)?,
        "onefile_leaks" => onefile_step(object, dry_run)?,
        "hooks" => hooks_step(object, dry_run)?,
        "package_shims" => package_shims_step(object, dry_run),
        _ => command_queue_step(object, dry_run),
    })
}

fn count(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(value) => value.as_i64().unwrap_or(0),
        None => 0,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn needs_attention(step: &Value) -> bool {
    step.get("needs_attention")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn out_of_budget(step: &Value) -> bool {
    step.get("budget_exhausted").and_then(Value::as_bool) == Some(true)
}

fn build_report(steps: Vec<Value>, dry_run: bool) -> Value {
    let statuses: Vec<&str> = steps.iter().map(|item| text(item.get("status"))).collect();
    let status = if statuses.contains(&"error") || steps.iter().any(needs_attention) {
        "partial"
    } else if statuses.contains(&"planned") {
        "needs_repair"
    } else if statuses.contains(&"changed") {
        "repaired"
    } else if steps.iter().any(out_of_budget) {
        // A step that stopped at its budget has not finished checking.
        "partial"
    } else {
        "healthy"
    };
    let summary = summary(&steps, status, dry_run);
    json!({
        "schema": REPORT_SCHEMA,
        "dry_run": dry_run,
        "status": status,
        "steps": steps,
        "summary": summary,
    })
}

fn mark(status: &str) -> &str {
    match status {
        "ok" => "ok",
        "changed" => "fixed",
        "planned" => "would fix",
        "skipped" => "skipped",
        "error" => "FAILED",
        other => other,
    }
}

fn summary(steps: &[Value], status: &str, dry_run: bool) -> String {
    let mut lines = vec![if dry_run {
        "Guard repair (dry run, nothing changed)".to_owned()
    } else {
        "Guard repair".to_owned()
    }];
    for item in steps {
        lines.push(format!(
            "  [{}] {}: {}",
            mark(text(item.get("status"))),
            text(item.get("title")),
            text(item.get("summary"))
        ));
    }
    let attention: Vec<&str> = steps
        .iter()
        .filter(|item| needs_attention(item))
        .map(|item| text(item.get("title")))
        .collect();
    let any_error = steps.iter().any(|item| text(item.get("status")) == "error");
    let out_of_budget = steps.iter().any(out_of_budget);
    let closing = match status {
        "partial" if any_error => {
            "Some steps failed. Re-run `hol-guard repair`; if it persists, run `hol-guard doctor --json`."
        }
        // Nothing failed, but a step stopped at its own budget with work left.
        "partial" if out_of_budget => {
            "No step failed. Run `hol-guard repair` again to continue the cleanup it could not finish."
        }
        // The steps ran and found something only the user can settle.
        "partial" => "No step failed, and another `hol-guard repair` run reaches the same answer.",
        "needs_repair" => "Run `hol-guard repair` to apply these fixes.",
        "repaired" => {
            "Guard was repaired. Restart any open coding-agent sessions that were blocked."
        }
        _ => "Nothing needed repair.",
    };
    lines.push(closing.to_owned());
    if !attention.is_empty() {
        lines.push(format!(
            "These still need attention: {}. Each step above says what it is waiting on.",
            attention.join(", ")
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
#[path = "guard_repair_report_tests.rs"]
mod tests;
