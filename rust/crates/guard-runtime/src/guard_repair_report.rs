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

fn daemon_step(object: &Map<String, Value>) -> Value {
    const HEALTHY: &str = "Daemon is healthy.";
    match object.get("probe").and_then(Value::as_str) {
        Some("unrecorded") => plain("daemon", "ok", "No daemon is recorded for this Guard home."),
        Some("healthy") => plain("daemon", "ok", HEALTHY),
        Some(_) => plain(
            "daemon",
            "planned",
            "Daemon is not responding; it would be restarted.",
        ),
        None => {
            let runtime_status = object
                .get("runtime_status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let detail = with(&[("runtime_status", runtime_status.into())]);
            if runtime_status == "restarted" {
                step(
                    "daemon",
                    "changed",
                    "Daemon was not healthy and was restarted.",
                    detail,
                )
            } else {
                step("daemon", "ok", HEALTHY, detail)
            }
        }
    }
}

fn native_runtime_step(object: &Map<String, Value>, dry_run: bool) -> Value {
    const NAME: &str = "native_runtime";
    let detail = object.get("detail").and_then(Value::as_object);
    let Some(detail) = detail else {
        if object.get("offered").and_then(Value::as_bool) == Some(true) {
            // The runtime offers the prune but gave no usable report; it may
            // already have removed entries, so this is not "unavailable".
            return step(
                NAME,
                "error",
                "Could not complete: the runtime gave no usable report.",
                with(&[("outcome", "failed".into())]),
            );
        }
        return step(
            NAME,
            "skipped",
            "Not checked (runtime unavailable).",
            with(&[("outcome", "unavailable".into())]),
        );
    };
    let outcome = text(detail.get("outcome"));
    if matches!(outcome, "unsupported" | "unavailable") {
        return step(
            NAME,
            "skipped",
            &format!("Not checked ({outcome})."),
            detail.clone(),
        );
    }
    let dirs = count(detail.get("stale_dirs"));
    let sockets = count(detail.get("dead_sockets"));
    if dirs == 0 && sockets == 0 {
        return step(NAME, "ok", "No stale native runtime state.", detail.clone());
    }
    let (status, verb) = if dry_run {
        ("planned", "Would remove")
    } else {
        ("changed", "Removed")
    };
    step(
        NAME,
        status,
        &format!("{verb} {dirs} stale runtime folder(s) and {sockets} dead socket(s)."),
        detail.clone(),
    )
}

fn count(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(value) => value.as_i64().unwrap_or(0),
        None => 0,
    }
}

/// `step` with the durable-runtime collapse report attached. A failed or
/// skipped collapse never changes the step's status: the copies it would have
/// shared stay as they are and still launch.
fn fold_collapse(mut step: Value, collapse: Option<&Value>) -> Value {
    let Some(collapse) = collapse.filter(|value| value.is_object()) else {
        return step;
    };
    let collapsed = count(collapse.get("collapsed"));
    let object = step.as_object_mut().expect("steps are objects");
    object.insert("durable_runtimes".into(), collapse.clone());
    let status = text(object.get("status")).to_owned();
    if collapsed > 0 && matches!(status.as_str(), "ok" | "changed") {
        let noun = if collapsed == 1 { "copy" } else { "copies" };
        let shared = format!("Shared one file among {collapsed} older durable runtime {noun}.");
        let summary = if status == "ok" {
            shared
        } else {
            format!("{} {shared}", text(object.get("summary")))
        };
        object.insert("status".into(), "changed".into());
        object.insert("summary".into(), summary.into());
    }
    step
}

fn native_install_step(object: &Map<String, Value>) -> Result<Value, String> {
    const NAME: &str = "native_install";
    let report = object
        .get("report")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let outcome = text(report.get("outcome"));
    let summary = text(report.get("summary"));
    let mut detail = with(&[
        ("outcome", outcome.into()),
        (
            "candidates",
            report.get("candidates").cloned().unwrap_or(Value::Null),
        ),
    ]);
    if let Some(action) = report.get("action").filter(|value| !value.is_null()) {
        detail.insert("action".into(), action.clone());
    }
    if matches!(outcome, "needs_reinstall" | "refused") {
        // Nothing here failed, and nothing here can fix either of them: a
        // reinstall is the user's to run, and an execute bit this account was
        // refused will be refused the same way next time.
        detail.insert("needs_attention".into(), json!(["native runtime"]));
        return Ok(step(NAME, "skipped", summary, detail));
    }
    let status = match outcome {
        "healthy" => "ok",
        "absent" => "skipped",
        "planned" => "planned",
        "restored" => "changed",
        _ => return Err(INVALID.to_owned()),
    };
    Ok(step(NAME, status, summary, detail))
}

fn onefile_step(object: &Map<String, Value>, dry_run: bool) -> Result<Value, String> {
    const NAME: &str = "onefile_leaks";
    if object.get("not_owner").and_then(Value::as_bool) == Some(true) {
        return Ok(plain(
            NAME,
            "skipped",
            "Shared temp folders are only reclaimed for the default Guard home.",
        ));
    }
    let result = object
        .get("result")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let reclaimed_count = count(result.get("reclaimed_count"));
    let reclaimed_bytes = count(result.get("reclaimed_bytes"));
    let unmarked_scan = result.get("unmarked_scan").cloned().unwrap_or(Value::Null);
    let budget_exhausted = result
        .get("budget_exhausted")
        .cloned()
        .unwrap_or(Value::Null);
    let detail = with(&[
        ("reclaimed_count", reclaimed_count.into()),
        ("reclaimed_bytes", reclaimed_bytes.into()),
        // Reclaimed (or, in a dry run, would-be reclaimed) dirs are never
        // counted in `unmarked_count`, so it already is the remainder.
        (
            "unmarked_remaining",
            result.get("unmarked_count").cloned().unwrap_or(Value::Null),
        ),
        ("unmarked_scan", unmarked_scan.clone()),
        ("budget_exhausted", budget_exhausted.clone()),
        ("error_count", count(result.get("error_count")).into()),
    ]);
    if unmarked_scan.as_str() == Some("unavailable") {
        return Ok(step(
            NAME,
            "skipped",
            "Could not prove unmarked folders unused (open-files scan unavailable); left in place.",
            detail,
        ));
    }
    if reclaimed_count == 0 {
        return Ok(step(
            NAME,
            "ok",
            "No leaked extraction folders found.",
            detail,
        ));
    }
    let megabytes = reclaimed_bytes.div_euclid(1024 * 1024);
    let (status, verb) = if dry_run {
        ("planned", "Would reclaim")
    } else {
        ("changed", "Reclaimed")
    };
    let suffix = if budget_exhausted.as_bool() == Some(true) {
        " Run repair again to continue."
    } else {
        ""
    };
    Ok(step(
        NAME,
        status,
        &format!("{verb} {reclaimed_count} leaked folder(s), about {megabytes} MB.{suffix}"),
        detail,
    ))
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

fn hooks_step(object: &Map<String, Value>, dry_run: bool) -> Result<Value, String> {
    const NAME: &str = "hooks";
    let broken = object
        .get("broken")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    if broken.is_empty() {
        return Ok(step(
            NAME,
            "ok",
            "Managed harness hooks look intact.",
            with(&[("repaired", json!([])), ("failed", json!([]))]),
        ));
    }
    let names: Vec<&str> = broken
        .iter()
        .map(|item| text(item.get("harness")))
        .collect();
    if dry_run {
        return Ok(step(
            NAME,
            "planned",
            &format!("Would reinstall hooks for: {}.", names.join(", ")),
            with(&[
                ("repaired", json!([])),
                ("failed", json!([])),
                ("broken", Value::Array(broken.clone())),
            ]),
        ));
    }
    let still_broken = strings(object.get("still_broken"));
    let repaired: Vec<String> = strings(object.get("repaired"))
        .into_iter()
        .filter(|name| !still_broken.contains(name))
        .collect();
    let failed: Vec<Value> = object
        .get("failed")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .map(
                    |item| json!({"harness": text(item.get("harness")), "error": error_text(item)}),
                )
                .collect()
        })
        .unwrap_or_default();
    if !failed.is_empty() {
        let failed_names: Vec<&str> = failed
            .iter()
            .map(|item| text(item.get("harness")))
            .collect();
        return Ok(step(
            NAME,
            "error",
            &format!(
                "Reinstalled {} app(s); {} failed: {}.",
                repaired.len(),
                failed.len(),
                failed_names.join(", ")
            ),
            with(&[
                ("repaired", json!(repaired)),
                ("failed", Value::Array(failed.clone())),
                ("needs_attention", json!(still_broken)),
            ]),
        ));
    }
    if !still_broken.is_empty() && repaired.is_empty() {
        return Ok(step(
            NAME,
            "skipped",
            &format!(
                "Reinstalling hooks did not clear the problem for: {}. Check that the app is \
                 installed and its hooks are trusted, then run `hol-guard doctor --json`.",
                still_broken.join(", ")
            ),
            with(&[
                ("repaired", json!([])),
                ("failed", json!([])),
                ("needs_attention", json!(still_broken)),
            ]),
        ));
    }
    let mut summary = format!("Reinstalled hooks for: {}.", repaired.join(", "));
    if !still_broken.is_empty() {
        summary.push_str(&format!(
            " Still needs attention: {}.",
            still_broken.join(", ")
        ));
    }
    Ok(step(
        NAME,
        "changed",
        &summary,
        with(&[
            ("repaired", json!(repaired)),
            ("failed", json!([])),
            ("needs_attention", json!(still_broken)),
        ]),
    ))
}

fn package_shims_step(object: &Map<String, Value>, dry_run: bool) -> Value {
    const NAME: &str = "package_shims";
    let managers = strings(object.get("managers"));
    if managers.is_empty() {
        return plain(NAME, "ok", "No package-manager shims installed.");
    }
    let list = managers.join(", ");
    if dry_run {
        return plain(
            NAME,
            "planned",
            &format!("Would regenerate shims for: {list}."),
        );
    }
    step(
        NAME,
        "changed",
        &format!("Regenerated shims for: {list}."),
        with(&[(
            "restart_shell_required",
            object
                .get("restart_shell_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .into(),
        )]),
    )
}

fn command_queue_step(object: &Map<String, Value>, dry_run: bool) -> Value {
    const NAME: &str = "command_queue";
    if dry_run {
        return plain(NAME, "skipped", "Not checked in a dry run.");
    }
    match count(object.get("repaired_count")) {
        0 => plain(NAME, "ok", "Command queue is healthy."),
        cleared => plain(
            NAME,
            "changed",
            &format!("Cleared {cleared} stuck queue item(s)."),
        ),
    }
}

fn needs_attention(step: &Value) -> bool {
    step.get("needs_attention")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn build_report(steps: Vec<Value>, dry_run: bool) -> Value {
    let statuses: Vec<&str> = steps.iter().map(|item| text(item.get("status"))).collect();
    let status = if statuses.contains(&"error") || steps.iter().any(needs_attention) {
        "partial"
    } else if statuses.contains(&"planned") {
        "needs_repair"
    } else if statuses.contains(&"changed") {
        "repaired"
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
    let out_of_budget = steps
        .iter()
        .any(|item| item.get("budget_exhausted").and_then(Value::as_bool) == Some(true));
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

/// The reconciliation pass's result from what each of its repairs returned.
fn reconcile(request: &Map<String, Value>) -> Result<Value, String> {
    let mut errors: Vec<String> = strings(request.get("launcher_errors"))
        .into_iter()
        .map(|error| format!("launcher:{error}"))
        .collect();
    let mut repaired = strings(request.get("repaired_harnesses"));
    let failed = strings(request.get("failed_harnesses"));
    if let Some(rebind) = request.get("cursor_rebind").and_then(Value::as_object) {
        if rebind.get("rebound").and_then(Value::as_bool) == Some(true)
            && !repaired.iter().any(|name| name == "cursor")
        {
            repaired.push("cursor".to_owned());
        }
        if matches!(
            text(rebind.get("reason")),
            "cursor_hook_script_rebind_failed" | "cursor_hook_script_unreadable"
        ) {
            let detail = rebind
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("failed");
            errors.push(format!("cursor:rebind:{detail}"));
        }
    }
    let package = request
        .get("package")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut repaired_managers = Vec::new();
    // A pass that read the manifest before it failed still reports what it read.
    let initial = package.get("initial").and_then(Value::as_object);
    match initial.and_then(|status| status.get("manifest_state")) {
        None | Some(Value::Null) => {}
        Some(Value::String(state)) if state == "absent" || state == "valid" => {}
        Some(state) => errors.push(format!("package:manifest:{}", python_str(state))),
    }
    if package.get("failed").and_then(Value::as_bool) == Some(true) {
        errors.push("package:reconciliation_failed".to_owned());
    } else {
        let installed = strings(initial.and_then(|status| status.get("installed_managers")));
        if !installed.is_empty() {
            repaired_managers = strings(package.get("repaired"));
            let details = package
                .get("verified")
                .and_then(|status| status.get("manager_details"))
                .and_then(Value::as_array);
            match details {
                Some(details) => {
                    for detail in details.iter().filter_map(Value::as_object) {
                        let Some(manager) = detail
                            .get("manager")
                            .and_then(Value::as_str)
                            .filter(|manager| installed.iter().any(|name| name == manager))
                        else {
                            continue;
                        };
                        if detail.get("integrity").and_then(Value::as_str) != Some("ok") {
                            errors.push(format!("package:{manager}:integrity"));
                        }
                        if detail.get("path_active").and_then(Value::as_bool) != Some(true) {
                            errors.push(format!("package:{manager}:path_inactive"));
                        }
                    }
                }
                None => errors.extend(
                    installed
                        .iter()
                        .map(|manager| format!("package:{manager}:status_missing")),
                ),
            }
        }
    }
    Ok(json!({
        "repaired_harnesses": repaired,
        "failed_harnesses": failed,
        "repaired_package_managers": repaired_managers,
        "errors": errors,
    }))
}

/// How Python's f-string renders a JSON scalar.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "guard_repair_report_tests.rs"]
mod tests;
