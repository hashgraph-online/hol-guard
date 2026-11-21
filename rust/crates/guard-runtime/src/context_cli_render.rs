//! The text `hol-guard context` prints for the engine state and for setup jobs.

use std::fmt::Write;

use serde_json::Value;

/// `value` as Python's `str()` prints it, which the CLI's text has always used.
fn text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(other) => other.to_string(),
    }
}

fn present(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Number(_)) | Some(Value::Bool(true)) => true,
    }
}

/// The engine state, for `status`, `runtimes`, `check`, `start` and `off`.
pub(super) fn status(state: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "CIGAR context assistance: {}",
        text(state.get("availability"))
    );
    let _ = writeln!(
        out,
        "Requested: {} · Active: {}",
        text(state.get("requested_enabled")),
        text(state.get("effective_enabled"))
    );
    if let Some(job) = state.get("job").filter(|job| present(Some(job))) {
        let _ = writeln!(
            out,
            "Background operation: {} ({})",
            text(job.get("operation")),
            text(job.get("phase"))
        );
    }
    if present(state.get("diagnostic")) {
        let _ = writeln!(out, "Diagnostic: {}", text(state.get("diagnostic")));
    }
    if let Some(options) = state.get("installation_options").and_then(Value::as_array) {
        let builtin: Vec<&Value> = options
            .iter()
            .filter(|option| {
                option.get("qualification").and_then(Value::as_str) == Some("guard_builtin")
            })
            .collect();
        for option in &builtin {
            let _ = writeln!(
                out,
                "  {}: Built into Guard · {} · {}",
                text(option.get("runtime_id")),
                text(option.get("platform")),
                text(option.get("qualification"))
            );
        }
        if builtin.is_empty() {
            out.push_str("The built-in engine is unavailable on this machine.\n");
        }
    }
    out.push_str(
        "CIGAR runs on the engine built into Guard; no Python or download is needed. \
         Choose preferences in Protection → Context assistance.\n",
    );
    out
}

/// A version request's answer, for `jobs`, `job`, `switch`, `commit`,
/// `cancel` and `recover`.
pub(super) fn versions(answer: &Value) -> String {
    let state = &answer["state"];
    let result = &answer["result"];
    let mut out = String::new();
    let _ = writeln!(
        out,
        "CIGAR: {} · generation {}",
        text(state.get("availability")),
        text(state.get("generation"))
    );
    let line = |job: &Value| {
        format!(
            "{}: {} · {} ({})",
            text(job.get("job_id")),
            text(job.get("operation")),
            text(job.get("phase")),
            text(job.get("code"))
        )
    };
    if result.get("job_id").is_some() {
        let _ = writeln!(out, "{}", line(result));
        if present(result.get("can_commit")) {
            if result.get("keeps_disabled") == Some(&Value::Bool(true))
                && result.get("reconnect_required") == Some(&Value::Bool(false))
            {
                out.push_str(
                    "Ready to select. CIGAR stays off; enable it separately when needed.\n",
                );
            } else {
                out.push_str(
                    "Ready to commit. Committing reconnects applications and requires fresh source grants.\n",
                );
            }
        } else if present(result.get("cleanup_pending")) {
            out.push_str(
                "Cleanup is still in progress; retry job inspection before another lifecycle operation.\n",
            );
        } else if present(result.get("recovery_available")) {
            out.push_str(
                "Explicit recovery is required; progress alone does not start a runtime.\n",
            );
        }
    } else if let Some(jobs) = result.get("jobs").and_then(Value::as_array) {
        for job in jobs {
            let _ = writeln!(out, "  {}", line(job));
        }
        if jobs.is_empty() {
            out.push_str("No setup jobs.\n");
        }
    } else {
        let pretty = serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string());
        let _ = writeln!(out, "{pretty}");
    }
    out
}
