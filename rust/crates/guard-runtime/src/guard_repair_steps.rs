//! The `report` op's per-step builders: each turns what one repair step
//! returned into its status, summary and detail.

use serde_json::{Map, Value};

use super::*;

pub(super) fn daemon_step(object: &Map<String, Value>) -> Value {
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

pub(super) fn native_runtime_step(object: &Map<String, Value>, dry_run: bool) -> Value {
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

/// `step` with the durable-runtime collapse report attached. A failed or
/// skipped collapse never changes the step's status: the copies it would have
/// shared stay as they are and still launch.
pub(super) fn fold_collapse(mut step: Value, collapse: Option<&Value>) -> Value {
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

pub(super) fn native_install_step(object: &Map<String, Value>) -> Result<Value, String> {
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

pub(super) fn onefile_step(object: &Map<String, Value>, dry_run: bool) -> Result<Value, String> {
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

pub(super) fn hooks_step(object: &Map<String, Value>, dry_run: bool) -> Result<Value, String> {
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

pub(super) fn package_shims_step(object: &Map<String, Value>, dry_run: bool) -> Value {
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

pub(super) fn command_queue_step(object: &Map<String, Value>, dry_run: bool) -> Value {
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
