//! `detected_harnesses`: the harnesses an install or uninstall of `--all`
//! targets, as `_resolve_targets` read them from `detect_all`.
//!
//! Every harness is detected by its own `detect` op, then extended with the
//! shared workspace AIBOM artifacts when its spec asks for it. A harness counts
//! as detected when it is installed, its command is available, or it found
//! config paths or artifacts. The caller's process supplies only the Codex
//! facts its `detect` takes (`facts.codex`, `transition`); the workspace skills
//! are walked here on every platform.

use serde_json::{json, Map, Value};

use crate::harness_adapter::describe::SPECS;
use crate::harness_adapter::detect_merged::plan;
use crate::harness_adapter::{route, Ctx, Step};

/// What one harness's detection found, as `HarnessDetection` counts it.
fn found(answer: &Value, extra: &Value) -> bool {
    let flag = |key: &str| answer.get(key).and_then(Value::as_bool) == Some(true);
    let count = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, std::vec::Vec::len)
    };
    flag("installed")
        || flag("command_available")
        || count(answer, "config_paths") > 0
        || count(answer, "artifacts") > 0
        || count(extra, "found_paths") > 0
        || count(extra, "appended") > 0
}

/// The sorted harness names that were detected, or the first detection's
/// failure (a Codex whose hook files are not trusted answers `untrusted`).
pub(super) fn run(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut detected: Vec<&str> = Vec::new();
    for spec in &SPECS {
        let answer = route(spec, "detect", ctx, fields)?;
        if answer.get("untrusted").is_some() {
            return Ok(answer);
        }
        let extra = plan(ctx, spec.harness, &answer)?;
        if found(&answer, &extra) {
            detected.push(spec.harness);
        }
    }
    detected.sort_unstable();
    Ok(json!({ "harnesses": detected }))
}
