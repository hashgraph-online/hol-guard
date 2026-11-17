//! `harness_diagnostics` op `diagnostics`: the whole report `hol-guard doctor`
//! prints for one harness, built from what the adapter detected.
//!
//! The request is `{"op": "diagnostics", "harness", "executable",
//! "command_absence_proves_uninstalled", "guard_home", "names", "warnings",
//! "runtime_probe", "detection"}`.
//!
//! - `detection` is `{"installed", "command_available", "config_paths",
//!   "artifacts", "warnings"}`. Each artifact is `{"artifact_type",
//!   "command", "args", "harness", "serialized"}`, where `serialized` is the
//!   artifact as the report shows it (the adapter's own redaction applies
//!   there). Every list crosses as chunks that join back in order, the
//!   shown artifact's `args` too.
//! - `guard_home` and `names` find the Guard launcher shim the harness has
//!   installed (`launcher_artifact`). A shim counts as a detected, Guard
//!   managed artifact and marks the harness installed.
//! - `warnings` is `null` for the warnings Guard words from the detection, or
//!   the final list a harness words itself.
//! - `runtime_probe` is `null` when the adapter ran no probe, else the
//!   adapter's own report, which the answer returns as it came.
//!
//! The answer is `{"diagnostics": {harness, installed, setup_status,
//! command_available, config_paths, artifacts, runtime_probe, warnings}}`.

use serde_json::{json, Map, Value};

use crate::harness_diagnostics::{
    added_warnings, artifacts, chunked, expect_keys, flag, setup_status, strings, text, Adapter,
    Artifact, Detection, Probe,
};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

type Fields = Map<String, Value>;

const KEYS: [&str; 9] = [
    "op",
    "harness",
    "executable",
    "command_absence_proves_uninstalled",
    "guard_home",
    "names",
    "warnings",
    "runtime_probe",
    "detection",
];
const DETECTION_KEYS: [&str; 5] = [
    "installed",
    "command_available",
    "config_paths",
    "artifacts",
    "warnings",
];

pub(crate) fn answer(fields: &Fields) -> KindResult {
    expect_keys(fields, &KEYS)?;
    let adapter = Adapter {
        harness: text(fields, "harness")?,
        executable: text(fields, "executable")?,
        command_absence_proves_uninstalled: flag(fields, "command_absence_proves_uninstalled")?,
    };
    let probe = Probe::parse(fields.get("runtime_probe"))?;
    let found = fields
        .get("detection")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    expect_keys(found, &DETECTION_KEYS)?;
    let launcher = launcher(fields)?;
    let view = launcher.as_ref().map(launcher_view);
    let mut detection = Detection {
        config_paths: strings(found.get("config_paths"))?,
        command_available: flag(found, "command_available")?,
        artifacts: artifacts(found.get("artifacts"))?,
    };
    let mut shown: Vec<Value> = Vec::new();
    for item in chunked(found.get("artifacts"))? {
        shown.push(joined_args(item.get("serialized").ok_or(ERR_INVALID)?)?);
    }
    let mut installed = flag(found, "installed")?;
    if let (Some(launcher), Some(view)) = (&launcher, &view) {
        detection.artifacts.push(Artifact::parse(view)?);
        shown.push(serialized_launcher(launcher));
        installed = true;
    }
    let warnings: Vec<String> = match fields.get("warnings").ok_or(ERR_INVALID)? {
        Value::Null => strings(found.get("warnings"))?
            .into_iter()
            .map(str::to_owned)
            .chain(added_warnings(&detection, &adapter, probe))
            .collect(),
        listed => strings(Some(listed))?
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
    let status = setup_status(
        &detection,
        &warnings.iter().map(String::as_str).collect::<Vec<_>>(),
        adapter.command_absence_proves_uninstalled,
    );
    Ok(json!({
        "diagnostics": {
            "harness": adapter.harness,
            "installed": installed,
            "setup_status": status,
            "command_available": detection.command_available,
            "config_paths": detection.config_paths,
            "artifacts": shown,
            "runtime_probe": fields.get("runtime_probe"),
            "warnings": warnings,
        }
    }))
}

/// The Guard launcher shim the harness has installed, as the
/// `launcher_artifact` op describes it.
fn launcher(fields: &Fields) -> Result<Option<Value>, &'static str> {
    let mut request = Fields::new();
    request.insert("op".to_owned(), json!("launcher_artifact"));
    for key in ["harness", "guard_home", "names"] {
        request.insert(key.to_owned(), fields.get(key).cloned().ok_or(ERR_INVALID)?);
    }
    let mut answer = crate::harness_launcher_artifact::answer(&request)?;
    Ok(answer
        .get_mut("launcher_artifact")
        .map(Value::take)
        .filter(Value::is_object))
}

/// The launcher in the shape the detection reads an artifact.
fn launcher_view(launcher: &Value) -> Value {
    json!({
        "artifact_type": launcher["artifact_type"],
        "command": launcher["command"],
        "args": [[]],
        "harness": launcher["harness"],
    })
}

/// The launcher as the report shows an artifact: no arguments, no URL, and
/// the shim directory as its only metadata.
fn serialized_launcher(launcher: &Value) -> Value {
    json!({
        "artifact_id": launcher["artifact_id"],
        "name": launcher["name"],
        "harness": launcher["harness"],
        "artifact_type": launcher["artifact_type"],
        "source_scope": launcher["source_scope"],
        "config_path": launcher["config_path"],
        "command": launcher["command"],
        "args": [],
        "url": null,
        "transport": null,
        "publisher": null,
        "metadata": launcher["metadata"],
    })
}

#[cfg(test)]
#[path = "harness_diagnostics_report_tests.rs"]
mod tests;

/// The shown artifact with its chunked `args` joined back into one list.
fn joined_args(serialized: &Value) -> Result<Value, &'static str> {
    let mut shown = serialized.as_object().ok_or(ERR_INVALID)?.clone();
    if let Some(args) = shown.get("args") {
        let joined: Vec<Value> = chunked(Some(args))?.into_iter().cloned().collect();
        shown.insert("args".to_owned(), Value::Array(joined));
    }
    Ok(Value::Object(shown))
}
