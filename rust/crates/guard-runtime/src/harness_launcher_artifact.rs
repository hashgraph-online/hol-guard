//! `harness_diagnostics` op `launcher_artifact`: the artifact for the Guard
//! launcher shim a harness has installed, as `HarnessAdapter` builds it for a
//! diagnostics report.
//!
//! The request is `{"op": "launcher_artifact", "harness", "guard_home",
//! "names", "cwd"?}`. `names` is the harness's launcher name followed by its
//! legacy names. The candidates are `guard-<name>` and `guard-<name>.cmd`
//! under `<guard_home>/bin`, in name order, and the first one that runs Guard
//! is the shim. A relative `guard_home` anchors on `cwd`, which is the
//! caller's directory. The answer is `{"launcher_artifact": null}` when no
//! candidate is a shim, else `{"launcher_artifact": {artifact_id, name,
//! harness, artifact_type, source_scope, config_path, command, metadata}}`.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::harness_diagnostics::is_launcher_shim;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

type Fields = Map<String, Value>;

const SUFFIXES: [&str; 2] = ["", ".cmd"];
const KEYS: [&str; 5] = ["op", "harness", "guard_home", "names", "cwd"];

pub(crate) fn answer(fields: &Fields) -> KindResult {
    if fields.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err(ERR_INVALID);
    }
    let harness = text(fields, "harness")?;
    let guard_home = Path::new(text(fields, "guard_home")?);
    let cwd = match fields.get("cwd") {
        None | Some(Value::Null) => None,
        Some(Value::String(cwd)) => Some(Path::new(cwd.as_str())),
        Some(_) => return Err(ERR_INVALID),
    };
    let names = fields
        .get("names")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|name| name.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let shim_dir = guard_home.join("bin");
    for name in names {
        for suffix in SUFFIXES {
            let file = format!("guard-{name}{suffix}");
            let path = shim_dir.join(&file);
            if is_launcher_shim(&anchored(&path, cwd)?) {
                return Ok(
                    json!({ "launcher_artifact": artifact(harness, &file, &path, &shim_dir) }),
                );
            }
        }
    }
    Ok(json!({ "launcher_artifact": null }))
}

/// `Path.absolute()`: a relative path anchors on the caller's directory.
fn anchored(path: &Path, cwd: Option<&Path>) -> Result<PathBuf, &'static str> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    cwd.map(|cwd| cwd.join(path)).ok_or(ERR_INVALID)
}

fn artifact(harness: &str, file: &str, path: &Path, shim_dir: &Path) -> Value {
    let path = path.to_string_lossy();
    json!({
        "artifact_id": format!("{harness}:guard-launcher-shim"),
        "name": file,
        "harness": harness,
        "artifact_type": "guard_launcher_shim",
        "source_scope": "guard",
        "config_path": path,
        "command": path,
        "metadata": { "shim_dir": shim_dir.to_string_lossy() },
    })
}

fn text<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

#[cfg(test)]
#[path = "harness_launcher_artifact_tests.rs"]
mod tests;
