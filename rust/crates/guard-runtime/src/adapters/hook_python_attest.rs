//! The `hook_python_identity` `attest` op: run the interpreter already running
//! Guard with site initialization off and accept it only when its own report
//! of what it imports matches the record derived from the parent's facts,
//! which `_attest_python` in `guard/adapters/hook_python.py` did before it
//! moved here.
//!
//! The parent sends where its package and distributions live (`facts`, see
//! `hook_python_expect.rs`), the neutral directory to run in (`probe`) and the
//! few environment values the probe may inherit. The probe runs with no
//! input, a 15 s deadline and 64 KiB of output, and the interpreter is read
//! again afterwards: one that changed while it ran is answered as changed
//! rather than bound to an identity it may no longer have. The answer carries
//! the record the probe confirmed.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::expect::{expectation, probe_dir, Facts};
use super::{identity, CHANGED};
use crate::daemon_lifecycle_text::py_splitlines;
use crate::hook_process_spawn::{run_isolated_hook_process, BoundedHookProcessResult};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 5] = ["op", "python", "inherited", "probe", "facts"];
/// The only caller environment the probe sees.
const INHERITED: [&str; 7] = [
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
];
const SCHEMA: u64 = 2;
const TIMEOUT_SECONDS: f64 = 15.0;
const OUTPUT_LIMIT: usize = 64 * 1024;

const TIMEOUT: &str = "guard_hook_python_probe_timeout";
const OUTPUT_LIMIT_EXCEEDED: &str = "guard_hook_python_probe_output_limit";
const CAPTURE_INCOMPLETE: &str = "guard_hook_python_probe_capture_incomplete";
const REJECTED: &str = "guard_hook_python_probe_rejected";
const OUTPUT_INVALID: &str = "guard_hook_python_probe_output_invalid";
const MISMATCH: &str = "guard_hook_python_probe_identity_mismatch";

/// Imports what the parent derived, from those roots only, and reports where
/// each module and distribution resolved.
const PROBE: &str = r#"
import importlib
import importlib.metadata
import json
import pathlib
import sys

expected = json.loads(sys.argv[1])
import_roots = expected["import_roots"]
for root in reversed(import_roots):
    sys.path.insert(0, root)

package = importlib.import_module("codex_plugin_scanner")
crypto = importlib.import_module("cryptography")
cli = importlib.import_module("codex_plugin_scanner.cli")
version_module = importlib.import_module("codex_plugin_scanner.version")

package_file = pathlib.Path(package.__file__).resolve(strict=True)
package_root = package_file.parent.parent
crypto_file = pathlib.Path(crypto.__file__).resolve(strict=True)
crypto_distribution = importlib.metadata.distribution("cryptography")
crypto_distribution_root = pathlib.Path(crypto_distribution.locate_file("")).resolve(strict=True)

try:
    hol_distribution = importlib.metadata.distribution("hol-guard")
except importlib.metadata.PackageNotFoundError:
    hol_distribution = None

if hol_distribution is None:
    hol_distribution_root = None
    entry_point = "codex_plugin_scanner.cli:main" if callable(getattr(cli, "main", None)) else ""
else:
    hol_distribution_root = pathlib.Path(hol_distribution.locate_file("")).resolve(strict=True)
    entry_points = {
        item.name: item.value
        for item in hol_distribution.entry_points
        if item.group == "console_scripts"
    }
    entry_point = entry_points.get("hol-guard", "")

payload = {
    "schema": 2,
    "resolved_executable": str(pathlib.Path(sys.executable).resolve(strict=True)),
    "package_file": str(package_file),
    "package_root": str(package_root),
    "cryptography_file": str(crypto_file),
    "import_roots": import_roots,
    "hol_distribution_root": str(hol_distribution_root) if hol_distribution_root is not None else None,
    "cryptography_distribution_root": str(crypto_distribution_root),
    "version": str(version_module.__version__),
    "entry_point": entry_point,
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
"#;

pub(super) fn attest(map: &Map<String, Value>) -> KindResult {
    if map.len() != KEYS.len() || KEYS.iter().any(|key| !map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let python = map
        .get("python")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or(ERR_INVALID)?;
    let mut inherited = BTreeMap::new();
    for (key, value) in map
        .get("inherited")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
    {
        let value = value.as_str().ok_or(ERR_INVALID)?;
        if !INHERITED.contains(&key.as_str()) {
            return Err(ERR_INVALID);
        }
        inherited.insert(key.clone(), value.to_owned());
    }
    let facts = Facts::parse(map.get("facts"))?;
    let probe = probe_dir(map.get("probe"))?;
    let answer = probe.and_then(|cwd| {
        let expected = expectation(&facts)?;
        let identity = run(python, &cwd, inherited, &expected)?;
        Ok(json!({ "identity": identity, "expected": expected }))
    });
    Ok(answer.unwrap_or_else(|error| json!({ "error": error })))
}

fn run(
    python: &Path,
    cwd: &Path,
    inherited: BTreeMap<String, String>,
    expected: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let before = identity(python)?;
    let target = before["target_path"].as_str().ok_or(CHANGED)?.to_owned();
    let mut record = expected.clone();
    record.insert("schema".into(), json!(SCHEMA));
    record.insert("resolved_executable".into(), json!(target));
    let record = Value::Object(record);
    let command: Vec<String> = [target.as_str(), "-I", "-S", "-s", "-c", PROBE]
        .iter()
        .map(|part| (*part).to_owned())
        .chain([record.to_string()])
        .collect();
    let result = run_isolated_hook_process(
        &command,
        "",
        cwd,
        &environment(inherited, cwd),
        Some(TIMEOUT_SECONDS),
        Some(OUTPUT_LIMIT),
        None,
        None,
    );
    settled(&result)?;
    if identity(python).ok().as_ref() != Some(&before) {
        return Err(CHANGED);
    }
    answered(&result.stdout, &record)?;
    Ok(before)
}

/// The inherited values, then a home in the neutral directory and the
/// switches that keep user site packages and the working directory off the
/// import path.
fn environment(mut inherited: BTreeMap<String, String>, cwd: &Path) -> BTreeMap<String, String> {
    let home = cwd.to_string_lossy().into_owned();
    for (key, value) in [
        ("HOME", home.as_str()),
        ("USERPROFILE", home.as_str()),
        ("PYTHONIOENCODING", "utf-8"),
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONSAFEPATH", "1"),
    ] {
        inherited.insert(key.to_owned(), value.to_owned());
    }
    inherited
}

/// How the probe ended, before anything it wrote is read.
fn settled(result: &BoundedHookProcessResult) -> Result<(), &'static str> {
    if result.timed_out {
        Err(TIMEOUT)
    } else if result.output_limit_exceeded {
        Err(OUTPUT_LIMIT_EXCEEDED)
    } else if result.containment_failed {
        Err(CAPTURE_INCOMPLETE)
    } else if result.returncode != Some(0) {
        Err(REJECTED)
    } else {
        Ok(())
    }
}

/// One line of JSON equal to the record, and nothing else.
fn answered(stdout: &str, record: &Value) -> Result<(), &'static str> {
    if stdout.contains(char::REPLACEMENT_CHARACTER) {
        return Err(OUTPUT_INVALID);
    }
    let [line] = py_splitlines(stdout)[..] else {
        return Err(OUTPUT_INVALID);
    };
    if line.is_empty() {
        return Err(OUTPUT_INVALID);
    }
    let payload: Value = serde_json::from_str(line).map_err(|_| OUTPUT_INVALID)?;
    if &payload != record {
        return Err(MISMATCH);
    }
    Ok(())
}

#[cfg(test)]
#[path = "hook_python_attest_tests.rs"]
mod tests;
