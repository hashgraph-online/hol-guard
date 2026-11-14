//! `runner_authority` kind `command_probe`: run a harness CLI's `--help` or
//! `--version` for diagnostics, which `_run_command_probe` in
//! `guard/adapters/base.py` did before it moved here.
//!
//! The caller sends the argv, the working directory, the environment the CLI
//! runs with and a whole-second deadline. The resident's own environment is
//! never used: a bare program name is found on the `PATH` the caller sent.
//! The CLI gets no input, runs in its own process group and is stopped with
//! that group at the deadline or once it writes more than 1 MiB.
//!
//! The answer is the probe record the doctor reads: the argv, whether it
//! exited 0, its return code and its trimmed output. A program that is not
//! there answers "command not found"; one that ran out of time keeps what it
//! wrote and adds `timed_out`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use crate::hook_process_spawn::{run_isolated_hook_process, BoundedHookProcessResult};

const KEYS: [&str; 4] = ["command", "cwd", "env", "timeout_seconds"];
const OUTPUT_LIMIT: usize = 1024 * 1024;
const MAX_TIMEOUT_SECONDS: u64 = 60;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.len() != KEYS.len() || KEYS.iter().any(|key| !map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let command = strings(map.get("command"))?;
    if command.is_empty() || command[0].is_empty() {
        return Err(ERR_INVALID);
    }
    let cwd = map
        .get("cwd")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or(ERR_INVALID)?;
    let env = environment(map)?;
    let timeout = map
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .filter(|seconds| (1..=MAX_TIMEOUT_SECONDS).contains(seconds))
        .ok_or(ERR_INVALID)?;
    let Some(program) = located(&command[0], cwd, &env) else {
        return Ok(record(&command, None));
    };
    // Start the file the lookup found, so the platform cannot pick another.
    let mut argv = command.clone();
    argv[0] = program.to_string_lossy().into_owned();
    let result = run_isolated_hook_process(
        &argv,
        "",
        cwd,
        &env,
        // Whole seconds below 2^53 are exact as f64.
        #[allow(clippy::cast_precision_loss)]
        Some(timeout as f64),
        Some(OUTPUT_LIMIT),
        None,
        None,
    );
    Ok(record(&command, Some(&result)))
}

/// The file `program` names: a path (relative to `cwd`), or a bare name
/// found on the caller's `PATH` as the platform would look it up. The child
/// starts in `cwd`, so a relative `PATH` entry is read from there and an
/// empty one names `cwd` itself.
fn located(program: &str, cwd: &Path, env: &BTreeMap<String, String>) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        return candidates(&cwd.join(path))
            .into_iter()
            .find(|file| file.is_file());
    }
    std::env::split_paths(env.get("PATH")?).find_map(|directory| {
        candidates(&cwd.join(directory).join(program))
            .into_iter()
            .find(|file| file.is_file())
    })
}

/// The file itself, and on Windows the extensions `CreateProcess` tries.
fn candidates(path: &Path) -> Vec<PathBuf> {
    let mut files = vec![path.to_path_buf()];
    if cfg!(windows) && path.extension().is_none() {
        files.extend(["exe", "com", "cmd", "bat"].map(|extension| path.with_extension(extension)));
    }
    files
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, &'static str> {
    value
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|part| part.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

fn environment(map: &Map<String, Value>) -> Result<BTreeMap<String, String>, &'static str> {
    let mut env = BTreeMap::new();
    for (key, value) in map
        .get("env")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
    {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(ERR_INVALID);
        }
        let value = value.as_str().filter(|text| !text.contains('\0'));
        env.insert(key.clone(), value.ok_or(ERR_INVALID)?.to_owned());
    }
    Ok(env)
}

/// The probe record `_run_command_probe` answered; `None` when the program
/// could not be found.
fn record(command: &[String], result: Option<&BoundedHookProcessResult>) -> Value {
    let Some(result) = result else {
        return json!({
            "command": command,
            "ok": false,
            "return_code": null,
            "stdout": "",
            "stderr": "command not found",
        });
    };
    let stdout = result.stdout.trim();
    let stderr = result.stderr.trim();
    if result.timed_out {
        return json!({
            "command": command,
            "ok": false,
            "return_code": null,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": true,
        });
    }
    let Some(code) = result.returncode else {
        // No exit status: a signal ended it, it could not start, or its
        // group could not be contained, and nothing it wrote is trusted.
        let stderr = if result.containment_failed {
            "probe capture incomplete"
        } else {
            "command did not exit normally"
        };
        return json!({
            "command": command,
            "ok": false,
            "return_code": null,
            "stdout": "",
            "stderr": stderr,
        });
    };
    let mut record = json!({
        "command": command,
        "ok": code == 0 && !result.output_limit_exceeded,
        "return_code": code,
        "stdout": stdout,
        "stderr": stderr,
    });
    if result.output_limit_exceeded {
        record["output_limit_exceeded"] = json!(true);
    }
    record
}

#[cfg(test)]
#[path = "command_probe_tests.rs"]
mod tests;
