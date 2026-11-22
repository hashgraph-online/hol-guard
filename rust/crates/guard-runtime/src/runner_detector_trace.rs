//! `detector_debug_trace`: the opt-in runtime detector debug trace.
//!
//! When `runtime_detector_debug_trace` is on, `guard run` keeps one JSON file
//! per evaluated action under `<guard home>/debug/detectors/`. The trace holds
//! the action with every field whose name mentions a prompt replaced by
//! `[redacted]`, plus the detector signals and telemetry. Writing it never
//! changes the verdict: a failed write comes back as `trace_error`, named the
//! way Python's `OSError` subclasses are, and the caller attaches it to the
//! evaluation instead of failing the run.
//!
//! The file is created new and private (mode 0600 on Unix, never following a
//! symlink), named by the UTC time and a digest of the canonical action.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::runner_authority_op::{KindResult, ERR_INVALID};
use guard_contracts::RUNNER_AUTHORITY_MAX_BYTES;

const REDACTED: &str = "[redacted]";
const DIGEST_HEX_CHARS: usize = 12;

/// Write the trace for one action; `trace_error` is `null` once it is on disk.
pub(crate) fn detector_debug_trace(args: &Value) -> KindResult {
    let args = args.as_object().ok_or(ERR_INVALID)?;
    let guard_home = args
        .get("guard_home")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ERR_INVALID)?;
    let action = args
        .get("action")
        .filter(|value| value.is_object())
        .ok_or(ERR_INVALID)?;
    let signals = list(args, "signals")?;
    let telemetry = list(args, "telemetry")?;
    let created_at = Utc::now();
    let trace = trace_payload(created_at, action, signals, telemetry);
    let name = trace_file_name(created_at, action)?;
    let trace_error = match write_trace(&guard_home, &name, &trace) {
        Ok(()) => Value::Null,
        Err(error) => error,
    };
    Ok(json!({"trace_error": trace_error}))
}

fn list<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a Value, &'static str> {
    args.get(key)
        .filter(|value| value.is_array())
        .ok_or(ERR_INVALID)
}

/// The trace document, with its object keys in sorted order.
pub(super) fn trace_payload(
    created_at: DateTime<Utc>,
    action: &Value,
    signals: &Value,
    telemetry: &Value,
) -> Value {
    sorted(&json!({
        "schema_version": 1,
        "created_at": created_at.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string(),
        "action": redacted(action),
        "signals": signals,
        "telemetry": telemetry,
    }))
}

/// `<UTC stamp>-<first 12 hex of the canonical action digest>.json`.
pub(super) fn trace_file_name(
    created_at: DateTime<Utc>,
    action: &Value,
) -> Result<String, &'static str> {
    let mut canonical = Vec::with_capacity(1024);
    crate::context_digest_json::write_canonical_json_with_limit(
        action,
        &mut canonical,
        RUNNER_AUTHORITY_MAX_BYTES,
    )?;
    let digest = hex::encode(Sha256::digest(&canonical));
    Ok(format!(
        "{}-{}.json",
        created_at.format("%Y%m%dT%H%M%S%6fZ"),
        &digest[..DIGEST_HEX_CHARS]
    ))
}

/// Every object field whose name mentions `prompt`, at any depth, is replaced.
pub(super) fn redacted(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, item)| {
                    let item = if key.to_lowercase().contains("prompt") {
                        Value::String(REDACTED.to_owned())
                    } else {
                        redacted(item)
                    };
                    (key.clone(), item)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redacted).collect()),
        other => other.clone(),
    }
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&fields[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// Create `debug/detectors` one level at a time, then the trace file itself.
pub(super) fn write_trace(guard_home: &Path, name: &str, trace: &Value) -> Result<(), Value> {
    fs::create_dir_all(guard_home).map_err(|error| io_failure(&error))?;
    let debug = guard_home.join("debug");
    let directory = debug.join("detectors");
    for level in [&debug, &directory] {
        directory_level(level)?;
    }
    let mut text = serde_json::to_string_pretty(trace)
        .map_err(|error| json!({"error_type": "ValueError", "message": error.to_string()}))?;
    text.push('\n');
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(directory.join(name))
        .map_err(|error| io_failure(&error))?;
    file.write_all(text.as_bytes())
        .map_err(|error| io_failure(&error))
}

/// One directory level: an existing non-directory entry is `FileExistsError`,
/// as `Path.mkdir(exist_ok=True)` raised for it on every platform.
fn directory_level(path: &Path) -> Result<(), Value> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if path.is_dir() {
                Ok(())
            } else {
                Err(json!({"error_type": "FileExistsError", "message": error.to_string()}))
            }
        }
        Err(error) => Err(io_failure(&error)),
    }
}

/// An I/O failure named as the Python `OSError` subclass it corresponds to.
pub(super) fn io_failure(error: &io::Error) -> Value {
    json!({"error_type": os_error_name(error), "message": error.to_string()})
}

fn os_error_name(error: &io::Error) -> &'static str {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        match code {
            libc::ENOTDIR => return "NotADirectoryError",
            libc::EISDIR => return "IsADirectoryError",
            libc::ELOOP => return "OSError",
            _ => {}
        }
    }
    match error.kind() {
        io::ErrorKind::AlreadyExists => "FileExistsError",
        io::ErrorKind::NotFound => "FileNotFoundError",
        io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
    }
}

#[cfg(test)]
#[path = "runner_detector_trace_tests.rs"]
mod tests;
