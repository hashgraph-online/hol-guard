//! Process output that cannot take the runtime down.
//!
//! `eprintln!` and `println!` panic when the write fails. A runtime launched
//! by a caller that has already gone (a hook whose agent moved on, a launcher
//! that hit its own timeout) has a stdout and stderr with no reader, so the
//! first diagnostic line panicked, the panic hook's own `eprintln!` panicked
//! again, and the process died with SIGABRT, taking the error code with it.
//! Writes here ignore failure, and a failed launch also leaves one bounded,
//! private line in `<guard home>/logs/runtime-failures.jsonl` so its code
//! survives a missing reader.

use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::runtime_output_directory::LogDirectory;

const LOG_DIRECTORY: &str = "logs";
const FAILURE_LOG: &str = "runtime-failures.jsonl";
const ROTATED_FAILURE_LOG: &str = "runtime-failures.jsonl.1";
const ROTATION_LOCK: &str = "runtime-failures.lock";
const ROTATION_LOCK_WAIT: Duration = Duration::from_millis(200);
const MAX_FAILURE_LOG_BYTES: u64 = 256 * 1024;
const MAX_LABEL_BYTES: usize = 96;
const RUNTIME_DIRECTORY: &str = "native-runtime";

/// Writes one line to stderr; a closed or broken stderr is ignored.
pub(crate) fn stderr_line(arguments: fmt::Arguments<'_>) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_fmt(arguments);
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

/// Writes one line to stdout; a closed or broken stdout is ignored.
pub(crate) fn stdout_line(arguments: fmt::Arguments<'_>) {
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_fmt(arguments);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

/// The panic hook for the runtime binary. It reports the panic without being
/// able to panic itself, so a panic never turns into an abort.
pub(crate) fn panic_hook(info: &std::panic::PanicHookInfo<'_>) {
    stderr_line(format_args!("native_runtime_panicked"));
    let location = info
        .location()
        .map(|location| panic_location(location.file(), location.line()));
    record_failure(
        "native_runtime_panicked",
        "panic",
        location.as_deref(),
        &launch_arguments(),
    );
}

/// Reports a failed launch: its code on stderr and one record on disk.
pub(crate) fn report_launch_failure(code: &str) {
    stderr_line(format_args!("{code}"));
    record_failure(code, "error", None, &launch_arguments());
}

fn launch_arguments() -> Vec<String> {
    std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

/// Appends one failure record; every failure to do so is ignored.
pub(crate) fn record_failure(code: &str, kind: &str, location: Option<&str>, arguments: &[String]) {
    let Some(guard_home) = failure_guard_home(arguments) else {
        return;
    };
    let _ = append_failure(&guard_home, code, kind, location, arguments);
}

fn append_failure(
    guard_home: &Path,
    code: &str,
    kind: &str,
    location: Option<&str>,
    arguments: &[String],
) -> Option<()> {
    let mut line = failure_record(code, kind, location, arguments)?.to_string();
    line.push('\n');
    let directory = LogDirectory::open(guard_home, LOG_DIRECTORY)?;
    // Only the holder of the rotation lock may move a full log aside; a
    // second launch that also saw it full would otherwise move the fresh log
    // over the one just kept. A launch that cannot get the lock in time
    // appends without rotating, so its record is never dropped.
    let rotation_lock = rotation_lock(&directory);
    if rotation_lock.is_some()
        && directory
            .file_len(FAILURE_LOG)
            .is_some_and(|length| length >= MAX_FAILURE_LOG_BYTES)
    {
        directory.rename(FAILURE_LOG, ROTATED_FAILURE_LOG)?;
    }
    let mut file = directory.open_file(FAILURE_LOG, true)?;
    // One write per record, so concurrent failing launches do not interleave.
    let written = file.write_all(line.as_bytes()).ok();
    drop(rotation_lock);
    written
}

/// The rotation lock, held until the returned file is dropped. The wait is
/// bounded so that reporting a failure never holds up the exit it reports.
fn rotation_lock(directory: &LogDirectory) -> Option<File> {
    let lock = directory.open_file(ROTATION_LOCK, false)?;
    let deadline = Instant::now() + ROTATION_LOCK_WAIT;
    loop {
        match lock.try_lock() {
            Ok(()) => return Some(lock),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return None,
        }
    }
}

/// The record holds labels only. Arguments and messages are left out: hook
/// arguments and error text can carry the user's paths and data.
pub(crate) fn failure_record(
    code: &str,
    kind: &str,
    location: Option<&str>,
    arguments: &[String],
) -> Option<Value> {
    let recorded_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let mut record = Map::new();
    record.insert("code".into(), safe_label(code).into());
    record.insert("kind".into(), safe_label(kind).into());
    if let Some(location) = location {
        record.insert("location".into(), safe_label(location).into());
    }
    record.insert("pid".into(), std::process::id().into());
    if let Some(parent) = parent_pid() {
        record.insert("parent_pid".into(), parent.into());
    }
    record.insert(
        "recorded_at_ns".into(),
        Value::from(u64::try_from(recorded_at_ns).ok()?),
    );
    record.insert("subcommand".into(), Value::from(subcommand(arguments)));
    record.insert("version".into(), 1.into());
    Some(Value::Object(record))
}

/// The leading run of label characters, so an error such as
/// `native_x_failed: /some/path` keeps its code and drops the path.
pub(crate) fn safe_label(value: &str) -> String {
    let label: String = value
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
        })
        .take(MAX_LABEL_BYTES)
        .collect();
    if label.is_empty() {
        "unlabelled".to_owned()
    } else {
        label
    }
}

/// The runtime's own subcommand names. A first argument that is not one of
/// them is recorded as `other`, so a stray argument never reaches the log.
pub(crate) const KNOWN_SUBCOMMANDS: &[&str] = &[
    "archive-inspect",
    "bounded-hook-bridge",
    "browser-explain",
    "capabilities",
    "claude-hook-bridge",
    "cline-hook-worker",
    "cloud-action",
    "codex-hook-bridge",
    "codex-sandbox-check",
    "command-model",
    "compile-business-policy",
    "contained-readonly-windows",
    "contained-workspace-launch",
    "contained-workspace-sink",
    "content-decode",
    "context-digest",
    "cursor-hook-bridge",
    "daemon-serve",
    "enroll-approval-authority",
    "enroll-approval-v4-authority",
    "enroll-workspace-review-authority",
    "hook",
    "hook-client",
    "mcp-config-assess",
    "mcp-relay",
    "migrate-policy",
    "native-bash-execute-client",
    "native-bash-host-context",
    "pack-lifecycle",
    "pi-hook-bridge",
    "plugin-kit",
    "plugin-telemetry",
    "pre-tool",
    "prepare-approval-enrollment",
    "prepare-approval-v4-enrollment",
    "provider-conformance",
    "provision-verifier-key",
    "resident-client",
    "resident-client-stream",
    "resident-health",
    "resident-prewarm",
    "resident-reset-restart-budget",
    "resident-stop",
    "restricted-linux-launch",
    "rule-contract",
    "runtime-identity-assess",
    "runtime-identity-probe",
    "secrets-cli",
    "self-test",
    "serve",
    "serve-managed",
    "supervise-managed",
    "workspace-export-preview",
    "workspace-fix",
    "workspace-review-decision",
    "workspace-snapshot",
];

pub(crate) fn subcommand(arguments: &[String]) -> &'static str {
    match arguments.first() {
        None => "hook",
        Some(first) if first.starts_with('-') => "hook",
        Some(first) => KNOWN_SUBCOMMANDS
            .iter()
            .find(|known| **known == first.as_str())
            .copied()
            .unwrap_or("other"),
    }
}

/// `src/daemon_edge_serve.rs:12` from a build path, without the directories.
fn panic_location(file: &str, line: u32) -> String {
    let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
    format!("{name}:{line}")
}

/// The Guard home a failure belongs to: `--guard-home` on the command line,
/// then `HOL_GUARD_HOME`, then the home this binary is installed in
/// (`<home>/native-runtime/<digest>/hol-guard-runtime`). A runtime with none
/// of these, such as a test build, records nothing.
pub(crate) fn failure_guard_home(arguments: &[String]) -> Option<PathBuf> {
    if let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--guard-home")
    {
        return arguments
            .get(index + 1)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
    }
    if let Some(value) = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--guard-home="))
    {
        return (!value.is_empty()).then(|| PathBuf::from(value));
    }
    if let Some(value) = std::env::var_os("HOL_GUARD_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(value));
    }
    installed_guard_home(&std::env::current_exe().ok()?)
}

pub(crate) fn installed_guard_home(executable: &Path) -> Option<PathBuf> {
    let digest_directory = executable.parent()?;
    let runtime_directory = digest_directory.parent()?;
    if runtime_directory.file_name()? != RUNTIME_DIRECTORY {
        return None;
    }
    runtime_directory.parent().map(Path::to_path_buf)
}

#[cfg(unix)]
fn parent_pid() -> Option<u32> {
    Some(std::os::unix::process::parent_id())
}

#[cfg(not(unix))]
fn parent_pid() -> Option<u32> {
    None
}

#[cfg(test)]
#[path = "runtime_output_tests.rs"]
mod tests;
