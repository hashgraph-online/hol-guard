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
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

const LOG_DIRECTORY: &str = "logs";
const FAILURE_LOG: &str = "runtime-failures.jsonl";
const ROTATED_FAILURE_LOG: &str = "runtime-failures.jsonl.1";
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
    if !guard_home.is_dir() || is_symlink(guard_home) {
        return None;
    }
    let directory = guard_home.join(LOG_DIRECTORY);
    if is_symlink(&directory) {
        return None;
    }
    if !directory.exists() {
        create_private_directory(&directory)?;
    }
    if !directory.is_dir() {
        return None;
    }
    let path = directory.join(FAILURE_LOG);
    if is_symlink(&path) {
        return None;
    }
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_FAILURE_LOG_BYTES) {
        let rotated = directory.join(ROTATED_FAILURE_LOG);
        if is_symlink(&rotated) {
            return None;
        }
        fs::rename(&path, &rotated).ok()?;
    }
    let mut line = failure_record(code, kind, location, arguments)?.to_string();
    line.push('\n');
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).ok()?;
    // One write per record, so concurrent failing launches do not interleave.
    file.write_all(line.as_bytes()).ok()
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
    record.insert("subcommand".into(), subcommand(arguments).into());
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

fn subcommand(arguments: &[String]) -> String {
    match arguments.first() {
        None => "hook".to_owned(),
        Some(first) if first.starts_with('-') => "hook".to_owned(),
        Some(first) => safe_label(first),
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

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> Option<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory) {
        Ok(()) => Some(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Some(()),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn create_private_directory(directory: &Path) -> Option<()> {
    match fs::create_dir(directory) {
        Ok(()) => Some(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Some(()),
        Err(_) => None,
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

#[cfg(test)]
#[path = "runtime_output_tests.rs"]
mod tests;
