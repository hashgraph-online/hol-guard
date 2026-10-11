//! Single-process launch, deadline enforcement and bounded output capture.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

use super::common::sha256_hex;
use super::contract::Backend;

const OUTPUT_LIMIT: usize = 64 * 1024;
const STATUS_LIMIT: usize = 8192;

/// Serialises the short window in which a status descriptor is inheritable so
/// no unrelated concurrent launch can capture it.
static INHERIT_WINDOW: Mutex<()> = Mutex::new(());

pub(super) struct ProcessOutcome {
    pub(super) exit_code: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) timed_out: bool,
    pub(super) execution_completed: bool,
}

fn kill_process_group(process_group: u32) {
    let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
}

fn exit_code_of(status: std::process::ExitStatus) -> Option<i32> {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Result<Option<i32>, String> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(exit_code_of(status));
        }
        if started.elapsed() >= timeout {
            return Err("timeout".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn create_status_file(temp_root: &Path) -> Result<File, String> {
    let path = temp_root
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .join(format!(
            "guard-status-{}-{}",
            std::process::id(),
            sha256_hex(temp_root.to_string_lossy().as_bytes())
        ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| error.to_string())?;
    fs::remove_file(&path).map_err(|error| error.to_string())?;
    Ok(file)
}

pub(super) fn run_process(
    argv: &[String],
    cwd: &str,
    environment: &BTreeMap<String, String>,
    timeout_seconds: f64,
    temp_root: &Path,
    backend: Backend,
) -> Result<ProcessOutcome, String> {
    let stdout_path = temp_root.join("stdout");
    let stderr_path = temp_root.join("stderr");
    let create = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| error.to_string())
    };
    let stdout_file = create(&stdout_path)?;
    let stderr_file = create(&stderr_path)?;
    let is_bwrap = backend == Backend::LinuxBwrap;
    let mut status_file = if is_bwrap {
        Some(create_status_file(temp_root)?)
    } else {
        None
    };
    let mut command;
    if let Some(status) = &status_file {
        command = Command::new(&argv[0]);
        command.arg("--json-status-fd");
        command.arg(status.as_raw_fd().to_string());
        command.args(&argv[1..]);
    } else {
        command = Command::new(&argv[0]);
        command.args(&argv[1..]);
    }
    command
        .current_dir(cwd)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .process_group(0);
    let mut child = {
        let _window = INHERIT_WINDOW
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(status) = &status_file {
            fcntl(status, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|error| error.to_string())?;
        }
        let spawned = command.spawn();
        if let Some(status) = &status_file {
            let _ = fcntl(status, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
        }
        spawned.map_err(|error| error.to_string())?
    };
    let group = child.id();
    let (exit_code, timed_out) =
        match wait_with_deadline(&mut child, Duration::from_secs_f64(timeout_seconds)) {
            Ok(code) => {
                kill_process_group(group);
                (code, false)
            }
            Err(message) if message == "timeout" => {
                kill_process_group(group);
                let _ = child.kill();
                let _ = wait_with_deadline(&mut child, Duration::from_secs(5));
                (None, true)
            }
            Err(message) => {
                kill_process_group(group);
                return Err(message);
            }
        };
    let execution_completed = match status_file.as_mut() {
        Some(status) => bwrap_execution_completed(status, exit_code),
        None => true,
    };
    Ok(ProcessOutcome {
        exit_code,
        stdout: read_bounded(&stdout_path)?,
        stderr: read_bounded(&stderr_path)?,
        timed_out,
        execution_completed,
    })
}

pub(super) fn bounded_text(value: &str) -> String {
    value.chars().take(OUTPUT_LIMIT).collect()
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut payload = Vec::new();
    file.take(OUTPUT_LIMIT as u64)
        .read_to_end(&mut payload)
        .map_err(|error| error.to_string())?;
    Ok(String::from_utf8_lossy(&payload).into_owned())
}

/// `bwrap_execution_completed`: require the exec-success report, not merely a
/// forked sandbox process.
pub(crate) fn bwrap_execution_completed(stream: &mut File, exit_code: Option<i32>) -> bool {
    let Some(exit_code) = exit_code.filter(|code| (0..=255).contains(code)) else {
        return false;
    };
    if stream.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut payload = Vec::new();
    if stream
        .take(STATUS_LIMIT as u64 + 1)
        .read_to_end(&mut payload)
        .is_err()
    {
        return false;
    }
    status_report_confirms(&payload, exit_code)
}

pub(crate) fn status_report_confirms(payload: &[u8], exit_code: i32) -> bool {
    if payload.len() > STATUS_LIMIT {
        return false;
    }
    let mut child_seen = false;
    let mut exit_seen = false;
    for line in split_lines(payload) {
        let Ok(serde_json::Value::Object(record)) =
            serde_json::from_slice::<serde_json::Value>(line)
        else {
            return false;
        };
        if let Some(pid) = record.get("child-pid") {
            let valid = pid.as_i64().is_some_and(|pid| pid > 0);
            if child_seen || exit_seen || !valid {
                return false;
            }
            child_seen = true;
        }
        if let Some(status) = record.get("exit-code") {
            let valid = status
                .as_i64()
                .is_some_and(|status| status == i64::from(exit_code));
            if !child_seen || exit_seen || !valid {
                return false;
            }
            exit_seen = true;
        }
    }
    child_seen && exit_seen
}

/// `bytes.splitlines()`: split on `\n`, `\r` and `\r\n`, dropping the terminator.
fn split_lines(payload: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < payload.len() {
        match payload[index] {
            b'\n' => {
                lines.push(&payload[start..index]);
                index += 1;
                start = index;
            }
            b'\r' => {
                lines.push(&payload[start..index]);
                index += if payload.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = index;
            }
            _ => index += 1,
        }
    }
    if start < payload.len() {
        lines.push(&payload[start..]);
    }
    lines
}
