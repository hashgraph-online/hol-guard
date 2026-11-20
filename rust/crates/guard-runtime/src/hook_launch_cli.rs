//! `hook-launch --stdin`: the one-shot entry Python calls instead of spawning
//! an isolated hook process itself (the retired Python
//! `codex_hook_launch_runtime.py` spawn kernel, `codex_hook_process_runtime.py`
//! and the `codex_hook_windows_job.py` ctypes Job Object code).
//!
//! The request is one JSON line on stdin, tagged by `op`:
//!
//! - `launch` runs `command` through `hook_process_spawn`: its own process
//!   group on unix, a Job Object on Windows, a bounded combined output, a
//!   deadline and the quarantine retry. The caller keeps stdin open for the
//!   whole run; its end of stdin closing is the stop signal, so a caller that
//!   is cancelled or dies leaves no child running.
//! - `guard_cli_command`, `daemon_start_command` build the isolated fallback
//!   commands, `hook_environment` keeps the allowlisted part of an environment, `private_runtime_cwd` validates a manifest directory and
//!   `system_executable` names a Windows System32 program.
//!
//! The answer is one JSON object on stdout; a failure is `{"error": "..."}`.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::hook_process_spawn::{
    isolated_daemon_start_command, isolated_guard_cli_command, isolated_hook_environment,
    private_hook_runtime_cwd, quarantined_pids, run_isolated_hook_process_extended,
    settle_quarantine, LaunchExtras,
};

pub(crate) const COMMAND: &str = "hook-launch";
/// Input text rides in the request, so the request may be large.
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// How long a failed containment is retried before the launcher exits.
const QUARANTINE_SETTLE_WINDOW: Duration = Duration::from_millis(1500);

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Launch {
        command: Vec<String>,
        #[serde(default)]
        input_text: String,
        cwd: String,
        environment: BTreeMap<String, String>,
        // Whole milliseconds: the workspace parses JSON with arbitrary-precision
        // numbers, which an internally tagged enum cannot read as a float.
        timeout_millis: u64,
        output_limit: Option<usize>,
        /// Also answer the exact bytes each stream wrote, as hex.
        #[serde(default)]
        raw_output: bool,
        #[serde(default)]
        parent_liveness: bool,
        #[serde(default)]
        allow_breakaway: bool,
        #[serde(default = "default_true")]
        kill_on_close: bool,
        job_memory_limit_bytes: Option<usize>,
        active_process_limit: Option<u32>,
    },
    GuardCliCommand {
        python: String,
        package_root: String,
        guard_args: Vec<String>,
    },
    DaemonStartCommand {
        python: String,
        package_root: String,
        guard_home: String,
        home_dir: Option<String>,
    },
    HookEnvironment {
        source: BTreeMap<String, String>,
    },
    PrivateRuntimeCwd {
        manifest_path: String,
    },
    SystemExecutable {
        filename: String,
    },
    /// Put a running process (the caller's own bootstrap) in a kill-on-close
    /// job this holder owns. The answer line is written once the process is
    /// assigned; the job then lives until the caller's end of stdin closes,
    /// which is also what happens when the caller dies.
    HoldJob {
        process_id: u32,
        #[serde(default)]
        allow_breakaway: bool,
    },
}

/// One request line: everything up to the first newline.
fn read_line(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() >= MAX_REQUEST_BYTES {
                    return Err("hook_launch_request_too_large".to_owned());
                }
                line.push(byte[0]);
            }
            Err(_) => return Err("hook_launch_request_unreadable".to_owned()),
        }
    }
    Ok(line)
}

pub(crate) fn run_command(mut reader: impl Read + Send + 'static) -> Result<Vec<u8>, String> {
    // The caller reads this launcher's output to its end. `Command` always
    // creates a child with handle inheritance on, so a detached process the
    // launched child starts (the daemon) would otherwise inherit the caller's
    // pipes through this launcher and hold them open for its whole life.
    #[cfg(windows)]
    guard_runtime_windows_process::disinherit_standard_handles();
    let line = read_line(&mut reader)?;
    let request: Request =
        serde_json::from_slice(&line).map_err(|_| "hook_launch_request_invalid".to_owned())?;
    if let Request::HoldJob {
        process_id,
        allow_breakaway,
    } = request
    {
        return hold_job(process_id, allow_breakaway, reader);
    }
    let stop = Arc::new(AtomicBool::new(false));
    if matches!(request, Request::Launch { .. }) {
        // The caller holds its end of stdin open for the whole run: EOF is the
        // stop signal, and the same group kill serves a deadline.
        let flag = stop.clone();
        std::thread::spawn(move || {
            let mut sink = [0u8; 256];
            loop {
                match reader.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            flag.store(true, Ordering::SeqCst);
        });
    }
    serde_json::to_vec(&answer(request, stop))
        .map_err(|_| "hook_launch_response_encode_failed".to_owned())
}

fn answer(request: Request, stop: Arc<AtomicBool>) -> Value {
    match request {
        Request::Launch {
            command,
            input_text,
            cwd,
            environment,
            timeout_millis,
            output_limit,
            raw_output,
            parent_liveness,
            allow_breakaway,
            kill_on_close,
            job_memory_limit_bytes,
            active_process_limit,
        } => {
            let extras = LaunchExtras {
                parent_liveness,
                allow_breakaway,
                kill_on_close,
                job_memory_limit_bytes,
                active_process_limit,
            };
            let outcome = run_isolated_hook_process_extended(
                &command,
                &input_text,
                Path::new(&cwd),
                &environment,
                Some(Duration::from_millis(timeout_millis).as_secs_f64()),
                output_limit,
                Some(stop),
                None,
                &extras,
            );
            let result = outcome.result;
            // A quarantined survivor has no later call to retry it once this
            // one-shot process exits, so settle it inside the same answer.
            let quarantine_settled =
                !result.containment_failed || settle_quarantine(QUARANTINE_SETTLE_WINDOW);
            // The one-shot process exits next, so name what it could not stop: the
            // client keeps the latch until each of these is confirmed gone.
            let survivors = if quarantine_settled {
                Vec::new()
            } else {
                quarantined_pids()
            };
            let hex = |bytes: &[u8]| {
                raw_output.then(|| {
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                })
            };
            json!({
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "stdout_hex": hex(&outcome.stdout_raw),
                "stderr_hex": hex(&outcome.stderr_raw),
                "output_limit_exceeded": result.output_limit_exceeded,
                "timed_out": result.timed_out,
                "containment_failed": result.containment_failed,
                "capture_incomplete": outcome.capture_incomplete,
                "quarantine_settled": quarantine_settled,
                "survivors": survivors,
            })
        }
        Request::GuardCliCommand {
            python,
            package_root,
            guard_args,
        } => json!({
            "command": isolated_guard_cli_command(&python, Path::new(&package_root), &guard_args),
        }),
        Request::DaemonStartCommand {
            python,
            package_root,
            guard_home,
            home_dir,
        } => json!({
            "command": isolated_daemon_start_command(
                &python,
                Path::new(&package_root),
                Path::new(&guard_home),
                home_dir.as_deref().map(Path::new),
            ),
        }),
        Request::HookEnvironment { source } => {
            json!({ "environment": isolated_hook_environment(&source) })
        }
        Request::PrivateRuntimeCwd { manifest_path } => {
            match private_hook_runtime_cwd(Path::new(&manifest_path)) {
                Ok(path) => json!({ "path": path.to_string_lossy() }),
                Err(message) => json!({ "error": message }),
            }
        }
        Request::HoldJob { .. } => json!({ "error": "hold_job_not_held" }),
        Request::SystemExecutable { filename } => match system_executable(&filename) {
            Ok(path) => json!({ "path": path.to_string_lossy() }),
            Err(message) => json!({ "error": message }),
        },
    }
}

#[cfg(windows)]
fn hold_job(
    process_id: u32,
    allow_breakaway: bool,
    mut reader: impl Read,
) -> Result<Vec<u8>, String> {
    use guard_runtime_windows_process::{ChildTree, ChildTreeOptions};
    use std::io::Write;

    let options = ChildTreeOptions {
        allow_breakaway,
        ..ChildTreeOptions::default()
    };
    let tree = match ChildTree::adopt_process_id(process_id, options) {
        Ok(tree) => tree,
        Err(error) => {
            return serde_json::to_vec(&json!({ "error": error.to_string() }))
                .map_err(|_| "hook_launch_response_encode_failed".to_owned());
        }
    };
    let mut out = std::io::stdout();
    let acknowledged = writeln!(out, "{}", json!({ "held": true })).and_then(|()| out.flush());
    if acknowledged.is_ok() {
        let mut sink = [0u8; 256];
        while matches!(reader.read(&mut sink), Ok(read) if read > 0) {}
    }
    // Closing the job ends every member the caller started.
    drop(tree);
    serde_json::to_vec(&json!({ "released": true }))
        .map_err(|_| "hook_launch_response_encode_failed".to_owned())
}

#[cfg(not(windows))]
fn hold_job(_: u32, _: bool, _: impl Read) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({ "error": "Windows Job Objects are unavailable" }))
        .map_err(|_| "hook_launch_response_encode_failed".to_owned())
}

/// A System32 program by the directory the kernel reports, never by `PATH`.
fn system_executable(filename: &str) -> Result<PathBuf, String> {
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.contains(['/', '\\', ':'])
    {
        return Err("Windows system executable must be a filename".to_owned());
    }
    let directory = guard_runtime_windows_process::kernel_windows_directory()
        .ok_or_else(|| "Windows system APIs are unavailable".to_owned())?;
    Ok(PathBuf::from(format!("{directory}\\System32\\{filename}")))
}

#[cfg(test)]
#[path = "hook_launch_cli_tests.rs"]
mod tests;
