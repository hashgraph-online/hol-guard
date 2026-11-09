//! Guard library calls the daemon makes through a short-lived Guard CLI
//! process (`desktop library-call`).
//!
//! The daemon owns every route; work that still lives in the Python library
//! (approval resolution, scope contracts, continuations) runs as one call:
//! `{"call": name, "args": {...}}` on standard input, and `{"ok": value}` or
//! `{"error": {"kind": ..., ...}}` on standard output. The daemon writes the
//! status and body from that answer.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::reads::ReadConfig;
use crate::onefile_open_paths::{isolate_group, kill_group};

/// How long one call may take: an approval may wait on the approval gate.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest answer a call may print.
const MAX_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// Why a library call gave no value.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum CallError {
    /// No CLI to run, or it did not answer in time with one JSON object.
    /// Nothing is known to have happened, so the request can be relayed.
    Unavailable,
    /// The call raised: `{"kind", "type", "message", ...}`.
    Raised(Map<String, Value>),
}

#[cfg(test)]
impl CallError {
    /// The kind the library named for a raised error.
    pub(in crate::daemon_edge) fn kind(&self) -> Option<&str> {
        match self {
            Self::Unavailable => None,
            Self::Raised(error) => error.get("kind").and_then(Value::as_str),
        }
    }
}

/// Runs `call` with `args` and returns its value.
pub(in crate::daemon_edge) fn call(
    config: &ReadConfig,
    name: &str,
    args: Value,
) -> Result<Value, CallError> {
    let request = serde_json::to_vec(&json!({"call": name, "args": args}))
        .map_err(|_| CallError::Unavailable)?;
    let answer = run(config, request).ok_or(CallError::Unavailable)?;
    decode(&answer)
}

/// The value or error one answer carries.
pub(in crate::daemon_edge) fn decode(answer: &[u8]) -> Result<Value, CallError> {
    let Ok(Value::Object(mut answer)) = serde_json::from_slice::<Value>(answer) else {
        return Err(CallError::Unavailable);
    };
    if let Some(value) = answer.remove("ok") {
        return Ok(value);
    }
    match answer.remove("error") {
        Some(Value::Object(error)) => Err(CallError::Raised(error)),
        _ => Err(CallError::Unavailable),
    }
}

/// The CLI arguments for one call.
pub(in crate::daemon_edge) fn call_args(guard_home: &str) -> [String; 4] {
    [
        "desktop".to_owned(),
        "library-call".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
    ]
}

fn run(config: &ReadConfig, request: Vec<u8>) -> Option<Vec<u8>> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(call_args(guard_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(child);
        return None;
    };
    thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout
            .take(MAX_ANSWER_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_ok();
        let _ = sender.send(read.then_some(bytes));
    });
    match receiver.recv_timeout(CALL_TIMEOUT) {
        Ok(Some(bytes)) if bytes.len() as u64 <= MAX_ANSWER_BYTES => {
            thread::spawn(move || {
                let _ = child.wait();
            });
            Some(bytes)
        }
        _ => {
            stop(child);
            None
        }
    }
}

/// The CLI arguments for the worker host.
pub(in crate::daemon_edge) fn host_args(guard_home: &str) -> [String; 4] {
    [
        "desktop".to_owned(),
        "daemon-workers".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
    ]
}

/// Runs the worker host until it exits and returns `None` when it could not
/// be started. Its standard input stays open while this process lives.
pub(in crate::daemon_edge) fn run_host(config: &ReadConfig) -> Option<()> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(host_args(guard_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    // Held, never written: the host stops when this end closes.
    let _input = child.stdin.take();
    let _ = child.wait();
    Some(())
}

fn stop(mut child: Child) {
    kill_group(&child);
    let _ = child.kill();
    thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_library_tests.rs"]
mod tests;
