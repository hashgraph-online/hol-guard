//! A runtime whose caller has already gone must still exit with its code.
//!
//! Hooks and launchers start the runtime and sometimes leave before it
//! answers, so its stdout and stderr are pipes with no reader. Writing the
//! error code used to panic, the panic hook's own write panicked again, and
//! the process aborted with SIGABRT, losing the code and leaving a crash
//! report behind.
#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// See `optional_command_authoring.rs`: nextest archives move the binary.
fn runtime_binary() -> OsString {
    [
        "NEXTEST_BIN_EXE_hol-guard-runtime",
        "NEXTEST_BIN_EXE_hol_guard_runtime",
    ]
    .into_iter()
    .find_map(std::env::var_os)
    .unwrap_or_else(|| env!("CARGO_BIN_EXE_hol-guard-runtime").into())
}

/// A pipe whose read end is already closed, as a departed caller leaves it.
fn readerless_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    Stdio::from(writer)
}

#[test]
fn a_failed_launch_with_no_reader_exits_with_its_code_and_records_it() {
    let home = tempfile::tempdir().unwrap();
    let status = Command::new(runtime_binary())
        .args(["not-a-runtime-command", "--guard-home"])
        .arg(home.path())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(readerless_pipe())
        .stderr(readerless_pipe())
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        None,
        "the runtime died on a signal: {status:?}"
    );
    assert_eq!(status.code(), Some(2));
    let log = home.path().join("logs").join("runtime-failures.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1, "{text}");
    assert_eq!(records[0]["kind"], "error");
    assert_eq!(records[0]["code"], "usage:");
    // An argument that is not a known subcommand may be user data, so the
    // record names it only as "other".
    assert_eq!(records[0]["subcommand"], "other");
}

#[test]
fn a_failed_launch_with_a_reader_still_reports_its_code_on_stderr() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(runtime_binary())
        .args(["not-a-runtime-command", "--guard-home"])
        .arg(home.path())
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("usage: hol-guard-runtime"), "{stderr}");
}
