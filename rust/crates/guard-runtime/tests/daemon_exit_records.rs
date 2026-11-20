//! A standalone daemon leaves the cause of its exit in the lifecycle journal.
//!
//! SIGTERM is recorded by the daemon itself. SIGKILL cannot be, so the next
//! daemon to start names the one that vanished.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde_json::{json, Value};

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

/// A daemon that has reported ready. Its standard input stays open, as a
/// launcher leaves it, and it is killed if a test fails before stopping it.
struct Daemon {
    child: Child,
    _stdin: ChildStdin,
}

impl Daemon {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn stop(mut self, signal: Signal) -> std::process::ExitStatus {
        kill(Pid::from_raw(self.pid() as i32), signal).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the daemon did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_home() -> tempfile::TempDir {
    let home = tempfile::Builder::new()
        .prefix("exit-records")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn start(home: &Path) -> Daemon {
    let launch = json!({
        "schema": "guard-daemon-serve-launch.v1",
        "guard_home": home,
        "port": 0,
        "store_path": home.join("guard.db"),
        "source": "daemon",
        "busy_timeout_ms": 5000,
        "cli_command": ["/usr/bin/false"],
        "state": {"compatibility_version": 2, "package_version": "9.9.9"},
    });
    let mut child = Command::new(runtime_binary())
        .args(["daemon-serve", "--guard-home"])
        .arg(home)
        .args(["--port", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{launch}\n").as_bytes()).unwrap();
    stdin.flush().unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let daemon = Daemon {
        child,
        _stdin: stdin,
    };
    let reported: Value = serde_json::from_str(ready.trim()).unwrap_or_else(|_| {
        panic!("the daemon did not report ready: {ready:?}");
    });
    assert_eq!(reported["pid"], daemon.pid());
    daemon
}

fn journal(home: &Path) -> Vec<Value> {
    let mut names: Vec<_> = fs::read_dir(home.join("daemon-lifecycle"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect()
}

fn events_of(home: &Path, pid: u32, event: &str) -> Vec<Value> {
    journal(home)
        .into_iter()
        .filter(|record| record["pid"] == pid && record["event"] == event)
        .collect()
}

#[test]
fn a_terminated_daemon_records_why_and_a_killed_one_is_named_by_the_next() {
    let home = private_home();

    let first = start(home.path());
    let first_pid = first.pid();
    let status = first.stop(Signal::SIGTERM);
    assert_eq!(status.signal(), Some(Signal::SIGTERM as i32), "{status:?}");
    let exits = events_of(home.path(), first_pid, "exiting");
    assert_eq!(exits.len(), 1, "{:?}", journal(home.path()));
    assert_eq!(exits[0]["reason"], "signal_term");

    let second = start(home.path());
    let second_pid = second.pid();
    second.stop(Signal::SIGKILL);
    assert!(events_of(home.path(), second_pid, "exiting").is_empty());

    let third = start(home.path());
    let unclean = events_of(home.path(), second_pid, "unclean_exit_detected");
    assert_eq!(unclean.len(), 1, "{:?}", journal(home.path()));
    assert_eq!(unclean[0]["reason"], "no_exit_record");
    assert_eq!(unclean[0]["by_pid"], third.pid());
    // The first daemon said why it stopped, so it is not named again.
    assert!(events_of(home.path(), first_pid, "unclean_exit_detected").is_empty());
    third.stop(Signal::SIGTERM);

    let log = fs::read_to_string(home.path().join("logs").join("daemon.log")).unwrap();
    assert!(
        log.contains(&format!("exiting pid={first_pid} reason=signal_term")),
        "{log}"
    );
}

#[test]
fn a_launch_that_names_another_daemon_records_its_failure() {
    let home = private_home();
    let status = Command::new(runtime_binary())
        .args(["daemon-serve", "--guard-home"])
        .arg(home.path())
        .args(["--port", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    let failures: Vec<Value> = journal(home.path())
        .into_iter()
        .filter(|record| record["event"] == "start_failed")
        .collect();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0]["reason"], "launch_config_invalid");
}
