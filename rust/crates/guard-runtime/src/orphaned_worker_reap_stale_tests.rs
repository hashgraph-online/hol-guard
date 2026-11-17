use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

use serde_json::json;

use super::super::{parse_process_snapshot, reap, Host, Stop};
use super::*;

const RUNTIME: &str = "/opt/guard/native-runtime/aa11/hol-guard-runtime";
const GONE_RUNTIME: &str = "/opt/guard/native-runtime/bb22/hol-guard-runtime";
const CORE: &str = "/opt/Application Support/core/versions/3.6.3/hol-guard";
const GONE_HOME: &str = "/tmp/scratch home/guard";
const LIVE_HOME: &str = "/opt/guard";

/// A process table in which every listed process keeps its command and
/// start token and exits on its first signal.
struct StaleHost {
    listing: String,
    absent: Vec<&'static str>,
    foreign: Vec<u32>,
    sent: RefCell<Vec<(u32, Stop)>>,
    started: Instant,
    elapsed: Cell<Duration>,
}

impl StaleHost {
    fn new(lines: &[String]) -> Self {
        Self {
            listing: lines.join("\n"),
            absent: vec![GONE_HOME, GONE_RUNTIME],
            foreign: Vec::new(),
            sent: RefCell::default(),
            started: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
        }
    }

    fn signalled(&self) -> Vec<u32> {
        self.sent.borrow().iter().map(|(pid, _)| *pid).collect()
    }

    fn command_of(&self, pid: u32) -> Option<String> {
        if self.sent.borrow().iter().any(|(sent, _)| *sent == pid) {
            return None;
        }
        parse_process_snapshot(&self.listing)
            .into_iter()
            .find(|process| process.pid == pid)
            .map(|process| process.command)
    }
}

impl Host for StaleHost {
    fn listing(&self, _timeout: Duration) -> Option<String> {
        Some(self.listing.clone())
    }

    fn command(&self, pid: u32) -> Option<String> {
        self.command_of(pid)
    }

    fn start_token(&self, pid: u32) -> Option<String> {
        self.command_of(pid).map(|_| format!("posix:{pid}"))
    }

    fn signal(&self, pid: u32, stop: Stop) {
        self.sent.borrow_mut().push((pid, stop));
    }

    fn owned_by_caller(&self, pid: u32) -> bool {
        !self.foreign.contains(&pid)
    }

    fn path_absent(&self, path: &str) -> bool {
        self.absent.contains(&path)
    }

    fn now(&self) -> Instant {
        self.started + self.elapsed.get()
    }

    fn sleep(&self, duration: Duration) {
        self.elapsed.set(self.elapsed.get() + duration);
    }
}

fn line(pid: u32, ppid: u32, command: &str) -> String {
    format!("{pid} {ppid} S {command}")
}

fn native_daemon(home: &str) -> String {
    format!("{RUNTIME} daemon-serve --guard-home {home} --port 5474")
}

fn python_daemon(home: &str) -> String {
    format!("{CORE} daemon --serve --guard-home {home} --home /opt/home --port 5474")
}

fn relay(runtime: &str) -> String {
    format!("{runtime} mcp-relay /usr/bin/python3 -m server --stdio")
}

fn stale(host: &StaleHost) -> Vec<u32> {
    stale_guard_processes(host, &parse_process_snapshot(&host.listing), &[])
        .iter()
        .map(|process| process.pid)
        .collect()
}

#[test]
fn a_daemon_whose_guard_home_is_gone_is_retired_in_one_pass() {
    let host = StaleHost::new(&[
        line(10, 1, &native_daemon(GONE_HOME)),
        line(11, 1, &python_daemon(GONE_HOME)),
        line(12, 11, &native_daemon(GONE_HOME)),
        line(20, 1, &native_daemon(LIVE_HOME)),
        line(21, 1, &python_daemon(LIVE_HOME)),
    ]);

    let answer = reap(&host, &[], None);

    assert_eq!(answer["selected"], json!([10, 11, 12]));
    assert_eq!(answer["signalled"], json!([10, 11, 12]));
    assert_eq!(host.signalled(), [10, 11, 12]);
}

#[test]
fn a_hostless_relay_whose_runtime_was_removed_is_retired() {
    let host = StaleHost::new(&[
        line(30, 1, &relay(GONE_RUNTIME)),
        // Its host is still talking to it.
        line(31, 900, &relay(GONE_RUNTIME)),
        // Its runtime is still installed.
        line(32, 1, &relay(RUNTIME)),
        line(900, 1, "/Applications/Editor.app/Contents/MacOS/Editor"),
    ]);

    let answer = reap(&host, &[], None);

    assert_eq!(answer["selected"], json!([30]));
    assert_eq!(host.signalled(), [30]);
}

#[test]
fn look_alike_and_foreign_processes_are_left_running() {
    let mut host = StaleHost::new(&[
        // Not a Guard executable.
        line(
            40,
            1,
            &format!("/usr/bin/sleep daemon-serve --guard-home {GONE_HOME}"),
        ),
        line(41, 1, "/opt/tools/hol-guard-runtime-dev mcp-relay x"),
        line(
            42,
            1,
            &format!("hol-guard-runtime daemon-serve --guard-home {GONE_HOME}"),
        ),
        // A Guard executable, but no daemon or relay subcommand.
        line(
            43,
            1,
            &format!("{RUNTIME} daemon-serve-check --guard-home {GONE_HOME}"),
        ),
        line(44, 1, &format!("{GONE_RUNTIME} mcp-relayed")),
        line(
            45,
            1,
            &format!("{RUNTIME} storage-retention --guard-home {GONE_HOME}"),
        ),
        // A relative Guard home proves nothing.
        line(
            46,
            1,
            &format!("{RUNTIME} daemon-serve --guard-home scratch --port 1"),
        ),
        // Another user's daemon.
        line(47, 1, &native_daemon(GONE_HOME)),
        // A zombie has nothing left to stop.
        format!("48 1 Z {}", native_daemon(GONE_HOME)),
    ]);
    host.foreign.push(47);

    assert!(stale(&host).is_empty());
    reap(&host, &[], None);
    assert!(host.signalled().is_empty());
}

#[test]
fn the_caller_is_never_retired() {
    let host = StaleHost::new(&[line(50, 1, &native_daemon(GONE_HOME))]);

    assert!(stale_guard_processes(&host, &parse_process_snapshot(&host.listing), &[50]).is_empty());
}

#[test]
fn a_reused_pid_is_not_signalled() {
    let listed = StaleHost::new(&[line(60, 1, &native_daemon(GONE_HOME))]);
    assert_eq!(stale(&listed), [60]);

    // The listed daemon exits and its pid now runs something else.
    let reused = StaleHost::new(&[line(60, 1, "/usr/bin/vim notes.txt")]);
    let processes = parse_process_snapshot(&listed.listing);
    let (signalled, forced) = super::super::terminate(
        &reused,
        &stale_guard_processes(&listed, &processes, &[]),
        &[],
        Duration::ZERO,
    );
    assert!(signalled.is_empty() && forced.is_empty());
    assert!(reused.signalled().is_empty());
}

#[test]
fn the_guard_home_runs_to_the_next_flag() {
    assert_eq!(
        daemon_guard_home(&native_daemon(GONE_HOME)),
        Some(GONE_HOME)
    );
    assert_eq!(
        daemon_guard_home(&format!("{RUNTIME} daemon-serve --guard-home {GONE_HOME}")),
        Some(GONE_HOME)
    );
    assert_eq!(
        daemon_guard_home(&python_daemon(LIVE_HOME)),
        Some(LIVE_HOME)
    );
    assert_eq!(
        daemon_guard_home(&format!("{RUNTIME} daemon-serve --port 1")),
        None
    );
}
