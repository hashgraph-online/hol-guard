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
/// A live home whose path holds ` --`: `ps` cannot tell it from a flag.
const FLAG_LIKE_HOME: &str = "/tmp/team --scratch/guard";

/// A process table in which every listed process keeps its command and
/// start token and exits on its first signal. Only `present` paths exist.
struct StaleHost {
    listing: String,
    present: Vec<&'static str>,
    foreign: Vec<u32>,
    /// Owner checks that hang until their timeout, as a stuck `ps` does.
    slow_owner_checks: bool,
    owner_timeouts: RefCell<Vec<Duration>>,
    /// How long each command-line lookup takes.
    command_delay: Duration,
    sent: RefCell<Vec<(u32, Stop)>>,
    started: Instant,
    elapsed: Cell<Duration>,
}

impl StaleHost {
    fn new(lines: &[String]) -> Self {
        Self {
            listing: lines.join("\n"),
            present: vec![LIVE_HOME, FLAG_LIKE_HOME, RUNTIME, CORE],
            foreign: Vec::new(),
            slow_owner_checks: false,
            owner_timeouts: RefCell::default(),
            command_delay: Duration::ZERO,
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
        self.elapsed.set(self.elapsed.get() + self.command_delay);
        self.command_of(pid)
    }

    fn start_token(&self, pid: u32) -> Option<String> {
        self.command_of(pid).map(|_| format!("posix:{pid}"))
    }

    fn signal(&self, pid: u32, stop: Stop) {
        self.sent.borrow_mut().push((pid, stop));
    }

    fn owned_by_caller(&self, pid: u32, timeout: Duration) -> bool {
        self.owner_timeouts.borrow_mut().push(timeout);
        if self.slow_owner_checks {
            self.elapsed.set(self.elapsed.get() + timeout);
        }
        !self.foreign.contains(&pid)
    }

    fn path_absent(&self, path: &str) -> bool {
        !self.present.contains(&path)
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
    stale_guard_processes(host, &parse_process_snapshot(&host.listing), &[], None)
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
        // A script that only names the packaged module is not its daemon.
        line(
            49,
            1,
            &format!(
                "/usr/bin/python3 -c import time; time.sleep(3600) codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"
            ),
        ),
        line(
            50,
            1,
            &format!(
                "/usr/bin/python3 -c pass -m codex_plugin_scanner.cli guard daemon --serve --guard-home {GONE_HOME}"
            ),
        ),
        line(
            51,
            1,
            &format!(
                "/usr/bin/python3 -m other codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"
            ),
        ),
        line(
            52,
            1,
            &format!(
                "/usr/bin/node -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"
            ),
        ),
    ]);
    host.foreign.push(47);

    assert!(stale(&host).is_empty());
    reap(&host, &[], None);
    assert!(host.signalled().is_empty());
}

#[test]
fn the_caller_is_never_retired() {
    let host = StaleHost::new(&[line(50, 1, &native_daemon(GONE_HOME))]);

    assert!(
        stale_guard_processes(&host, &parse_process_snapshot(&host.listing), &[50], None)
            .is_empty()
    );
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
        &stale_guard_processes(&listed, &processes, &[], None),
        &[],
        Duration::ZERO,
        None,
    );
    assert!(signalled.is_empty() && forced.is_empty());
    assert!(reused.signalled().is_empty());
}

#[test]
fn the_guard_home_is_read_at_every_place_it_could_end() {
    assert_eq!(
        daemon_guard_homes(&native_daemon(GONE_HOME)),
        Some(vec![GONE_HOME, "/tmp/scratch home/guard --port 5474"])
    );
    assert_eq!(
        daemon_guard_homes(&format!("{RUNTIME} daemon-serve --guard-home {GONE_HOME}")),
        Some(vec![GONE_HOME])
    );
    assert_eq!(
        daemon_guard_homes(&native_daemon(FLAG_LIKE_HOME)),
        Some(vec![
            "/tmp/team",
            FLAG_LIKE_HOME,
            "/tmp/team --scratch/guard --port 5474",
        ])
    );
    assert_eq!(
        daemon_guard_homes(&format!("{RUNTIME} daemon-serve --port 1")),
        Some(Vec::new())
    );
    assert_eq!(daemon_guard_homes(&relay(RUNTIME)), None);
}

#[test]
fn a_live_daemon_whose_home_holds_a_flag_like_space_is_kept() {
    // `/tmp/team` does not exist, but the home the daemon serves does.
    let host = StaleHost::new(&[
        line(70, 1, &native_daemon(FLAG_LIKE_HOME)),
        line(71, 1, &python_daemon(FLAG_LIKE_HOME)),
        line(72, 1, &native_daemon("/tmp/gone --scratch/guard")),
    ]);

    let answer = reap(&host, &[], None);

    assert_eq!(answer["selected"], json!([72]));
    assert_eq!(host.signalled(), [72]);
}

#[test]
fn owner_checks_stop_when_the_budget_is_spent() {
    let mut host = StaleHost::new(&[
        line(80, 1, &native_daemon(GONE_HOME)),
        line(81, 1, &native_daemon(GONE_HOME)),
        line(82, 1, &native_daemon(GONE_HOME)),
    ]);
    host.slow_owner_checks = true;
    let deadline = host.now() + Duration::from_millis(700);

    let selected = stale_guard_processes(
        &host,
        &parse_process_snapshot(&host.listing),
        &[],
        Some(deadline),
    );

    // The first check may take its full 500 ms, the second only the 200 ms
    // left, and the third never runs.
    assert_eq!(
        selected
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>(),
        [80, 81]
    );
    assert_eq!(
        *host.owner_timeouts.borrow(),
        [Duration::from_millis(500), Duration::from_millis(200)]
    );
    assert!(host.now() <= deadline);
}

#[test]
fn a_packaged_module_daemon_of_a_deleted_home_is_retired() {
    let host = StaleHost::new(&[
        line(
            90,
            1,
            &format!("python -m codex_plugin_scanner.cli guard daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            91,
            1,
            &format!("/usr/bin/python3 -I -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            92,
            1,
            &format!("/usr/bin/python3 -m codex_plugin_scanner.cli daemon --serve --guard-home {LIVE_HOME}"),
        ),
    ]);

    assert_eq!(stale(&host), [90, 91]);
}

#[test]
fn termination_stops_when_the_pass_budget_is_spent() {
    let lines: Vec<String> = (100..110)
        .map(|pid| line(pid, 1, &native_daemon(GONE_HOME)))
        .collect();
    let mut host = StaleHost::new(&lines);
    // Each process costs two 400 ms command lookups before its signal.
    host.command_delay = Duration::from_millis(400);
    let deadline = host.now() + Duration::from_secs(3);

    reap(&host, &[], Some(Duration::from_secs(3)));

    // Checks start at 0, 0.8, 1.6 and 2.4 s; none starts at 3.2 s.
    assert_eq!(host.signalled(), [100, 101, 102, 103]);
    assert!(host.now() <= deadline + Duration::from_millis(800));
}

#[test]
fn a_packaged_module_daemon_under_a_spaced_directory_is_retired() {
    let host = StaleHost::new(&[
        line(
            93,
            1,
            &format!("/opt/Team Tools/.venv/bin/python -I -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        // Another program that runs a file named python is not a daemon.
        line(
            94,
            1,
            &format!("/bin/sh /opt/tools/python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            95,
            1,
            &format!("/bin/sh -x python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            96,
            1,
            &format!("relative tools/python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            97,
            1,
            &format!("/opt/Team Tools/python3 -c pass -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            98,
            1,
            &format!("/opt/Team Tools/node -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        // A shell or launcher that runs a relative python is not a spaced path.
        line(
            99,
            1,
            &format!("/bin/sh tools/python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            100,
            1,
            &format!("/bin/sh python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            101,
            1,
            &format!("/usr/bin/env python3 -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
        line(
            102,
            1,
            &format!("/missing/launcher/bash tools/python -m codex_plugin_scanner.cli daemon --serve --guard-home {GONE_HOME}"),
        ),
    ]);

    assert_eq!(stale(&host), [93]);
    reap(&host, &[], None);
    assert_eq!(host.signalled(), [93]);
}

#[test]
fn owner_checks_leave_time_to_signal_what_they_select() {
    let lines: Vec<String> = (110..116)
        .map(|pid| line(pid, 1, &native_daemon(GONE_HOME)))
        .collect();
    let mut host = StaleHost::new(&lines);
    host.slow_owner_checks = true;
    host.command_delay = Duration::from_millis(400);

    reap(&host, &[], Some(Duration::from_millis(2_500)));

    // Owner checks of 500 ms each stop at 1 s, leaving 1.5 s in which the
    // two selected daemons are checked and signalled. Without the reserve
    // the checks select five daemons, spend the budget and signal none.
    assert_eq!(host.signalled(), [110, 111]);
}
