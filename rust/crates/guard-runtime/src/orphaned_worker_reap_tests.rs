use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::*;

const CORE: &str = "/opt/Application Support/hol-guard-desktop/core/versions/3.6.3/hol-guard";
const OTHER_DAEMON: &str =
    "/opt/runner/versions/3.0.193/hol-guard daemon --serve --guard-home /opt/other-home --port 9";
const OTHER_WORKER: &str =
    "/opt/runner/versions/3.0.193/hol-guard --multiprocessing-fork tracker_fd=7 pipe_handle=8";

fn daemon() -> String {
    format!("{CORE} daemon --serve --guard-home /opt/guard-home --home /opt/home --port 5474")
}

fn worker() -> String {
    format!("{CORE} --multiprocessing-fork tracker_fd=20 pipe_handle=17")
}

fn tracker() -> String {
    format!("{CORE} -B -S -I -c from multiprocessing.resource_tracker import main;main(18)")
}

fn python_worker() -> String {
    format!(
        "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main; \
         spawn_main(tracker_fd=5, pipe_handle=6) --multiprocessing-fork {HOOK_WORKER_COMMAND_MARKER}"
    )
}

fn line(pid: u32, ppid: u32, state: &str, command: &str) -> String {
    format!("{pid} {ppid} {state} {command}")
}

fn selected(lines: &[String]) -> Vec<u32> {
    orphaned_daemon_workers(&parse_process_snapshot(&lines.join("\n")), &[])
        .iter()
        .map(|process| process.pid)
        .collect()
}

fn snapshot(pid: u32, command: &str) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        ppid: 1,
        state: "S".to_owned(),
        command: command.to_owned(),
    }
}

#[test]
fn live_daemon_workers_stay_and_orphans_are_selected() {
    let lines = [
        line(100, 1, "Ss", &daemon()),
        line(101, 100, "S", &worker()),
        line(102, 100, "S", &tracker()),
        line(103, 101, "S", &worker()),
        line(200, 1, "Z", &daemon()),
        line(201, 200, "S", &worker()),
        line(202, 1, "S", &tracker()),
        line(203, 1, "S", &python_worker()),
        line(204, 201, "S", &worker()),
        line(205, 202, "S", &tracker()),
        line(206, 1, "S", "/usr/bin/hol-guard-desktop"),
        line(207, 206, "S", &worker()),
        line(300, 1, "S", OTHER_DAEMON),
        line(301, 300, "S", OTHER_WORKER),
        line(
            400,
            1,
            "S",
            "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main",
        ),
        line(401, 1, "S", "echo /opt/hol-guard --multiprocessing-fork"),
    ];

    assert_eq!(selected(&lines), [201, 202, 203, 204, 205, 207]);
}

#[test]
fn python_module_daemon_anchors_its_worker() {
    let module_daemon = "/usr/bin/python3 -m codex_plugin_scanner.cli guard daemon --serve \
                         --guard-home /opt/guard-home --port 5474";

    assert!(selected(&[
        line(10, 1, "S", module_daemon),
        line(11, 10, "S", &worker())
    ])
    .is_empty());
}

#[test]
fn excluded_pids_are_never_selected() {
    let processes = parse_process_snapshot(&line(50, 1, "S", &worker()));

    assert!(orphaned_daemon_workers(&processes, &[50]).is_empty());
    assert!(
        orphaned_daemon_workers(&parse_process_snapshot(&line(1, 0, "S", &worker())), &[])
            .is_empty()
    );
}

#[test]
fn marked_python_command_is_attributable() {
    let unmarked =
        "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main --multiprocessing-fork";
    let marked = format!("{unmarked} {HOOK_WORKER_COMMAND_MARKER}");

    assert_eq!(
        orphaned_daemon_workers(&[snapshot(50, &marked)], &[])
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>(),
        [50]
    );
    assert!(orphaned_daemon_workers(&[snapshot(50, unmarked)], &[]).is_empty());
}

#[test]
fn process_snapshot_skips_lines_that_are_not_processes() {
    assert!(parse_process_snapshot("\n   \nnope\n7\n7 x\n7 8\n7 8 S\n").is_empty());
}

#[test]
fn process_snapshot_reads_padded_columns() {
    assert_eq!(
        parse_process_snapshot("  42     1 Ss   /bin/zsh -l  \r\n"),
        [ProcessSnapshot {
            pid: 42,
            ppid: 1,
            state: "Ss".to_owned(),
            command: "/bin/zsh -l".to_owned(),
        }]
    );
}

#[test]
fn frozen_daemon_and_live_executable_ancestors_keep_their_workers() {
    let frozen = format!("{CORE} --_hol-guard-daemon-serve");
    let kept = [
        line(100, 1, "Ss", &frozen),
        line(101, 100, "S", &worker()),
        line(200, 1, "S", CORE),
        line(201, 200, "S", &worker()),
        line(
            300,
            1,
            "S",
            "python3 -c spawn --multiprocessing-fork --hol-guard-hook-worker",
        ),
        line(301, 1, "S", "/usr/bin/python3 --hol-guard-hook-worker"),
    ];
    let relative_parent = [
        line(400, 1, "S", "python3 -c helper"),
        line(401, 400, "S", &worker()),
    ];

    assert!(selected(&kept).is_empty());
    assert_eq!(selected(&relative_parent), [401]);
}

#[test]
fn parent_chain_past_the_hop_limit_is_orphaned() {
    let mut lines = vec![line(20, 19, "S", &worker())];
    for pid in (12..=19).rev() {
        lines.push(line(pid, pid - 1, "S", "/bin/zsh"));
    }
    lines.push(line(11, 1, "S", &daemon()));

    assert_eq!(selected(&lines), [20]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Terminate(u32),
    Kill(u32),
}

/// A process table whose reads come from scripted sequences; the last entry
/// repeats once a sequence runs out.
struct FakeHost {
    listing: Option<String>,
    commands: RefCell<HashMap<u32, Vec<Option<String>>>>,
    tokens: RefCell<HashMap<u32, Vec<Option<String>>>>,
    dies_on_terminate: Vec<u32>,
    dead: RefCell<Vec<u32>>,
    sent: RefCell<Vec<Sent>>,
    listing_timeouts: RefCell<Vec<Duration>>,
    started: Instant,
    elapsed: Cell<Duration>,
}

impl FakeHost {
    fn new() -> Self {
        Self {
            listing: None,
            commands: RefCell::default(),
            tokens: RefCell::default(),
            dies_on_terminate: Vec::new(),
            dead: RefCell::default(),
            sent: RefCell::default(),
            listing_timeouts: RefCell::default(),
            started: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
        }
    }

    fn with_process(self, pid: u32, commands: &[Option<&str>], tokens: &[Option<&str>]) -> Self {
        let owned = |values: &[Option<&str>]| -> Vec<Option<String>> {
            values
                .iter()
                .map(|value| value.map(str::to_owned))
                .collect()
        };
        self.commands.borrow_mut().insert(pid, owned(commands));
        self.tokens.borrow_mut().insert(pid, owned(tokens));
        self
    }

    fn next(table: &RefCell<HashMap<u32, Vec<Option<String>>>>, pid: u32) -> Option<String> {
        let mut table = table.borrow_mut();
        let values = table.get_mut(&pid)?;
        if values.len() > 1 {
            values.remove(0)
        } else {
            values.first().cloned().flatten()
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.borrow().clone()
    }
}

impl Host for FakeHost {
    fn listing(&self, timeout: Duration) -> Option<String> {
        self.listing_timeouts.borrow_mut().push(timeout);
        self.listing.clone()
    }

    fn command(&self, pid: u32) -> Option<String> {
        if self.dead.borrow().contains(&pid) {
            return None;
        }
        Self::next(&self.commands, pid)
    }

    fn start_token(&self, pid: u32) -> Option<String> {
        if self.dead.borrow().contains(&pid) {
            return None;
        }
        Self::next(&self.tokens, pid)
    }

    fn signal(&self, pid: u32, stop: Stop) {
        self.sent.borrow_mut().push(match stop {
            Stop::Terminate => Sent::Terminate(pid),
            Stop::Kill => Sent::Kill(pid),
        });
        if stop == Stop::Kill || self.dies_on_terminate.contains(&pid) {
            self.dead.borrow_mut().push(pid);
        }
    }

    fn now(&self) -> Instant {
        self.started + self.elapsed.get()
    }

    fn sleep(&self, duration: Duration) {
        self.elapsed.set(self.elapsed.get() + duration);
    }
}

#[test]
fn terminate_signals_the_worker_then_forces_a_survivor() {
    let command = worker();
    let host = FakeHost::new().with_process(50, &[Some(&command)], &[Some("posix:start")]);

    let (signalled, forced) = terminate(&host, &[snapshot(50, &command)], &[], Duration::ZERO);

    assert_eq!(host.sent(), [Sent::Terminate(50), Sent::Kill(50)]);
    assert_eq!((signalled, forced), (vec![50], vec![50]));
}

#[test]
fn terminate_does_not_force_a_worker_that_exits() {
    let command = worker();
    let mut host = FakeHost::new().with_process(50, &[Some(&command)], &[Some("posix:start")]);
    host.dies_on_terminate.push(50);

    let (_, forced) = terminate(&host, &[snapshot(50, &command)], &[], GRACE);

    assert_eq!(host.sent(), [Sent::Terminate(50)]);
    assert!(forced.is_empty());
    assert!(host.elapsed.get() <= POLL);
}

#[test]
fn terminate_does_not_signal_the_current_process_or_init() {
    let command = worker();
    let host = FakeHost::new()
        .with_process(0, &[Some(&command)], &[Some("posix:start")])
        .with_process(1, &[Some(&command)], &[Some("posix:start")])
        .with_process(77, &[Some(&command)], &[Some("posix:start")]);
    let workers = [
        snapshot(0, &command),
        snapshot(1, &command),
        snapshot(77, &command),
    ];

    terminate(&host, &workers, &[77], Duration::ZERO);

    assert!(host.sent().is_empty());
}

#[test]
fn terminate_skips_a_reused_pid() {
    let host = FakeHost::new().with_process(
        50,
        &[Some("/usr/bin/python3 unrelated")],
        &[Some("posix:other")],
    );

    terminate(&host, &[snapshot(50, &worker())], &[], Duration::ZERO);

    assert!(host.sent().is_empty());
}

#[test]
fn terminate_skips_a_worker_without_a_start_token() {
    let command = worker();
    for token in [None, Some("")] {
        let host = FakeHost::new().with_process(50, &[Some(&command)], &[token]);

        terminate(&host, &[snapshot(50, &command)], &[], Duration::ZERO);

        assert!(host.sent().is_empty());
    }
}

#[test]
fn terminate_does_not_force_kill_after_the_start_token_changes() {
    let command = worker();
    let host = FakeHost::new().with_process(
        50,
        &[Some(&command)],
        &[Some("posix:original"), Some("posix:replacement")],
    );

    terminate(&host, &[snapshot(50, &command)], &[], Duration::ZERO);

    assert_eq!(host.sent(), [Sent::Terminate(50)]);
}

#[test]
fn signal_waits_out_the_grace_period_and_skips_a_changed_worker() {
    let command = worker();
    let host =
        FakeHost::new().with_process(4242, &[Some(&command)], &[Some("born"), Some("replaced")]);

    terminate(&host, &[snapshot(4242, &command)], &[], GRACE);

    assert_eq!(host.sent(), [Sent::Terminate(4242)]);
    assert!(host.elapsed.get() > Duration::ZERO);
}

#[test]
fn signal_stops_when_the_command_changes_after_the_token_is_captured() {
    let command = worker();
    let host =
        FakeHost::new().with_process(4242, &[Some(&command), Some("/bin/other")], &[Some("born")]);

    terminate(&host, &[snapshot(4242, &command)], &[], Duration::ZERO);

    assert!(host.sent().is_empty());
}

#[test]
fn delivery_prefers_the_group_and_falls_back_to_the_pid() {
    let calls = RefCell::new(Vec::new());
    let run = |leads: Option<bool>, group_ok: bool| {
        calls.borrow_mut().clear();
        deliver(
            || leads,
            || {
                calls.borrow_mut().push("group");
                group_ok
            },
            || calls.borrow_mut().push("pid"),
        );
        calls.borrow().clone()
    };

    assert_eq!(run(Some(true), true), ["group"]);
    assert_eq!(run(Some(true), false), ["group", "pid"]);
    assert_eq!(run(Some(false), true), ["pid"]);
    assert!(run(None, true).is_empty());
}

#[test]
fn reap_selects_and_stops_orphans_from_the_listing() {
    let command = worker();
    let mut host = FakeHost::new().with_process(201, &[Some(&command)], &[Some("posix:start")]);
    host.listing = Some([line(200, 1, "Z", &daemon()), line(201, 200, "S", &command)].join("\n"));
    host.dies_on_terminate.push(201);

    let answer = reap(&host, &[], None);

    assert_eq!(
        answer,
        json!({"listed": true, "selected": [201], "signalled": [201], "forced": []})
    );
    assert_eq!(host.listing_timeouts.borrow().as_slice(), [LISTING_TIMEOUT]);
}

#[test]
fn reap_bounds_the_listing_by_the_budget() {
    let host = FakeHost::new();

    let answer = reap(&host, &[], Some(Duration::from_millis(300)));

    assert_eq!(answer["listed"], false);
    assert_eq!(
        host.listing_timeouts.borrow().as_slice(),
        [Duration::from_millis(300)]
    );
}

#[test]
fn reap_with_a_spent_budget_never_lists() {
    let host = FakeHost::new();

    let answer = reap(&host, &[], Some(Duration::ZERO));

    assert_eq!(answer["listed"], false);
    assert!(host.listing_timeouts.borrow().is_empty());
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        "",
        "{}",
        r#"{"schema":"orphaned-worker-reap.v0","self_pid":5}"#,
        r#"{"schema":"orphaned-worker-reap.v1","self_pid":0}"#,
        r#"{"schema":"orphaned-worker-reap.v1","self_pid":5,"budget_ms":60001}"#,
        r#"{"schema":"orphaned-worker-reap.v1","self_pid":5,"extra":true}"#,
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("orphaned_worker_reap_request_invalid".to_owned()),
            "{request}"
        );
    }
    let oversized = format!(
        r#"{{"schema":"orphaned-worker-reap.v1","self_pid":5,"pad":"{}"}}"#,
        "x".repeat(5000)
    );
    assert_eq!(
        run_command(oversized.as_bytes()),
        Err("orphaned_worker_reap_request_too_large".to_owned())
    );
}

#[cfg(not(unix))]
#[test]
fn reaping_is_unsupported_off_unix() {
    let answer =
        run_command(br#"{"schema":"orphaned-worker-reap.v1","self_pid":5}"#.as_slice()).unwrap();

    assert_eq!(
        serde_json::from_slice::<Value>(&answer).unwrap(),
        json!({"error": "orphaned_worker_reap_unsupported"})
    );
}
