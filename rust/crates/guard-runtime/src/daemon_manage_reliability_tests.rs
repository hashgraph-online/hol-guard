use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const DAY: u64 = 86_400 * 1_000_000_000;
/// 2026-11-17T00:00:00Z.
pub(super) const NOW: u64 = 1_794_873_600 * 1_000_000_000;

pub(super) fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn write_private(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

pub(super) fn event(home: &Path, at: u64, pid: u32, name: &str, reason: Option<&str>) {
    let mut record = json!({"event": name, "pid": pid, "recorded_at_ns": at, "version": 1});
    if let Some(reason) = reason {
        record["reason"] = json!(reason);
    }
    let suffix = if name == "recovery_requested" {
        ".recovery.json"
    } else {
        ".json"
    };
    let file = format!("{at:020}-{pid:010}-{:016x}{suffix}", u64::from(pid) ^ at);
    write_private(
        &home.join("daemon-lifecycle").join(file),
        &record.to_string(),
    );
}

fn ask(home: &Path, op: &str, args: Value) -> Value {
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": op,
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 5000,
        "args": args,
    });
    let bytes = super::super::run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn report(home: &Path, args: Value) -> Value {
    let mut args = args;
    args["now_ns"] = json!(NOW);
    ask(home, "reliability", args)
}

#[test]
fn exits_starts_repairs_and_recoveries_are_counted_inside_the_window() {
    let home = private_home();
    let home = home.path();
    // Outside a 7-day window: counted only by the 30-day report.
    event(home, NOW - 20 * DAY, 101, "exiting", Some("signal_term"));
    event(home, NOW - 2 * DAY, 102, "ready", None);
    event(home, NOW - 2 * DAY + 5, 102, "exiting", Some("signal_term"));
    event(home, NOW - DAY, 103, "ready", None);
    event(
        home,
        NOW - DAY + 1,
        103,
        "retirement_requested",
        Some("requested_retire"),
    );
    event(home, NOW - DAY + 2, 104, "unclean_exit_detected", None);
    event(
        home,
        NOW - DAY + 3,
        105,
        "start_failed",
        Some("port_unavailable"),
    );
    event(home, NOW - 10, 106, "ready", None);
    event(
        home,
        NOW - 9,
        107,
        "repair_requested",
        Some("daemon_repair"),
    );
    event(
        home,
        NOW - 8,
        108,
        "recovery_requested",
        Some("transport_failure"),
    );
    event(
        home,
        NOW - 7,
        108,
        "recovery_requested",
        Some("transport_failure"),
    );
    event(
        home,
        NOW - 6,
        109,
        "recovery_requested",
        Some("no_resident"),
    );
    // After `now`: not counted.
    event(home, NOW + DAY, 110, "exiting", Some("signal_term"));

    let week = report(home, json!({"days": 7}));
    assert_eq!(week["schema"], "hol-guard-daemon-reliability.v1");
    assert_eq!(
        week["window"],
        json!({"days": 7, "since_ns": NOW - 7 * DAY, "until_ns": NOW})
    );
    assert_eq!(
        week["daemon_exits"],
        json!({"total": 4, "by_cause": {
            "exiting:signal_term": 1,
            "retirement_requested:requested_retire": 1,
            "start_failed:port_unavailable": 1,
            "unclean_exit_detected": 1,
        }})
    );
    assert_eq!(
        week["ready_per_day"],
        json!({"2026-11-15": 1, "2026-11-16": 2})
    );
    assert_eq!(
        week["repairs"],
        json!({"total": 1, "per_day": {"2026-11-16": 1}})
    );
    assert_eq!(
        week["recovery_requests"],
        json!({"total": 3, "by_reason": {"no_resident": 1, "transport_failure": 2}})
    );
    assert_eq!(week["journal"]["status"], "ok");
    assert_eq!(
        week["journal"]["lifecycle_oldest_ns"],
        json!(NOW - 20 * DAY)
    );
    assert_eq!(week["journal"]["recovery_oldest_ns"], json!(NOW - 8));

    let month = report(home, json!({}));
    assert_eq!(month["window"]["days"], 30);
    assert_eq!(month["daemon_exits"]["by_cause"]["exiting:signal_term"], 2);
}

#[test]
fn failed_launches_are_counted_by_code_across_the_rotated_log() {
    let home = private_home();
    let home = home.path();
    let line = |code: &str, at: u64| {
        json!({"code": code, "kind": "panic", "pid": 7, "recorded_at_ns": at, "version": 1})
            .to_string()
    };
    write_private(
        &home.join("logs/runtime-failures.jsonl.1"),
        &[
            line("runtime_panic", NOW - 40 * DAY),
            line("runtime_panic", NOW - 3 * DAY),
        ]
        .join("\n"),
    );
    write_private(
        &home.join("logs/runtime-failures.jsonl"),
        &[
            line("runtime_panic", NOW - DAY),
            line("stdout_closed", NOW - 5),
            line("/Users/someone/secret path", NOW - 4),
            "not json".to_owned(),
            json!({"recorded_at_ns": NOW}).to_string(),
        ]
        .join("\n"),
    );

    assert_eq!(
        report(home, json!({}))["failed_launches"],
        json!({
            "status": "ok",
            "total": 4,
            "by_code": {"runtime_panic": 2, "stdout_closed": 1, "unlabelled": 1},
            "invalid_lines": 2,
        })
    );
}

#[test]
fn a_home_without_records_reports_each_section_as_absent() {
    let home = private_home();
    let answer = report(home.path(), json!({}));
    assert_eq!(answer["journal"]["status"], "journal_unavailable");
    assert_eq!(answer["daemon_exits"], json!({"total": 0, "by_cause": {}}));
    assert_eq!(answer["failed_launches"]["status"], "no_failures_recorded");
    assert_eq!(answer["crash_reports"], json!({"status": "not_checked"}));
    assert_eq!(answer["orphaned_daemons"], json!({"status": "not_checked"}));
}

#[test]
fn a_linked_journal_and_damaged_entries_are_not_read() {
    let home = private_home();
    let elsewhere = private_home();
    event(
        elsewhere.path(),
        NOW - 5,
        101,
        "exiting",
        Some("signal_term"),
    );
    std::os::unix::fs::symlink(
        elsewhere.path().join("daemon-lifecycle"),
        home.path().join("daemon-lifecycle"),
    )
    .unwrap();
    let linked = report(home.path(), json!({}));
    assert_eq!(linked["journal"]["status"], "journal_path_unsafe");
    assert_eq!(linked["daemon_exits"]["total"], 0);

    let damaged = elsewhere.path().join("daemon-lifecycle");
    fs::write(damaged.join("00000000000000000001-0000000001-0.json"), "{").unwrap();
    let shared = damaged.join("00000000000000000002-0000000002-0.json");
    fs::write(
        &shared,
        json!({"event": "exiting", "pid": 2, "recorded_at_ns": NOW - 4, "version": 1}).to_string(),
    )
    .unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o644)).unwrap();
    let answer = report(elsewhere.path(), json!({}));
    assert_eq!(answer["journal"]["status"], "invalid_entries_omitted");
    assert_eq!(answer["journal"]["invalid_entries"], 2);
    assert_eq!(answer["daemon_exits"]["total"], 1);
}

fn crash_report(directory: &Path, name: &str, path: &str, frames: &[&str]) {
    let header = json!({"app_name": "hol-guard-runtime", "bug_type": "309"});
    let frames: Vec<Value> = frames
        .iter()
        .map(|symbol| json!({"symbol": symbol}))
        .collect();
    let body = json!({
        "procPath": path,
        "threads": [
            {"frames": [{"symbol": "std::io::stdio::_eprint"}]},
            {"triggered": true, "frames": frames},
        ],
    });
    fs::write(directory.join(name), format!("{header}\n{body}")).unwrap();
}

#[test]
fn crash_reports_are_counted_by_origin_and_stack() {
    let home = private_home();
    let crashes = tempfile::tempdir().unwrap();
    let directory = crashes.path();
    crash_report(
        directory,
        "hol-guard-runtime-2026-11-16-101010.ips",
        "/private/tmp/*/hol-guard-runtime",
        &[
            "__pthread_kill",
            "std::io::stdio::_eprint",
            "hol_guard_runtime::launch::{{closure}}",
        ],
    );
    crash_report(
        directory,
        "hol-guard-runtime-2026-11-16-101011.ips",
        "/Users/U/Library/Application Support/org.hol.guard.desktop/*/hol-guard-runtime",
        &["__pthread_kill", "core::panicking::panic"],
    );
    crash_report(
        directory,
        "hol-guard-runtime-2026-11-16-101012.ips",
        "/Users/U/*/hol-guard-runtime",
        // The double-panic frames on a thread that did not crash do not count.
        &["__pthread_kill"],
    );
    crash_report(
        directory,
        "other-tool-2026-11-16-101013.ips",
        "/private/tmp/*/other-tool",
        &["std::io::stdio::_eprint", "hol_guard_runtime::launch"],
    );
    fs::write(directory.join("hol-guard-runtime-damaged.ips"), "{}").unwrap();

    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let answer = ask(
        home.path(),
        "reliability",
        json!({"now_ns": now + DAY, "crash_reports_dir": directory}),
    );
    let reports = &answer["crash_reports"];
    assert_eq!(reports["status"], "ok");
    assert_eq!(reports["total"], 4);
    assert_eq!(
        reports["by_origin"],
        json!({"desktop": 1, "other": 1, "temporary": 1, "unreadable": 1})
    );
    assert_eq!(
        reports["by_stack"],
        json!({"double_panic": 1, "other": 2, "unreadable": 1})
    );

    // Reports older than the window are left out.
    let later = ask(
        home.path(),
        "reliability",
        json!({"now_ns": now + 40 * DAY, "crash_reports_dir": directory}),
    );
    assert_eq!(later["crash_reports"]["total"], 0);

    // A relative directory is not read.
    let relative = ask(
        home.path(),
        "reliability",
        json!({"now_ns": now, "crash_reports_dir": "Library/Logs"}),
    );
    assert_eq!(relative["crash_reports"], json!({"status": "not_checked"}));
}

#[test]
fn a_daemon_run_that_several_records_end_is_one_exit() {
    let home = private_home();
    let home = home.path();
    // A retirement: the request, then the daemon's own exit on SIGTERM.
    event(home, NOW - 50, 201, "published", None);
    event(
        home,
        NOW - 49,
        201,
        "retirement_requested",
        Some("requested_retire"),
    );
    event(home, NOW - 48, 201, "exiting", Some("signal_term"));
    // One death seen by two launchers.
    event(home, NOW - 40, 202, "published", None);
    event(
        home,
        NOW - 39,
        202,
        "death_observed",
        Some("process_missing"),
    );
    event(
        home,
        NOW - 38,
        202,
        "death_observed",
        Some("process_missing"),
    );
    // The same pid running again later is a second run with its own exit.
    event(home, NOW - 30, 201, "published", None);
    event(home, NOW - 29, 201, "exiting", Some("signal_term"));

    assert_eq!(
        report(home, json!({}))["daemon_exits"],
        json!({"total": 3, "by_cause": {
            "death_observed": 1,
            "exiting:signal_term": 1,
            "retirement_requested:requested_retire": 1,
        }})
    );
}

#[test]
fn a_failed_start_on_a_reused_pid_is_its_own_exit() {
    let home = private_home();
    let home = home.path();
    event(home, NOW - 50, 301, "published", None);
    event(home, NOW - 49, 301, "exiting", Some("signal_term"));
    // The OS hands pid 301 to a later daemon whose start fails before it
    // publishes; its own exit record folds into that failed start.
    event(
        home,
        NOW - 30,
        301,
        "start_failed",
        Some("port_unavailable"),
    );
    event(home, NOW - 29, 301, "exiting", Some("start_failed"));

    assert_eq!(
        report(home, json!({}))["daemon_exits"],
        json!({"total": 2, "by_cause": {
            "exiting:signal_term": 1,
            "start_failed:port_unavailable": 1,
        }})
    );
}

#[test]
fn other_apps_crash_reports_do_not_end_the_scan() {
    let home = private_home();
    let crashes = tempfile::tempdir().unwrap();
    let directory = crashes.path();
    for index in 0..2_100 {
        fs::write(directory.join(format!("OtherApp-{index:05}.ips")), "{}").unwrap();
    }
    crash_report(
        directory,
        "hol-guard-runtime-2026-11-16-101010.ips",
        "/opt/hol-guard-runtime",
        &["core::panicking::panic"],
    );
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let answer = ask(
        home.path(),
        "reliability",
        json!({"now_ns": now + DAY, "crash_reports_dir": directory}),
    );
    assert_eq!(answer["crash_reports"]["status"], "ok");
    assert_eq!(answer["crash_reports"]["total"], 1);
}

#[test]
fn a_failure_log_that_cannot_be_trusted_is_not_reported_as_no_failures() {
    let home = private_home();
    let log = home.path().join("logs").join("runtime-failures.jsonl");
    write_private(
        &log,
        &format!(
            "{}\n",
            json!({"code": "spawn_failed", "recorded_at_ns": NOW - 5})
        ),
    );
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();

    let launches = &report(home.path(), json!({}))["failed_launches"];
    assert_eq!(launches["status"], "log_unreadable");
    assert_eq!(launches["total"], 0);
}

#[test]
fn a_recorded_repair_is_counted_and_nothing_else_is_written() {
    let home = private_home();
    assert_eq!(
        ask(home.path(), "record_repair", json!({})),
        json!({"done": true})
    );
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let answer = ask(
        home.path(),
        "reliability",
        json!({"now_ns": now + 1_000_000_000}),
    );
    assert_eq!(answer["repairs"]["total"], 1);
    assert_eq!(answer["daemon_exits"]["total"], 0);
    let entries: Vec<_> = fs::read_dir(home.path().join("daemon-lifecycle"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn listing_processes_never_lists_the_published_daemon() {
    let home = private_home();
    write_private(
        &super::super::records::state_path(home.path()),
        &json!({"pid": std::process::id()}).to_string(),
    );
    let answer = report(home.path(), json!({"processes": true}));
    let orphaned = &answer["orphaned_daemons"];
    assert!(
        matches!(orphaned["status"].as_str(), Some("known" | "unknown")),
        "{orphaned}"
    );
    let own = i64::from(std::process::id());
    assert!(!orphaned["pids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|pid| pid.as_i64() == Some(own)));
}
