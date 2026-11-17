//! `hol-guard doctor reliability`: what the records in a Guard home say about
//! the daemon over a window of days (30 unless asked otherwise).
//!
//! Everything here reads; nothing is started, signalled or repaired. The
//! report counts:
//!
//! - daemon exits by cause, from the lifecycle journal (`exiting`,
//!   `retirement_requested`, `start_failed`, `shutdown_requested`,
//!   `unclean_exit_detected`, `death_observed`);
//! - daemon starts that reached `ready`, per UTC day;
//! - failed runtime launches by error code, from `logs/runtime-failures.jsonl`;
//! - runtime crash reports in a directory the caller names, by where the
//!   binary ran from and whether the stack is the stderr double panic;
//! - `daemon repair` runs (`repair_requested`);
//! - recovery requests by reason, the degraded state hooks report;
//! - daemons of this home still running besides the published one.
//!
//! Each section says how far back its records reach, because the journal
//! rings are bounded and a short ring can cover less than the window.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::host::{self, Caller};
use super::records;
use crate::daemon_edge::lifecycle;

const DEFAULT_DAYS: u64 = 30;
const MAX_DAYS: u64 = 90;
const NANOS_PER_DAY: u64 = 86_400 * 1_000_000_000;
const MAX_JOURNAL_SCAN: usize = 4096;
const FAILURE_LOGS: [&str; 2] = ["runtime-failures.jsonl.1", "runtime-failures.jsonl"];
const MAX_FAILURE_LOG_BYTES: u64 = 512 * 1024;
const CRASH_REPORT_PREFIX: &str = "hol-guard-runtime";
const CRASH_REPORT_SUFFIX: &str = ".ips";
const MAX_CRASH_REPORTS: usize = 2000;
const MAX_CRASH_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LABEL_BYTES: usize = 64;
/// Frames of the abort #7926 removed: the panic hook's own `eprintln!`
/// panicking inside `launch`.
const DOUBLE_PANIC_FRAMES: [&str; 2] = ["std::io::stdio::_eprint", "hol_guard_runtime::launch"];

/// The report for `caller`'s Guard home.
pub(super) fn report(caller: &Caller, args: &Map<String, Value>) -> Value {
    let days = args
        .get("days")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_DAYS)
        .clamp(1, MAX_DAYS);
    let now_ns = args
        .get("now_ns")
        .and_then(Value::as_u64)
        .unwrap_or_else(now_ns);
    let since_ns = now_ns.saturating_sub(days * NANOS_PER_DAY);
    let home = caller.guard_home.as_path();
    let (events, journal_status) = journal(home, since_ns, now_ns);
    let crash_reports = args
        .get("crash_reports_dir")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .map_or_else(
            || json!({"status": "not_checked"}),
            |directory| crash_reports(directory, since_ns, now_ns),
        );
    let processes = if args.get("processes").and_then(Value::as_bool) == Some(true) {
        orphaned_daemons(caller)
    } else {
        json!({"status": "not_checked"})
    };
    json!({
        "schema": "hol-guard-daemon-reliability.v1",
        "window": {"days": days, "since_ns": since_ns, "until_ns": now_ns},
        "journal": journal_status,
        "daemon_exits": exits(&events),
        "ready_per_day": per_day(&events, |event| event_name(event) == "ready"),
        "repairs": repairs(&events),
        "recovery_requests": recovery_requests(&events),
        "failed_launches": failed_launches(home, since_ns, now_ns),
        "crash_reports": crash_reports,
        "orphaned_daemons": processes,
    })
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0)
}

/// Every valid journal record inside the window, oldest first, and how far
/// back each ring reaches.
fn journal(home: &Path, since_ns: u64, until_ns: u64) -> (Vec<Value>, Value) {
    let directory = home.join(lifecycle::DIRECTORY);
    if lifecycle::is_symlink(&directory) {
        return (Vec::new(), json!({"status": "journal_path_unsafe"}));
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return (Vec::new(), json!({"status": "journal_unavailable"}));
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') && name.ends_with(".json") {
            names.push(name);
        }
    }
    let mut status = "ok";
    if names.len() > MAX_JOURNAL_SCAN {
        names.sort_unstable_by(|left, right| right.cmp(left));
        names.truncate(MAX_JOURNAL_SCAN);
        status = "journal_scan_limit";
    }
    let mut events = Vec::new();
    let mut oldest: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut invalid = 0_u64;
    for name in &names {
        let Some(event) = lifecycle::read_event(&directory.join(name)) else {
            invalid += 1;
            continue;
        };
        let at = recorded_at(&event);
        let ring = if event_name(&event) == "recovery_requested" {
            "recovery"
        } else {
            "lifecycle"
        };
        oldest
            .entry(ring)
            .and_modify(|current| *current = (*current).min(at))
            .or_insert(at);
        if (since_ns..=until_ns).contains(&at) {
            events.push(event);
        }
    }
    events.sort_by_key(recorded_at);
    if invalid > 0 && status == "ok" {
        status = "invalid_entries_omitted";
    }
    let summary = json!({
        "status": status,
        "invalid_entries": invalid,
        "lifecycle_oldest_ns": oldest.get("lifecycle"),
        "recovery_oldest_ns": oldest.get("recovery"),
    });
    (events, summary)
}

fn event_name(event: &Value) -> &str {
    event.get("event").and_then(Value::as_str).unwrap_or("")
}

fn reason(event: &Value) -> &str {
    event
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn recorded_at(event: &Value) -> u64 {
    event
        .get("recorded_at_ns")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// `exiting:signal_term`, `retirement_requested:requested_retire`,
/// `unclean_exit_detected` and so on, with a count for each.
fn exits(events: &[Value]) -> Value {
    let mut by_cause: BTreeMap<String, u64> = BTreeMap::new();
    for event in events {
        let cause = match event_name(event) {
            name @ ("exiting" | "retirement_requested" | "start_failed" | "shutdown_requested") => {
                format!("{name}:{}", reason(event))
            }
            name @ ("unclean_exit_detected" | "death_observed") => name.to_owned(),
            _ => continue,
        };
        *by_cause.entry(cause).or_default() += 1;
    }
    let total: u64 = by_cause.values().sum();
    json!({"total": total, "by_cause": by_cause})
}

fn repairs(events: &[Value]) -> Value {
    let matches = |event: &Value| event_name(event) == "repair_requested";
    let total = events.iter().filter(|event| matches(event)).count();
    json!({"total": total, "per_day": per_day(events, matches)})
}

fn recovery_requests(events: &[Value]) -> Value {
    let mut by_reason: BTreeMap<&str, u64> = BTreeMap::new();
    for event in events {
        if event_name(event) == "recovery_requested" {
            *by_reason.entry(reason(event)).or_default() += 1;
        }
    }
    let total: u64 = by_reason.values().sum();
    json!({"total": total, "by_reason": by_reason})
}

fn per_day(events: &[Value], matches: impl Fn(&Value) -> bool) -> BTreeMap<String, u64> {
    let mut days = BTreeMap::new();
    for event in events.iter().filter(|event| matches(event)) {
        *days.entry(utc_day(recorded_at(event))).or_default() += 1;
    }
    days
}

/// `YYYY-MM-DD` in UTC.
fn utc_day(at_ns: u64) -> String {
    let days = i64::try_from(at_ns / NANOS_PER_DAY).unwrap_or(0);
    let (year, month, day) = crate::guard_store_json::civil_date(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Failed launches by error code, from the bounded failure log and its one
/// rotated predecessor. Only records inside the window count.
fn failed_launches(home: &Path, since_ns: u64, until_ns: u64) -> Value {
    let directory = home.join("logs");
    let mut by_code: BTreeMap<String, u64> = BTreeMap::new();
    let mut found = false;
    let mut invalid = 0_u64;
    for name in FAILURE_LOGS {
        let Some(text) = crate::daemon_policy_authority::read_private_regular_text(
            &directory.join(name),
            MAX_FAILURE_LOG_BYTES,
            false,
        ) else {
            continue;
        };
        found = true;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                invalid += 1;
                continue;
            };
            let at = recorded_at(&record);
            let code = record.get("code").and_then(Value::as_str).map(label);
            match code {
                Some(code) if (since_ns..=until_ns).contains(&at) => {
                    *by_code.entry(code).or_default() += 1;
                }
                Some(_) => {}
                None => invalid += 1,
            }
        }
    }
    let total: u64 = by_code.values().sum();
    json!({
        "status": if found { "ok" } else { "no_failures_recorded" },
        "total": total,
        "by_code": by_code,
        "invalid_lines": invalid,
    })
}

/// A record's code cut to a short label, so a damaged line cannot put a
/// path or a long string into the report.
fn label(value: &str) -> String {
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

/// Runtime crash reports modified inside the window. `origin` is where the
/// crashed binary ran from: `temporary` (a temporary directory, as a test
/// build is), `desktop` (inside Guard Desktop's app data) or `other`.
fn crash_reports(directory: &Path, since_ns: u64, until_ns: u64) -> Value {
    let Ok(entries) = fs::read_dir(directory) else {
        return json!({"status": "unavailable"});
    };
    let mut by_origin: BTreeMap<&str, u64> = BTreeMap::new();
    let mut by_stack: BTreeMap<&str, u64> = BTreeMap::new();
    let mut per_day: BTreeMap<String, u64> = BTreeMap::new();
    let mut status = "ok";
    for (index, entry) in entries.flatten().enumerate() {
        if index >= MAX_CRASH_REPORTS {
            status = "scan_limit";
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(CRASH_REPORT_PREFIX) || !name.ends_with(CRASH_REPORT_SUFFIX) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .and_then(|at| u64::try_from(at.as_nanos()).ok())
            .unwrap_or(0);
        if !metadata.is_file() || !(since_ns..=until_ns).contains(&modified) {
            continue;
        }
        let report = read_crash_report(&entry.path(), metadata.len());
        let (origin, stack) = report
            .as_ref()
            .map_or(("unreadable", "unreadable"), |body| {
                (crash_origin(body), crash_stack(body))
            });
        *by_origin.entry(origin).or_default() += 1;
        *by_stack.entry(stack).or_default() += 1;
        *per_day.entry(utc_day(modified)).or_default() += 1;
    }
    let total: u64 = by_origin.values().sum();
    json!({
        "status": status,
        "total": total,
        "by_origin": by_origin,
        "by_stack": by_stack,
        "per_day": per_day,
    })
}

/// The body of an `.ips` report: a JSON header line, then a JSON document.
fn read_crash_report(path: &Path, length: u64) -> Option<Value> {
    if length > MAX_CRASH_REPORT_BYTES {
        return None;
    }
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_CRASH_REPORT_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let (_, body) = text.split_once('\n')?;
    serde_json::from_str(body).ok()
}

fn crash_origin(body: &Value) -> &'static str {
    let path = body.get("procPath").and_then(Value::as_str).unwrap_or("");
    if [
        "/private/tmp/",
        "/tmp/",
        "/private/var/folders/",
        "/var/folders/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        "temporary"
    } else if path.contains("/org.hol.guard.desktop/") {
        "desktop"
    } else {
        "other"
    }
}

/// `double_panic` when the crashed thread shows the panic hook's `eprintln!`
/// panicking inside `launch`, `other` for any other stack.
fn crash_stack(body: &Value) -> &'static str {
    let crashed = body
        .get("threads")
        .and_then(Value::as_array)
        .and_then(|threads| {
            threads
                .iter()
                .find(|thread| thread.get("triggered").and_then(Value::as_bool) == Some(true))
        });
    let symbols: Vec<&str> = crashed
        .and_then(|thread| thread.get("frames"))
        .and_then(Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .filter_map(|frame| frame.get("symbol").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let shows = |needle: &str| symbols.iter().any(|symbol| symbol.starts_with(needle));
    if DOUBLE_PANIC_FRAMES.iter().all(|needle| shows(needle)) {
        "double_panic"
    } else {
        "other"
    }
}

/// Daemons of this home that are running but are not the one its state
/// publishes. Only proven daemons are listed; nothing is signalled.
fn orphaned_daemons(caller: &Caller) -> Value {
    let published = records::load_state_unverified(&caller.guard_home)
        .and_then(|state| state.get("pid").and_then(Value::as_i64));
    match host::daemon_inventory(caller) {
        Some(processes) => {
            let pids: Vec<i64> = processes
                .into_iter()
                .map(|(pid, _)| pid)
                .filter(|pid| Some(*pid) != published)
                .collect();
            json!({"status": "known", "published_pid": published, "pids": pids})
        }
        None => json!({"status": "unknown", "published_pid": published, "pids": []}),
    }
}

/// Records that `daemon repair` ran, for the report's `repairs` count.
pub(super) fn record_repair(caller: &Caller) -> Value {
    let pid = u32::try_from(caller.own_pid).unwrap_or(0);
    lifecycle::record_for_pid(
        &caller.guard_home,
        pid,
        "repair_requested",
        Some("daemon_repair"),
        None,
    );
    json!({"done": pid > 0})
}

#[cfg(all(test, unix))]
#[path = "daemon_manage_reliability_tests.rs"]
mod tests;
