use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{Local, NaiveDate};
use serde_json::{json, Value};

use super::text::{grouped, render};
use super::{scan, summarize, Files, CACHE_NAME};

struct Homes {
    _root: tempfile::TempDir,
    home: PathBuf,
    guard: PathBuf,
    rollouts: PathBuf,
    projects: PathBuf,
}

fn homes() -> Homes {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let guard = root.path().join("guard");
    let rollouts = home.join(".codex/sessions/2026/11/05");
    let projects = home.join(".claude/projects/-work-alpha");
    std::fs::create_dir_all(&rollouts).unwrap();
    std::fs::create_dir_all(&projects).unwrap();
    Homes {
        _root: root,
        home,
        guard,
        rollouts,
        projects,
    }
}

fn now() -> f64 {
    super::now()
}

fn today() -> NaiveDate {
    Local::now().date_naive()
}

fn stamp() -> String {
    Local::now().to_rfc3339()
}

fn line(record: &Value) -> String {
    format!("{record}\n")
}

fn codex_usage(total: u64, cached: u64, output: u64, at: &str) -> String {
    line(
        &json!({"timestamp": at, "type": "token_usage_record", "payload": {"usage": {
        "input_tokens": total, "cached_input_tokens": cached,
        "cache_write_input_tokens": 0, "output_tokens": output}}}),
    )
}

fn claude(id: &str, fresh: u64, read: u64, written: u64, output: u64, model: &str) -> String {
    line(
        &json!({"timestamp": stamp(), "type": "assistant", "cwd": "/work/alpha",
        "message": {"id": id, "model": model, "content": [{"type": "text"}], "usage": {
            "input_tokens": fresh, "cache_read_input_tokens": read,
            "cache_creation_input_tokens": written, "output_tokens": output}}}),
    )
}

fn scan_now(homes: &Homes) -> Files {
    scan(&homes.home, &homes.guard, |_| None, now())
}

fn week(files: &Files, harness: &str) -> Value {
    summarize(files, today())["week"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["harness"] == harness)
        .unwrap()
        .clone()
}

fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

fn age(path: &Path, seconds: u64) {
    let at = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
    let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.set_modified(at).unwrap();
}

#[test]
fn codex_rollout_counts_requests_compactions_and_the_model() {
    let homes = homes();
    let at = stamp();
    let text = [
        line(&json!({"timestamp": at, "type": "turn_context", "payload": {"model": "gpt-test", "cwd": "/work/beta"}})),
        line(&json!({"timestamp": at, "type": "response_item", "payload": {"text": "token_usage_record"}})),
        codex_usage(1000, 800, 50, &at),
        codex_usage(1200, 1000, 70, &at),
        line(&json!({"timestamp": at, "type": "compacted", "payload": {}})),
    ]
    .concat();
    std::fs::write(homes.rollouts.join("rollout-a.jsonl"), text).unwrap();
    let codex = week(&scan_now(&homes), "codex");
    assert_eq!(codex["sessions"], 1);
    assert_eq!(
        codex["totals"],
        json!({"uncached_input_tokens": 400, "cached_input_tokens": 1800, "cache_write_tokens": 0,
            "output_tokens": 120, "requests": 2, "compactions": 1})
    );
    assert_eq!(codex["recent"][0]["model"], "gpt-test");
    assert_eq!(codex["recent"][0]["folder"], "beta");
}

#[test]
fn claude_code_counts_one_response_once_even_when_it_is_logged_again() {
    let homes = homes();
    let filler: String = (0..300)
        .map(|_| line(&json!({"type": "user", "message": {"content": "x"}})))
        .collect();
    let text = [
        claude("msg_one", 3, 100, 10, 7, "claude-test"),
        claude("msg_one", 3, 100, 10, 7, "claude-test"),
        claude("msg_two", 5, 200, 0, 9, "claude-test"),
        filler,
        claude("msg_one", 3, 100, 10, 7, "claude-test"),
        claude("msg_syn", 0, 0, 0, 0, "<synthetic>"),
        line(&json!({"timestamp": stamp(), "type": "system", "subtype": "compact_boundary"})),
    ]
    .concat();
    std::fs::write(homes.projects.join("session-1.jsonl"), text).unwrap();
    let subagents = homes.projects.join("session-1/subagents");
    std::fs::create_dir_all(&subagents).unwrap();
    std::fs::write(
        subagents.join("agent-a.jsonl"),
        claude("msg_sub", 1, 10, 0, 2, "claude-test"),
    )
    .unwrap();
    let tool = week(&scan_now(&homes), "claude-code");
    assert_eq!(tool["sessions"], 1);
    assert_eq!(
        tool["totals"],
        json!({"uncached_input_tokens": 9, "cached_input_tokens": 310, "cache_write_tokens": 10,
            "output_tokens": 18, "requests": 4, "compactions": 1})
    );
    assert_eq!(tool["recent"][0]["model"], "claude-test");
    assert_eq!(tool["recent"][0]["folder"], "alpha");
}

#[test]
fn a_later_scan_reads_only_new_lines_and_waits_for_a_half_written_one() {
    let homes = homes();
    let at = stamp();
    let rollout = homes.rollouts.join("rollout-b.jsonl");
    let first = codex_usage(100, 0, 1, &at);
    std::fs::write(&rollout, &first).unwrap();
    assert_eq!(week(&scan_now(&homes), "codex")["totals"]["requests"], 1);
    let partial = codex_usage(200, 0, 2, &at);
    let (head, tail) = partial.split_at(partial.len() - 20);
    append(&rollout, head);
    assert_eq!(week(&scan_now(&homes), "codex")["totals"]["requests"], 1);
    append(&rollout, &format!("{tail}{}", codex_usage(300, 0, 3, &at)));
    let cache: Value =
        serde_json::from_slice(&std::fs::read(homes.guard.join(CACHE_NAME)).unwrap()).unwrap();
    let entry = cache["files"].as_object().unwrap().values().next().unwrap();
    assert_eq!(entry["offset"], first.len());
    let totals = week(&scan_now(&homes), "codex")["totals"].clone();
    assert_eq!(totals["requests"], 3);
    assert_eq!(totals["uncached_input_tokens"], 600);
}

#[test]
fn the_dedupe_window_survives_between_scans() {
    let homes = homes();
    let transcript = homes.projects.join("session-2.jsonl");
    std::fs::write(&transcript, claude("msg_keep", 1, 1, 1, 1, "claude-test")).unwrap();
    age(&transcript, 7_200);
    scan_now(&homes);
    append(&transcript, &claude("msg_keep", 1, 1, 1, 1, "claude-test"));
    assert_eq!(
        week(&scan_now(&homes), "claude-code")["totals"]["requests"],
        1
    );
}

#[test]
fn a_file_that_was_rewritten_shorter_is_counted_again_from_the_start() {
    let homes = homes();
    let at = stamp();
    let rollout = homes.rollouts.join("rollout-c.jsonl");
    std::fs::write(&rollout, codex_usage(100, 0, 1, &at).repeat(2)).unwrap();
    scan_now(&homes);
    std::fs::write(&rollout, codex_usage(50, 0, 1, &at)).unwrap();
    let totals = week(&scan_now(&homes), "codex")["totals"].clone();
    assert_eq!(
        (
            totals["requests"].clone(),
            totals["uncached_input_tokens"].clone()
        ),
        (json!(1), json!(50))
    );
}

#[test]
fn today_and_the_week_leave_out_older_days_and_old_files() {
    let homes = homes();
    let at = stamp();
    let old = (Local::now() - chrono::Duration::days(10)).to_rfc3339();
    std::fs::write(
        homes.rollouts.join("rollout-d.jsonl"),
        codex_usage(100, 0, 1, &at) + &codex_usage(999, 0, 1, &old),
    )
    .unwrap();
    let stale = homes.rollouts.join("rollout-e.jsonl");
    std::fs::write(&stale, codex_usage(5000, 0, 1, &at)).unwrap();
    age(&stale, 9 * 86_400);
    let summary = summarize(&scan_now(&homes), today());
    for window in ["today", "week"] {
        let codex = summary[window]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["harness"] == "codex")
            .unwrap();
        assert_eq!(codex["totals"]["uncached_input_tokens"], 100);
        assert_eq!(codex["sessions"], 1);
    }
    assert_eq!(
        summary["unread"],
        json!(["copilot", "cursor", "gemini", "opencode", "pi"])
    );
}

#[test]
fn tool_homes_follow_their_environment_variables() {
    let homes = homes();
    let at = stamp();
    let custom = homes.home.parent().unwrap().join("custom-codex");
    std::fs::create_dir_all(custom.join("sessions")).unwrap();
    std::fs::write(
        custom.join("sessions/rollout-f.jsonl"),
        codex_usage(10, 0, 1, &at),
    )
    .unwrap();
    std::fs::write(
        homes.rollouts.join("rollout-g.jsonl"),
        codex_usage(99, 0, 1, &at),
    )
    .unwrap();
    let env = HashMap::from([(
        "CODEX_HOME".to_owned(),
        custom.to_string_lossy().into_owned(),
    )]);
    let files = scan(
        &homes.home,
        &homes.guard,
        |name| env.get(name).cloned(),
        now(),
    );
    assert_eq!(week(&files, "codex")["totals"]["uncached_input_tokens"], 10);
}

/// `read` until its background count is ready.
fn read_ready(homes: &Homes, env: &HashMap<String, String>) -> Value {
    for _ in 0..500 {
        let state = super::read(&homes.home, &homes.guard, env.clone());
        if state["state"] == "ready" {
            return state;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("the usage count never finished");
}

#[test]
fn each_callers_folders_are_counted_apart() {
    let homes = homes();
    let at = stamp();
    let custom = homes.home.parent().unwrap().join("custom-codex");
    std::fs::create_dir_all(custom.join("sessions")).unwrap();
    std::fs::write(
        custom.join("sessions/rollout-f.jsonl"),
        codex_usage(10, 0, 1, &at),
    )
    .unwrap();
    std::fs::write(
        homes.rollouts.join("rollout-g.jsonl"),
        codex_usage(99, 0, 1, &at),
    )
    .unwrap();
    let custom_env = HashMap::from([(
        "CODEX_HOME".to_owned(),
        custom.to_string_lossy().into_owned(),
    )]);
    let codex_input = |state: &Value| state["week"][0]["totals"]["uncached_input_tokens"].clone();
    assert_eq!(codex_input(&read_ready(&homes, &custom_env)), 10);
    // A second caller within the refresh window still gets its own folders.
    assert_eq!(codex_input(&read_ready(&homes, &HashMap::new())), 99);
    assert_eq!(codex_input(&read_ready(&homes, &custom_env)), 10);
}

#[test]
fn no_records_reports_zero_sessions_not_an_estimate() {
    let homes = homes();
    let summary = summarize(&scan_now(&homes), today());
    let rows: Vec<(Value, Value, Value)> = summary["week"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| {
            (
                tool["harness"].clone(),
                tool["sessions"].clone(),
                tool["totals"]["requests"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (json!("codex"), json!(0), json!(0)),
            (json!("claude-code"), json!(0), json!(0))
        ]
    );
}

#[test]
fn a_cache_written_before_keeps_its_offsets() {
    let homes = homes();
    let at = stamp();
    let rollout = homes.rollouts.join("rollout-h.jsonl");
    let first = codex_usage(100, 0, 1, &at);
    std::fs::write(&rollout, &first).unwrap();
    let files = scan_now(&homes);
    let key = files.keys().next().unwrap().clone();
    assert!(key.starts_with("codex:"));
    // The next scan reuses the saved entry instead of counting the line again.
    let again = scan_now(&homes);
    assert_eq!(again[&key].offset, first.len() as u64);
    assert_eq!(week(&again, "codex")["totals"]["requests"], 1);
    std::fs::write(
        homes.guard.join(CACHE_NAME),
        b"{\"version\":9,\"files\":{}}",
    )
    .unwrap();
    assert_eq!(week(&scan_now(&homes), "codex")["totals"]["requests"], 1);
}

#[test]
fn the_cli_text_names_the_tables_and_labels_the_estimate() {
    assert_eq!(grouped(0), "0");
    assert_eq!(grouped(1_234_567), "1,234,567");
    let homes = homes();
    std::fs::write(
        homes.rollouts.join("rollout-i.jsonl"),
        codex_usage(1500, 0, 20, &stamp()),
    )
    .unwrap();
    let state = summarize(&scan_now(&homes), today());
    let none = render(&state, &Value::Null);
    assert!(none.contains("Codex: 1 session"));
    let row = format!(
        "  {:24}{:>18}{:>20}",
        "Input at full price", "1,500", "1,500"
    );
    assert!(none.contains(&row));
    assert!(none.contains("Claude Code: no sessions in the last 7 days."));
    assert!(none.contains("Copilot, Cursor, Gemini, OpenCode or Pi"));
    assert!(none.contains("did not answer, so it cannot estimate"));
    let report = json!({"window_days": 7, "apps": [{"app": "codex", "rate_percent": 60}],
        "total": {"sessions": 3, "measured_sessions": 2, "used_tokens": 9000,
            "estimated_saved_tokens": 12345, "prompts": 1, "context_tokens": 800,
            "files_checked": 4, "files_opened_anyway": 1}});
    let text = render(&state, &report);
    assert!(
        text.contains("CIGAR saved about 12,345 tokens in the last 7 days. This is an estimate.")
    );
    assert!(text.contains("The estimate covers 2 of 3 sessions."));
    assert!(text.contains("It handed 1 prompt about 800 tokens of code."));
    assert!(text.contains("Of 4 files it showed, the agent opened 1 again anyway."));
    assert!(text.contains("benchmark (Codex 60%)"));
}
