use super::report::{rate, report_at, saved};
use super::*;
use std::path::PathBuf;

const DAY: u64 = 86_400;
/// 2026-11-14T09:00:00Z; the fixture records are dated an hour later.
const NOW: u64 = 1_794_646_800;

fn added<'a>(app: &'a str, id: &'a str, transcript: Option<&'a str>, files: &[&str]) -> Added<'a> {
    Added {
        app,
        id,
        transcript,
        chars: 4_000,
        files: files.iter().map(|file| (*file).to_owned()).collect(),
    }
}

fn shown(files: &[String], at: u64) -> Vec<Shown> {
    files
        .iter()
        .map(|path| Shown {
            path: path.clone(),
            at,
            last: at,
        })
        .collect()
}

fn paths(files: &[Shown]) -> Vec<&str> {
    files.iter().map(|file| file.path.as_str()).collect()
}

fn no_env(_: &str) -> Option<String> {
    None
}

struct Homes {
    _dir: tempfile::TempDir,
    guard: PathBuf,
    home: PathBuf,
}

fn homes() -> Homes {
    let dir = tempfile::tempdir().unwrap();
    let guard = dir.path().join("guard");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&guard).unwrap();
    std::fs::create_dir_all(home.join(".codex/sessions/2026/11/14")).unwrap();
    std::fs::create_dir_all(home.join(".claude/projects/demo")).unwrap();
    Homes {
        _dir: dir,
        guard,
        home,
    }
}

fn write_lines(path: &Path, lines: &[String]) -> String {
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).unwrap();
    path.to_string_lossy().into_owned()
}

fn codex_record(home: &Path) -> String {
    let usage = |input: u64, output: u64| {
        format!(
            r#"{{"timestamp":"2026-11-14T10:00:00Z","type":"token_usage_record","payload":{{"usage":{{"input_tokens":{input},"cached_input_tokens":{},"cache_write_input_tokens":100,"output_tokens":{output}}}}}}}"#,
            input / 2
        )
    };
    write_lines(
        &home.join(".codex/sessions/2026/11/14/rollout-a.jsonl"),
        &[
            usage(10_000, 500),
            r#"{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"sed -n 1,80p src/billing/invoice.rs\"}"}}"#.to_owned(),
            r#"{"type":"response_item","payload":{"type":"custom_tool_call","input":"cat src/billing/invoice_test_helpers.rs"}}"#.to_owned(),
            usage(20_000, 1_500),
            "not json".to_owned(),
        ],
    )
}

fn claude_record(home: &Path) -> String {
    let block = |id: &str, kind: &str| {
        format!(
            r#"{{"type":"assistant","message":{{"id":"{id}","content":[{kind}],"usage":{{"input_tokens":100,"cache_read_input_tokens":9000,"cache_creation_input_tokens":800,"output_tokens":100}}}}}}"#
        )
    };
    write_lines(
        &home.join(".claude/projects/demo/session.jsonl"),
        &[
            block(
                "msg_1",
                r#"{"type":"text","text":"Looking at src/app/main.ts"}"#,
            ),
            // The same reply logged again for its tool block: count its usage once.
            block(
                "msg_1",
                r#"{"type":"tool_use","name":"Read","input":{"file_path":"/work/demo/src/app/main.ts"}}"#,
            ),
            block(
                "msg_2",
                r#"{"type":"tool_use","name":"Edit","input":{"file_path":"/work/demo/src/app/routes.ts"}}"#,
            ),
        ],
    )
}

#[test]
fn record_merges_one_session_and_keeps_files_once() {
    let homes = homes();
    record_at(
        &homes.guard,
        added("codex", "s1", Some("/x.jsonl"), &["a.rs", "b.rs"]),
        NOW,
    );
    record_at(
        &homes.guard,
        added("codex", "s1", None, &["b.rs", "c.rs", ""]),
        NOW + 60,
    );
    record_at(
        &homes.guard,
        added("claude-code", "s1", None, &["a.rs"]),
        NOW + 90,
    );
    let journal = load(&homes.guard);
    assert_eq!(journal.sessions.len(), 2);
    let codex = journal
        .sessions
        .iter()
        .find(|item| item.app == "codex")
        .unwrap();
    assert_eq!(
        (codex.prompts(), codex.chars(), codex.first, codex.last),
        (2, 8_000, NOW, NOW + 60)
    );
    assert_eq!(paths(&codex.files), ["a.rs", "b.rs", "c.rs"]);
    assert_eq!((codex.files[1].at, codex.files[1].last), (NOW, NOW + 60));
    // A later prompt without a record path keeps the one already known.
    assert_eq!(codex.transcript.as_deref(), Some("/x.jsonl"));
}

#[test]
fn record_skips_empty_answers_and_unnamed_sessions() {
    let homes = homes();
    let mut empty = added("codex", "s1", None, &["a.rs"]);
    empty.chars = 0;
    record_at(&homes.guard, empty, NOW);
    record_at(&homes.guard, added("codex", "  ", None, &["a.rs"]), NOW);
    let long = "x".repeat(MAX_ID_BYTES + 1);
    record_at(&homes.guard, added("codex", &long, None, &["a.rs"]), NOW);
    assert!(load(&homes.guard).sessions.is_empty());
    assert!(!homes.guard.join(FILE_NAME).exists());
}

#[test]
fn hook_payloads_are_noted_except_for_apps_that_may_drop_context() {
    let homes = homes();
    let payload = serde_json::json!({"session_id": "s1", "transcript_path": "/r.jsonl"});
    let files = || vec!["a.rs".to_owned(), String::new()];
    noted(&homes.guard, &payload, "omp", 10, files());
    noted(&homes.guard, &payload, "pi", 10, files());
    noted(&homes.guard, &payload, "codex", 0, files());
    noted(&homes.guard, &serde_json::json!({}), "codex", 10, files());
    assert!(load(&homes.guard).sessions.is_empty());
    noted(&homes.guard, &payload, "codex", 10, files());
    let journal = load(&homes.guard);
    assert_eq!(journal.sessions[0].transcript.as_deref(), Some("/r.jsonl"));
    // The once-per-session hint has no file; it is not a file shown.
    assert_eq!(paths(&journal.sessions[0].files), ["a.rs"]);
}

#[test]
fn record_drops_old_sessions_and_stays_bounded() {
    let homes = homes();
    record_at(
        &homes.guard,
        added("codex", "old", None, &["a.rs"]),
        NOW - 8 * DAY,
    );
    for index in 0..MAX_SESSIONS + 5 {
        record_at(
            &homes.guard,
            added("codex", &format!("s{index}"), None, &["a.rs"]),
            NOW,
        );
    }
    let many: Vec<String> = (0..MAX_FILES + 10)
        .map(|index| format!("f{index}.rs"))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    record_at(&homes.guard, added("codex", "wide", None, &refs), NOW);
    let journal = load(&homes.guard);
    assert_eq!(journal.sessions.len(), MAX_SESSIONS);
    assert!(journal
        .sessions
        .iter()
        .all(|item| item.id != "old" && item.id != "s0"));
    assert_eq!(journal.sessions.last().unwrap().files.len(), MAX_FILES);
}

#[test]
fn a_damaged_record_starts_over_instead_of_failing() {
    let homes = homes();
    std::fs::write(homes.guard.join(FILE_NAME), b"{not json").unwrap();
    record_at(&homes.guard, added("codex", "s1", None, &["a.rs"]), NOW);
    assert_eq!(load(&homes.guard).sessions.len(), 1);
}

#[test]
fn codex_record_gives_tokens_and_files_opened_anyway() {
    let homes = homes();
    let path = codex_record(&homes.home);
    let roots = record_roots(&homes.home, no_env);
    let files = [
        "src/billing/invoice.rs".to_owned(),
        "src/billing/tax.rs".to_owned(),
        "invoice_test".to_owned(),
    ];
    let usage = read::usage(&path, &roots, 0, &shown(&files, 0)).unwrap();
    assert_eq!(usage.requests, 2);
    // Codex input already includes cached reads and cache writes.
    assert_eq!(usage.tokens, 10_000 + 500 + 20_000 + 1_500);
    // `invoice_test` is only part of a longer name, so it was not opened.
    assert_eq!(usage.opened, ["src/billing/invoice.rs"]);
}

#[test]
fn claude_record_counts_each_reply_once_with_cache_reads() {
    let homes = homes();
    let path = claude_record(&homes.home);
    let roots = record_roots(&homes.home, no_env);
    let files = [
        "src/app/main.ts".to_owned(),
        "src/app/routes.ts".to_owned(),
        "src/app/db.ts".to_owned(),
    ];
    let usage = read::usage(&path, &roots, 0, &shown(&files, 0)).unwrap();
    assert_eq!(usage.requests, 2);
    assert_eq!(usage.tokens, 2 * 10_000);
    // Text that mentions a file is not a tool opening it.
    assert_eq!(usage.opened, ["src/app/main.ts", "src/app/routes.ts"]);
}

#[test]
fn records_outside_the_apps_folders_are_never_read() {
    let homes = homes();
    let roots = record_roots(&homes.home, no_env);
    let outside = homes.home.join("notes.jsonl");
    std::fs::write(&outside, "{}\n").unwrap();
    let wrong_kind = homes.home.join(".codex/sessions/secret.txt");
    std::fs::write(&wrong_kind, "{}\n").unwrap();
    let escape = format!("{}/.codex/sessions/../../notes.jsonl", homes.home.display());
    for path in [
        outside.to_string_lossy().into_owned(),
        wrong_kind.to_string_lossy().into_owned(),
        escape,
        "rollout.jsonl".to_owned(),
    ] {
        assert!(read::allowed(&path, &roots).is_none(), "{path}");
    }
    #[cfg(unix)]
    {
        let link = homes.home.join(".codex/sessions/link.jsonl");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(read::allowed(&link.to_string_lossy(), &roots).is_none());
    }
}

#[test]
fn app_folders_from_the_environment_are_allowed() {
    let homes = homes();
    let custom = homes.home.join("custom-codex");
    std::fs::create_dir_all(custom.join("sessions")).unwrap();
    let path = write_lines(&custom.join("sessions/rollout-b.jsonl"), &["{}".to_owned()]);
    let custom_text = custom.to_string_lossy().into_owned();
    let env = |name: &str| (name == "CODEX_HOME").then(|| custom_text.clone());
    assert!(read::allowed(&path, &record_roots(&homes.home, no_env)).is_none());
    assert!(read::allowed(&path, &record_roots(&homes.home, env)).is_some());
}

#[test]
fn whole_path_matching_ignores_longer_names() {
    assert!(read::names("cat src/a.rs", "src/a.rs"));
    assert!(read::names("{\"file_path\":\"/w/src/a.rs\"}", "src/a.rs"));
    assert!(read::names("open src/a.rs.", "src/a.rs"));
    assert!(!read::names("cat src/a.rs.bak", "src/a.rs"));
    assert!(!read::names("cat xsrc/a.rs", "src/a.rs"));
    assert!(!read::names("cat src/a.rsx", "src/a.rs"));
    assert!(read::names("é src/a.rs", "src/a.rs"));
}

#[test]
fn the_estimate_uses_the_benchmark_share_for_each_app() {
    assert_eq!(
        (rate("codex"), rate("claude-code"), rate("omp")),
        (52, 61, 52)
    );
    // Saving 52% means 48 tokens used would have been 100: 52 saved.
    assert_eq!(saved(48, 52), 52);
    assert_eq!(saved(39, 61), 61);
    assert_eq!(saved(0, 61), 0);
    assert_eq!(saved(u64::MAX, 99), u64::MAX / 10);
}

#[test]
fn report_counts_only_recent_sessions_that_were_shown_code() {
    let homes = homes();
    let codex = codex_record(&homes.home);
    let claude = claude_record(&homes.home);
    record_at(
        &homes.guard,
        added(
            "codex",
            "c1",
            Some(&codex),
            &["src/billing/invoice.rs", "src/billing/tax.rs"],
        ),
        NOW,
    );
    record_at(
        &homes.guard,
        added("codex", "c1", Some(&codex), &[]),
        NOW + 10,
    );
    record_at(
        &homes.guard,
        added("claude-code", "k1", Some(&claude), &["src/app/db.ts"]),
        NOW,
    );
    // Helped but showed no files: not counted as saved work.
    record_at(
        &homes.guard,
        added("codex", "hint-only", Some(&codex), &[]),
        NOW,
    );
    // Unreadable record: counted as helped, but nothing estimated.
    record_at(
        &homes.guard,
        added("codex", "c2", Some("/elsewhere/r.jsonl"), &["a.rs"]),
        NOW,
    );
    let report = report_at(&homes.guard, &homes.home, no_env, NOW + DAY);
    assert_eq!(report.schema, "guard-cigar-savings.v1");
    assert!(report.estimate);
    let total = &report.total;
    assert_eq!(
        (total.sessions, total.prompts, total.measured_sessions),
        (3, 4, 2)
    );
    assert_eq!(
        (
            total.files_shown,
            total.files_checked,
            total.files_opened_anyway
        ),
        (4, 3, 1)
    );
    assert_eq!(total.context_tokens, 4 * 1_000);
    assert_eq!(total.used_tokens, 32_000 + 20_000);
    assert_eq!(
        total.estimated_saved_tokens,
        saved(32_000, 52) + saved(20_000, 61)
    );
    // Biggest saver first.
    assert_eq!(report.apps[0].app, "codex");
    assert_eq!(report.apps[0].totals.sessions, 2);
    assert_eq!(
        (report.apps[1].app.as_str(), report.apps[1].rate_percent),
        ("claude-code", 61)
    );
    let later = report_at(&homes.guard, &homes.home, no_env, NOW + 8 * DAY);
    assert_eq!(later.total, report::Totals::default());
}

#[test]
fn a_growing_record_is_read_again() {
    let homes = homes();
    let path = codex_record(&homes.home);
    let roots = record_roots(&homes.home, no_env);
    let files = shown(&["src/billing/tax.rs".to_owned()], 0);
    assert!(read::usage(&path, &roots, 0, &files)
        .unwrap()
        .opened
        .is_empty());
    let mut body = std::fs::read_to_string(&path).unwrap();
    body.push_str(r#"{"type":"response_item","payload":{"type":"function_call","arguments":"{\"cmd\":\"cat src/billing/tax.rs\"}"}}"#);
    body.push('\n');
    std::fs::write(&path, body).unwrap();
    assert_eq!(
        read::usage(&path, &roots, 0, &files).unwrap().opened,
        ["src/billing/tax.rs"]
    );
}

#[test]
fn records_the_usage_meter_found_are_read_without_the_apps_settings() {
    // Guard's background service can start without the user's CODEX_HOME;
    // the usage meter, which ran with it, already found the record.
    let homes = homes();
    let custom = homes.home.join("custom-codex/sessions");
    std::fs::create_dir_all(&custom).unwrap();
    let codex = codex_record(&homes.home);
    let moved = custom.join("rollout-a.jsonl");
    std::fs::rename(&codex, &moved).unwrap();
    let moved_text = moved.to_string_lossy().into_owned();
    let unlisted = custom.join("rollout-other.jsonl");
    std::fs::copy(&moved, &unlisted).unwrap();
    let meter = serde_json::json!({"version": 1, "files": {
        format!("codex:{moved_text}"): {"size": 1},
        "codex:relative.jsonl": {},
        "garbage": {},
    }});
    let note = |id: &str, path: &str, at: u64| {
        record_at(
            &homes.guard,
            added("codex", id, Some(path), &["src/billing/invoice.rs"]),
            at,
        );
    };
    let at = NOW;
    note("listed", &moved_text, at);
    note("unlisted", &unlisted.to_string_lossy(), at);
    let before = report_at(&homes.guard, &homes.home, no_env, at);
    assert_eq!(before.total.measured_sessions, 0);
    std::fs::write(
        homes.guard.join("context-usage-meter.json"),
        meter.to_string(),
    )
    .unwrap();
    let after = report_at(&homes.guard, &homes.home, no_env, at);
    assert_eq!(
        (after.total.sessions, after.total.measured_sessions),
        (2, 1)
    );
    assert_eq!(after.total.used_tokens, 32_000);
    assert_eq!(after.total.files_opened_anyway, 1);
}
