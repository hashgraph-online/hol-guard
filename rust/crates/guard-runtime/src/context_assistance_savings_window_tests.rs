//! The savings window: only this week's work, only opens after a file was
//! shown, and each record read once without holding huge lines.
use super::report::{report_at, saved};
use super::*;

const DAY: u64 = 86_400;
/// 2026-11-14T09:00:00Z.
const NOW: u64 = 1_794_646_800;

fn stamp(at: u64) -> String {
    let (day, second) = (at / DAY, at % DAY);
    // Days since 1970 to a civil date (Howard Hinnant's algorithm).
    let z = day as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let of_era = z - era * 146_097;
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let date = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{date:02}T{:02}:{:02}:{:02}.5Z",
        second / 3_600,
        second % 3_600 / 60,
        second % 60
    )
}

fn tokens(at: u64, input: u64) -> String {
    format!(
        r#"{{"timestamp":"{}","type":"token_usage_record","payload":{{"usage":{{"input_tokens":{input},"output_tokens":0}}}}}}"#,
        stamp(at)
    )
}

fn opens(at: u64, file: &str) -> String {
    format!(
        r#"{{"timestamp":"{}","type":"response_item","payload":{{"type":"function_call","arguments":"cat {file}"}}}}"#,
        stamp(at)
    )
}

struct Rig {
    _dir: tempfile::TempDir,
    guard: PathBuf,
    home: PathBuf,
    record: PathBuf,
}

fn rig(lines: &[String]) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let guard = dir.path().join("guard");
    let home = dir.path().join("home");
    let sessions = home.join(".codex/sessions");
    std::fs::create_dir_all(&guard).unwrap();
    std::fs::create_dir_all(&sessions).unwrap();
    let record = sessions.join("rollout.jsonl");
    std::fs::write(&record, lines.join("\n") + "\n").unwrap();
    Rig {
        _dir: dir,
        guard,
        home,
        record,
    }
}

fn help(rig: &Rig, files: &[&str], at: u64) {
    let added = Added {
        app: "codex",
        id: "s1",
        transcript: rig.record.to_str(),
        chars: 4_000,
        files: files.iter().map(|file| (*file).to_owned()).collect(),
    };
    record_at(&rig.guard, added, at);
}

fn report(rig: &Rig, at: u64) -> report::Totals {
    report_at(&rig.guard, &rig.home, |_| None, at).total
}

#[test]
fn a_resumed_session_counts_only_this_weeks_tokens_and_prompts() {
    let rig = rig(&[tokens(NOW - 20 * DAY, 90_000), tokens(NOW + 60, 1_000)]);
    help(&rig, &["src/a.rs"], NOW - 3 * DAY);
    help(&rig, &["src/a.rs"], NOW);
    // Five days on, the window starts the day before NOW's day.
    let total = report(&rig, NOW + 5 * DAY);
    assert_eq!((total.prompts, total.context_tokens), (1, 1_000));
    assert_eq!(total.used_tokens, 1_000);
    assert_eq!(total.estimated_saved_tokens, saved(1_000, 52));
}

#[test]
fn a_file_opened_before_it_was_shown_is_not_opened_anyway() {
    let rig = rig(&[
        tokens(NOW + 10, 1_000),
        opens(NOW - 60, "src/early.rs"),
        opens(NOW + 60, "src/late.rs"),
    ]);
    help(&rig, &["src/early.rs", "src/late.rs"], NOW);
    let total = report(&rig, NOW);
    assert_eq!((total.files_checked, total.files_opened_anyway), (2, 1));
}

#[test]
fn a_replaced_record_is_read_from_the_start() {
    let rig = rig(&[tokens(NOW + 60, 5_000), tokens(NOW + 70, 5_000)]);
    help(&rig, &["src/a.rs"], NOW);
    assert_eq!(report(&rig, NOW).used_tokens, 10_000);
    std::fs::remove_file(&rig.record).unwrap();
    std::fs::write(&rig.record, tokens(NOW + 80, 7) + "\n").unwrap();
    assert_eq!(report(&rig, NOW).used_tokens, 7);
}

#[test]
fn a_line_still_being_written_is_read_once_it_ends() {
    let rig = rig(&[tokens(NOW + 60, 5_000)]);
    help(&rig, &["src/a.rs"], NOW);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&rig.record)
        .unwrap();
    let late = tokens(NOW + 70, 3);
    std::io::Write::write_all(&mut file, &late.as_bytes()[..20]).unwrap();
    assert_eq!(report(&rig, NOW).used_tokens, 5_000);
    std::io::Write::write_all(
        &mut file,
        [&late.as_bytes()[20..], b"\n"].concat().as_slice(),
    )
    .unwrap();
    assert_eq!(report(&rig, NOW).used_tokens, 5_003);
}

#[test]
fn a_huge_line_is_skipped_and_the_rest_still_counts() {
    let huge = format!(
        r#"{{"timestamp":"{}","pad":"{}"}}"#,
        stamp(NOW + 1),
        "x".repeat(5 << 20)
    );
    let rig = rig(&[huge, tokens(NOW + 60, 42)]);
    help(&rig, &["src/a.rs"], NOW);
    let total = report(&rig, NOW);
    assert_eq!((total.measured_sessions, total.used_tokens), (1, 42));
    // The skipped line could have opened the shown file, so it is not checked.
    assert_eq!((total.files_checked, total.files_opened_anyway), (0, 0));
}

#[test]
fn days_without_help_before_this_weeks_first_help_do_not_count() {
    let rig = rig(&[tokens(NOW - DAY + 60, 50_000), tokens(NOW + 60, 1_000)]);
    help(&rig, &["src/a.rs"], NOW - 3 * DAY);
    help(&rig, &["src/a.rs"], NOW);
    // The window now opens the day before NOW, a day CIGAR did not help.
    assert_eq!(report(&rig, NOW + 5 * DAY).used_tokens, 1_000);
}

#[test]
fn files_shown_before_the_window_free_their_slots() {
    let rig = rig(&[tokens(NOW + 7 * DAY, 1_000)]);
    let old: Vec<String> = (0..MAX_FILES).map(|n| format!("src/{n}.rs")).collect();
    let old: Vec<&str> = old.iter().map(String::as_str).collect();
    help(&rig, &old, NOW);
    help(&rig, &[], NOW + 3 * DAY);
    // A week later the first files are outside the window.
    help(&rig, &["src/new.rs"], NOW + 7 * DAY);
    let total = report(&rig, NOW + 7 * DAY);
    assert_eq!((total.sessions, total.files_shown), (1, 1));
}

#[test]
fn showing_a_file_again_keeps_the_read_going() {
    let first = |last| Shown {
        path: "src/a.rs".into(),
        at: NOW,
        last,
    };
    assert!(read::same_files(&[first(NOW)], &[first(NOW + 60)]));
    let later = Shown {
        at: NOW + 1,
        ..first(NOW)
    };
    assert!(!read::same_files(&[first(NOW)], &[later]));
}
