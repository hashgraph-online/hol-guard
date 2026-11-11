use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::rotate;

const DAY_SECONDS: u64 = 86_400;
/// 2026-11-10T12:00:00Z.
const NOW_SECONDS: u64 = 1_794_312_000;

fn write_at(path: &Path, text: &str, seconds: u64) {
    fs::write(path, text).unwrap();
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

fn now_micros() -> i64 {
    i64::try_from(NOW_SECONDS).unwrap() * 1_000_000
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_log_last_written_yesterday_moves_to_that_days_backup() {
    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("logs");
    fs::create_dir(&logs).unwrap();
    write_at(&logs.join("daemon.log"), "old\n", NOW_SECONDS - DAY_SECONDS);

    rotate(home.path(), now_micros());

    assert_eq!(names(&logs), vec!["daemon.log.2026-11-09"]);
    assert_eq!(
        fs::read_to_string(logs.join("daemon.log.2026-11-09")).unwrap(),
        "old\n"
    );
}

#[test]
fn a_log_written_today_stays_live() {
    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("logs");
    fs::create_dir(&logs).unwrap();
    write_at(&logs.join("daemon.log"), "today\n", NOW_SECONDS - 60);

    rotate(home.path(), now_micros());

    assert_eq!(names(&logs), vec!["daemon.log"]);
}

#[test]
fn rotated_logs_keep_seven_days_and_seven_backups() {
    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("logs");
    fs::create_dir(&logs).unwrap();
    write_at(
        &logs.join("daemon.log.2026-11-01"),
        "expired\n",
        NOW_SECONDS - 8 * DAY_SECONDS,
    );
    for day in 2..=9 {
        write_at(
            &logs.join(format!("daemon.log.2026-11-0{day}")),
            "kept\n",
            NOW_SECONDS - DAY_SECONDS,
        );
    }
    write_at(
        &logs.join("other.log.2026-11-01"),
        "unrelated\n",
        NOW_SECONDS - 30 * DAY_SECONDS,
    );

    rotate(home.path(), now_micros());

    let mut expected: Vec<String> = (3..=9)
        .map(|day| format!("daemon.log.2026-11-0{day}"))
        .collect();
    expected.push("other.log.2026-11-01".into());
    assert_eq!(names(&logs), expected);
}

#[test]
fn a_linked_log_directory_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    write_at(
        &target.path().join("daemon.log"),
        "old\n",
        NOW_SECONDS - DAY_SECONDS,
    );
    std::os::unix::fs::symlink(target.path(), home.path().join("logs")).unwrap();

    rotate(home.path(), now_micros());

    assert_eq!(names(target.path()), vec!["daemon.log"]);
}
