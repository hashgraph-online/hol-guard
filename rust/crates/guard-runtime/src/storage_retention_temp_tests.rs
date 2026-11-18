use super::*;

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const DAY: f64 = 24.0 * 60.0 * 60.0;

fn now() -> f64 {
    super::super::epoch_seconds(SystemTime::now()) + 1.0
}

fn guard_home() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = fs::canonicalize(directory.path())
        .expect("canonical")
        .join("guard-home");
    fs::create_dir_all(home.join("native-runtime/direct-lane")).expect("home");
    (directory, home)
}

/// Write `size` bytes to `path` and move its mtime `age_seconds` back.
fn leftover(path: &Path, size: usize, age_seconds: f64) {
    fs::write(path, vec![b'x'; size]).expect("write");
    let file = OpenOptions::new().write(true).open(path).expect("open");
    let modified = file
        .metadata()
        .expect("metadata")
        .modified()
        .expect("mtime");
    file.set_modified(modified - Duration::from_secs_f64(age_seconds))
        .expect("set mtime");
}

#[test]
fn an_abandoned_empty_temp_file_is_removed_wherever_writes_leave_them() {
    let (_directory, home) = guard_home();
    let abandoned = [
        home.join(".runtime-hook-evidence.jsonl.43e38b8347834.tmp"),
        home.join("native-runtime/.policy-snapshot-publisher-v3.json.cf01e98.tmp"),
        home.join("native-runtime/direct-lane/.ack.json.53601.14797582336.tmp"),
    ];
    for path in &abandoned {
        leftover(path, 0, 2.0 * DAY);
    }
    assert_eq!(prune_abandoned_temp_files(&home, now()), 3);
    for path in &abandoned {
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
fn a_recent_or_written_temp_file_is_kept() {
    let (_directory, home) = guard_home();
    let recent = home.join(".state.json.1a2b.tmp");
    let written = home.join(".state.json.3c4d.tmp");
    leftover(&recent, 0, DAY / 2.0);
    leftover(&written, 12, 30.0 * DAY);
    assert_eq!(prune_abandoned_temp_files(&home, now()), 0);
    assert!(recent.exists());
    assert!(written.exists());
}

#[test]
fn only_temp_names_are_touched() {
    let (_directory, home) = guard_home();
    let kept = [
        "guard.db",
        "state.json.1a2b.tmp",
        ".state.tmp",
        "..1a2b.tmp",
        ".state.json.1a2b.tmp.bak",
        ".state.json.1a2b.TMP",
    ];
    for name in kept {
        leftover(&home.join(name), 0, 30.0 * DAY);
    }
    fs::create_dir(home.join(".directory.1a2b.tmp")).expect("dir");
    assert_eq!(prune_abandoned_temp_files(&home, now()), 0);
    for name in kept {
        assert!(home.join(name).exists(), "{name}");
    }
    assert!(home.join(".directory.1a2b.tmp").is_dir());
}

#[test]
fn other_directories_are_not_swept() {
    let (_directory, home) = guard_home();
    fs::create_dir_all(home.join("secrets")).expect("secrets");
    let nested = home.join("secrets/.anchor.enc.0da5.tmp");
    leftover(&nested, 0, 30.0 * DAY);
    assert_eq!(prune_abandoned_temp_files(&home, now()), 0);
    assert!(nested.exists());
}

#[test]
fn a_missing_guard_home_is_a_noop() {
    let (_directory, home) = guard_home();
    assert_eq!(prune_abandoned_temp_files(&home.join("absent"), now()), 0);
}

#[cfg(unix)]
#[test]
fn links_are_never_followed_or_removed() {
    use std::os::unix::fs::symlink;

    let (directory, home) = guard_home();
    let outside = fs::canonicalize(directory.path())
        .expect("canonical")
        .join("outside");
    fs::create_dir(&outside).expect("outside");
    let target = outside.join(".state.json.1a2b.tmp");
    leftover(&target, 0, 30.0 * DAY);

    // A linked temp name is not a regular file.
    let link = home.join(".state.json.9f9f.tmp");
    symlink(&target, &link).expect("link");

    // A linked swept directory is not entered.
    fs::remove_dir_all(home.join("native-runtime/direct-lane")).expect("remove");
    symlink(&outside, home.join("native-runtime/direct-lane")).expect("dir link");

    assert_eq!(prune_abandoned_temp_files(&home, now()), 0);
    assert!(fs::symlink_metadata(&link).expect("link").is_symlink());
    assert!(target.exists());
}

#[test]
fn the_maintenance_sweep_removes_abandoned_temp_files() {
    let (_directory, home) = guard_home();
    let abandoned = home.join("native-runtime/.authority.json.77aa.tmp");
    leftover(&abandoned, 0, 2.0 * DAY);
    super::super::sweep_after_maintenance(&home);
    assert!(!abandoned.exists());
}
