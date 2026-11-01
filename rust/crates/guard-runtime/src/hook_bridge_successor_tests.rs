use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use tempfile::TempDir;

use super::*;

const OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const RUNTIME: &str = "hol-guard-runtime";

/// A durable copy of `digest` under `base`, published `age` ago.
fn publish(base: &Path, digest: &str, age: Duration) -> PathBuf {
    let directory = base.join(digest);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = directory.join(RUNTIME);
    fs::write(&runtime, b"runtime").unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    File::options()
        .write(true)
        .open(&runtime)
        .unwrap()
        .set_modified(SystemTime::now() - age)
        .unwrap();
    runtime.canonicalize().unwrap()
}

fn state_base() -> TempDir {
    let base = TempDir::new().unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    base
}

#[test]
fn a_copy_published_after_this_one_answers_for_it() {
    let base = state_base();
    let own = publish(base.path(), OLD, Duration::from_secs(3600));
    let newer = publish(base.path(), NEW, Duration::from_secs(60));

    assert_eq!(successor_copy(&own, base.path(), NEW), Some(newer));
}

#[test]
fn a_copy_published_before_this_one_never_answers_for_it() {
    let base = state_base();
    let own = publish(base.path(), NEW, Duration::from_secs(60));
    publish(base.path(), OLD, Duration::from_secs(3600));

    assert_eq!(successor_copy(&own, base.path(), OLD), None);
}

#[test]
fn the_resident_running_this_copy_leaves_the_hook_here() {
    let base = state_base();
    let own = publish(base.path(), OLD, Duration::from_secs(60));

    assert_eq!(successor_copy(&own, base.path(), OLD), None);
    assert_eq!(
        successor_copy(&own, base.path(), &OLD.to_ascii_uppercase()),
        None
    );
}

#[test]
fn a_bridge_that_is_not_a_durable_copy_never_hands_off() {
    let base = state_base();
    let elsewhere = state_base();
    let own = publish(elsewhere.path(), OLD, Duration::from_secs(3600));
    publish(base.path(), NEW, Duration::from_secs(60));

    assert_eq!(successor_copy(&own, base.path(), NEW), None);
}

#[test]
fn a_live_digest_without_a_published_copy_leaves_the_hook_here() {
    let base = state_base();
    let own = publish(base.path(), OLD, Duration::from_secs(3600));

    assert_eq!(successor_copy(&own, base.path(), NEW), None);
    assert_eq!(successor_copy(&own, base.path(), "../escape"), None);
}

#[test]
fn a_copy_others_can_write_is_never_run() {
    let base = state_base();
    let own = publish(base.path(), OLD, Duration::from_secs(3600));
    let newer = publish(base.path(), NEW, Duration::from_secs(60));
    fs::set_permissions(&newer, fs::Permissions::from_mode(0o720)).unwrap();

    assert_eq!(successor_copy(&own, base.path(), NEW), None);

    fs::set_permissions(&newer, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(newer.parent().unwrap(), fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(successor_copy(&own, base.path(), NEW), None);
}

#[test]
fn a_symlinked_copy_is_never_run() {
    let base = state_base();
    let own = publish(base.path(), OLD, Duration::from_secs(3600));
    let target = state_base();
    let real = publish(target.path(), NEW, Duration::from_secs(60));
    let directory = base.path().join(NEW);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, directory.join(RUNTIME)).unwrap();

    assert_eq!(successor_copy(&own, base.path(), NEW), None);
}

#[test]
fn the_successor_answers_with_the_hook_and_never_hands_it_on() {
    let arguments = [
        "-c".to_owned(),
        r#"printf '%s|%s|' "$HOL_GUARD_HOOK_HANDED_OFF" "$1"; cat; exit 3"#.to_owned(),
        "sh".to_owned(),
        "cursor-hook-bridge".to_owned(),
    ];
    let deadline = Instant::now() + Duration::from_secs(30);

    let answer = hand_off(Path::new("/bin/sh"), &arguments, b"{\"hook\":1}", deadline);

    assert_eq!(
        answer,
        Some(HandOff::Answered(
            b"1|cursor-hook-bridge|{\"hook\":1}".to_vec(),
            3
        ))
    );
}

#[test]
fn a_successor_past_the_deadline_is_stopped_and_fails() {
    let arguments = ["-c".to_owned(), "exec sleep 30".to_owned()];
    let started = Instant::now();

    let answer = hand_off(
        Path::new("/bin/sh"),
        &arguments,
        b"{}",
        started + Duration::from_millis(200),
    );

    assert_eq!(answer, Some(HandOff::Failed));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_successor_that_cannot_start_leaves_the_hook_here() {
    let missing = state_base();
    let deadline = Instant::now() + Duration::from_secs(30);

    let answer = hand_off(&missing.path().join(RUNTIME), &[], b"{}", deadline);

    assert_eq!(answer, None);
    assert_eq!(
        hand_off(Path::new("/bin/sh"), &[], b"{}", Instant::now()),
        None
    );
}
