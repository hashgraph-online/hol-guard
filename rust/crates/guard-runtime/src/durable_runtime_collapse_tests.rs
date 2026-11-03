use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::posix::MIN_AGE;
use super::*;

const CURRENT_BYTES: &[u8] = b"current runtime image";
const OLD_BYTES: &[u8] = b"an older runtime image that a previous update left behind";
const OLD_DIGEST: &str = "8888888888888888888888888888888888888888888888888888888888888888";

struct Home {
    _dir: tempfile::TempDir,
    state: PathBuf,
    digest: String,
}

fn digest_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_runtime(state: &Path, digest: &str, bytes: &[u8]) -> PathBuf {
    let directory = state.join(digest);
    fs::create_dir_all(&directory).expect("copy dir");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("dir mode");
    let runtime = directory.join("hol-guard-runtime");
    fs::write(&runtime, bytes).expect("write runtime");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
    runtime
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("native-runtime");
    fs::create_dir(&state).expect("state dir");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
    let digest = digest_of(CURRENT_BYTES);
    write_runtime(&state, &digest, CURRENT_BYTES);
    Home {
        _dir: dir,
        state,
        digest,
    }
}

fn later() -> SystemTime {
    SystemTime::now() + MIN_AGE + Duration::from_secs(3600)
}

fn run(home: &Home, now: SystemTime) -> Value {
    serde_json::to_value(collapse(&home.state, &home.digest, now)).expect("report")
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path).expect("metadata").ino()
}

#[test]
fn an_older_copy_is_relinked_to_the_current_file_and_still_launches() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    let current = home.state.join(&home.digest).join("hol-guard-runtime");

    let report = run(&home, later());

    assert_eq!(report["outcome"], "ok");
    assert_eq!(report["collapsed"], 1);
    assert_eq!(report["reclaimed_bytes"], OLD_BYTES.len() as u64);
    // The pinned path still names an executable file: the current runtime.
    assert_eq!(inode(&old), inode(&current));
    assert_eq!(fs::read(&old).expect("read old pin"), CURRENT_BYTES);
    assert_ne!(fs::metadata(&old).expect("mode").mode() & 0o100, 0);
    assert!(!home
        .state
        .join(OLD_DIGEST)
        .join(".hol-guard-runtime.collapse.tmp")
        .exists());
}

#[test]
fn a_second_pass_finds_the_copy_already_shared() {
    let home = home();
    write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    run(&home, later());

    let report = run(&home, later());

    assert_eq!(report["collapsed"], 0);
    assert_eq!(report["kept"]["already_shared"], 1);
}

#[test]
fn a_copy_published_within_the_minimum_age_is_left_alone() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);

    let report = run(&home, SystemTime::now());

    assert_eq!(report["collapsed"], 0);
    assert_eq!(report["kept"]["too_recent"], 1);
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_current_copy_that_does_not_hash_to_its_digest_relinks_nothing() {
    let home = home();
    let current = home.state.join(&home.digest).join("hol-guard-runtime");
    fs::write(&current, b"tampered bytes").expect("tamper");
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);

    let report = run(&home, later());

    assert_eq!(report["outcome"], "unavailable");
    assert_eq!(report["errors"], json!(["current_runtime_unverified"]));
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_current_copy_others_can_write_relinks_nothing() {
    let home = home();
    let current = home.state.join(&home.digest).join("hol-guard-runtime");
    fs::set_permissions(&current, fs::Permissions::from_mode(0o720)).expect("mode");
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);

    let report = run(&home, later());

    assert_eq!(report["outcome"], "unavailable");
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_current_copy_in_a_directory_others_can_write_relinks_nothing() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    fs::set_permissions(
        home.state.join(&home.digest),
        fs::Permissions::from_mode(0o770),
    )
    .expect("mode");

    let report = run(&home, later());

    assert_eq!(report["outcome"], "unavailable");
    assert_eq!(report["errors"], json!(["current_runtime_unverified"]));
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_state_directory_others_can_write_relinks_nothing() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    fs::set_permissions(&home.state, fs::Permissions::from_mode(0o775)).expect("mode");

    let report = run(&home, later());

    assert_eq!(report["outcome"], "unavailable");
    assert_eq!(report["errors"], json!(["state_dir_untrusted"]));
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn an_older_copy_in_a_directory_others_can_write_is_kept() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    fs::set_permissions(
        home.state.join(OLD_DIGEST),
        fs::Permissions::from_mode(0o770),
    )
    .expect("mode");

    let report = run(&home, later());

    assert_eq!(report["kept"]["untrusted_directory"], 1);
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_directory_holding_anything_but_the_runtime_is_kept() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    fs::write(
        home.state
            .join(OLD_DIGEST)
            .join(".hol-guard-runtime.abc.tmp"),
        b"publishing",
    )
    .expect("in-flight publish");

    let report = run(&home, later());

    assert_eq!(report["kept"]["unexpected_contents"], 1);
    assert_eq!(fs::read(&old).expect("read old"), OLD_BYTES);
}

#[test]
fn a_symlinked_copy_directory_is_kept() {
    let home = home();
    let elsewhere = tempfile::tempdir().expect("elsewhere");
    let target = write_runtime(elsewhere.path(), OLD_DIGEST, OLD_BYTES);
    symlink(
        elsewhere.path().join(OLD_DIGEST),
        home.state.join(OLD_DIGEST),
    )
    .expect("symlink");

    let report = run(&home, later());

    assert_eq!(report["kept"]["untrusted_directory"], 1);
    assert_eq!(fs::read(&target).expect("read target"), OLD_BYTES);
}

#[test]
fn a_symlinked_runtime_is_kept() {
    let home = home();
    let directory = home.state.join(OLD_DIGEST);
    fs::create_dir(&directory).expect("copy dir");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("dir mode");
    let elsewhere = tempfile::tempdir().expect("elsewhere");
    let target = elsewhere.path().join("runtime");
    fs::write(&target, OLD_BYTES).expect("write target");
    symlink(&target, directory.join("hol-guard-runtime")).expect("symlink");

    let report = run(&home, later());

    assert_eq!(report["kept"]["untrusted_runtime"], 1);
    assert_eq!(fs::read(&target).expect("read target"), OLD_BYTES);
}

#[test]
fn a_link_left_by_an_interrupted_pass_is_replaced() {
    let home = home();
    let old = write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    let stray = home
        .state
        .join(OLD_DIGEST)
        .join(".hol-guard-runtime.collapse.tmp");
    fs::write(&stray, b"stray").expect("stray link");

    let report = run(&home, later());

    assert_eq!(report["collapsed"], 1);
    assert_eq!(fs::read(&old).expect("read old"), CURRENT_BYTES);
    assert!(!stray.exists());
}

#[test]
fn entries_that_are_not_durable_copies_are_ignored() {
    let home = home();
    fs::create_dir(home.state.join("resident-v3-b4ae9142f6e46575")).expect("resident dir");
    fs::write(home.state.join("policy-snapshot-v3.json"), b"{}").expect("state file");
    let upper = OLD_DIGEST.replace('8', "A");
    write_runtime(&home.state, &upper, OLD_BYTES);

    let report = run(&home, later());

    assert_eq!(report["collapsed"], 0);
    assert_eq!(report["kept"], json!({}));
    assert_eq!(
        fs::read(home.state.join(&upper).join("hol-guard-runtime")).expect("read"),
        OLD_BYTES
    );
}

#[test]
fn a_home_without_durable_copies_is_a_clean_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = collapse(
        &dir.path().join("native-runtime"),
        &digest_of(CURRENT_BYTES),
        later(),
    );

    assert_eq!(report.outcome, "ok");
    assert_eq!(report.collapsed, 0);
    assert!(report.errors.is_empty());
}

#[test]
fn malformed_requests_are_refused() {
    let digest = digest_of(CURRENT_BYTES);
    for request in [
        json!({"schema": "durable-runtime-collapse.v1", "guard_home": "relative", "current_digest": digest}),
        json!({"schema": "durable-runtime-collapse.v1", "guard_home": "/g", "current_digest": digest.to_uppercase()}),
        json!({"schema": "durable-runtime-collapse.v1", "guard_home": "/g", "current_digest": "../x"}),
        json!({"schema": "durable-runtime-collapse.v2", "guard_home": "/g", "current_digest": digest}),
        json!({"schema": "durable-runtime-collapse.v1", "guard_home": "/g", "current_digest": digest, "extra": 1}),
    ] {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert_eq!(
            run_command(bytes.as_slice()),
            Err("durable_runtime_collapse_request_invalid".to_owned()),
            "{request}"
        );
    }
}

#[test]
fn the_command_answers_for_a_real_home() {
    let home = home();
    write_runtime(&home.state, OLD_DIGEST, OLD_BYTES);
    let guard_home = home.state.parent().expect("guard home");
    let request = json!({
        "schema": "durable-runtime-collapse.v1",
        "guard_home": guard_home,
        "current_digest": home.digest,
    });

    let answer =
        run_command(serde_json::to_vec(&request).expect("request").as_slice()).expect("answer");
    let answer: Value = serde_json::from_slice(&answer).expect("json");

    // The copy was published just now, so the live clock keeps it.
    assert_eq!(answer["outcome"], "ok");
    assert_eq!(answer["kept"]["too_recent"], 1);
}
