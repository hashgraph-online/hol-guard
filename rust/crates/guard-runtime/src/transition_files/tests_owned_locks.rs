//! The lifecycle locks of Codex configuration directories.

#[cfg(unix)]
use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use tempfile::TempDir;

use super::dispatch;

const BUSY: &str =
    "codex_lifecycle_busy: another lifecycle operation owns this Codex configuration";

fn lock(dirs: &[&Path], extra: Value) -> Value {
    let dirs: Vec<String> = dirs
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    let mut request = json!({
        "op": "owned_locks", "dirs": dirs, "client_pid": std::process::id(),
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    dispatch(&request).unwrap()
}

fn leases(answer: &Value) -> Vec<Value> {
    assert_eq!(answer["ok"], true, "{answer}");
    answer["leases"].as_array().unwrap().clone()
}

fn release(held: &[Value]) {
    for lease in held {
        dispatch(&json!({ "op": "lease_release", "lease": lease })).unwrap();
    }
}

fn busy() -> Value {
    json!({ "ok": false, "failure": { "kind": "runtime", "message": BUSY } })
}

#[test]
fn a_second_owner_of_one_configuration_is_refused_until_the_first_releases() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let first = leases(&lock(&[&dir], json!({})));
    assert_eq!(lock(&[&dir], json!({})), busy());
    let held = dispatch(&json!({ "op": "lease_check", "lease": first[0] })).unwrap();
    assert_eq!(held["held"], true);
    release(&first);
    release(&leases(&lock(&[&dir], json!({}))));
}

#[test]
fn locking_never_creates_the_configuration_directory() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    release(&leases(&lock(&[&dir], json!({}))));
    assert!(!dir.exists());
    assert!(!root.path().join("home").exists());
}

#[test]
fn two_spellings_of_one_directory_take_one_lock() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let spelled = root.path().join("home/other/../.codex");
    let held = leases(&lock(&[&dir, &spelled], json!({})));
    assert_eq!(held.len(), 1);
    release(&held);
}

#[cfg(unix)]
#[test]
fn configuration_aliases_share_a_lock() {
    let root = TempDir::new().unwrap();
    let actual = root.path().join("actual");
    fs::create_dir_all(&actual).unwrap();
    for name in ["first", "second"] {
        fs::create_dir_all(root.path().join(name)).unwrap();
        std::os::unix::fs::symlink(&actual, root.path().join(name).join(".codex")).unwrap();
    }
    let first = root.path().join("first/.codex");
    let second = root.path().join("second/.codex");
    let held = leases(&lock(&[&first], json!({})));
    assert_eq!(lock(&[&second], json!({})), busy());
    release(&held);
    release(&leases(&lock(&[&second], json!({}))));
}

#[test]
fn a_shared_directory_contends_between_different_homes() {
    let root = TempDir::new().unwrap();
    let workspace = root.path().join("workspace/.codex");
    let global = root.path().join("one/.codex");
    let first = leases(&lock(&[&global, &workspace], json!({})));
    let other = root.path().join("two/.codex");
    assert_eq!(lock(&[&other, &workspace], json!({})), busy());
    // The refused owner kept nothing: its own directory is free.
    release(&leases(&lock(&[&other], json!({}))));
    release(&first);
}

#[test]
fn waiting_ends_at_the_deadline_with_the_lifecycle_timeout() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let first = leases(&lock(&[&dir], json!({})));
    let waited = lock(&[&dir], json!({ "wait": true, "deadline_ms": 100 }));
    assert_eq!(
        waited,
        json!({ "ok": false, "failure": {
            "kind": "timeout", "message": "Codex lifecycle transaction deadline exceeded."
        } })
    );
    release(&first);
    release(&leases(&lock(
        &[&dir],
        json!({ "wait": true, "deadline_ms": 100 }),
    )));
}

#[test]
fn a_wait_ends_when_the_holder_lets_go() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let first = leases(&lock(&[&dir], json!({})));
    let releaser = std::thread::spawn({
        let first = first.clone();
        move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            release(&first);
        }
    });
    let second = leases(&lock(&[&dir], json!({ "wait": true, "deadline_ms": 5000 })));
    releaser.join().unwrap();
    release(&second);
}

#[test]
fn a_deadline_already_past_refuses_before_any_lock_is_taken() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let refused = lock(&[&dir], json!({ "deadline_ms": 0 }));
    assert_eq!(refused["failure"]["kind"], "timeout");
    release(&leases(&lock(&[&dir], json!({}))));
}

#[test]
fn a_waiting_request_needs_its_deadline() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("home/.codex");
    let request = json!({
        "op": "owned_locks", "dirs": [dir.to_string_lossy()],
        "client_pid": std::process::id(), "wait": true,
    });
    assert!(dispatch(&request).is_err());
}

#[test]
fn an_owner_keeps_its_directories_locked_until_it_ends() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let dir = root.path().join("home/.codex");
    let started = dispatch(&json!({
        "op": "owned_begin", "guard_home": home.to_string_lossy(),
        "target": dir.join("config.toml").to_string_lossy(), "actor": "test",
        "process_identity": "p", "client_pid": std::process::id(), "thread": 1,
        "deadline_ms": 2000, "dirs": [dir.to_string_lossy()],
    }))
    .unwrap();
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(lock(&[&dir], json!({})), busy());
    dispatch(&json!({ "op": "owned_end", "owner": started["owner"], "committed": true })).unwrap();
    release(&leases(&lock(&[&dir], json!({}))));
}

fn begin_owner(home: &Path, dir: &Path) -> Value {
    let started = dispatch(&json!({
        "op": "owned_begin", "guard_home": home.to_string_lossy(),
        "target": dir.join("config.toml").to_string_lossy(), "actor": "test",
        "process_identity": "p", "client_pid": std::process::id(), "thread": 1,
        "deadline_ms": 2000, "dirs": [dir.to_string_lossy()],
    }))
    .unwrap();
    assert_eq!(started["ok"], true, "{started}");
    started
}

#[test]
fn an_owner_that_lost_one_lock_gives_up_all_of_them() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let dir = root.path().join("home/.codex");
    let started = begin_owner(&home, &dir);
    let held = started["leases"].as_array().unwrap().clone();
    assert!(held.len() >= 2, "{started}");
    // One lease goes; the owner's next request prunes it and the rest.
    release(&held[..1]);
    let late =
        dispatch(&json!({ "op": "owned_end", "owner": started["owner"], "committed": true }))
            .unwrap();
    assert_eq!(late["ended"], false);
    release(&leases(&lock(&[&dir], json!({}))));
    let install = dispatch(&json!({
        "op": "lease_acquire", "lock": "install",
        "guard_home": home.to_string_lossy(), "client_pid": std::process::id(),
    }))
    .unwrap();
    assert_eq!(install["ok"], true, "{install}");
    release(&[install["lease"].clone()]);
}

#[test]
fn recovery_for_an_owner_that_lost_its_locks_fails_closed() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let dir = root.path().join("home/.codex");
    let started = begin_owner(&home, &dir);
    release(&started["leases"].as_array().unwrap()[..1]);
    let answer = dispatch(&json!({ "op": "owned_recover", "owner": started["owner"] })).unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["failure"]["kind"], "runtime");
    assert_eq!(
        answer["failure"]["message"],
        "codex_lifecycle_lock_invalid: lifecycle lock changed during ownership"
    );
}

#[test]
fn ending_an_owner_that_is_gone_says_so() {
    let answer =
        dispatch(&json!({ "op": "owned_end", "owner": "missing", "committed": true })).unwrap();
    assert_eq!(answer["ok"], true);
    assert_eq!(answer["ended"], false);
}
