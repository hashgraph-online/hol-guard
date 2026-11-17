//! Every retirement leaves a `retirement_requested` record naming the
//! caller, and only for a process Guard proved is its own daemon.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::run_command;

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn ask(home: &Path, op: &str, args: Value) -> Value {
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": op,
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 5000,
        "caller_pid": std::process::id(),
        "caller_parent_pid": parent_pid(),
        "args": args,
    });
    serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap()
}

/// The CLI names its own parent; a test does the same.
fn parent_pid() -> u32 {
    std::os::unix::process::parent_id()
}

/// A process whose command line names a Guard daemon of `guard_home`, as
/// process inventory reads it.
fn daemon_look_alike(guard_home: &Path) -> Running {
    Running(
        Command::new("/bin/sh")
            .args([
                "-c",
                "sleep 30; true",
                "sh",
                "codex_plugin_scanner.cli",
                "daemon",
                "--serve",
            ])
            .arg("--guard-home")
            .arg(guard_home)
            .args(["--port", "59733"])
            .spawn()
            .unwrap(),
    )
}

fn journal(home: &Path) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(home.join("daemon-lifecycle")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect()
}

fn retirements_of(home: &Path, pid: i64) -> Vec<Value> {
    journal(home)
        .into_iter()
        .filter(|event| event["event"] == "retirement_requested" && event["pid"] == pid)
        .collect()
}

fn alive(child: &mut Running) -> bool {
    child.0.try_wait().unwrap().is_none()
}

#[test]
fn retiring_a_home_records_the_caller_for_its_daemon_only() {
    let home = private_home();
    let other = private_home();
    let mut ours = daemon_look_alike(home.path());
    let mut theirs = daemon_look_alike(other.path());
    let ours_pid = i64::from(ours.0.id());
    let theirs_pid = i64::from(theirs.0.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    let answer = loop {
        let answer = ask(home.path(), "retire", json!({}));
        if answer["retired"] != json!([]) || Instant::now() > deadline {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(answer, json!({"retired": [ours_pid]}));
    assert!(alive(&mut theirs), "a daemon of another home was signalled");
    assert!(!alive(&mut ours));
    let records = retirements_of(home.path(), ours_pid);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["reason"], "requested_retire");
    assert_eq!(records[0]["by_pid"], std::process::id());
    assert_eq!(records[0]["by_parent_pid"], parent_pid());
    assert!(retirements_of(home.path(), theirs_pid).is_empty());
    assert!(retirements_of(other.path(), theirs_pid).is_empty());
}

#[test]
fn retiring_one_pid_records_the_caller_and_spares_a_foreign_process() {
    let home = private_home();
    let mut foreign = Running(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let foreign_pid = i64::from(foreign.0.id());
    // The foreign process's real start marker and owner: only its command
    // line says it is not this home's daemon.
    let answer = ask(
        home.path(),
        "retire_pid",
        json!({
            "pid": foreign_pid,
            "start_marker": super::host::start_marker(foreign_pid).unwrap(),
            "owner_marker": super::host::owner_marker(foreign_pid).unwrap(),
        }),
    );
    assert_eq!(answer, json!({"retired": false}));
    assert!(alive(&mut foreign), "a foreign process was signalled");
    assert!(retirements_of(home.path(), foreign_pid).is_empty());

    let mut ours = daemon_look_alike(home.path());
    let ours_pid = i64::from(ours.0.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    let answer = loop {
        let answer = ask(
            home.path(),
            "retire_pid",
            json!({
                "pid": ours_pid,
                "start_marker": super::host::start_marker(ours_pid).unwrap(),
                "owner_marker": super::host::owner_marker(ours_pid).unwrap(),
            }),
        );
        if answer["retired"] == json!(true) || Instant::now() > deadline {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(answer, json!({"retired": true}));
    assert!(!alive(&mut ours));
    let records = retirements_of(home.path(), ours_pid);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["reason"], "requested_pid");
    assert_eq!(records[0]["by_pid"], std::process::id());
}

#[test]
fn a_recovery_records_how_it_ended() {
    let home = private_home();
    // An ensure with nothing to launch fails; the recovery records its code.
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": "recover",
        "guard_home": home.path(),
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 2000,
        "failure_kind": "transport-failure",
    });
    let answer: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    let completed: Vec<Value> = journal(home.path())
        .into_iter()
        .filter(|event| event["event"] == "recovery_completed")
        .collect();
    assert!(answer["error"].is_string(), "{answer}");
    assert_eq!(completed.len(), 1, "{completed:?}");
    assert_eq!(completed[0]["pid"], std::process::id());
    assert!(completed[0]["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
}

#[test]
fn a_recovery_that_finds_protection_off_after_the_lock_records_its_ending() {
    let home = private_home();
    let lock = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(home.path().join("daemon-recovery.lock"))
        .unwrap();
    lock.lock().unwrap();
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": "recover",
        "guard_home": home.path(),
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 5000,
        "failure_kind": "transport-failure",
    });
    let recovery = std::thread::spawn(move || {
        serde_json::from_slice::<Value>(&run_command(request.to_string().as_bytes()).unwrap())
            .unwrap()
    });
    let until = Instant::now() + Duration::from_secs(5);
    while !journal(home.path())
        .iter()
        .any(|event| event["event"] == "recovery_requested")
    {
        assert!(Instant::now() < until, "the recovery never started");
        std::thread::sleep(Duration::from_millis(10));
    }
    let config = home.path().join("config.toml");
    fs::write(&config, "protection_posture = \"watch\"\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    lock.unlock().unwrap();
    let answer = recovery.join().unwrap();
    let completed: Vec<Value> = journal(home.path())
        .into_iter()
        .filter(|event| event["event"] == "recovery_completed")
        .collect();
    assert!(answer["error"].is_string(), "{answer}");
    assert_eq!(completed.len(), 1, "{completed:?}");
    assert_eq!(completed[0]["reason"], "protection_off");
}
