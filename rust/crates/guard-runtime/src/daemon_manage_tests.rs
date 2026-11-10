use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Value};

use super::{records, run_command};

fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn ask(home: &Path, op: &str) -> Result<Value, String> {
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": op,
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 5000,
    });
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn rejects_unknown_ops_and_relative_homes() {
    let home = private_home();
    assert_eq!(
        ask(home.path(), "explode"),
        Err("daemon_manage_request_invalid".to_owned())
    );
    assert_eq!(
        ask(Path::new("relative/home"), "retire"),
        Err("daemon_manage_request_invalid".to_owned())
    );
}

#[test]
fn exact_tombstone_requires_two_bytes_in_a_private_parent() {
    let home = private_home();
    let path = home.path().join("record.json");
    write_private(&path, "{}");
    assert!(records::is_exact_tombstone(&path));
    write_private(&path, "{ }");
    assert!(!records::is_exact_tombstone(&path));
    write_private(&path, "{}");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!records::is_exact_tombstone(&path));
}

#[test]
fn retirement_of_an_empty_home_quarantines_unsigned_state() {
    let home = private_home();
    write_private(
        &records::state_path(home.path()),
        r#"{"pid": 1, "port": 5474}"#,
    );
    let answer = ask(home.path(), "retire").unwrap();
    assert_eq!(answer, json!({"retired": []}));
    assert!(records::is_exact_tombstone(&records::state_path(
        home.path()
    )));
    let quarantined = fs::read_to_string(home.path().join("daemon-state.invalid.json")).unwrap();
    assert_eq!(quarantined, r#"{"pid": 1, "port": 5474}"#);
    assert_eq!(
        ask(home.path(), "retirement_complete").unwrap(),
        json!({"complete": true})
    );
}

#[test]
fn unsigned_state_is_not_a_completed_retirement() {
    let home = private_home();
    write_private(&records::state_path(home.path()), r#"{"pid": 1}"#);
    assert_eq!(
        ask(home.path(), "retirement_complete").unwrap(),
        json!({"complete": false})
    );
}

#[test]
fn repair_clears_the_locator_and_untrusted_state() {
    let home = private_home();
    write_private(&home.path().join(records::LOCATOR_FILE), "{}");
    write_private(&records::state_path(home.path()), r#"{"pid": 0}"#);
    write_private(&home.path().join(records::DISCOVERY_FILE), "not-hex");
    let answer = ask(home.path(), "repair_locator").unwrap();
    assert_eq!(
        answer,
        json!({"repaired": true, "cleared": ["locator", "daemon_state", "daemon_discovery_key"]})
    );
    assert!(!home.path().join(records::LOCATOR_FILE).exists());
    assert!(!home.path().join(records::DISCOVERY_FILE).exists());
    assert!(records::is_exact_tombstone(&records::state_path(
        home.path()
    )));
}

#[test]
fn repair_of_a_clean_home_clears_nothing() {
    let home = private_home();
    assert_eq!(
        ask(home.path(), "repair_locator").unwrap(),
        json!({"repaired": true, "cleared": []})
    );
}

#[test]
fn retire_stops_an_inventoried_daemon_of_this_home_only() {
    let home = private_home();
    let other = private_home();
    let spawn = |guard_home: &Path| {
        std::process::Command::new("/bin/sh")
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
            .args(["--port", "59731"])
            .spawn()
            .unwrap()
    };
    let mut ours = spawn(home.path());
    let mut theirs = spawn(other.path());
    let pid = i64::from(ours.id());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let answer = loop {
        let answer = ask(home.path(), "retire").unwrap();
        if answer["retired"] != json!([]) || std::time::Instant::now() > deadline {
            break answer;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let _ = ours.kill();
    let _ = ours.wait();
    let still_running = theirs.try_wait().unwrap().is_none();
    let _ = theirs.kill();
    let _ = theirs.wait();
    assert_eq!(answer, json!({"retired": [pid]}));
    assert!(still_running);
}
