use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Value};

use super::{records, repair_from_daemon, run_command};

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

#[test]
fn the_edge_repairs_a_home_without_retiring_itself() {
    let home = private_home();
    write_private(&home.path().join(records::LOCATOR_FILE), "{}");
    assert_eq!(
        repair_from_daemon(home.path(), "/nonexistent-user-home"),
        Some(json!({"repaired": true, "cleared": ["locator"]}))
    );
    assert_eq!(
        repair_from_daemon(home.path(), "/nonexistent-user-home"),
        Some(json!({"repaired": true, "cleared": []}))
    );
    assert_eq!(repair_from_daemon(Path::new("relative"), "/home"), None);
}

fn ask_with(home: &Path, op: &str, extra: Value) -> Value {
    let mut request = json!({
        "schema": "daemon-manage.v1",
        "op": op,
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 2000,
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    let bytes = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn recovery_posture_follows_watch_and_harness_overrides() {
    let home = private_home();
    assert_eq!(ask(home.path(), "posture").unwrap()["posture"], "on");
    write_private(
        &home.path().join("config.toml"),
        "protection_posture = \"watch\"\n",
    );
    assert_eq!(ask(home.path(), "posture").unwrap()["posture"], "off");
    write_private(
        &home.path().join("config.toml"),
        "protection_posture = \"watch\"\n[harness_postures]\ncodex = \"protected\"\n",
    );
    assert_eq!(ask(home.path(), "posture").unwrap()["posture"], "on");
}

#[test]
fn recovery_rejects_an_unknown_failure_kind() {
    let home = private_home();
    for op in ["recover", "schedule_recovery"] {
        let answer = ask_with(home.path(), op, json!({"failure_kind": "crash"}));
        assert_eq!(answer["kind"], "value", "{op}");
    }
}

#[test]
fn scheduling_is_skipped_while_protection_is_off() {
    let home = private_home();
    write_private(&home.path().join("config.toml"), "mode = \"observe\"\n");
    let answer = ask_with(
        home.path(),
        "schedule_recovery",
        json!({"failure_kind": "overload"}),
    );
    assert_eq!(answer["scheduled"], false);
    assert!(!home
        .path()
        .join("daemon-recovery-reservation.json")
        .exists());
}

#[test]
fn a_reservation_is_cleared_only_by_its_holder() {
    let home = private_home();
    let caller = super::host::Caller {
        guard_home: home.path().to_path_buf(),
        implicit_home: String::new(),
        own_pid: i64::from(std::process::id()),
        parent_pid: 0,
        frozen_runtime: false,
        frozen_parent_trusted: false,
        executable_name: None,
    };
    let path = home.path().join("daemon-recovery-reservation.json");
    let field = format!("{}{}", "tok", "en");
    write_private(
        &path,
        &json!({"created_at": 1.0, field: "a".repeat(32)}).to_string(),
    );
    assert!(!super::recover::clear(&caller, &"b".repeat(32)));
    assert!(path.exists());
    assert!(super::recover::clear(&caller, &"a".repeat(32)));
    assert!(!path.exists());
}

#[test]
fn locator_publish_without_an_authenticated_state_writes_nothing() {
    let home = private_home();
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": "locator_publish",
        "guard_home": home.path(),
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 5000,
        "args": {"daemon_url": "http://127.0.0.1:6175"},
    });
    let answer: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(answer["kind"], "runtime");
    assert!(!home.path().join("approval-center-locator.json").exists());
}

/// The heartbeat line the frozen entry point writes: its pid, the time, and
/// the launch nonce it was given.
const HEARTBEAT: &str = "$$ $(/bin/date +%s)000000000 $HOL_GUARD_DAEMON_LAUNCH_NONCE";

fn progress_pid(home: &Path) -> Option<i64> {
    super::start_progress::load_progress(home)
        .and_then(|progress| progress.get("pid").and_then(Value::as_i64))
}

fn kill_now(pid: Option<i64>) {
    if let Some(pid) = pid {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
}

/// A stand-in for the frozen Core: `heartbeat` is the line it writes, as the
/// entry point does, before it stays up without ever handing off.
fn slow_core(dir: &Path, heartbeat: Option<&str>) -> std::path::PathBuf {
    let path = dir.join("slow-core");
    let write = heartbeat.map_or(String::new(), |line| {
        format!(
            "umask 077\n/bin/sleep 1\nprintf '%s' \"{line}\" > \"$HOL_GUARD_DAEMON_START_HEARTBEAT.t\"\n\
             /bin/mv \"$HOL_GUARD_DAEMON_START_HEARTBEAT.t\" \"$HOL_GUARD_DAEMON_START_HEARTBEAT\"\n"
        )
    });
    fs::write(&path, format!("#!/bin/sh\n{write}exec /bin/sleep 30\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn ensure_slow_core(home: &Path, core: &Path) -> Value {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    ask_with(
        home,
        "ensure",
        json!({
            "budget_ms": 4000,
            "launch": {"state": {
                "package_version": "1.0.0",
                "runtime_fingerprint": "slow-core-fingerprint",
            }},
            "executable": core,
            "home_dir": home,
            "launch_cwd": home,
            "preferred_port": port,
        }),
    )
}

fn pid_exists(pid: i64) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn a_frozen_core_still_starting_at_the_deadline_is_left_running() {
    let home = private_home();
    let core = slow_core(home.path(), Some(HEARTBEAT));
    let answer = ensure_slow_core(home.path(), &core);
    let progress = super::start_progress::load_progress(home.path());
    let pid = progress
        .as_ref()
        .and_then(|progress| progress.get("pid"))
        .and_then(Value::as_i64);
    let alive = pid.is_some_and(pid_exists);
    if let Some(pid) = pid {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    assert_eq!(answer["kind"], "timeout", "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .is_some_and(|error| error.contains("still starting")),
        "{answer}"
    );
    assert!(alive, "the starting Core was killed: {progress:?}");
}

#[test]
fn a_silent_core_at_the_deadline_is_still_terminated() {
    let home = private_home();
    let core = slow_core(home.path(), None);
    let answer = ensure_slow_core(home.path(), &core);
    assert_eq!(answer["kind"], "runtime", "{answer}");
    assert!(super::start_progress::load_progress(home.path()).is_none());
}

#[test]
fn a_heartbeat_from_outside_the_spawned_tree_does_not_count() {
    let home = private_home();
    let core = slow_core(
        home.path(),
        Some("1 $(/bin/date +%s)000000000 $HOL_GUARD_DAEMON_LAUNCH_NONCE"),
    );
    let answer = ensure_slow_core(home.path(), &core);
    assert_eq!(answer["kind"], "runtime", "{answer}");
    assert!(super::start_progress::load_progress(home.path()).is_none());
}

#[test]
fn a_heartbeat_without_this_launchs_nonce_does_not_count() {
    let home = private_home();
    let other_nonce = "0".repeat(64);
    let core = slow_core(
        home.path(),
        Some(&format!("$$ $(/bin/date +%s)000000000 {other_nonce}")),
    );
    let answer = ensure_slow_core(home.path(), &core);
    assert_eq!(answer["kind"], "runtime", "{answer}");
    assert!(super::start_progress::load_progress(home.path()).is_none());
}

/// The stand-in Core execs `/bin/sleep`, which is not a Guard daemon command,
/// so its progress marker no longer counts as live, the same verdict an
/// expired marker gets. The second start therefore takes the stalled-launch
/// path: it settles that launch's receipt instead of refusing to start.
#[test]
fn a_still_starting_launch_that_never_hands_off_does_not_block_the_next_start() {
    let home = private_home();
    let core = slow_core(home.path(), Some(HEARTBEAT));
    let first = ensure_slow_core(home.path(), &core);
    let first_pid = progress_pid(home.path());
    let second = ensure_slow_core(home.path(), &core);
    let second_pid = progress_pid(home.path());
    kill_now(first_pid);
    kill_now(second_pid);
    assert_eq!(first["kind"], "timeout", "{first}");
    assert!(first_pid.is_some(), "the first launch recorded no progress");
    let error = second["error"].as_str().unwrap_or_default();
    assert!(
        !error.contains("previous Guard daemon launch") && !error.contains("In-progress"),
        "a stalled launch blocked the next start: {second}"
    );
    assert_eq!(second["kind"], "timeout", "{second}");
    assert_ne!(second_pid, first_pid, "{second}");
}
