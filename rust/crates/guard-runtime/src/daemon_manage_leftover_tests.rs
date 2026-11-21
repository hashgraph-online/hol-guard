//! A process that looks like this home's daemon but that Guard cannot prove
//! is its own must never be signalled, and must not stop a start either. It
//! used to: retirement could not finish, so every start refused until the
//! home was repaired by hand.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

use super::leftovers::FOREIGN_OWNER_FOR_TEST;
use super::orphan_tests::{abandoned_receipt, free_port, private_home, Running};
use super::run_command;

const PREVIOUS_LAUNCH: &str = "previous Guard daemon launch";

/// A process whose command line the inventory reads as this home's daemon
/// on `port`, but whose owner Guard cannot match to its own.
struct LookAlike(Running);

impl LookAlike {
    fn spawn(home: &Path, port: u16) -> Self {
        let running = Running::spawn(
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
                .arg(home)
                .args(["--port", &port.to_string()]),
        );
        FOREIGN_OWNER_FOR_TEST
            .lock()
            .unwrap()
            .push(i64::from(running.pid()));
        Self(running)
    }

    fn pid(&self) -> u32 {
        self.0.pid()
    }

    fn still_running(&mut self) -> bool {
        !self.0.exited()
    }
}

impl Drop for LookAlike {
    fn drop(&mut self) {
        let pid = i64::from(self.0.pid());
        if let Ok(mut pids) = FOREIGN_OWNER_FOR_TEST.lock() {
            pids.retain(|foreign| *foreign != pid);
        }
    }
}

/// One start through a stand-in Core that records the arguments it was
/// launched with and exits.
fn ensure(home: &Path, preferred_port: u16, env_port: Option<u16>) -> Value {
    let core = home.join("replacement-core");
    fs::write(&core, "#!/bin/sh\nprintf '%s\\n' \"$@\" > launch-args\n").unwrap();
    fs::set_permissions(&core, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = json!({
        "schema": "daemon-manage.v1",
        "op": "ensure",
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 6000,
        "launch": {"state": {"package_version": "2.0.0", "runtime_fingerprint": "new-runtime"}},
        "executable": core,
        "home_dir": home,
        "launch_cwd": home,
        "preferred_port": preferred_port,
    });
    if let Some(port) = env_port {
        request["env_port"] = port.to_string().into();
    }
    let bytes = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The port the stand-in Core was launched on, if it was launched.
fn launch_port(home: &Path) -> Option<u16> {
    let args = fs::read_to_string(home.join("launch-args")).ok()?;
    let mut args = args.lines();
    args.find(|arg| *arg == "--port")?;
    args.next()?.parse().ok()
}

fn left_alone(home: &Path, pid: u32) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(home.join("daemon-lifecycle")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(|event| event["event"] == "leftover_left_alone" && event["pid"] == pid)
        .collect()
}

#[test]
fn a_start_leaves_an_unproven_look_alike_running_and_launches_on_another_port() {
    let home = private_home();
    let port = free_port();
    let mut look_alike = LookAlike::spawn(home.path(), port);
    let answer = ensure(home.path(), port, None);
    assert!(
        look_alike.still_running(),
        "the look-alike was signalled: {answer}"
    );
    let launched = launch_port(home.path());
    assert!(
        launched.is_some_and(|launched| launched != port),
        "the start did not move past the look-alike's port {port}: launched on {launched:?}, {answer}"
    );
    let records = left_alone(home.path(), look_alike.pid());
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["reason"], "foreign_owner");
    assert_eq!(records[0]["port"], port);
}

/// The fixture the reliability plan names: a stale launch receipt and a
/// look-alike daemon. The start must succeed with no other command.
#[test]
fn an_abandoned_receipt_and_an_unproven_look_alike_do_not_block_a_start() {
    let home = private_home();
    let port = free_port();
    let mut look_alike = LookAlike::spawn(home.path(), port);
    abandoned_receipt(home.path());
    let answer = ensure(home.path(), port, None);
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(!error.contains(PREVIOUS_LAUNCH), "{answer}");
    assert!(
        look_alike.still_running(),
        "the look-alike was signalled: {answer}"
    );
    let launched = launch_port(home.path());
    assert!(
        launched.is_some_and(|launched| launched != port),
        "no launch past the look-alike's port {port}: launched on {launched:?}, {answer}"
    );
}

#[test]
fn a_look_alike_on_the_only_port_is_named_and_left_running() {
    let home = private_home();
    let port = free_port();
    let mut look_alike = LookAlike::spawn(home.path(), port);
    let answer = ensure(home.path(), port, Some(port));
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(&format!("pid {} on port {port}", look_alike.pid())),
        "{answer}"
    );
    assert!(error.contains("codex_plugin_scanner.cli"), "{answer}");
    assert!(
        look_alike.still_running(),
        "the look-alike was signalled: {answer}"
    );
    assert_eq!(launch_port(home.path()), None, "{answer}");
}
