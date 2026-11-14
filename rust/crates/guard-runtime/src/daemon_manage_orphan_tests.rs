//! A daemon of this home that lost its state must not keep the next start
//! from replacing it. Desktop updates hit both cases: the old daemon's state
//! was removed while it kept running, the new Core's launch exited on its
//! port, and every rollback start then refused on that launch's receipt.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command};

use serde_json::{json, Map, Value};

use super::{host, records, run_command};
use crate::daemon_edge::standalone::write_signed_record;

const PREVIOUS_LAUNCH: &str = "previous Guard daemon launch";

struct Running(Child);

impl Running {
    fn exited(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }
}

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A process the inventory reads as this home's daemon, with no state.
fn orphaned_daemon(home: &Path) -> Running {
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
            .arg(home)
            .args(["--port", &free_port().to_string()])
            .spawn()
            .unwrap(),
    )
}

fn dead_pid() -> i64 {
    let mut child = Command::new("/usr/bin/true").spawn().unwrap();
    child.wait().unwrap();
    i64::from(child.id())
}

/// The signed receipt a launch leaves when its child exits before handoff.
fn abandoned_receipt(home: &Path) {
    let nonce = "ab".repeat(32);
    let mut pending = Map::new();
    pending.insert("state_kind".into(), "daemon_launch_pending".into());
    pending.insert(
        "guard_home".into(),
        host::resolve_lenient(home)
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    pending.insert("pid".into(), dead_pid().into());
    pending.insert("port".into(), i64::from(free_port()).into());
    for key in ["launch_nonce", "launch_generation", "generation"] {
        pending.insert(key.into(), nonce.clone().into());
    }
    pending.insert(
        "process_start_marker".into(),
        "posix:Sat Nov 14 07:09:23 2026".into(),
    );
    let owner = host::own_owner_marker().unwrap();
    pending.insert("user".into(), owner.clone().into());
    pending.insert("owner".into(), owner.into());
    pending.insert("runtime_fingerprint".into(), "new-runtime".into());
    write_signed_record(home, "daemon-launch-pending.json", pending).unwrap();
    assert!(records::load_pending(home).is_some());
}

/// One start through a stand-in Core that records its launch and exits.
fn ensure(home: &Path) -> Value {
    let core = home.join("replacement-core");
    fs::write(&core, "#!/bin/sh\n: > launch-sentinel\n").unwrap();
    fs::set_permissions(&core, fs::Permissions::from_mode(0o700)).unwrap();
    let request = json!({
        "schema": "daemon-manage.v1",
        "op": "ensure",
        "guard_home": home,
        "implicit_home": "/nonexistent-implicit-home/.hol-guard",
        "budget_ms": 6000,
        "launch": {"state": {"package_version": "2.0.0", "runtime_fingerprint": "new-runtime"}},
        "executable": core,
        "home_dir": home,
        "launch_cwd": home,
        "preferred_port": free_port(),
    });
    let bytes = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn an_abandoned_receipt_does_not_block_a_start_while_an_orphaned_daemon_runs() {
    let home = private_home();
    let mut orphan = orphaned_daemon(home.path());
    abandoned_receipt(home.path());
    let answer = ensure(home.path());
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(!error.contains(PREVIOUS_LAUNCH), "{answer}");
    assert!(
        orphan.exited(),
        "the orphaned daemon kept running: {answer}"
    );
    assert!(
        home.path().join("launch-sentinel").exists(),
        "no replacement launched: {answer}"
    );
}

#[test]
fn a_start_retires_an_orphaned_daemon_before_it_launches() {
    let home = private_home();
    let mut orphan = orphaned_daemon(home.path());
    let answer = ensure(home.path());
    assert!(
        orphan.exited(),
        "the orphaned daemon kept running: {answer}"
    );
    assert!(
        home.path().join("launch-sentinel").exists(),
        "no replacement launched: {answer}"
    );
}

#[test]
fn a_live_launch_receipt_still_protects_its_daemon() {
    let home = private_home();
    let mut orphan = orphaned_daemon(home.path());
    let nonce = "cd".repeat(32);
    let pid = i64::from(orphan.0.id());
    let mut pending = Map::new();
    pending.insert("state_kind".into(), "daemon_launch_pending".into());
    pending.insert(
        "guard_home".into(),
        host::resolve_lenient(home.path())
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    pending.insert("pid".into(), pid.into());
    pending.insert("port".into(), i64::from(free_port()).into());
    for key in ["launch_nonce", "launch_generation", "generation"] {
        pending.insert(key.into(), nonce.clone().into());
    }
    pending.insert(
        "process_start_marker".into(),
        host::start_marker(pid).unwrap().into(),
    );
    let owner = host::own_owner_marker().unwrap();
    pending.insert("user".into(), owner.clone().into());
    pending.insert("owner".into(), owner.into());
    pending.insert("runtime_fingerprint".into(), "new-runtime".into());
    write_signed_record(home.path(), "daemon-launch-pending.json", pending).unwrap();
    let answer = ensure(home.path());
    assert!(!orphan.exited(), "a live launch was retired: {answer}");
    assert!(!home.path().join("launch-sentinel").exists(), "{answer}");
}
