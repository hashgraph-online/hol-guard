//! A daemon of this home that lost its state must not keep the next start
//! from replacing it. Desktop updates hit both cases: the old daemon's state
//! was removed while it kept running, the new Core's launch exited on its
//! port, and every rollback start then refused on that launch's receipt.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::ensure::start_lock;
use super::retire::Deadline;
use super::{host, records, run_command};
use crate::daemon_edge::standalone::write_signed_record;

const PREVIOUS_LAUNCH: &str = "previous Guard daemon launch";

pub(super) struct Running(Child);

impl Running {
    pub(super) fn spawn(command: &mut Command) -> Self {
        Self(command.process_group(0).spawn().unwrap())
    }

    pub(super) fn pid(&self) -> u32 {
        self.0.id()
    }

    pub(super) fn exited(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }
}

impl Drop for Running {
    /// The stand-in leads its own process group; stop the shell and its
    /// `sleep` together so neither outlives the test.
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.0.id())])
            .status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

pub(super) fn free_port() -> u16 {
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
            .process_group(0)
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
pub(super) fn abandoned_receipt(home: &Path) {
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

/// One start through a stand-in Core that records its launch and exits. The
/// stand-in records nothing while `orphan` is still running, so a launch that
/// races ahead of the orphan's retirement leaves no sentinel. The orphan is
/// this test's child, so once stopped it lingers as a zombie until reaped.
fn ensure(home: &Path, orphan: u32) -> Value {
    let core = home.join("replacement-core");
    let script = format!(
        "#!/bin/sh\ncase \"$(/bin/ps -o stat= -p {orphan} 2>/dev/null)\" in\n  ''|Z*) : > launch-sentinel ;;\nesac\n"
    );
    fs::write(&core, script).unwrap();
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
    let answer = ensure(home.path(), orphan.pid());
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(!error.contains(PREVIOUS_LAUNCH), "{answer}");
    assert!(
        orphan.exited(),
        "the orphaned daemon kept running: {answer}"
    );
    assert!(
        home.path().join("launch-sentinel").exists(),
        "no replacement launched after the orphan stopped: {answer}"
    );
}

#[test]
fn a_start_retires_an_orphaned_daemon_before_it_launches() {
    let home = private_home();
    let mut orphan = orphaned_daemon(home.path());
    let answer = ensure(home.path(), orphan.pid());
    assert!(
        orphan.exited(),
        "the orphaned daemon kept running: {answer}"
    );
    assert!(
        home.path().join("launch-sentinel").exists(),
        "no replacement launched after the orphan stopped: {answer}"
    );
}

/// The signed receipt a launch writes while its launcher, `launcher`, is
/// still running and handing off.
fn live_receipt(home: &Path, launcher: &Running) {
    let nonce = "cd".repeat(32);
    let pid = i64::from(launcher.pid());
    let mut pending = Map::new();
    pending.insert("state_kind".into(), "daemon_launch_pending".into());
    pending.insert(
        "guard_home".into(),
        host::resolve_lenient(home)
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
    write_signed_record(home, "daemon-launch-pending.json", pending).unwrap();
}

#[test]
fn a_live_launch_receipt_still_protects_its_daemon() {
    let home = private_home();
    let mut orphan = orphaned_daemon(home.path());
    live_receipt(home.path(), &orphan);
    // Gate the stand-in on a pid that is already gone, so any launch at all
    // leaves the sentinel this test expects to stay absent.
    let gone = u32::try_from(dead_pid()).unwrap();
    let answer = ensure(home.path(), gone);
    assert!(!orphan.exited(), "a live launch was retired: {answer}");
    assert!(!home.path().join("launch-sentinel").exists(), "{answer}");
}

/// A Core update and a hook recovery can start the daemon at the same time.
/// The second starter finds the first one's receipt naming a live launcher;
/// it must wait for the first to finish its handoff under the start lock,
/// not fail at once with the previous-launch refusal.
#[test]
fn a_start_waits_for_another_starter_still_handing_off_its_launch() {
    let home = private_home();
    let launcher = orphaned_daemon(home.path());
    live_receipt(home.path(), &launcher);
    let deadline = Deadline(Some(Instant::now() + Duration::from_secs(5)));
    let Ok(lock) = start_lock(home.path(), deadline) else {
        panic!("the start lock could not be taken");
    };
    // The second starter begins while the first holds the lock and its
    // receipt names a live launcher.
    let (answered, answer) = std::sync::mpsc::channel();
    let second = {
        let home = home.path().to_path_buf();
        let gone = u32::try_from(dead_pid()).unwrap();
        std::thread::spawn(move || {
            let _ = answered.send(ensure(&home, gone));
        })
    };
    let early = answer.recv_timeout(Duration::from_millis(800));
    assert!(
        early.is_err(),
        "the start answered while another starter held the lock: {early:?}"
    );
    // The first starter's handoff clears its receipt, then it releases the
    // start lock.
    fs::remove_file(home.path().join("daemon-launch-pending.json")).unwrap();
    drop(lock);
    let answer = answer.recv_timeout(Duration::from_secs(10)).unwrap();
    second.join().unwrap();
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(!error.contains(PREVIOUS_LAUNCH), "{answer}");
    assert!(
        home.path().join("launch-sentinel").exists(),
        "no launch after the first starter finished: {answer}"
    );
    drop(launcher);
}
