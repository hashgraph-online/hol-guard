//! Adopting a daemon that already published its own state.
//!
//! A starter that found no live daemon waits on the start lock, and by the
//! time it holds the lock another starter's daemon may be serving. Adoption
//! must then leave that daemon's state alone: rewriting it from this caller's
//! launch configuration stamps the daemon with the caller's runtime identity.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::super::host::Caller;
use super::super::retire::Deadline;
use super::{publish_adopted, Context, Ensure, COMPATIBILITY_VERSION};
use crate::daemon_policy_authority::load_authenticated_daemon_identity;

const PORT: u16 = 45_731;

fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("guard home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private home");
    }
    home
}

fn caller(home: &Path) -> Caller {
    Caller {
        guard_home: home.to_path_buf(),
        implicit_home: "/nonexistent-implicit-home/.hol-guard".into(),
        own_pid: i64::from(std::process::id()),
        parent_pid: 0,
        frozen_runtime: false,
        frozen_parent_trusted: false,
        executable_name: None,
    }
}

fn launch(home: &Path, fingerprint: &str) -> Map<String, Value> {
    json!({
        "schema": "guard-daemon-serve-launch.v1",
        "guard_home": home.to_str().expect("utf-8 home"),
        "port": PORT,
        "store_path": home.join("guard.db").to_str().expect("utf-8 store"),
        "source": "test",
        "busy_timeout_ms": 1000,
        "cli_command": ["hol-guard"],
        "state": {
            "compatibility_version": COMPATIBILITY_VERSION,
            "package_version": "3.60.0",
            "source_root": "/nonexistent-source-root",
            "runtime_fingerprint": fingerprint,
        },
    })
    .as_object()
    .expect("object")
    .clone()
}

/// Adopts `pid` on `PORT` as a caller whose runtime fingerprint is `fingerprint`.
fn adopt_as(home: &Path, fingerprint: &str, pid: u32) -> Option<bool> {
    let caller = caller(home);
    let launch = launch(home, fingerprint);
    let env = BTreeMap::new();
    let request = Ensure {
        launch: &launch,
        serve_executable: None,
        executable: None,
        home_dir: None,
        launch_cwd: None,
        preferred_port: None,
        background_maintenance: false,
        allow_windows_job_breakaway: false,
        start_lock_held: true,
        launcher_env: &env,
        env_port: None,
    };
    let current = launch["state"].as_object().expect("state").clone();
    let context = Context {
        caller: &caller,
        request: &request,
        deadline: Deadline(None),
        current,
    };
    publish_adopted(&context, PORT, pid)
}

fn published(home: &Path) -> Map<String, Value> {
    load_authenticated_daemon_identity(home)
        .expect("authenticated daemon state")
        .0
}

#[test]
fn an_older_starter_keeps_the_identity_a_serving_daemon_published() {
    let home = private_home();
    let pid = std::process::id();
    assert_eq!(adopt_as(home.path(), "current-runtime", pid), Some(true));
    let before = published(home.path());

    assert_eq!(adopt_as(home.path(), "older-runtime", pid), Some(true));

    let after = published(home.path());
    assert_eq!(after["runtime_fingerprint"], "current-runtime");
    assert_eq!(after["state_id"], before["state_id"]);
}

#[test]
fn a_daemon_the_state_does_not_name_is_published_again() {
    let home = private_home();
    let pid = std::process::id();
    assert_eq!(adopt_as(home.path(), "current-runtime", pid), Some(true));

    assert_eq!(
        adopt_as(home.path(), "current-runtime", pid + 1),
        Some(true)
    );

    let after = published(home.path());
    assert_eq!(after["pid"], pid + 1);
    assert_eq!(after["port"], PORT);
}

#[test]
fn a_home_without_state_publishes_the_adopted_daemon() {
    let home = private_home();
    let pid = std::process::id();

    assert_eq!(adopt_as(home.path(), "older-runtime", pid), Some(true));

    let after = published(home.path());
    assert_eq!(after["pid"], pid);
    assert_eq!(after["runtime_fingerprint"], "older-runtime");
}
