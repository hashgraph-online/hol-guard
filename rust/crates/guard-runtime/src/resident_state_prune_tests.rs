use std::fs::{self, File};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};

use super::sockets::{default_socket_roots, probe_socket};
use super::{
    owner_lock_free, prune, run_command, unix_seconds, Host, Report, Settings, SocketState,
    OWNER_LOCK_NAME,
};

const HOUR: f64 = 3600.0;

struct FakeHost {
    alive: Vec<i64>,
    lock: Option<bool>,
    socket: SocketState,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self {
            alive: Vec::new(),
            lock: Some(true),
            socket: SocketState::Dead,
        }
    }
}

impl Host for FakeHost {
    fn pid_alive(&mut self, pid: i64) -> bool {
        self.alive.contains(&pid)
    }

    fn owner_lock_free(&mut self, _directory: &Path) -> Option<bool> {
        self.lock
    }

    fn probe_socket(&mut self, _socket: &Path) -> SocketState {
        self.socket
    }

    fn elapsed(&mut self) -> Duration {
        Duration::ZERO
    }
}

fn now() -> f64 {
    unix_seconds(SystemTime::now())
}

/// Settings that see every file written now as three hours old.
fn settings() -> Settings {
    Settings {
        now: now() + 3.0 * HOUR,
        min_age: HOUR,
        socket_min_age: 600.0,
        max_entries: 2000,
        dry_run: false,
        socket_roots: Some(Vec::new()),
    }
}

fn resident(home: &Path, name: &str, pids: (u64, u64)) -> PathBuf {
    let directory = home
        .join("native-runtime")
        .join(format!("resident-v3-{name}"));
    fs::create_dir_all(&directory).expect("resident dir");
    fs::write(
        directory.join("generation-0000000000000001.json"),
        json!({"process_id": pids.0, "owner_process_id": pids.1}).to_string(),
    )
    .expect("generation");
    fs::write(directory.join(OWNER_LOCK_NAME), b"").expect("owner lock");
    directory
}

fn prune_with(home: &Path, settings: &Settings, host: &mut FakeHost) -> Report {
    prune(home, settings, host)
}

/// A socket file nothing listens on.
fn dead_socket(path: &Path) {
    drop(UnixListener::bind(path).expect("bind"));
}

fn short_tempdir() -> tempfile::TempDir {
    // Socket paths have a short length limit, so stay out of a long TMPDIR.
    tempfile::Builder::new()
        .prefix("hgrp")
        .tempdir_in("/tmp")
        .expect("tempdir")
}

#[test]
fn a_stale_dir_with_dead_owners_is_removed() {
    let home = tempfile::tempdir().expect("tempdir");
    let stale = resident(home.path(), &"a".repeat(16), (111, 222));
    let report = prune_with(home.path(), &settings(), &mut FakeHost::default());
    assert!(!stale.exists());
    assert_eq!(report.removed_dirs, [stale.to_string_lossy()]);
    assert_eq!(report.stale_dirs, 1);
    let leftovers = fs::read_dir(home.path().join("native-runtime"))
        .expect("state dir")
        .count();
    assert_eq!(leftovers, 0, "no tombstone is left behind");
}

#[test]
fn a_dry_run_reports_without_deleting() {
    let home = tempfile::tempdir().expect("tempdir");
    let stale = resident(home.path(), &"a".repeat(16), (111, 222));
    let report = prune_with(
        home.path(),
        &Settings {
            dry_run: true,
            ..settings()
        },
        &mut FakeHost::default(),
    );
    assert!(stale.exists());
    assert_eq!(report.removed_dirs, [stale.to_string_lossy()]);
}

#[test]
fn dirs_without_full_proof_are_kept() {
    let cases: [(&str, FakeHost, &str); 3] = [
        (
            "live pid",
            FakeHost {
                alive: vec![222],
                ..FakeHost::default()
            },
            "owner_alive",
        ),
        (
            "held lock",
            FakeHost {
                lock: Some(false),
                ..FakeHost::default()
            },
            "owner_lock_unverified",
        ),
        (
            "unknowable lock",
            FakeHost {
                lock: None,
                ..FakeHost::default()
            },
            "owner_lock_unverified",
        ),
    ];
    for (label, mut host, reason) in cases {
        let home = tempfile::tempdir().expect("tempdir");
        let directory = resident(home.path(), &"b".repeat(16), (111, 222));
        let report = prune_with(home.path(), &settings(), &mut host);
        assert!(directory.exists(), "{label}");
        assert!(report.removed_dirs.is_empty(), "{label}");
        assert_eq!(report.kept.get(reason), Some(&1), "{label}");
    }
}

#[test]
fn a_recent_dir_is_kept() {
    let home = tempfile::tempdir().expect("tempdir");
    let directory = resident(home.path(), &"b".repeat(16), (111, 222));
    let recent = Settings {
        now: now(),
        ..settings()
    };
    let report = prune_with(home.path(), &recent, &mut FakeHost::default());
    assert!(directory.exists());
    assert_eq!(report.kept.get("recent"), Some(&1));
}

#[test]
fn unreadable_generation_state_keeps_the_dir_for_a_day() {
    for payload in [
        "{",
        "[]",
        r#"{"process_id": true}"#,
        r#"{"process_id": -4}"#,
    ] {
        let home = tempfile::tempdir().expect("tempdir");
        let directory = resident(home.path(), &"b".repeat(16), (111, 222));
        fs::write(directory.join("generation-0000000000000002.json"), payload).expect("state");
        let report = prune_with(home.path(), &settings(), &mut FakeHost::default());
        assert!(directory.exists(), "{payload}");
        assert_eq!(report.kept.get("unverifiable_state"), Some(&1), "{payload}");

        let a_day_later = Settings {
            now: now() + 25.0 * HOUR,
            ..settings()
        };
        prune_with(home.path(), &a_day_later, &mut FakeHost::default());
        assert!(!directory.exists(), "{payload}");
    }
}

#[test]
fn an_oversized_pid_counts_as_alive() {
    let home = tempfile::tempdir().expect("tempdir");
    let directory = resident(home.path(), &"b".repeat(16), (u64::MAX, 222));
    let mut host = FakeHost {
        alive: vec![i64::MAX],
        ..FakeHost::default()
    };
    prune_with(home.path(), &settings(), &mut host);
    assert!(directory.exists());
}

#[test]
fn a_symlinked_resident_dir_is_never_followed() {
    let home = tempfile::tempdir().expect("tempdir");
    let outside = home.path().join("outside");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("keep.txt"), b"x").expect("keep");
    dead_socket_in(&outside);
    let state = home.path().join("native-runtime");
    fs::create_dir(&state).expect("state dir");
    let link = state.join(format!("resident-v3-{}", "c".repeat(16)));
    symlink(&outside, &link).expect("symlink");
    let report = prune_with(home.path(), &settings(), &mut FakeHost::default());
    assert!(outside.join("keep.txt").exists());
    assert!(fs::symlink_metadata(&link).expect("link").is_symlink());
    assert_eq!(report.kept.get("not_directory"), Some(&1));
    assert!(
        report.removed_sockets.is_empty(),
        "the link is never walked"
    );
}

fn dead_socket_in(directory: &Path) {
    // `outside` lives under a long TMPDIR; bind through a short alias.
    let short = short_tempdir();
    let bound = short.path().join("hook-v2-1.sock");
    dead_socket(&bound);
    fs::rename(&bound, directory.join("hook-v2-1.sock")).expect("move socket");
}

#[test]
fn an_untrusted_state_dir_stops_the_prune() {
    let home = tempfile::tempdir().expect("tempdir");
    fs::write(home.path().join("native-runtime"), b"x").expect("file");
    let report = prune_with(home.path(), &settings(), &mut FakeHost::default());
    assert_eq!(report.outcome, "unavailable");
    assert_eq!(report.errors, ["state_dir_untrusted"]);
}

#[test]
fn probe_socket_tells_dead_from_live_and_gone() {
    let root = short_tempdir();
    let dead = root.path().join("d.sock");
    dead_socket(&dead);
    let live = root.path().join("l.sock");
    let _listener = UnixListener::bind(&live).expect("listen");
    assert_eq!(probe_socket(&dead), SocketState::Dead);
    assert_eq!(probe_socket(&live), SocketState::Live);
    assert_eq!(
        probe_socket(&root.path().join("missing.sock")),
        SocketState::Gone
    );
}

#[test]
fn only_dead_old_resident_sockets_are_removed() {
    let home = tempfile::tempdir().expect("tempdir");
    let root = short_tempdir();
    let names = [
        "hook-v2-1.sock",
        "h3-aaaa-0000000000000001.sock",
        "other.sock",
    ];
    for name in names {
        dead_socket(&root.path().join(name));
    }
    fs::write(root.path().join("hook-v2-notasocket.sock"), b"x").expect("file");
    let with_root = Settings {
        socket_roots: Some(vec![root.path().to_path_buf()]),
        ..settings()
    };
    let report = prune_with(home.path(), &with_root, &mut FakeHost::default());
    assert!(!root.path().join(names[0]).exists());
    assert!(!root.path().join(names[1]).exists());
    assert!(root.path().join("other.sock").exists());
    assert!(root.path().join("hook-v2-notasocket.sock").exists());
    assert_eq!(report.dead_sockets, 2);
    assert_eq!(report.kept.get("not_socket"), Some(&1));

    // A socket that still answers is never removed.
    dead_socket(&root.path().join("hook-v2-live.sock"));
    let mut live = FakeHost {
        socket: SocketState::Live,
        ..FakeHost::default()
    };
    let kept = prune_with(home.path(), &with_root, &mut live);
    assert!(root.path().join("hook-v2-live.sock").exists());
    assert!(kept.removed_sockets.is_empty());

    // Nor one that is too recent to judge.
    let recent = Settings {
        now: now(),
        ..with_root
    };
    let report = prune_with(home.path(), &recent, &mut FakeHost::default());
    assert!(root.path().join("hook-v2-live.sock").exists());
    assert_eq!(report.kept.get("recent_socket"), Some(&1));
}

#[test]
fn owner_lock_free_sees_a_held_flock() {
    let directory = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        owner_lock_free(directory.path()),
        Some(true),
        "never created"
    );
    let lock = directory.path().join(OWNER_LOCK_NAME);
    fs::write(&lock, b"").expect("lock");
    let held = File::open(&lock).expect("open");
    fs2::FileExt::lock_exclusive(&held).expect("lock");
    assert_eq!(owner_lock_free(directory.path()), Some(false));
    drop(held);
    assert_eq!(owner_lock_free(directory.path()), Some(true));
}

#[test]
fn the_entry_budget_bounds_work() {
    let home = tempfile::tempdir().expect("tempdir");
    for index in 0..5 {
        resident(home.path(), &format!("{index:016x}"), (111, 222));
    }
    let report = prune_with(
        home.path(),
        &Settings {
            max_entries: 2,
            ..settings()
        },
        &mut FakeHost::default(),
    );
    assert!(report.budget_exhausted);
    assert_eq!(report.stale_dirs, 2);
}

#[test]
fn a_missing_state_dir_is_a_clean_no_op() {
    let home = tempfile::tempdir().expect("tempdir");
    let report = prune_with(home.path(), &settings(), &mut FakeHost::default());
    assert_eq!(report.outcome, "ok");
    assert_eq!((report.stale_dirs, report.dead_sockets), (0, 0));
}

#[test]
fn default_socket_roots_only_returns_private_dirs_of_this_user() {
    let base = tempfile::tempdir().expect("tempdir");
    let private = base.path().join("hgr-private");
    fs::create_dir(&private).expect("private");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("mode");
    let shared = base.path().join("hgr-shared");
    fs::create_dir(&shared).expect("shared");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("mode");
    fs::write(base.path().join("hgr-file"), b"x").expect("file");
    symlink(&private, base.path().join("hgr-link")).expect("symlink");
    fs::create_dir(base.path().join("other")).expect("other");

    let missing = base.path().join("missing");
    assert_eq!(
        default_socket_roots(&[missing.as_path(), base.path()]),
        [private]
    );
}

fn answer(request: &Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("json answer"))
}

#[test]
fn the_command_prunes_a_dead_resident() {
    let home = tempfile::tempdir().expect("tempdir");
    let stale = resident(home.path(), &"e".repeat(16), (1 << 30, (1 << 30) + 1));
    let hours_ago = SystemTime::now() - Duration::from_secs(3 * 3600);
    for entry in fs::read_dir(&stale).expect("entries") {
        let file = File::options()
            .write(true)
            .open(entry.expect("entry").path())
            .expect("open");
        file.set_modified(hours_ago).expect("age file");
    }
    File::open(&stale)
        .expect("open dir")
        .set_modified(hours_ago)
        .expect("age dir");
    let request = |dry_run: bool| {
        json!({
            "schema": "resident-state-prune.v1",
            "guard_home": home.path(),
            "dry_run": dry_run,
            "include_system_sockets": false,
        })
    };

    let planned = answer(&request(true)).expect("dry run");
    assert_eq!(planned["outcome"], "ok");
    assert_eq!(planned["dry_run"], true);
    assert_eq!(planned["stale_dirs"], 1);
    assert!(stale.exists());

    let done = answer(&request(false)).expect("prune");
    assert_eq!(done["stale_dirs"], 1);
    assert_eq!(done["removed_dirs"], json!([stale]));
    assert!(!stale.exists());
    assert_eq!(answer(&request(false)).expect("again")["stale_dirs"], 0);
}

#[test]
fn the_command_refuses_malformed_requests() {
    for request in [
        json!({"schema": "other", "guard_home": "/x", "dry_run": true, "include_system_sockets": false}),
        json!({"schema": "resident-state-prune.v1", "guard_home": "relative", "dry_run": true, "include_system_sockets": false}),
        json!({"schema": "resident-state-prune.v1", "guard_home": "/x", "dry_run": true}),
        json!({"schema": "resident-state-prune.v1", "guard_home": "/x", "dry_run": true, "include_system_sockets": false, "extra": 1}),
    ] {
        assert_eq!(
            answer(&request),
            Err("resident_state_prune_request_invalid".to_owned()),
            "{request}"
        );
    }
}
