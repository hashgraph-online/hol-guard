use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{ffi, Connection};
use serde_json::{json, Value};

use super::{classify, detail, probe, restore, run_command, suffixed, Detail, State};

const WAIT: Duration = Duration::from_secs(1);

fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(dir.path()).expect("canonical tempdir");
    (dir, root)
}

fn healthy_store(path: &Path) {
    let connection = Connection::open(path).expect("open");
    connection
        .execute_batch("create table keep (value integer); insert into keep values (7);")
        .expect("seed");
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn answer(request: &Value) -> Value {
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    serde_json::from_slice(&bytes).expect("json answer")
}

#[test]
fn routes_extended_codes_by_their_primary_byte() {
    assert_eq!(classify(ffi::SQLITE_CORRUPT), State::Fatal);
    assert_eq!(classify(ffi::SQLITE_NOTADB), State::Fatal);
    // SQLITE_CORRUPT_VTAB
    assert_eq!(classify(267), State::Fatal);
    // SQLITE_IOERR_READ and SQLITE_IOERR_FSYNC stay I/O whatever they say.
    assert_eq!(classify(266), State::Io);
    assert_eq!(classify(1034), State::Io);
    assert_eq!(classify(ffi::SQLITE_CANTOPEN), State::Unknown);
    assert_eq!(classify(ffi::SQLITE_BUSY), State::Unknown);
}

#[test]
fn probes_a_healthy_store_whose_path_carries_reserved_characters() {
    let (_dir, root) = tempdir();
    let home = root.join("guard?home#1");
    fs::create_dir(&home).expect("home");
    let path = home.join("guard.db");
    healthy_store(&path);

    assert_eq!(probe(&path, WAIT), State::Healthy);
}

#[test]
fn probes_a_file_that_is_not_a_database_as_fatal() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    fs::write(&path, b"not a sqlite database, padded past the header size").expect("write");

    assert_eq!(probe(&path, WAIT), State::Fatal);
}

#[test]
fn probes_a_missing_store_as_unknown() {
    let (_dir, root) = tempdir();
    assert_eq!(probe(&root.join("missing.db"), WAIT), State::Unknown);
}

#[test]
fn two_stable_fatal_probes_with_a_writable_home_prove_the_store_unusable() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    fs::write(&path, b"store").expect("write");

    let detail = detail(&path, |_path| State::Fatal, || true);

    assert_eq!(
        detail,
        Detail {
            proven_unusable: true,
            first_state: State::Fatal,
            second_state: Some(State::Fatal),
            guard_home_accepts_write: Some(true),
            identity_stable: true,
        }
    );
}

#[test]
fn a_store_that_turns_healthy_on_the_second_probe_is_not_proven() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    let mut probes = [State::Fatal, State::Healthy].into_iter();

    let detail = detail(
        &path,
        |_path| probes.next().unwrap_or(State::Unknown),
        || true,
    );

    assert!(!detail.proven_unusable);
    assert_eq!(detail.second_state, Some(State::Healthy));
}

#[test]
fn a_sidecar_rewritten_during_the_probe_refuses_proof() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    fs::write(&path, b"store").expect("store");
    let wal = suffixed(&path, "-wal");
    fs::write(&wal, b"first").expect("wal");
    let mut probes = 0;

    let detail = detail(
        &path,
        |_path| {
            probes += 1;
            fs::write(&wal, b"other, longer").expect("rewrite");
            State::Fatal
        },
        || true,
    );

    assert_eq!(probes, 1);
    assert!(!detail.proven_unusable && !detail.identity_stable);
    assert_eq!(detail.second_state, None);
}

#[test]
fn a_home_that_refuses_writes_is_never_proof_of_corruption() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    let mut probes = 0;

    let detail = detail(
        &path,
        |_path| {
            probes += 1;
            State::Fatal
        },
        || false,
    );

    assert_eq!(probes, 1);
    assert!(!detail.proven_unusable);
    assert_eq!(detail.guard_home_accepts_write, Some(false));
}

#[test]
fn io_and_unknown_first_probes_stop_before_the_write_check() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    for state in [State::Io, State::Unknown, State::Healthy] {
        let detail = detail(&path, |_path| state, || panic!("write probe ran"));
        assert!(!detail.proven_unusable && detail.identity_stable);
        assert_eq!(detail.first_state, state);
    }
}

#[test]
fn command_proves_a_corrupt_store_and_leaves_no_write_probe() {
    let (_dir, root) = tempdir();
    let path = root.join("guard.db");
    fs::write(&path, b"not a sqlite database, padded past the header size").expect("write");

    let answer = answer(&json!({
        "schema": "sqlite-store-probe.v1",
        "op": "detail",
        "path": text(&path),
        "guard_home": text(&root),
        "wait_seconds": 1.0,
    }));

    assert_eq!(
        answer,
        json!({
            "proven_unusable": true,
            "first_state": "fatal",
            "second_state": "fatal",
            "guard_home_accepts_write": true,
            "identity_stable": true,
        })
    );
    let leftovers: Vec<_> = fs::read_dir(&root)
        .expect("read home")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("storage-probe-")
        })
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn restores_a_healthy_quarantined_store_with_its_sidecars() {
    let (_dir, root) = tempdir();
    let destination = root.join("guard.db");
    let quarantined = root.join("guard.db.corrupt-1");
    healthy_store(&quarantined);
    fs::write(suffixed(&quarantined, "-shm"), b"").expect("shm");

    let answer = answer(&json!({
        "schema": "sqlite-store-probe.v1",
        "op": "restore",
        "path": text(&destination),
        "quarantined": text(&quarantined),
        "wait_seconds": 1.0,
    }));

    assert_eq!(answer, json!({"restored": true}));
    assert!(destination.is_file() && !quarantined.exists());
    assert!(suffixed(&destination, "-shm").exists());
}

#[test]
fn never_restores_over_an_existing_store_or_a_corrupt_one() {
    let (_dir, root) = tempdir();
    let destination = root.join("guard.db");
    let quarantined = root.join("guard.db.corrupt-1");
    healthy_store(&quarantined);
    fs::write(&destination, b"").expect("destination");
    assert!(!restore(&destination, &quarantined, WAIT));
    assert!(quarantined.exists());

    fs::remove_file(&destination).expect("remove");
    fs::write(
        &quarantined,
        b"not a sqlite database, padded past the header size",
    )
    .expect("corrupt");
    assert!(!restore(&destination, &quarantined, WAIT));
    assert!(quarantined.exists() && !destination.exists());
}

#[test]
fn restore_rolls_back_when_a_sidecar_move_fails() {
    let (_dir, root) = tempdir();
    let destination = root.join("guard.db");
    let quarantined = root.join("guard.db.corrupt-1");
    healthy_store(&quarantined);
    let wal = suffixed(&quarantined, "-wal");
    fs::write(&wal, b"").expect("wal");
    let shm = suffixed(&quarantined, "-shm");
    fs::write(&shm, b"").expect("shm");
    // A non-empty directory where the shared-memory file would land refuses
    // the rename on every platform.
    let blocked = suffixed(&destination, "-shm");
    fs::create_dir(&blocked).expect("blocked");
    fs::write(blocked.join("keep"), b"").expect("keep");

    assert!(!restore(&destination, &quarantined, WAIT));

    assert!(quarantined.is_file() && wal.exists() && shm.exists());
    assert!(!destination.exists() && !suffixed(&destination, "-wal").exists());
}

#[test]
fn command_refuses_malformed_requests() {
    let base = json!({
        "schema": "sqlite-store-probe.v1",
        "op": "detail",
        "path": "/tmp/guard.db",
        "guard_home": "/tmp",
        "wait_seconds": 1.0,
    });
    let with = |key: &str, value: Value| {
        let mut request = base.clone();
        request[key] = value;
        request.to_string()
    };
    let mut no_home = base.clone();
    if let Some(object) = no_home.as_object_mut() {
        object.remove("guard_home");
    }
    for request in [
        "not json".to_owned(),
        with("schema", json!("other")),
        with("op", json!("delete")),
        with("path", json!("guard.db")),
        with("guard_home", json!("relative")),
        with("quarantined", json!("/tmp/q")),
        with("wait_seconds", json!(0.0)),
        with("wait_seconds", json!(-1.0)),
        with("extra", json!(1)),
        no_home.to_string(),
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("sqlite_store_probe_request_invalid".to_owned()),
            "{request}"
        );
    }
}
