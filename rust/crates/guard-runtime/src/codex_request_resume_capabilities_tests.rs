//! The capability report: ports of the `inspect_codex_resume_capabilities`
//! checks of `codex_resume.py`.

#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

use guard_contracts::CodexRequestResumeRequestV1;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::capabilities;
use crate::codex_request_resume_op::Outcome;

fn store(rows: bool) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_request_resumes (
               request_id text primary key, operation_id text, harness text not null,
               resolution_action text, strategy text not null,
               supported integer not null default 0, status text not null, thread_id text,
               reason text, message text, last_error text,
               attempt_count integer not null default 0, created_at text not null,
               updated_at text not null, last_attempt_at text, sent_at text,
               continuation_contract_version text, continuation_capability text,
               continuation_status text, continuation_reason text,
               continuation_evidence_json text not null default '[]',
               continuation_offer_hash text, continuation_action text,
               continuation_completed_at text, continuation_cancelled_at text);",
        )
        .unwrap();
    if rows {
        connection
            .execute_batch(
                "insert into guard_request_resumes
                   (request_id, harness, strategy, supported, status, created_at, updated_at,
                    last_attempt_at)
                 values
                   ('req-old', 'codex', 'thread', 1, 'failed', 't0', 't1', 't2'),
                   ('req-new', 'codex', 'thread', 1, 'sent', 't0', 't3', 't4'),
                   ('req-pi', 'pi', 'manual-only', 0, 'pending', 't0', 't9', 't9');",
            )
            .unwrap();
    }
    connection
}

fn request(home: &Path, codex_home: Option<&Path>) -> CodexRequestResumeRequestV1 {
    serde_json::from_value(json!({
        "schema": "guard-codex-request-resume-request.v1",
        "approval_request_id": "req-new",
        "call": "capabilities",
        "now": "2026-05-19T10:00:00+00:00",
        "store_path": "/unused",
        "guard_home": "/unused",
        "busy_timeout_ms": 1000,
        "home_dir": home,
        "temp_dir": "/tmp",
        "cwd": home,
        "codex_home": codex_home,
        "timeout_ms": 1000,
    }))
    .unwrap()
}

fn report(connection: &Connection, request: &CodexRequestResumeRequestV1) -> (bool, Value) {
    match capabilities(connection, request).unwrap() {
        Outcome::Capabilities {
            socket_available,
            latest_attempt,
        } => (socket_available, latest_attempt),
        other => panic!("not a capability report: {other:?}"),
    }
}

/// A private Codex home under `/tmp` with a listening control socket.
fn listening_home() -> (tempfile::TempDir, UnixListener) {
    let home = tempfile::Builder::new()
        .prefix("hgc")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = home.path().join("app-server-control");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("app-server-control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    (home, listener)
}

#[test]
fn a_listening_private_socket_is_available() {
    let (home, _listener) = listening_home();
    let (available, _) = report(&store(false), &request(home.path(), Some(home.path())));
    assert!(available);
}

#[test]
fn the_default_socket_is_under_the_callers_home() {
    let (home, _listener) = listening_home();
    let default = home.path().join(".codex");
    std::fs::rename(home.path().join("app-server-control"), {
        std::fs::create_dir(&default).unwrap();
        std::fs::set_permissions(&default, std::fs::Permissions::from_mode(0o700)).unwrap();
        default.join("app-server-control")
    })
    .unwrap();
    let (available, _) = report(&store(false), &request(home.path(), None));
    assert!(available);
}

#[test]
fn a_missing_or_unreachable_socket_is_not_available() {
    let home = tempfile::Builder::new()
        .prefix("hgc")
        .tempdir_in("/tmp")
        .unwrap();
    let (available, latest) = report(&store(false), &request(home.path(), Some(home.path())));
    assert!(!available);
    assert_eq!(latest, Value::Null);
    // A socket file nothing listens on refuses the connection.
    let (stale_home, listener) = listening_home();
    drop(listener);
    let (available, _) = report(
        &store(false),
        &request(stale_home.path(), Some(stale_home.path())),
    );
    assert!(!available);
}

#[test]
fn a_socket_others_can_write_is_not_trusted() {
    let (home, _listener) = listening_home();
    let socket = home
        .path()
        .join("app-server-control/app-server-control.sock");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    let (available, _) = report(&store(false), &request(home.path(), Some(home.path())));
    assert!(!available);
}

#[test]
fn the_latest_codex_attempt_is_reported() {
    let home = tempfile::Builder::new()
        .prefix("hgc")
        .tempdir_in("/tmp")
        .unwrap();
    let (_, latest) = report(&store(true), &request(home.path(), None));
    assert_eq!(latest["request_id"], json!("req-new"));
    assert_eq!(latest["status"], json!("sent"));
}
