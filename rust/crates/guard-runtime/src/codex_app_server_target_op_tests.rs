//! Whether a recorded Codex target is safe and accepting connections.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;

/// A short folder under `/tmp`: a socket path has a small length limit.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("hg")
        .tempdir_in("/tmp")
        .expect("dir")
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).expect("dir");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
}

/// A listening owner-only socket at `path`, in an owner-only folder.
fn listen(path: &Path) -> UnixListener {
    private_dir(path.parent().expect("parent"));
    let listener = UnixListener::bind(path).expect("bind");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    listener
}

fn reachable(metadata: Value, home: &Path, cwd: Option<&Path>) -> bool {
    let request = json!({
        "metadata": metadata,
        "home_dir": home,
        "temp_dir": null,
        "cwd": cwd,
    });
    let answer = run_command(request.to_string().as_bytes()).expect("answer");
    let answer: Value = serde_json::from_slice(&answer).expect("json");
    answer["reachable"].as_bool().expect("flag")
}

fn default_socket(home: &Path) -> PathBuf {
    home.join(".codex")
        .join("app-server-control")
        .join("app-server-control.sock")
}

#[test]
fn the_default_socket_of_the_callers_home_is_reachable() {
    let home = short_dir();
    let _listener = listen(&default_socket(home.path()));

    assert!(reachable(
        json!({"codex_thread_id": "thread-safe-0001"}),
        home.path(),
        None
    ));
}

#[test]
fn a_recorded_codex_home_or_socket_overrides_the_default() {
    let home = short_dir();
    let elsewhere = home.path().join("alt");
    // A recorded Codex home replaces `~/.codex`, it does not sit under it.
    let _listener = listen(
        &elsewhere
            .join("app-server-control")
            .join("app-server-control.sock"),
    );
    let explicit = home.path().join("ctl").join("s.sock");
    let _explicit_listener = listen(&explicit);
    let thread = json!("thread-safe-0001");

    assert!(reachable(
        json!({"thread_id": thread, "codexHome": elsewhere}),
        home.path(),
        None
    ));
    for key in [
        "codex_app_server_socket",
        "app_server_socket",
        "appServerSocket",
    ] {
        assert!(
            reachable(
                json!({"threadId": thread, key: explicit}),
                home.path(),
                None
            ),
            "{key}"
        );
    }
}

#[test]
fn a_relative_socket_is_read_against_the_callers_directory() {
    let home = short_dir();
    let _listener = listen(&home.path().join("ctl").join("s.sock"));
    let metadata =
        json!({"session_id": "thread-safe-0001", "codex_app_server_socket": "ctl/s.sock"});

    assert!(reachable(metadata.clone(), home.path(), Some(home.path())));
    assert!(!reachable(metadata, home.path(), None));
}

#[test]
fn every_thread_spelling_names_the_target() {
    let home = short_dir();
    let _listener = listen(&default_socket(home.path()));

    for key in [
        "codex_thread_id",
        "thread_id",
        "threadId",
        "conversation_id",
        "conversationId",
        "session_id",
        "sessionId",
    ] {
        assert!(
            reachable(json!({key: " thread-safe-0001 "}), home.path(), None),
            "{key}"
        );
    }
}

#[test]
fn a_missing_or_unsafe_thread_id_is_never_reachable() {
    let home = short_dir();
    let _listener = listen(&default_socket(home.path()));
    let too_long = "t".repeat(257);

    for thread in [
        json!(null),
        json!(""),
        json!("   "),
        json!(7),
        json!("-flag"),
        json!("a b"),
        json!("a/b"),
        json!(too_long),
    ] {
        assert!(
            !reachable(json!({"codex_thread_id": thread}), home.path(), None),
            "{thread}"
        );
    }
    assert!(!reachable(json!({}), home.path(), None));
    assert!(reachable(
        json!({"codex_thread_id": "t".repeat(256)}),
        home.path(),
        None
    ));
}

#[test]
fn a_regular_file_is_not_a_control_socket() {
    let home = short_dir();
    let fake = default_socket(home.path());
    private_dir(fake.parent().expect("parent"));
    fs::write(&fake, "not a socket").expect("file");

    assert!(!reachable(
        json!({"codex_thread_id": "thread-safe-0001"}),
        home.path(),
        None
    ));
}

#[test]
fn a_socket_nobody_listens_on_is_not_reachable() {
    let home = short_dir();
    drop(listen(&default_socket(home.path())));

    assert!(!reachable(
        json!({"codex_thread_id": "thread-safe-0001"}),
        home.path(),
        None
    ));
}

#[test]
fn a_socket_or_folder_others_can_write_is_not_trusted() {
    let home = short_dir();
    let socket = default_socket(home.path());
    let _listener = listen(&socket);
    let metadata = json!({"codex_thread_id": "thread-safe-0001"});

    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).expect("mode");
    assert!(!reachable(metadata.clone(), home.path(), None));
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(reachable(metadata.clone(), home.path(), None));
    fs::set_permissions(
        socket.parent().expect("parent"),
        fs::Permissions::from_mode(0o770),
    )
    .expect("mode");
    assert!(!reachable(metadata, home.path(), None));
}

#[test]
fn a_socket_outside_the_callers_roots_is_not_trusted() {
    let home = short_dir();
    let metadata = json!({
        "codex_thread_id": "thread-safe-0001",
        "codex_app_server_socket": "/etc/codex-control.sock",
    });

    assert!(!reachable(metadata, home.path(), None));
}

#[test]
fn a_malformed_request_is_an_error_not_an_answer() {
    assert!(run_command(&b"not json"[..]).is_err());
    assert!(run_command(&b"{}"[..]).is_err());
}
