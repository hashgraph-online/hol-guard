use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const SOCKET: &str = "/home/user/.codex/app-server-control/app-server-control.sock";

fn tails(args: Value) -> Value {
    let request = json!({ "op": "plan", "args": args, "socket": SOCKET });
    dispatch(&request).unwrap()["tails"].clone()
}

#[test]
fn an_interactive_launch_prefers_the_remote_tui() {
    for args in [
        json!([]),
        json!(["Fix it."]),
        json!(["--model", "o3", "resume"]),
    ] {
        let mut remote = vec![json!("--remote"), json!(format!("unix://{SOCKET}"))];
        remote.extend(args.as_array().unwrap().iter().cloned());
        assert_eq!(tails(args.clone()), json!([remote, args]), "{args}");
    }
}

#[test]
fn a_launch_that_cannot_use_the_remote_tui_keeps_its_argv() {
    for args in [
        json!(["--remote", "unix:///custom/codex.sock"]),
        json!(["--remote=unix:///custom/codex.sock"]),
        json!(["--help"]),
        json!(["prompt", "-h"]),
        json!(["--version"]),
        json!(["-V"]),
        json!(["exec", "Fix it."]),
        json!(["--model", "o3", "app-server"]),
        json!(["mcp-server"]),
        json!(["remote-control", "start"]),
        json!(["update"]),
    ] {
        assert_eq!(tails(args.clone()), json!([args]), "{args}");
    }
    // Only an exact subcommand or flag name opts out.
    assert_eq!(tails(json!(["execute"])).as_array().unwrap().len(), 2);
    assert_eq!(tails(json!(["--remote-x"])).as_array().unwrap().len(), 2);
}

#[test]
fn a_tracked_process_is_ours_only_when_it_listens_on_this_socket() {
    let tracked = |command: &str| {
        let request = json!({ "op": "tracked", "command": command, "socket": SOCKET });
        dispatch(&request).unwrap()["ours"].clone()
    };
    let ours = format!("/usr/bin/codex\napp-server\n--listen\nunix://{SOCKET}");
    assert_eq!(tracked(&ours), json!(true));
    assert_eq!(
        tracked(&format!(
            "/usr/bin/codex app-server --listen unix://{SOCKET}"
        )),
        json!(true)
    );
    assert_eq!(
        tracked("/usr/bin/codex app-server --listen unix:///other.sock"),
        json!(false)
    );
    // The socket path names `app-server`; the subcommand must appear on its own.
    assert_eq!(
        tracked(&format!("/usr/bin/sleep unix://{SOCKET}")),
        json!(false)
    );
    assert_eq!(
        tracked(&format!("/usr/bin/sleep --listen unix://{SOCKET}")),
        json!(false)
    );
}

#[cfg(unix)]
mod sockets {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use serde_json::{json, Value};

    use super::dispatch;

    fn wait(socket: &str, seconds: f64) -> Value {
        let request = json!({ "op": "wait", "socket": socket, "seconds": seconds });
        dispatch(&request).unwrap()["ready"].clone()
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix("crl")
            .tempdir_in("/tmp")
            .expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        directory
    }

    fn socket_in(directory: &Path) -> (PathBuf, String) {
        let socket = directory.join("app-server.sock");
        let text = socket.to_str().expect("utf-8 path").to_owned();
        (socket, text)
    }

    #[test]
    fn a_trusted_listening_socket_is_ready() {
        let directory = private_directory();
        let (socket, text) = socket_in(directory.path());
        let _listener = UnixListener::bind(&socket).expect("bind");
        assert_eq!(wait(&text, 1.0), json!(true));
    }

    #[test]
    fn a_trusted_stale_socket_is_not_ready() {
        let directory = private_directory();
        let (socket, text) = socket_in(directory.path());
        drop(UnixListener::bind(&socket).expect("bind"));
        assert!(socket.exists());
        assert_eq!(wait(&text, 0.01), json!(false));
    }

    #[test]
    fn a_socket_in_a_writable_directory_is_not_ready() {
        let directory = private_directory();
        let (socket, text) = socket_in(directory.path());
        let _listener = UnixListener::bind(&socket).expect("bind");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o720)).expect("chmod");
        assert_eq!(wait(&text, 0.1), json!(false));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o702)).expect("chmod");
        assert_eq!(wait(&text, 0.1), json!(false));
    }

    #[test]
    fn a_regular_file_or_missing_path_is_not_ready() {
        let directory = private_directory();
        let (socket, text) = socket_in(directory.path());
        assert_eq!(wait(&text, 0.1), json!(false));
        fs::write(&socket, b"").expect("write");
        assert_eq!(wait(&text, 0.1), json!(false));
    }

    #[test]
    fn a_socket_that_appears_during_the_wait_is_ready() {
        let directory = private_directory();
        let (socket, text) = socket_in(directory.path());
        let binder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            UnixListener::bind(&socket).expect("bind")
        });
        assert_eq!(wait(&text, 2.0), json!(true));
        drop(binder.join().expect("join"));
    }
}

#[test]
fn refuses_malformed_requests() {
    for request in [
        json!([]),
        json!({ "op": "plan", "args": ["x"] }),
        json!({ "op": "plan", "args": "x", "socket": SOCKET }),
        json!({ "op": "plan", "args": [1], "socket": SOCKET }),
        json!({ "op": "plan", "args": [], "socket": 1 }),
        json!({ "op": "wait", "socket": SOCKET, "seconds": -1.0 }),
        json!({ "op": "wait", "socket": SOCKET, "seconds": "3" }),
        json!({ "op": "wait", "socket": "relative.sock", "seconds": 1.0 }),
        json!({ "op": "wait", "socket": SOCKET }),
        json!({ "op": "tracked", "command": 1, "socket": SOCKET }),
        json!({ "op": "tracked", "command": "x", "socket": SOCKET, "extra": 1 }),
        json!({ "op": "start", "socket": SOCKET, "args": [] }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
