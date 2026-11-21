use serde_json::{json, Value};

use crate::codex_remote_launch::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn ask(home: &std::path::Path, stage: &str, extra: Value) -> Value {
    let socket = home.join(".codex/app-server-control/app-server-control.sock");
    let mut request = json!({
        "op": "prepare",
        "home_dir": home,
        "socket": socket,
        "seconds": 0.0,
        "stage": stage,
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    dispatch(&request).unwrap()
}

#[test]
fn start_creates_the_codex_home_and_names_remote_control() {
    let home = tempfile::tempdir().unwrap();
    let answer = ask(home.path(), "start", json!({}));
    assert!(home.path().join(".codex").is_dir());
    assert_eq!(answer["stage"], "started");
    assert_eq!(answer["run"], json!(["remote-control", "start", "--json"]));
    assert_eq!(answer["timeout"], 10);
    assert_eq!(answer["env"]["HOME"], json!(home.path()));
    assert_eq!(
        answer["env"]["CODEX_HOME"],
        json!(home.path().join(".codex"))
    );
}

#[cfg(unix)]
#[test]
fn a_failed_managed_daemon_falls_back_to_a_private_direct_server() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    for exit in [json!(1), Value::Null, json!(0)] {
        let answer = ask(home.path(), "started", json!({ "exit": exit }));
        let directory = home.path().join(".codex/app-server-control");
        let socket = directory.join("app-server-control.sock");
        assert_eq!(answer["stage"], "spawned", "{exit}");
        assert_eq!(
            answer["spawn"],
            json!([
                "app-server",
                "--listen",
                format!("unix://{}", socket.display())
            ])
        );
        let mode = std::fs::metadata(&directory).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn a_spawned_server_is_recorded_owner_only_and_never_through_a_link() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join(".codex/app-server-control");
    std::fs::create_dir_all(&directory).unwrap();
    let pid_path = directory.join("hol-guard-app-server.pid");
    std::fs::write(&pid_path, "4321").unwrap();
    let answer = ask(home.path(), "spawned", json!({ "pid": 9876 }));
    assert_eq!(answer, json!({ "launch": "plain" }));
    assert_eq!(std::fs::read_to_string(&pid_path).unwrap(), "9876");
    let mode = std::fs::metadata(&pid_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let victim = home.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::fs::remove_file(&pid_path).unwrap();
    std::os::unix::fs::symlink(&victim, &pid_path).unwrap();
    let answer = ask(home.path(), "spawned", json!({ "pid": 9876 }));
    assert_eq!(answer, json!({ "launch": "plain" }));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn refuses_malformed_prepare_requests() {
    let home = tempfile::tempdir().unwrap();
    let socket = home.path().join("s.sock");
    for request in [
        json!({ "op": "prepare", "socket": socket, "seconds": 0.0, "stage": "other" }),
        json!({ "op": "prepare", "socket": "relative.sock", "seconds": 0.0, "stage": "start", "home_dir": "/h" }),
        json!({ "op": "prepare", "socket": socket, "seconds": -1.0, "stage": "start", "home_dir": "/h" }),
        json!({ "op": "prepare", "socket": socket, "seconds": 0.0, "stage": "started" }),
        json!({ "op": "prepare", "socket": socket, "seconds": 0.0, "stage": "started", "exit": "0" }),
        json!({ "op": "prepare", "socket": socket, "seconds": 0.0, "stage": "spawned", "pid": 0 }),
        json!({ "op": "prepare", "socket": socket, "seconds": 0.0, "stage": "start", "home_dir": "/h", "extra": 1 }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[cfg(windows)]
#[test]
fn windows_has_no_direct_server_and_keeps_the_ordinary_launch() {
    let home = tempfile::tempdir().unwrap();
    for exit in [json!(1), Value::Null, json!(0)] {
        let answer = ask(home.path(), "started", json!({ "exit": exit }));
        assert_eq!(answer, json!({ "launch": "plain" }), "{exit}");
    }
}
