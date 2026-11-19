use serde_json::{json, Value};

use crate::codex_remote_launch::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn run(prefixes: Value, home: &std::path::Path, args: Value, environ: Value) -> Value {
    dispatch(&json!({
        "op": "run",
        "prefixes": prefixes,
        "home_dir": home,
        "args": args,
        "environ": environ,
    }))
    .unwrap()
}

#[test]
fn a_launch_that_cannot_use_the_remote_tui_runs_nothing() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("no-such-codex");
    let answer = run(
        json!([[missing]]),
        home.path(),
        json!(["--help"]),
        json!({}),
    );
    assert_eq!(answer, json!({ "argv": [missing, "--help"] }));
    assert!(!home.path().join(".codex").exists());
}

#[test]
fn a_launch_without_one_shared_prefix_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let answer = run(
        json!([["/a/codex"], ["/b/codex"]]),
        home.path(),
        json!([]),
        json!({}),
    );
    assert_eq!(
        answer["refusal"],
        "Codex launch candidates do not share one authorized executable prefix."
    );
    assert!(answer.get("argv").is_none());
}

#[test]
fn refuses_malformed_run_requests() {
    let base = json!({
        "op": "run",
        "prefixes": [["/a/codex"]],
        "home_dir": "/h",
        "args": [],
        "environ": {},
    });
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("environ");
    let mut extra = base.clone();
    extra["extra"] = json!(1);
    let mut numeric = base.clone();
    numeric["environ"] = json!({ "KEY": 1 });
    let mut listed = base.clone();
    listed["environ"] = json!(["KEY"]);
    for request in [missing, extra, numeric, listed] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[cfg(unix)]
mod processes {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::run;

    /// A `codex` that appends `<args>|<CODEX_HOME>` to `$LOG`, then exits with `exit`.
    fn fake_codex(directory: &Path, exit: i32) -> PathBuf {
        let path = directory.join("codex");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s|%s\\n' \"$*\" \"$CODEX_HOME\" >> \"$LOG\"\nexit {exit}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn control_directory(home: &Path) -> PathBuf {
        let directory = home.join(".codex/app-server-control");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn a_started_remote_control_that_listens_connects_the_tui() {
        // A Unix socket path is short-limited, so the home sits under `/tmp`.
        let root = tempfile::Builder::new()
            .prefix("guard-codex-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        let socket = control_directory(&home).join("app-server-control.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let codex = fake_codex(root.path(), 0);
        let log = root.path().join("log");
        let answer = run(
            json!([[codex]]),
            &home,
            json!(["Fix it."]),
            json!({ "LOG": log }),
        );
        assert_eq!(
            answer,
            json!({ "argv": [codex, "--remote", format!("unix://{}", socket.display()), "Fix it."] })
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            format!(
                "remote-control start --json|{}\n",
                home.join(".codex").display()
            )
        );
    }

    #[test]
    fn a_server_started_directly_is_recorded_and_an_unready_socket_keeps_the_ordinary_launch() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let codex = fake_codex(root.path(), 1);
        let log = root.path().join("log");
        let answer = run(json!([[codex]]), &home, json!([]), json!({ "LOG": log }));
        assert_eq!(answer, json!({ "argv": [codex] }));
        let socket = home.join(".codex/app-server-control/app-server-control.sock");
        let mut logged = String::new();
        // The detached server runs on its own; give it a moment to write its line.
        for _ in 0..100 {
            logged = std::fs::read_to_string(&log).unwrap_or_default();
            if logged.lines().count() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let codex_home = home.join(".codex");
        assert_eq!(
            logged,
            format!(
                "remote-control start --json|{0}\napp-server --listen unix://{1}|{0}\n",
                codex_home.display(),
                socket.display()
            )
        );
        let pid = std::fs::read_to_string(
            home.join(".codex/app-server-control/hol-guard-app-server.pid"),
        )
        .unwrap();
        assert!(pid.parse::<u32>().unwrap() > 0);
    }
}
