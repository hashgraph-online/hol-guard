use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{run_command, strerror, MAX_REQUEST_BYTES};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(dir.path()).expect("canonical tempdir");
    Fixture { _dir: dir, root }
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent dir");
    fs::write(path, body).expect("write");
}

fn answer(request: &Value) -> Value {
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    serde_json::from_slice(&bytes).expect("json answer")
}

fn request(venvs: Value, stale_entries: Value, user_site: Value) -> Value {
    json!({
        "schema": "desktop-foreign-remove.v1",
        "venvs": venvs,
        "stale_entries": stale_entries,
        "user_site": user_site,
        "running_module": "/nonexistent/guard/desktop_foreign_installs.py",
        "environment": {},
    })
}

#[test]
fn removes_a_retired_venv_and_its_entries() {
    let fixture = fixture();
    let venv = fixture.root.join("pipx").join("venvs").join("hol-guard");
    write(&venv.join("bin").join("hol-guard"), "#!/bin/sh\n");
    let entry = fixture.root.join("bin").join("hol-guard");
    write(&entry, "#!/bin/sh\n");

    let answer = answer(&request(
        json!([{"kind": "pipx", "root": text(&venv), "entries": [text(&entry)], "retired": true}]),
        json!([]),
        json!([]),
    ));

    assert!(!venv.exists());
    assert!(!entry.exists());
    assert_eq!(
        answer["removed"],
        json!([{"kind": "pipx", "path": text(&venv)}])
    );
    assert_eq!(
        answer["removed_entry_dirs"],
        json!([text(&fixture.root.join("bin"))])
    );
    assert_eq!(answer["notes"], json!([]));
}

#[test]
fn keeps_a_venv_whose_runtime_is_still_running() {
    let fixture = fixture();
    let venv = fixture.root.join("venv");
    write(&venv.join("bin").join("hol-guard"), "");
    let entry = fixture.root.join("bin").join("hol-guard");
    write(&entry, "");

    let answer = answer(&request(
        json!([{"kind": "uv", "root": text(&venv), "entries": [text(&entry)], "retired": false}]),
        json!([]),
        json!([]),
    ));

    assert!(venv.exists());
    assert!(entry.exists());
    assert_eq!(answer["removed"], json!([]));
    assert_eq!(
        answer["notes"],
        json!([format!(
            "Kept {}: its Guard runtime is still running.",
            text(&venv)
        )])
    );
}

#[test]
fn reports_a_venv_that_cannot_be_removed() {
    let fixture = fixture();
    let missing = fixture.root.join("missing");

    let answer = answer(&request(
        json!([{"kind": "pipx", "root": text(&missing), "entries": [], "retired": true}]),
        json!([]),
        json!([]),
    ));

    assert_eq!(answer["removed"], json!([]));
    let note = answer["notes"][0].as_str().unwrap_or_default();
    assert!(note.starts_with(&format!("Could not remove {}: ", text(&missing))));
    assert!(note.ends_with('.') && !note.contains("os error"), "{note}");
}

#[cfg(unix)]
#[test]
fn never_follows_a_symlinked_venv_root() {
    let fixture = fixture();
    let target = fixture.root.join("target");
    write(&target.join("keep"), "");
    let link = fixture.root.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let answer = answer(&request(
        json!([{"kind": "pipx", "root": text(&link), "entries": [], "retired": true}]),
        json!([]),
        json!([]),
    ));

    assert!(target.join("keep").exists());
    assert!(link.exists());
    assert_eq!(
        answer["notes"],
        json!([format!(
            "Could not remove {}: Cannot call rmtree on a symbolic link.",
            text(&link)
        )])
    );
}

#[test]
fn removes_stale_links_and_skips_missing_ones() {
    let fixture = fixture();
    let entry = fixture.root.join("bin").join("plugin-guard");
    write(&entry, "");
    let missing = fixture.root.join("bin").join("gone");

    let answer = answer(&request(
        json!([]),
        json!([text(&entry), text(&missing)]),
        json!([]),
    ));

    assert!(!entry.exists());
    assert_eq!(
        answer["removed"],
        json!([{"kind": "stale_link", "path": text(&entry)}])
    );
}

#[cfg(unix)]
mod user_site {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn kinds(answer: &Value) -> Vec<&str> {
        answer["removed"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item["kind"].as_str())
            .collect()
    }

    struct Interpreter {
        fixture: Fixture,
        python: PathBuf,
        script: PathBuf,
        pip_ran: PathBuf,
        user_site: PathBuf,
    }

    /// A fake interpreter: the probe prints `$LOCATION` and exits
    /// `$PROBE_EXIT`; pip records that it ran, deletes the script and exits
    /// `$PIP_EXIT`. Both read the environment the request sends.
    fn interpreter() -> Interpreter {
        let fixture = fixture();
        let python = fixture.root.join("system").join("bin").join("python3.12");
        write(
            &python,
            "#!/bin/sh\n\
             if [ \"$1\" = \"-c\" ]; then\n  \
               [ -n \"$LOCATION\" ] && printf '%s\\n' \"$LOCATION\"\n  \
               exit \"$PROBE_EXIT\"\n\
             fi\n\
             : > \"$PIP_RAN\"\n\
             [ \"$PIP_EXIT\" = 0 ] && rm -f \"$SCRIPT\"\n\
             exit \"$PIP_EXIT\"\n",
        );
        fs::set_permissions(&python, fs::Permissions::from_mode(0o755)).expect("chmod");
        let script = fixture
            .root
            .join("home")
            .join(".local")
            .join("bin")
            .join("hol-guard");
        write(&script, "#!/usr/bin/python3\n");
        let pip_ran = fixture.root.join("pip-ran");
        let user_site = fixture.root.join("user-site");
        Interpreter {
            fixture,
            python,
            script,
            pip_ran,
            user_site,
        }
    }

    impl Interpreter {
        fn remove(&self, location: &str, probe_exit: i32, pip_exit: i32, running: &Path) -> Value {
            let environment = BTreeMap::from([
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("LOCATION".to_owned(), location.to_owned()),
                ("PROBE_EXIT".to_owned(), probe_exit.to_string()),
                ("PIP_EXIT".to_owned(), pip_exit.to_string()),
                ("PIP_RAN".to_owned(), text(&self.pip_ran)),
                ("SCRIPT".to_owned(), text(&self.script)),
            ]);
            let mut request = request(
                json!([]),
                json!([]),
                json!([{"interpreter": text(&self.python), "entries": [text(&self.script)]}]),
            );
            request["running_module"] = json!(text(running));
            request["environment"] = json!(environment);
            answer(&request)
        }

        fn elsewhere(&self) -> PathBuf {
            self.fixture.root.join("elsewhere").join("module.py")
        }

        fn not_separate(&self) -> Value {
            json!([format!(
                "Kept hol-guard for {}: it is not a separate pip --user install.",
                text(&self.python)
            )])
        }
    }

    #[test]
    fn uninstalls_a_confirmed_user_site_copy() {
        let host = interpreter();
        let answer = host.remove(&text(&host.user_site), 0, 0, &host.elsewhere());

        assert!(host.pip_ran.exists());
        assert!(!host.script.exists());
        assert_eq!(
            answer["removed"],
            json!([{"kind": "pip_user", "path": text(&host.python)}])
        );
        assert_eq!(
            answer["removed_entry_dirs"],
            json!([text(host.script.parent().expect("bin"))])
        );
        assert_eq!(answer["notes"], json!([]));
    }

    #[test]
    fn removes_only_the_scripts_when_the_package_is_gone() {
        let host = interpreter();
        let answer = host.remove("", 3, 0, &host.elsewhere());

        assert!(!host.pip_ran.exists());
        assert!(!host.script.exists());
        assert_eq!(kinds(&answer), ["stale_script"]);
        assert_eq!(answer["notes"], json!([]));
    }

    #[test]
    fn keeps_a_copy_outside_the_user_site() {
        let host = interpreter();
        let answer = host.remove("", 4, 0, &host.elsewhere());

        assert!(!host.pip_ran.exists());
        assert!(host.script.exists());
        assert_eq!(answer["removed"], json!([]));
        assert_eq!(answer["notes"], host.not_separate());
    }

    #[test]
    fn keeps_a_relative_probe_answer() {
        let host = interpreter();
        let answer = host.remove("user-site", 0, 0, &host.elsewhere());

        assert!(!host.pip_ran.exists());
        assert_eq!(answer["notes"], host.not_separate());
    }

    #[test]
    fn never_uninstalls_the_running_module() {
        let host = interpreter();
        let running = host
            .user_site
            .join("codex_plugin_scanner")
            .join("guard")
            .join("x.py");
        let answer = host.remove(&text(&host.user_site), 0, 0, &running);

        assert!(!host.pip_ran.exists());
        assert!(host.script.exists());
        assert_eq!(answer["notes"], host.not_separate());
    }

    #[test]
    fn reports_a_failed_uninstall() {
        let host = interpreter();
        let answer = host.remove(&text(&host.user_site), 0, 2, &host.elsewhere());

        assert!(host.pip_ran.exists());
        assert!(host.script.exists());
        assert_eq!(answer["removed"], json!([]));
        assert_eq!(
            answer["notes"],
            json!([format!(
                "Could not uninstall hol-guard from {}: pip exited 2.",
                text(&host.python)
            )])
        );
    }

    #[test]
    fn keeps_an_interpreter_that_will_not_start() {
        let host = interpreter();
        fs::remove_file(&host.python).expect("remove python");
        let answer = host.remove(&text(&host.user_site), 0, 0, &host.elsewhere());

        assert!(host.script.exists());
        assert_eq!(answer["notes"], host.not_separate());
    }
}

#[test]
fn strerror_drops_the_os_error_number() {
    let error = std::io::Error::from_raw_os_error(2);
    assert!(!strerror(&error).contains("os error"));
    assert_eq!(strerror(&std::io::Error::other("plain")), "plain");
}

#[test]
fn accepts_a_request_larger_than_the_inventory_answer() {
    let fixture = fixture();
    let stale: Vec<String> = (0..25_000)
        .map(|index| text(&fixture.root.join(format!("{index:0>200}"))))
        .collect();
    let request = request(json!([]), json!(stale), json!([]));
    assert!(request.to_string().len() > 4 * 1024 * 1024);

    assert_eq!(answer(&request)["removed"], json!([]));
}

#[test]
fn refuses_a_request_over_the_cap() {
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) + 1];
    assert_eq!(
        run_command(oversized.as_slice()),
        Err("desktop_foreign_remove_request_too_large".to_owned())
    );
}

#[test]
fn command_refuses_malformed_requests() {
    let mut extra = request(json!([]), json!([]), json!([]));
    extra["extra"] = json!(1);
    let mut schema = request(json!([]), json!([]), json!([]));
    schema["schema"] = json!("other");
    let mut unretired = request(
        json!([{"kind": "pipx", "root": "/x", "entries": []}]),
        json!([]),
        json!([]),
    );
    unretired["environment"] = json!({});
    for request in [
        "not json".to_owned(),
        extra.to_string(),
        schema.to_string(),
        unretired.to_string(),
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("desktop_foreign_remove_request_invalid".to_owned())
        );
    }
}
