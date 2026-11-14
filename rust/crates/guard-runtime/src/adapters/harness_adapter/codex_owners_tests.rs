use serde_json::{json, Value};

use super::codex_owners::dispatch;
use super::{Failure, Step};

fn ask(request: Value) -> Step<Value> {
    dispatch(request.as_object().unwrap())
}

fn ask_ok(mut request: Value) -> Value {
    request["windows"] = json!(false);
    request["long_paths"] = json!({});
    ask(request).unwrap_or_else(|_| panic!("refused"))
}

fn decoded(answer: &Value, key: &str) -> Value {
    serde_json::from_str(answer[key].as_str().unwrap()).unwrap()
}

const STATUS: &str = "HOL Guard checking Bash command";

fn handler(command: &str) -> Value {
    json!({"type": "command", "command": command, "statusMessage": STATUS})
}

#[test]
fn a_binding_removes_its_exact_group_or_else_its_exact_handler() {
    let ours = handler("guard hook");
    let theirs = handler("user hook");
    let hooks = json!({
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [theirs, ours]},
            {"matcher": "Bash", "hooks": [ours]},
        ],
        "PostToolUse": [{"matcher": "*", "hooks": [ours]}],
        "Stop": [{"hooks": [ours]}],
    });
    let bindings = json!([
        {"event": "PreToolUse", "group": {"matcher": "Bash"}, "handler": ours},
        {"event": "PostToolUse", "group": {"matcher": "*", "hooks": [ours]}, "handler": ours},
        {"event": "Stop", "group": {"hooks": [ours]}, "handler": ours},
        {"event": "PreToolUse", "group": {"matcher": "Other"}, "handler": ours},
    ]);
    let answer = ask_ok(json!({
        "op": "remove",
        "hooks": hooks.to_string(),
        "bindings": bindings.to_string(),
    }));
    assert_eq!(answer["changed"], json!(true));
    assert_eq!(
        decoded(&answer, "hooks"),
        json!({
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [theirs]},
                {"matcher": "Bash", "hooks": [ours]},
            ],
            "Stop": [{"hooks": [ours]}],
        })
    );
    let unchanged = ask_ok(json!({"op": "remove", "hooks": "{}", "bindings": "[]"}));
    assert_eq!(unchanged["changed"], json!(false));
}

#[test]
fn a_legacy_binding_is_the_first_accepted_handler_per_event() {
    let argv = ["/py", "-I", "/pkg/bridge.py", "{\"a\":1}"];
    let command = "/py -I /pkg/bridge.py '{\"a\":1}'";
    let current = handler(command);
    let other_status = json!({"command": command, "statusMessage": "other"});
    let group = json!({"matcher": "Bash", "hooks": [other_status, current]});
    let hooks = json!({
        "PreToolUse": [{"matcher": "Edit", "hooks": [current]}, group],
        "PostToolUse": [{"matcher": "Bash", "hooks": [current]}],
    });
    let expected = json!([{"event": "PreToolUse", "group": {"matcher": "Bash"}}]);
    let answer = ask_ok(json!({
        "op": "legacy",
        "hooks": hooks.to_string(),
        "expected": expected.to_string(),
        "argv": argv,
        "legacy_argv": ["/old", "x"],
        "statuses": [STATUS],
    }));
    assert_eq!(
        decoded(&answer, "bindings"),
        json!([{"event": "PreToolUse", "group": group, "handler": current}])
    );
}

#[test]
fn a_windows_legacy_binding_accepts_the_plain_json_config() {
    // `{"a":1}` as unpadded base64url.
    let argv = ["C:\\py.exe", "-I", "C:\\pkg\\bridge.py", "eyJhIjoxfQ"];
    let plain = handler("C:\\py.exe -I C:\\pkg\\bridge.py \"{\\\"a\\\":1}\"");
    let hooks = json!({"PreToolUse": [{"matcher": "Bash", "hooks": [plain]}]});
    let request = json!({
        "op": "legacy",
        "windows": true,
        "long_paths": {},
        "hooks": hooks.to_string(),
        "expected": json!([{"event": "PreToolUse", "group": {"matcher": "Bash"}}]).to_string(),
        "argv": argv,
        "legacy_argv": [],
        "statuses": [STATUS],
    });
    let answer = ask(request).unwrap_or_else(|_| panic!("refused"));
    assert_eq!(decoded(&answer, "bindings").as_array().unwrap().len(), 1);
}

#[test]
fn a_windows_short_path_asks_the_host_to_expand_it() {
    let hooks = json!({"PreToolUse": [{"matcher": "Bash", "hooks": [handler("C:\\PROGRA~1\\py.exe -I x y")]}]});
    let mut request = json!({
        "op": "legacy",
        "windows": true,
        "long_paths": {},
        "hooks": hooks.to_string(),
        "expected": json!([{"event": "PreToolUse", "group": {"matcher": "Bash"}}]).to_string(),
        "argv": ["C:\\Program Files\\py.exe", "-I", "x", "y"],
        "legacy_argv": [],
        "statuses": [STATUS],
    });
    match ask(request.clone()) {
        Err(Failure::Reply(reply)) => {
            assert_eq!(reply, json!({"expand": ["C:\\PROGRA~1\\py.exe"]}));
        }
        _ => panic!("expected a reply"),
    }
    request["long_paths"] = json!({"C:\\PROGRA~1\\py.exe": "C:\\Program Files\\py.exe"});
    let answer = ask(request).unwrap_or_else(|_| panic!("refused"));
    assert_eq!(decoded(&answer, "bindings").as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn a_legacy_guard_handler_whose_program_is_gone_is_removed() {
    let home = tempfile::tempdir().unwrap();
    let present = home.path().join("python");
    std::fs::write(&present, "").unwrap();
    let missing = home.path().join("gone/python");
    let gone = handler(&format!(
        "{} -m guard hook --harness codex",
        missing.display()
    ));
    let live = handler(&format!(
        "{} -m guard hook --harness codex",
        present.display()
    ));
    let args = json!({"command": missing.display().to_string(), "args": ["--harness=codex"], "statusMessage": STATUS});
    let user = json!({"command": missing.display().to_string(), "statusMessage": STATUS});
    let hooks = json!({
        "PreToolUse": [{"matcher": "Bash", "hooks": [gone, live]}],
        "PostToolUse": [{"matcher": "*", "hooks": [args]}],
        "UserPromptSubmit": [{"hooks": [user]}],
    });
    let answer = ask_ok(json!({
        "op": "unlaunchable",
        "hooks": hooks.to_string(),
        "statuses": [STATUS],
    }));
    assert_eq!(answer["changed"], json!(true));
    assert_eq!(
        decoded(&answer, "hooks"),
        json!({
            "PreToolUse": [{"matcher": "Bash", "hooks": [live]}],
            "UserPromptSubmit": [{"hooks": [user]}],
        })
    );
}

#[cfg(unix)]
struct Install {
    _root: tempfile::TempDir,
    guard_home: std::path::PathBuf,
    package_root: std::path::PathBuf,
    native: std::path::PathBuf,
}

#[cfg(unix)]
fn install() -> Install {
    let root = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(root.path()).unwrap();
    let guard_home = base.join("guard");
    let package_root = base.join("site");
    let native = guard_home.join("native/hol-guard-runtime");
    std::fs::create_dir_all(native.parent().unwrap()).unwrap();
    std::fs::create_dir_all(package_root.join("guard")).unwrap();
    std::fs::write(&native, "").unwrap();
    std::fs::write(package_root.join("guard/codex_daemon_hook_bridge.py"), "").unwrap();
    Install {
        _root: root,
        guard_home,
        package_root,
        native,
    }
}

#[cfg(unix)]
fn bridge(program: &std::path::Path, script: &std::path::Path, payload: &Value) -> String {
    format!(
        "{} codex-hook-bridge /usr/bin/python3 -I {} '{}'",
        program.display(),
        script.display(),
        payload
    )
}

#[cfg(unix)]
fn owners(install: &Install, op: &str, extra: Value) -> Value {
    let mut request = json!({
        "op": op,
        "cwd": "/",
        "guard_home": install.guard_home,
        "package_root": install.package_root,
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    ask_ok(request)
}

#[cfg(unix)]
#[test]
fn a_launcher_binds_only_its_one_home_and_an_owned_program() {
    let install = install();
    let script = install
        .package_root
        .join("guard/codex_daemon_hook_bridge.py");
    let query = format!("guard-home={}", install.guard_home.display());
    let one = json!({"query": query, "state_path": install.guard_home.join("daemon-state.json")});
    let two = json!({"query": query, "fallback_command": ["x", "--guard-home=/elsewhere"]});
    let binds = |command: String| {
        let answer = owners(&install, "binds", json!({"command": command}));
        answer["binds"].as_bool().unwrap()
    };
    assert!(binds(bridge(&install.native, &script, &one)));
    assert!(!binds(bridge(&install.native, &script, &two)));
    assert!(!binds(bridge(
        std::path::Path::new("/usr/bin/env"),
        std::path::Path::new("/tmp/codex_daemon_hook_bridge.py"),
        &one
    )));
    let python = format!("/usr/bin/python3 -I {} '{}'", script.display(), one);
    assert!(binds(python.clone()));
    let home = ask_ok(json!({"op": "guard_home", "command": python, "cwd": null}));
    assert_eq!(home["home"], json!(install.guard_home));
    let none = ask_ok(json!({"op": "guard_home", "command": "echo hi", "cwd": "/"}));
    assert_eq!(none["home"], Value::Null);
    let relative = json!({"state_path": "daemon-state.json"});
    let command = format!("/usr/bin/python3 -I {} '{}'", script.display(), relative);
    for (cwd, expected) in [
        (json!(install.guard_home), json!(install.guard_home)),
        (Value::Null, Value::Null),
    ] {
        let home = ask_ok(json!({"op": "guard_home", "command": command, "cwd": cwd}));
        assert_eq!(home["home"], expected);
    }
}

#[cfg(unix)]
#[test]
fn self_bindings_claim_stale_generations_and_hold_recorded_commands() {
    let install = install();
    let script = install
        .package_root
        .join("guard/codex_daemon_hook_bridge.py");
    let payload = json!({"query": format!("guard-home={}", install.guard_home.display())});
    let command = bridge(&install.native, &script, &payload);
    let ours = handler(&command);
    let theirs = handler("user hook");
    let flat = json!({"matcher": "*", "command": command});
    let hooks = json!({
        "PreToolUse": [{"matcher": "Bash", "hooks": [theirs, ours]}],
        "PostToolUse": [flat],
    });
    let answer = owners(
        &install,
        "self",
        json!({"hooks": hooks.to_string(), "recorded": []}),
    );
    assert_eq!(
        decoded(&answer, "bindings"),
        json!([
            {"event": "PreToolUse", "group": {"matcher": "Bash"}, "handler": ours},
            {"event": "PostToolUse", "group": flat, "handler": flat},
        ])
    );
    let held = owners(
        &install,
        "self",
        json!({"hooks": hooks.to_string(), "recorded": [command]}),
    );
    assert_eq!(decoded(&held, "bindings"), json!([]));

    let stripped = owners(
        &install,
        "strip",
        json!({
            "hooks": hooks.to_string(),
            "owned": "[]",
            "expected": "[]",
            "argv": [],
            "legacy_argv": [],
            "statuses": [STATUS],
            "unlaunchable": true,
            "hold_recorded": false,
        }),
    );
    assert_eq!(stripped["changed"], json!(true));
    assert_eq!(
        decoded(&stripped, "hooks"),
        json!({"PreToolUse": [{"matcher": "Bash", "hooks": [theirs]}]})
    );
}

#[test]
fn malformed_requests_are_refused() {
    let base = json!({"op": "remove", "windows": false, "long_paths": {}, "hooks": "{}", "bindings": "[]"});
    assert!(ask(base.clone()).is_ok());
    let mut extra = base.clone();
    extra["more"] = json!(1);
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("bindings");
    let mut hooks = base.clone();
    hooks["hooks"] = json!("[]");
    let mut long = base.clone();
    long["long_paths"] = json!({"a": 1});
    let mut op = base.clone();
    op["op"] = json!("other");
    for request in [extra, missing, hooks, long, op] {
        assert!(matches!(ask(request), Err(Failure::Invalid)));
    }
}
