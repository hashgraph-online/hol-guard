//! Cursor through the `harness_adapter` kind.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{after, caller, dispatch, Home};
use crate::runner_authority_op::KindResult;

/// A frozen caller stamp whose launcher is a real executable in `home`, so
/// the attestation reads its identity, and whose native runtime is `bridge`,
/// or has none when null.
fn stamped(home: &Home, bridge: &Value) -> Value {
    let launcher = home.home().join("core").join("hol-guard-core");
    write(&launcher, "#!/bin/sh\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut stamp = caller(true);
    stamp["frozen_launcher"] = json!(launcher);
    if bridge.is_null() {
        stamp["native_runtime"] = Value::Null;
    } else {
        // A frozen caller's hooks run a durable copy of the runtime, so the
        // stamped runtime is a real file whose size and digest match.
        let runtime = home.home().join("runtime").join("hol-guard-runtime");
        let bytes = b"#!/bin/sh\n";
        write(&runtime, std::str::from_utf8(bytes).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
        }
        stamp["native_runtime"]["path"] = json!(runtime);
        stamp["native_runtime"]["size"] = json!(bytes.len());
        stamp["native_runtime"]["sha256"] =
            json!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)));
    }
    stamp
}

fn ask(home: &Home, op: &str, fields: &Map<String, Value>) -> KindResult {
    ask_with(home, op, fields, &bridge())
}

fn ask_with(home: &Home, op: &str, fields: &Map<String, Value>, bridge: &Value) -> KindResult {
    let mut request =
        json!({"harness": "cursor", "op": op, "context": home.context(json!({"PATH": ""}))});
    request["context"]["caller"] = stamped(home, bridge);
    for (key, value) in fields {
        request[key] = value.clone();
    }
    dispatch(&request)
}

/// One op, which settles without asking the Guard process anything.
fn run(home: &Home, op: &str, bridge: Value) -> KindResult {
    let answer = ask_with(home, op, &Map::new(), &bridge)?;
    assert!(answer.get("reply").is_none(), "{op} asked {answer}");
    Ok(answer)
}

fn bridge() -> Value {
    json!("/g/bin/hol-guard-runtime")
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn a_frozen_cursor_install_attests_the_launcher_natively() {
    let home = Home::new();
    let answer = run(&home, "install", bridge()).unwrap();
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    let identity = &manifest["guard_cli_identity"];
    assert_eq!(identity["runtime"], "frozen-core");
    assert_eq!(identity["entry_point"], "hol-guard");
    let launcher = home.home().join("core").join("hol-guard-core");
    assert_eq!(identity["command"], json!([launcher]));
    assert_eq!(identity["interpreter"]["invocation_path"], json!(launcher));
    assert_eq!(
        identity["interpreter"]["target_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn cursor_prepare_without_an_enrolled_key_is_a_transition_error() {
    let home = Home::new();
    let answer = run(&home, "prepare_install", bridge()).unwrap();
    assert_eq!(
        answer["transition_error"],
        "adapter_preparation_authority_missing"
    );
    let answer = run(&home, "prepare_install", Value::Null).unwrap();
    assert_eq!(
        answer["transition_error"],
        "adapter_preparation_native_cursor_bridge_missing"
    );
    assert!(!home.guard().join("cursor").exists());
}

#[test]
fn cursor_install_without_a_bridge_writes_nothing() {
    let home = Home::new();
    let answer = run(&home, "install", Value::Null).unwrap();
    assert_eq!(
        answer["runtime_error"],
        "guard_cursor_native_bridge_unavailable"
    );
    assert_eq!(fs::read_dir(home.guard()).unwrap().count(), 0);
}

#[test]
fn cursor_install_keeps_other_hooks_beside_guards() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {"stop": [{"command": "./other-tool.sh"}]}}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    let identity = answer["identity"][0].as_str().unwrap();
    assert_eq!(fs::read(identity).unwrap().len(), 32);
    let planned = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(hooks))
        .expect("hooks.json is planned");
    let merged: Value = serde_json::from_str(&after(planned)).unwrap();
    let text = merged.to_string();
    assert!(text.contains("./other-tool.sh"));
    assert!(text.contains("hol-guard-cursor-hook.py"));
    assert!(merged["hooks"]["preToolUse"].is_array());
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["harness"], "cursor");
}

#[test]
fn cursor_without_hooks_is_inactive_and_not_rebound() {
    let home = Home::new();
    let state = run(&home, "hook_state", bridge()).unwrap();
    let state: Value = serde_json::from_str(state["state"].as_str().unwrap()).unwrap();
    assert_eq!(state["protection_active"], false);
    assert!(run(&home, "health", bridge()).unwrap()["verified"].is_null());
    let rebind = run(&home, "rebind", bridge()).unwrap();
    assert_eq!(rebind["rebound"], false);
}

fn rebind_with_caller(caller: Value) -> Value {
    let home = Home::new();
    let mut request = json!({
        "harness": "cursor",
        "op": "rebind",
        "context": home.context(json!({"PATH": ""})),
    });
    request["context"]["caller"] = caller;
    dispatch(&request).unwrap()
}

fn frozen_caller(prune_safe: bool, runnable: bool) -> Value {
    json!({
        "executable": "/g/core",
        "executable_resolved": "/g/core",
        "frozen": true,
        "launcher": "/g/bin/hol-guard-core",
        "frozen_launcher": "/g/bin/hol-guard-core",
        "launcher_prune_safe": prune_safe,
        "launcher_runnable": runnable,
        "cli_executable": "/g/core",
        "package_root": "/opt/guard/site",
        "version": "0.0.0",
    })
}

#[test]
fn a_rebind_needs_a_prune_safe_runnable_frozen_launcher_from_the_caller() {
    for (prune_safe, runnable) in [(false, true), (true, false), (false, false)] {
        let answer = rebind_with_caller(frozen_caller(prune_safe, runnable));
        assert_eq!(answer["reason"], "stable_frozen_cli_unavailable");
    }
    let answer = rebind_with_caller(frozen_caller(true, true));
    assert_eq!(answer["reason"], "cursor_hook_script_absent");
}

#[test]
fn cursor_uninstall_of_an_empty_home_reports_inactive() {
    let home = Home::new();
    let answer = run(&home, "uninstall", bridge()).unwrap();
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["active"], false);
    assert_eq!(manifest["restored"], false);
}

#[test]
fn cursor_rejects_a_missing_hook_script() {
    let home = Home::new();
    let missing = home
        .home()
        .join(".cursor")
        .join("hooks")
        .join("hol-guard-cursor-hook.py");
    let mut fields = Map::new();
    fields.insert("script".into(), json!(missing));
    let answer = ask(&home, "frozen_hook_script", &fields).unwrap();
    assert_eq!(answer["accepted"], false);
}

#[test]
fn cursor_install_then_uninstall_returns_the_users_hooks_file() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    let original = json!({
        "version": 1,
        "hooks": {
            "stop": [{"command": "./other-tool.sh"}],
            "beforeShellExecution": [{"command": "./audit.sh", "timeout": 5}]
        },
        "futureKey": {"nested": ["kept", 1, true, null]},
        "unicode": "caf\u{e9} \u{2014} \u{1f512}"
    });
    write(&hooks, &serde_json::to_string_pretty(&original).unwrap());
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        let path = Path::new(change["path"].as_str().unwrap());
        if change["after"].is_string() {
            write(path, &after(change));
        }
    }
    let installed = fs::read_to_string(&hooks).unwrap();
    assert!(
        installed.contains("hol-guard-cursor-hook.py"),
        "install added nothing"
    );
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(cleaned, original);
}

#[test]
fn cursor_uninstall_keeps_a_hook_the_user_added_after_install() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {"stop": [{"command": "./other-tool.sh"}]}}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    let mut edited: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    edited["hooks"]["stop"]
        .as_array_mut()
        .unwrap()
        .push(json!({"command": "./added-later.sh"}));
    write(&hooks, &serde_json::to_string_pretty(&edited).unwrap());
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        cleaned,
        json!({"version": 1, "hooks": {"stop": [
            {"command": "./other-tool.sh"},
            {"command": "./added-later.sh"}
        ]}})
    );
}

/// When Guard's entries are the only hooks, uninstall keeps the file for the
/// user's other top-level keys instead of deleting it.
#[test]
fn cursor_uninstall_keeps_top_level_keys_when_guard_held_the_only_hooks() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {}, "futureKey": "keep"}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    let mut edited: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    edited["addedLater"] = json!(true);
    write(&hooks, &serde_json::to_string_pretty(&edited).unwrap());
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        cleaned,
        json!({"version": 1, "hooks": {}, "futureKey": "keep", "addedLater": true})
    );
}

/// A hooks file with no hooks of its own comes back byte for byte.
#[test]
fn cursor_uninstall_restores_a_file_that_had_no_hooks_of_its_own() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    let original = "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n";
    write(&hooks, original);
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    assert_ne!(fs::read_to_string(&hooks).unwrap(), original);
    run(&home, "uninstall", bridge()).unwrap();
    assert_eq!(fs::read_to_string(&hooks).unwrap(), original);
}

#[test]
fn cursor_uninstall_keeps_a_file_whose_guard_hooks_are_already_gone() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(&hooks, "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n");
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    // The user removed Guard's entries by hand and added a hook of their own.
    let edited =
        "{\n  \"version\": 1,\n  \"hooks\": {\"stop\": [{\"command\": \"./later.sh\"}]}\n}\n";
    write(&hooks, edited);
    run(&home, "uninstall", bridge()).unwrap();
    assert_eq!(fs::read_to_string(&hooks).unwrap(), edited);
}

fn surfaces(home: &Home, surface: &str, bridge: Value) -> Value {
    let mut fields = Map::new();
    fields.insert("surface".into(), json!(surface));
    fields.insert(
        "interpreter".into(),
        json!({
            "executable": "/opt/python/bin/python3",
            "frozen": false,
            "package_interpreter": "/opt/python/bin/python3",
            "python_flags": ["-I", "-P"],
            "import_root": "/opt/site",
            "launcher_env": [],
        }),
    );
    fields.insert(
        "shell_profile".into(),
        json!({"shell": "", "shim_dir_transient": false}),
    );
    ask_with(home, "prepare_surfaces", &fields, &bridge).unwrap()
}

#[test]
fn cursor_prepares_both_cli_launchers_without_writing_one() {
    let home = Home::new();
    let answer = surfaces(&home, "cli", bridge());
    let files = answer["files"].as_array().unwrap();
    let bin = home.guard().join("bin");
    for name in ["guard-cursor-agent", "guard-cursor"] {
        assert!(
            files
                .iter()
                .any(|file| file["path"] == json!(bin.join(name))),
            "{name} missing from {answer}"
        );
    }
    assert_eq!(answer["identity"], json!([]));
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert!(manifest.is_object(), "{manifest}");
    assert!(!bin.exists());
}

#[test]
fn cursor_editor_and_all_surfaces_stop_at_the_editor_transition_error() {
    let home = Home::new();
    for surface in ["editor", "all"] {
        let answer = surfaces(&home, surface, bridge());
        assert_eq!(
            answer,
            json!({"transition_error": "adapter_preparation_authority_missing"}),
            "{surface}"
        );
    }
    assert!(!home.guard().join("bin").exists());
}

#[test]
fn describe_names_the_cursor_and_claude_launcher_flags() {
    let answer = dispatch(&json!({"op": "describe"})).unwrap();
    let spec = |name: &str| {
        answer["adapters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|adapter| adapter["harness"] == name)
            .unwrap()
            .clone()
    };
    let cursor = spec("cursor");
    assert_eq!(cursor["prepare"], "surfaces");
    assert_eq!(cursor["absence_proves_uninstalled"], false);
    assert_eq!(cursor["legacy_launchers"], json!(["cursor"]));
    assert_eq!(cursor["executable"], "cursor-agent");
    let claude = spec("claude-code");
    assert_eq!(claude["legacy_launchers"], json!(["claude-code"]));
    assert_eq!(claude["absence_proves_uninstalled"], true);
    assert_eq!(spec("devin")["legacy_launchers"], json!([]));
}
