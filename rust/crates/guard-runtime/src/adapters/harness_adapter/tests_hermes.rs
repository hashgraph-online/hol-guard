//! Hermes through the `harness_adapter` kind. The runtime renders `config.yaml`
//! itself; the tests read it back with the PyYAML-compatible loader.

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::{after, dispatch, shim, Home};

const ARGV: [&str; 3] = ["/py", "-I", "/g/managed/bounded-hooks/hermes.py"];
const COMMAND: &str = "/py -I /g/managed/bounded-hooks/hermes.py";

fn ask(home: &Home, op: &str, fields: &Map<String, Value>) -> Value {
    let mut request =
        json!({"harness": "hermes", "op": op, "context": home.context(json!({"PATH": ""}))});
    for (key, value) in fields {
        request[key] = value.clone();
    }
    dispatch(&request).unwrap()
}

/// One answer of the op; the runtime asks the caller for nothing.
fn run(home: &Home, op: &str, extra: Value) -> Value {
    let fields = extra.as_object().cloned().unwrap_or_default();
    let answer = ask(home, op, &fields);
    if let Some(reply) = answer.get("reply") {
        panic!("unexpected reply {reply}");
    }
    answer
}

fn hermes_home(home: &Home) -> PathBuf {
    home.home().join(".hermes")
}

fn write_config(home: &Home, text: &str) {
    fs::create_dir_all(hermes_home(home)).unwrap();
    fs::write(hermes_home(home).join("config.yaml"), text).unwrap();
}

fn install(home: &Home) -> Value {
    run(
        home,
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ARGV}),
    )
}

fn planned(answer: &Value, name: &str) -> Value {
    let change = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"].as_str().unwrap().ends_with(name))
        .unwrap_or_else(|| panic!("no planned {name}"));
    if name.ends_with(".yaml") {
        yaml_json(&after(change))
    } else {
        serde_json::from_str(&after(change)).unwrap()
    }
}

/// A rendered `config.yaml` read back as JSON.
fn yaml_json(text: &str) -> Value {
    let Ok(Ok(doc)) = crate::hermes_yaml::load(text) else {
        panic!("config.yaml loads");
    };
    let rendered = super::super::files::render(&doc).expect("config renders");
    serde_json::from_str(&rendered).unwrap()
}

#[test]
fn install_registers_a_fail_closed_hook_and_approves_only_its_command() {
    let home = Home::new();
    write_config(
        &home,
        "mcp_servers:\n  github:\n    command: npx\n  remote:\n    url: https://example.invalid/mcp\n  bare:\n    env: {A: b}\n\
         hooks:\n  pre_tool_call:\n    - matcher: write_file\n      command: echo mention managed/bounded-hooks in docs\n",
    );
    let answer = install(&home);

    let config = planned(&answer, "config.yaml");
    let entries = config["hooks"]["pre_tool_call"].as_array().unwrap();
    assert_eq!(
        entries[0]["command"],
        "echo mention managed/bounded-hooks in docs"
    );
    assert_eq!(
        entries[1],
        json!({"id": "hol-guard-pretool", "matcher": ".*", "command": COMMAND, "timeout": 5, "fail_closed": true})
    );
    let allowlist = planned(&answer, "shell-hooks-allowlist.json");
    assert_eq!(
        allowlist["approvals"],
        json!([{"event": "pre_tool_call", "command": COMMAND}])
    );

    let overlay = planned(&answer, "mcp-overlay.json");
    let server = |key: &str| {
        overlay
            .as_object()
            .unwrap()
            .values()
            .find(|entry| entry["metadata"]["guard_server_key"] == key)
            .unwrap_or_else(|| panic!("no overlay entry for {key}"))
            .clone()
    };
    assert_eq!(
        server("yaml:github")["metadata"]["guard_transport"],
        "stdio"
    );
    for (key, transport) in [
        ("yaml:github", "stdio"),
        ("yaml:remote", "remote"),
        ("yaml:bare", "stdio"),
    ] {
        let entry = server(key);
        // The launcher is the caller stamp's; no native runtime means no relay.
        assert_eq!(entry["command"], "/py");
        assert_eq!(entry["transport"], "stdio");
        let args: Vec<&str> = entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        if key == "yaml:github" {
            // A stdio server with its own command runs under the module-form proxy.
            assert_eq!(&args[args.len() - 3..], ["stdio", "--command", "npx"]);
        } else {
            assert_eq!(&args[args.len() - 3..], ["--server", key, "--stdio"]);
        }
        assert_eq!(entry["metadata"]["guard_transport"], transport);
    }
}

#[test]
fn install_refuses_a_config_it_cannot_read_completely() {
    let home = Home::new();
    write_config(
        &home,
        "mcp_servers:\n  same: {command: python}\n  same: {command: bash}\n",
    );
    let answer = ask(
        &home,
        "prepare_install",
        &json!({"shim": shim(), "hook_argv": ARGV})
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(
        answer["refusal"]
            .as_str()
            .unwrap()
            .starts_with("Hermes config inspection failed"),
        "{answer}"
    );
}

fn registered(home: &Home, matcher: &str, approvals: Value) -> bool {
    write_config(
        home,
        &format!(
            "hooks:\n  pre_tool_call:\n    - id: hol-guard-pretool\n      matcher: '{matcher}'\n      \
             command: python hol-guard-hook\n      fail_closed: true\n"
        ),
    );
    fs::write(
        hermes_home(home).join("shell-hooks-allowlist.json"),
        json!({"approvals": approvals}).to_string(),
    )
    .unwrap();
    ask(home, "runtime_probe", &Map::new())["probe"]["runtime_hook_registered"] == json!(true)
}

#[test]
fn registration_needs_the_catch_all_matcher_and_an_approval() {
    let home = Home::new();
    let approved = json!([{"event": "pre_tool_call", "command": "python hol-guard-hook"}]);
    assert!(!registered(&home, "write_file", approved.clone()));
    assert!(registered(&home, ".*", approved));
    assert!(!registered(&home, ".*", json!([])));
}

#[test]
fn uninstall_without_a_manifest_removes_only_this_homes_proxies() {
    let home = Home::new();
    let guard = home.guard().display().to_string();
    write_config(
        &home,
        &format!(
            "mcp_servers:\n  guard-python:\n    command: python\n    \
             args: [-m, codex_plugin_scanner.cli, guard, hermes-mcp-proxy, --guard-home, {guard}]\n  \
             guard-native:\n    command: /opt/hol-guard-runtime\n    \
             args: [mcp-relay, python, -m, codex_plugin_scanner.cli, guard, hermes-mcp-proxy, --guard-home, {guard}]\n  \
             foreign:\n    command: python\n    \
             args: [-m, codex_plugin_scanner.cli, guard, hermes-mcp-proxy, --guard-home, /elsewhere]\n  \
             malformed:\n    command: python\n    \
             args: [-m, codex_plugin_scanner.cli, hermes, mcp-proxy, --guard-home, [unexpected]]\n"
        ),
    );
    let answer = run(&home, "prepare_uninstall", json!({}));
    let config = answer["writes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|write| write["path"].as_str().unwrap().ends_with("config.yaml"))
        .unwrap();
    let config = yaml_json(config["text"].as_str().unwrap());
    let names: Vec<&String> = config["mcp_servers"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["foreign", "malformed"]);
}

#[test]
fn diagnostics_mark_an_install_without_its_hook_launch_review_only() {
    let home = Home::new();
    write_config(&home, "mcp_servers: {}\n");
    let answer = install(&home);
    for change in answer["files"].as_array().unwrap() {
        let path = PathBuf::from(change["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, after(change)).unwrap();
    }
    write_config(&home, "hooks:\n  pre_tool_call: []\n");
    let answer = ask(&home, "diagnostics", &Map::new());
    let update: Value = serde_json::from_str(answer["update"].as_str().unwrap()).unwrap();
    assert_eq!(
        update,
        json!({"runtime_protection_label": "launch-review only"})
    );
}
