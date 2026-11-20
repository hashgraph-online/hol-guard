//! The Codex hook manifest spec the runtime builds from the caller stamp.

use serde_json::{json, Map, Value};

use super::super::{caller, Home};
use crate::harness_adapter::codex_spec::with_spec;
use crate::harness_adapter::Ctx;

fn launch(home: &Home, explicit: bool) -> Value {
    json!({
        "home_is_current": false,
        "runtime_guard_home": home.guard(),
        "workspace_explicit": explicit,
        "manifest_path": "/g/manifest.json",
        "long_timeout": 85,
    })
}

fn spec_of(home: &Home, frozen: bool) -> Value {
    let stamp = if frozen {
        super::super::frozen_with_runtime(home).0
    } else {
        caller(false)
    };
    let answer = home.ask(
        "codex",
        "manifest_spec",
        json!({ "launch": launch(home, false), "caller": stamp }),
    );
    answer["spec"].clone()
}

#[test]
fn a_source_caller_names_its_package_files_under_its_root() {
    let home = Home::new();
    let spec = spec_of(&home, false);
    assert_eq!(spec["interpreter_path"], "/py");
    assert_eq!(spec["package_version"], "0.0.0");
    assert_eq!(spec["workspace_dir"], Value::Null);
    assert_eq!(
        spec["config_path"],
        json!(home.home().join(".codex").join("config.toml"))
    );
    assert_eq!(spec["guard_home"], json!(home.guard()));
    assert_eq!(spec["home_dir"], json!(home.home()));
    assert_eq!(spec["runtime_guard_home"], json!(home.guard()));
    let files = spec["packaged_file_paths"].as_array().unwrap();
    let roles: Vec<&str> = files.iter().map(|pair| pair[0].as_str().unwrap()).collect();
    assert_eq!(
        roles,
        [
            "bridge",
            "hook_probe",
            "native_receipt",
            "fallback_entrypoint",
            "daemon_entrypoint",
            "daemon_manager",
            "launch_runtime",
            "runtime_trust",
            "windows_job",
        ]
    );
    assert_eq!(files[0][1], "/g/hol-guard-runtime");
    let root = "/opt/guard/site/codex_plugin_scanner";
    let path = |role: &str| {
        files
            .iter()
            .find(|pair| pair[0] == role)
            .map(|pair| pair[1].as_str().unwrap().to_owned())
            .unwrap()
    };
    assert_eq!(path("fallback_entrypoint"), format!("{root}/cli.py"));
    assert_eq!(
        path("daemon_entrypoint"),
        format!("{root}/guard/cli/daemon_serve.py")
    );
    assert_eq!(
        path("windows_job"),
        format!("{root}/guard/codex_hook_windows_job.py")
    );
}

#[test]
fn the_spec_carries_the_launch_commands_and_every_event_binding() {
    let home = Home::new();
    let spec = spec_of(&home, false);
    let argv = home.ask(
        "codex",
        "argv",
        json!({
            "home_is_current": false,
            "runtime_guard_home": home.guard(),
            "workspace_explicit": false,
                "manifest_path": "/g/manifest.json",
            "long_timeout": 85,
            "caller": caller(false),
        }),
    );
    assert_eq!(spec["fallback_argv"], argv["fallback"]);
    assert_eq!(spec["daemon_start_argv"], argv["start"]);
    let bindings = spec["event_bindings"].as_array().unwrap();
    let events: Vec<&str> = bindings
        .iter()
        .map(|binding| binding["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "PreToolUse",
            "PermissionRequest",
            "UserPromptSubmit",
            "PostToolUse"
        ]
    );
    for binding in bindings {
        assert_eq!(binding["argv"], argv["argv"]);
        assert_eq!(binding["handler"]["env"]["PYTHONPATH"], "/opt/guard/site");
    }
    assert_eq!(bindings[0]["handler"]["timeout"], 85);
    assert_eq!(bindings[1]["handler"]["timeout"], 30);
}

#[test]
fn a_frozen_caller_is_every_role_and_its_own_interpreter() {
    let home = Home::new();
    let spec = spec_of(&home, true);
    assert_eq!(spec["interpreter_path"], "/py");
    for pair in spec["packaged_file_paths"].as_array().unwrap() {
        assert_eq!(pair[1], "/py", "role {}", pair[0]);
    }
    // The bridge and the eight roles in `ROLES`.
    assert_eq!(spec["packaged_file_paths"].as_array().unwrap().len(), 9);
}

#[test]
fn an_explicit_workspace_is_the_spec_workspace() {
    let home = Home::new();
    let workspace = home.home().join("project");
    let mut request = home.context(json!({}));
    request["workspace"] = json!(workspace);
    let ctx = Ctx::parse(Some(&request)).unwrap();
    for (explicit, expected) in [(true, json!(workspace)), (false, Value::Null)] {
        let mut fields = Map::new();
        fields.insert("launch".into(), launch(&home, explicit));
        let spec = with_spec(&ctx, &fields).ok().unwrap();
        assert_eq!(spec["spec"]["workspace_dir"], expected);
    }
}

#[test]
fn a_launch_becomes_the_spec_of_a_generation_and_the_request() {
    let home = Home::new();
    let ctx = Ctx::parse(Some(&home.context(json!({})))).unwrap();
    let mut fields = Map::new();
    fields.insert("launch".into(), launch(&home, false));
    fields.insert("generation".into(), json!({ "create_key": true }));
    let request = with_spec(&ctx, &fields).ok().unwrap();
    assert!(request.get("launch").is_none());
    assert_eq!(request["generation"]["create_key"], true);
    assert_eq!(request["generation"]["spec"], request["spec"]);
    assert_eq!(request["spec"]["package_version"], "0.0.0");
}

#[test]
fn a_request_with_its_own_spec_is_left_alone() {
    let home = Home::new();
    let ctx = Ctx::parse(Some(&home.context(json!({})))).unwrap();
    let mut fields = Map::new();
    fields.insert("spec".into(), json!({ "own": true }));
    let request = with_spec(&ctx, &fields).ok().unwrap();
    assert_eq!(*request, fields);
}
