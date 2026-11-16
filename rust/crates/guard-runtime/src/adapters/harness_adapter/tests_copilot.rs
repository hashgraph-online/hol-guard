//! Copilot through the `harness_adapter` kind.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{after, dispatch, shim, Home};
use crate::runner_authority_op::KindResult;

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn workspace(home: &Home) -> PathBuf {
    let workspace = home.root.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    workspace
}

fn ask(home: &Home, op: &str, extra: Value) -> KindResult {
    let mut context = home.context(json!({"PATH": ""}));
    context["workspace"] = json!(workspace(home));
    let mut request = json!({"harness": "copilot", "op": op, "context": context});
    for (key, value) in extra.as_object().unwrap() {
        // A test's own `caller` replaces the context's default one.
        if key == "caller" {
            request["context"]["caller"] = value.clone();
        } else {
            request[key] = value.clone();
        }
    }
    dispatch(&request)
}

/// The fields Python sends with `prepare_install` after `install_detection`:
/// no hook argv, which the native runtime builds from the caller stamp.
fn install_fields(found: &Value) -> Value {
    let mut fields = Map::new();
    for (key, value) in [
        ("create_key", json!(true)),
        ("digest", found["digest"].clone()),
        ("shim", json!(shim())),
    ] {
        fields.insert(key.to_owned(), value);
    }
    Value::Object(fields)
}

#[test]
fn copilot_rebind_without_an_enrolled_key_creates_no_file() {
    let home = Home::new();
    for op in ["install_detection", "prepare_install"] {
        let answer = ask(&home, op, json!({"create_key": false})).unwrap();
        assert_eq!(
            answer,
            json!({"transition_error": "adapter_preparation_authority_missing"})
        );
    }
    assert!(!home.guard().join("managed").exists());
}

#[test]
fn copilot_install_plans_both_workspace_mcp_targets() {
    let home = Home::new();
    let ws = workspace(&home);
    write(
        &ws.join(".mcp.json"),
        r#"{"mcpServers": {"cli_lab": {"command": "python", "args": ["cli.py"]}}}"#,
    );
    let found = ask(&home, "install_detection", json!({})).unwrap();
    let answer = ask(&home, "prepare_install", install_fields(&found)).unwrap();
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    let targets: Vec<PathBuf> =
        serde_json::from_value(manifest["managed_config_paths"].clone()).unwrap();
    assert_eq!(targets, [ws.join(".mcp.json"), ws.join(".vscode/mcp.json")]);
    assert_eq!(manifest["managed_servers"], json!(["cli_lab"]));
    assert_eq!(manifest["skipped_servers"], json!([]));
    let config = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(home.home().join(".copilot/config.json")))
        .unwrap();
    assert!(after(config).contains("/g/hol-guard-runtime bounded-hook-bridge '"));
    let workspace_hook = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(ws.join(".github/hooks/hol-guard-copilot.json")))
        .unwrap();
    let hook = after(workspace_hook);
    assert!(hook.contains("/g/hol-guard-runtime bounded-hook-bridge '"));
    assert!(hook.contains("--workspace"));
}

#[test]
fn copilot_install_names_a_frozen_callers_durable_runtime_copy() {
    let home = Home::new();
    let found = ask(&home, "install_detection", json!({})).unwrap();
    let (stamp, copy) = super::frozen_with_runtime(&home);
    let mut fields = install_fields(&found);
    fields["caller"] = stamp;
    let answer = ask(&home, "prepare_install", fields).unwrap();
    let config = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(home.home().join(".copilot/config.json")))
        .unwrap();
    assert!(after(config).contains(&format!("{copy} bounded-hook-bridge '")));
}

#[test]
fn copilot_install_without_a_native_runtime_asks_for_repair() {
    let home = Home::new();
    let found = ask(&home, "install_detection", json!({})).unwrap();
    let mut stamp = super::caller(false);
    stamp["native_runtime"] = Value::Null;
    let mut fields = install_fields(&found);
    fields["caller"] = stamp;
    let answer = ask(&home, "prepare_install", fields).unwrap();
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("hol-guard repair"));
}

#[test]
fn copilot_install_refuses_a_malformed_later_config_before_planning_any_write() {
    let home = Home::new();
    let ws = workspace(&home);
    let cli = ws.join(".mcp.json");
    let ide = ws.join(".vscode/mcp.json");
    write(
        &cli,
        r#"{"mcpServers": {"cli_lab": {"command": "python", "args": ["cli.py"]}}}"#,
    );
    write(&ide, "{not json");
    let before = (fs::read(&cli).unwrap(), fs::read(&ide).unwrap());
    assert!(ask(&home, "install_detection", json!({})).is_err());
    assert_eq!((fs::read(&cli).unwrap(), fs::read(&ide).unwrap()), before);
}
