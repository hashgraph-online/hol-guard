use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::{Ctx, Failure};
use super::{hooks_wire, live_hook_state, refusal};
use crate::pyjson::PyVal;

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    (dir, root)
}

fn ctx(root: &Path) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": root.join("home"),
        "guard_home": root.join("guard"),
        "cwd": root,
        "user_home": root.join("home"),
        "env": {},
    })))
    .unwrap()
}

fn fields(root: &Path, config: &Path) -> Map<String, Value> {
    let spec = json!({
        "guard_home": root.join("guard"),
        "home_dir": root.join("home"),
        "runtime_guard_home": root.join("guard"),
        "workspace_dir": null,
        "config_path": config,
        "interpreter_path": "/usr/bin/python3",
        "package_version": "0.0.0",
        "packaged_file_paths": [],
        "fallback_argv": [],
        "daemon_start_argv": [],
        "event_bindings": [],
    });
    let mut fields = Map::new();
    fields.insert("spec".into(), spec);
    fields.insert("package_roots".into(), json!([]));
    fields.insert("windows".into(), json!(false));
    fields.insert("long_paths".into(), json!({}));
    fields
}

#[test]
fn a_missing_manifest_reports_unprotected_with_its_path() {
    let (_dir, root) = root();
    let ctx = ctx(&root);
    let config = root.join("home").join(".codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[features]\nhooks = true\n").unwrap();
    let answer = live_hook_state(&ctx, &fields(&root, &config)).ok().unwrap();
    let state: Value = serde_json::from_str(answer["state"].as_str().unwrap()).unwrap();
    assert_eq!(
        state["integrity_reason"],
        json!("codex_hook_manifest_missing")
    );
    assert_eq!(state["protection_active"], json!(false));
    assert_eq!(state["config_present"], json!(true));
    assert_eq!(state["hooks_enabled"], json!(true));
    let manifest = state["manifest_path"].as_str().unwrap();
    assert!(manifest.starts_with(root.join("guard").join("managed").to_str().unwrap()));
    assert!(manifest.ends_with(".manifest.json"));
}

#[test]
fn a_spec_for_another_config_is_refused() {
    let (_dir, root) = root();
    let ctx = ctx(&root);
    let other = root.join("elsewhere.toml");
    assert!(matches!(
        live_hook_state(&ctx, &fields(&root, &other)),
        Err(Failure::Invalid)
    ));
}

#[test]
fn a_group_holding_a_toml_date_crosses_as_null() {
    let mut tokens = Map::new();
    tokens.insert("tok-1".into(), json!({"kind": "date"}));
    let hooks = PyVal::Dict(vec![(
        "PreToolUse".into(),
        PyVal::List(vec![
            PyVal::Dict(vec![("when".into(), PyVal::Str("tok-1".into()))]),
            PyVal::Dict(vec![("matcher".into(), PyVal::Str("*".into()))]),
        ]),
    )]);
    assert_eq!(
        hooks_wire(&hooks, &tokens),
        Some(json!({"PreToolUse": [null, {"matcher": "*"}]}))
    );
    assert_eq!(hooks_wire(&PyVal::Null, &tokens), None);
}

#[test]
fn an_unavailable_key_is_reported_as_unverified() {
    assert_eq!(
        refusal("runtime_unavailable").0,
        "codex_hook_manifest_verification_unavailable"
    );
    assert_eq!(
        refusal("codex_hook_manifest_mac_invalid").0,
        "codex_hook_manifest_mac_invalid"
    );
}

#[test]
fn a_spent_budget_reports_unverified_without_reading_the_manifest() {
    let (_dir, root) = root();
    let ctx = ctx(&root);
    let config = root.join("home").join(".codex").join("config.toml");
    let mut fields = fields(&root, &config);
    fields.insert("budget_spent".into(), json!(true));
    let answer = live_hook_state(&ctx, &fields).ok().unwrap();
    let state: Value = serde_json::from_str(answer["state"].as_str().unwrap()).unwrap();
    assert_eq!(
        state["integrity_reason"],
        json!("codex_hook_manifest_verification_unavailable")
    );
    assert_eq!(state["protection_active"], json!(false));
}
