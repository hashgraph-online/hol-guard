//! The bounded hook argv the native runtime names for a calling Guard.
//!
//! Python used to wrap a hook config in the bounded bridge itself
//! (`bounded_hook_command_for_config`, `native_bridge_executable`). Each case
//! here is one of the outcomes its tests pinned.

use serde_json::{json, Value};

use super::{caller, frozen_with_runtime, Home, NATIVE_FEATURES};

const BRIDGE: [&str; 10] = [
    "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok", "muse",
];

fn hook_config(home: &Home, harness: &str, stamp: Option<Value>) -> Value {
    let mut extra = json!({"cli_args": ["guard", "hook"], "timeout_seconds": 20});
    if let Some(stamp) = stamp {
        extra["caller"] = stamp;
    }
    home.ask(harness, "hook_config", extra)
}

fn assert_repair(answer: &Value) {
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("hol-guard repair"));
    assert!(answer.get("hook_argv").is_none());
}

#[test]
fn every_bounded_harness_runs_the_callers_native_runtime() {
    let home = Home::new();
    for harness in BRIDGE {
        let answer = hook_config(&home, harness, None);
        let config = answer["config"].as_str().unwrap();
        assert_eq!(
            answer["hook_argv"],
            json!(["/g/hol-guard-runtime", "bounded-hook-bridge", config]),
            "{harness}"
        );
        assert!(config.contains(&format!("\"harness\":\"{harness}\"")));
        assert!(config.ends_with("\"timeout_seconds\":20,\"frozen_launcher\":false}"));
    }
}

#[test]
fn a_frozen_callers_hook_names_the_durable_runtime_copy() {
    let home = Home::new();
    let (stamp, copy) = frozen_with_runtime(&home);
    let answer = hook_config(&home, "kimi", Some(stamp));
    let config = answer["config"].as_str().unwrap();
    assert!(config.ends_with("\"frozen_launcher\":true}"));
    assert_eq!(
        answer["hook_argv"],
        json!([copy, "bounded-hook-bridge", config])
    );
}

#[test]
fn a_frozen_callers_config_is_the_compact_json_python_wrote() {
    let home = Home::new();
    let (stamp, _) = frozen_with_runtime(&home);
    let answer = hook_config(&home, "grok", Some(stamp));
    assert_eq!(
        answer["config"],
        format!(
            "{{\"python_executable\":\"/py\",\"package_root\":\"/opt/guard/site\",\
             \"guard_home\":{},\"cli_args\":[\"guard\",\"hook\"],\"harness\":\"grok\",\
             \"timeout_seconds\":20,\"frozen_launcher\":true}}",
            json!(home.guard())
        )
    );
}

#[test]
fn a_caller_without_a_native_runtime_asks_for_repair() {
    let home = Home::new();
    let mut stamp = caller(false);
    stamp["native_runtime"] = Value::Null;
    assert_repair(&hook_config(&home, "copilot", Some(stamp)));
}

#[test]
fn a_runtime_without_the_bounded_feature_asks_for_repair() {
    let home = Home::new();
    let mut stamp = caller(false);
    let others: Vec<&str> = NATIVE_FEATURES
        .iter()
        .copied()
        .filter(|feature| !feature.starts_with("bounded-hook-bridge"))
        .collect();
    stamp["native_runtime"]["features"] = json!(others);
    assert_repair(&hook_config(&home, "copilot", Some(stamp)));
}

#[test]
fn a_harness_with_no_bounded_hook_asks_for_repair() {
    let home = Home::new();
    assert_repair(&hook_config(&home, "gemini", None));
}

#[test]
fn muse_needs_its_own_bridge_feature() {
    let home = Home::new();
    let mut stamp = caller(false);
    stamp["native_runtime"]["features"] = json!(["bounded-hook-bridge-v1"]);
    assert_repair(&hook_config(&home, "muse", Some(stamp.clone())));
    assert!(hook_config(&home, "devin", Some(stamp))["hook_argv"].is_array());

    let mut stamp = caller(false);
    stamp["native_runtime"]["features"] = json!(["bounded-hook-bridge-muse-v1"]);
    assert!(hook_config(&home, "muse", Some(stamp.clone()))["hook_argv"].is_array());
    assert_repair(&hook_config(&home, "devin", Some(stamp)));
}

#[test]
fn a_hook_spec_carries_the_argv_of_its_config() {
    let home = Home::new();
    let spec = home.ask("cline", "hook_spec", json!({}));
    let config = spec["config"].as_str().unwrap();
    assert_eq!(
        spec["hook_argv"],
        json!(["/g/hol-guard-runtime", "bounded-hook-bridge", config])
    );
}
