//! The pairs, groups and legacy bridge identity an install request leaves to
//! the runtime when it sends a `launch`.

use serde_json::{json, Map, Value};

use super::super::Home;
use crate::harness_adapter::codex_install_request::{complete, complete_uninstall};
use crate::harness_adapter::codex_spec::with_spec;
use crate::harness_adapter::Ctx;

fn launch(home: &Home) -> Value {
    json!({
        "home_is_current": false,
        "runtime_guard_home": home.guard(),
        "workspace_explicit": false,
        "manifest_path": "/g/manifest.json",
        "long_timeout": 85,
    })
}

fn fields(home: &Home, extra: Value) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("launch".into(), launch(home));
    fields.extend(extra.as_object().unwrap().clone());
    fields
}

fn ctx(home: &Home) -> Ctx {
    Ctx::parse(Some(&home.context(json!({})))).unwrap()
}

#[test]
fn a_launch_completes_the_pairs_groups_and_legacy_bridge() {
    let home = Home::new();
    let request = fields(&home, json!({}));
    let done = complete(&ctx(&home), &request, false).ok().unwrap();
    let config = home.home().join(".codex").join("config.toml");
    let hooks = home.home().join(".codex").join("hooks.json");
    assert_eq!(done["pairs"], json!([[config, hooks]]));
    assert_eq!(done["workspace_config"], Value::Null);
    assert!(done.get("home").is_none() && done.get("config").is_none());
    let argv = home.ask(
        "codex",
        "argv",
        json!({
            "home_is_current": false,
            "runtime_guard_home": home.guard(),
            "workspace_explicit": false,
            "manifest_path": "/g/manifest.json",
            "long_timeout": 85,
        }),
    );
    let groups = home.ask(
        "codex",
        "groups",
        json!({ "argv": argv["argv"], "long_timeout": 85 }),
    );
    assert_eq!(done["argv"], argv["argv"]);
    assert_eq!(done["managed"], groups["groups"]);
    let expected: Value = serde_json::from_str(done["expected"].as_str().unwrap()).unwrap();
    let bindings: Value = serde_json::from_str(groups["bindings"].as_str().unwrap()).unwrap();
    assert_eq!(expected, bindings);
    // Both are the compact text of the same bindings; a launch argument may
    // hold ", " inside a string, so the separators are compared, not searched.
    assert_eq!(done["expected"], groups["bindings"]);
    assert_eq!(done["legacy_argv"][0], "/py");
    let statuses: Vec<&str> = done["statuses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|status| status.as_str().unwrap())
        .collect();
    let mut sorted = statuses.clone();
    sorted.sort_unstable();
    assert_eq!(statuses, sorted);
    assert_eq!(statuses.len(), 5);
}

#[test]
fn a_whole_install_names_its_anchored_home_and_config() {
    let home = Home::new();
    let request = fields(&home, json!({}));
    let done = complete(&ctx(&home), &request, true).ok().unwrap();
    assert_eq!(done["home"], json!(home.guard()));
    assert_eq!(
        done["config"],
        json!(home.home().join(".codex").join("config.toml"))
    );
    assert_eq!(done["budget_spent"], false);
}

#[test]
fn a_field_the_request_names_is_kept_and_no_launch_leaves_it_alone() {
    let home = Home::new();
    let own = json!({ "pairs": [["/a", "/b"]], "managed": "{}", "budget_spent": true });
    let request = fields(&home, own);
    let done = complete(&ctx(&home), &request, true).ok().unwrap();
    assert_eq!(done["pairs"], json!([["/a", "/b"]]));
    assert_eq!(done["managed"], "{}");
    assert_eq!(done["budget_spent"], true);
    let bare = Map::new();
    assert_eq!(*complete(&ctx(&home), &bare, true).ok().unwrap(), bare);
    assert_eq!(*complete_uninstall(&ctx(&home), &bare).ok().unwrap(), bare);
}

#[test]
fn an_uninstall_gets_the_legacy_bridge_and_consumes_the_launch() {
    let home = Home::new();
    let request = fields(&home, json!({ "owned": "[]" }));
    let done = complete_uninstall(&ctx(&home), &request).ok().unwrap();
    assert!(done.get("launch").is_none());
    assert_eq!(done["owned"], "[]");
    for key in ["expected", "argv", "legacy_argv", "statuses"] {
        assert!(done.get(key).is_some(), "{key}");
    }
    assert!(done.get("pairs").is_none() && done.get("managed").is_none());
}

#[test]
fn a_generation_takes_its_anchored_paths_from_the_spec() {
    let home = Home::new();
    let request = fields(&home, json!({ "generation": { "create_key": true } }));
    let done = with_spec(&ctx(&home), &request).ok().unwrap();
    let generation = &done["generation"];
    assert_eq!(generation["home"], json!(home.guard()));
    assert_eq!(generation["guard_home"], json!(home.guard()));
    assert_eq!(generation["home_dir"], json!(home.home()));
    assert_eq!(generation["runtime_guard_home"], json!(home.guard()));
    assert_eq!(
        generation["config"],
        json!(home.home().join(".codex").join("config.toml"))
    );
    assert_eq!(generation["workspace_dir"], Value::Null);
    assert_eq!(generation["workspace_rebinding_allowed"], true);
    assert_eq!(generation["create_key"], true);
}

#[test]
fn a_request_with_a_launch_and_its_own_spec_keeps_the_spec() {
    let home = Home::new();
    let request = fields(&home, json!({ "spec": { "own": true }, "generation": {} }));
    let done = with_spec(&ctx(&home), &request).ok().unwrap();
    assert!(done.get("launch").is_none());
    assert_eq!(done["spec"], json!({ "own": true }));
    assert_eq!(done["generation"]["spec"], json!({ "own": true }));
}
