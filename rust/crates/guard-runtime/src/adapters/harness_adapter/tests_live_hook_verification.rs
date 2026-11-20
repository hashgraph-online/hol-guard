//! `live_hook_verification`: one verdict per active managed install.

use std::fs;

use serde_json::{json, Value};

use super::super::dispatch;
use super::Home;

fn verified(home: &Home, installs: Value) -> Value {
    let request = json!({
        "op": "live_hook_verification",
        "context": home.context(json!({"PATH": ""})),
        "managed_installs": installs,
    });
    dispatch(&request).unwrap()["verified"].clone()
}

fn bound_manifest(home: &Home) -> (std::path::PathBuf, Value) {
    let config = home.home().join("settings.json");
    fs::write(&config, "{}").unwrap();
    let request = json!({
        "op": "proof_bind",
        "context": home.context(json!({})),
        "manifest": {"config_path": config},
    });
    let bound = dispatch(&request).unwrap();
    let proof: Value = serde_json::from_str(bound["proof"].as_str().unwrap()).unwrap();
    (config, json!({"protection_artifact_proof": proof}))
}

#[test]
fn an_install_that_is_inactive_or_unnamed_is_left_out() {
    let home = Home::new();
    let answer = verified(
        &home,
        json!([
            {"harness": "gemini", "active": false, "manifest": {}},
            {"harness": 7, "active": true, "manifest": {}},
            {"active": true, "manifest": {}},
            {"harness": "pi", "manifest": {}},
        ]),
    );
    assert_eq!(answer, json!({}));
}

#[test]
fn another_harness_is_verified_by_its_recorded_artifact_proof() {
    let home = Home::new();
    let (config, manifest) = bound_manifest(&home);
    let installs = json!([{"harness": "gemini", "active": true, "manifest": manifest}]);
    assert_eq!(verified(&home, installs.clone()), json!({"gemini": true}));
    fs::write(&config, "{\"x\": 1}").unwrap();
    assert_eq!(verified(&home, installs), json!({"gemini": false}));
}

#[test]
fn another_harness_without_a_proof_is_not_verified() {
    let home = Home::new();
    let answer = verified(
        &home,
        json!([{"harness": "gemini", "active": true, "manifest": {}}]),
    );
    assert_eq!(answer, json!({"gemini": false}));
}

#[test]
fn codex_that_cannot_be_read_is_not_verified() {
    let home = Home::new();
    let answer = verified(&home, json!([{"harness": "codex", "active": true}]));
    assert_eq!(answer, json!({"codex": false}));
}

#[test]
fn managed_installs_must_be_a_list() {
    let home = Home::new();
    let request = json!({
        "op": "live_hook_verification",
        "context": home.context(json!({})),
        "managed_installs": "gemini",
    });
    assert!(dispatch(&request).is_err());
}
