use serde_json::{json, Value};

use super::*;

fn ask(op: &str, harness: &str) -> Value {
    dispatch(&json!({"op": op, "harness": harness})).unwrap()
}

fn contract(harness: &str) -> Value {
    ask("contract", harness)["contract"].clone()
}

#[test]
fn an_alias_answers_with_the_contract_of_its_harness() {
    let claude = contract("claude");
    assert_eq!(claude["harness"], "claude-code");
    assert_eq!(claude["display_name"], "Claude Code");
    assert_eq!(claude["install_aliases"], json!(["claude-code", "claude"]));
    assert_eq!(
        claude["setup_steps"][0],
        json!({
            "step_id": "connect",
            "title": "Connect Claude Code",
            "body": "Add Guard's local protection hooks for Claude Code.",
            "command": ["hol-guard", "apps", "connect", "claude-code"],
            "writes_config": true,
            "requires_confirmation": false,
        })
    );
    assert_eq!(
        claude["setup_steps"][1],
        json!({
            "step_id": "review-coverage",
            "title": "Review what Guard can see",
            "body": "Check covered events and known blind spots before relying on this app.",
            "command": [],
            "writes_config": false,
            "requires_confirmation": false,
        })
    );
    assert_eq!(
        claude["verify_steps"][0]["command"],
        json!(["hol-guard", "apps", "test", "claude-code"])
    );
    assert_eq!(
        claude["repair_steps"][0]["title"],
        "Repair Claude Code protection"
    );
    assert_eq!(
        claude["repair_steps"][0]["command"],
        json!(["hol-guard", "apps", "repair", "claude-code"])
    );
    assert_eq!(claude["repair_steps"][0]["writes_config"], true);
    for absent in [
        "surface_capabilities",
        "supported_actions",
        "docs_path",
        "icon_label",
    ] {
        assert!(claude.get(absent).is_none(), "{absent}");
    }
}

#[test]
fn coverage_reads_the_contracts_event_surfaces() {
    let codex = contract("codex");
    assert_eq!(codex["coverage"]["native_hooks"], true);
    assert_eq!(codex["coverage"]["browser_fallback"], true);
    assert_eq!(codex["coverage"]["mcp_proxy"], true);
    assert_eq!(codex["coverage"]["prompt_hooks"], true);
    assert_eq!(
        codex["coverage"]["blind_spots"].as_array().unwrap().len(),
        1
    );
    let gemini = contract("gemini");
    assert_eq!(gemini["coverage"]["native_hooks"], false);
    assert_eq!(gemini["coverage"]["prompt_hooks"], false);
}

#[test]
fn optional_fields_appear_only_when_the_contract_has_them() {
    let cursor = contract("cursor");
    assert_eq!(cursor["surface_capabilities"], json!(["editor", "cli"]));
    assert_eq!(cursor["supported_actions"][0], "connect:editor");
    assert_eq!(cursor["icon_label"], "Cursor");
    assert!(cursor["docs_path"].is_string());
    let paseo = contract("paseo");
    assert_eq!(
        paseo["setup_steps"][0]["body"],
        "Install native provider hooks on the Paseo daemon host."
    );
    assert_eq!(paseo["coverage"]["mcp_proxy"], false);
}

#[test]
fn an_unknown_name_has_no_contract_and_is_its_own_label() {
    assert_eq!(ask("contract", "nothing"), json!({"contract": null}));
    assert_eq!(
        ask("display_name", "nothing"),
        json!({"display_name": "nothing"})
    );
    assert_eq!(
        ask("display_name", "omp"),
        json!({"display_name": "Oh My Pi"})
    );
    assert_eq!(
        ask("display_name", "oh-my-pi"),
        json!({"display_name": "Oh My Pi"})
    );
}

#[test]
fn every_contract_has_a_label_and_a_setup_contract() {
    let harnesses = contracts()
        .iter()
        .map(|contract| contract["harness"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(harnesses.len(), DISPLAY_NAMES.len());
    for harness in harnesses {
        assert!(
            DISPLAY_NAMES.iter().any(|(key, _)| *key == harness),
            "{harness}"
        );
        assert_eq!(contract(harness)["harness"], harness);
    }
}

#[test]
fn a_malformed_request_is_refused() {
    for request in [
        json!({"op": "contract"}),
        json!({"op": "contract", "harness": 1}),
        json!({"op": "other", "harness": "codex"}),
        json!({"op": "contract", "harness": "codex", "extra": 1}),
        json!("codex"),
    ] {
        assert!(dispatch(&request).is_err());
    }
}
