//! The firewall metadata a detection attaches to its own artifacts.

use std::fs;

use serde_json::{json, Value};

use super::super::firewall::enrich;
use super::Home;

fn artifact(artifact_type: &str, config_path: &str, command: Value) -> Value {
    json!({
        "artifact_id": "x:global:one",
        "name": "one",
        "harness": "x",
        "artifact_type": artifact_type,
        "source_scope": "global",
        "config_path": config_path,
        "command": command,
        "args": ["--flag"],
        "url": null,
        "transport": "stdio",
        "publisher": null,
        "metadata": {"keep": true},
    })
}

#[test]
fn an_unreadable_skill_document_keeps_its_metadata() {
    let home = Home::new();
    let missing = home.home().join("missing").join("SKILL.md");
    let answer = json!({"artifacts": [artifact("skill", &missing.to_string_lossy(), Value::Null)]});
    let enriched = enrich(answer.clone()).unwrap();
    assert_eq!(enriched, answer);
}

#[test]
fn a_skill_document_gains_its_identity() {
    let home = Home::new();
    let document = home.home().join("one").join("SKILL.md");
    fs::create_dir_all(document.parent().unwrap()).unwrap();
    fs::write(&document, "# One\r\nDoes a thing.\r\n").unwrap();
    let answer =
        json!({"artifacts": [artifact("skill", &document.to_string_lossy(), Value::Null)]});
    let enriched = enrich(answer).unwrap();
    let metadata = &enriched["artifacts"][0]["metadata"];
    assert_eq!(metadata["keep"], json!(true));
    let identity = metadata["mcpSkillFirewall"]["skill"]["identityHash"].as_str();
    assert!(identity.is_some_and(|hash| !hash.is_empty()), "{metadata}");
}

#[test]
fn an_mcp_server_without_a_command_is_left_alone() {
    let answer = json!({"artifacts": [artifact("mcp_server", "/tmp/mcp.json", json!("  "))]});
    assert_eq!(enrich(answer.clone()).unwrap(), answer);
}

#[test]
fn other_artifact_types_are_left_alone() {
    let answer = json!({"artifacts": [artifact("guard_hook", "/tmp/hooks.json", json!("guard"))]});
    assert_eq!(enrich(answer.clone()).unwrap(), answer);
}

#[test]
fn a_server_with_a_command_gains_firewall_metadata() {
    let answer = json!({"artifacts": [artifact("mcp_server", "/tmp/mcp.json", json!("npx"))]});
    let enriched = enrich(answer).unwrap();
    let metadata = enriched["artifacts"][0]["metadata"].as_object().unwrap();
    assert_eq!(metadata["keep"], json!(true));
    assert!(
        metadata["mcpSkillFirewall"]["mcpServer"].is_object(),
        "{metadata:?}"
    );
}

#[test]
fn a_non_string_server_name_is_refused() {
    let mut server = artifact("mcp_server", "/tmp/mcp.json", json!("npx"));
    server["metadata"] = json!({"server_name": null});
    assert!(enrich(json!({"artifacts": [server]})).is_err());
}
