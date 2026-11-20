//! When a stored MCP catalog counts as declaring the Skills extension: the
//! server must name the extension and serve resources, on a well-formed
//! protocol version no older than the one that introduced it. A tool that
//! happens to be called "skills" is not a declaration.

use serde_json::{json, Value};

use crate::guard_store_local_cli_mcp_snapshot::skills_declared;

fn declared(capabilities: &Value, protocol_version: &str) -> bool {
    skills_declared(Some(capabilities), Some(&json!(protocol_version)))
}

fn capabilities() -> Value {
    json!({"resources": {}, "extensions": {"io.modelcontextprotocol/skills": {}}})
}

#[test]
fn the_extension_and_resources_together_declare_skills_from_the_first_version_on() {
    assert!(declared(&capabilities(), "2026-07-28"));
    assert!(declared(&capabilities(), "2027-01-01"));
}

#[test]
fn a_missing_extension_or_missing_resources_is_not_a_declaration() {
    for partial in [
        json!({}),
        json!({"tools": {}}),
        json!({"extensions": {"io.modelcontextprotocol/skills": {}}}),
        json!({"resources": {}}),
    ] {
        assert!(!declared(&partial, "2026-07-28"), "{partial}");
    }
}

#[test]
fn an_older_or_malformed_protocol_version_is_not_a_declaration() {
    for version in [
        "2025-11-25",
        "2026-07-27",
        "2026-13-01",
        "2026-07-28-extra",
        "20260728",
    ] {
        assert!(!declared(&capabilities(), version), "{version}");
    }
    assert!(!skills_declared(Some(&capabilities()), None));
    assert!(!skills_declared(None, Some(&json!("2026-07-28"))));
}
