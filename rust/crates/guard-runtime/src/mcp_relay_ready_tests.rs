use super::{evaluate, McpRelayReadyRequestV1, MCP_RELAY_READY_SCHEMA};
use crate::mcp_relay_servers::{RelayServerV1, SERVER_PROXY_TOOLS, SERVER_UNKNOWN};
use crate::policy_store::policy_store_direct_lane::tests::{
    binding, fixture, push, write_current_ack, Fixture,
};
use serde_json::{json, Value};
use std::fs;

fn view() -> Value {
    json!({
        "schema": "guard-mcp-relay-view.v2",
        "harnesses": {"codex": {
            "config": {"mode": "enforce"},
            "hash_config": {},
            "receipt_redaction_level": "full",
        }},
        "extension_layers": [],
    })
}

/// A store bound for a settled workspace, with `extra` merged into the binding.
fn bound(label: &str, extra: Value) -> (Fixture, String) {
    let fixture = fixture(&format!("relay-ready-{label}"));
    let directory = fixture.root.join("repo");
    fs::create_dir_all(&directory).unwrap();
    let workspace = fs::canonicalize(&directory)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut lane = binding(&fixture, &workspace);
    lane["evidence_drain"] = json!(true);
    lane["exact_action_control_digest"] = json!("c".repeat(64));
    lane["mcp_relay"] = view();
    lane["blocked_request_mode"] = json!("safe-alternative");
    for (key, value) in extra.as_object().unwrap() {
        lane[key] = value.clone();
    }
    push(&fixture, Some(lane)).unwrap();
    write_current_ack(&fixture);
    (fixture, workspace)
}

fn server(harness: &str) -> RelayServerV1 {
    RelayServerV1 {
        harness: harness.to_owned(),
        server_name: "docs".to_owned(),
        source_scope: "global".to_owned(),
        config_path: "/home/user/.codex/config.toml".to_owned(),
        server_id: None,
        identity_hash: "a".repeat(64),
    }
}

/// Ask for a server whose catalog was reported without a proxy tool.
fn ask(fixture: &Fixture, workspace: &str, harness: &str) -> Value {
    fixture
        .store
        .mcp_relay_servers()
        .record(&server(harness), false);
    ask_for(fixture, workspace, harness, server(harness))
}

fn ask_for(fixture: &Fixture, workspace: &str, harness: &str, server: RelayServerV1) -> Value {
    let request = McpRelayReadyRequestV1 {
        guard_home: fixture.root.to_str().unwrap().to_owned(),
        workspace: workspace.to_owned(),
        harness: harness.to_owned(),
        server,
    };
    serde_json::from_slice(&evaluate(&request, &fixture.store).unwrap()).unwrap()
}

fn not_ready(reason: &str) -> Value {
    json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false, "reason": reason})
}

#[test]
fn a_bound_workspace_and_harness_is_ready() {
    let (fixture, workspace) = bound("ready", json!({}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": true})
    );
}

#[test]
fn an_observing_session_is_ready() {
    let mut observe = view();
    observe["harnesses"]["codex"]["config"]["mode"] = json!("observe");
    let (fixture, workspace) = bound("observe", json!({"mcp_relay": observe}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": true})
    );
}

#[test]
fn an_unbound_lane_names_the_lane_defer() {
    let fixture = fixture("relay-ready-unbound");
    let directory = fixture.root.join("repo");
    fs::create_dir_all(&directory).unwrap();
    let workspace = directory.to_str().unwrap().to_owned();
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("direct_lane_unbound")
    );
}

#[test]
fn a_workspace_the_lane_did_not_settle_is_not_ready() {
    let (fixture, _workspace) = bound("other", json!({}));
    let other = fixture.root.join("other");
    fs::create_dir_all(&other).unwrap();
    // An overlay keeps the unbound directory waiting for its own publish.
    fs::write(fixture.root.join(".hol-guard.toml"), b"").unwrap();
    assert_eq!(
        ask(&fixture, other.to_str().unwrap(), "codex"),
        not_ready("direct_lane_workspace_unknown")
    );
    assert_eq!(
        ask(
            &fixture,
            fixture.root.join("missing").to_str().unwrap(),
            "codex"
        ),
        not_ready("mcp_relay_workspace_invalid")
    );
}

#[test]
fn a_binding_without_relay_state_is_not_ready() {
    let (fixture, workspace) = bound("undrained", json!({"evidence_drain": false}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("mcp_relay_evidence_undrained")
    );
    let (fixture, workspace) = bound("digest", json!({"exact_action_control_digest": null}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("mcp_relay_binding_incomplete")
    );
    let (fixture, workspace) = bound("harness", json!({}));
    assert_eq!(
        ask(&fixture, &workspace, "cursor"),
        not_ready("mcp_relay_harness_unbound")
    );
}

#[test]
fn a_session_the_resident_cannot_decide_is_not_ready() {
    let (fixture, workspace) = bound("ask", json!({"blocked_request_mode": "ask"}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("mcp_relay_session_review_mode")
    );
    let mut observe = view();
    observe["harnesses"]["codex"]["config"]["mode"] = json!("observe");
    let (fixture, workspace) = bound(
        "observe-ask",
        json!({"mcp_relay": observe, "blocked_request_mode": "ask"}),
    );
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("mcp_relay_session_review_mode")
    );
    let (fixture, workspace) = bound("view", json!({"mcp_relay": {"harnesses": {}}}));
    assert_eq!(
        ask(&fixture, &workspace, "codex"),
        not_ready("mcp_relay_view_invalid")
    );
}

#[test]
fn a_server_without_a_clean_catalog_report_is_not_ready() {
    let (fixture, workspace) = bound("servers", json!({}));
    assert_eq!(
        ask_for(&fixture, &workspace, "codex", server("codex")),
        not_ready(SERVER_UNKNOWN)
    );
    fixture
        .store
        .mcp_relay_servers()
        .record(&server("codex"), true);
    assert_eq!(
        ask_for(&fixture, &workspace, "codex", server("codex")),
        not_ready(SERVER_PROXY_TOOLS)
    );
    // A server named for another harness is never this session's.
    fixture
        .store
        .mcp_relay_servers()
        .record(&server("cursor"), false);
    assert_eq!(
        ask_for(&fixture, &workspace, "codex", server("cursor")),
        not_ready(SERVER_UNKNOWN)
    );
}
