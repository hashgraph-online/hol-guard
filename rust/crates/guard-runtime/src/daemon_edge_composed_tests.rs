use serde_json::json;

use super::*;

fn setup() -> Value {
    json!({
        "package_version": "9.9.9",
        "items": [
            {"harness": "codex", "display_name": "Codex", "status": "protected", "command_available": true},
            {"harness": "claude-code", "display_name": "Claude Code", "status": "needs_repair", "command_available": false},
            {"harness": "cursor", "status": "not_found"},
            {"display_name": "unnamed", "status": "found", "command_available": 1},
        ],
    })
}

#[test]
fn capabilities_lists_each_named_harness_with_its_app_status() {
    let body = capabilities(&setup(), false).unwrap();
    assert_eq!(body["auth_state"], "local_token");
    assert_eq!(body["command_available"], true);
    assert_eq!(body["daemon"]["package_version"], "9.9.9");
    assert_eq!(body["daemon"]["compatibility_version"], 2);
    assert_eq!(
        body["supported_harnesses"],
        json!(["claude-code", "codex", "cursor"])
    );
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["status"], "protected");
    assert_eq!(items[1]["status"], "observed");
    assert_eq!(items[2]["status"], "inactive");
    assert_eq!(items[2]["display_name"], Value::Null);
    assert_eq!(items[2]["command_available"], false);
    assert_eq!(
        items[0]["headless_actions"],
        json!(["install", "repair", "remove", "status", "scan"])
    );
    assert_eq!(
        body["headless_api"]["operations"],
        json!([
            "install",
            "repair",
            "remove",
            "status",
            "scan",
            "policy_sync"
        ])
    );
}

#[test]
fn a_dashboard_session_reports_its_auth_state() {
    let body = capabilities(&setup(), true).unwrap();
    assert_eq!(body["auth_state"], "dashboard_session");
}

#[test]
fn an_unnamed_item_still_counts_toward_command_availability() {
    let body = capabilities(
        &json!({"items": [{"status": "found", "command_available": 1}]}),
        false,
    )
    .unwrap();
    assert_eq!(body["command_available"], true);
    assert_eq!(body["items"], json!([]));
    assert_eq!(body["daemon"]["package_version"], Value::Null);
}

#[test]
fn the_composed_routes_leave_the_dispatch() {
    for path in [
        "/v1/harnesses",
        "/v1/capabilities",
        "/v1/policy",
        "/v1/cloud-review",
        "/v1/cloud-actions/status",
        "/v1/context-assistance",
        "/v1/context-assistance/usage",
        "/v1/policy/cloud-exception-requests",
        "/v1/supply-chain/workspace-findings",
        "/v1/supply-chain/workspace-fix-proposals",
    ] {
        assert!(routed(path));
        assert!(!dispatch::get_routed(path));
    }
    assert!(!routed("/v1/policy/cloud-exceptions"));
}
