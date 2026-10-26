use super::*;
use guard_contracts::ComposioRoleResultV1;

fn request(tool_name: &str) -> ComposioRoleRequestV1 {
    ComposioRoleRequestV1 {
        schema: COMPOSIO_ROLE_REQUEST_SCHEMA.to_owned(),
        request_id: "composio-1".to_owned(),
        tool_name: tool_name.to_owned(),
    }
}

fn run(request: &ComposioRoleRequestV1) -> ComposioRoleResultV1 {
    let bytes = evaluate_composio_role_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn every_wrapper_reports_the_role_the_contract_routes_it_to() {
    for (tool, role) in [
        (
            "mcp__codex_apps__composio__composio_search_tools",
            "discovery",
        ),
        (
            "mcp__codex_apps__composio__composio_get_tool_schemas",
            "discovery",
        ),
        (
            "mcp__codex_apps__composio__composio_multi_execute_tool",
            "batch",
        ),
        (
            "mcp__codex_apps__composio__composio_remote_workbench",
            "workbench",
        ),
        (
            "mcp__codex_apps__composio__composio_remote_bash_tool",
            "workbench",
        ),
        (
            "mcp__codex_apps__composio__composio_manage_connections",
            "connections",
        ),
        ("mcp__codex_apps__composio__composio_brand_new", "unknown"),
    ] {
        let result = run(&request(tool));
        assert_eq!(result.status, "ok");
        assert_eq!(result.role.as_deref(), Some(role), "{tool}");
        assert_eq!(result.requires_action_review, role != "discovery", "{tool}");
    }
}

#[test]
fn a_tool_the_contract_does_not_route_has_no_role_and_draws_no_provider_review() {
    let result = run(&request("mcp__notes__read_note"));
    assert_eq!(result.status, "ok");
    assert_eq!(result.role, None);
    assert!(!result.requires_action_review);
}

#[test]
fn the_role_follows_the_last_segment_under_full_case_folding() {
    assert_eq!(
        run(&request("mcp__a__COMPOSIO_SEARCH_TOOLS"))
            .role
            .as_deref(),
        Some("discovery")
    );
    assert_eq!(
        run(&request("mcp__a__compo\u{17f}io_manage_connections"))
            .role
            .as_deref(),
        Some("connections")
    );
}

#[test]
fn a_request_the_op_cannot_read_names_no_role_and_still_draws_review() {
    let mut mismatched = request("mcp__notes__read_note");
    mismatched.schema = "guard-composio-role-request.v0".to_owned();
    let result = run(&mismatched);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_composio_role_schema_mismatch");
    assert_eq!(result.role, None);
    assert!(result.requires_action_review);
}

#[test]
fn the_result_binds_the_request_that_produced_it() {
    let result = run(&request(
        "mcp__codex_apps__composio__composio_multi_execute_tool",
    ));
    assert_eq!(result.schema, COMPOSIO_ROLE_RESULT_SCHEMA);
    assert_eq!(result.request_id, "composio-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    let other = run(&request("mcp__codex_apps__composio__composio_search_tools"));
    assert_ne!(result.request_sha256, other.request_sha256);
}
