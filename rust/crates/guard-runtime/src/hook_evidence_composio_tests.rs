use guard_command::hook_evidence_writer::ComposioApi;
use serde_json::{json, Map, Value};

use super::*;

const DISCOVERY: &str = "mcp__composio__composio_search_tools";

fn schemas(entries: Value) -> Value {
    json!({"successful": true, "error": null, "data": {"tool_schemas": entries}})
}

fn results(entries: Value) -> Value {
    json!({"successful": true, "error": null, "data": {"results": entries}})
}

#[test]
fn an_observed_tool_keeps_the_connector_it_names() {
    let tool = observed_mcp_tool("Claude ", "mcp__linear__create_issue").expect("parsed");
    assert_eq!(tool.harness, "claude-code");
    assert_eq!(tool.qualified_name, "mcp__linear__create_issue");
    assert_eq!(tool.server.identity_hash.len(), 64);
    assert_eq!(
        tool.identity.cli_id,
        format!("local-cli.mcp-{}", &tool.server.identity_hash[..16])
    );
    assert_eq!(tool.identity.name, "linear");
    assert_eq!(tool.identity.kind, "executable");
    assert_eq!(tool.identity.example_label, "mcp__linear__");
    assert_eq!(tool.identity.identity_hash, tool.server.identity_hash);
    assert!(tool.identity.interpreter_name.is_none());
    assert_eq!(
        tool.server.command.as_deref(),
        Some("observed-mcp:claude-code:mcp__linear__")
    );
}

#[test]
fn a_codex_app_is_scoped_to_its_own_server_segment() {
    let app = observed_mcp_tool("codex", "mcp__codex_apps__notion__search").expect("parsed");
    let plain = observed_mcp_tool("codex", "mcp__notion__search").expect("parsed");
    assert_eq!(
        app.server.command.as_deref(),
        Some("observed-mcp:codex:mcp__codex_apps__notion__")
    );
    // A Codex app and a directly connected server of the same name are
    // separate connectors, so their grants must not collide.
    assert_ne!(app.server.identity_hash, plain.server.identity_hash);
}

#[test]
fn a_name_outside_the_mcp_namespace_is_not_a_connector() {
    assert!(observed_mcp_tool("claude", "Bash").is_none());
    assert!(observed_mcp_tool("claude", "mcp__linear").is_none());
    assert!(observed_mcp_tool("claude", "mcp__linear__a b").is_none());
    assert!(observed_mcp_tool("not a harness", "mcp__linear__create_issue").is_none());
    let long = format!("mcp__linear__{}", "a".repeat(200));
    assert!(observed_mcp_tool("claude", &long).is_none());
}

#[test]
fn the_seam_answers_the_same_as_the_free_functions() {
    let seam = NativeComposio;
    assert_eq!(
        seam.observed_mcp_tool("claude", "mcp__linear__create_issue")
            .expect("parsed")
            .identity,
        observed_mcp_tool("claude", "mcp__linear__create_issue")
            .expect("parsed")
            .identity
    );
    let response = schemas(json!({"GITHUB_STAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "Star a repository.",
        "input_schema": {"type": "object"},
        "hasFullSchema": true,
    }}));
    assert_eq!(
        seam.composio_discovered_actions(DISCOVERY, &response)
            .expect("actions")
            .len(),
        1
    );
    assert!(seam
        .composio_workflow_proposals(DISCOVERY, &results(json!([])))
        .expect("proposals")
        .is_empty());
}

#[test]
fn only_a_discovery_tool_carries_a_catalog() {
    let response = schemas(json!({"GITHUB_STAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "",
        "input_schema": {},
        "hasFullSchema": false,
    }}));
    assert!(composio_discovered_actions(DISCOVERY, &response).is_some());
    for other in [
        "mcp__composio__composio_multi_execute_tool",
        "mcp__composio__composio_remote_bash_tool",
        "mcp__linear__create_issue",
    ] {
        assert!(composio_discovered_actions(other, &response).is_none());
        assert!(composio_workflow_proposals(other, &results(json!([]))).is_none());
    }
}

#[test]
fn a_discovered_action_keeps_its_schema_and_bounded_description() {
    let response = schemas(json!({"GITHUB_STAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "d".repeat(2_500),
        "input_schema": {"type": "object", "properties": {"repo": {"type": "string"}}},
        "hasFullSchema": true,
    }}));
    let actions = composio_discovered_actions(DISCOVERY, &response).expect("actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].toolkit, "github");
    assert_eq!(actions[0].tool_slug, "GITHUB_STAR");
    assert_eq!(actions[0].description.chars().count(), 2_000);
    assert!(actions[0].full_schema);
    assert_eq!(actions[0].input_schema.get("type"), Some(&json!("object")));
}

#[test]
fn a_key_that_disagrees_with_its_slug_is_refused() {
    let response = schemas(json!({"GITHUB_UNSTAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "",
        "input_schema": {},
        "hasFullSchema": false,
    }}));
    assert!(composio_discovered_actions(DISCOVERY, &response).is_none());
}

#[test]
fn a_response_that_reported_an_error_carries_nothing() {
    for response in [
        json!({"successful": false, "data": {"tool_schemas": {}}}),
        json!({"successful": true, "error": "nope", "data": {"tool_schemas": {}}}),
        json!({"successful": true, "error": null, "data": {"success": false, "tool_schemas": {}}}),
        json!({"successful": true, "error": null, "data": {"error": "nope"}}),
        json!({"isError": true, "successful": true, "error": null, "data": {}}),
    ] {
        assert!(composio_discovered_actions(DISCOVERY, &response).is_none());
        assert!(composio_workflow_proposals(DISCOVERY, &response).is_none());
    }
    // An empty catalog is not a successful discovery either.
    assert!(composio_discovered_actions(DISCOVERY, &schemas(json!({}))).is_none());
}

#[test]
fn a_catalog_larger_than_its_byte_budget_is_refused() {
    let mut entries = Map::new();
    for index in 0..600 {
        entries.insert(
            format!("TOOL_{index}"),
            json!({
                "tool_slug": format!("TOOL_{index}"),
                "toolkit": "github",
                "description": "d".repeat(2_000),
                "input_schema": {},
                "hasFullSchema": false,
            }),
        );
    }
    assert!(composio_discovered_actions(DISCOVERY, &schemas(Value::Object(entries))).is_none());
}

#[test]
fn a_schema_deeper_than_the_tree_bound_is_refused() {
    let mut schema = json!({"type": "string"});
    for _ in 0..40 {
        schema = json!({"properties": {"next": schema}});
    }
    let response = schemas(json!({"DEEP": {
        "tool_slug": "DEEP",
        "toolkit": "github",
        "description": "",
        "input_schema": schema,
        "hasFullSchema": false,
    }}));
    assert!(composio_discovered_actions(DISCOVERY, &response).is_none());
}

#[test]
fn a_proposal_drops_a_supporting_slug_its_primary_already_names() {
    let response = results(json!([{
        "primary_tool_slugs": ["GITHUB_STAR", "GITHUB_STAR"],
        "related_tool_slugs": ["GITHUB_STAR", "SLACK_POST"],
        "recommended_plan_steps": ["star it", "say so"],
        "use_case": "ignored",
    }]));
    let proposals = composio_workflow_proposals(DISCOVERY, &response).expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].primary, vec!["GITHUB_STAR".to_owned()]);
    assert_eq!(proposals[0].supporting, vec!["SLACK_POST".to_owned()]);
    assert!(proposals[0].guidance_present);
}

#[test]
fn an_identical_proposal_is_recorded_once_and_an_empty_one_not_at_all() {
    let entry = json!({
        "primary_tool_slugs": ["GITHUB_STAR"],
        "related_tool_slugs": [],
    });
    let response = results(json!([entry, entry, {"primary_tool_slugs": []}]));
    let proposals = composio_workflow_proposals(DISCOVERY, &response).expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert!(!proposals[0].guidance_present);
}

#[test]
fn a_proposal_outside_its_bounds_is_refused() {
    for entry in [
        json!({"primary_tool_slugs": "GITHUB_STAR"}),
        json!({"primary_tool_slugs": ["not a slug"]}),
        json!({"primary_tool_slugs": ["GITHUB_STAR"], "recommended_plan_steps": "star it"}),
        json!({"primary_tool_slugs": ["GITHUB_STAR"], "recommended_plan_steps": [1]}),
    ] {
        assert!(composio_workflow_proposals(DISCOVERY, &results(json!([entry]))).is_none());
    }
    let many: Vec<Value> = (0..51)
        .map(|index| json!({"primary_tool_slugs": [format!("TOOL_{index}")]}))
        .collect();
    assert!(composio_workflow_proposals(DISCOVERY, &results(json!(many))).is_none());
}

#[test]
fn a_text_content_block_is_unwrapped_once() {
    let payload = serde_json::to_string(&schemas(json!({"GITHUB_STAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "",
        "input_schema": {},
        "hasFullSchema": false,
    }})))
    .expect("encoded");
    let wrapped = json!({"isError": false, "content": [{"type": "text", "text": payload}]});
    assert_eq!(
        composio_discovered_actions(DISCOVERY, &wrapped)
            .expect("actions")
            .len(),
        1
    );
    let structured = json!({"structuredContent": schemas(json!({"GITHUB_STAR": {
        "tool_slug": "GITHUB_STAR",
        "toolkit": "github",
        "description": "",
        "input_schema": {},
        "hasFullSchema": false,
    }}))});
    assert_eq!(
        composio_discovered_actions(DISCOVERY, &structured)
            .expect("actions")
            .len(),
        1
    );
}

#[test]
fn a_duplicate_key_in_a_text_block_is_refused() {
    let text = r#"{"successful":true,"error":null,"data":{"tool_schemas":{},"tool_schemas":{}}}"#;
    let wrapped = json!({"content": [{"type": "text", "text": text}]});
    assert!(composio_discovered_actions(DISCOVERY, &wrapped).is_none());
    // Two content blocks name no single result to read.
    let pair = json!({"content": [
        {"type": "text", "text": "{}"},
        {"type": "text", "text": "{}"},
    ]});
    assert!(composio_discovered_actions(DISCOVERY, &pair).is_none());
}
