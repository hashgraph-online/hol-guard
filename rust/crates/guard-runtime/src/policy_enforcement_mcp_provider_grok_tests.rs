//! Grok runs every MCP tool through one dispatcher. These tests pin how the
//! tool it runs is named and how a dispatched Composio batch is judged.

use super::*;
use serde_json::json;

#[test]
fn a_grok_call_names_one_complete_tool_or_none() {
    let named = |input: Value| {
        mcp_tool_name(
            &json!({"toolName": "use_tool", "tool_input": input}),
            "grok",
        )
        .unwrap()
    };
    let list = Some("mcp__ads_api__list_ads".to_owned());
    assert_eq!(named(json!({"tool_name": "ads_api__list_ads"})), list);
    assert_eq!(named(json!({"tool_name": "mcp__ads_api__list_ads"})), list);
    assert_eq!(
        named(json!({"server": "ads_api", "tool": "list_ads", "tool_name": "ads_api__list_ads"})),
        list
    );
    for input in [
        json!({"server": "ads_api", "tool": "list_ads", "tool_name": "ads_api__delete_ads"}),
        json!({"server": "ads_api", "tool_name": "ads_api__list_ads"}),
        json!({"tool": "list_ads"}),
        json!({"tool_name": ["ads_api__list_ads"]}),
        json!({"tool_name": "list_ads"}),
        json!({"tool_name": "ads__api__list_ads"}),
        json!({"tool_name": "ads_api___list_ads"}),
        json!({"tool_name": "ads_api__list__ads"}),
        json!({"server": "ads__api", "tool": "list_ads"}),
        json!({"limit": 5}),
    ] {
        assert_eq!(named(input.clone()), None, "{input}");
    }
    let wrapped = |inner: &str| {
        json!({
            "toolName": "use_tool",
            "tool_input": {"tool_name": "ads_api__list_ads"},
            "tool_call": {"tool_input": {"tool_name": inner}},
        })
    };
    assert_eq!(
        mcp_tool_name(&wrapped("ads_api__list_ads"), "grok").unwrap(),
        list
    );
    assert_eq!(
        mcp_tool_name(&wrapped("ads_api__delete_ads"), "grok").unwrap(),
        None
    );
    let prepared = |server: &str| {
        json!({"toolName": "MCPTool", "mcp_server": server, "mcp_tool": "list_ads",
            "tool_input": {"limit": 5}})
    };
    assert_eq!(mcp_tool_name(&prepared("ads_api"), "grok").unwrap(), list);
    assert_eq!(
        mcp_tool_name(&prepared("mcp"), "grok").unwrap(),
        Some("mcp__mcp__list_ads".into())
    );
    assert_eq!(
        named(json!({"server": "mcp", "tool": "list_ads", "tool_name": "mcp__list_ads"})),
        Some("mcp__mcp__list_ads".into())
    );
    let codex = json!({"tool_name": "use_tool", "tool_input": {"tool_name": "ads_api__x"}});
    assert_eq!(
        mcp_tool_name(&codex, "codex").unwrap(),
        Some("use_tool".into())
    );
}

#[test]
fn a_grok_dispatched_batch_is_judged_by_the_actions_it_runs() {
    let choices = BTreeMap::from([(
        "grok:mcp__composio__:composio:all-accounts:SLACK_SEND_MESSAGE".to_owned(),
        "block".to_owned(),
    )]);
    let batch = |slug: &str| {
        json!({"toolName": "use_tool", "tool_input": {
            "tool_name": "composio__COMPOSIO_MULTI_EXECUTE_TOOL",
            "tool_input": {"tools": [{"tool_slug": slug, "arguments": {}}]},
        }})
    };
    let tool = mcp_tool_name(&batch("SLACK_SEND_MESSAGE"), "grok")
        .unwrap()
        .unwrap();
    assert_eq!(
        denied_provider_execution(&choices, "grok", &tool, &batch("SLACK_SEND_MESSAGE")),
        Some("native_composio_denied_batch_member")
    );
    assert_eq!(
        denied_provider_execution(&choices, "grok", &tool, &batch("SLACK_SEARCH_MESSAGES")),
        None
    );
    // Prepared adapter events carry the batch directly in tool_input.
    let prepared = |slug: &str| {
        json!({"toolName": "MCPTool", "mcp_server": "composio",
            "mcp_tool": "COMPOSIO_MULTI_EXECUTE_TOOL",
            "tool_input": {"tools": [{"tool_slug": slug, "arguments": {}}]}})
    };
    let prepared_tool = mcp_tool_name(&prepared("SLACK_SEND_MESSAGE"), "grok")
        .unwrap()
        .unwrap();
    assert_eq!(prepared_tool, tool);
    assert_eq!(
        denied_provider_execution(
            &choices,
            "grok",
            &prepared_tool,
            &prepared("SLACK_SEND_MESSAGE")
        ),
        Some("native_composio_denied_batch_member")
    );
    assert_eq!(
        denied_provider_execution(
            &choices,
            "grok",
            &prepared_tool,
            &prepared("SLACK_SEARCH_MESSAGES")
        ),
        None
    );
    let conflicting = json!({
        "toolName": "MCPTool", "mcp_server": "composio",
        "mcp_tool": "COMPOSIO_MULTI_EXECUTE_TOOL",
        "tool_input": {"tools": [{"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {}}]},
        "tool_call": {
            "tool_input": {"tools": [{"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}}]}
        }
    });
    assert_eq!(
        denied_provider_execution(&choices, "grok", &prepared_tool, &conflicting),
        Some("native_composio_opaque_execution_with_deny")
    );

    // A *single* prepared input can also hide its direct batch behind
    // a conflicting nested copy. Neither ordering may bypass the deny.
    for (direct, nested) in [
        ("SLACK_SEND_MESSAGE", "SLACK_SEARCH_MESSAGES"),
        ("SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE"),
    ] {
        let mixed = json!({
            "toolName": "MCPTool",
            "mcp_server": "composio",
            "mcp_tool": "COMPOSIO_MULTI_EXECUTE_TOOL",
            "tool_input": {
                "tools": [{"tool_slug": direct, "arguments": {}}],
                "arguments": {"tools": [{"tool_slug": nested, "arguments": {}}]}
            }
        });
        assert_eq!(
            denied_provider_execution(&choices, "grok", &prepared_tool, &mixed),
            Some("native_composio_opaque_execution_with_deny"),
            "direct={direct}; nested={nested}"
        );
    }

    // A direct batch and a nested arguments copy can disagree about
    // which member runs. Both orders must remain opaque, never allowed.
    for (direct, nested) in [
        ("SLACK_SEND_MESSAGE", "SLACK_SEARCH_MESSAGES"),
        ("SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE"),
    ] {
        let mixed = json!({
            "toolName": "MCPTool",
            "mcp_server": "composio",
            "mcp_tool": "COMPOSIO_MULTI_EXECUTE_TOOL",
            "tool_input": {"tools": [{"tool_slug": direct, "arguments": {}}]},
            "tool_call": {"tool_input": {
                "arguments": {"tools": [{"tool_slug": nested, "arguments": {}}]}
            }}
        });
        assert_eq!(
            denied_provider_execution(&choices, "grok", &prepared_tool, &mixed),
            Some("native_composio_opaque_execution_with_deny"),
            "direct={direct}; nested={nested}"
        );
    }
}
