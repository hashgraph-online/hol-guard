//! Inner action denies are floors for the entire router call, never partial execution.

use std::collections::BTreeMap;

use guard_policy_snapshot::{mcp_provider_action_choice, mcp_provider_namespace_has_deny};
use serde_json::Value;

pub(super) fn denied_provider_execution(
    choices: &BTreeMap<String, String>,
    harness: &str,
    tool: &str,
    payload: &Value,
) -> Option<&'static str> {
    let name = tool.rsplit("__").next()?.to_ascii_lowercase();
    if !name.starts_with("composio_")
        || matches!(
            name.as_str(),
            "composio_search_tools" | "composio_get_tool_schemas" | "composio_manage_connections"
        )
        || !mcp_provider_namespace_has_deny(choices, harness, tool)
    {
        return None;
    }
    let opaque = "native_composio_opaque_execution_with_deny";
    if name != "composio_multi_execute_tool" {
        return Some(opaque);
    }
    let Some(arguments) = unambiguous_arguments(payload).and_then(Value::as_object) else {
        return Some(opaque);
    };
    let Some(members) = arguments.get("tools").and_then(Value::as_array) else {
        return Some(opaque);
    };
    if members.is_empty() || members.len() > 50 {
        return Some(opaque);
    }
    // Provider slugs are ASCII. Case variants can never evade a Deny; this
    // conservative comparison does not resolve aliases or authorize actions.
    for slug in members
        .iter()
        .filter_map(|member| member.get("tool_slug").and_then(Value::as_str))
    {
        if mcp_provider_action_choice(choices, harness, tool, slug) == Some("block")
            || choices.iter().any(|(selector, state)| {
                state == "block"
                    && selector.rsplit(':').next().is_some_and(|denied| {
                        denied.eq_ignore_ascii_case(slug)
                            && mcp_provider_action_choice(choices, harness, tool, denied)
                                == Some("block")
                    })
            })
        {
            return Some("native_composio_denied_batch_member");
        }
    }
    for member in members {
        let Some(record) = member.as_object() else {
            return Some(opaque);
        };
        let Some(slug) = record.get("tool_slug").and_then(Value::as_str) else {
            return Some(opaque);
        };
        let account_valid = record.get("account").is_none_or(|value| {
            value.is_null()
                || value.as_str().is_some_and(|account| {
                    !account.is_empty() && account.len() <= 256 && account.trim() == account
                })
        });
        if slug.is_empty()
            || slug.len() > 128
            || !slug.as_bytes()[0].is_ascii_alphanumeric()
            || !slug
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || !record.get("arguments").is_some_and(Value::is_object)
            || !account_valid
            || record
                .keys()
                .any(|key| !matches!(key.as_str(), "tool_slug" | "arguments" | "account"))
        {
            return Some(opaque);
        }
    }
    None
}

fn unambiguous_arguments(payload: &Value) -> Option<&Value> {
    let record = payload.as_object()?;
    let mut envelopes = vec![record];
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        if let Some(envelope) = record.get(key).and_then(Value::as_object) {
            envelopes.push(envelope);
        }
    }
    let mut selected = None;
    for envelope in envelopes {
        for key in ["tool_input", "toolInput", "arguments"] {
            if let Some(arguments) = envelope.get(key) {
                if selected.is_some_and(|previous| previous != arguments) {
                    return None;
                }
                selected = Some(arguments);
            }
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn choices() -> BTreeMap<String, String> {
        BTreeMap::from([(
            "codex:mcp__codex_apps__composio__:composio:all-accounts:SLACK_SEND_MESSAGE".into(),
            "block".into(),
        )])
    }

    const BATCH: &str = "mcp__codex_apps__composio__composio_multi_execute_tool";

    #[test]
    fn deny_blocks_whole_batch_even_with_malformed_sibling_or_case_variant() {
        for slug in ["SLACK_SEND_MESSAGE", "slack_send_message"] {
            let payload = json!({"tool_input":{"tools":[
                {"tool_slug":slug,"arguments":{},"account":"different-account"}, null
            ]}});
            assert_eq!(
                denied_provider_execution(&choices(), "codex", BATCH, &payload),
                Some("native_composio_denied_batch_member")
            );
        }
    }

    #[test]
    fn conflicting_arguments_and_opaque_execution_cannot_escape_deny() {
        let allowed = json!({"tools":[{"tool_slug":"SLACK_SEARCH_MESSAGES","arguments":{}}]});
        let conflict = json!({"tool_input":allowed,"arguments":{"tools":[]}});
        assert_eq!(
            denied_provider_execution(&choices(), "codex", BATCH, &conflict),
            Some("native_composio_opaque_execution_with_deny")
        );
        for tool in ["composio_remote_workbench", "composio_execute_future"] {
            assert_eq!(
                denied_provider_execution(
                    &choices(),
                    "codex",
                    &format!("mcp__codex_apps__composio__{tool}"),
                    &json!({})
                ),
                Some("native_composio_opaque_execution_with_deny")
            );
        }
        assert_eq!(
            denied_provider_execution(&choices(), "codex", BATCH, &json!({"tool_input":allowed})),
            None
        );
    }

    #[test]
    fn provider_denies_keep_namespace_and_harness_boundaries() {
        let payload = json!({"tool_input":{"tools":[
            {"tool_slug":"SLACK_SEND_MESSAGE","arguments":{}}
        ]}});
        assert_eq!(
            denied_provider_execution(&choices(), "claude", BATCH, &payload),
            None
        );
        assert_eq!(
            denied_provider_execution(
                &choices(),
                "codex",
                "mcp__other__composio_multi_execute_tool",
                &payload
            ),
            None
        );
        assert_eq!(
            denied_provider_execution(
                &choices(),
                "codex",
                "mcp__codex_apps__composio__composio_search_tools",
                &payload
            ),
            None
        );
    }
}
