//! Inner action denies are floors for the entire router call, never partial execution.

use std::collections::BTreeMap;

use guard_policy_snapshot::{
    mcp_provider_action_choice, mcp_provider_namespace_has_deny, observed_mcp_tool_action,
};
use serde_json::{Map, Value};

use super::preferred_tool_name;

/// The hook payload and the envelopes some harnesses wrap the call in.
fn envelopes(record: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    let mut envelopes = vec![record];
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        if let Some(envelope) = record.get(key).and_then(Value::as_object) {
            envelopes.push(envelope);
        }
    }
    envelopes
}

/// The outer tool of a hook payload. Tool arguments can themselves contain
/// `tool_name` (dispatchers are common). They are data, never the outer
/// tool's authority selector.
pub(super) fn outer_tool_name(payload: &Value) -> Result<Option<String>, String> {
    let Some(record) = payload.as_object() else {
        return Ok(None);
    };
    Ok(preferred_tool_name(&envelopes(record))?.or_else(|| {
        ["action", "operation"]
            .into_iter()
            .find_map(|key| record.get(key).and_then(Value::as_str).map(str::to_owned))
    }))
}

/// Whether this is Grok's MCP dispatcher, which runs the tool its input names.
pub(super) fn grok_dispatch(payload: &Value, harness: &str) -> Result<bool, String> {
    Ok(harness == "grok"
        && outer_tool_name(payload)?.is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "use_tool" | "callmcptool" | "mcptool"
            )
        }))
}

/// The MCP tool a hook payload calls, under the name the operator's choices
/// use. Grok calls every MCP tool through one dispatcher, `use_tool`, whose
/// input names the tool as `<server>__<tool>`; Grok runs exactly that tool, so
/// it is the call's identity, written `mcp__<server>__<tool>` as the observed
/// tool list records it. The adapter's prepared form says the same in
/// `mcp_server` and `mcp_tool`. Every name the call carries must be complete
/// and name the same tool, or the call names no tool.
pub(super) fn mcp_tool_name(payload: &Value, harness: &str) -> Result<Option<String>, String> {
    if !grok_dispatch(payload, harness)? {
        return outer_tool_name(payload);
    }
    let Some(root) = payload.as_object() else {
        return Ok(None);
    };
    let mut names = Vec::new();
    for envelope in envelopes(root) {
        if !dispatched_names(envelope, false, &mut names) {
            return Ok(None);
        }
        for key in ["tool_input", "toolInput"] {
            let Some(input) = envelope.get(key) else {
                continue;
            };
            let Some(input) = input.as_object() else {
                return Ok(None);
            };
            if !dispatched_names(input, true, &mut names) {
                return Ok(None);
            }
        }
    }
    let Some(first) = names.first() else {
        return Ok(None);
    };
    Ok(names
        .iter()
        .all(|name| name == first)
        .then(|| first.clone()))
}

/// Adds the qualified names one record gives its tool. Returns false when a
/// name is incomplete, malformed or ambiguous. A tool input that holds only
/// the tool's arguments adds nothing; the call still needs a name elsewhere.
fn dispatched_names(record: &Map<String, Value>, input: bool, names: &mut Vec<String>) -> bool {
    let pairs: &[(&str, &str)] = if input {
        &[("server", "tool"), ("mcp_server", "mcp_tool")]
    } else {
        &[("mcp_server", "mcp_tool")]
    };
    for (server, tool) in pairs {
        match (record.get(*server), record.get(*tool)) {
            (None, None) => {}
            (Some(Value::String(server)), Some(Value::String(tool))) => {
                match qualified_pair(server.trim(), tool.trim()) {
                    Some(name) => names.push(name),
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    if input {
        for key in ["tool_name", "toolName", "toolname"] {
            match record.get(key) {
                None => {}
                Some(Value::String(name)) => match qualified(name.trim()) {
                    Some(name) => names.push(name),
                    None => return false,
                },
                Some(_) => return false,
            }
        }
    }
    true
}

/// `mcp__<server>__<tool>` from a `<server>__<tool>` name, with or without
/// the `mcp__` prefix. `mcp__list_ads` can only be server `mcp`.
fn qualified(name: &str) -> Option<String> {
    let rest = name.strip_prefix("mcp__").unwrap_or(name);
    let (server, tool) = rest.split_once("__").or_else(|| name.split_once("__"))?;
    qualified_pair(server, tool)
}

/// `mcp__<server>__<tool>`, with exactly one boundary between two non-empty
/// parts so that no other split names a different tool.
fn qualified_pair(server: &str, tool: &str) -> Option<String> {
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && !part.starts_with('_')
            && !part.ends_with('_')
            && !part.contains("__")
            && !part.chars().any(char::is_whitespace)
    };
    (valid(server) && valid(tool)).then(|| format!("mcp__{server}__{tool}"))
}

/// Whether the operator's custom allow covers this exact tool. A Composio
/// executor runs whichever provider action its arguments name, so its tool
/// name cannot stand for those actions. A renamed or flattened connector can
/// put a prefix before the executor's name in the last part of the tool name
/// (`mcp__work_COMPOSIO_MULTI_EXECUTE_TOOL`), so it is looked for anywhere
/// in that part.
pub(super) fn operator_allows_tool(
    actions: &BTreeMap<String, String>,
    harness: &str,
    tool: &str,
) -> bool {
    let name = tool
        .rsplit("__")
        .next()
        .unwrap_or(tool)
        .to_ascii_lowercase();
    let executor = name.rfind("composio_").is_some_and(|start| {
        !matches!(
            &name[start..],
            "composio_search_tools" | "composio_get_tool_schemas"
        )
    });
    !executor && observed_mcp_tool_action(actions, harness, tool) == Some("allow")
}

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
    let arguments = if grok_dispatch(payload, harness).unwrap_or(true) {
        dispatched_arguments(payload)
    } else {
        unambiguous_arguments(payload)
    };
    let Some(arguments) = arguments.and_then(Value::as_object) else {
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

const ARGUMENT_KEYS: [&str; 3] = ["tool_input", "toolInput", "arguments"];

fn unambiguous_arguments(payload: &Value) -> Option<&Value> {
    one_value(envelopes(payload.as_object()?))
}

/// The arguments Grok's dispatcher passes to the tool it runs, nested one
/// level inside its own input.
fn dispatched_arguments(payload: &Value) -> Option<&Value> {
    let raw = envelopes(payload.as_object()?)
        .into_iter()
        .flat_map(|envelope| ["tool_input", "toolInput"].map(|key| envelope.get(key)))
        .flatten()
        .collect::<Vec<_>>();
    let inputs = raw
        .iter()
        .map(|value| value.as_object())
        .collect::<Option<Vec<_>>>()?;
    // Raw dispatcher arguments are nested; prepared MCPTool arguments are
    // directly inside tool_input. Keep conflicting or malformed copies opaque.
    if inputs
        .iter()
        .any(|input| ARGUMENT_KEYS.iter().any(|key| input.contains_key(*key)))
    {
        // Never ignore a direct batch beside nested arguments, whether
        // they appear in separate envelopes or in the same input record.
        if inputs.iter().any(|input| {
            input.contains_key("tools") || ARGUMENT_KEYS.iter().all(|key| !input.contains_key(*key))
        }) {
            return None;
        }
        return one_value(inputs);
    }
    let first = *raw.first()?;
    raw.iter().all(|other| *other == first).then_some(first)
}

/// The one argument value the records carry; two different values are none.
fn one_value(records: Vec<&Map<String, Value>>) -> Option<&Value> {
    let mut selected = None;
    for record in records {
        for key in ARGUMENT_KEYS {
            if let Some(arguments) = record.get(key) {
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

#[cfg(test)]
#[path = "policy_enforcement_mcp_provider_grok_tests.rs"]
mod grok_tests;
