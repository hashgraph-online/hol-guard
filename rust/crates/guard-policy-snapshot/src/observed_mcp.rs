//! Exact operator choices for MCP namespaces exposed by a harness.

use std::collections::BTreeMap;

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

pub fn mcp_tool_namespace(tool: &str) -> Option<&str> {
    if tool.len() > 160 {
        return None;
    }
    let rest = tool.strip_prefix("mcp__")?;
    let (server, tail) = rest.split_once("__")?;
    if !rest.split("__").all(token) {
        return None;
    }
    let mut boundary = 5 + server.len() + 2;
    let mut name = tail;
    if server == "codex_apps" {
        if let Some((connector, suffix)) = tail.split_once("__") {
            boundary += connector.len() + 2;
            name = suffix;
        }
    }
    if name.len() > 120 || boundary > 155 {
        return None;
    }
    Some(&tool[..boundary])
}

pub(crate) fn validate_mcp_tool_actions(actions: &BTreeMap<String, String>) -> bool {
    if actions.len() > super::POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS {
        return false;
    }
    actions.iter().all(|(selector, action)| {
        let Some((harness, tool)) = selector.split_once(':') else {
            return false;
        };
        if !token(harness)
            || super::normalized_harness_selector(harness).as_deref() != Some(harness)
        {
            return false;
        }
        if let Some(prefix) = tool.strip_suffix('*') {
            let candidate = format!("{prefix}probe");
            return action == "block" && mcp_tool_namespace(&candidate) == Some(prefix);
        }
        matches!(action.as_str(), "allow" | "block") && mcp_tool_namespace(tool).is_some()
    })
}

pub fn observed_mcp_tool_action<'a>(
    actions: &'a BTreeMap<String, String>,
    harness: &str,
    tool: &str,
) -> Option<&'a str> {
    let namespace = mcp_tool_namespace(tool)?;
    actions
        .get(&format!("{harness}:{tool}"))
        .or_else(|| actions.get(&format!("{harness}:{namespace}*")))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_permissions_never_cross_namespaces_or_harnesses() {
        let actions = BTreeMap::from([
            (
                "codex:mcp__codex_apps__composio__search".into(),
                "allow".into(),
            ),
            ("codex:mcp__codex_apps__composio__*".into(), "block".into()),
        ]);
        assert!(validate_mcp_tool_actions(&actions));
        assert_eq!(
            observed_mcp_tool_action(&actions, "codex", "mcp__codex_apps__composio__search"),
            Some("allow")
        );
        assert_eq!(
            observed_mcp_tool_action(&actions, "codex", "mcp__codex_apps__composio__execute"),
            Some("block")
        );
        assert_eq!(
            observed_mcp_tool_action(&actions, "codex", "mcp__codex_apps__github__search"),
            None
        );
        assert_eq!(
            observed_mcp_tool_action(&actions, "claude-code", "mcp__codex_apps__composio__search"),
            None
        );
        assert!(!validate_mcp_tool_actions(&BTreeMap::from([(
            "codex:mcp__codex_apps__composio__*".into(),
            "allow".into()
        ),])));
    }
}
