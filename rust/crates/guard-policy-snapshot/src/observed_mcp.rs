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
        matches!(action.as_str(), "allow" | "review" | "block")
            && mcp_tool_namespace(tool).is_some()
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

pub(crate) fn validate_mcp_provider_actions(actions: &BTreeMap<String, String>) -> bool {
    if actions.len() > super::POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS {
        return false;
    }
    actions.iter().all(|(selector, action)| {
        let parts: Vec<_> = selector.split(':').collect();
        if parts.len() != 5
            || parts[2] != "composio"
            || parts[3] != "all-accounts"
            || !matches!(action.as_str(), "review" | "block")
            || super::normalized_harness_selector(parts[0]).as_deref() != Some(parts[0])
            || parts[4].is_empty()
            || parts[4].len() > 128
            || !parts[4]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || !parts[4].as_bytes()[0].is_ascii_alphanumeric()
        {
            return false;
        }
        mcp_tool_namespace(&format!("{}probe", parts[1])) == Some(parts[1])
    })
}

pub fn mcp_provider_action_choice<'a>(
    actions: &'a BTreeMap<String, String>,
    harness: &str,
    tool: &str,
    slug: &str,
) -> Option<&'a str> {
    let namespace = mcp_tool_namespace(tool)?;
    actions
        .get(&format!(
            "{harness}:{namespace}:composio:all-accounts:{slug}"
        ))
        .map(String::as_str)
}

pub fn mcp_provider_namespace_has_deny(
    actions: &BTreeMap<String, String>,
    harness: &str,
    tool: &str,
) -> bool {
    let Some(namespace) = mcp_tool_namespace(tool) else {
        return false;
    };
    let prefix = format!("{harness}:{namespace}:composio:all-accounts:");
    actions
        .range(prefix.clone()..)
        .take_while(|(key, _)| key.starts_with(&prefix))
        .any(|(_, state)| state == "block")
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
