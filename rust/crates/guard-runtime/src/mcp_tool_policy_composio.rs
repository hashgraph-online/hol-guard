//! Composio meta-tool routing and the provider-action deny floor.
//!
//! Tool roles describe routing, never authority. Operators can deny provider
//! actions for a whole connector namespace; a denied action blocks every
//! execution path that could carry it, including malformed or opaque batches.

use serde_json::{Map, Value};

use crate::context_digest::python_strip;
use crate::skill_identity_canon::casefold;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Discovery,
    Batch,
    Workbench,
    Connections,
    Unknown,
}

pub(crate) fn tool_role(tool_name: &str) -> Option<Role> {
    let tail = tool_name
        .rsplit_once("__")
        .map_or(tool_name, |(_, tail)| tail);
    let name = casefold(tail);
    match name.as_str() {
        "composio_search_tools" | "composio_get_tool_schemas" => Some(Role::Discovery),
        "composio_multi_execute_tool" => Some(Role::Batch),
        "composio_remote_workbench" | "composio_remote_bash_tool" => Some(Role::Workbench),
        "composio_manage_connections" => Some(Role::Connections),
        _ if name.starts_with("composio_") => Some(Role::Unknown),
        _ => None,
    }
}

pub(crate) fn requires_action_review(tool_name: &str) -> bool {
    matches!(
        tool_role(tool_name),
        Some(Role::Batch | Role::Workbench | Role::Connections | Role::Unknown)
    )
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 120
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// The canonical harness an observed tool is scoped to.
fn observed_harness(harness: &str) -> Option<String> {
    let lowered = python_strip(harness).to_lowercase();
    if !token(&lowered) {
        return None;
    }
    guard_policy_snapshot::normalized_harness_selector(&lowered)
}

fn valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
}

fn valid_provider_selector(selector: &str) -> bool {
    let parts: Vec<&str> = selector.split(':').collect();
    if parts.len() != 5 || parts[2] != "composio" || parts[3] != "all-accounts" {
        return false;
    }
    if !valid_slug(parts[4]) || observed_harness(parts[0]).as_deref() != Some(parts[0]) {
        return false;
    }
    guard_policy_snapshot::mcp_tool_namespace(&format!("{}probe", parts[1])) == Some(parts[1])
}

fn bounded_text(value: &Value, limit: usize) -> Option<&str> {
    let text = value.as_str()?;
    (!text.is_empty() && python_strip(text) == text && text.chars().count() <= limit)
        .then_some(text)
}

/// Slugs of a complete supported batch; `None` for anything malformed.
fn batch_slugs(arguments: &Value) -> Option<Vec<&str>> {
    let tools = arguments.as_object()?.get("tools")?.as_array()?;
    if !(1..=50).contains(&tools.len()) {
        return None;
    }
    let mut slugs = Vec::with_capacity(tools.len());
    for tool in tools {
        let tool = tool.as_object()?;
        if tool
            .keys()
            .any(|key| !matches!(key.as_str(), "tool_slug" | "account" | "arguments"))
        {
            return None;
        }
        let slug = bounded_text(tool.get("tool_slug")?, 256)?;
        if let Some(account) = tool.get("account").filter(|value| !value.is_null()) {
            bounded_text(account, 256)?;
        }
        tool.get("arguments")?.as_object()?;
        slugs.push(slug);
    }
    Some(slugs)
}

/// Whether the operator's provider choices floor this call at `block`.
///
/// A `review` floor is implied by the wrapper review that always follows, so
/// only the blocking outcome is reported.
pub(crate) fn provider_floor_blocks(
    choices: &Map<String, Value>,
    harness: &str,
    tool_name: &str,
    arguments: &Value,
) -> bool {
    let Some(canonical_harness) = observed_harness(harness) else {
        return false;
    };
    if !tool_name.starts_with("mcp__") || tool_name.chars().count() > 160 {
        return false;
    }
    let Some(namespace) = guard_policy_snapshot::mcp_tool_namespace(tool_name) else {
        return false;
    };
    let role = tool_role(tool_name);
    if !matches!(role, Some(Role::Batch | Role::Workbench | Role::Unknown)) {
        return false;
    }
    let prefix = format!("{canonical_harness}:{namespace}:composio:all-accounts:");
    let scoped: Vec<(&str, &str)> = choices
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix) && valid_provider_selector(key))
        .filter_map(|(key, value)| {
            let state = value
                .as_str()
                .filter(|s| matches!(*s, "review" | "block"))?;
            Some((&key[prefix.len()..], state))
        })
        .collect();
    if role != Some(Role::Batch) {
        return scoped.iter().any(|(_, state)| *state == "block");
    }
    let denied: Vec<String> = scoped
        .iter()
        .filter(|(_, state)| *state == "block")
        .map(|(slug, _)| casefold(slug))
        .collect();
    let raw = arguments
        .as_object()
        .and_then(|object| object.get("tools"))
        .and_then(Value::as_array);
    if let Some(members) = raw.filter(|members| members.len() <= 50) {
        let hit = members.iter().any(|member| {
            member
                .as_object()
                .and_then(|member| member.get("tool_slug"))
                .and_then(Value::as_str)
                .is_some_and(|slug| denied.contains(&casefold(slug)))
        });
        if hit {
            return true;
        }
    }
    let opaque = match batch_slugs(arguments) {
        None => true,
        Some(slugs) => slugs.iter().any(|slug| !valid_slug(slug)),
    };
    opaque && !denied.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BATCH: &str = "mcp__codex_apps__composio__composio_multi_execute_tool";

    fn choices(entries: &[(&str, &str)]) -> Map<String, Value> {
        entries
            .iter()
            .map(|(slug, state)| {
                (
                    format!("codex:mcp__codex_apps__composio__:composio:all-accounts:{slug}"),
                    json!(state),
                )
            })
            .collect()
    }

    #[test]
    fn roles_follow_the_last_segment_with_full_casefold() {
        assert_eq!(tool_role(BATCH), Some(Role::Batch));
        assert_eq!(
            tool_role("mcp__a__COMPOSIO_SEARCH_TOOLS"),
            Some(Role::Discovery)
        );
        assert_eq!(tool_role("mcp__a__composio_new"), Some(Role::Unknown));
        assert_eq!(tool_role("mcp__a__read_note"), None);
        assert_eq!(
            tool_role("mcp__a__compo\u{17f}io_manage_connections"),
            Some(Role::Connections)
        );
        assert!(!requires_action_review("mcp__a__composio_get_tool_schemas"));
    }

    #[test]
    fn denied_member_blocks_even_when_case_or_shape_differs() {
        let arguments = json!({"tools": [{"tool_slug": "SLACK_SEND", "arguments": {}}]});
        let denied = choices(&[("slack_send", "block")]);
        assert!(provider_floor_blocks(&denied, "codex", BATCH, &arguments));
        let other = choices(&[("GMAIL_SEND", "block")]);
        assert!(!provider_floor_blocks(&other, "codex", BATCH, &arguments));
        let malformed = json!({"tools": "nope"});
        assert!(provider_floor_blocks(&other, "codex", BATCH, &malformed));
        assert!(!provider_floor_blocks(
            &Map::new(),
            "codex",
            BATCH,
            &malformed
        ));
        let review_only = choices(&[("SLACK_SEND", "review")]);
        assert!(!provider_floor_blocks(
            &review_only,
            "codex",
            BATCH,
            &arguments
        ));
    }

    #[test]
    fn invalid_selectors_never_count() {
        let mut bad = Map::new();
        bad.insert(
            "codex:mcp__codex_apps__composio__:composio:wrong:SLACK_SEND".into(),
            json!("block"),
        );
        bad.insert(
            "codex:mcp__codex_apps__composio__:composio:all-accounts:bad slug".into(),
            json!("block"),
        );
        let arguments = json!({"tools": [{"tool_slug": "SLACK_SEND", "arguments": {}}]});
        assert!(!provider_floor_blocks(&bad, "codex", BATCH, &arguments));
    }

    #[test]
    fn non_batch_wrapper_blocks_on_any_namespace_deny() {
        let denied = choices(&[("ANY", "block")]);
        let bench = "mcp__codex_apps__composio__composio_remote_workbench";
        assert!(provider_floor_blocks(&denied, "codex", bench, &json!({})));
        let search = "mcp__codex_apps__composio__composio_search_tools";
        assert!(!provider_floor_blocks(&denied, "codex", search, &json!({})));
    }
}
