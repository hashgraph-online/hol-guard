//! Identity and command-id rules for this-device MCP grants.
//!
//! These mirror `observed_mcp_tools.py`, `runtime/local_cli_commands.py`,
//! `runtime/composio_contract.py`, and the stored-launch parsing in
//! `store_local_mcp.py`, so grants stored by earlier builds keep matching.

use guard_policy_snapshot::{digest_bytes, normalized_harness_selector};
use serde_json::Map;

pub(crate) const OTHER_COMMAND_ID: &str = "other";
const ROOT_COMMAND_ID: &str = "root";
const OBSERVED_MCP_PREFIX: &str = "observed-mcp:";
const MAX_COMMAND_DEPTH: usize = 4;

/// A connector observed by tool name on one harness, with no launch command.
pub(crate) struct ObservedMcpTool {
    pub(crate) identity_hash: String,
    pub(crate) command_id: String,
}

/// `observed_mcp_tool`: parse a fully qualified MCP name and keep the
/// connector boundary.
pub(crate) fn observed_mcp_tool(harness: &str, tool_name: &str) -> Option<ObservedMcpTool> {
    let harness = harness.trim().to_lowercase();
    if !is_token(&harness) || !tool_name.starts_with("mcp__") || tool_name.chars().count() > 160 {
        return None;
    }
    let harness = normalized_harness_selector(&harness)?;
    let parts: Vec<&str> = tool_name[5..].split("__").collect();
    if parts.len() < 2 || parts.iter().any(|part| !is_token(part)) {
        return None;
    }
    let split = if parts[0] == "codex_apps" && parts.len() >= 3 {
        2
    } else {
        1
    };
    if parts[split..].join("__").chars().count() > 120 {
        return None;
    }
    let namespace = format!("mcp__{}__", parts[..split].join("__"));
    if namespace.chars().count() > 155 {
        return None;
    }
    let identity = guard_command::mcp_decision::build_mcp_server_identity(
        "",
        &format!("{OBSERVED_MCP_PREFIX}{harness}:{namespace}"),
        &[],
        "observed",
        None::<&Map<String, serde_json::Value>>,
        &[],
    );
    Some(ObservedMcpTool {
        identity_hash: identity.identity_hash,
        // Names that slug to the same text keep separate permissions.
        command_id: format!("tool-{}", &digest_bytes(tool_name.as_bytes())[..24]),
    })
}

fn is_token(value: &str) -> bool {
    (1..=120).contains(&value.chars().count())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// `is_local_cli_command_id`.
fn is_command_id(value: &str) -> bool {
    if value == ROOT_COMMAND_ID || value == OTHER_COMMAND_ID {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    (1..=MAX_COMMAND_DEPTH).contains(&parts.len())
        && parts.iter().all(|part| {
            let bytes = part.as_bytes();
            (1..=41).contains(&bytes.len())
                && bytes[0].is_ascii_alphabetic()
                && bytes[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
        })
}

/// `slug_local_cli_command_id`: turn an MCP tool name into a catalog command id.
pub(crate) fn slug_command_id(name: &str) -> String {
    let stripped = name.trim();
    if stripped != ROOT_COMMAND_ID && stripped != OTHER_COMMAND_ID && is_command_id(stripped) {
        return stripped.to_owned();
    }
    let spaced: String = stripped
        .chars()
        .flat_map(|ch| {
            if ch.is_alphanumeric() {
                ch.to_lowercase().collect::<Vec<_>>()
            } else {
                vec!['-']
            }
        })
        .collect();
    let compact = spaced
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let digest = &digest_bytes(stripped.as_bytes())[..8];
    let base: String = if compact.is_empty() {
        "tool".to_owned()
    } else {
        compact.chars().take(31).collect()
    };
    let candidate = format!("{base}-{digest}");
    if is_command_id(&candidate) {
        candidate
    } else {
        OTHER_COMMAND_ID.to_owned()
    }
}

/// `composio_requires_action_review`: wrapper tools that execute other actions.
pub(crate) fn composio_requires_action_review(tool_name: &str) -> bool {
    // Python's `str.casefold()` is full Unicode case folding (`ſ` -> `s`,
    // `ß` -> `ss`); `to_lowercase()` leaves those unchanged and would let a
    // fold-equivalent spelling of a meta-tool inherit a remembered approval.
    let name = caseless::default_case_fold_str(tool_name.rsplit("__").next().unwrap_or(""));
    match name.as_str() {
        "composio_search_tools" | "composio_get_tool_schemas" => false,
        "composio_multi_execute_tool"
        | "composio_remote_workbench"
        | "composio_remote_bash_tool"
        | "composio_manage_connections" => true,
        _ => name.starts_with("composio_"),
    }
}

/// Lowercased sha256 hex, or `None`.
pub(crate) fn normalized_hash(value: Option<&str>) -> Option<String> {
    let value = value?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// `shlex.split` (POSIX): `None` for an unclosed quote or dangling escape.
pub(crate) fn shlex_split(input: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' | '\r' | '\n' => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            '\'' => {
                in_token = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        inner => current.push(inner),
                    }
                }
            }
            '"' => {
                in_token = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => {
                            let escaped = chars.next()?;
                            if escaped != '"' && escaped != '\\' {
                                current.push('\\');
                            }
                            current.push(escaped);
                        }
                        inner => current.push(inner),
                    }
                }
            }
            '\\' => {
                in_token = true;
                current.push(chars.next()?);
            }
            other => {
                in_token = true;
                current.push(other);
            }
        }
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

#[cfg(test)]
mod composio_fold_tests {
    use super::composio_requires_action_review;

    #[test]
    fn fold_equivalent_meta_tool_names_still_require_review() {
        assert!(composio_requires_action_review(
            "srv__compo\u{17f}io_multi_execute_tool"
        ));
        assert!(composio_requires_action_review(
            "srv__COMPOSIO_MULTI_EXECUTE_TOOL"
        ));
        assert!(!composio_requires_action_review(
            "srv__composio_search_tools"
        ));
        assert!(!composio_requires_action_review("srv__other_tool"));
    }
}
