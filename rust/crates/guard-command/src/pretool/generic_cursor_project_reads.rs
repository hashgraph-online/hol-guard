//! Cursor keeps per-workspace working files under
//! `~/.cursor/projects/<workspace slug>/`: the output of the shells it runs in
//! the background, tool output too large to return inline, the descriptions of
//! the MCP servers it has connected, and its own conversation transcripts. The
//! agent reads these back as part of ordinary work, and a review there stalls
//! the session on a file Cursor itself just wrote.
//!
//! This proof admits a Cursor `Read` of one of those leaves, and only for the
//! project directory named after the session's own workspace. A transcript is
//! admitted only for the conversation that asks. Credential-shaped names,
//! links, hidden components and every other file in the project directory
//! (its MCP auth store among them) keep the ordinary review path, as do reads
//! of the same files from any other harness.

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn evaluate(
    harness: &str,
    event: &str,
    payload: &Value,
    signals: &GenericSignals,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<PreToolResultV1> {
    if harness != "cursor"
        || event != "PreToolUse"
        || !matches!(signals.tool_name.as_deref(), Some("Read" | "read"))
        || signals.sensitive_target
        || signals.command.is_some()
        || !signals.url_values.is_empty()
        || signals.path_values.len() != 1
    {
        return None;
    }
    let declared_home = Path::new(home_dir?);
    let home = canonical(declared_home)?;
    let target = exact_target(&signals.path_values[0], declared_home, &home)?;
    let cursor = home.join(".cursor");
    let relative = target.strip_prefix(&cursor).ok()?;
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let admitted = match parts.as_slice() {
        ["projects", slug, rest @ ..] => {
            workspace_slugs(cwd).iter().any(|own| own == *slug)
                && project_leaf(rest, conversation_id(payload))
        }
        ["skills-cursor", skill, rest @ ..] => {
            !rest.is_empty()
                && visible(skill)
                && rest.iter().all(|part| visible(part))
                && rest.last().is_some_and(|leaf| leaf.ends_with(".md"))
        }
        _ => false,
    };
    if !admitted {
        return None;
    }
    let action = generic_action(
        harness,
        event,
        PreToolActionTypeV1::FileRead,
        PreToolOperationV1::Read,
        true,
        false,
    );
    Some(generic_result(
        action,
        "allow",
        "native_cursor_project_state_read",
        "Cursor wrote this file for the current workspace (shell or tool output, an MCP tool description, or this conversation's transcript), so reading it back reveals nothing new.",
    ))
}

/// The file `value` names when the name is already its own canonical path: an
/// absolute (or `~`) spelling with no `.`/`..` component and no link anywhere
/// below the home directory, holding a bounded regular file with no
/// credential-shaped name. A home that is itself a link is read through its
/// resolved location, so only links inside it disqualify the read.
fn exact_target(value: &str, declared_home: &Path, home: &Path) -> Option<PathBuf> {
    let mut spelled = match super::super::read_paths::expand_home_read_path(value, home.to_str()) {
        Some(expanded) => PathBuf::from(expanded),
        None => PathBuf::from(value),
    };
    if let Ok(rest) = spelled.strip_prefix(declared_home) {
        spelled = home.join(rest);
    }
    if !spelled.is_absolute()
        || spelled
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || guard_secure_fs::contains_symlink_component(&spelled)
        || guard_secure_fs::sensitive_path_family(&spelled).is_some()
        || guard_secure_fs::credential_named_path(&spelled)
    {
        return None;
    }
    let resolved = canonical(&spelled)?;
    if resolved != spelled {
        return None;
    }
    let metadata = std::fs::symlink_metadata(&resolved).ok()?;
    (metadata.is_file() && metadata.len() <= MAX_READ_BYTES).then_some(resolved)
}

pub(super) fn canonical(path: &Path) -> Option<PathBuf> {
    crate::runtime_read_paths::canonicalize_text(path).ok()
}

/// The leaves Cursor writes below one project directory.
fn project_leaf(rest: &[&str], conversation: Option<&str>) -> bool {
    if !rest.iter().all(|part| visible(part)) {
        return false;
    }
    match rest {
        ["terminals" | "agent-tools", leaf] => leaf.ends_with(".txt"),
        ["mcps", _server, leaf] => leaf.ends_with(".md") || leaf.ends_with(".json"),
        ["mcps", _server, "tools", leaf] => leaf.ends_with(".json"),
        ["agent-transcripts", id, inner @ ..] => {
            conversation.is_some_and(|own| own == *id)
                && inner.last().is_some_and(|leaf| {
                    [".md", ".txt", ".json", ".jsonl"]
                        .iter()
                        .any(|extension| leaf.ends_with(extension))
                })
        }
        _ => false,
    }
}

/// The conversation the hook payload belongs to, when every spelling of the
/// field present names the same plausible id.
pub(super) fn conversation_id(payload: &Value) -> Option<&str> {
    let mut found: Option<&str> = None;
    for key in ["conversation_id", "conversationId"] {
        let Some(value) = payload.get(key) else {
            continue;
        };
        let id = value.as_str()?.trim();
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || found.is_some_and(|earlier| earlier != id)
        {
            return None;
        }
        found = Some(id);
    }
    found
}

/// The project directory names Cursor gives the session workspace: its path
/// with the leading separator dropped and every other non-alphanumeric
/// character spelled `-`. Cursor names the directory after the path it was
/// opened with, so both that spelling and the canonical one are accepted.
pub(super) fn workspace_slugs(cwd: Option<&str>) -> Vec<String> {
    let Some(cwd) = cwd.map(str::trim).filter(|cwd| !cwd.is_empty()) else {
        return Vec::new();
    };
    let mut spellings = vec![PathBuf::from(cwd)];
    if let Some(resolved) = canonical(Path::new(cwd)) {
        spellings.push(resolved);
    }
    spellings
        .iter()
        .filter(|path| path.is_absolute())
        .map(|path| slug(&path.to_string_lossy()))
        .filter(|slug| !slug.is_empty())
        .collect()
}

fn slug(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_start_matches('-')
        .to_owned()
}

fn visible(part: &str) -> bool {
    !part.is_empty() && !part.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::{project_leaf, slug};

    #[test]
    fn slug_matches_cursor_project_directory_names() {
        assert_eq!(
            slug("/Users/dev/work/app-portal"),
            "Users-dev-work-app-portal"
        );
        assert_eq!(slug("/srv/app.v2/web_ui"), "srv-app-v2-web-ui");
    }

    #[test]
    fn transcripts_need_the_payload_conversation() {
        let rest = ["agent-transcripts", "abc-123", "compaction", "INDEX.md"];
        assert!(project_leaf(&rest, Some("abc-123")));
        assert!(!project_leaf(&rest, Some("other-456")));
        assert!(!project_leaf(&rest, None));
    }

    #[test]
    fn only_cursor_written_leaves_are_admitted() {
        assert!(project_leaf(&["terminals", "120467.txt"], None));
        assert!(project_leaf(
            &["mcps", "server", "tools", "query.json"],
            None
        ));
        assert!(project_leaf(&["mcps", "server", "INSTRUCTIONS.md"], None));
        assert!(!project_leaf(&["mcp-auth.json"], None));
        assert!(!project_leaf(&["worker.log"], None));
        assert!(!project_leaf(&["terminals", ".hidden.txt"], None));
        assert!(!project_leaf(&["terminals", "nested", "1.txt"], None));
    }
}
