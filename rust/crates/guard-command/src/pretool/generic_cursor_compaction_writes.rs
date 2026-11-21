//! When a Cursor conversation compacts, the agent files the summary as
//! Markdown notes beside that conversation's transcript:
//! `~/.cursor/projects/<workspace slug>/agent-transcripts/<conversation>/compaction/`
//! holds an `INDEX.md` and numbered `segment_NNN.md` files, and Cursor reads
//! them back into the same conversation. The directory sits inside Cursor's
//! home, so every one of those writes was held as a harness-state change, and
//! because each segment has a new name a saved approval never covered the
//! next one.
//!
//! This proof admits a Cursor `Write` of one of those two names, and only for
//! the project directory named after the session's own workspace and the
//! conversation that asks. The compaction directory must already be a real
//! folder at its canonical path, and an existing note must be a regular file
//! with one link and no execute bit. The transcript itself, every other name
//! in the directory, another conversation's notes, and the same write from
//! any other harness keep the ordinary review path.
//!
//! Cursor also spills tool output too large to return inline to
//! `~/.cursor/projects/<workspace slug>/agent-tools/<uuid>.txt`, and its
//! subagents file that output with the same `Write` tool. A write of one of
//! those names is admitted for the session's own project directory under the
//! same folder and file checks. Any other name in `agent-tools`, and another
//! workspace's folder, keep the review. Cursor's read-back of these files is
//! admitted by `generic_cursor_project_reads.rs`.

use super::cursor_project_reads::{canonical, conversation_id, workspace_slugs};
use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

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
        || signals.tool_name.as_deref() != Some("Write")
        || signals.sensitive_target
        || signals.command.is_some()
        || !signals.url_values.is_empty()
        || signals.path_values.len() != 1
    {
        return None;
    }
    let declared_home = Path::new(home_dir?);
    let home = canonical(declared_home)?;
    let target = note_target(&signals.path_values[0], declared_home, &home)?;
    let relative = target.strip_prefix(home.join(".cursor")).ok()?;
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let own_slug = |slug: &str| workspace_slugs(cwd).iter().any(|own| own == slug);
    let reason = match parts.as_slice() {
        ["projects", slug, "agent-transcripts", id, "compaction", leaf]
            if own_slug(slug)
                && conversation_id(payload) == Some(*id)
                && compaction_note_name(leaf) =>
        {
            "The Rust authority proved this write is a compaction note for the current Cursor conversation, beside its own transcript, which only that conversation reads back."
        }
        ["projects", slug, "agent-tools", leaf] if own_slug(slug) && spilled_output_name(leaf) => {
            "The Rust authority proved this write is Cursor's spilled tool output for the current workspace: a plain text file in its own agent-tools folder that the session reads back."
        }
        _ => return None,
    };
    let action = generic_action(
        harness,
        event,
        PreToolActionTypeV1::FileWrite,
        PreToolOperationV1::Write,
        true,
        false,
    );
    Some(generic_result(
        action,
        "allow",
        "native_exact_safe_file_write",
        reason,
    ))
}

/// `INDEX.md` or `segment_<digits>.md`, the two names Cursor gives the notes.
pub(super) fn compaction_note_name(leaf: &str) -> bool {
    leaf == "INDEX.md"
        || leaf
            .strip_prefix("segment_")
            .and_then(|rest| rest.strip_suffix(".md"))
            .is_some_and(|number| {
                (1..=6).contains(&number.len()) && number.bytes().all(|byte| byte.is_ascii_digit())
            })
}

/// `<uuid>.txt`, the name Cursor gives spilled tool output: five groups of
/// 8, 4, 4, 4 and 12 hex digits joined by dashes.
pub(super) fn spilled_output_name(leaf: &str) -> bool {
    let Some(id) = leaf.strip_suffix(".txt") else {
        return false;
    };
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// The note `value` names when its spelling is already canonical: an absolute
/// (or `~`) path with no `.`/`..` component and no link, whose folder exists as
/// a real directory and whose leaf is missing or a plain single-link file that
/// nothing would run. A home that is itself a link is read through its
/// resolved location, so only links inside it disqualify the write.
fn note_target(value: &str, declared_home: &Path, home: &Path) -> Option<PathBuf> {
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
    let folder = spelled.parent()?;
    if canonical(folder).as_deref() != Some(folder)
        || !std::fs::symlink_metadata(folder).is_ok_and(|metadata| metadata.is_dir())
    {
        return None;
    }
    match std::fs::symlink_metadata(&spelled) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(spelled),
        Err(_) => None,
        Ok(metadata) => plain_note(&metadata).then_some(spelled),
    }
}

#[cfg(unix)]
fn plain_note(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    metadata.is_file() && metadata.nlink() == 1 && metadata.permissions().mode() & 0o111 == 0
}

/// The link count is not available on stable Windows, so a note that already
/// exists keeps its review there; a new segment name is still admitted.
#[cfg(not(unix))]
fn plain_note(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{compaction_note_name, spilled_output_name};

    #[test]
    fn only_uuid_text_files_are_spilled_output() {
        for leaf in [
            "ebfc6863-95b8-4564-92fa-1902ecf9eca3.txt",
            "0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D.txt",
        ] {
            assert!(spilled_output_name(leaf), "{leaf}");
        }
        for leaf in [
            "ebfc6863-95b8-4564-92fa-1902ecf9eca3",
            "ebfc6863-95b8-4564-92fa-1902ecf9eca3.sh",
            "ebfc6863-95b8-4564-92fa-1902ecf9eca3.txt.sh",
            "ebfc6863-95b8-4564-92fa-1902ecf9eca.txt",
            "ebfc6863-95b8-4564-92fa-1902ecf9eca3-0.txt",
            "ebfc686395b8456492fa1902ecf9eca3.txt",
            "gbfc6863-95b8-4564-92fa-1902ecf9eca3.txt",
            ".ebfc6863-95b8-4564-92fa-1902ecf9eca3.txt",
            "notes.txt",
            "AGENTS.md",
        ] {
            assert!(!spilled_output_name(leaf), "{leaf}");
        }
    }

    #[test]
    fn only_the_index_and_numbered_segments_are_notes() {
        for leaf in ["INDEX.md", "segment_000.md", "segment_12.md"] {
            assert!(compaction_note_name(leaf), "{leaf}");
        }
        for leaf in [
            "index.md",
            "segment_.md",
            "segment_1234567.md",
            "segment_00a.md",
            "segment_001.md.sh",
            "segment_001.txt",
            "AGENTS.md",
            ".INDEX.md",
            "notes.md",
        ] {
            assert!(!compaction_note_name(leaf), "{leaf}");
        }
    }
}
