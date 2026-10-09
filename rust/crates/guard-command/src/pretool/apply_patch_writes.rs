//! Proof for routine Codex `apply_patch` edits.
//!
//! Codex sends the whole patch as `tool_input.command`. That text is an edit
//! description, not a shell command, so it gets its own bounded proof: every
//! header must name an added or updated file that the ordinary workspace write
//! proof accepts and that is not agent instruction or VCS metadata. Deletes,
//! moves, unknown headers and malformed or oversized patches stay unproven.

use std::path::{Component, Path};

const MAX_PATCH_BYTES: usize = 512 * 1024;
const MAX_PATCH_TARGETS: usize = 64;
const AGENT_INSTRUCTION_FILE_NAMES: &[&str] = &[
    "agents.md",
    "claude.md",
    "copilot-instructions.md",
    ".clinerules",
    ".cursorrules",
    ".windsurfrules",
];
const PROTECTED_DIRECTORIES: &[&str] = &[
    ".agents", ".claude", ".codex", ".cursor", ".bzr", ".git", ".hg", ".jj", ".pijul", ".svn",
    "_darcs",
];

/// Files an `apply_patch` body adds or updates, or `None` when the body is
/// not a well-formed patch limited to those two operations.
pub(super) fn apply_patch_targets(patch: &str) -> Option<Vec<String>> {
    if patch.len() > MAX_PATCH_BYTES || patch.contains('\0') {
        return None;
    }
    let lines: Vec<&str> = patch
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let first = lines.iter().position(|line| !line.trim().is_empty())?;
    let last = lines.iter().rposition(|line| !line.trim().is_empty())?;
    if lines[first].trim() != "*** Begin Patch"
        || lines[last].trim() != "*** End Patch"
        || first == last
    {
        return None;
    }
    let mut targets = Vec::new();
    for line in &lines[first + 1..last] {
        let Some(header) = line.strip_prefix("***") else {
            continue;
        };
        let header = header.trim_start();
        let path = if let Some(path) = header.strip_prefix("Update File:") {
            path
        } else if let Some(path) = header.strip_prefix("Add File:") {
            path
        } else if header.trim() == "End of File" {
            continue;
        } else {
            return None;
        };
        let path = path.trim();
        if path.is_empty() || targets.len() == MAX_PATCH_TARGETS {
            return None;
        }
        targets.push(path.to_owned());
    }
    (!targets.is_empty()).then_some(targets)
}

/// True only when every patch target is an ordinary workspace file write.
pub(super) fn routine_apply_patch(patch: &str, home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let Some(targets) = apply_patch_targets(patch) else {
        return false;
    };
    targets.iter().all(|target| {
        super::safe_writes::bounded_file_write_target(target, home_dir, cwd)
            && !protected_target(target, &workspace)
    })
}

fn protected_target(target: &str, workspace: &Path) -> bool {
    let supplied = Path::new(target);
    let joined = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        workspace.join(supplied)
    };
    let Some(canonical) = super::worktree_writes::canonical_write_target(&joined) else {
        return true;
    };
    // Inside the workspace only its own components count; a registered
    // sibling worktree is checked along its whole path, which fails closed.
    let scope = canonical.strip_prefix(workspace).unwrap_or(&canonical);
    let named = |path: &Path, names: &[&str]| {
        path.components().any(|component| match component {
            Component::Normal(part) => part
                .to_str()
                .is_none_or(|part| names.contains(&part.to_ascii_lowercase().as_str())),
            _ => false,
        })
    };
    let file_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase);
    file_name.is_none_or(|name| AGENT_INSTRUCTION_FILE_NAMES.contains(&name.as_str()))
        || named(scope, PROTECTED_DIRECTORIES)
}

#[cfg(test)]
#[path = "apply_patch_writes_tests.rs"]
mod tests;
