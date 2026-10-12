//! Proof for routine Codex `apply_patch` edits.
//!
//! Codex sends the whole patch as `tool_input.command`. That text is an edit
//! description, not a shell command, so it gets its own bounded proof: every
//! header must name an added or updated file that the ordinary workspace write
//! proof accepts and that is not agent instruction or VCS metadata. Deletes,
//! moves, environment selectors, unknown lines and malformed or oversized
//! patches stay unproven.
//!
//! The parser mirrors the grammar of Codex's own streaming `apply_patch`
//! parser, including where it trims lines before matching hunk headers, so
//! every header Codex would act on is a header here too. Any line Codex
//! would not accept as hunk content ends the proof instead of being skipped.

use std::path::{Component, Path};

const MAX_PATCH_TARGETS: usize = 64;
const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ADD_FILE: &str = "*** Add File: ";
const UPDATE_FILE: &str = "*** Update File: ";
const END_OF_FILE: &str = "*** End of File";
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Started,
    AddFile,
    UpdateFile,
    Ended,
}

enum Header<'a> {
    Add(&'a str),
    Update(&'a str),
    End,
    // Deletes and remote environment selectors are never proven.
    Unprovable,
    Content,
}

fn header(line: &str) -> Header<'_> {
    if line == END_PATCH {
        Header::End
    } else if let Some(path) = line.strip_prefix(ADD_FILE) {
        Header::Add(path)
    } else if let Some(path) = line.strip_prefix(UPDATE_FILE) {
        Header::Update(path)
    } else if line.starts_with("*** Delete File: ") || line.starts_with("*** Environment ID:") {
        Header::Unprovable
    } else {
        Header::Content
    }
}

/// Files an `apply_patch` body adds or updates, or `None` when the body is
/// not a well-formed patch limited to those two operations.
pub(super) fn apply_patch_targets(patch: &str) -> Option<Vec<String>> {
    // The generic extractor already rejects longer strings; keep the same cap.
    if patch.len() > crate::MAX_COMMAND_BYTES || patch.contains('\0') {
        return None;
    }
    let mut lines = patch.trim().lines();
    if lines.next()?.trim() != BEGIN_PATCH {
        return None;
    }
    let mut mode = Mode::Started;
    let mut targets = Vec::new();
    for line in lines {
        if mode == Mode::Ended {
            if line.trim().is_empty() {
                continue;
            }
            return None;
        }
        // Codex matches headers on the trimmed line, except inside an update
        // hunk where only trailing space is removed.
        let candidate = if mode == Mode::UpdateFile {
            line.trim_end()
        } else {
            line.trim()
        };
        let (path, next) = match header(candidate) {
            Header::End => {
                mode = Mode::Ended;
                continue;
            }
            Header::Add(path) => (path, Mode::AddFile),
            Header::Update(path) => (path, Mode::UpdateFile),
            Header::Unprovable => return None,
            Header::Content => {
                let content = match mode {
                    Mode::AddFile => line.starts_with('+'),
                    Mode::UpdateFile => {
                        candidate == "@@"
                            || candidate.starts_with("@@ ")
                            || candidate == END_OF_FILE
                            || line.is_empty()
                            || line.starts_with([' ', '+', '-'])
                    }
                    Mode::Started | Mode::Ended => false,
                };
                if !content {
                    return None;
                }
                continue;
            }
        };
        if path.trim().is_empty() || targets.len() == MAX_PATCH_TARGETS {
            return None;
        }
        targets.push(path.to_owned());
        mode = next;
    }
    (mode == Mode::Ended && !targets.is_empty()).then_some(targets)
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
            && !protected_target(target, &workspace, cwd)
    })
}

fn protected_target(target: &str, workspace: &Path, cwd: Option<&str>) -> bool {
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
    // The name the patch uses counts as much as the file it resolves to, so a
    // link such as `AGENTS.md -> docs/rules.md` still names agent instructions.
    let spelled = cwd
        .and_then(|root| supplied.strip_prefix(root).ok())
        .or_else(|| supplied.strip_prefix(workspace).ok())
        .unwrap_or(supplied);
    protected_name(scope) || protected_name(spelled)
}

fn protected_name(path: &Path) -> bool {
    let instruction_file = match path.file_name() {
        Some(name) => name.to_str().is_none_or(|name| {
            AGENT_INSTRUCTION_FILE_NAMES.contains(&name.to_ascii_lowercase().as_str())
        }),
        None => true,
    };
    instruction_file
        || path.components().any(|component| match component {
            Component::Normal(part) => part.to_str().is_none_or(|part| {
                PROTECTED_DIRECTORIES.contains(&part.to_ascii_lowercase().as_str())
            }),
            _ => false,
        })
}

#[cfg(test)]
#[path = "apply_patch_writes_tests.rs"]
mod tests;
