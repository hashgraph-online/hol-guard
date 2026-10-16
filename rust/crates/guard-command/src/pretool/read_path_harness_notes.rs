//! Markdown notes in the Codex and Claude Code home directories, such as
//! `~/.claude/projects/<p>/memory/note.md`, `~/.claude/CLAUDE.md` or
//! `~/.codex/plans/todo.md`. Logins and secret-bearing config there
//! (`auth.json`, `.credentials.json`, `config.toml`, `settings.json`) are not
//! Markdown, and the caller has already refused credential names and
//! sensitive families, so they stay guarded. Session transcripts and logs
//! can echo tool output, secrets included, so their trees stay guarded too.

use std::path::{Component, Path};

/// The harness homes below the user's home directory.
pub(in crate::pretool) const HARNESS_HOMES: [&str; 2] = [".claude", ".codex"];

/// Top-level harness entries that hold transcripts, logs or shell snapshots.
const TRANSCRIPT_TREES: [&str; 6] = [
    "archived_sessions",
    "log",
    "logs",
    "sessions",
    "shell-snapshots",
    "transcripts",
];

/// A `.md` file below `~/.claude` or `~/.codex`, outside the transcript
/// trees, whose every component below that root is visible. The root must
/// resolve to itself, so a link cannot dress another directory as a harness
/// home.
pub(in crate::pretool) fn harness_home_document(canonical: &Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    HARNESS_HOMES.iter().any(|name| {
        let root = home.join(name);
        std::fs::canonicalize(&root).is_ok_and(|resolved| resolved == root)
            && canonical.strip_prefix(&root).is_ok_and(|relative| {
                relative.components().next().is_some_and(|first| {
                    first
                        .as_os_str()
                        .to_str()
                        .is_some_and(|name| !TRANSCRIPT_TREES.contains(&name))
                }) && relative.components().all(|component| {
                    matches!(component, Component::Normal(part)
                            if !part.to_string_lossy().starts_with('.'))
                })
            })
    })
}
