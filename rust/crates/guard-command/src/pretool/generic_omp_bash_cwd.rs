//! Oh My Pi's `bash` tool runs its command in the optional `cwd` argument.
//!
//! The host resolves that argument against the session directory, so a
//! command such as `cat config` with `cwd: "~/.ssh"` reads `~/.ssh/config`.
//! Evaluating the command against the session directory instead judged the
//! wrong files, and a Git command in a repository below the session
//! directory could not prove its configuration.

use serde_json::Value;
use std::path::{Component, Path, PathBuf};

const INPUT_KEYS: [&str; 3] = ["tool_input", "toolInput", "arguments"];

pub(super) enum BashCwd {
    /// No `cwd` argument, or one naming the session directory.
    Session,
    /// A directory the command is judged in directly: one below the session
    /// directory, spelled from it, or one inside a linked worktree of a
    /// repository there, canonicalized.
    Within(String),
    /// A directory outside the session directory, canonicalized.
    Outside(String),
    /// A plain path naming no existing directory, so nothing would run.
    Missing,
    /// A form the host resolves in a way Guard does not model.
    Unresolved,
}

pub(super) fn resolve(payload: &Value, home_dir: Option<&str>, session: Option<&str>) -> BashCwd {
    let mut values = INPUT_KEYS
        .iter()
        .filter_map(|key| payload.get(*key)?.as_object()?.get("cwd"));
    let Some(first) = values.next() else {
        return BashCwd::Session;
    };
    if values.any(|value| value != first) {
        return BashCwd::Unresolved;
    }
    let Some(text) = first.as_str() else {
        return BashCwd::Unresolved;
    };
    // The host treats an empty value as absent and a root of only slashes
    // as the session directory.
    if text.is_empty() || text.bytes().all(|byte| byte == b'/') {
        return BashCwd::Session;
    }
    let Some(session) = session.filter(|session| Path::new(session).is_absolute()) else {
        return BashCwd::Unresolved;
    };
    let Some(target) = literal_target(text, home_dir, session) else {
        return BashCwd::Unresolved;
    };
    let Ok(root) = Path::new(session).canonicalize() else {
        return BashCwd::Unresolved;
    };
    let target = match target.canonicalize() {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BashCwd::Missing,
        Err(_) => return BashCwd::Unresolved,
    };
    if !target.is_dir() {
        return BashCwd::Unresolved;
    }
    match target.strip_prefix(&root) {
        Ok(suffix) if suffix.as_os_str().is_empty() => BashCwd::Session,
        Ok(suffix) => match suffix.to_str() {
            Some(suffix) => BashCwd::Within(format!("{}/{suffix}", session.trim_end_matches('/'))),
            None => BashCwd::Unresolved,
        },
        Err(_) => match target.to_str() {
            Some(text) if session_worktree(&target, &root) => BashCwd::Within(text.to_owned()),
            Some(text) if !text.contains('\'') => BashCwd::Outside(text.to_owned()),
            _ => BashCwd::Unresolved,
        },
    }
}

/// The directory a plain path names. The host also rewrites `@`, `:` and
/// `file:` prefixes, Unicode spaces and internal URLs before resolving, so
/// those forms stay unresolved rather than guessed.
fn literal_target(text: &str, home_dir: Option<&str>, session: &str) -> Option<PathBuf> {
    if !text.is_ascii()
        || text
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || text.starts_with(['@', ':'])
        || text.starts_with("file:")
        || text.contains("://")
    {
        return None;
    }
    let path = if text == "~" || text.starts_with("~/") {
        let home = home_dir.filter(|home| Path::new(home).is_absolute())?;
        Path::new(home).join(text.trim_start_matches('~').trim_start_matches('/'))
    } else if text.starts_with('~') {
        return None;
    } else {
        Path::new(session).join(text)
    };
    path.components()
        .all(|component| !matches!(component, Component::Prefix(_)))
        .then_some(path)
}

/// Whether `target` sits inside a linked worktree of a repository at or below
/// the session directory. Guard already treats such a checkout like the
/// workspace for writes, and the host runs the whole command there, so it is
/// judged there directly. A leading `cd` would instead require every segment
/// after a `;` or `||` to be proven from the session directory as well, as if
/// the `cd` could fail.
fn session_worktree(target: &Path, root: &Path) -> bool {
    let Some(worktree) = target
        .ancestors()
        .find(|directory| directory.join(".git").symlink_metadata().is_ok())
    else {
        return false;
    };
    let Some(repository) = registered_repository(worktree) else {
        return false;
    };
    repository.starts_with(root)
        && guard_secure_fs::hidden_read_parts_allowed(target)
        && super::super::git_routes::linked_worktree_admin(worktree, &repository).is_some()
}

/// The primary checkout a worktree's `.git` file names through
/// `<repository>/.git/worktrees/<name>`. `linked_worktree_admin` then checks
/// the registry's `commondir` and `gitdir` backlinks.
fn registered_repository(worktree: &Path) -> Option<PathBuf> {
    use std::io::Read;
    let mut contents = String::new();
    std::fs::File::open(worktree.join(".git"))
        .ok()?
        .take(4097)
        .read_to_string(&mut contents)
        .ok()?;
    if contents.len() > 4096 {
        return None;
    }
    let pointer = contents.lines().next()?.strip_prefix("gitdir: ")?.trim();
    let admin = worktree.join(pointer).canonicalize().ok()?;
    let registry = admin.parent()?;
    let common = registry.parent()?;
    (registry.file_name()? == "worktrees" && common.file_name()? == ".git")
        .then(|| common.parent().map(Path::to_path_buf))
        .flatten()
}
