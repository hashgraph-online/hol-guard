//! A `cd` into an agent's own notes directory, proved for read-only steps.
//!
//! An agent that keeps plans and memory notes under the user home often
//! enters that directory before reading a note: `cd ~/.codex/plans && sed -n
//! 1,40p plan.md`. The direct read of the same note is already allowed, but
//! the hidden home component kept the `cd` from being proved, so the two
//! spellings of one read did not answer alike. Every read after the `cd`
//! still clears its own operand proof, so `cat ../auth.json` or a recursive
//! search of the parent stays under review.
//!
//! Write, Git write and contained-run routes keep `verified_cwd_target` and
//! never reach this proof.

use std::path::{Component, Path, PathBuf};

/// The canonical directory of a `cd` operand naming an agent notes directory
/// or a visible directory below one, in the verified user home.
pub(crate) fn verified_note_directory_target(
    value: &str,
    context: super::super::PathContext<'_>,
) -> Option<String> {
    if cfg!(windows) || context.cwd.is_none() {
        return None;
    }
    let home = context.home_dir?;
    let spelled;
    let value = match super::home_variable::tilde_spelling(value) {
        Some(spelling) => {
            if !super::home_variable::home_expands_to_one_word(context.home_dir) {
                return None;
            }
            spelled = spelling;
            spelled.as_str()
        }
        None => value,
    };
    if !super::safe_directory_target(value) {
        return None;
    }
    // An unquoted leading `~` expands from the shell's HOME, so it is proved
    // only when that HOME is the declared one.
    let expanded;
    let value = if value.starts_with("~/") {
        if !context.shell_home_matches {
            return None;
        }
        expanded = super::super::read_paths::expand_home_read_path(value, Some(home))?;
        expanded.as_str()
    } else {
        value
    };
    let supplied = Path::new(value);
    if !supplied.is_absolute() {
        return None;
    }
    // No link anywhere in the spelling: the operand must already be the
    // canonical directory it names.
    let canonical = std::fs::canonicalize(supplied).ok()?;
    if canonical != supplied || !canonical.is_dir() {
        return None;
    }
    let home = std::fs::canonicalize(home).ok()?;
    if !note_directory(&canonical, &home) {
        return None;
    }
    canonical.to_str().map(str::to_owned)
}

/// `dir` is a notes root or a visible directory below one. A notes root is
/// one of the shared agent note roots or `~/.claude/projects/<project>/memory`,
/// and must resolve to itself.
fn note_directory(dir: &Path, home: &Path) -> bool {
    let rooted = |root: PathBuf, relative: &Path| {
        std::fs::canonicalize(&root).is_ok_and(|resolved| resolved == root) && visible(relative)
    };
    let shared = super::super::read_paths::AGENT_NOTE_ROOTS
        .iter()
        .any(|name| {
            let root = name
                .split('/')
                .fold(home.to_path_buf(), |path, part| path.join(part));
            dir.strip_prefix(&root)
                .is_ok_and(|relative| rooted(root.clone(), relative))
        });
    shared || project_memory(dir, home, rooted)
}

fn project_memory(dir: &Path, home: &Path, rooted: impl Fn(PathBuf, &Path) -> bool) -> bool {
    let projects = home.join(".claude").join("projects");
    let Ok(relative) = dir.strip_prefix(&projects) else {
        return false;
    };
    let mut parts = relative.components();
    let (Some(Component::Normal(project)), Some(Component::Normal(memory))) =
        (parts.next(), parts.next())
    else {
        return false;
    };
    !project.to_string_lossy().starts_with('.')
        && memory == "memory"
        && rooted(projects.join(project).join(memory), parts.as_path())
}

fn visible(relative: &Path) -> bool {
    relative.components().all(|component| {
        matches!(component, Component::Normal(part) if !part.to_string_lossy().starts_with('.'))
    })
}
