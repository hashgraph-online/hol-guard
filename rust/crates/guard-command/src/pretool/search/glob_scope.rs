//! Where a glob read operand starts expanding, and what its matches may be.
//!
//! A relative glob expands below the cwd. An absolute, `~/` or `../` glob
//! expands below its literal prefix when that prefix is a directory inside a
//! git working tree below home, the layout `git -C` and `rg` sibling routes
//! accept. The prefix may pass through a hidden project-metadata directory
//! such as `.github`, never through `.git`, a dot directory holding secrets or
//! a `..` after its first named component.
//!
//! A prefix that is not inside a repository qualifies only when it is the
//! directory holding the current repository and its siblings (or the cwd
//! itself), as in `ls ~/code/org/*/README.md`. Every match must then lie in a
//! sibling repository: the component the first wildcard expands to must be a
//! git working tree below home.
//!
//! Any of these wider forms is expanded strictly (see `GlobBase::strict`).
use super::super::{hidden_allowed, home_relative, real_allowed_directory, ReadContext};
use std::path::{Component, Path, PathBuf};

const GLOB_CHARACTERS: [char; 3] = ['*', '?', '['];

pub(super) struct GlobBase<'a> {
    pub(super) base: PathBuf,
    /// Credential names and links are judged below this directory.
    pub(super) root: PathBuf,
    pub(super) pattern: &'a str,
    /// Expand as a superset of every shell's matches: only `*` and `?`,
    /// ignoring case, ASCII names only, and a hidden entry a wildcard could
    /// match under `dotglob` sends the operand to review.
    pub(super) strict: bool,
    /// Matches must lie in a sibling repository directly below `root`.
    pub(super) siblings: bool,
}

pub(super) fn glob_base<'a>(value: &'a str, context: ReadContext<'_>) -> Option<GlobBase<'a>> {
    let hidden = value
        .split('/')
        .any(|part| part.starts_with('.') && part != "." && part != "..");
    if value.starts_with(['/', '~']) || value.starts_with("../") {
        let (prefix, pattern) = split_prefix(value)?;
        let mut base = repository_base(prefix, pattern, context)
            .or_else(|| sibling_parent_base(prefix, pattern, context))?;
        base.strict |= hidden || value.starts_with("../");
        return Some(base);
    }
    let cwd = home_relative(context.cwd?, context.home_dir)?;
    Some(GlobBase {
        base: real_allowed_directory(&cwd, context)?,
        root: cwd,
        pattern: value,
        strict: hidden,
        siblings: false,
    })
}

/// Literal prefix and pattern. Leading `..` steps are the only parent steps;
/// every named component is visible or a benign project-metadata directory.
fn split_prefix(value: &str) -> Option<(&str, &str)> {
    if value.starts_with('~') && !value.starts_with("~/") {
        return None;
    }
    let first_pattern = value.find(GLOB_CHARACTERS)?;
    let prefix_end = value[..first_pattern].rfind('/')?;
    let (prefix, pattern) = (&value[..prefix_end], &value[prefix_end + 1..]);
    // `/*` leaves an empty prefix, which would otherwise resolve to the cwd.
    if prefix.is_empty() {
        return None;
    }
    let mut parts = prefix.split('/').peekable();
    if prefix.starts_with(['/', '~']) {
        parts.next();
    } else {
        while parts.next_if_eq(&"..").is_some() {}
    }
    parts
        .all(|part| {
            !part.is_empty()
                && part != ".."
                && part != "."
                && (!part.starts_with('.') || hidden_allowed(part))
        })
        .then_some((prefix, pattern))
}

/// The real directory a prefix names; a `..` spelling is resolved physically,
/// as the kernel resolves it for the reader.
fn prefix_directory(prefix: &str, context: ReadContext<'_>) -> Option<(PathBuf, PathBuf)> {
    let base = real_allowed_directory(&super::super::expanded_operand(prefix, context)?, context)?;
    let canonical = std::fs::canonicalize(&base).ok()?;
    let base = if prefix.starts_with('.') {
        canonical.clone()
    } else {
        base
    };
    Some((base, canonical))
}

fn repository_base<'a>(
    prefix: &str,
    pattern: &'a str,
    context: ReadContext<'_>,
) -> Option<GlobBase<'a>> {
    let (base, canonical) = prefix_directory(prefix, context)?;
    let root = base
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())?
        .to_path_buf();
    let repository = std::fs::canonicalize(&root).ok()?;
    let below = canonical.strip_prefix(&repository).ok()?;
    let metadata_only = below.components().all(|part| {
        matches!(part, Component::Normal(name)
            if name.to_str().is_some_and(|name| !name.starts_with('.') || hidden_allowed(name)))
    });
    (metadata_only
        && crate::pretool::git_routes::repository_below_home(&repository, context)
        && !super::super::inside_agent_state(&base, context))
    .then_some(GlobBase {
        base,
        root,
        pattern,
        strict: false,
        siblings: false,
    })
}

/// The visible directory below home that holds the current repository and
/// its siblings, or the cwd itself, and is not inside a repository.
fn sibling_parent_base<'a>(
    prefix: &str,
    pattern: &'a str,
    context: ReadContext<'_>,
) -> Option<GlobBase<'a>> {
    let (_, parent) = prefix_directory(prefix, context)?;
    let home = std::fs::canonicalize(context.home_dir?).ok()?;
    let below_home = parent.strip_prefix(&home).ok()?;
    let visible = below_home.components().all(
        |part| matches!(part, Component::Normal(name) if !name.to_string_lossy().starts_with('.')),
    );
    let inside_repository = parent
        .ancestors()
        .take_while(|path| path.as_os_str() != home.as_os_str())
        .any(|path| std::fs::symlink_metadata(path.join(".git")).is_ok());
    let cwd = std::fs::canonicalize(home_relative(context.cwd?, context.home_dir)?).ok()?;
    let current_parent = cwd
        .ancestors()
        .take_while(|path| path.as_os_str() != home.as_os_str())
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())
        .and_then(Path::parent);
    (below_home.components().next().is_some()
        && visible
        && !inside_repository
        && (cwd == parent || current_parent == Some(parent.as_path()))
        && !super::super::inside_agent_state(&parent, context))
    .then_some(GlobBase {
        base: parent.clone(),
        root: parent,
        pattern,
        strict: true,
        siblings: true,
    })
}

/// A match in sibling mode lies in a git working tree directly below `root`.
pub(super) fn in_sibling_repository(
    path: &Path,
    root: &Path,
    context: ReadContext<'_>,
) -> Option<bool> {
    let Component::Normal(first) = path.strip_prefix(root).ok()?.components().next()? else {
        return Some(false);
    };
    let repository = root.join(first);
    let entry = std::fs::symlink_metadata(repository.join(".git")).ok()?;
    Some(
        (entry.is_dir() || entry.is_file())
            && crate::pretool::git_routes::repository_below_home(
                &std::fs::canonicalize(&repository).ok()?,
                context,
            ),
    )
}
