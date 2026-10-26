//! Read routes to a directory that holds no repository.
//!
//! `git -C <directory> status` only prints `fatal: not a git repository` when
//! Git's own discovery walk finds no `.git` above that directory, and only
//! prints the path it could not enter when the directory is not there at all.
//! Git dies in its own setup before it reads a configuration helper, opens an
//! object or pages anything, so neither spelling needs the repository proofs
//! that admit a route to a real checkout. Agents reach this shape constantly:
//! a scratch directory a checkout was expected in, a sibling that has not
//! been cloned yet, a temporary root that holds plain files.
//!
//! What the route still has to prove is where it lands, because the answer is
//! only `fatal:` while nobody else can turn the target into a repository
//! first. The target therefore passes the same location screens that admit a
//! repository route outside the working directory — at or below the declared
//! home, or below the shared temporary root with every directory down to it
//! owned by the home owner and writable by no one else — and every name below
//! that root is an ordinary visible one, so a home dot-directory keeps its own
//! answer. A `..` spelling names no directory of its own and is left to the
//! route proofs unchanged.
//!
//! Git's discovery walk finds more than a `.git` entry: a directory that is
//! itself shaped like a bare repository (`HEAD`, `objects` or `refs`) is
//! found implicitly, so either one above the target leaves the route to the
//! repository proofs.
//!
//! "Only prints an error" holds for most read subcommands, but not all of
//! them: outside a repository `git diff <a> <b>` falls back to comparing two
//! files, `git grep` does too under `grep.fallbackToNoIndex`, and `apply` and
//! `hash-object` read their file operands directly. Those operands resolve
//! against the `-C` directory, which no repository proof has screened, so
//! [`reads_without_repository`] keeps them out of this route.

use std::path::{Component, Path, PathBuf};

/// Whether a read-only `-C <target>` can only print an error because Git
/// discovers no repository from it.
pub(crate) fn git_route_without_repository(
    target: &str,
    context: super::super::PathContext<'_>,
) -> bool {
    if target.is_empty()
        || super::super::sensitive_read_path_argument(target)
        || !super::super::read_paths::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(path) = expanded_route(target, context) else {
        return false;
    };
    if path.components().any(|part| {
        !matches!(
            part,
            Component::Prefix(_) | Component::RootDir | Component::Normal(_)
        )
    }) {
        return false;
    }
    let Some((anchor, missing)) = deepest_existing(&path) else {
        return false;
    };
    // A name that is not there yet is still a name: a hidden one would reach
    // the home directory's own answer as soon as it existed.
    if missing.iter().any(|name| name.starts_with('.')) {
        return false;
    }
    let Ok(anchor) = std::fs::canonicalize(&anchor) else {
        return false;
    };
    if !anchor.is_dir() || !anchor_allowed(&anchor, context) {
        return false;
    }
    if !missing.is_empty() {
        // `git -C` prints the directory it could not enter and stops, so no
        // discovery walk runs at all.
        return true;
    }
    // A `-C` to a file, a symlink of any kind, or a socket never starts Git
    // in a directory this screen read.
    if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    !anchor.ancestors().any(|ancestor| {
        [".git", "HEAD", "objects", "refs"]
            .iter()
            .any(|entry| std::fs::symlink_metadata(ancestor.join(entry)).is_ok())
    })
}

/// Whether the subcommand after a `-C` route can still read a file when Git
/// finds no repository: `diff` given any operand (two paths fall back to a
/// file comparison), `grep` (which falls back under `grep.fallbackToNoIndex`),
/// and `apply` and `hash-object`, which read their operands with or without a
/// repository. Only option-only `diff` spellings stay on the error path.
pub(crate) fn reads_without_repository(rest: &[String]) -> bool {
    match rest.first().map(String::as_str) {
        Some("diff") => rest[1..].iter().any(|argument| {
            !argument.starts_with('-') || argument == "--" || argument == "--no-index"
        }),
        Some("grep" | "apply" | "hash-object") => true,
        _ => false,
    }
}

/// The deepest ancestor of `path` that is there, and the names below it that
/// are not, deepest last.
fn deepest_existing(path: &Path) -> Option<(PathBuf, Vec<String>)> {
    let mut missing = Vec::new();
    let mut probe = path.to_path_buf();
    loop {
        if std::fs::symlink_metadata(&probe).is_ok() {
            missing.reverse();
            return Some((probe, missing));
        }
        missing.push(probe.file_name()?.to_string_lossy().into_owned());
        probe = probe.parent()?.to_path_buf();
    }
}

/// Whether canonical `anchor` is a directory only the home owner can turn
/// into a repository: the declared home itself, a visible directory below it,
/// or a visible directory below the shared temporary root whose every
/// directory down from that root belongs to the home owner and is writable by
/// no one else. It must also clear the sensitive-path screens and sit outside
/// the agent state tree, exactly as a repository route outside the working
/// directory does.
fn anchor_allowed(anchor: &Path, context: super::super::PathContext<'_>) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    let ordinary = |relative: &Path| {
        relative.components().all(|part| {
            matches!(part, Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
        })
    };
    let screened = |path: &Path| {
        super::super::read_paths::resolved_path_allowed(path, context.home_dir, context.cwd)
            && !super::super::read_paths::inside_agent_state_tree(path, context.home_dir)
    };
    if anchor == home {
        return true;
    }
    if let Ok(relative) = anchor.strip_prefix(&home) {
        return ordinary(relative) && screened(anchor);
    }
    super::temporary::owned_temporary_roots()
        .iter()
        .any(|root| {
            anchor
                .strip_prefix(root)
                .is_ok_and(|relative| !relative.as_os_str().is_empty() && ordinary(relative))
                && super::temporary::owned_below(root, anchor, &home)
                && screened(anchor)
        })
}

/// The path `-C` names, with `~` and a relative target resolved against the
/// declared working directory. A `~` spelling is proved only against the
/// declared home, as every other read route is.
fn expanded_route(target: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
    if let Some(rest) = target.strip_prefix('~') {
        if !rest.is_empty() && !rest.starts_with('/') {
            return None;
        }
        let home = context.home_dir?;
        return Some(Path::new(home).join(rest.trim_start_matches('/')));
    }
    let path = Path::new(target);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let cwd = context.cwd?;
    if !Path::new(cwd).is_absolute() {
        return None;
    }
    Some(Path::new(cwd).join(path))
}
