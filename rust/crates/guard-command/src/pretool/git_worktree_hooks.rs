//! The proof that a hook manager's repository-relative `core.hooksPath` runs
//! nothing for `worktree add`: neither in this repository nor in the new tree
//! the commit being checked out decides.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use super::super::git_hook_files::{
    hook_file_inert, repository_relative_hooks_path, walk_hooks_directory, HooksDirectory,
};
use super::{git_query_with_args, WORKTREE_PROBE_LIMIT};

/// Git runs hooks from the root of a working tree: `reference-transaction`
/// in this repository and `post-checkout` in the new tree. A hooks directory
/// below the repository root holds no hook either runs when this working
/// tree's directory has none and the commit checked out tracks none, with no
/// symlink on the way into either tree. `None` is doubt.
pub(super) fn repository_hooks_inert(
    base: &Command,
    leading: &[String],
    hooks_path: &str,
    commit: &str,
    deadline: Instant,
) -> Option<bool> {
    if !repository_relative_hooks_path(hooks_path) {
        return Some(false);
    }
    let (status, output) = git_query_with_args(
        base,
        leading,
        &["rev-parse", "--show-toplevel"],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    if !status.success() {
        return None;
    }
    let toplevel = fs::canonicalize(std::str::from_utf8(&output).ok()?.trim()).ok()?;
    // The directory is walked as Git spells it, so a link anywhere on the way
    // is refused rather than resolved, and the shim Husky installs is judged
    // from the path its runner sees.
    match walk_hooks_directory(&toplevel, hooks_path) {
        HooksDirectory::Missing => {}
        HooksDirectory::Plain(directory) => {
            if !hooks_are_inert(&directory, &|_| true) {
                return Some(false);
            }
        }
        HooksDirectory::Unsafe => return Some(false),
    }
    // Every directory on the way must be a plain tree in the commit, or absent.
    let mut prefix = String::new();
    for component in hooks_path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        match tree_entry(base, leading, commit, &prefix, deadline)? {
            None => return Some(true),
            Some(mode) if mode == "040000" => {}
            Some(_) => return Some(false),
        }
    }
    for hook in EXECUTABLE_HOOKS {
        let path = format!("{hooks_path}/{hook}");
        match tree_entry(base, leading, commit, &path, deadline)? {
            None => {}
            // Git runs a tracked hook wherever a regular file counts as
            // executable, which is every platform but those with a mode bit.
            Some(mode) if mode == "100644" && cfg!(unix) => {}
            Some(_) => return Some(false),
        }
    }
    Some(true)
}

/// The mode of `path` in `commit`, or `None` where the tree has no such entry.
fn tree_entry(
    base: &Command,
    leading: &[String],
    commit: &str,
    path: &str,
    deadline: Instant,
) -> Option<Option<String>> {
    let (status, output) = git_query_with_args(
        base,
        leading,
        &["ls-tree", "-z", "--full-tree", commit, "--", path],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    if !status.success() {
        return None;
    }
    if output.is_empty() {
        return Some(None);
    }
    let rendered = std::str::from_utf8(&output).ok()?;
    let entry = rendered.strip_suffix('\0')?;
    let (meta, name) = entry.split_once('\t')?;
    // One entry, named exactly: a pattern never widens the lookup.
    (name == path && !entry.contains('\0'))
        .then(|| meta.split(' ').next().map(str::to_owned))
        .flatten()
        .map(Some)
}

const EXECUTABLE_HOOKS: &[&str] = &[
    "post-checkout",
    "post-index-change",
    "reference-transaction",
];

/// No hook Git runs for `worktree add` can start in the directory `path`.
/// Git finds a hook by its exact name, so each is looked up directly.
///
/// `husky_directory_reached` says whether the Husky shim there may count: the
/// caller has confirmed Git reaches `path` with no link on the way.
pub(super) fn hooks_are_inert(
    path: &Path,
    husky_directory_reached: &dyn Fn(&Path) -> bool,
) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        _ => return false,
    }
    EXECUTABLE_HOOKS
        .iter()
        .all(|hook| hook_file_inert(&path.join(hook), hook, husky_directory_reached))
}
