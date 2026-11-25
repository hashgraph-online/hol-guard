//! Which `core.excludesFile` values name nothing but an ignore list.
//!
//! A verbose `git check-ignore` prints the rule that matched and the file it
//! came from. A configured excludes file can name any file, so the check
//! keeps its review while the setting could point at one that holds
//! something other than ignore rules. Two kinds of value cannot:
//!
//! - `.git/info/exclude`, the repository's own exclude file. Git reads it on
//!   every ignore check whatever the setting says, so naming it again adds no
//!   file to what the check can print. In a linked worktree `.git` is a file
//!   and the path does not open, so Git skips it.
//! - The conventional per-user ignore lists in the home directory Git runs
//!   with: `~/.config/git/ignore`, which Git reads when the setting is unset,
//!   and the `~/.gitignore` and `~/.gitignore_global` names Git's own
//!   documentation and hosting guides suggest. Only the user can create a
//!   file there; a repository's configuration can only name one.
//!
//! The value is matched lexically. Any other spelling, a `..` component, or a
//! `~user/` home keeps the review.

use std::path::Path;

/// The per-user ignore lists a home-relative value may name.
const HOME_IGNORE_LISTS: [&str; 5] = [
    ".config/git/ignore",
    ".gitignore",
    ".gitignore_global",
    ".gitignore-global",
    ".global_gitignore",
];

/// Whether `value` names only the repository's own exclude file or a
/// per-user ignore list in `home`.
pub(super) fn names_an_ignore_list(value: &str, home: &Path) -> bool {
    if value == ".git/info/exclude" {
        return true;
    }
    if value.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    let named = if let Some(rest) = value.strip_prefix("~/") {
        rest
    } else {
        let path = Path::new(value);
        if !path.is_absolute() || !home.is_absolute() {
            return false;
        }
        let Ok(rest) = path.strip_prefix(home) else {
            return false;
        };
        let Some(rest) = rest.to_str() else {
            return false;
        };
        return HOME_IGNORE_LISTS
            .iter()
            .any(|name| Path::new(rest) == Path::new(name));
    };
    HOME_IGNORE_LISTS.contains(&rest_without_dot_prefix(named))
}

/// `~/./.gitignore` is the same file as `~/.gitignore`; any other leading
/// spelling is compared as written.
fn rest_without_dot_prefix(value: &str) -> &str {
    let mut value = value;
    while let Some(rest) = value.strip_prefix("./") {
        value = rest;
    }
    value
}

#[cfg(test)]
#[path = "git_excludes_file_tests.rs"]
mod tests;
