//! Name-only listing of a hidden directory in the home directory
//! (`ls ~/.config/`, `ls ~/.agents/skills/`, `find ~/.config -maxdepth 1`).
//!
//! A listing prints entry names and metadata, never file content, so a
//! dot-directory that stores no credentials, and its visible subdirectories,
//! are as safe to list as the home directory itself. `~/.codex` and
//! `~/.claude` keep their logins in known files that content reads still
//! refuse, so their names list too. Credential, key, wallet, browser-profile,
//! other agent-login and Guard state stores keep their review at any depth, and so do the stores that live below `~/.config` and
//! `~/.local/share` (`~/.config/gh`). Callers must bound the listing to the
//! directory's own entries: a recursive listing of `~/.config` prints the
//! names inside `~/.config/gh` and keeps its review.
//!
//! The store lists themselves live in [`crate::credential_store_names`], so the
//! content screen that `cat` and `rg` go through refuses the same directories.
//! That content screen is the narrower of the two: it answers for one file's
//! bytes, below one hidden directory, in a tree no other rule owns.

use std::path::{Path, PathBuf};

use crate::credential_store_names::{
    clears_store_screen, hidden_content_read_allowed, lowered_names, narrow_guidance_rule_owns,
};
pub(super) use crate::credential_store_names::{CREDENTIAL_STORE_NAMES, HARNESS_HOME_NAMES};

/// Whether `value` names an existing directory below a hidden component of
/// the home directory that is not, and is not inside, a credential store.
pub(in crate::pretool) fn home_hidden_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some((canonical, relative)) = resolved_home_entry(value, home_dir, cwd) else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    // Only the home entry itself is hidden: a dot-directory nested deeper
    // (`~/.nvm/.cache`) is private state of the tool that owns it.
    let mut names = relative.components().skip(1);
    canonical.is_dir()
        && first.as_os_str().to_string_lossy().starts_with('.')
        && !names.any(|name| name.as_os_str().to_string_lossy().starts_with('.'))
        && clears_store_screen(&relative)
        && super::super::resolved_location_allowed(&canonical, home_dir, cwd, false)
}

/// The canonical path of `value` and its path relative to the home directory,
/// for a spelling that names an entry of the home directory and nothing else.
///
/// The spelled path must be the resolved one: a link anywhere below the home
/// directory could dress another store, or the home directory itself, as an
/// ordinary dot-directory.
fn resolved_home_entry(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<(PathBuf, PathBuf)> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(|c: char| {
            // Windows spells the home path with `\`, so there it is a separator.
            (c == '\\' && !cfg!(windows))
                || [
                    '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{',
                    '}',
                ]
                .contains(&c)
        })
        || value.split(['/', '\\']).any(|part| part == "..")
        || !super::super::verified_path_context(home_dir, cwd)
    {
        return None;
    }
    let raw_home = home_dir?;
    let expanded = expanded(value, home_dir, cwd)?;
    let home = std::fs::canonicalize(raw_home).ok()?;
    let canonical = std::fs::canonicalize(&expanded).ok()?;
    let relative = expanded
        .strip_prefix(raw_home)
        .or_else(|_| expanded.strip_prefix(&home))
        .ok()
        .filter(|relative| home.join(relative) == canonical)?;
    Some((canonical.clone(), relative.to_path_buf()))
}

/// Whether `value` names a directory one tool owns, rather than a root that
/// several tools keep their own directories under.
///
/// A depth-bounded listing prints the entries of the directory it was handed
/// and stops there, so `~/.config` prints the names of the tool directories
/// below it and nothing from inside them. A walk with no depth bound prints
/// what those directories hold, and below `~/.config` and `~/.local/share`
/// that is where the credential stores live: `find ~/.config -name hosts.yml`
/// would print a path through `~/.config/gh`, which the listing screen
/// refuses to name. A tool's own directory has no such shared children, so a
/// deeper walk stays inside the tree the agent actually named.
pub(in crate::pretool) fn home_hidden_tool_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if !home_hidden_directory(value, home_dir, cwd) {
        return false;
    }
    let Some((_, relative)) = resolved_home_entry(value, home_dir, cwd) else {
        return false;
    };
    let lowered = lowered_names(&relative);
    match lowered.first().map(String::as_str) {
        Some(".config") => lowered.len() > 1,
        Some(".local") => lowered.len() > 2,
        _ => true,
    }
}

/// How many entries of a tool directory are read before the screen below
/// gives up. A tool keeps tens of entries at its top level; a root holding
/// thousands is not the inventory this proof is for.
const MAX_ROOT_ENTRIES: usize = 1_024;

/// Whether a walk of `value` that prints directory paths can print one from
/// inside a credential store the tool directory holds.
///
/// A `-type d` walk names directories and opens no file, so what it can
/// disclose is the layout of what it reaches. The listing screen draws its
/// line at printing from inside a store rather than at naming one:
/// `~/.config` may name `gh`, and a listing may not print what `gh` holds. A
/// tool's own directory is screened the same way here. Its entries may be
/// named, and a store among them stops the walk, because a walk that is not
/// depth-bounded would go on to print that store's own layout.
///
/// Only the root's own entries are read. Deeper names repeat the words
/// ordinary package trees are written with -- a `credentials` directory sits
/// inside more than one published package -- so a name screen at depth would
/// refuse the toolchain inventories this proof exists for while proving
/// nothing about a store a tool does not create.
pub(in crate::pretool) fn home_hidden_walk_clears_stores(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some((canonical, relative)) = resolved_home_entry(value, home_dir, cwd) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&canonical) else {
        return false;
    };
    for (inspected, entry) in entries.enumerate() {
        if inspected >= MAX_ROOT_ENTRIES {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        if !clears_store_screen(&relative.join(entry.file_name())) {
            return false;
        }
    }
    true
}

/// Whether `value` names an existing file below a hidden entry of the home
/// directory that returns no credential.
///
/// The listing screen above answers `ls ~/.agents/skills/`; this answers the
/// read that follows it, `cat ~/.agents/skills/release-check/scripts/run.sh`.
/// A hidden component used to end that lookup on its own, so an ordinary
/// source read under a toolchain, a shared skill tree or a repository's own
/// workflows collected an approval nobody answered.
///
/// What a hidden component has to clear is
/// [`hidden_content_read_allowed`]: one hidden directory directly below home,
/// no store at any depth, no name a secret is conventionally written under,
/// and no tree a narrower rule already owns. The path itself is canonicalized
/// and compared with the spelling first, so a link cannot dress a credential
/// store as an ordinary dot-directory.
pub(in crate::pretool) fn home_hidden_content_read(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some((canonical, relative)) = resolved_home_entry(value, home_dir, cwd) else {
        return false;
    };
    let lowered = lowered_names(&relative);
    canonical.is_file()
        && hidden_content_read_allowed(&lowered)
        && !narrow_guidance_rule_owns(&lowered)
        && super::super::resolved_location_allowed(&canonical, home_dir, cwd, false)
}

/// The same screen for a path a caller has already resolved.
///
/// A structured read tool hands its target to the shared resolved-path gate
/// rather than to a spelling screen, so the canonical path is all there is to
/// read. That is the stronger starting point: a link has already been followed,
/// so a name below the home directory cannot stand in for a store somewhere
/// else. What is left is the same question the spelling screen asks, over the
/// components the path has after the home prefix.
pub(in crate::pretool) fn resolved_home_hidden_content_read(
    canonical: &Path,
    home_dir: Option<&str>,
) -> bool {
    let Some(raw_home) = home_dir else {
        return false;
    };
    let Ok(home) = std::fs::canonicalize(raw_home) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(&home) else {
        return false;
    };
    let lowered = lowered_names(relative);
    // A listing asks a different question and has its own screen: this rule
    // answers for the bytes of one file.
    canonical.is_file()
        && hidden_content_read_allowed(&lowered)
        && !narrow_guidance_rule_owns(&lowered)
}

/// The listing screen for a path a caller has already resolved.
///
/// A structured read tool handed a directory lists its entries, or says it is
/// a directory; either way it returns no file's bytes, so the question is the
/// listing one rather than the content one. The resolved path has already
/// followed every link, so a name below the home directory cannot stand in
/// for a store somewhere else, and the store screen still refuses the trees
/// whose entry names are themselves the secret.
pub(in crate::pretool) fn resolved_home_hidden_listing(
    canonical: &Path,
    home_dir: Option<&str>,
) -> bool {
    let Some(raw_home) = home_dir else {
        return false;
    };
    let Ok(home) = std::fs::canonicalize(raw_home) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(&home) else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    let mut names = relative.components().skip(1);
    canonical.is_dir()
        && first.as_os_str().to_string_lossy().starts_with('.')
        && !names.any(|name| name.as_os_str().to_string_lossy().starts_with('.'))
        && clears_store_screen(relative)
}

fn expanded(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> Option<PathBuf> {
    let path = if value == "~" || value.starts_with("~/") || value.starts_with("~\\") {
        PathBuf::from(super::super::expand_home_read_path(value, home_dir)?)
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        let cwd = cwd?;
        let root =
            super::super::expand_home_read_path(cwd, home_dir).unwrap_or_else(|| cwd.to_owned());
        Path::new(&root).join(value)
    };
    Some(path.components().collect())
}

#[cfg(test)]
#[path = "home_hidden_walk_tests.rs"]
mod walk_tests;
