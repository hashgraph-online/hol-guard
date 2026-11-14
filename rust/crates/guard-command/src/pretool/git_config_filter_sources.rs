//! A quick answer for the filter proof: no attributes file a tracked path
//! reads names a filter.
//!
//! `git lfs install` writes `filter.lfs.*` into the user's global
//! configuration, so almost every developer machine defines a filter. The
//! full proof then asks `check-attr` about every path in the checkout, which
//! in a checkout of a few tens of thousands of files takes longer than a
//! hook's whole budget, so a plain `git status` went to review.
//!
//! A filter runs on a path only when an attributes rule matching it sets
//! `filter`, directly or through a macro, and a macro can only be defined
//! with the word `filter` in its definition. So when no attributes source a
//! tracked path reads contains that word anywhere, no path has a filter.
//! The sources are the `.gitattributes` file of every directory holding a
//! tracked path, the repository's `info/attributes`, and the global and
//! system attributes files Git itself reports. Status and the working-tree
//! diffs clean only tracked files, so untracked ones need no answer here.
//!
//! Anything this cannot read plainly falls back to the full proof: a gitlink,
//! a tracked attributes file missing from disk, a linked or oversized one, an
//! `attr.tree` setting, or a Git too old to report its attributes files.

use super::GitQuery;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

/// More directories than this go to the full proof.
const MAX_DIRECTORIES: usize = 50_000;
/// A larger attributes file goes to the full proof.
const MAX_ATTRIBUTES_BYTES: u64 = 1024 * 1024;
const NAME: &str = ".gitattributes";

/// `true` when no attributes source the tracked paths of the work tree read
/// names a filter. `false` means only that this quick check did not show it.
pub(super) fn none_named(query: &GitQuery<'_>, deadline: Instant) -> bool {
    named_nowhere(query, deadline).unwrap_or(false)
}

fn named_nowhere(query: &GitQuery<'_>, deadline: Instant) -> Option<bool> {
    let locations = text(query(
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
            "--show-toplevel",
        ],
        None,
        None,
    )?)?;
    let mut lines = locations.lines();
    let (git_dir, common_dir, root) = (lines.next()?, lines.next()?, lines.next()?);
    if lines.next().is_some() {
        return None;
    }
    let root = std::fs::canonicalize(root).ok()?;
    // A user-set attributes path can contain symlinks and ".." segments.
    // Git's variable output may normalize them differently from its reader;
    // keep the full per-path proof rather than guess at the effective file.
    if text(query(
        &["config", "--default=", "--get", "core.attributesfile"],
        None,
        None,
    )?)? != "\n"
    {
        return None;
    }
    // `attr.tree` reads attributes out of a tree instead of these files.
    if text(query(
        &["config", "--default=", "--get", "attr.tree"],
        None,
        None,
    )?)? != "\n"
    {
        return Some(false);
    }
    let mut outside = vec![
        Path::new(git_dir).join("info/attributes"),
        Path::new(common_dir).join("info/attributes"),
    ];
    for variable in ["GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM"] {
        let path = text(query(&["var", variable], None, None)?)?;
        let path = path.strip_suffix('\n')?;
        if !path.is_empty() {
            let external = PathBuf::from(path);
            // The git-var result is not a safe filesystem locator when it is
            // relative or has path-traversal components.
            if !external.is_absolute()
                || external
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return None;
            }
            outside.push(external);
        }
    }
    for path in outside {
        if !quiet(&path, true)? {
            return Some(false);
        }
    }
    let index = query(&["ls-files", "--stage", "-z"], None, Some(&root))?;
    let mut directories = BTreeSet::new();
    let mut tracked_attributes = BTreeSet::new();
    for entry in index
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = std::str::from_utf8(entry).ok()?;
        let (stage, path) = entry.split_once('\t')?;
        // A gitlink sends status into another repository and its attributes.
        if stage.starts_with("160000 ") {
            return Some(false);
        }
        if path == NAME || path.ends_with("/.gitattributes") {
            tracked_attributes.insert(path);
        }
        let mut directory = path;
        while let Some((parent, _)) = directory.rsplit_once('/') {
            if !directories.insert(parent) {
                break;
            }
            directory = parent;
        }
        if directories.len() > MAX_DIRECTORIES {
            return None;
        }
    }
    directories.insert("");
    for directory in directories {
        if Instant::now() >= deadline {
            return None;
        }
        let relative = if directory.is_empty() {
            NAME.to_owned()
        } else {
            format!("{directory}/{NAME}")
        };
        let path = root.join(&relative);
        // A tracked attributes file missing from disk is read from the
        // index, which this check does not open.
        if tracked_attributes.contains(relative.as_str())
            && std::fs::symlink_metadata(&path).is_err()
        {
            return None;
        }
        if !quiet(&path, false)? {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether the attributes file at `path` is absent or never says `filter`.
/// `None` when it cannot be read plainly. Git follows a link only for the
/// files outside the work tree.
fn quiet(path: &Path, follow: bool) -> Option<bool> {
    let metadata = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    };
    let metadata = match metadata {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(true),
        Err(_) => return None,
        Ok(metadata) => metadata,
    };
    if !metadata.is_file() || metadata.len() > MAX_ATTRIBUTES_BYTES {
        return None;
    }
    // Bound the actual read too: a file can be replaced or enlarged after
    // metadata, and a hook must not read an unbounded replacement.
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_ATTRIBUTES_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_ATTRIBUTES_BYTES {
        return None;
    }
    Some(
        !bytes
            .windows(6)
            .any(|window| window.eq_ignore_ascii_case(b"filter")),
    )
}

fn text(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
#[path = "git_config_filter_sources_tests.rs"]
mod tests;
