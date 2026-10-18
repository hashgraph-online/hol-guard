//! The negated patterns a `.gitignore` carries, and the entries they
//! re-include.
//!
//! `rg` may search an entry a negation re-includes even when it is hidden,
//! so the walk screens the entries they name rather than skipping them. A
//! negation that spells a literal path names one entry; a globbed negation
//! names a set, kept here as the pattern git wrote and matched where the
//! walk meets an entry.

use super::plain_name;
use crate::pretool::search_scope_glob::glob_matches;
use std::path::{Path, PathBuf};

/// One negated pattern, kept with the scope git gives it.
///
/// A pattern anchored to its ignore file's directory, by a leading slash or
/// by a slash anywhere inside it, re-includes paths below that directory:
/// `!/.env.example` in the root says nothing about `src/.env.example`.
/// A bare name re-includes every matching entry below the directory.
pub(super) struct Whitelist {
    /// The directory the ignore file applies to.
    base: PathBuf,
    /// The re-included path relative to `base`, lowercased and separated by
    /// `/`. It keeps the pattern's wildcards when it has any.
    relative: String,
    /// Whether the name is re-included at any depth below `base`.
    anywhere: bool,
    /// Whether `relative` is a glob rather than a path that matches only
    /// itself.
    glob: bool,
}

/// Whether a negation re-includes `path`, which the walk reached below the
/// directory its ignore file applies to.
pub(super) fn whitelists(whitelisted: &[Whitelist], path: &Path) -> bool {
    whitelisted.iter().any(|whitelisted| {
        let text = if whitelisted.anywhere {
            path.file_name()
                .map(|name| name.to_string_lossy().to_lowercase())
        } else {
            path.strip_prefix(&whitelisted.base).ok().map(relative_text)
        };
        let Some(text) = text else {
            return false;
        };
        if !whitelisted.glob {
            return text == whitelisted.relative;
        }
        // A pattern this matcher cannot read is read as re-including the
        // entry, so the walk screens it instead of skipping it.
        glob_matches(&whitelisted.relative, &text).unwrap_or(true)
    })
}

/// Records the negated patterns among `lines`, read from an ignore file that
/// applies to the tree being walked, and reports whether every one of them
/// leaves the walk's pruning intact. `anywhere` and `at_root` are the plain
/// names the walk prunes.
pub(super) fn admit(
    whitelisted: &mut Vec<Whitelist>,
    lines: &[String],
    base: &Path,
    anywhere: &[String],
    at_root: &[String],
) -> bool {
    for line in lines {
        let Some(pattern) = line.strip_prefix('!') else {
            continue;
        };
        let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
        // A leading `**/` stands for any run of directories, which is what a
        // bare name already means: `!**/notes.md` re-includes that name
        // wherever it sits.
        let (pattern, any_depth) = match pattern.strip_prefix("**/") {
            Some(rest) => (rest, true),
            None => (pattern, false),
        };
        // Git anchors a pattern to its ignore file's directory as soon as it
        // carries a slash anywhere but the end, so only a bare name
        // re-includes entries deeper down.
        let anchored = !any_depth && (pattern.starts_with('/') || pattern.contains('/'));
        let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
        let components: Vec<&str> = pattern.split('/').collect();
        let literal = components.iter().all(|component| plain_name(component));
        // The matcher below folds case so a pattern matches at least what git
        // matches. A character class inverts that: folding `[!A-Z]` to
        // `[!a-z]` narrows it, and the walk would then skip an entry git
        // re-includes. Such a negation is not read at all.
        if !literal && pattern.contains('[') {
            return false;
        }
        if (!anchored && components.len() != 1)
            || reaches_pruned(&components, literal, anywhere, at_root)
        {
            return false;
        }
        whitelisted.push(Whitelist {
            base: base.to_path_buf(),
            relative: components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>()
                .join("/"),
            anywhere: !anchored,
            glob: !literal,
        });
    }
    true
}

/// Whether a negation can re-include an entry the walk prunes.
///
/// Git leaves everything below an excluded directory excluded, so a pattern
/// whose middle names a pruned directory re-includes nothing `rg` would
/// reach, and the walk and `rg` agree on skipping it. What matters is the
/// component naming the re-included entry itself: a pattern that can name a
/// pruned entry would put a whole unwalked subtree back in `rg`'s reach. A
/// literal pattern keeps the stricter screen it has always had.
fn reaches_pruned(
    components: &[&str],
    literal: bool,
    anywhere: &[String],
    at_root: &[String],
) -> bool {
    let mut pruned = anywhere.iter().chain(at_root);
    if literal {
        return pruned.any(|ignored| {
            components
                .iter()
                .any(|component| ignored.eq_ignore_ascii_case(component))
        });
    }
    let Some(named) = components.last() else {
        return true;
    };
    let named = named.to_lowercase();
    // A pattern this matcher cannot read is read as naming the pruned entry.
    pruned.any(|ignored| glob_matches(&named, &ignored.to_lowercase()).unwrap_or(true))
}

/// The path below an ignore file's directory, lowercased and separated by
/// `/` on every platform, which is how git spells a pattern.
fn relative_text(relative: &Path) -> String {
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}
