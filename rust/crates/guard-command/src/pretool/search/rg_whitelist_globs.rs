//! Whether a search's `-g` inclusions can reach an entry at all.
//!
//! With one inclusion ripgrep searches only what the inclusions select, so
//! a negation that re-includes an entry they cannot select re-includes
//! nothing the search reads. This module answers that selection question
//! for the whitelist walk.

use crate::pretool::search_scope_filter::{Override, SearchFilter};
use std::path::Path;

/// Whether the search's `-g` inclusions can select `path`, or anything below
/// it when it is a directory. Without inclusions every entry is selected.
///
/// A path the walk cannot describe, or an entry it cannot stat, counts as
/// selected: the question then falls back to the negation screen itself.
pub(super) fn selected_by_globs(filter: Option<&SearchFilter>, root: &Path, path: &Path) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let (Some(name), Ok(relative)) = (
        path.file_name().and_then(std::ffi::OsStr::to_str),
        path.strip_prefix(root),
    ) else {
        return true;
    };
    let Some(components) = relative
        .iter()
        .map(std::ffi::OsStr::to_str)
        .collect::<Option<Vec<&str>>>()
    else {
        return true;
    };
    let directory = std::fs::symlink_metadata(path).map_or(true, |metadata| metadata.is_dir());
    !matches!(
        filter.override_for(name, &components.join("/"), directory),
        Override::Skipped
    )
}
