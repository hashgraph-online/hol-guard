//! Turning a read operand into the real directory it names.
//!
//! An operand reaches here as shell text. It is expanded against the caller's
//! home and working directory, screened for the characters that would make it
//! mean more than one literal path, and resolved without following a directory
//! link.
use super::ReadContext;
use std::path::{Path, PathBuf};

pub(in crate::pretool::search) fn home_relative(
    value: &str,
    home: Option<&str>,
) -> Option<PathBuf> {
    if value == "~" || value.starts_with("~/") {
        Some(Path::new(home?).join(value.strip_prefix("~/").unwrap_or("")))
    } else {
        Some(PathBuf::from(value))
    }
}

pub(in crate::pretool::search) fn expanded_operand(
    value: &str,
    context: ReadContext<'_>,
) -> Option<PathBuf> {
    let expanded = if value == "~" || value.starts_with("~/") {
        home_relative(value, context.home_dir)?
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        home_relative(context.cwd?, context.home_dir)?.join(value)
    };
    // Remove trailing separators so symlink_metadata cannot follow a directory link.
    Some(expanded.components().collect())
}

/// Characters that make a word mean more than one literal path.
pub(in crate::pretool::search) const HAZARDS: [char; 11] =
    ['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\'];

/// A relative, quoted operand naming an existing real directory.
pub(in crate::pretool::search) fn checked_directory(
    value: &str,
    context: ReadContext<'_>,
) -> Option<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}', '*', '?'])
        || value.starts_with(['/', '~', '-'])
        || value.split('/').any(|part| part == "..")
        || !crate::pretool::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let path = expanded_operand(value, context)?;
    real_allowed_directory(&path, context)
}

pub(in crate::pretool::search) fn real_allowed_directory(
    path: &Path,
    context: ReadContext<'_>,
) -> Option<PathBuf> {
    if !std::fs::symlink_metadata(path).ok()?.is_dir() {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    crate::pretool::read_paths::resolved_path_allowed(&canonical, context.home_dir, context.cwd)
        .then(|| path.to_path_buf())
}
