//! The Guard-managed PATH block a shell profile carries.

use std::collections::BTreeSet;

use super::profile::{fish_path_prepend, posix_path_export};
use super::values::{py_splitlines, py_strip};
use super::GUARD_PROFILE_MARKER;

/// `prepare_guard_shim_shell_profile`: `existing` with the harness launcher
/// block that puts `shim_dir` first on PATH, in fish or POSIX syntax.
pub fn guard_shim_profile_content(existing: &str, shim_dir: &str, fish: bool) -> String {
    let line = if fish {
        fish_path_prepend(shim_dir)
    } else {
        posix_path_export(shim_dir)
    };
    managed_profile_content(
        existing,
        &format!("{GUARD_PROFILE_MARKER}\n{line}"),
        GUARD_PROFILE_MARKER,
    )
}

/// `_strip_managed_marker_blocks`.
pub fn strip_managed_marker_blocks(content: &str, marker: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let marker_stripped = py_strip(marker);
    let lines = py_splitlines(content);
    let mut drop: BTreeSet<usize> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if py_strip(line) == marker_stripped && index + 1 < lines.len() {
            drop.insert(index);
            drop.insert(index + 1);
        }
    }
    if drop.is_empty() {
        return if content.ends_with('\n') {
            content.to_owned()
        } else {
            format!("{content}\n")
        };
    }
    let mut keep: Vec<&str> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if drop.contains(&index) {
            continue;
        }
        if py_strip(line).is_empty() {
            let previous_blank = keep.last().is_some_and(|kept| py_strip(kept).is_empty());
            let previous_dropped = index > 0 && drop.contains(&(index - 1));
            let next_dropped = drop.contains(&(index + 1));
            if (previous_dropped || next_dropped) && !previous_blank {
                continue;
            }
        }
        keep.push(line);
    }
    let mut cleaned = keep.join("\n");
    if !cleaned.is_empty() && !cleaned.ends_with('\n') {
        cleaned.push('\n');
    }
    cleaned
}

/// `_managed_profile_content`.
pub(super) fn managed_profile_content(existing: &str, export_line: &str, marker: &str) -> String {
    let mut export_line = export_line.trim_end_matches('\n').to_owned();
    let marker_line = export_line.split('\n').next().unwrap_or("");
    if py_strip(marker_line) != py_strip(marker) {
        export_line = format!("{marker}\n{export_line}");
    }
    let desired = format!("{export_line}\n");
    if existing == desired {
        return existing.to_owned();
    }
    let cleaned = strip_managed_marker_blocks(existing, marker);
    if cleaned.is_empty() {
        desired
    } else {
        let prefix = if cleaned.ends_with('\n') { "" } else { "\n" };
        format!("{cleaned}{prefix}{desired}")
    }
}

#[cfg(test)]
#[path = "profile_block_tests.rs"]
mod tests;
