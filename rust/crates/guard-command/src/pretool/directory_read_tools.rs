//! Which harness `Read` tools get the names-only directory proof.
//!
//! Grok's `list_dir` returns a tree of entry names below its
//! `target_directory`, so it takes the root screen a names-only `find` walk
//! takes rather than the one-level listing screen.

use super::{
    bounded_omp_directory_read_target, bounded_omp_directory_read_target_without_selector,
};

/// Whether `harness`'s `tool` reading `value` lists a directory the
/// names-only proof covers. OMP's `read` takes line selectors; Claude Code's
/// and Grok's `Read` open their path literally and answer a directory with no
/// file content.
pub(in crate::pretool) fn bounded_directory_read_tool_target(
    harness: &str,
    tool: Option<&str>,
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match (harness, tool) {
        ("omp", Some("read")) => bounded_omp_directory_read_target(value, home_dir, cwd),
        ("claude-code" | "grok", Some("Read")) => {
            literal_path(value)
                && bounded_omp_directory_read_target_without_selector(value, home_dir, cwd)
        }
        ("grok", Some("list_dir")) => grok_list_dir_target(value, home_dir, cwd),
        _ => false,
    }
}

/// A Grok `list_dir` of a folder the `find` listing screen admits.
///
/// The tool prints names, never file contents, but it walks every level
/// below the folder. A home store such as `~/.ssh` and any root that resolves
/// to one keep their review, and so do home itself and the folders above it,
/// whose walk would name every store at once. A `~`, a parent climb or a
/// pattern is not modeled because the tool's own reading of each is not
/// known.
fn grok_list_dir_target(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.trim() == value
        && !value.starts_with('~')
        && !value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        && !value.split(['/', '\\']).any(|part| part == "..")
        && literal_path(value)
        && super::super::bounded_read_target(value, home_dir, cwd, true)
        && walk_root(value, home_dir, cwd)
}

/// The value names an existing directory, read against the working directory
/// when relative, that is neither home nor a folder holding it.
fn walk_root(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|home| std::fs::canonicalize(home).ok()) else {
        return false;
    };
    let path = std::path::Path::new(value);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match cwd {
            Some(cwd) => std::path::Path::new(cwd).join(path),
            None => return false,
        }
    };
    std::fs::canonicalize(candidate).is_ok_and(|path| path.is_dir() && !home.starts_with(path))
}

/// No colon past the drive: Windows reads `dir:name` as a stream.
fn literal_path(value: &str) -> bool {
    let path = value.strip_prefix(r"\\?\").unwrap_or(value);
    let drive = path.as_bytes().get(1) == Some(&b':') && path.as_bytes()[0].is_ascii_alphabetic();
    !path[if drive { 2 } else { 0 }..].contains(':')
}

#[cfg(test)]
#[path = "literal_directory_read_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "grok_read_tools_tests.rs"]
mod grok_tests;
