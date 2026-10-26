//! Which harness `Read` tools get the names-only directory proof.

use super::{
    bounded_omp_directory_read_target, bounded_omp_directory_read_target_without_selector,
};

/// Whether `harness`'s `tool` reading `value` lists a directory the
/// names-only proof covers. OMP's `read` takes line selectors; Claude Code's
/// `Read` opens its path literally and answers a directory with no file
/// content.
pub(in crate::pretool) fn bounded_directory_read_tool_target(
    harness: &str,
    tool: Option<&str>,
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match (harness, tool) {
        ("omp", Some("read")) => bounded_omp_directory_read_target(value, home_dir, cwd),
        ("claude-code", Some("Read")) => {
            literal_path(value)
                && bounded_omp_directory_read_target_without_selector(value, home_dir, cwd)
        }
        _ => false,
    }
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
