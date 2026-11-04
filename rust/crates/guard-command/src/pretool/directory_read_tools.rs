//! Which harness `Read` tools get the names-only directory proof.

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
        ("omp", Some("read")) => {
            // OMP's `read` also addresses a directory by `file://` URL, which
            // is a spelling of the path, not a wider capability: reduce it to
            // the path it denotes and prove that path the ordinary way. No
            // other tool here resolves URLs, so none widens by this.
            let resolved = super::super::omp_file_url::local_file_url_path(value);
            bounded_omp_directory_read_target(resolved.as_deref().unwrap_or(value), home_dir, cwd)
        }
        ("claude-code" | "grok", Some("Read")) => {
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

#[cfg(test)]
#[path = "grok_read_tools_tests.rs"]
mod grok_tests;
