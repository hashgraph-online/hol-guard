//! Ref and path spellings a proven `git worktree add` accepts.

const MAX_GIT_NAME_BYTES: usize = 256;

pub(crate) fn valid_branch_name(value: &str) -> bool {
    valid_ref_component(value)
        && !value.starts_with('-')
        && !value.ends_with('.')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.ends_with(".lock")
}

pub(super) fn valid_local_reference(value: &str) -> bool {
    value == "HEAD"
        || (value
            .strip_prefix("refs/heads/")
            .or_else(|| value.strip_prefix("refs/tags/"))
            .or_else(|| value.strip_prefix("refs/remotes/"))
            .or_else(|| value.strip_prefix("origin/"))
            .is_some_and(valid_ref_component))
}

fn valid_ref_component(value: &str) -> bool {
    value.len() <= MAX_GIT_NAME_BYTES
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.ends_with('.')
        && !value.ends_with('/')
        && !value.ends_with(".lock")
}

/// A relative destination may start by climbing out of the repository, as in
/// `../report-worktree`, the usual sibling layout; `fresh_destination` then
/// requires the canonical parent to stay under home or an owned temporary
/// directory.
pub(super) fn valid_path_text(value: &str) -> bool {
    let absolute = value.strip_prefix('/');
    let mut parts = absolute.unwrap_or(value).split('/').peekable();
    if absolute.is_none() {
        while parts.next_if_eq(&"..").is_some() {}
    }
    let parts: Vec<&str> = parts.collect();
    value.len() <= super::MAX_DESTINATION_BYTES
        && !parts.is_empty()
        && value.trim() == value
        && !value.starts_with('~')
        && !value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}', '\\',
        ])
        && !parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
}

/// A destination as `git worktree add` receives it. `~/<path>` is accepted
/// here; `parse` requires the shell to expand it (no quoted or escaped `~`)
/// and `fresh_destination` requires the shell's HOME to be the declared one.
pub(in crate::pretool) fn valid_destination_text(value: &str) -> bool {
    match value.strip_prefix('~') {
        Some(rest) => rest.starts_with('/') && valid_path_text(rest),
        None => valid_path_text(value),
    }
}
