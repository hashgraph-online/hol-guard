#[path = "read_paths_screens.rs"]
pub(super) mod screens;
#[path = "read_paths_selectors.rs"]
pub(super) mod selectors;

use screens::{matches_sensitive_system_root, resolved_path_allowed_for_operation};
use selectors::{bounded_existing_file_read_target, bounded_selector_path, BoundedSelectorPath};

pub(super) fn safe_read_target(argument: &str) -> bool {
    let Some(normalized) = lexical_read_path(argument) else {
        return false;
    };
    let lowered = normalized.to_ascii_lowercase();
    if lowered.starts_with('/')
        || matches_sensitive_system_root(&lowered)
        || lowered.starts_with('~')
        || super::sensitive_command(argument)
        || super::sensitive_command(&normalized)
        || super::sensitive_read_path_argument(&normalized)
    {
        return false;
    }
    true
}

/// Share canonical path-risk checks between structured reads and shell reads.
/// Absolute/home-relative targets must resolve; sensitive symlink destinations
/// stay guarded. Unresolved relative targets retain the legacy lexical floor.
pub(super) fn bounded_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_read_target(value, home_dir, cwd, false)
}

/// OMP's `read` tool accepts a bounded source selector after a literal-path
/// probe. Keep that host-specific syntax out of shared command/file proofs.
pub(super) fn bounded_omp_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match bounded_selector_path(value, home_dir, cwd) {
        BoundedSelectorPath::Base(base) => {
            return bounded_existing_file_read_target(&base, home_dir, cwd);
        }
        BoundedSelectorPath::Unsupported => return false,
        BoundedSelectorPath::NotSelector => {}
    }
    bounded_read_target(value, home_dir, cwd, false)
}

pub(super) fn existing_regular_read_target(
    value: &str,
    home: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if value.trim() != value || !bounded_file_read_target(value, home, cwd) {
        return false;
    }
    let expanded = expand_home_read_path(value, home).unwrap_or_else(|| value.to_owned());
    let path = std::path::Path::new(&expanded);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = cwd {
        std::path::Path::new(&expand_home_read_path(cwd, home).unwrap_or_else(|| cwd.to_owned()))
            .join(path)
    } else {
        return false;
    };
    std::fs::canonicalize(candidate).is_ok_and(|path| path.is_file())
}

pub(super) fn bounded_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    allow_directory: bool,
) -> bool {
    let path = value.trim();
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    if path.contains([
        '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
    ]) {
        return false;
    }
    if path.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    if path.starts_with('~') && expand_home_read_path(path, home_dir).is_none() {
        return false;
    }
    let expanded = expand_home_read_path(path, home_dir).unwrap_or_else(|| path.to_owned());
    let expanded_path = std::path::Path::new(&expanded);
    let candidate = if expanded_path.is_absolute() {
        expanded_path.to_path_buf()
    } else if let Some(root) = cwd
        .and_then(|root| expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned())))
        .filter(|root| std::path::Path::new(root).is_absolute())
    {
        std::path::Path::new(&root).join(expanded_path)
    } else {
        return safe_read_target(path);
    };
    if let Ok(canonical) = std::fs::canonicalize(&candidate) {
        return (canonical.is_file() || (allow_directory && canonical.is_dir()))
            && resolved_path_allowed_for_operation(&canonical, home_dir, cwd, false, true);
    }
    // An unresolvable absolute or `~` target cannot prove a bounded file;
    // a workspace-relative spelling keeps the pre-existing lexical floor.
    if expanded_path.is_absolute() {
        return false;
    }
    safe_read_target(path)
}

pub(super) fn expand_home_read_path(path: &str, home_dir: Option<&str>) -> Option<String> {
    let rest = path.strip_prefix('~')?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let home = home_dir?.trim();
    if home.is_empty() || !std::path::Path::new(home).is_absolute() {
        return None;
    }
    if rest.is_empty() {
        return Some(home.to_owned());
    }
    #[cfg(windows)]
    let rest = rest.trim_start_matches('/').replace('/', "\\");
    #[cfg(not(windows))]
    let rest = rest.trim_start_matches('/');
    Some(
        std::path::Path::new(home)
            .join(rest)
            .to_string_lossy()
            .into_owned(),
    )
}

pub(super) fn lexical_read_path(value: &str) -> Option<String> {
    if value.is_empty() || value.contains(['\0', '\n', '\r', '%', '*', '?', '[', ']', '{', '}']) {
        return None;
    }
    let unified = value.replace('\\', "/");
    let absolute = unified.starts_with('/');
    let mut parts = Vec::new();
    for part in unified.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.starts_with('~') {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return None;
    }
    let mut normalized = String::new();
    if absolute {
        normalized.push('/');
    }
    normalized.push_str(&parts.join("/"));
    Some(normalized)
}
