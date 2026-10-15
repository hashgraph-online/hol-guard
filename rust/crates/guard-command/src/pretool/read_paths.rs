#[path = "read_path_allowances.rs"]
mod allowances;
pub(super) use allowances::{
    agent_skill_listing_directory, agent_state_tree_holds_only_documents, inside_agent_state_tree,
    project_skill_listing_directory, skill_link_resolves_over_home,
};
#[path = "hidden_listing.rs"]
mod hidden_listing;
#[path = "omp_json_query.rs"]
mod omp_json_query;
#[path = "omp_read_targets.rs"]
mod omp_targets;
pub(super) use hidden_listing::{home_hidden_directory, repository_hidden_directory};
#[path = "private_temporary_workspace.rs"]
mod private_temporary;
#[path = "workspace_scratch_reads.rs"]
mod scratch;
use allowances::{
    agent_home_state, agent_skill_document, codex_notes_document, execution_output_log,
    git_config_document, git_ref_document, guard_safety_doc, project_skill_document,
    worktree_gitfile,
};
pub(super) use omp_targets::{
    bounded_omp_directory_read_target, bounded_omp_file_read_target,
    bounded_omp_file_selector_target, bounded_omp_selector_requires_review, missing_read_target,
};

pub(super) fn safe_read_target(argument: &str) -> bool {
    let Some(normalized) = lexical_read_path(argument) else {
        return false;
    };
    let lowered = normalized.to_ascii_lowercase();
    const ROOTS: [&str; 7] = [
        "/etc",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/private/etc",
        "/private/var",
    ];
    if lowered.starts_with('/')
        || ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
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
    bounded_read_target_with_brackets(value, home_dir, cwd, allow_directory, false)
}

/// A structured read tool opens its path literally, so `[slug]` in a Next.js
/// route is a directory name, not a glob. Brackets are accepted only when the
/// exact spelling resolves to an existing regular file; every other glob
/// metacharacter, and any unresolved bracketed path, stays rejected.
pub(super) fn bounded_structured_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_read_target_with_brackets(value, home_dir, cwd, false, true)
}

fn bounded_read_target_with_brackets(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    allow_directory: bool,
    literal_brackets: bool,
) -> bool {
    let path = value.trim();
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    let has_brackets = path.contains(['[', ']']);
    if path.contains([
        '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '{', '}',
    ]) || (has_brackets && !literal_brackets)
    {
        return false;
    }
    // The kernel resolves `..` physically, against the working directory or
    // the root, which is what canonicalizing the spelling yields. Only that
    // proof admits a parent component; every lexical fallback still rejects
    // it. Windows normalizes a rooted `..` lexically first, so there a drive,
    // verbatim or root-relative spelling with `..` stays refused.
    let parent_component = path.split(['/', '\\']).any(|part| part == "..");
    let lexical_root = !cfg!(unix) && rooted(value.trim());
    if parent_component && (has_brackets || path.starts_with('~') || lexical_root) {
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
        return !parent_component && safe_read_target(path);
    };
    if let Ok(canonical) = std::fs::canonicalize(&candidate) {
        return (canonical.is_file() || (allow_directory && canonical.is_dir()))
            && (resolved_path_allowed_for_operation(&canonical, home_dir, cwd, false, true)
                || package_source::installed_package_source(
                    &candidate, &canonical, home_dir, cwd,
                ));
    }
    if has_brackets || parent_component {
        return false;
    }
    // An unresolvable absolute or `~` target cannot prove a bounded file;
    // a workspace-relative spelling keeps the pre-existing lexical floor.
    if expanded_path.is_absolute() {
        return false;
    }
    safe_read_target(path)
}

/// A drive, verbatim, or root-relative spelling does not resolve against the
/// working directory.
fn rooted(value: &str) -> bool {
    std::path::Path::new(value).components().any(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        )
    })
}

pub(super) fn verified_path_context(home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    let (Some(home_dir), Some(cwd)) = (home_dir, cwd) else {
        return false;
    };
    context_root_is_absolute(home_dir, Some(home_dir))
        && context_root_is_absolute(cwd, Some(home_dir))
}

pub(super) fn context_root_is_absolute(root: &str, home_dir: Option<&str>) -> bool {
    if root.is_empty() || root.trim() != root {
        return false;
    }
    let expanded = if std::path::Path::new(root).is_absolute() {
        Some(root.to_owned())
    } else {
        expand_home_read_path(root, home_dir)
    };
    expanded.is_some_and(|root| {
        let path = std::path::Path::new(&root);
        path.is_absolute() && std::fs::canonicalize(path).is_ok_and(|canonical| canonical.is_dir())
    })
}

/// Location outside the workspace is not itself a risk. The resolved regular
/// file must still clear every sensitive-path screen.
pub(super) fn resolved_path_allowed(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    resolved_path_allowed_in_scope(canonical, home_dir, cwd, false)
}

pub(super) fn resolved_path_allowed_in_scope(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    verified_temporary: bool,
) -> bool {
    resolved_path_allowed_for_operation(canonical, home_dir, cwd, verified_temporary, false)
}

pub(super) fn resolved_path_allowed_for_operation(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    verified_temporary: bool,
    read_only: bool,
) -> bool {
    if !resolved_location_allowed(canonical, home_dir, cwd, verified_temporary)
        || !(guard_secure_fs::hidden_read_parts_allowed(canonical)
            || (read_only && guard_secure_fs::hidden_empty_work_tree_file(canonical))
            || guard_safety_doc(canonical, home_dir)
            || (read_only
                && (agent_skill_document(canonical, home_dir)
                    || agent_home_state(canonical, home_dir)
                    || project_skill_document(canonical, home_dir, cwd)
                    || codex_notes_document(canonical, home_dir)
                    || git_ref_document(canonical, home_dir, cwd)
                    || git_config_document(canonical, cwd)
                    || worktree_gitfile(canonical)
                    || scratch::workspace_scratch_read(canonical, home_dir, cwd)))
            || (read_only && execution_output_log(canonical, home_dir)))
    {
        return false;
    }
    true
}

/// Every resolved-path screen except the hidden-component one: system roots,
/// another user's home, sensitive families and credential-named paths.
pub(super) fn resolved_location_allowed(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    verified_temporary: bool,
) -> bool {
    let rendered = canonical.to_string_lossy().replace('\\', "/");
    let lowered = rendered.to_ascii_lowercase();
    const ROOTS: [&str; 7] = [
        "/etc",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/private/etc",
        "/private/var",
    ];
    !((!verified_temporary
        && !private_temporary::inside_private_temporary_workspace(canonical, home_dir, cwd)
        && ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/"))))
        || foreign_user_home(canonical, home_dir, cwd)
        || guard_secure_fs::sensitive_path_family(canonical).is_some()
        || guard_secure_fs::credential_named_path(canonical))
}

pub(super) fn foreign_user_home(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let user_root = ["/home", "/Users"].iter().find_map(|root| {
        let relative = canonical.strip_prefix(root).ok()?;
        let user = relative.components().next()?;
        Some(std::path::Path::new(root).join(user.as_os_str()))
    });
    user_root.is_some_and(|user_root| {
        ![home_dir, cwd]
            .into_iter()
            .flatten()
            .any(|root| std::fs::canonicalize(root).is_ok_and(|root| root.starts_with(&user_root)))
    })
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

#[path = "package_source_reads.rs"]
mod package_source;

#[cfg(test)]
#[path = "read_output_tests.rs"]
mod execution_output_tests;

#[cfg(test)]
#[path = "hidden_listing_tests.rs"]
mod hidden_listing_tests;

#[cfg(test)]
#[path = "directory_read_tests.rs"]
mod directory_read_tests;
