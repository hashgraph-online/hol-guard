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

pub(super) fn verified_path_context(home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    let (Some(home_dir), Some(cwd)) = (home_dir, cwd) else {
        return false;
    };
    context_root_is_absolute(home_dir, Some(home_dir))
        && context_root_is_absolute(cwd, Some(home_dir))
}

pub(super) fn verified_cwd_target(value: &str, context: super::PathContext<'_>) -> Option<String> {
    if context.home_dir.is_none() || context.cwd.is_none() || !super::safe_directory_target(value) {
        return None;
    }
    let supplied = std::path::Path::new(value);
    if !supplied.is_absolute() {
        return None;
    }
    let canonical = std::fs::canonicalize(supplied).ok()?;
    // Absolute, non-aliased targets avoid CDPATH and logical/physical cwd ambiguity.
    if canonical != supplied
        || !canonical.is_dir()
        || !resolved_path_allowed(&canonical, context.home_dir, context.cwd)
    {
        return None;
    }
    canonical.to_str().map(str::to_owned)
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

fn resolved_path_allowed_for_operation(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    verified_temporary: bool,
    read_only: bool,
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
    if (!verified_temporary
        && ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/"))))
        || foreign_user_home(canonical, home_dir, cwd)
        || guard_secure_fs::sensitive_path_family(canonical).is_some()
        || guard_secure_fs::credential_named_path(canonical)
        || !(guard_secure_fs::hidden_read_parts_allowed(canonical)
            || guard_safety_doc(canonical, home_dir)
            || agent_skill_document(canonical, home_dir)
            || (read_only && execution_output_log(canonical, home_dir)))
    {
        return false;
    }
    true
}

/// Hosts persist oversized tool output separately from their credentials and
/// configuration. Allow only a regular output leaf in the verified user's
/// execution tree, not arbitrary files in hidden application state.
fn execution_output_log(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(home) else {
        return false;
    };
    let Some(parts) = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let [state, "cli", "exec", session, output] = parts.as_slice() else {
        return false;
    };
    let Some(state_name) = state.strip_prefix('.') else {
        return false;
    };
    if state_name.is_empty()
        || !state_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || guard_secure_fs::EXTERNAL_SENSITIVE_PARTS
            .iter()
            .any(|part| state.eq_ignore_ascii_case(part) || state_name.eq_ignore_ascii_case(part))
    {
        return false;
    }
    let Some(session) = session.strip_prefix("sess_") else {
        return false;
    };
    if session.len() != 36
        || !session.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return false;
    }
    let Some(call) = output.strip_prefix("call_").and_then(|value| {
        value
            .strip_suffix("-stdout.log")
            .or_else(|| value.strip_suffix("-stderr.log"))
    }) else {
        return false;
    };
    call.len() == 24
        && call.bytes().all(|byte| byte.is_ascii_hexdigit())
        && std::fs::metadata(canonical)
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 64 * 1024 * 1024)
}

pub(super) fn agent_skill_document(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let Ok(skills) = std::fs::canonicalize(home.join(".agents/skills")) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(skills) else {
        return false;
    };
    canonical.extension().is_some_and(|extension| extension == "md")
        && relative.components().count() >= 2
        && relative.components().all(|component| {
            matches!(component, std::path::Component::Normal(part) if !part.to_string_lossy().starts_with('.'))
        })
}

/// `~/.hol-support/SAFETY.md` is the harness-facing safety guide that agents
/// are instructed to read before acting; it gets the same explicit allowance
/// the Python source-path classifier grants.
pub(super) fn guard_safety_doc(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
    home_dir
        .and_then(|root| std::fs::canonicalize(root).ok())
        .is_some_and(|home| canonical == home.join(".hol-support/SAFETY.md"))
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

#[cfg(test)]
#[path = "read_output_tests.rs"]
mod execution_output_tests;
