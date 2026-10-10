//! Canonical-path sensitive screens for read proofs. One screen authority for
//! the bounded-read entry points and the OMP selector grammar; every screen is
//! read-only over the resolved canonical path and never grants a path it did
//! not screen.

use super::expand_home_read_path;

const SENSITIVE_SYSTEM_ROOTS: [&str; 7] = [
    "/etc",
    "/dev",
    "/proc",
    "/sys",
    "/var",
    "/private/etc",
    "/private/var",
];

fn sensitive_system_root_prefix(lowered: &str) -> Option<&'static str> {
    SENSITIVE_SYSTEM_ROOTS
        .iter()
        .copied()
        .filter(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
        .max_by_key(|prefix| prefix.len())
}

pub(super) fn matches_sensitive_system_root(lowered: &str) -> bool {
    sensitive_system_root_prefix(lowered).is_some()
}

/// A verified project may live under `/var` or `/private/var` on macOS, where
/// `$TMPDIR` canonicalizes from `/var/folders` to `/private/var/folders`.
/// Containment there is not permission to read that root, its first child
/// (`/var/tmp`, `/private/var/folders`), or `/etc`, `/dev`, `/proc`, `/sys`,
/// or `/private/etc`.
fn inside_verified_project_scope(canonical: &std::path::Path, root: Option<&str>) -> bool {
    let Some(root) = root else {
        return false;
    };
    let Ok(scope) = std::fs::canonicalize(root) else {
        return false;
    };
    if !scope.is_dir() || (canonical != scope && !canonical.starts_with(&scope)) {
        return false;
    }
    let rendered = scope.to_string_lossy().replace('\\', "/");
    let lowered = rendered.to_ascii_lowercase();
    let Some(prefix) = sensitive_system_root_prefix(&lowered) else {
        return true;
    };
    if !matches!(prefix, "/var" | "/private/var") || lowered == prefix {
        return false;
    }
    let rest = lowered[prefix.len()..].trim_start_matches('/');
    rest.split('/').filter(|part| !part.is_empty()).count() >= 2
}

pub(in crate::pretool) fn verified_path_context(home_dir: Option<&str>, cwd: Option<&str>) -> bool {
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
pub(in crate::pretool) fn resolved_path_allowed(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    resolved_path_allowed_in_scope(canonical, home_dir, cwd, false)
}

pub(in crate::pretool) fn resolved_path_allowed_in_scope(
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
    let rendered = canonical.to_string_lossy().replace('\\', "/");
    let lowered = rendered.to_ascii_lowercase();
    let under_sensitive_root = !verified_temporary && matches_sensitive_system_root(&lowered);
    let inside_verified_project = under_sensitive_root
        && (inside_verified_project_scope(canonical, cwd)
            || inside_verified_project_scope(canonical, home_dir));
    if (under_sensitive_root && !inside_verified_project)
        || foreign_user_home(canonical, home_dir, cwd)
        || guard_secure_fs::sensitive_path_family(canonical).is_some()
        || guard_secure_fs::credential_named_path(canonical)
        || !(guard_secure_fs::hidden_read_parts_allowed(canonical)
            || guard_safety_doc(canonical, home_dir)
            || (read_only && agent_skill_document(canonical, home_dir))
            || (read_only && execution_output_log(canonical, home_dir)))
    {
        return false;
    }
    true
}

/// Hosts persist oversized tool output separately from their credentials and
/// configuration. Allow only a regular output leaf in the verified user's
/// execution tree, not arbitrary files in hidden application state.
pub(super) fn execution_output_log(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
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
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    for root in [
        ".agents/skills",
        ".claude/skills",
        ".codex/skills",
        ".codex/superpowers/skills",
        ".zcode/cli/plugins/cache",
    ] {
        let Ok(skills) = std::fs::canonicalize(home.join(root)) else {
            continue;
        };
        // Retain the existing managed .agents root-link support. New roots
        // must not turn a broader hidden application directory into skills.
        if root != ".agents/skills" && skills != home.join(root) {
            continue;
        }
        let Ok(relative) = canonical.strip_prefix(skills) else {
            continue;
        };
        // Codex ships its bundled skills under `skills/.system`; that one
        // top-level directory is a skill namespace, not hidden application state.
        let Some(parts) = relative
            .components()
            .enumerate()
            .map(|(index, component)| match component {
                std::path::Component::Normal(part)
                    if !part.to_string_lossy().starts_with('.')
                        || (root == ".codex/skills" && index == 0 && part == ".system") =>
                {
                    Some(part)
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        // Cache entries are marketplace/plugin/version/skills/skill/document.
        let scoped = if root == ".zcode/cli/plugins/cache" {
            parts.len() >= 6 && parts[3] == "skills"
        } else {
            parts.len() >= 2
        };
        if scoped {
            return true;
        }
    }
    false
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
