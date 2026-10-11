//! Narrow read allowances for known agent-facing files inside the verified
//! user home: host tool-output logs, agent skill documents and the Guard
//! safety guide.

/// Hosts persist oversized tool output separately from their credentials and
/// configuration. Allow only a regular output leaf in the verified user's
/// execution tree, not arbitrary files in hidden application state.
pub(in crate::pretool) fn execution_output_log(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
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

pub(in crate::pretool) fn agent_skill_document(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
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
        // Oh My Pi also discovers user skills from the singular spelling.
        ".agent/skills",
        ".claude/skills",
        ".codex/skills",
        ".codex/superpowers/skills",
        ".zcode/cli/plugins/cache",
    ] {
        let Ok(skills) = std::fs::canonicalize(home.join(root)) else {
            continue;
        };
        // Retain the existing managed .agents root-link support. New roots,
        // including the singular .agent spelling, must resolve to themselves
        // so a link cannot turn hidden application state into skills.
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

/// OMP's document trees may be inspected, but its adjacent auth/config state
/// may not. Directory callers still prove the reachable tree before search.
pub(in crate::pretool) fn omp_agent_document_path(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    if guard_secure_fs::contains_symlink_component(canonical) {
        return false;
    }
    let Ok(relative) = canonical.strip_prefix(&home) else {
        return false;
    };
    let Some(parts) = relative
        .components()
        .map(|part| match part {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if parts.first() != Some(&".agent")
        || !matches!(parts.get(1), Some(&"skills" | &"artifacts"))
        || parts[2..].iter().any(|value| value.starts_with('.'))
    {
        return false;
    }
    canonical.is_dir()
        || (parts.len() >= 3
            && canonical.is_file()
            && canonical
                .extension()
                .is_some_and(|extension| extension == "md"))
}

/// `~/.hol-support/SAFETY.md` is the harness-facing safety guide that agents
/// are instructed to read before acting; it gets the same explicit allowance
/// the Python source-path classifier grants.
pub(in crate::pretool) fn guard_safety_doc(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    home_dir
        .and_then(|root| std::fs::canonicalize(root).ok())
        .is_some_and(|home| canonical == home.join(".hol-support").join("SAFETY.md"))
}

fn visible_components(relative: &std::path::Path) -> Option<Vec<&std::ffi::OsStr>> {
    relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(part) if !part.to_string_lossy().starts_with('.') => {
                Some(part)
            }
            _ => None,
        })
        .collect()
}

/// Project-level skill documents: `<dir>/.agents|.claude|.codex/skills/<skill>/**/*.md`
/// below the verified workspace or user home. Every component outside the
/// single skills marker must be visible, so this never opens other hidden
/// application state. `canonical` is already fully resolved.
pub(in crate::pretool) fn project_skill_document(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    let inside = [home_dir, cwd]
        .into_iter()
        .flatten()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| canonical.starts_with(root));
    if !inside {
        return false;
    }
    let parts: Vec<&std::ffi::OsStr> = canonical
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    let Some(marker) = parts.iter().position(|part| {
        part.to_str()
            .is_some_and(|part| matches!(part, ".agents" | ".claude" | ".codex"))
    }) else {
        return false;
    };
    // Skill directory plus document leaf must follow `skills`.
    parts.get(marker + 1).is_some_and(|part| *part == "skills")
        && parts.len() >= marker + 4
        && parts[..marker]
            .iter()
            .all(|part| !part.to_string_lossy().starts_with('.'))
        && parts[marker + 2..]
            .iter()
            .all(|part| !part.to_string_lossy().starts_with('.'))
}

/// Codex planning and memory notes in the verified user home:
/// `~/.codex/plans/**/*.md` and `~/.codex/memories/**/*.md`. Auth material,
/// config and sessions live elsewhere under `.codex` and stay guarded.
pub(in crate::pretool) fn codex_notes_document(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    ["plans", "memories"].iter().any(|name| {
        let root = home.join(".codex").join(name);
        std::fs::canonicalize(&root).is_ok_and(|resolved| resolved == root)
            && canonical.strip_prefix(&root).is_ok_and(|relative| {
                visible_components(relative).is_some_and(|parts| !parts.is_empty())
            })
    })
}
