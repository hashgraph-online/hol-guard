//! Narrow read allowances for known agent-facing files inside the verified
//! user home: host tool-output logs, agent skill documents and the Guard
//! safety guide.

#[path = "read_path_git.rs"]
mod read_path_git;

pub(in crate::pretool) use read_path_git::{
    git_config_document, git_ref_document, worktree_gitfile,
};

/// A root the caller named, canonical and in the spelling these proofs
/// compare in: Windows' verbatim `\\?\` prefix removed, as every other
/// runtime path helper reports it.
fn canonical_root(text: &str) -> Option<std::path::PathBuf> {
    crate::runtime_read_paths::canonicalize_text(std::path::Path::new(text)).ok()
}

/// The same spelling for a path the caller already canonicalized. Callers
/// reach these proofs with either spelling, and a verbatim path neither
/// equals nor prefixes a plain one.
fn plain(path: &std::path::Path) -> std::path::PathBuf {
    crate::runtime_read_paths::strip_verbatim_prefix(path.to_path_buf())
}

/// A `/`-spelled root under `base`, one component at a time. A single join
/// keeps the slashes inside one component when the base is a Windows path,
/// and no host reports that component back from a canonical path.
fn under(base: &std::path::Path, root: &str) -> std::path::PathBuf {
    root.split('/')
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// Hosts persist oversized tool output separately from their credentials and
/// configuration. Allow only a regular output leaf in the verified user's
/// execution tree, not arbitrary files in hidden application state.
pub(in crate::pretool) fn execution_output_log(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
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
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
        return false;
    };
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    // A linked `.agents/skills` can put one path under two roots; any root
    // whose own depth rule admits the document is enough. Bind the answer
    // before `home` drops: the iterator borrows that canonical path.
    let admitted = skill_tree_parts(canonical, &home).any(|(root, parts)| {
        // Cache entries are marketplace/plugin/version/skills/skill/document.
        if root == ".zcode/cli/plugins/cache" {
            parts.len() >= 6 && parts[3] == "skills"
        } else {
            parts.len() >= 2
        }
    });
    admitted
}

/// A directory a names-only listing may start from: a user skill root, any
/// visible directory below one, or `~/.agents` itself, which holds only the
/// skills tree and its lock file. Content readers never use this allowance;
/// scripts beside skill documents stay outside the read rules.
pub(in crate::pretool) fn agent_skill_listing_directory(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
        return false;
    };
    let agents = home.join(".agents");
    if !canonical.is_dir() {
        return false;
    }
    if canonical == agents
        && std::fs::symlink_metadata(&agents).is_ok_and(|metadata| metadata.is_dir())
    {
        return true;
    }
    // Drop the iterator before `home`. It borrows that canonical path.
    // Plugin-cache listings may name the cache and the marketplace, plugin,
    // and version directories above `skills`. A sibling such as `logs` is
    // not a skill tree. Deeper entries must sit under that `skills` directory,
    // matching the document allowance.
    let admitted = skill_tree_parts(canonical, &home).any(|(root, parts)| {
        root != ".zcode/cli/plugins/cache" || parts.len() <= 3 || parts[3] == "skills"
    });
    admitted
}

/// A directory a names-only listing may start from inside the session
/// folder: a project's own `.agents` folder when it holds only a `skills`
/// tree, or a visible directory at or below `.agents/skills`,
/// `.claude/skills` or `.codex/skills`. Every component above the marker must
/// be visible. A listing of the session folder already prints these names,
/// and each file keeps its own read proof.
pub(in crate::pretool) fn project_skill_listing_directory(
    canonical: &std::path::Path,
    session: &std::path::Path,
) -> bool {
    let Ok(relative) = canonical.strip_prefix(session) else {
        return false;
    };
    let Some(parts) = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<&str>>>()
    else {
        return false;
    };
    let Some(marker) = parts.iter().position(|part| part.starts_with('.')) else {
        return false;
    };
    let below = &parts[marker + 1..];
    let skills_tree = matches!(parts[marker], ".agents" | ".claude" | ".codex")
        && below.first() == Some(&"skills")
        && below.iter().all(|part| !part.starts_with('.'));
    let agents_root = parts[marker] == ".agents"
        && below.is_empty()
        && std::fs::read_dir(canonical).is_ok_and(|entries| {
            entries.into_iter().all(|entry| {
                entry.is_ok_and(|entry| {
                    entry.file_name() == "skills"
                        && entry.file_type().is_ok_and(|kind| kind.is_dir())
                })
            })
        });
    canonical.is_dir() && (skills_tree || agents_root)
}

const SKILL_ROOTS: [&str; 6] = [
    ".agents/skills",
    // Oh My Pi also discovers user skills from the singular spelling.
    ".agent/skills",
    ".claude/skills",
    ".codex/skills",
    ".codex/superpowers/skills",
    ".zcode/cli/plugins/cache",
];

/// A skill-root symlink that resolves to the home directory, or to one of
/// its ancestors, would make a names-only listing print the whole home.
///
/// `home` is canonical. `lexical_home` is the spelling the caller supplied:
/// tilde expansion uses that spelling, and a symlink home does not share a
/// prefix with the canonical path.
pub(in crate::pretool) fn skill_link_resolves_over_home(
    expanded: &std::path::Path,
    canonical: &std::path::Path,
    home: &std::path::Path,
    lexical_home: &std::path::Path,
) -> bool {
    if !home.starts_with(canonical) {
        return false;
    }
    let spellings = [home, lexical_home];
    SKILL_ROOTS.iter().any(|root| {
        spellings.iter().any(|spelling| {
            let lexical = under(spelling, root);
            expanded.starts_with(&lexical)
                && canonical != lexical
                && !canonical.starts_with(&lexical)
        })
    })
}

/// Every skill root holding `canonical`, each with the visible components
/// below it.
fn skill_tree_parts<'a>(
    canonical: &'a std::path::Path,
    home: &'a std::path::Path,
) -> impl Iterator<Item = (&'static str, Vec<&'a std::ffi::OsStr>)> + 'a {
    SKILL_ROOTS.into_iter().filter_map(move |root| {
        let skills = crate::runtime_read_paths::canonicalize_text(&under(home, root)).ok()?;
        // Retain the existing managed .agents root-link support. New roots,
        // including the singular .agent spelling, must resolve to themselves
        // so a link cannot turn hidden application state into skills.
        if root != ".agents/skills" && skills != under(home, root) {
            return None;
        }
        // A link to the home directory or one of its ancestors would make the
        // whole home a skill tree.
        if home.starts_with(&skills) {
            return None;
        }
        let relative = canonical.strip_prefix(skills).ok()?;
        // Codex ships its bundled skills under `skills/.system`; that one
        // top-level directory is a skill namespace, not hidden application state.
        let parts = relative
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
            .collect::<Option<Vec<_>>>()?;
        Some((root, parts))
    })
}

/// Oh My Pi keeps session artifacts and user skills under `~/.agent`. Reads
/// below `artifacts/` and listings of the `skills/` or `artifacts/` trees are
/// routine agent state. The state root must resolve to itself (no link can
/// redirect it), every component below it must be visible, artifact files
/// are documents (`.md`), and the caller has already screened credential
/// names and sensitive families.
pub(in crate::pretool) fn agent_home_state(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
        return false;
    };
    ["skills", "artifacts"].into_iter().any(|name| {
        let root = home.join(".agent").join(name);
        crate::runtime_read_paths::canonicalize_text(&root).is_ok_and(|resolved| resolved == root)
            && canonical.strip_prefix(&root).is_ok_and(|relative| {
                let Some(parts) = visible_components(relative) else {
                    return false;
                };
                if canonical.is_dir() {
                    return true;
                }
                name == "artifacts"
                    && !parts.is_empty()
                    && canonical
                        .extension()
                        .is_some_and(|extension| extension == "md")
            })
    })
}

/// True when `canonical` is, or lies inside, an Oh My Pi agent-state tree
/// (`~/.agent/skills`, `~/.agent/artifacts`). Content searches must not walk
/// these trees: the per-file exclusions that deny direct reads of non-document
/// files there (for example `artifacts/data.json`) do not apply to a walk.
pub(in crate::pretool) fn inside_agent_state_tree(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
        return false;
    };
    let agent = home.join(".agent");
    ["skills", "artifacts"]
        .into_iter()
        .any(|name| canonical.starts_with(agent.join(name)))
}

/// True when a content search rooted at `root` inside an agent-state tree can
/// reach only files a direct read would allow (visible `.md` documents). The
/// walk is bounded and refuses links and hidden entries, so a search over
/// `~/.agent/artifacts` holding reports proceeds while one that would reach
/// `artifacts/data.json` or `artifacts/.cache` still asks.
pub(in crate::pretool) fn agent_state_tree_holds_only_documents(
    root: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let mut pending = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return false;
        };
        for entry in entries {
            seen += 1;
            let Ok(entry) = entry else {
                return false;
            };
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            let path = entry.path();
            if seen > 4096 || entry.file_name().to_string_lossy().starts_with('.') {
                return false;
            }
            if kind.is_dir() {
                pending.push(path);
            } else if !(kind.is_file()
                && (agent_home_state(&path, home_dir) || agent_skill_document(&path, home_dir)))
            {
                return false;
            }
        }
    }
    agent_home_state(root, home_dir)
}

/// `~/.hol-support/SAFETY.md` is the harness-facing safety guide that agents
/// are instructed to read before acting; it gets the same explicit allowance
/// the Python source-path classifier grants.
pub(in crate::pretool) fn guard_safety_doc(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    home_dir
        .and_then(canonical_root)
        .is_some_and(|home| plain(canonical) == home.join(".hol-support").join("SAFETY.md"))
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
    let canonical: &std::path::Path = &plain(canonical);
    if canonical
        .extension()
        .is_none_or(|extension| extension != "md")
    {
        return false;
    }
    let inside = [home_dir, cwd]
        .into_iter()
        .flatten()
        .filter_map(canonical_root)
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

/// Agent planning and memory notes in the verified user home:
/// `~/.codex/plans/**`, `~/.codex/memories/**` and `~/.claude/plans/**`.
/// Notes are Markdown, plain text or JSON evidence. Auth material, config and
/// sessions live elsewhere under `.codex` and `.claude` and stay guarded, and
/// the caller has already refused credential names and sensitive families.
pub(in crate::pretool) fn codex_notes_document(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    let Some(home) = home_dir.and_then(canonical_root) else {
        return false;
    };
    if canonical
        .extension()
        .and_then(|extension| extension.to_str())
        .is_none_or(|extension| !matches!(extension, "md" | "txt" | "json"))
    {
        return false;
    }
    [".codex/plans", ".codex/memories", ".claude/plans"]
        .iter()
        .any(|name| {
            let root = under(&home, name);
            crate::runtime_read_paths::canonicalize_text(&root)
                .is_ok_and(|resolved| resolved == root)
                && canonical.strip_prefix(&root).is_ok_and(|relative| {
                    visible_components(relative).is_some_and(|parts| !parts.is_empty())
                })
        })
}
