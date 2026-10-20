//! Names-only listings of the Oh My Pi agent-state root (`ls ~/.agent`,
//! `ls -R ~/.agent`, `find ${HOME}/.agent -name SKILL.md`).
//!
//! `ls` prints names and metadata, never file contents, and Oh My Pi's own
//! glob tool already lists these trees. The operand must resolve exactly to
//! `<home>/.agent` with no link anywhere on the way, and a recursive listing
//! must still clear the bounded metadata walk, so hidden, credential-named,
//! key-container and linked descendants keep asking. Content readers never
//! use this allowance: `grep -r` over the root could reach agent-state files
//! that direct reads deny.
use super::tree::{expanded_operand, walk, HAZARDS};
use super::ReadContext;
use std::path::Path;

pub(in crate::pretool) fn agent_root_listing(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    // `$HOME` and `${HOME}` name the same directory a leading `~` does. The
    // parser drops quotes, so `'$HOME/.agent'` reaches here too, where the
    // shell leaves the name alone; that literal path must not exist.
    let spelled;
    let value = match ["${HOME}", "$HOME"]
        .iter()
        .find_map(|name| value.strip_prefix(name))
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    {
        Some(rest) => {
            let literal = context
                .cwd
                .is_none_or(|cwd| std::fs::symlink_metadata(Path::new(cwd).join(value)).is_ok());
            if literal {
                return false;
            }
            spelled = format!("~{rest}");
            spelled.as_str()
        }
        None => value,
    };
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(|c: char| HAZARDS.contains(&c) && !windows_separator(c))
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || value.split(['/', '\\']).any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    let Some(root) = expanded_operand(value, context) else {
        return false;
    };
    // A linked `.agent` resolves elsewhere and fails the equality; the walk
    // itself never follows links below the root.
    let agent = home.join(".agent");
    std::fs::symlink_metadata(&agent).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::canonicalize(&root).is_ok_and(|canonical| canonical == agent)
        && (!recursive || walk(agent, &[], &[], false, false))
}

/// A user skill directory, `~/.agents`, or the `skills` tree of any tool's
/// own home directory, named for a listing that prints names only (`ls`
/// without recursion, `find` without actions). Agents look
/// up skill scripts this way; the operand must clear the same word screens as
/// the `.agent` root and resolve to a directory the skill rules admit.
/// The operand names a skill root, and that root is a link to the home
/// directory or an ancestor. `skill_listing_root` already rejects it; a
/// bounded directory read must reject it too, or `find` allows the listing.
pub(in crate::pretool) fn skill_link_resolves_over_home(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(HAZARDS)
        || value.contains(['*', '?', '[', ']', '{', '}'])
    {
        return false;
    }
    let Some(raw_home) = context.home_dir else {
        return false;
    };
    let Some(home) = std::fs::canonicalize(raw_home).ok() else {
        return false;
    };
    let Some(expanded) = expanded_operand(value, context) else {
        return false;
    };
    let Some(canonical) = std::fs::canonicalize(&expanded).ok() else {
        return false;
    };
    // Only a target that holds the home directory can be a skill link over
    // it, so a spelling the fold below cannot follow is refused exactly then.
    let holds_home = home.starts_with(&canonical);
    // The kernel walks `..` physically. Fold the spelling against the
    // canonical cwd so `../../.claude/skills/<link>` still names the skill
    // root. Only a leading run of `..` folds exactly: a later one, or one
    // behind a rooted or `~` spelling, could step back out of a symlinked
    // directory the lexical fold cannot see, so that spelling is treated as
    // naming the skill root. `/tmp/org/..` lists a directory below no home.
    let mut parts = value.split('/').skip_while(|part| *part == "..");
    let spelled = if parts.any(|part| part == "..") {
        return holds_home;
    } else if value.split('/').any(|part| part == "..") {
        let cwd = expanded_operand(".", context).and_then(|cwd| std::fs::canonicalize(cwd).ok());
        match cwd {
            Some(cwd) if !value.starts_with('~') && !Path::new(value).has_root() => {
                fold_parents(&cwd.join(value))
            }
            _ => return holds_home,
        }
    } else {
        expanded
    };
    super::super::read_paths::skill_link_resolves_over_home(
        &spelled,
        &canonical,
        &home,
        std::path::Path::new(raw_home),
    )
}

/// Drop each `..` with the component before it, without touching the disk.
fn fold_parents(path: &Path) -> std::path::PathBuf {
    let mut folded = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                folded.pop();
            }
            component => folded.push(component),
        }
    }
    folded
}

pub(in crate::pretool) fn skill_listing_root(value: &str, context: ReadContext<'_>) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(HAZARDS)
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || value.split('/').any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    expanded_operand(value, context)
        .and_then(|root| std::fs::canonicalize(root).ok())
        .is_some_and(|canonical| {
            guard_secure_fs::sensitive_path_family(&canonical).is_none()
                && !guard_secure_fs::credential_named_path(&canonical)
                && (super::super::read_paths::agent_skill_listing_directory(
                    &canonical,
                    context.home_dir,
                ) || home_tool_skill_tree(&canonical, context.home_dir))
        })
}

/// A `skills` tree below a tool's own home directory.
///
/// Every harness keeps user skills at `~/.<tool>/skills`, and the named roots
/// above are the handful that were written down first. The next harness's
/// tree is the same shape and prints the same thing — skill folders and the
/// documents inside them — so it is recognised by that shape rather than by
/// its name, and an agent looking up its own skills does not have to be using
/// a harness someone remembered. Only names are printed: a document below the
/// tree keeps its own read proof, which this never grants.
///
/// The screens the named roots carry are kept. `canonical` is resolved, so a
/// linked `skills` that lands anywhere other than a `.<tool>/skills` of this
/// home fails the shape. Components below `skills` must be visible, because a
/// hidden one is private state of the skill rather than part of the tree, and
/// no component may name a credential store.
fn home_tool_skill_tree(canonical: &Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|home| std::fs::canonicalize(home).ok()) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(&home) else {
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
    let lowered: Vec<String> = parts.iter().map(|part| part.to_ascii_lowercase()).collect();
    parts.len() >= 2
        && parts[0].starts_with('.')
        && parts[1] == "skills"
        && parts[2..].iter().all(|part| !part.starts_with('.'))
        && !crate::credential_store_names::names_hold_credential_store(&lowered)
}

/// Windows spells the home path with `\`, so there it is a separator; the
/// canonical equality in `agent_root_listing` still pins the operand to `<home>/.agent`.
fn windows_separator(c: char) -> bool {
    cfg!(windows) && c == '\\'
}
