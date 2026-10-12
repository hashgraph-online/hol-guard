//! Names-only listings of the Oh My Pi agent-state root (`ls ~/.agent`,
//! `ls -R ~/.agent`).
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

pub(in crate::pretool) fn agent_root_listing(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
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
        && (!recursive || walk(agent, &[], &[], false))
}

/// A user skill directory, or `~/.agents`, named for a listing that prints
/// names only (`ls` without recursion, `find` without actions). Agents look
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
        || value.split('/').any(|part| part == "..")
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
    super::super::read_paths::skill_link_resolves_over_home(
        &expanded,
        &canonical,
        &home,
        std::path::Path::new(raw_home),
    )
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
                && super::super::read_paths::agent_skill_listing_directory(
                    &canonical,
                    context.home_dir,
                )
        })
}

/// Windows spells the home path with `\`, so there it is a separator; the
/// canonical equality in `agent_root_listing` still pins the operand to `<home>/.agent`.
fn windows_separator(c: char) -> bool {
    cfg!(windows) && c == '\\'
}
