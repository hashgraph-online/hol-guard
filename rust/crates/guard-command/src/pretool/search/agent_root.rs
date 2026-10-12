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

/// Windows spells the home path with `\`, so there it is a separator; the
/// canonical equality in `agent_root_listing` still pins the operand to `<home>/.agent`.
fn windows_separator(c: char) -> bool {
    cfg!(windows) && c == '\\'
}
