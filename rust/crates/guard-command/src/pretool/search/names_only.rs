//! Roots of a listing that prints names and reads nothing (`rg --files`).
//!
//! `rg --files` walks its operands and prints the paths it would search. It
//! opens none of them, so the proof its roots owe is the one `ls -R` owes and
//! not the one a content search owes: what may be named, rather than what may
//! be read. Screened as a content search, the shapes agents list constantly
//! went to review — a scratch directory holding a socket lock, an agent's own
//! skill tree — because a walk that reads has to answer for every hidden
//! entry below the root.
//!
//! A hidden entry is exactly what this walk never reaches. Without `--hidden`
//! `rg` skips a hidden file or directory wherever it meets one below an
//! operand, and [`super::rg`] refuses `--hidden`, every `--no-ignore`
//! spelling, `--follow` and `--pre` before a root is asked for anything. So
//! the walk here steps over a hidden descendant the way `rg` does, and
//! screens every visible one exactly as a reading walk screens it: a visible
//! credential name, a key container, a link or a socket still refuses.
//!
//! Two things bring a hidden entry back without a flag. A negation in an
//! ignore file under the root (`!.aws/`) re-includes it, so the root also has
//! to clear [`super::rg_whitelist::roots_proven`]. An inclusion glob outranks
//! the hidden filter, so [`super::rg`] proves every inclusion glob of a
//! names-only listing by what it selects on disk.
//!
//! The root itself is named on the command line, where `rg` does descend into
//! a hidden directory, so it keeps every screen a read operand clears,
//! including the agent-state trees whose files direct reads deny.

use super::{tree, ReadContext};

/// Whether a names-only search may be rooted at `value`.
pub(in crate::pretool) fn safe_names_only_search_target(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    visible_walk_target(value, context)
        || super::agent_root::agent_root_listing(value, context, true)
}

fn visible_walk_target(value: &str, context: ReadContext<'_>) -> bool {
    // A walk through `..` reaches a sibling tree whose ignore rules were never
    // inspected, as it does for a search that reads.
    if tree::parent_component(value)
        || !super::super::safe_reads::bounded_read_target(
            value,
            context.home_dir,
            context.cwd,
            true,
        )
    {
        return false;
    }
    let Some(root) = tree::expanded_operand(value, context) else {
        return false;
    };
    if tree::inside_agent_state(&root, context)
        || !super::rg_whitelist::roots_proven(&[value], context)
    {
        return false;
    }
    super::walk_memo::memoized(&root, &[], &[], false, false, true, || {
        tree::walk_uncached(root.clone(), &[], &[], false, false, None, true)
    })
}
