//! The hooks each local Git write form runs, and which segments are those
//! forms (`git_local_writes`).

use super::forms::{add, branch_rename, commit, rm, stash_list, stash_restore, stash_show};
use super::{merge, rebase, start};
use crate::CommandSegmentV1;

const INDEX_HOOKS: &[&str] = &["post-index-change"];
pub(super) const COMMIT_HOOKS: &[&str] = &[
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-rewrite",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
];
const BRANCH_HOOKS: &[&str] = &["reference-transaction"];
/// `git stash list` and `git stash show` write nothing and run no hook.
const LIST_HOOKS: &[&str] = &[];
pub(super) const CHECKOUT_HOOKS: &[&str] = &[
    "post-checkout",
    "post-index-change",
    "reference-transaction",
];

/// The hooks a proven write form runs, or `None` when `original` is not one.
/// Leading Git options such as `-c` are refused: they can point the command
/// at another configuration. A leading `-C <dir>` reaches here only after
/// the route proof dropped it.
pub(super) fn write_hooks(
    original: &CommandSegmentV1,
) -> Option<(&'static [&'static str], Option<String>)> {
    let stripped = super::super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    if segment.executable.as_deref() != Some("git")
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !super::identity_only(segment)
        || segment.text.contains(['$', '`', '\n', '\r'])
        // A quoted `<` or `>` (`--author="A <a@example.test>"`) is data.
        || crate::codex_output_search::has_unquoted_shell_control(&segment.text)
    {
        return None;
    }
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    let hooks = match words.split_first()? {
        (&"add", rest) => add(rest).then_some(INDEX_HOOKS),
        (&"rm", rest) => rm(rest).then_some(INDEX_HOOKS),
        (&"commit", rest) => commit(rest).then_some(COMMIT_HOOKS),
        (&"branch", rest) => branch_rename(rest).then_some(BRANCH_HOOKS),
        (&"merge", rest) => merge::merge(rest).then_some(merge::HOOKS),
        (&"cherry-pick", rest) => merge::cherry_pick(rest).then_some(merge::HOOKS),
        (&"rebase", rest) => rebase::resume(rest).then_some(rebase::HOOKS),
        (&"stash", [action, rest @ ..]) if *action == "list" => {
            stash_list(rest).then_some(LIST_HOOKS)
        }
        (&"stash", [action, rest @ ..]) if *action == "show" => {
            stash_show(rest).then_some(LIST_HOOKS)
        }
        (&"stash", [action, rest @ ..]) if matches!(*action, "apply" | "pop") => {
            stash_restore(rest).then_some(CHECKOUT_HOOKS)
        }
        _ => super::super::workspace_contained::keeping_arguments(&segment.arguments)
            .then_some(CHECKOUT_HOOKS),
    };
    if let Some(hooks) = hooks {
        return Some((hooks, None));
    }
    let point = start::start_point(&segment.arguments)?;
    Some((CHECKOUT_HOOKS, Some(point.to_owned())))
}
