//! `git worktree add <path> <ref> && cd <path> && git log ...`: Git reads in
//! the checkout the same command creates.
//!
//! A linked worktree shares its repository's configuration, hooks and object
//! store. The worktree proof already rejects per-worktree configuration
//! (`extensions.*`), every include (so no `includeIf "gitdir:..."` can
//! select other settings for the new path), `core.fsmonitor`, and filters
//! the checked-out tree could select. A read the configuration probe proves
//! helper-free in the repository is therefore helper-free in the new
//! checkout too. Anything else after the `cd` (a write, a push, a path read
//! the repository's own copy could not stand in for) keeps its review.
//!
//! `git worktree add <path> <ref> && git -C <path> status` is the same work
//! without the `cd`: each read, and the branch the chain creates, names the
//! new checkout with `-C`, and only a proven `mkdir` may run between them,
//! in the shell's own directory.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

/// Whether the whole command is proven `origin` fetches, one proven
/// `git worktree add`, a `cd` into exactly the checkout it creates, and
/// proven Git reads there with bounded `head`, `tail` and `wc` stages. The
/// result is memoized so the Git read floor reuses this proof instead of
/// probing again.
pub(in super::super) fn proven(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || worktree_index(model).is_none()
    {
        return false;
    }
    let key = (
        format!("\0worktree-chain:{}", model.normalized_text),
        Vec::new(),
        context.home_dir.map(str::to_owned),
        context.cwd.map(str::to_owned),
        false,
    );
    super::super::git_probe::memoized(key, || {
        Some(prove(model, context, deadline, execution_environment))
    }) == Some(true)
}

/// The `git worktree add` segment directly followed by a `cd`, a routed
/// `git -C` read, a `mkdir`, or an `ln`.
fn worktree_index(model: &CanonicalCommandV1) -> Option<usize> {
    let index = model.segments.iter().position(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|value| super::super::executable_basename(value) == "git")
            && super::parse(segment).is_some()
    })?;
    let next = model.segments.get(after_creation(model, index))?;
    (matches!(next.executable.as_deref(), Some("cd" | "mkdir" | "ln"))
        || super::chain_route::routed_position(next).is_some())
    .then_some(index)
}

/// The segment after the `git worktree add` and the stages of its own
/// pipeline. `git worktree add ... 2>&1 | tail -3` reports what the add
/// printed; the checkout it creates is the same one either way.
fn after_creation(model: &CanonicalCommandV1, add: usize) -> usize {
    let mut index = add + 1;
    while model
        .segments
        .get(index)
        .is_some_and(|segment| segment.pipeline_index > 0)
    {
        index += 1;
    }
    index
}

#[path = "worktree_add_chain_leading.rs"]
mod leading;

#[path = "worktree_add_chain_proof.rs"]
mod proof;
use proof::prove;

/// `git -C <checkout> <step>`: the read or new branch Git runs after
/// entering the new checkout, proven as the same step without `-C` in its
/// repository. Agents write the whole setup this way as readily as with a
/// `cd`, and `-C` reaches exactly the directory the `cd` would enter.
fn routed_step(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
    repository: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(position) = new_checkout_route(model, index, context) else {
        return false;
    };
    let mut stripped = model.clone();
    stripped.segments[index]
        .arguments
        .drain(position..position + 2);
    super::chain_route::new_branch_step(&stripped.segments[index])
        || super::chain_route::unrouted_read(
            &stripped,
            index,
            repository,
            deadline,
            execution_environment,
        )
}

/// The position of segment `index`'s `-C` when it routes Git into the
/// checkout an earlier `git worktree add` of the same command creates. The
/// spelling is compared before that directory exists, so no route check
/// that needs an existing directory can stand in for it.
pub(crate) fn new_checkout_route(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
) -> Option<usize> {
    let add = worktree_index(model)?;
    let segment = model.segments.get(index).filter(|_| index > add)?;
    let position = super::chain_route::routed_position(segment)?;
    let (_, destination, _) = super::planned_checkout(&model.segments[add], context)?;
    (super::super::directory_targets::home_targets_unquoted(segment)
        && super::chain_route::dash_c_target(&segment.arguments[position + 1], context)
            == Some(destination))
    .then_some(position)
}

/// The `cd` segments that enter exactly the checkout an earlier
/// `git worktree add` of the same command creates, when every command after
/// them is `git` or `gh`, or an action the user's own permission covers.
///
/// Entering the new checkout is what `git -C <path>` does for one step, so an
/// extension Allow that covers the add and each Git or GitHub step after it
/// covers the `cd` as well; those steps keep their own rules and floors.
/// Their repository is the same one either way, because a linked worktree
/// shares it.
///
/// `permitted` names the other steps whose own permission the user enabled:
/// an extension action such as a model runner's `rm`. The user's consent to
/// that action does not depend on the directory it runs in, so it may follow
/// the `cd` too, when its shape names nothing the `cd` could change (see
/// `chain_route::permitted_step_shape`). Any other command after the `cd`
/// (a path read, a write, a build) would have its paths judged against the
/// shell's directory instead of the checkout, so it leaves the `cd` uncovered
/// and the command keeps its review.
///
/// The bounded `head`, `tail` or `wc` stages of the steps after the `cd` are
/// named too. They read only what the stage before them prints and name no
/// path, so the directory they run in does not matter; the general proof,
/// which follows no `cd` after the first step, would leave them uncovered
/// where their `git -C` twins are not.
pub(crate) fn entered_checkouts(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    permitted: &dyn Fn(usize) -> bool,
) -> Vec<usize> {
    let Some((_, cd, _)) = entered_checkout(model, context, execution_environment, permitted)
    else {
        return Vec::new();
    };
    // A `git` or `gh` stage keeps its own permission; only the stages that
    // read standard input are named here.
    let stage = |index: &usize| {
        model.segments[*index].pipeline_index > 0
            && super::chain_route::stdin_stage(
                &model.segments[*index],
                context,
                execution_environment,
            )
    };
    std::iter::once(cd)
        .chain((cd + 1..model.segments.len()).filter(stage))
        .collect()
}

/// Whether the command's Git after the `cd` that [`entered_checkouts`] names
/// may be probed in the shell's own directory: the add takes no `-C` and the
/// worktree proof holds for it. That proof rejects per-worktree
/// configuration, every include and any filter the checked-out tree could
/// select, so the new checkout reads the same configuration as the
/// repository it shares, and a read helper-free here is helper-free there.
///
/// This floor reads no extension controls, so it lets through any step of
/// the shape a permission may cover after the `cd`. That only places the
/// probe. A step the floor cannot prove leaves the read unsettled, and only an
/// Allow settles it; that Allow must cover the step, which
/// [`entered_checkouts`] answers with the user's permissions in hand.
pub(in super::super) fn reads_in_entered_checkout(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<EnteredReads> {
    let left_to_the_allow = |_: usize| true;
    let (add, _, entry) =
        entered_checkout(model, context, execution_environment, &left_to_the_allow)?;
    let start = usize::from(entry.is_some());
    let context = super::super::PathContext {
        cwd: entry.as_deref().or(context.cwd),
        ..context
    };
    // Anything before the add may move the start point, so the proof then
    // admits only the standard LFS filter. A proven leading `cd` moves
    // nothing: it names a directory and stops.
    matches!(
        super::proven_checkout(
            &model.segments[add],
            add > start,
            context,
            deadline,
            execution_environment,
        ),
        Some((_, None, _))
    )
    .then_some(EnteredReads { cwd: entry })
}

/// An entered-checkout chain whose Git reads this floor may probe, and the
/// directory a proven leading `cd` moved them into.
pub(in super::super) struct EnteredReads {
    pub(in super::super) cwd: Option<String>,
}

/// The `git worktree add` and the `cd` into the checkout it creates, as
/// [`entered_checkouts`] describes them.
fn entered_checkout(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    permitted: &dyn Fn(usize) -> bool,
) -> Option<(usize, usize, Option<String>)> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    // `cd <repository> && git worktree add ...` sets the new checkout up
    // from another one. The leading `cd` names a directory and stops, and
    // `&&` carries the add only once it succeeded, so the add resolves its
    // destination there.
    let entry = leading::leading_entry(model, context);
    let start = usize::from(entry.is_some());
    let context = super::super::PathContext {
        cwd: entry.as_deref().or(context.cwd),
        ..context
    };
    let is = |segment: &CommandSegmentV1, names: &[&str]| {
        segment.executable.as_deref().is_some_and(|value| {
            let basename = super::super::executable_basename(value);
            names.contains(&basename)
        })
    };
    for (add, segment) in model.segments.iter().enumerate().skip(start) {
        // The add resolves its destination against the reported cwd, which
        // is the shell's directory only until something changes it.
        if is(segment, &["cd", "pushd", "popd"]) {
            return None;
        }
        if segment.pipeline_index != 0 || !is(segment, &["git"]) {
            continue;
        }
        let Some((spec, destination, chdir)) = super::planned_checkout(segment, context) else {
            continue;
        };
        // After the `cd` the shell looks up `git` and `gh` again, and a
        // search path entry that is relative, or that names a folder of the
        // new checkout, then resolves to what the ref it checks out supplies.
        if !super::search_path::search_path_outside(&destination, execution_environment) {
            return None;
        }
        let after = after_creation(model, add);
        let next = model.segments.get(after)?;
        if next.executable.as_deref() != Some("cd") || next.pipeline_index != 0 {
            return None;
        }
        let joined = super::separator_between(model, after - 1, after)
            .as_deref()
            .map(str::trim)
            .is_some_and(|separator| matches!(separator, "&&" | ";"));
        // A later pipeline stage reads only what the step before it prints:
        // a bounded `head`, `tail` or `wc` with no path of its own.
        // A permitted action must also have a shape whose meaning the `cd`
        // cannot change (see `chain_route::permitted_step_shape`). A bare
        // word it takes is judged against the shell's directory but opened in
        // the checkout, so it must name nothing the checkout holds: no entry
        // of the tree the add checks out, which every step before it left
        // unchanged. Anything before the add may move that reference.
        let permitted_action = |index: usize, later: &CommandSegmentV1| {
            if !super::chain_route::permitted_step_shape(later) || !permitted(index) {
                return false;
            }
            let names = super::chain_route::bare_names(later);
            if names.is_empty() {
                return true;
            }
            add == start
                && model.segments[after + 1..index]
                    .iter()
                    .all(|step| !super::super::tree_writers::may_rewrite_tree(step))
                && super::super::git_worktree::tree_names_any(
                    segment.executable.as_deref().unwrap_or("git"),
                    &spec.leading,
                    spec.reference.unwrap_or("HEAD"),
                    &names,
                    super::super::PathContext {
                        cwd: chdir.as_deref().or(context.cwd),
                        ..context
                    },
                    execution_environment,
                ) == Some(false)
        };
        let rest_is_git = model.segments[after + 1..]
            .iter()
            .enumerate()
            .all(|(offset, later)| {
                super::chain_route::resolved_outside(later, &destination)
                    && (is(later, &["git", "gh"])
                        || super::chain_route::inert_step(later)
                        || permitted_action(after + 1 + offset, later)
                        || (later.pipeline_index > 0
                            && super::chain_route::stdin_stage(
                                later,
                                context,
                                execution_environment,
                            )))
            });
        // If the add fails, the `cd` fails too and a `git` or `gh` step after
        // `;` runs in the original checkout, judged by its own permission with
        // its reads probed there. No proof here follows `||`.
        let sequenced = (after + 1..model.segments.len()).all(|index| {
            super::separator_between(model, index - 1, index)
                .as_deref()
                .map(str::trim)
                .is_some_and(|separator| matches!(separator, "&&" | "|" | ";"))
        });
        return (joined
            && rest_is_git
            && sequenced
            && super::chain_route::cd_target(next, context).as_ref() == Some(&destination))
        .then_some((add, after, entry.clone()));
    }
    None
}

/// The declarative review rules a proven chain's own steps may raise. The
/// chain proof above constrains every segment, so a rule here can only have
/// matched a step it proved: `command.git.worktree` the bounded add,
/// `command.git.fetch` an `origin` fetch before it, and
/// `command.git.checkout` or `command.git.switch` the one shape
/// [`chain_route::new_branch_step`] admits, `-b`/`-c` with a single new
/// branch name and nothing else.
const RULES: &[&str] = &[
    "command.git.worktree",
    "command.git.fetch",
    "command.git.checkout",
    "command.git.switch",
];

/// Turn the catalog's generic review of a proven chain into an allow.
///
/// [`super::exact_safe_command`] already allows this command inside
/// `pretool::decide`, but a packaged rule whose own mode reviews — the
/// catalog ships `command.git.checkout` and `command.git.switch` that way —
/// raises a floor over that allow afterwards, so a chain that creates its
/// branch in the checkout it just made still stopped at review. Only the
/// chain's own rules are lifted: another rule that asks for more than allow,
/// a permission the user keeps under review, a disabled extension and any
/// uncertain match keep their verdict.
pub(in crate::pretool) fn settle(
    result: &mut guard_contracts::PreToolResultV1,
    model: Option<&CanonicalCommandV1>,
    controls: Option<&crate::native_command_controls::CompiledNativeCommandControls>,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) {
    if result.minimum_action != "review"
        || !matches!(
            result.reason_code.as_str(),
            "native_command_review_required" | "native_command_extension_review"
        )
        || result.action.action_type != guard_contracts::PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let Some(model) = model else {
        return;
    };
    let Some(extensions) = result.command_extensions.as_ref() else {
        return;
    };
    if extensions.binding.uncertainty_count != 0
        || extensions.evaluation_error.is_some()
        || !extensions
            .permission_observations
            .iter()
            .all(|observation| {
                observation.uncertainty_reasons.is_empty()
                    && controls.is_some_and(|controls| {
                        controls.permission_settles_at_allow(
                            &observation.extension_id,
                            &observation.permission_id,
                        )
                    })
            })
        || !extensions.observations.iter().all(|observation| {
            observation.uncertainty_reasons.is_empty()
                && (RULES.contains(&observation.rule_id.as_str())
                    || controls.is_some_and(|controls| {
                        controls.rule_settles_at_allow(&observation.rule_id)
                    }))
        })
    {
        return;
    }
    if !proven(model, context, deadline, execution_environment) {
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = "native_exact_safe_worktree_add".into();
    result.reason = concat!(
        "The Rust command authority proved this bounded worktree creation has a fresh ",
        "contained destination, a local ref, and no executable Git routes.",
    )
    .into();
}
