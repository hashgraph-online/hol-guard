//! Local Git writes that keep every change reachable: `git add`, a non-forced
//! `git rm`, `git commit -m`, a new branch at `HEAD` or at a start point that
//! replaces no untracked file, a non-forced branch rename, a plain stash push,
//! `git stash apply` or `pop` of one entry, `git stash list`, a `git merge`
//! or `git cherry-pick` (`git_local_writes_merge`) and a `git rebase` onto a
//! local ref or `--continue` (`git_local_writes_rebase`), with Git reads the configuration
//! probe proves helper-free around them.
//! On a host with a workspace sandbox the sandbox runs them contained, in a
//! main checkout or in a linked worktree whose shared Git directory it grants,
//! before this proof is asked. Some hosts have no sandbox, and a command the
//! sandbox does not take would stop at review, so the proof still answers.
//! Here the session's own Git is proven to start no program: no filter other
//! than the user's Git LFS install, no fsmonitor, configured signing, diff
//! program, lazy fetch, submodule recursion or configured hook, and none of
//! the hook files the command runs. A commit the command itself signs (`-S`)
//! must start the user's installed signing program
//! (`git_local_writes_signing`). `git rm` without `-f` refuses a file that
//! differs from `HEAD`, and a commit, branch or stash only adds history.
//! `git commit --amend` replaces the local tip, but the reflog still reaches
//! the old commit, and rewriting what a remote holds still needs a reviewed
//! forced push. `git add -f` stays reviewed: it is how an ignored secret file gets
//! staged. `git branch -M` stays reviewed: it overwrites an existing branch.
//!
//! The same chain may end by publishing that work: one `git push origin
//! <branch>` proven by the runtime push verdict, for the branch the chain
//! creates or the one checked out, and a `gh pr create` the user's GitHub
//! permissions already let run alone. Every step keeps the proof it has on
//! its own; anything else in the chain keeps the review.

use super::git_remote_config::GitConfig;
use super::git_session_probe::Probe;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeCommandPermissionObservationV1, PreToolActionTypeV1,
    PreToolResultV1,
};
use std::time::Instant;

#[path = "git_local_writes_config.rs"]
mod config;
#[path = "git_local_writes_forms.rs"]
mod forms;
#[path = "git_local_writes_hooks.rs"]
mod hooks;
#[path = "git_local_writes_merge.rs"]
mod merge;
#[path = "git_local_writes_rebase.rs"]
mod rebase;
#[path = "git_local_writes_route.rs"]
mod route;
#[path = "git_local_writes_signing.rs"]
mod signing;
#[path = "git_local_writes_start.rs"]
mod start;

use forms::{created_branch, moves_head};
use hooks::{write_hooks, CHECKOUT_HOOKS, COMMIT_HOOKS};

pub(crate) const REASON: &str = "native_exact_safe_git_local_write";
pub(crate) const PUBLISH_REASON: &str = "native_exact_safe_git_publish_chain";

/// The declarative review rules these forms may settle.
const RULES: &[&str] = &[
    "command.git.add",
    "command.git.rm",
    "command.git.commit",
    "command.git.branch",
    "command.git.switch",
    "command.git.checkout",
    "command.git.stash",
    "command.git.merge",
    "command.git.cherry-pick",
    "command.git.rebase",
];

/// The rule a proven `git push origin <branch>` step may raise.
const PUSH_RULE: &str = "command.git.push";
const PROPOSE_PERMISSION: &str = "command.github.permission.propose-remote";
const READ_PERMISSION: &str = "command.github.permission.read-remote";

/// Rules the packaged catalog ships disabled; they count only on segments
/// proven as reads (`git worktree list`), never raising a review of their own.
const READ_RULES: &[&str] = &[
    "command.git.status",
    "command.git.log",
    "command.git.diff",
    "command.git.show",
    "command.git.ls-files",
    "command.git.grep",
    "command.git.worktree",
];

/// Turn a generic review whose only matched rules are the ones above into an
/// allow when every write segment is proven and every other segment is
/// benign on its own.
pub(super) fn settle(
    result: &mut PreToolResultV1,
    pre_floor: &(String, String),
    model: Option<&CanonicalCommandV1>,
    controls: Option<&CompiledNativeCommandControls>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) {
    let reviewable = |reason: &str| {
        matches!(
            reason,
            "native_command_review_required" | "native_command_extension_review"
        )
    };
    let generic = reviewable(&result.reason_code) && result.minimum_action == "review";
    // The Git floor stands for helpers the configuration could start; the
    // probe below proves that none can.
    let git_floor = result.reason_code == "native_git_execution_context_review"
        && pre_floor.1 == "review"
        && (reviewable(&pre_floor.0) || pre_floor.0 == "native_git_helper_context_review");
    if !(generic || git_floor)
        || result.action.action_type != PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let Some(model) = model else {
        return;
    };
    let Some(published) = proven(
        result,
        model,
        controls,
        context,
        deadline,
        execution_environment,
    ) else {
        super::git_init_chain::settle(result, model, context, deadline, execution_environment);
        return;
    };
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    (result.reason_code, result.reason) = if published {
        (
            PUBLISH_REASON.into(),
            concat!(
                "The Rust command authority proved each step of this chain: the local Git ",
                "writes keep every change reachable and start no configured program or hook, ",
                "a push sends the branch the chain checks out to a credential-free GitHub ",
                "HTTPS origin, and a GitHub step is one your permissions allow on its own.",
            )
            .into(),
        )
    } else {
        (
            REASON.into(),
            concat!(
                "The Rust command authority proved this Git command only updates the local ",
                "repository, keeps every change reachable, and starts no configured program or hook.",
            )
            .into(),
        )
    };
}

/// `Some(true)` when the proven chain also pushes, `Some(false)` when it
/// only writes locally, and `None` when any step is unproven.
fn proven(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    controls: Option<&CompiledNativeCommandControls>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let extensions = result.command_extensions.as_ref()?;
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || extensions.binding.uncertainty_count != 0
        || extensions.evaluation_error.is_some()
    {
        return None;
    }
    // A `gh pr create`, or a GitHub read such as `gh pr list`, the user's
    // GitHub permissions allow on its own. Nothing else may carry a permission
    // observation, and a read still needs the read proof below.
    let granted = controls
        .map(|controls| controls.github_granted_segments(&extensions.permission_observations))
        .unwrap_or_default();
    let allowed_alone = |observation: &NativeCommandPermissionObservationV1| {
        let mut segments = observation.matcher_evidence.iter();
        matches!(
            observation.permission_id.as_str(),
            PROPOSE_PERMISSION | READ_PERMISSION
        ) && !observation.matcher_evidence.is_empty()
            && segments.all(|evidence| granted.contains(&evidence.segment_index))
    };
    if !extensions.permission_observations.iter().all(allowed_alone) {
        return None;
    }
    let proposing: Vec<usize> = extensions
        .permission_observations
        .iter()
        .filter(|observation| observation.permission_id == PROPOSE_PERMISSION)
        .flat_map(|observation| observation.matcher_evidence.iter())
        .map(|evidence| evidence.segment_index)
        .collect();
    let route = route::route(model, context)?;
    let model = route.model(model);
    let shell = context;
    let context = super::PathContext {
        cwd: route.cwd().or(context.cwd),
        ..context
    };
    let read = |index: usize, context: super::PathContext<'_>| {
        super::segment_proof::exact_safe_segment_with_context(
            model,
            &model.segments[index],
            false,
            context,
        ) || configured_read(model, index, context, deadline, execution_environment)
    };
    let mut writes: Vec<(usize, &'static [&'static str])> = Vec::new();
    let mut stashed = Vec::new();
    let mut starts = Vec::new();
    let mut safe = Vec::new();
    let mut created: Vec<(usize, &str)> = Vec::new();
    let mut moved = false;
    let mut push: Option<usize> = None;
    let mut proposal = false;
    for (index, segment) in model.segments.iter().enumerate() {
        if segment.executable.as_deref() == Some("cd") {
            if route.cd_index() != Some(index) {
                return None;
            }
            continue;
        }
        // After a `;` that follows the `cd`, a step may run in either
        // directory: only a read proven in both may.
        if route.either(index) {
            if !(read(index, context) && read(index, shell)) {
                return None;
            }
            safe.push(index);
            continue;
        }
        if let Some((hooks, point)) = write_hooks(segment) {
            if segment.arguments.first().map(String::as_str) == Some("stash") {
                stashed.push(index);
            }
            writes.push((index, hooks));
            starts.extend(point);
            match created_branch(segment) {
                Some(name) => created.push((index, name)),
                None => moved |= moves_head(segment),
            }
            continue;
        }
        // Behind `git -C` only the Git steps run in that repository; a push
        // or a GitHub step would act from the shell's directory.
        if route.chdir() && (super::git_push::chained(segment) || proposing.contains(&index)) {
            return None;
        }
        if super::git_push::chained(segment) {
            // A proposal opens the pull request for work the chain pushed.
            if proposal || push.replace(index).is_some() {
                return None;
            }
            continue;
        }
        if proposing.contains(&index) {
            proposal = true;
            continue;
        }
        // Behind `git -C`, every other step runs in the shell's directory.
        let step = if route.chdir() && segment.executable.as_deref() != Some("git") {
            shell
        } else {
            context
        };
        if !(read(index, step) || route.unlinks(model, index, shell)) {
            return None;
        }
        safe.push(index);
    }
    let written = |index: &usize| writes.iter().any(|(write, _)| write == index);
    let pushed = |index: &usize| push == Some(*index);
    // Off-by-default read rules (`command.git.status`) still record what they
    // matched; on a segment proven above they add nothing to review.
    let inert_match = |observation: &guard_contracts::NativeCommandObservationV1| {
        READ_RULES.contains(&observation.rule_id.as_str())
            && !observation.effective_segment_indexes.is_empty()
            && observation
                .matcher_evidence
                .iter()
                .map(|evidence| evidence.segment_index)
                .chain(observation.effective_segment_indexes.iter().copied())
                .all(|index| safe.contains(&index))
    };
    // A chain that publishes runs each step only after the one before it
    // succeeded: `;`, `||`, `&` or a pipe could push or propose after a failed
    // branch creation or commit.
    let published = push.is_some() || proposal;
    let and_chained = (1..model.segments.len()).all(|index| {
        super::worktree_add::separator_between(model, index - 1, index)
            .is_some_and(|separator| separator.trim() == "&&")
    });
    if (writes.is_empty() && push.is_none())
        || (published && !and_chained)
        || !extensions.observations.iter().all(|observation| {
            if observation.uncertainty_reasons.is_empty() && inert_match(observation) {
                return true;
            }
            let mut indexes = observation
                .matcher_evidence
                .iter()
                .map(|evidence| evidence.segment_index)
                .chain(observation.effective_segment_indexes.iter().copied())
                .peekable();
            let rule = observation.rule_id.as_str();
            observation.uncertainty_reasons.is_empty()
                && indexes.peek().is_some()
                && if rule == PUSH_RULE {
                    indexes.all(|index| pushed(&index))
                } else {
                    RULES.contains(&rule) && indexes.all(|index| written(&index))
                }
        })
    {
        return None;
    }
    let probe = Probe::new("git", &[], context, deadline, execution_environment)?;
    let (effective, repository) = probe.config()?;
    // A configuration included for the branch a checkout leaves would apply
    // to the reads after it without having been probed.
    let branch_scoped = writes.iter().any(|(_, hooks)| *hooks == CHECKOUT_HOOKS)
        && effective
            .keys()
            .any(|key| key.to_ascii_lowercase().starts_with("includeif.onbranch"));
    let merging = writes.iter().any(|(_, hooks)| *hooks == merge::HOOKS);
    let rebases: Vec<usize> = writes
        .iter()
        .filter(|(_, hooks)| *hooks == rebase::HOOKS)
        .map(|(index, _)| *index)
        .collect();
    let rebasing = !rebases.is_empty();
    // `commit.gpgsign` signs every commit Git creates, so a commit then runs
    // the signing program as if it had asked with `-S`. Merges and rebases
    // already refuse it through `merge::inert`.
    let committing = writes.iter().any(|(_, hooks)| *hooks == COMMIT_HOOKS);
    let signs = (committing && signs_by_default(&effective))
        || writes
            .iter()
            .any(|(index, _)| forms::signs(&model.segments[*index]));
    let (external_off, textconv_off) = config::diff_drivers_disarmed(model, &writes, &stashed);
    if branch_scoped
        || !config::inert_with(&effective, &repository, external_off, textconv_off)
        || ((merging || rebasing) && !merge::inert(&effective, &repository))
        || !rebases
            .iter()
            .all(|index| rebase::proven(&probe, &model.segments[*index], &effective))
        || (signs
            && !signing::trusted(
                &effective,
                &repository,
                &probe.home,
                &probe.cwd,
                execution_environment,
            ))
        || forms::aliased(&effective, model)
        || !probe.hooks_inert(writes.iter().flat_map(|(_, hooks)| hooks.iter().copied()))
        || !stashed.iter().all(|index| {
            forms::stash_free(
                &effective,
                model,
                *index,
                context,
                deadline,
                execution_environment,
            )
        })
        || !starts
            .iter()
            .all(|point| start::replaces_nothing(&probe, point))
    {
        return None;
    }
    let Some(push) = push else {
        return Some(published);
    };
    // A rename or a switch to another branch would change what the push
    // sends after the verdict saw the checkout.
    if moved {
        return None;
    }
    // The push sends the branch the chain checks out: the one it creates, or
    // with no creation the one checked out now. A creation after the push or a
    // second one would leave a different branch checked out than the verdict saw.
    let created = match created.as_slice() {
        [] => None,
        [(index, name)] if *index < push => Some(*name),
        _ => return None,
    };
    super::git_push::chained_push_proven(
        &model.segments[push],
        context,
        deadline,
        execution_environment,
        created,
    )
    .then_some(true)
}

/// A Git read whose configuration the session probe proves starts no
/// helper. The writes proven here change no configuration it reads.
pub(in crate::pretool) fn configured_read(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let original = &model.segments[index];
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    segment.executable.as_deref() == Some("git")
        && identity_only(segment)
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && super::directory_targets::drive_targets_quoted(segment)
        && super::git_config::execution_free(
            "git",
            &segment.arguments,
            context,
            deadline,
            execution_environment,
            super::git_helper_context::stdout_piped(model, index),
        ) == Some(true)
        && super::git_reads::safe_git_arguments(&segment.arguments, true, context)
}

/// `git add` or an unsigned `git commit -m` in a form proven here, given the
/// words after `git`; the steps `git_init_chain` runs in a new repository.
pub(in crate::pretool) fn index_or_commit(words: &[&str]) -> bool {
    match words.split_first() {
        Some((&"add", rest)) => forms::add(rest),
        Some((&"commit", rest)) => forms::commit_form(rest) == Some(false),
        _ => false,
    }
}

/// Whether every setting in front of the Git step only names the commit
/// identity or adjusts output; none can choose a program Git runs.
fn identity_only(segment: &CommandSegmentV1) -> bool {
    segment
        .environment_names
        .iter()
        .all(|name| crate::command_compatibility::inert_git_environment_name(name))
}

/// Whether the effective configuration signs commits without `-S`.
pub(in crate::pretool) fn signs_by_default(effective: &GitConfig) -> bool {
    effective.get("commit.gpgsign").is_some_and(|values| {
        values
            .iter()
            .any(|value| !super::git_remote_ops::pull::disabled(value))
    })
}

/// Whether the effective configuration lets these writes start no program.
/// Commit signing is left to the caller: only a write that creates a commit
/// runs the signing program, and [`signs_by_default`] reports it.
pub(in crate::pretool) fn inert(effective: &GitConfig, repository: &GitConfig) -> bool {
    config::inert_with(effective, repository, false, false)
}
