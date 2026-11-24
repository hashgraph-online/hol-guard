//! The Git execution-context floor for reads the native proofs allowed.
//!
//! A Git read can run a configured pager, diff driver or textconv helper. The
//! configuration probe proves a single read helper-free; a read later in a
//! compound command keeps that proof only when nothing before it could have
//! changed the configuration it reads.
use crate::CanonicalCommandV1;
use std::time::Instant;

/// Whether a Git read in the command needs review before it runs.
pub(super) fn requires_review(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    !matches!(
        verdict(model, context, deadline, execution_environment),
        Verdict::Clear
    )
}

/// Whether the segment is the patch check. The check is not a read this floor
/// owns: it prints its report whatever the configuration says, and the helper
/// proof answers for the index it refreshes. An unprovable configuration
/// therefore leaves the check its own review floor rather than this one's.
fn patch_check(arguments: &[String], context: super::PathContext<'_>) -> bool {
    crate::command_compatibility::git_inspection_arguments(arguments, context)
        .and_then(|remaining| remaining.first())
        .is_some_and(|operation| operation.as_str() == "apply")
}

/// The earlier steps that alone keep the command's Git reads under the
/// floor: every Git read was proven helper-free, but a step before it could
/// not be proven to leave Git's configuration unchanged. Run alone, each read
/// keeps its own proof, so the review reason can say so.
pub(super) fn unsettled_steps_before_reads(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<Vec<usize>> {
    match verdict(model, context, deadline, execution_environment) {
        Verdict::Unsettled(steps) => Some(steps),
        Verdict::Clear | Verdict::Review(_) | Verdict::UnansweredProbe(_) => None,
    }
}

/// What an explicit user allow for the command's Git reads could settle in
/// this floor. Both answers name a question the allow itself answers; every
/// other review cause stands whatever the user allowed.
pub(super) enum AllowableReview {
    /// Nothing an allow answers: the command is clear, or its review has
    /// another cause.
    None,
    /// Every Git read was proven helper-free on its own. Only these earlier
    /// steps, by index into the model, kept that proof from carrying over.
    EarlierSteps(Vec<usize>),
    /// A Git read was left unproven by a probe that could not answer. The
    /// allow says to run the read as this checkout configures it, so long as
    /// these earlier steps, by index into the model, leave the configuration
    /// the read is allowed to run under alone.
    UnansweredProbe(Vec<usize>),
}

/// The part of this floor's verdict an explicit user allow may settle.
pub(super) fn allowable_review(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> AllowableReview {
    match verdict(model, context, deadline, execution_environment) {
        Verdict::Unsettled(steps) => AllowableReview::EarlierSteps(steps),
        Verdict::UnansweredProbe(steps) => AllowableReview::UnansweredProbe(steps),
        Verdict::Review(ReviewCause::UnansweredProbe) => {
            AllowableReview::UnansweredProbe(Vec::new())
        }
        Verdict::Clear | Verdict::Review(ReviewCause::Other) => AllowableReview::None,
    }
}

/// Step indexes of the model after a leading `cd`, as indexes into the
/// model that still holds the `cd`.
fn shifted_past_cd(steps: Vec<usize>) -> Vec<usize> {
    steps.into_iter().map(|index| index + 1).collect()
}

/// One segment's configuration proof: what it answered, and whether a
/// refusal was an unanswered probe rather than a helper it found.
#[derive(Clone, Copy)]
struct Inspection {
    answer: Option<bool>,
    unanswered: bool,
}

enum Verdict {
    Clear,
    Review(ReviewCause),
    /// Only the order failed: these earlier steps, by index into the model.
    Unsettled(Vec<usize>),
    /// A probe that could not answer left a Git read unproven, and these
    /// earlier steps, by index into the model, were not proven to leave the
    /// configuration that read runs under alone. An allow for the read
    /// answers the probe, but only where it also settles those steps.
    UnansweredProbe(Vec<usize>),
}

/// Why a Git read needs review.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReviewCause {
    /// The configuration probe could not answer for a Git read, so the read
    /// is unproven without anything having been found against it. A user who
    /// allowed that read answered this question: run it as this checkout
    /// configures it. A helper the probe actually read out of the
    /// configuration is a program Guard cannot see, and is `Other`.
    UnansweredProbe,
    /// Anything else: a step that moves the reads somewhere the probe never
    /// looked, an environment name that changes what Git runs, an unquoted
    /// drive target. Allowing the read says nothing about these.
    Other,
}

impl Verdict {
    /// The review cause, or `None` when the verdict is clear. Steps unsettled
    /// inside a sub-model are indexes into that model rather than this one,
    /// so they cannot be carried out of a nested verdict; they keep the
    /// review they already produced, with no cause an allow answers.
    fn cause(self) -> Option<ReviewCause> {
        match self {
            Self::Clear => None,
            Self::Review(cause) => Some(cause),
            Self::Unsettled(_) => Some(ReviewCause::Other),
            Self::UnansweredProbe(steps) if steps.is_empty() => Some(ReviewCause::UnansweredProbe),
            Self::UnansweredProbe(_) => Some(ReviewCause::Other),
        }
    }

    /// The verdict for a command that needs review when any of these parts
    /// does. The allow answers for it only where every part that needs review
    /// needs it for the one reason the allow covers.
    fn from_parts(parts: impl IntoIterator<Item = Self>) -> Self {
        parts
            .into_iter()
            .filter_map(Self::cause)
            .reduce(|left, right| {
                if left == ReviewCause::UnansweredProbe && right == ReviewCause::UnansweredProbe {
                    ReviewCause::UnansweredProbe
                } else {
                    ReviewCause::Other
                }
            })
            .map_or(Self::Clear, Self::Review)
    }
}

fn verdict(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Verdict {
    // Reads in a checkout the same command creates were proven against the
    // repository whose configuration the new worktree shares; reads after a
    // proven worktree removal were each proven helper-free on their own.
    if super::worktree_add::chain::proven(model, context, deadline, execution_environment)
        || super::worktree_maintenance::chain::proven(
            model,
            context,
            deadline,
            execution_environment,
        )
    {
        return Verdict::Clear;
    }
    // A proven `origin` refresh or fast-forward of one answers for its whole
    // chain: it starts no hook, filter or transport program, and the Git
    // reads standing beside it were each proven helper-free in the directory
    // it runs in. Those reads keep that proof, so the fetch or merge before
    // them is not an unsettled step.
    if super::git_remote_ops::exact_safe_command(model, context, deadline, execution_environment)
        .is_some()
    {
        return Verdict::Clear;
    }
    // A proven read prefix holds no Git segment and changes nothing a later
    // read depends on, so the floor judges the command from its `cd` onward.
    if let Some(rest) = super::segment_proof::after_read_prefix(model, context) {
        return Verdict::from_parts([verdict(&rest, context, deadline, execution_environment)]);
    }
    if let Some(rest) = after_git_read_prefix(model, context, deadline, execution_environment) {
        return Verdict::from_parts([verdict(&rest, context, deadline, execution_environment)]);
    }
    // After `cd <dir>;` the rest runs in either directory, so each Git read
    // must be helper-free in both.
    if let Some((cwd, rest)) = super::safe_reads::leading_semicolon_cd(model, context) {
        let moved = super::PathContext {
            cwd: Some(&cwd),
            ..context
        };
        return Verdict::from_parts([
            verdict(&rest, moved, deadline, execution_environment),
            verdict(&rest, context, deadline, execution_environment),
        ]);
    }
    // `cd <dir> && <head>; <tail>`: the head runs only in `<dir>`, the tail
    // after it there or alone in the original directory when the `cd` failed.
    if let Some((cwd, rest, tail)) = super::safe_reads::leading_and_cd(model, context) {
        let moved = super::PathContext {
            cwd: Some(&cwd),
            ..context
        };
        let head = verdict(&rest, moved, deadline, execution_environment);
        let after = verdict(&tail, context, deadline, execution_environment);
        // `cd <dir> && git add <file> && git status; echo "exit $?"`: when
        // the whole tail is the trailing report, only the head's earlier
        // steps keep its reads under the floor. The head holds every segment
        // after the `cd`, so its step indexes name this model's segments one
        // place later, and an allow is asked the same question it would be
        // asked without the tail. Any other tail keeps the review: the read
        // directory an allow settles in resolves through the `cd` only when
        // the tail is that report.
        let reported = super::contained_wrapper::trailing_report_steps(model, &model.segments, 1);
        if matches!(after, Verdict::Clear)
            && reported > 0
            && reported == tail.segments.len()
            && !tail
                .segments
                .iter()
                .any(super::git_read_after_allow::git_segment)
        {
            match head {
                Verdict::Unsettled(steps) => {
                    return Verdict::Unsettled(shifted_past_cd(steps));
                }
                Verdict::UnansweredProbe(steps) if !steps.is_empty() => {
                    return Verdict::UnansweredProbe(shifted_past_cd(steps));
                }
                _ => {}
            }
        }
        return Verdict::from_parts([head, after]);
    }
    // Past this point every Git read is probed in one directory, so a later
    // `cd` moves reads somewhere this probe never looked. The exception is
    // `git worktree add <path> && cd <path> && ...` with only Git and GitHub
    // after: that Git runs in a worktree proven to share this configuration.
    let entered = super::worktree_add::chain::reads_in_entered_checkout(
        model,
        context,
        deadline,
        execution_environment,
    );
    if entered.is_none() && git_after_later_cd(model) {
        return Verdict::Review(ReviewCause::Other);
    }
    // `cd ../app && git status` runs the read in `../app`, so it is probed
    // there. The `cd` itself writes nothing a later read could pick up.
    // An entered-checkout chain carries its own directory: the one a proven
    // leading `cd` moved it into, or the shell's own.
    let destination = match &entered {
        Some(reads) => reads.cwd.clone(),
        None => super::segment_proof::git_read_cwd_compound_context(model, context),
    };
    let read_context = super::PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    let benign = super::segment_proof::benign_command_segments(model, context);
    // `git merge-base ... | xargs git log` runs its Git read as the child, so
    // that stage is judged as the Git command it runs.
    let children: Vec<Option<crate::CommandSegmentV1>> = (0..model.segments.len())
        .map(|index| super::fanout_reads::git_xargs_child(model, index))
        .collect();
    let segments: Vec<&crate::CommandSegmentV1> = model
        .segments
        .iter()
        .zip(&children)
        .map(|(segment, child)| child.as_ref().unwrap_or(segment))
        .collect();
    // A trailing `2>&1` is a redirect, not a Git argument.
    let arguments: Vec<Vec<String>> = segments
        .iter()
        .map(|segment| {
            super::segment_proof::without_stderr_merge(segment)
                .map_or_else(|| segment.arguments.clone(), |stripped| stripped.arguments)
        })
        .collect();
    let proofs: Vec<Inspection> = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let answer = segment
                .executable
                .as_deref()
                .filter(|executable| super::executable_basename(executable) == "git")
                .filter(|_| !patch_check(&arguments[index], read_context))
                .and_then(|executable| {
                    // Git dies in its own setup on a `-C` target holding no
                    // repository, before reading a pager, textconv or filter
                    // setting, and the probe cannot answer there either.
                    // Operations that keep running without a repository, and
                    // inline `-c` settings, stay probed; the binary the
                    // search path finds must still be a trusted one.
                    if super::git_helper_context::routes_to_no_repository(
                        segments[index],
                        read_context,
                    ) {
                        // An untrusted launch is a program Guard cannot see,
                        // not a question left open, so it is never unanswered.
                        return Some(super::git_config::trusted_launch(
                            executable,
                            read_context,
                            execution_environment,
                        ));
                    }
                    super::git_config::execution_free(
                        executable,
                        &arguments[index],
                        read_context,
                        deadline,
                        execution_environment,
                        super::git_helper_context::stdout_piped(model, index),
                    )
                });
            // Only a refusal has a cause worth telling apart, and the two
            // calls share one probe memo, so this starts no second probe.
            let unanswered = answer == Some(false)
                && segment.executable.as_deref().is_some_and(|executable| {
                    !super::git_helper_context::routes_to_no_repository(
                        segments[index],
                        read_context,
                    )
                    // Every way the probe refuses before it reaches the
                    // configuration -- a home or working directory it cannot
                    // resolve, a `-C ~` target under another home, an
                    // environment it cannot vouch for, a Git binary it does
                    // not trust -- is a program or a layout Guard cannot see,
                    // not a question left open, so it is never unanswered.
                    && super::git_config::trusted_launch(
                        executable,
                        read_context,
                        execution_environment,
                    )
                    && super::git_config::probe_unanswered(
                        executable,
                        &arguments[index],
                        read_context,
                        deadline,
                        execution_environment,
                        super::git_helper_context::stdout_piped(model, index),
                    )
                });
            Inspection { answer, unanswered }
        })
        .collect();
    let inspections: Vec<Option<bool>> = proofs.iter().map(|proof| proof.answer).collect();
    // Exact models carry no file redirects, and a proof admits a file writer
    // only as the whole command, so a proven segment before a read wrote
    // nothing. Its own read may still lack the path proof that `benign`
    // needs (a bare `ls`); that is decided separately.
    let write_free = |segment: &crate::CommandSegmentV1| {
        model.confidence == "exact"
            && !model.path_overridden
            && model.wrapper_chain.is_empty()
            && !segment.path_overridden
            && segment.wrapper_chain.is_empty()
            && super::segment_proof::exact_safe_segment_with_context(
                model,
                segment,
                false,
                read_context,
            )
    };
    // A proven Git read, `origin` fetch or worktree add writes no
    // configuration, so it cannot change what a later read in the same
    // command would run. A proven dependency link settles only Git reads
    // that run no configured helper whatever the configuration holds: the
    // link can make a configuration include, or a `-C` route, reachable that
    // the probe never read.
    let link_settles = segments.iter().all(|segment| {
        segment
            .executable
            .as_deref()
            .is_none_or(|executable| super::executable_basename(executable) != "git")
            || super::symlink_writes::current_branch_read(segment, read_context)
    });
    // A reader whose operand sits outside the workspace fails the disclosure
    // proofs above, yet writes nothing. `creates_nothing` is a narrow write
    // proof: no redirect, wrapper chain or `PATH` override, and only programs
    // with no option naming a file to write, by bare name (`./echo` is
    // local). Excluded: `cd`, moving the directory the checks above account
    // for, and `rg`, running a caller-chosen program (`--pre`). A `find`
    // whose expression holds no action walks its roots and prints names,
    // wherever the roots are.
    let writes_nothing = |segment: &crate::CommandSegmentV1| {
        segment.executable.as_deref().is_some_and(|executable| {
            super::executable_basename(executable) == executable
                && !matches!(executable, "cd" | "rg")
        }) && !segment.path_overridden
            && segment.wrapper_chain.is_empty()
            && segment.environment_names.is_empty()
            && (super::search::grep::creates_nothing(segment)
                || super::write_free_steps::writes_nothing(segment, read_context))
    };
    let settled = |prior: usize, later: &crate::CommandSegmentV1| {
        let segment = segments[prior];
        if shell_local_assignment(segment) {
            return true;
        }
        // A step that changes shell state (an assignment, `export`, `source`,
        // `printf -v` or `%n`, arithmetic like `$((PATH=10))`) can name the
        // configuration Git reads; the proofs below answer only for what a
        // step writes to disk. `cd` is checked above instead.
        if super::shell_arithmetic::arithmetic_assigns(&segment.text)
            || super::printf_words::printf_sets_variable(segment)
            || segment
                .environment_names
                .iter()
                .any(|name| !crate::command_compatibility::inert_git_environment_name(name))
            || (segment.executable.as_deref() != Some("cd")
                && super::control_flow_flatten::command_word_changes_shell_state(&segment.text))
        {
            return false;
        }
        benign.contains(&prior)
            || (prior == 0 && destination.is_some())
            || write_free(segment)
            || writes_nothing(segment)
            || (link_settles
                && super::symlink_writes::safe_symlink_arguments(segment, read_context))
            || super::git_remote_ops::verified_refresh(
                segment,
                later,
                read_context,
                deadline,
                execution_environment,
            )
            || super::git_remote_ops::verified_refresh(
                segment,
                later,
                context,
                deadline,
                execution_environment,
            )
            || super::worktree_add::proven_alone(
                model,
                prior,
                read_context,
                deadline,
                execution_environment,
                // Anything that ran before the add, a `git fetch` above all,
                // can have moved the reference it names, so the tree it
                // checks out is not the one the proof reads.
                prior > 0,
            )
            || (inspections[prior] == Some(true)
                && segment.environment_names.is_empty()
                && (super::git_reads::safe_git_arguments(&arguments[prior], true, read_context)
                    || super::git_reads::inspection_writes_nothing(
                        &arguments[prior],
                        read_context,
                    )))
    };
    let mut unsettled = Vec::new();
    let mut refused: Option<ReviewCause> = None;
    for (index, segment) in segments.iter().enumerate() {
        let git = segment
            .executable
            .as_deref()
            .is_some_and(|executable| super::executable_basename(executable) == "git");
        if !git {
            continue;
        }
        let inspection = inspections[index];
        // Inert names (`CI`, `LANG`, ...) and the commit identity change
        // no Git behavior, so the segment keeps its own permission decision.
        if segment
            .environment_names
            .iter()
            .any(|name| !crate::command_compatibility::inert_git_environment_name(name))
            || !super::directory_targets::drive_targets_quoted(segment)
        {
            return Verdict::Review(ReviewCause::Other);
        }
        // A refused read either runs a helper the probe read out of the
        // configuration, which no allow answers for, or was left unproven by
        // a probe that could not answer, which the read's own allow does.
        // Every refusal in the command is weighed, because one read whose
        // helper Guard found is reason enough for the whole command: stopping
        // at the first refusal would let an unanswered probe in an earlier
        // step hand the allow a helper found in a later one.
        if inspection == Some(false) {
            let cause = if proofs[index].unanswered {
                ReviewCause::UnansweredProbe
            } else {
                ReviewCause::Other
            };
            refused = Some(match refused {
                Some(ReviewCause::Other) => ReviewCause::Other,
                _ => cause,
            });
        }
        // Only inspection operations have a configuration proof to
        // invalidate. Other Git operations retain their own native
        // review/permission floors, not this read floor.
        if inspection.is_some() {
            unsettled.extend((0..index).filter(|prior| !settled(*prior, segment)));
        }
    }
    unsettled.sort_unstable();
    unsettled.dedup();
    // An allow that answers an unanswered probe runs the read as this
    // checkout configures it, so the steps before it must be proven to leave
    // that configuration alone. Carrying them out keeps a `git config` write
    // ahead of the read from riding the allow.
    if let Some(cause) = refused {
        return match cause {
            ReviewCause::Other => Verdict::Review(ReviewCause::Other),
            ReviewCause::UnansweredProbe => Verdict::UnansweredProbe(unsettled),
        };
    }
    if unsettled.is_empty() {
        Verdict::Clear
    } else {
        Verdict::Unsettled(unsettled)
    }
}

#[path = "git_read_floor_prefix.rs"]
mod prefix;
use prefix::{after_git_read_prefix, git_after_later_cd};

/// `dir=/tmp/work` or `dir="$HOME/work"` on its own: a plain shell variable
/// the command sets for its own later words.
///
/// A lowercase name is not one Git, or anything Git starts, reads from its
/// environment, and [`super::generic::chain_literals::ordinary_name`] refuses the ones
/// a shell ties to its own state (zsh's `path`, `cdpath`, `fpath`) or that
/// name a proxy or a credential. Only a bare assignment counts: no command
/// word, so nothing runs with it in its environment. The value is a literal
/// path or a double-quoted `$HOME` root, so no substitution, arithmetic or
/// subscript runs while it is set. An uppercase name keeps the review, since
/// one already exported (`GIT_DIR`, `PAGER`) would reach Git.
fn shell_local_assignment(segment: &crate::CommandSegmentV1) -> bool {
    let text = segment.text.trim();
    let Some((name, value)) = text.split_once('=') else {
        return false;
    };
    let value = ["\"$HOME/", "\"${HOME}/"]
        .iter()
        .find_map(|root| value.strip_prefix(root))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value);
    segment.executable.is_none()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.tokens.len() == 1
        && !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && name.bytes().any(|byte| byte.is_ascii_lowercase())
        && super::generic::chain_literals::ordinary_name(name)
        && !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
        })
}

pub(super) fn after_safe_git_read_prefix(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    prefix::after_safe_git_read_prefix(model, allow_git_helper_context, context)
}
