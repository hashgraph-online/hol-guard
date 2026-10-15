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
        Verdict::Clear | Verdict::Review => None,
    }
}

enum Verdict {
    Clear,
    Review,
    /// Only the order failed: these earlier steps, by index into the model.
    Unsettled(Vec<usize>),
}

impl Verdict {
    fn from_review(review: bool) -> Self {
        if review {
            Self::Review
        } else {
            Self::Clear
        }
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
    // A proven read prefix holds no Git segment and changes nothing a later
    // read depends on, so the floor judges the command from its `cd` onward.
    if let Some(rest) = super::segment_proof::after_read_prefix(model, context) {
        return Verdict::from_review(requires_review(
            &rest,
            context,
            deadline,
            execution_environment,
        ));
    }
    if let Some(rest) = after_git_read_prefix(model, context, deadline, execution_environment) {
        return Verdict::from_review(requires_review(
            &rest,
            context,
            deadline,
            execution_environment,
        ));
    }
    // After `cd <dir>;` the rest runs in either directory, so each Git read
    // must be helper-free in both.
    if let Some((cwd, rest)) = super::safe_reads::leading_semicolon_cd(model, context) {
        let moved = super::PathContext {
            cwd: Some(&cwd),
            ..context
        };
        return Verdict::from_review(
            requires_review(&rest, moved, deadline, execution_environment)
                || requires_review(&rest, context, deadline, execution_environment),
        );
    }
    // `cd <dir> && <head>; <tail>`: the head runs only in `<dir>`, the tail
    // after it there or alone in the original directory when the `cd` failed.
    if let Some((cwd, rest, tail)) = super::safe_reads::leading_and_cd(model, context) {
        let moved = super::PathContext {
            cwd: Some(&cwd),
            ..context
        };
        return Verdict::from_review(
            requires_review(&rest, moved, deadline, execution_environment)
                || requires_review(&tail, context, deadline, execution_environment),
        );
    }
    // Past this point every Git read is probed in one directory. A later
    // `cd` the read prefixes above did not account for moves the reads after
    // it somewhere this probe never looked.
    if git_after_later_cd(model) {
        return Verdict::Review;
    }
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
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
    let inspections: Vec<Option<bool>> = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            segment
                .executable
                .as_deref()
                .filter(|executable| super::executable_basename(executable) == "git")
                .and_then(|executable| {
                    super::git_config::execution_free(
                        executable,
                        &arguments[index],
                        read_context,
                        deadline,
                        execution_environment,
                        super::git_helper_context::stdout_piped(model, index),
                    )
                })
        })
        .collect();
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
    // command would run.
    let settled = |prior: usize| {
        let segment = segments[prior];
        benign.contains(&prior)
            || write_free(segment)
            || super::git_remote_ops::verified_fetch(segment, read_context)
            || super::git_remote_ops::verified_fetch(segment, context)
            || super::worktree_add::proven_alone(
                model,
                prior,
                read_context,
                deadline,
                execution_environment,
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
            || inspection == Some(false)
        {
            return Verdict::Review;
        }
        // Only inspection operations have a configuration proof to
        // invalidate. Other Git operations retain their own native
        // review/permission floors, not this read floor.
        if inspection.is_some() {
            unsettled.extend((0..index).filter(|prior| !settled(*prior)));
        }
    }
    unsettled.sort_unstable();
    unsettled.dedup();
    if unsettled.is_empty() {
        Verdict::Clear
    } else {
        Verdict::Unsettled(unsettled)
    }
}

/// The command from its only `cd` onward, when everything before the `cd`
/// is a Git read proven helper-free in the reported directory, or a read the
/// plain read prefix also accepts. `git log -5 && git status --short | head
/// && cd ../other && git log -5` then gets the same floor as
/// `cd ../other && git log -5`: a proven read writes no configuration, ref
/// or hook the later reads could pick up. A Git write, a configuration change
/// or anything that can run a hook leaves no proven read, so it stays in the
/// floor's judgement of the whole command.
fn after_git_read_prefix(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<CanonicalCommandV1> {
    after_prefix(model, |prefix, index| {
        let segment = &prefix.segments[index];
        let git = segment
            .executable
            .as_deref()
            .is_some_and(|executable| super::executable_basename(executable) == "git");
        if git {
            super::git_remote_ops::proven_read(
                prefix,
                index,
                context,
                deadline,
                execution_environment,
            )
        } else {
            super::segment_proof::cwd_read_executable(segment.executable.as_deref())
                && super::segment_proof::exact_safe_segment_with_context(
                    prefix, segment, false, context,
                )
        }
    })
}

/// The command from its only `cd` onward when everything before the `cd` is
/// a read the plain segment proofs accept, Git reads included. The allow path
/// uses this lexical split; `requires_review` still insists that each Git
/// read in the prefix is proven helper-free before it trusts the split.
pub(super) fn after_safe_git_read_prefix(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    after_prefix(model, |prefix, index| {
        let segment = &prefix.segments[index];
        super::segment_proof::cwd_read_executable(segment.executable.as_deref())
            && super::segment_proof::exact_safe_segment_with_context(
                prefix,
                segment,
                allow_git_helper_context,
                context,
            )
    })
}

fn after_prefix(
    model: &CanonicalCommandV1,
    proven_segment: impl Fn(&CanonicalCommandV1, usize) -> bool,
) -> Option<CanonicalCommandV1> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let mut changes = model
        .segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.executable.as_deref() == Some("cd"));
    let (start, _) = changes.next()?;
    if start == 0 || changes.next().is_some() {
        return None;
    }
    for index in 1..=start {
        let separator = super::worktree_add::separator_between(model, index - 1, index)?;
        let expected: &[&str] = if index == start {
            &["&&"]
        } else {
            &["&&", "|"]
        };
        if !expected.contains(&separator.trim()) {
            return None;
        }
    }
    let mut prefix = model.clone();
    prefix.segments.truncate(start);
    let proven = (0..start).all(|index| {
        let segment = &prefix.segments[index];
        segment.environment_names.is_empty()
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
            && proven_segment(&prefix, index)
    });
    if !proven {
        return None;
    }
    let mut rest = model.clone();
    rest.segments = model.segments[start..].to_vec();
    Some(rest)
}

/// Whether a Git inspection runs after a `cd` that is not the command's first
/// segment. Other Git operations keep their own native permission floors,
/// which judge the moved directory themselves.
fn git_after_later_cd(model: &CanonicalCommandV1) -> bool {
    let mut moved = false;
    model.segments.iter().enumerate().any(|(index, segment)| {
        let basename = segment
            .executable
            .as_deref()
            .map(super::executable_basename);
        if index > 0 && basename == Some("cd") {
            moved = true;
        }
        moved && basename == Some("git") && may_inspect(&segment.arguments)
    })
}

/// Whether Git arguments may name an inspection operation. Global options that
/// relocate or reconfigure Git count as inspections, so they stay reviewed.
fn may_inspect(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-C" => index += 2,
            "--no-pager" | "-P" | "--no-replace-objects" | "--literal-pathspecs" => index += 1,
            option if option.starts_with('-') => return true,
            operation => {
                return matches!(
                    operation,
                    "status"
                        | "diff"
                        | "log"
                        | "show"
                        | "grep"
                        | "branch"
                        | "hash-object"
                        | "config"
                        | "merge-base"
                        | "ls-tree"
                        | "cat-file"
                        | "show-ref"
                        | "for-each-ref"
                        | "rev-list"
                )
            }
        }
    }
    true
}
