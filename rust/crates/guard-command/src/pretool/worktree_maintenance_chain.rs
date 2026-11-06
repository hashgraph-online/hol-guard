//! Cleaning up a linked worktree in one `&&` chain: `rm <link>` for the
//! links an agent placed in it (Git refuses to remove a worktree that holds
//! untracked entries), the non-forced `git worktree remove`, then reads of
//! what is left, such as `git worktree list` and `git branch -v`.
//!
//! Each step keeps its own proof. A removed link sits at the root of a
//! linked worktree of the session's repository, and removing it leaves its
//! target alone. The worktree removal passes the single-command proof.
//! Neither changes the configuration a Git read uses, so each read after
//! them is proven helper-free in the session's directory, as it would be
//! alone. A `;`, `||`, pipe or `cd` anywhere keeps the review.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::GuardExecutionEnvironmentV1;
use std::time::Instant;

const MAX_SEGMENTS: usize = 8;

pub(in crate::pretool) fn proven(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let count = model.segments.len();
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || !(2..=MAX_SEGMENTS).contains(&count)
        || !(1..count).all(|index| {
            super::super::worktree_add::separator_between(model, index - 1, index)
                .is_some_and(|separator| separator.trim() == "&&")
        })
    {
        return false;
    }
    let Some(removal) = model.segments.iter().position(|segment| {
        matches!(
            super::parse(segment, context),
            Some((_, super::Maintenance::Remove(_)))
        )
    }) else {
        return false;
    };
    let mut alone = model.clone();
    alone.segments = vec![model.segments[removal].clone()];
    if !super::exact_safe_command(&alone, context, deadline, execution_environment) {
        return false;
    }
    model
        .segments
        .iter()
        .enumerate()
        .all(|(index, segment)| match index.cmp(&removal) {
            std::cmp::Ordering::Less => unlinks(segment, context),
            std::cmp::Ordering::Equal => true,
            std::cmp::Ordering::Greater => {
                reads(model, index, context, deadline, execution_environment)
            }
        })
}

/// `rm [-f] [--] <link>...` over links at the root of linked worktrees of
/// the session's repository.
fn unlinks(segment: &CommandSegmentV1, context: super::super::PathContext<'_>) -> bool {
    plain_step(segment) && super::super::directory_targets::sibling::link_removal(segment, context)
}

/// A read the segment proofs accept on its own; a Git read must also be
/// proven helper-free by the configuration probe.
fn reads(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let segment = &model.segments[index];
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    if !plain_step(segment) || executable == "cd" {
        return false;
    }
    if super::super::executable_basename(executable) == "git" {
        // `git worktree list` has no configuration probe; it keeps the
        // segment proof it gets alone, pager screen included.
        let listing = matches!(
            segment.arguments.as_slice(),
            [worktree, list] | [worktree, list, _]
                if worktree == "worktree"
                    && list == "list"
                    && segment.arguments.get(2).is_none_or(|flag| flag == "--porcelain")
        );
        return super::super::git_local_writes::configured_read(
            model,
            index,
            context,
            deadline,
            execution_environment,
        ) || (listing
            && super::super::segment_proof::exact_safe_segment_with_context(
                model, segment, false, context,
            ));
    }
    super::super::segment_proof::cwd_read_executable(Some(executable))
        && super::super::segment_proof::exact_safe_segment_with_context(
            model, segment, false, context,
        )
}

fn plain_step(segment: &CommandSegmentV1) -> bool {
    segment.pipeline_index == 0
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && !segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
}
