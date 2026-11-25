//! How the Git floor judges a command in parts, and whether a user's
//! explicit allow answers every part.

use super::{
    after_git_read_prefix, allowable_review, requires_review, AllowableReview, CanonicalCommandV1,
    Instant,
};

/// Whether an explicit user allow answers every question this floor leaves
/// open for the command.
///
/// A command the floor judges in parts -- after a proven read prefix, or at a
/// leading `cd` whose remainder runs in that directory, the original one or
/// either -- is answered part by part, each in the directory it runs in. A
/// part's unsettled steps index the part rather than the command, so they are
/// settled against the part: `cd <dir> && git fetch; git log` asks whether
/// the fetch leaves the log's configuration alone in `<dir>`, and whether the
/// log alone is answered where it runs when the `cd` failed. A part whose
/// review has any cause an allow does not answer keeps the whole review.
pub(in crate::pretool) fn allow_answers(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if let Some(split) = split(model, context, deadline, execution_environment) {
        return split.parts.iter().all(|(part, cwd)| {
            let part_context = super::super::PathContext {
                cwd: cwd.as_deref().or(context.cwd),
                ..context
            };
            !requires_review(part, part_context, deadline, execution_environment)
                || allow_answers(part, part_context, deadline, execution_environment)
        });
    }
    match allowable_review(model, context, deadline, execution_environment) {
        AllowableReview::None => false,
        AllowableReview::EarlierSteps(steps) | AllowableReview::UnansweredProbe(steps) => {
            super::super::git_read_after_allow::allow_settles_read_order(
                model,
                &steps,
                context,
                deadline,
                execution_environment,
            )
        }
    }
}

/// The parts the floor judges a command in, each with the directory it runs
/// in (`None` for the one the command started in).
pub(super) struct Split {
    pub(super) parts: Vec<(CanonicalCommandV1, Option<String>)>,
    /// `cd <dir> && <head>; <tail>`: the second part is the tail, which runs
    /// after the head in `<dir>` or alone where the command started.
    pub(super) reported_tail: bool,
}

impl Split {
    fn whole(parts: Vec<(CanonicalCommandV1, Option<String>)>) -> Self {
        Self {
            parts,
            reported_tail: false,
        }
    }
}

/// How the floor splits `model`, or `None` when it judges the command whole.
pub(super) fn split(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<Split> {
    // A proven read prefix holds no Git segment and changes nothing a later
    // read depends on, so the floor judges the command from its `cd` onward.
    if let Some(rest) = super::super::segment_proof::after_read_prefix(model, context) {
        return Some(Split::whole(vec![(rest, None)]));
    }
    if let Some(rest) = after_git_read_prefix(model, context, deadline, execution_environment) {
        return Some(Split::whole(vec![(rest, None)]));
    }
    // After `cd <dir>;` the rest runs in either directory, so each Git read
    // must be helper-free in both.
    if let Some((cwd, rest)) = super::super::safe_reads::leading_semicolon_cd(model, context) {
        return Some(Split::whole(vec![(rest.clone(), Some(cwd)), (rest, None)]));
    }
    // `cd <dir> && <head>; <tail>`: the head runs only in `<dir>`, the tail
    // after it there or alone in the original directory when the `cd` failed.
    if let Some((cwd, rest, tail)) = super::super::safe_reads::leading_and_cd(model, context) {
        return Some(Split {
            parts: vec![(rest, Some(cwd)), (tail, None)],
            reported_tail: true,
        });
    }
    None
}
