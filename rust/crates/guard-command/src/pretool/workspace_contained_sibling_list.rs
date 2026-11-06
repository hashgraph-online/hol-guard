//! The list of runs after a `cd` below a sibling checkout's root.
//!
//! `contained_core` peels a single core out of a wrapped command, so a list
//! of runs below a root -- a checkout's own test files run one after another
//! -- had no core and went to review, while the same list after a `cd` to the
//! root itself ran. The sink rejoins both, and the edge roots the sandbox at
//! the repository for either, so the grammar here is the one `sibling_list`
//! already reads.
use super::{joined_filters, PathContext};
use crate::pretool::sink_peel::ARGUMENT_REJECT;
use crate::{CanonicalCommandV1, CommandSegmentV1};

/// The commands after `cd <dir below a sibling root> &&`, when two or more
/// of them follow and the sink rejoins the list whole rather than peeling one
/// core out of it.
pub(super) fn joined_core(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    let commands = model
        .segments
        .iter()
        .filter(|segment| segment.pipeline_index == 0)
        .count();
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || commands < 3
        || !rejoinable_words(model)
        || !joined_filters(model, context)
    {
        return None;
    }
    let mut rest = model.clone();
    rest.segments.remove(0);
    if rest
        .segments
        .iter()
        .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    Some(rest)
}

/// Whether every word the sink would write back is one it can hand to a
/// shell.
///
/// The rejoin refuses a word holding a redirection or list operator, because
/// the sandbox takes words rather than shell text, so admitting one here
/// would approve a list the sink then declines to run -- a review the user
/// cannot clear by approving. Only the two stderr forms the peel resolves
/// itself survive that screen, and they are stripped before the check.
fn rejoinable_words(model: &CanonicalCommandV1) -> bool {
    model.segments.iter().all(|segment| {
        words_without_stderr(segment)
            .iter()
            .all(|token| !token.chars().any(|part| ARGUMENT_REJECT.contains(part)))
    })
}

/// A segment's words with a trailing `2>&1` or `2>/dev/null` removed.
fn words_without_stderr(segment: &CommandSegmentV1) -> &[String] {
    let tokens = segment.tokens.as_slice();
    if let [rest @ .., last] = tokens {
        if last == "2>&1" {
            return rest;
        }
    }
    if let [rest @ .., redirect, target] = tokens {
        if redirect == "2>" && target == "/dev/null" {
            return rest;
        }
    }
    tokens
}
