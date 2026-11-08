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
        || !bounded_stderr_sinks(model)
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

/// A segment's words with a trailing `2>&1` removed. An unquoted
/// `2>/dev/null` never reaches here: the parse drops it from the words
/// before the segment is built, which is what `bounded_stderr_sinks` reads
/// the segment's own text for.
fn words_without_stderr(segment: &CommandSegmentV1) -> &[String] {
    let tokens = segment.tokens.as_slice();
    if let [rest @ .., last] = tokens {
        if last == "2>&1" {
            return rest;
        }
    }
    tokens
}

/// Whether every run that sends its standard error to the null device is
/// followed by the bound the sink needs to rejoin it.
///
/// The sink writes a stderr redirect back only when a filter stage follows
/// it, the same rule `joined_filters` applies to `2>&1`. The parse drops an
/// unquoted `2>/dev/null` from a segment's words, so that rule never saw this
/// spelling and the list was admitted here while the sink declined to rejoin
/// it -- a review approving it could not clear.
fn bounded_stderr_sinks(model: &CanonicalCommandV1) -> bool {
    model.segments.iter().enumerate().all(|(index, segment)| {
        segment.pipeline_index != 0
            || (!holds_a_sink_the_peel_cannot_write_back(&segment.text)
                && (!sends_stderr_to_the_null_device(&segment.text)
                    || model
                        .segments
                        .get(index + 1)
                        .is_some_and(|next| next.pipeline_index == 1)))
    })
}

/// Whether a segment's text holds the one stderr sink the parse drops and the
/// peel resolves itself.
fn sends_stderr_to_the_null_device(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    (0..characters.len())
        .any(|start| crate::parser_segments::is_stderr_to_null_redirect(&characters, start, false))
}

/// Whether a segment's text holds a redirect to the null device that the
/// parse drops but `sink_peel` cannot write back.
///
/// The parse drops every inert spelling -- `>`, `>>`, `1>`, `&>` and a `2>`
/// with blanks before its target. `sink_peel::stderr_redirect` resolves only
/// the contiguous `2>/dev/null`, and `joined_list` refuses the `>` operator
/// its own lexer finds in the raw text. Admitting one of the other spellings
/// here would approve a list the sink then declines to rejoin -- a review the
/// user cannot clear by approving it -- so the rejoin is refused instead.
fn holds_a_sink_the_peel_cannot_write_back(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    (0..characters.len()).any(|start| {
        crate::parser_segments::null_sink_redirect_end(&characters, start, false).is_some()
            && !crate::parser_segments::is_stderr_to_null_redirect(&characters, start, false)
    })
}
