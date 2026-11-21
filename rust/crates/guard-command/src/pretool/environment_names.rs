//! `awk 'BEGIN { for (name in ENVIRON) print name }'` and its reordered forms.
//!
//! Agents ask for the list of environment variable names while they work out
//! which variable a service reads, and reviewing the question stalls ordinary
//! work. A dump of the environment piped into a filter cannot answer it
//! without review, because a value with a newline in it reaches the filter as
//! a line of its own; why, and the one listing that renders no value, is set
//! out in [`crate::environment_name_filters`]. Later stages may reorder,
//! count or trim the names, but may not run a program or name a file of
//! their own.
use crate::environment_name_filters::{stage_lists_environment_names, stage_only_reorders_lines};
use crate::CanonicalCommandV1;

/// Whether a token redirects a stream. A redirect can send the names
/// somewhere this proof says nothing about, so one refuses the command.
fn redirects_a_stream(token: &str) -> bool {
    token.contains('>') || token.contains('<')
}

/// The name a stage runs, when the stage spells it plainly. A path such as
/// `/tmp/evil/sort` carries the basename of a stage this proof trusts while
/// the shell runs a program the proof knows nothing about, so a qualified
/// executable refuses the stage rather than being reduced to its last
/// component.
fn stage_name(segment: &crate::command_parse_surface::CommandSegmentV1) -> Option<&str> {
    segment
        .executable
        .as_deref()
        .filter(|executable| !executable.contains(['/', '\\']))
}

pub(super) fn exact_safe_command(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return false;
    }
    let [listing, rest @ ..] = model.segments.as_slice() else {
        return false;
    };
    let context = &listing.execution_context;
    if model.segments.iter().enumerate().any(|(index, segment)| {
        segment.path_overridden
            || !segment.wrapper_chain.is_empty()
            || !segment.environment_names.is_empty()
            || segment.pipeline_index != index
            || &segment.execution_context != context
            || segment.tokens.iter().any(|token| redirects_a_stream(token))
    }) {
        return false;
    }
    stage_name(listing).is_some_and(|name| stage_lists_environment_names(name, &listing.arguments))
        && rest.iter().all(|segment| {
            stage_name(segment)
                .is_some_and(|name| stage_only_reorders_lines(name, &segment.arguments))
        })
}

#[cfg(test)]
#[path = "environment_names_tests.rs"]
mod tests;
