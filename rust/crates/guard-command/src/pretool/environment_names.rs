//! `printenv | cut -d= -f1` and the other listings of variable names.
//!
//! A bare `printenv` prints every value the process was given, so it stays
//! under review. Piped into a stage that keeps only the text before the `=`,
//! it prints a list of names and no secret at all. Agents ask for that list
//! while they work out which variable a service reads, and reviewing it
//! stalls ordinary work, so the pipeline is proven here instead.
//!
//! The proof rests on the first filter: once a stage provably emits only the
//! text before the `=`, nothing after it can print a value. Later stages may
//! therefore reorder or trim the names, but may not run a program or name a
//! file of their own.
use crate::environment_name_filters::{
    stage_is_plain_env_dump, stage_only_reorders_lines, stage_renders_only_variable_names,
};
use crate::CanonicalCommandV1;

use super::executable_basename;

/// Whether a token redirects a stream. A redirect can send the names
/// somewhere this proof says nothing about, so one refuses the command.
fn redirects_a_stream(token: &str) -> bool {
    token.contains('>') || token.contains('<')
}

fn stage_name(segment: &crate::command_parse_surface::CommandSegmentV1) -> Option<&str> {
    segment.executable.as_deref().map(executable_basename)
}

pub(super) fn exact_safe_command(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return false;
    }
    let [dump, filter, rest @ ..] = model.segments.as_slice() else {
        return false;
    };
    let context = &dump.execution_context;
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
    let (Some(dump_name), Some(filter_name)) = (stage_name(dump), stage_name(filter)) else {
        return false;
    };
    stage_is_plain_env_dump(dump_name, &dump.arguments)
        && stage_renders_only_variable_names(filter_name, &filter.arguments)
        && rest.iter().all(|segment| {
            stage_name(segment)
                .is_some_and(|name| stage_only_reorders_lines(name, &segment.arguments))
        })
}

#[cfg(test)]
#[path = "environment_names_tests.rs"]
mod tests;
