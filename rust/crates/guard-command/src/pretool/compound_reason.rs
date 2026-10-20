//! A compound command goes to review as a whole when any one step cannot be
//! proven benign. The generic reason left agents guessing which step was the
//! problem, so they retried the whole command or gave up. When the other
//! steps are proven, name the unproven ones with a short label built only
//! from shape-checked tokens, never from raw command text.

use super::segment_proof::{
    exact_safe_segment_with_context, stdin_filter_segment, verified_cwd_compound_context,
};
use crate::CanonicalCommandV1;

const MAX_NAMED_STEPS: usize = 3;

/// A review reason naming the unproven steps of an otherwise proven compound
/// command, or `None` when the generic reason applies.
pub(super) fn unproven_steps_reason(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<String> {
    let total = model.segments.len();
    if total < 2
        || model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return None;
    }
    let cwd = verified_cwd_compound_context(model, context);
    if cwd.is_none()
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    let proof_context = super::PathContext {
        cwd: cwd.as_deref().or(context.cwd),
        ..context
    };
    let unproven: Vec<usize> = model
        .segments
        .iter()
        .enumerate()
        .filter(|(index, segment)| {
            !((*index == 0 && cwd.is_some())
                || stdin_filter_segment(segment)
                || exact_safe_segment_with_context(model, segment, false, proof_context))
        })
        .map(|(index, _)| index)
        .collect();
    if unproven.is_empty() || unproven.len() == total {
        return None;
    }
    let steps = unproven
        .iter()
        .take(MAX_NAMED_STEPS)
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>();
    let labels = unproven
        .iter()
        .take(MAX_NAMED_STEPS)
        .map(|index| step_label(&model.segments[*index]))
        .collect::<Vec<_>>();
    let more = if unproven.len() > MAX_NAMED_STEPS {
        " and others"
    } else {
        ""
    };
    let (noun, verb, need) = if unproven.len() == 1 {
        ("Step", "is", "needs")
    } else {
        ("Steps", "are", "need")
    };
    Some(format!(
        "HOL Guard requires review because this command chains {total} steps and {noun} {}{more} ({}) {verb} not proven read-only. Run the proven-safe steps as separate commands; only the unproven {} {need} review.",
        steps.join(", "),
        labels.join(", "),
        noun.to_lowercase(),
    ))
}

/// The executable basename plus a subcommand-shaped first argument, or a
/// neutral word when neither token has a safe shape.
pub(super) fn step_label(segment: &crate::CommandSegmentV1) -> String {
    let basename = segment
        .executable
        .as_deref()
        .map(|executable| executable.rsplit(['/', '\\']).next().unwrap_or(executable))
        .filter(|name| safe_token(name, 32, |character| matches!(character, '.' | '_' | '+')))
        .unwrap_or("command");
    // `git -C <dir> push` names its subcommand after the directory value.
    let mut skip_value = false;
    let first_operand = segment.arguments.iter().find(|argument| {
        if std::mem::take(&mut skip_value) {
            return false;
        }
        skip_value = matches!(argument.as_str(), "-C" | "-c");
        !argument.starts_with('-')
    });
    // Subcommands are short words; anything with digits or longer may be a
    // value (a ticket, a host, a name) that must not reach the reason text.
    let subcommand = first_operand.filter(|argument| {
        argument.len() <= 16
            && argument.starts_with(|character: char| character.is_ascii_lowercase())
            && argument
                .chars()
                .all(|character| character.is_ascii_lowercase() || character == '-')
    });
    match subcommand {
        Some(subcommand) => format!("{basename} {subcommand}"),
        None => basename.to_owned(),
    }
}

fn safe_token(value: &str, max_len: usize, extra: impl Fn(char) -> bool) -> bool {
    let mut characters = value.chars();
    value.len() <= max_len
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || extra(character)
        })
}

#[cfg(test)]
#[path = "compound_reason_tests.rs"]
mod tests;
