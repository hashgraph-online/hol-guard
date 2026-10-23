use crate::CommandSegmentV1;

/// Only the proven CLI namespace is metadata, never a credential operand.
/// Keep quoted/escaped text and wrappers on the ordinary sensitive screen.
pub(super) fn secret_namespace(segment: &CommandSegmentV1) -> Option<usize> {
    if segment.executable.as_deref() != Some("gh")
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.tokens.len() != segment.arguments.len() + 1
        || !segment
            .text
            .split_whitespace()
            .eq(segment.tokens.iter().map(String::as_str))
        || !crate::command_compatibility::github_arguments_are_read_only(
            &segment.arguments,
            &segment.text,
        )
    {
        return None;
    }
    let mut index = 0;
    while let Some(argument) = segment.arguments.get(index) {
        match argument.split('=').next()? {
            "--repo" | "-R" | "--hostname" => {
                index += if argument.contains('=') { 1 } else { 2 };
            }
            _ => break,
        }
    }
    (segment
        .arguments
        .get(index)
        .is_some_and(|arg| arg == "secret")
        && segment
            .arguments
            .get(index + 1)
            .is_some_and(|arg| arg == "list"))
    .then_some(index)
}

pub(super) fn without_namespace(segment: &CommandSegmentV1, index: usize) -> String {
    std::iter::once("gh")
        .chain(
            segment
                .arguments
                .iter()
                .enumerate()
                .filter_map(|(position, arg)| (position != index).then_some(arg.as_str())),
        )
        .collect::<Vec<_>>()
        .join(" ")
}
