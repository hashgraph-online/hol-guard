//! `sed -i` and `perl -i` rewrite files in place, so Guard never proves them
//! (see `sed_workflow_boundaries`). The generic reason told agents only that
//! the command was not read-only; a headless agent then asked a person to
//! approve a one-line rename instead of retrying. Naming the in-place editor
//! and the file edit tool gives the agent a path that Guard can check.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// A review reason for a command with a `sed -i` or `perl -i` step, or `None`.
pub(super) fn inplace_edit_reason(model: &CanonicalCommandV1) -> Option<String> {
    let editor = model.segments.iter().find_map(inplace_editor)?;
    let rest = if model.segments.len() > 1 {
        ", then run the other steps as separate commands"
    } else {
        ""
    };
    Some(format!(
        "HOL Guard requires review because `{editor} -i` rewrites files in place and Guard cannot check what it changes. Make the change with your file edit tool instead (such as Edit, Write or apply_patch), which Guard checks file by file{rest}."
    ))
}

fn inplace_editor(segment: &CommandSegmentV1) -> Option<&'static str> {
    let executable = segment.executable.as_deref()?;
    // A short flag that takes a value ends the cluster: the rest is its value.
    let (editor, value_flags): (_, &[char]) = match executable.rsplit(['/', '\\']).next()? {
        "sed" | "gsed" => ("sed", &['e', 'f', 'l']),
        "perl" => (
            "perl",
            &['e', 'E', 'I', 'M', 'm', 'x', '0', 'C', 'd', 'D', 'l'],
        ),
        _ => return None,
    };
    segment
        .arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| in_place_flag(argument, value_flags))
        .then_some(editor)
}

/// `-i`, `-i.bak`, `--in-place[=SUFFIX]`, or a short-flag cluster such as
/// `-pi` or `-Ei` that sets `-i` before any flag that takes a value.
fn in_place_flag(argument: &str, value_flags: &[char]) -> bool {
    if argument == "--in-place" || argument.starts_with("--in-place=") {
        return true;
    }
    let Some(cluster) = argument.strip_prefix('-') else {
        return false;
    };
    !cluster.starts_with('-')
        && cluster
            .chars()
            .take_while(|flag| !value_flags.contains(flag))
            .any(|flag| flag == 'i')
}

#[cfg(test)]
#[path = "inplace_edit_reason_tests.rs"]
mod tests;
