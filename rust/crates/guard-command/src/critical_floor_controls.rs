//! Guard control-command checks shared with native pre-tool enforcement.
use super::rules::{executable_name, guard_control_floor};
use crate::canonical_command::CanonicalCommand;
use crate::command_launcher_floors::{launcher_child_commands, shlex_split, MAX_LAUNCHER_CHILDREN};
use crate::effect_decision::GuardAction;
use crate::CommandSegmentV1;

/// Reason code for a Guard control command the critical floors classify as a
/// block, so the native pre-tool path can refuse it exactly like the composite
/// evaluation instead of leaving it as a reviewable action.
pub(crate) fn guard_control_block_reason(segment: &CommandSegmentV1) -> Option<&'static str> {
    let executable = executable_name(segment);
    if executable != "hol-guard" && executable != "plugin-guard" {
        return None;
    }
    let normalized: Vec<String> = segment
        .arguments
        .iter()
        .map(|item| item.to_lowercase())
        .collect();
    match guard_control_floor(&normalized) {
        Some((GuardAction::Block, reason)) => Some(reason),
        _ => None,
    }
}

/// Whether any segment of `command`, including commands that `xargs`,
/// `parallel` or `find -exec` launch, is a Guard control command the critical
/// floors block. Uses the same depth and child limits as the composite walk.
pub(crate) fn guard_control_block_in_command(command: &CanonicalCommand) -> bool {
    fn walk(command: &CanonicalCommand, depth: usize, remaining: &mut usize) -> bool {
        for segment in &command.segments {
            if guard_control_block_reason(segment).is_some() {
                return true;
            }
            if depth >= 3 {
                continue;
            }
            let Ok(children) =
                launcher_child_commands(&executable_name(segment), &segment.arguments)
            else {
                return true;
            };
            for child in children {
                if *remaining == 0 {
                    return false;
                }
                *remaining -= 1;
                if walk(&child, depth + 1, remaining) {
                    return true;
                }
            }
        }
        false
    }
    let mut remaining = MAX_LAUNCHER_CHILDREN;
    walk(command, 0, &mut remaining)
}

/// Launcher form of [`guard_control_block_in_command`] for commands the native
/// parser leaves unmodeled (`xargs`, `parallel`, `find -exec`): scans the raw
/// tokens for each launcher and checks the commands it would run.
pub(crate) fn guard_control_block_in_launcher_text(text: &str) -> bool {
    let Ok(tokens) = shlex_split(text) else {
        return false;
    };
    let mut remaining = MAX_LAUNCHER_CHILDREN;
    for (index, token) in tokens.iter().enumerate() {
        let name = token
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !matches!(name.as_str(), "xargs" | "parallel" | "find") {
            continue;
        }
        let Ok(children) = launcher_child_commands(&name, &tokens[index + 1..]) else {
            return true;
        };
        for child in children {
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            if guard_control_block_in_command(&child) {
                return true;
            }
        }
    }
    false
}
