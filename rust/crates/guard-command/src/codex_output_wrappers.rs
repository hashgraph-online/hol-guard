//! Command wrapper (`command`, `env`) unwrapping and shell-token segmentation
//! shared by the Codex tool-output reviews.

use crate::codex_output_py::PyPath;
use crate::env_wrapper::parse_env_wrapper;

const CONTROL_TOKENS: &[&str] = &["&&", "||", ";", "&", "|", "|&"];

pub(crate) fn is_control_token(token: &str) -> bool {
    CONTROL_TOKENS.contains(&token)
}

/// Lower-cased basename of an executable token (`Path(token).name.lower()`).
pub(crate) fn executable_name_lower(token: &str) -> String {
    PyPath::new(token).name().to_lowercase()
}

/// `_codex_command_start_indexes`.
pub(crate) fn command_start_indexes(parts: &[String]) -> Vec<usize> {
    let mut starts = Vec::new();
    if !parts.is_empty() {
        starts.push(0);
    }
    for (index, part) in parts.iter().enumerate().take(parts.len().saturating_sub(1)) {
        if is_control_token(part) {
            starts.push(index + 1);
        }
    }
    starts
}

/// `_codex_command_segment_parts`.
pub(crate) fn command_segment_parts(parts: &[String], start: usize) -> Vec<String> {
    let mut end = start;
    while end < parts.len() && !is_control_token(&parts[end]) {
        end += 1;
    }
    parts[start..end].to_vec()
}

fn strip_command_wrapper(parts: &[String]) -> Vec<String> {
    let mut index = 0;
    while index < parts.len() && matches!(parts[index].as_str(), "-p" | "-v" | "-V") {
        index += 1;
    }
    if index < parts.len() && parts[index] == "--" {
        index += 1;
    }
    parts[index..].to_vec()
}

fn strip_env_wrapper(parts: &[String]) -> Vec<String> {
    let parsed = parse_env_wrapper(parts, None, None);
    if parsed.complete {
        parsed.executable_argv
    } else {
        Vec::new()
    }
}

/// `_codex_unwrapped_command_parts`.
pub(crate) fn unwrapped_command_parts(parts: &[String]) -> Vec<String> {
    let mut remaining: Vec<String> = parts.to_vec();
    while !remaining.is_empty() {
        match executable_name_lower(&remaining[0]).as_str() {
            "command" => remaining = strip_command_wrapper(&remaining[1..]),
            "env" => remaining = strip_env_wrapper(&remaining[1..]),
            _ => return remaining,
        }
    }
    Vec::new()
}

/// `_codex_env_args_clear_environment`.
fn env_args_clear_environment(parts: &[String]) -> bool {
    let parsed = parse_env_wrapper(parts, None, None);
    parsed.complete
        && parsed.option_effects.ignore_environment
        && parsed.executable_argv.is_empty()
        && !parsed
            .environment_delta
            .assignments
            .iter()
            .any(|(_, value)| value.contains('$') || value.contains('`'))
}

/// `_codex_command_parts_are_environment_dump`.
pub(crate) fn parts_are_environment_dump(parts: &[String]) -> bool {
    let Some(first) = parts.first() else {
        return false;
    };
    match executable_name_lower(first).as_str() {
        "printenv" => true,
        "env" => {
            if env_args_clear_environment(&parts[1..]) {
                return false;
            }
            strip_env_wrapper(&parts[1..]).is_empty()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn unwraps_like_python() {
        assert_eq!(
            unwrapped_command_parts(&v(&["command", "-p", "--", "cat", "a"])),
            v(&["cat", "a"])
        );
        assert_eq!(
            unwrapped_command_parts(&v(&["env", "A=1", "cat", "a"])),
            v(&["cat", "a"])
        );
        assert!(unwrapped_command_parts(&v(&["env"])).is_empty());
        assert_eq!(
            command_start_indexes(&v(&["a", "|", "b", "&&", "c"])),
            vec![0, 2, 4]
        );
        assert_eq!(
            command_segment_parts(&v(&["a", "x", "|", "b"]), 0),
            v(&["a", "x"])
        );
        assert!(parts_are_environment_dump(&v(&["printenv"])));
        assert!(parts_are_environment_dump(&v(&["env"])));
        assert!(!parts_are_environment_dump(&v(&["env", "-i"])));
        assert!(!parts_are_environment_dump(&v(&["env", "A=1", "cat"])));
    }
}
