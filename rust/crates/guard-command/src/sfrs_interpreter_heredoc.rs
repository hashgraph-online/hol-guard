//! Heredoc and redirect-target helpers the interpreter observers use
//! (`destructive_shell_detection._normalized_redirect_target`,
//! `_shell_script_targets_pytest`, `_single_interpreter_heredoc_script`,
//! `github_pr_body_safety._shell_heredoc_payloads` and
//! `developer_inspection._is_read_only_observer_interpreter_command`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::{py_splitlines, py_strip};
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_patterns::{HEREDOC_PATTERN, SINGLE_INTERPRETER_HEREDOC_PATTERN};
use crate::sfrs_pytest_target::segment_targets_pytest;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};

/// `_normalized_redirect_target`.
pub(crate) fn normalized_redirect_target(target: &str) -> String {
    let stripped = py_strip(target).trim_matches(|c| matches!(c, ')' | ';' | ','));
    stripped.trim_matches(|c| c == '\'' || c == '"').to_owned()
}

/// `_shell_script_targets_pytest`.
pub(crate) fn shell_script_targets_pytest(script_text: &str) -> bool {
    for segment in iter_shell_command_segments(&split_shell_parts(script_text)) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if segment_targets_pytest(&segment, &command_name, command_index, 0) {
            return true;
        }
    }
    false
}

/// `_is_read_only_observer_interpreter_command`.
pub(crate) fn is_read_only_observer_interpreter_command(command_name: &str) -> bool {
    is_python_interpreter_command(command_name)
}

/// `_SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())`
/// groups; a matcher failure is no match.
fn single_interpreter_heredoc_group(command_text: &str, group: &str) -> Option<String> {
    let text = py_strip(command_text);
    let captures = SINGLE_INTERPRETER_HEREDOC_PATTERN
        .captures(text)
        .ok()
        .flatten()?;
    let whole = captures.get(0)?;
    if whole.start() != 0 || whole.end() != text.len() {
        return None;
    }
    captures.name(group).map(|found| found.as_str().to_owned())
}

/// `_single_interpreter_heredoc_script`.
pub(crate) fn single_interpreter_heredoc_script(command_text: &str) -> Option<String> {
    let body = single_interpreter_heredoc_group(command_text, "body")?;
    let script_text = py_strip(&body);
    (!script_text.is_empty()).then(|| script_text.to_owned())
}

/// `_single_interpreter_heredoc_interpreter`.
pub(crate) fn single_interpreter_heredoc_interpreter(command_text: &str) -> Option<String> {
    let interpreter = single_interpreter_heredoc_group(command_text, "interpreter")?;
    let interpreter = py_strip(&interpreter);
    (!interpreter.is_empty()).then(|| interpreter.to_owned())
}

/// `_single_interpreter_heredoc_args`.
pub(crate) fn single_interpreter_heredoc_args(command_text: &str) -> Option<String> {
    let args = single_interpreter_heredoc_group(command_text, "args")?;
    Some(py_strip(&args).to_owned())
}

/// `_shell_heredoc_payloads`.
pub(crate) fn shell_heredoc_payloads(command_text: &str) -> Vec<String> {
    let mut payloads = Vec::new();
    let lines = py_splitlines(command_text);
    let mut line_index = 0;
    while line_index < lines.len() {
        let line = &lines[line_index];
        let captures = HEREDOC_PATTERN.captures(line).ok().flatten();
        let (Some(whole), Some(delimiter)) = (
            captures.as_ref().and_then(|found| found.get(0)),
            captures.as_ref().and_then(|found| found.get(2)),
        ) else {
            line_index += 1;
            continue;
        };
        let delimiter = delimiter.as_str();
        let strip_tabs = line[whole.start()..].starts_with("<<-");
        let mut body_lines: Vec<&str> = Vec::new();
        line_index += 1;
        while line_index < lines.len() {
            let candidate = lines[line_index].as_str();
            let normalized = if strip_tabs {
                candidate.trim_start_matches('\t')
            } else {
                candidate
            };
            if normalized == delimiter {
                line_index += 1;
                break;
            }
            body_lines.push(normalized);
            line_index += 1;
        }
        let payload = body_lines.join("\n");
        let payload = py_strip(&payload);
        if !payload.is_empty() {
            payloads.push(payload.to_owned());
        }
    }
    payloads
}
