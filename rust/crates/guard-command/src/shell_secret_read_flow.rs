//! Flow and segment helpers for shell secret-read assessment
//! (`runtime/_shell_secret_read_flow.py`, 92 lines — verbatim).

#![cfg(unix)]

use std::sync::OnceLock;

use regex::Regex;

use crate::command_model::{CanonicalCommand, CommandSegment};
use crate::shell_execution_context::ShellExecutionSegment;
use crate::shell_execution_context_support::split_shell_tokens;
use crate::shell_secret_read_support::{
    command_name_for, path_qualified, python_executable, shell_segment_file_operand_tokens,
    short_circuiting_cd_failures, FLOW_OPERATORS, OTHER_READERS, SHELLS,
};

fn input_redirect_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d*<").expect("input redirect"))
}

/// `_parse_execution_segment` (:23-49).
pub(crate) fn parse_execution_segment(
    execution: &ShellExecutionSegment,
    raw_model: &CanonicalCommand,
    raw_segment: Option<&CommandSegment>,
) -> Option<CanonicalCommand> {
    // Keep source syntax and require agreement with the cwd model. Re-quoting
    // decoded tokens changes input redirections into ordinary argv and can
    // erase command/exec ambiguity; the raw parser deliberately skips
    // transparent-wrapper normalization for this inspection path.
    if !execution.complete || execution.effective_cwd.is_none() || raw_segment.is_none() {
        return None;
    }
    let raw_segment = raw_segment?;
    match split_shell_tokens(&raw_segment.text) {
        Ok(tokens) if tokens == execution.tokens => {}
        _ => return None,
    }
    let mut cloned = raw_model.clone();
    cloned.segments = vec![raw_segment.clone()];
    cloned.redirects = raw_model
        .redirects
        .iter()
        .filter(|r| raw_segment.start <= r.start && r.end <= raw_segment.end)
        .cloned()
        .collect();
    cloned.embedded_commands = Vec::new();
    Some(cloned)
}

/// `_segment_may_touch_local_data` (:52-74).
pub(crate) fn segment_may_touch_local_data(execution: &ShellExecutionSegment) -> bool {
    // Keep unknown file/code access closed without treating stdout as a file.
    if execution.tokens.is_empty() {
        return false;
    }
    let token = &execution.tokens[0];
    let executable = command_name_for(token);
    let args = &execution.tokens[1..];
    // emulate the Python (?!<) lookahead: the char after `<` must not be `<`.
    let has_input_redirect = execution.tokens.iter().any(|item| {
        if let Some(m) = input_redirect_re().find(item) {
            !item[m.end()..].starts_with('<')
        } else {
            false
        }
    });
    if has_input_redirect {
        return true;
    }
    let mut argv: Vec<String> = vec![executable.clone()];
    argv.extend(args.iter().cloned());
    if !shell_segment_file_operand_tokens(&argv).is_empty() {
        return true;
    }
    if OTHER_READERS.contains(&executable.as_str()) {
        return args.iter().any(|a| !a.starts_with('-'));
    }
    SHELLS.contains(&executable.as_str())
        || ["command", "exec", "node", "bun", "ruby", "perl"].contains(&executable.as_str())
        || python_executable(&executable)
        || path_qualified(token)
}

/// `_flow_operator_before` (:77-78).
pub(crate) fn flow_operator_before(execution: &ShellExecutionSegment) -> Option<&String> {
    execution
        .control_before
        .iter()
        .rev()
        .find(|t| FLOW_OPERATORS.contains(&t.as_str()))
}

/// `_failed_cd_short_circuit_state` (:81-92). `(active, unreachable)`.
pub(crate) fn failed_cd_short_circuit_state(
    execution: &ShellExecutionSegment,
    active: bool,
) -> (bool, bool) {
    let mut active = active;
    let operator = flow_operator_before(execution).map(String::as_str);
    if ["||", ";", "&", "|"].contains(&operator.unwrap_or("")) {
        active = false;
    }
    if execution.directory_operation.is_some()
        && execution
            .reason_code
            .as_deref()
            .is_some_and(|r| short_circuiting_cd_failures().contains(&r))
    {
        return (true, false);
    }
    (active, active && operator == Some("&&"))
}
