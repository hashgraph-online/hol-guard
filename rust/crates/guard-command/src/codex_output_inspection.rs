//! Bounded read-only pipe filter recognition (`commands_support_codex_reads`
//! filter half).

use crate::codex_output_args::{
    cat_targets, nl_targets, parse_head_tail_args, wc_targets, READ_ONLY_PIPE_FILTERS,
};
use crate::codex_output_py::{shlex_split, PyPath};
use crate::codex_output_search::sed_args_are_bounded_filter;

fn executable_of(token: &str) -> String {
    PyPath::new(token).name().to_owned()
}

/// `_codex_command_uses_untrusted_search_binary`.
fn uses_untrusted_search_binary(executable_token: &str) -> bool {
    executable_token.starts_with('.')
        || executable_token.contains('/')
        || executable_token.contains('\\')
}

fn head_tail_args_are_bounded_filter(args: &[String]) -> bool {
    let (targets, valid, skip_next) = parse_head_tail_args(args);
    valid && !skip_next && targets.is_empty()
}

/// `_codex_command_is_bounded_read_only_filter`.
pub fn is_bounded_read_only_filter(command_text: &str) -> bool {
    let Some(parts) = shlex_split(command_text) else {
        return false;
    };
    let Some(first) = parts.first() else {
        return false;
    };
    if uses_untrusted_search_binary(first) {
        return false;
    }
    let executable = executable_of(first);
    if !READ_ONLY_PIPE_FILTERS.contains(&executable.as_str()) {
        return false;
    }
    let args = &parts[1..];
    match executable.as_str() {
        "cat" => cat_targets(args).is_empty(),
        "sed" => sed_args_are_bounded_filter(args),
        "nl" => nl_targets(args).is_some_and(|targets| targets.is_empty()),
        "wc" => wc_targets(args).is_some_and(|targets| targets.is_empty()),
        _ => head_tail_args_are_bounded_filter(args),
    }
}
