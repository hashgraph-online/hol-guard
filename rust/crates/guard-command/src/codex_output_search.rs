//! Shell-control and bounded `sed` filter checks shared by the read-only
//! inspection reviews.

use crate::codex_output_args::{parse_sed_args, sed_script_is_bounded_print};

/// `_codex_command_has_unquoted_shell_control`.
pub(crate) fn has_unquoted_shell_control(command: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            if quote == Some('"') && (c == '`' || c == '$') {
                return true;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            continue;
        }
        if matches!(c, '\n' | '\r' | '|' | '&' | ';' | '>' | '<' | '`' | '$') {
            return true;
        }
    }
    false
}

/// `_codex_sed_args_are_bounded_filter`.
pub(crate) fn sed_args_are_bounded_filter(args: &[String]) -> bool {
    let Some(parsed) = parse_sed_args(args) else {
        return false;
    };
    parsed.targets.is_empty()
        && parsed.saw_print_suppression
        && parsed
            .scripts
            .iter()
            .all(|script| sed_script_is_bounded_print(script))
}
