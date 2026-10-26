//! Recorded-vector dispatch for the pull-request expansion checks.

use serde_json::Value;

use crate::sfrs_gh_pr_expansion::{
    gh_pr_body_args_start_index, gh_pr_create_body_args_have_substitution,
    gh_pr_create_body_args_start_index, gh_pr_create_body_has_shell_command_substitution,
    gh_pr_create_has_active_shell_expansion, gh_pr_edit_has_shell_command_substitution,
    gh_pr_env_split_string_payloads_with_active_expansion, is_pytest_python_interpreter_command,
    shell_token_has_active_expansion, skip_command_builtin_options, skip_env_wrapper_options,
    skip_shell_case_header, skip_shell_select_header, skip_sudo_wrapper_options,
};
use crate::sfrs_quote_tokens::{shell_token_segments, shell_tokens_preserving_quote_context};

fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

fn position(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("index")
}

pub(crate) fn run(function: &str, args: &[Value]) -> Option<Value> {
    let source = || args.first().map(text).unwrap_or_default();
    Some(match function {
        "pr_body_substitution" => {
            gh_pr_create_body_has_shell_command_substitution(source(), 0).into()
        }
        "pr_edit_substitution" => gh_pr_edit_has_shell_command_substitution(source()).into(),
        "pr_active_expansion" => gh_pr_create_has_active_shell_expansion(source(), 0).into(),
        "pr_token_active" => shell_token_has_active_expansion(source()).into(),
        "pr_python_interpreter" => is_pytest_python_interpreter_command(source()).into(),
        "pr_active_payloads"
        | "pr_create_start"
        | "pr_edit_start"
        | "pr_skip_command"
        | "pr_skip_case"
        | "pr_skip_select"
        | "pr_skip_env"
        | "pr_skip_sudo"
        | "pr_args_substitution" => {
            let tokens = shell_tokens_preserving_quote_context(source());
            let segments = shell_token_segments(&tokens);
            let segment = &segments[position(&args[1])];
            let start = || position(&args[2]);
            match function {
                "pr_active_payloads" => {
                    gh_pr_env_split_string_payloads_with_active_expansion(segment).into()
                }
                "pr_create_start" => gh_pr_create_body_args_start_index(segment).into(),
                "pr_edit_start" => gh_pr_body_args_start_index(segment, &["edit"]).into(),
                "pr_skip_command" => skip_command_builtin_options(segment, start()).into(),
                "pr_skip_case" => skip_shell_case_header(segment, start()).into(),
                "pr_skip_select" => skip_shell_select_header(segment, start()).into(),
                "pr_skip_env" => skip_env_wrapper_options(segment, start()).into(),
                "pr_skip_sudo" => skip_sudo_wrapper_options(segment, start()).into(),
                _ => {
                    gh_pr_create_body_args_have_substitution(&segment[start().min(segment.len())..])
                        .into()
                }
            }
        }
        _ => return None,
    })
}
