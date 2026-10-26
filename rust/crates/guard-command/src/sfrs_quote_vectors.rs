//! Replay of the recorded working-directory and runner-chain cases.

use std::path::Path;

use serde_json::{json, Value};

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::sfrs_quote_parsing::{
    bounded_current_workspace_source_edit_execution_context,
    gh_pr_env_split_string_payloads_with_substitution, literal_cd_execution_context,
    runner_argument_escapes_root, skip_generic_shell_wrapper_options, skip_gh_pr_options,
};
use crate::sfrs_quote_tokens::{shell_token_segments, shell_tokens_preserving_quote_context};
use crate::shell_execution_context::ShellExecutionContext;

/// Mirrors the recorder stand-ins for the resident trust services.
struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
    fn trusted_path_command(&self, command: &str, cwd: &str, _: &str) -> bool {
        matches!(command, "bun" | "head" | "tail") && !cwd.contains("untrusted")
    }
    fn bun_script_evidence_complete(&self, args: &[String], _: &str) -> bool {
        args.get(1).is_none_or(|value| value != "bad")
    }
}

fn summary(context: Option<ShellExecutionContext>) -> Value {
    context.map_or(Value::Null, |context| {
        json!({
            "complete": context.complete,
            "segments": context.segments.len(),
            "command_text": context.command_text,
            "workspace_root": context
                .workspace_root
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        })
    })
}

fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

fn position(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("index")
}

pub(crate) fn run(function: &str, args: &[Value]) -> Option<Value> {
    Some(match function {
        "literal_cd_context" => {
            let ctx = Ctx::new(&Host, "/", "/");
            summary(literal_cd_execution_context(
                text(&args[0]),
                Path::new(text(&args[1])),
                &ctx,
            ))
        }
        "current_workspace_edit" => {
            summary(bounded_current_workspace_source_edit_execution_context(
                text(&args[0]),
                args[1].as_str().map(Path::new),
                Path::new(text(&args[2])),
            ))
        }
        "quote_env_payloads" | "quote_skip_gh_pr" | "quote_skip_wrapper" => {
            let tokens = shell_tokens_preserving_quote_context(text(&args[0]));
            let segments = shell_token_segments(&tokens);
            let segment = &segments[position(&args[1])];
            match function {
                "quote_env_payloads" => {
                    gh_pr_env_split_string_payloads_with_substitution(segment).into()
                }
                "quote_skip_gh_pr" => skip_gh_pr_options(segment, position(&args[2])).into(),
                _ => {
                    skip_generic_shell_wrapper_options(text(&args[3]), segment, position(&args[2]))
                        .into()
                }
            }
        }
        "runner_arg_escapes" => runner_argument_escapes_root(
            text(&args[0]),
            Path::new(text(&args[1])),
            Path::new(text(&args[2])),
        )
        .into(),
        other => return crate::sfrs_pr_expansion_vectors::run(other, args),
    })
}
