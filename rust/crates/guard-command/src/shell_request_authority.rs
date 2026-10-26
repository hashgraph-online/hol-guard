//! Public boundary for the existing GitHub shell and PR expansion kernels.

use std::path::Path;

use serde_json::{json, Value};

use crate::codex_output_env::Ctx;
use crate::sfrs_gh_environment as environment;
use crate::sfrs_gh_pr_expansion as expansion;
use crate::sfrs_quote_tokens::QuotedToken;
use crate::sfrs_substitution as substitution;

const INVALID: &str = "native_shell_request_arguments_invalid";

fn text<'a>(args: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    args[name].as_str().ok_or(INVALID)
}

fn strings(args: &Value, name: &str) -> Result<Vec<String>, &'static str> {
    serde_json::from_value(args[name].clone()).map_err(|_| INVALID)
}

fn index(args: &Value, name: &str) -> Result<usize, &'static str> {
    usize::try_from(args[name].as_u64().ok_or(INVALID)?).map_err(|_| INVALID)
}

fn tokens(args: &Value, name: &str) -> Result<Vec<QuotedToken>, &'static str> {
    args[name]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .map(|token| {
            Ok(QuotedToken {
                raw: text(token, "raw")?.to_owned(),
                plain: text(token, "plain")?.to_owned(),
            })
        })
        .collect()
}

fn flags(command: &str, depth: isize) -> Value {
    json!({
        "_gh_pr_create_body_has_shell_command_substitution": expansion::gh_pr_create_body_has_shell_command_substitution(command, depth),
        "_gh_pr_create_has_active_shell_expansion": expansion::gh_pr_create_has_active_shell_expansion(command, depth),
        "_gh_pr_edit_has_shell_command_substitution": expansion::gh_pr_edit_has_shell_command_substitution(command),
    })
}

/// The classification plus the floor and workflow eligibility its contract
/// derives, so a caller never needs its own copy of the capability table.
fn github_assessment_value(
    assessment: &crate::github_capability_contract::GitHubCommandAssessment,
) -> Value {
    json!({
        "capability": assessment.capability.as_str(),
        "capabilities": assessment.capabilities.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
        "reason_code": assessment.reason_code,
        "detail": assessment.detail,
        "action_floor": assessment.action_floor().as_str(),
        "workflow_authorizable": assessment.workflow_authorizable(),
    })
}

/// One command-level request executes every nested helper inside Rust.
///
/// # Errors
/// Returns a static error for malformed carriers or an unknown public entry.
pub fn dispatch(entry: &str, args: &Value, context: &Ctx) -> Result<Value, &'static str> {
    let outcome = match entry {
        "classify_github_shell_capabilities" => {
            let command = text(args, "command_text")?;
            let home = args["home_dir"].as_str().map(Path::new);
            let assessment =
                crate::sfrs_gh_service::classify_github_shell_capabilities(command, home, context)
                    .map_or(Value::Null, |assessment| {
                        github_assessment_value(&assessment)
                    });
            return Ok(json!({"value":assessment,"flags":flags(command,0)}));
        }
        "pr_flags" => {
            let depth =
                isize::try_from(args["depth"].as_i64().unwrap_or(0)).map_err(|_| INVALID)?;
            return Ok(json!({"flags":flags(text(args,"command_text")?,depth)}));
        }
        "_gh_pr_create_uses_safe_static_body_file" => json!(
            crate::sfrs_gh_static_body_safety::gh_pr_create_uses_safe_static_body_file(
                text(args, "command_text")?,
                args["cwd"].as_str().map(Path::new),
                args["home_dir"].as_str().map(Path::new),
                context
            )
        ),
        "_gh_pr_edit_uses_safe_static_body_file" => json!(
            crate::sfrs_gh_static_body_safety::gh_pr_edit_uses_safe_static_body_file(
                text(args, "command_text")?,
                args["cwd"].as_str().map(Path::new),
                args["home_dir"].as_str().map(Path::new),
                context
            )
        ),
        "_github_environment_requires_review" => {
            let assignments: Vec<(String, String)> =
                serde_json::from_value(args["assignments"].clone()).map_err(|_| INVALID)?;
            json!(environment::github_environment_requires_review(
                &assignments
            ))
        }
        "_persistent_github_environment_requires_review" => json!(
            environment::persistent_github_environment_requires_review(&strings(args, "parts")?)
        ),
        "_github_shell_has_dynamic_arguments" => json!(
            environment::github_shell_has_dynamic_arguments(text(args, "command_text")?)
        ),
        "github_argument_token_has_untrusted_expansion" => json!(
            substitution::github_argument_token_has_untrusted_expansion(text(args, "token")?)
        ),
        "_shell_token_has_expansion" => json!(substitution::shell_token_has_expansion(text(
            args, "token"
        )?)),
        "_github_script_requires_review" => json!(environment::github_script_requires_review(
            text(args, "script")?
        )),
        "_github_environment_name" => {
            json!(environment::github_environment_name(text(args, "name")?))
        }
        "_shell_segment_is_command_builtin_lookup" => json!(
            environment::shell_segment_is_command_builtin_lookup(&strings(args, "segment")?)
        ),
        "_github_pipeline_companion_is_read_only" => {
            json!(environment::github_pipeline_companion_is_read_only(
                &strings(args, "segment")?,
                args["home_dir"].as_str().map(Path::new),
                text(args, "command_text")?,
                context
            ))
        }
        "_command_builtin_options_are_lookup_only" => {
            let plain = tokens(args, "segment")?
                .into_iter()
                .map(|token| token.plain)
                .collect::<Vec<_>>();
            json!(environment::command_builtin_options_are_lookup_only(
                &plain,
                index(args, "index")?
            ))
        }
        "_shell_command_substitution_payloads" => json!(
            substitution::shell_command_substitution_payloads(text(args, "command_text")?)
        ),
        "_read_command_substitution" => json!(substitution::read_command_substitution(
            &text(args, "command_text")?.chars().collect::<Vec<_>>(),
            index(args, "start_index")?
        )),
        "_read_backtick_command_substitution" => {
            json!(substitution::read_backtick_command_substitution(
                &text(args, "command_text")?.chars().collect::<Vec<_>>(),
                index(args, "start_index")?
            ))
        }
        "_iter_shell_pipelines" => {
            json!(substitution::iter_shell_pipelines(&strings(args, "parts")?))
        }
        "_env_split_string_payloads" => json!(substitution::env_split_string_payloads(&strings(
            args, "parts"
        )?)),
        "_shell_segment_env_index" => json!(substitution::shell_segment_env_index(&strings(
            args, "segment"
        )?)),
        "_shell_command_scripts" => json!(substitution::shell_command_scripts(&strings(
            args, "parts"
        )?)),
        "_gh_pr_env_split_string_payloads_with_active_expansion" => json!(
            expansion::gh_pr_env_split_string_payloads_with_active_expansion(&tokens(
                args, "segment"
            )?)
        ),
        "_shell_token_has_active_expansion" => json!(expansion::shell_token_has_active_expansion(
            text(args, "raw_token")?
        )),
        "_gh_pr_create_body_args_start_index" => json!(
            expansion::gh_pr_create_body_args_start_index(&tokens(args, "segment")?)
        ),
        "_gh_pr_body_args_start_index" => {
            let operations = strings(args, "operations")?;
            let refs = operations.iter().map(String::as_str).collect::<Vec<_>>();
            json!(expansion::gh_pr_body_args_start_index(
                &tokens(args, "segment")?,
                &refs
            ))
        }
        "_skip_command_builtin_options" => json!(expansion::skip_command_builtin_options(
            &tokens(args, "segment")?,
            index(args, "index")?
        )),
        "_skip_shell_case_header" => json!(expansion::skip_shell_case_header(
            &tokens(args, "segment")?,
            index(args, "index")?
        )),
        "_skip_shell_select_header" => json!(expansion::skip_shell_select_header(
            &tokens(args, "segment")?,
            index(args, "index")?
        )),
        "_skip_env_wrapper_options" => json!(expansion::skip_env_wrapper_options(
            &tokens(args, "segment")?,
            index(args, "index")?
        )),
        "_skip_sudo_wrapper_options" => json!(expansion::skip_sudo_wrapper_options(
            &tokens(args, "segment")?,
            index(args, "index")?
        )),
        "_gh_pr_create_body_args_have_substitution" => json!(
            expansion::gh_pr_create_body_args_have_substitution(&tokens(args, "args")?)
        ),
        "_is_pytest_python_interpreter_command" => json!(
            expansion::is_pytest_python_interpreter_command(text(args, "command_name")?)
        ),
        _ => return Err("native_shell_request_entry_unknown"),
    };
    Ok(json!({"value":outcome}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sfrs_token_vectors::NoEnvHost;

    #[test]
    fn pinned_original_python_helpers() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/shell_request_authority.json"
        ))
        .unwrap();
        let host = NoEnvHost;
        let context = Ctx::new(&host, "/", "/");
        for case in fixture["cases"].as_array().unwrap() {
            let entry = case["call"].as_str().unwrap();
            let names: &[&str] = match entry {
                "_read_command_substitution" | "_read_backtick_command_substitution" => {
                    &["command_text", "start_index"]
                }
                "_github_environment_name" => &["name"],
                "_is_pytest_python_interpreter_command" => &["command_name"],
                "_iter_shell_pipelines" => &["parts"],
                "_shell_token_has_active_expansion" => &["raw_token"],
                "_shell_token_has_expansion" | "github_argument_token_has_untrusted_expansion" => {
                    &["token"]
                }
                _ => &["command_text"],
            };
            let mut args = serde_json::Map::new();
            for (name, value) in names.iter().zip(case["args"].as_array().unwrap()) {
                args.insert((*name).to_owned(), value.clone());
            }
            let outcome = dispatch(entry, &Value::Object(args), &context).unwrap();
            assert_eq!(outcome["value"], case["result"], "{case}");
        }
    }

    #[test]
    fn github_classification_carries_the_contract_floor() {
        let host = NoEnvHost;
        let context = Ctx::new(&host, "/", "/");
        let classify = |command: &str| {
            dispatch(
                "classify_github_shell_capabilities",
                &json!({"command_text": command, "home_dir": null}),
                &context,
            )
            .unwrap()["value"]
                .clone()
        };

        let secret = classify("gh pr view 1; gh secret set TOKEN --body value");
        assert_eq!(
            secret["capabilities"],
            json!(["read_remote", "secret_remote"])
        );
        assert_eq!(secret["action_floor"], "block");
        assert_eq!(secret["workflow_authorizable"], false);

        let maintenance = classify("gh pr lock 1");
        assert_eq!(maintenance["capabilities"], json!(["maintain_remote"]));
        assert_eq!(maintenance["action_floor"], "review");
        assert_eq!(maintenance["workflow_authorizable"], true);
    }
}
