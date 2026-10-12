//! Transport projection of the source-faithful shell helper kernels.
use crate::{data_flow, shell_command_wrappers, shell_structure};
use serde_json::{json, Value};
use std::path::Path;

pub fn evaluate(action: &str, input: &Value) -> Result<Value, &'static str> {
    let allowed: &[&str] = match action {
        "masked_bodies" | "masked_complete" => &["command", "heredocs"],
        "normalization" | "trusted_path" => &["command", "cwd", "home_dir"],
        "trace" => &["command", "state", "index"],
        "top_level" => &["command", "state"],
        "interpreter_payload" => &["command", "parts", "command_index"],
        _ => &["command"],
    };
    let object = input.as_object().ok_or("shell_helpers_invalid")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("shell_helpers_invalid");
    }
    for key in ["cwd", "home_dir"] {
        if input
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return Err("shell_helpers_invalid");
        }
    }
    let command = input
        .get("command")
        .and_then(Value::as_str)
        .ok_or("shell_helpers_invalid")?;
    // Workflow and heredoc callers admit inputs larger than command models.
    if command.len() > 6 * 1024 * 1024 {
        return Err("shell_helpers_bounds");
    }
    match action {
        "interpreter_payload" => {
            let parts: Vec<String> = serde_json::from_value(input["parts"].clone())
                .map_err(|_| "shell_helpers_invalid")?;
            let index = usize::try_from(
                input["command_index"]
                    .as_u64()
                    .ok_or("shell_helpers_invalid")?,
            )
            .map_err(|_| "shell_helpers_invalid")?;
            Ok(json!(
                shell_command_wrappers::shell_interpreter_command_payload(&parts, index)
            ))
        }
        "top_level" => Ok(json!(shell_structure::ShellScanState::from_snapshot(
            &input["state"]
        )?
        .is_top_level())),
        "segments" => Ok(json!(data_flow::extract_command_segments(command))),
        "pipe_segments" => Ok(json!(data_flow::split_top_level_pipes(command))),
        "redirects" => Ok(json!(data_flow::extract_input_redirects(command))),
        "pipes" => Ok(json!(data_flow::extract_pipes(command)
            .into_iter()
            .map(|p| json!({"left":p.left,"right":p.right}))
            .collect::<Vec<_>>())),
        "heredocs" => Ok(json!(shell_structure::extract_heredocs(command))),
        "substitutions" => Ok(json!(shell_structure::extract_command_substitution_spans(
            command
        ))),
        "expanded_substitutions" => Ok(json!(
            shell_structure::extract_expanded_heredoc_substitution_spans(command)
        )),
        "masked_bodies" | "masked_complete" => {
            let heredocs: Vec<shell_structure::ShellHeredoc> =
                serde_json::from_value(input["heredocs"].clone())
                    .map_err(|_| "shell_helpers_invalid")?;
            let length = command.chars().count();
            if heredocs.iter().any(|h| {
                h.operator_start > h.declaration_end
                    || h.declaration_end > length
                    || h.body_start > h.body_end
                    || h.body_end > h.end
                    || h.end > length
            }) {
                return Err("shell_helpers_invalid_spans");
            }
            Ok(json!(if action == "masked_bodies" {
                shell_structure::mask_heredoc_bodies(command, &heredocs)
            } else {
                shell_structure::mask_complete_heredocs(command, &heredocs)
            }))
        }
        "normalization" | "trusted_path" => {
            let cwd = input.get("cwd").and_then(Value::as_str).map(Path::new);
            let home = input.get("home_dir").and_then(Value::as_str).map(Path::new);
            if action == "trusted_path" {
                return Ok(json!(
                    shell_command_wrappers::is_trusted_absolute_command_path(
                        Path::new(command),
                        cwd,
                        home
                    )
                ));
            }
            let r = shell_command_wrappers::normalize_transparent_shell_command(command, cwd, home);
            Ok(
                json!({"raw_command":r.raw_command,"normalized_command":r.normalized_command,"wrapper_chain":r.wrapper_chain}),
            )
        }
        "trace" => {
            let chars: Vec<char> = command.chars().collect();
            let mut state = shell_structure::ShellScanState::from_snapshot(&input["state"])?;
            let mut index = input["index"].as_u64().ok_or("shell_helpers_invalid")? as usize;
            let mut rows = Vec::new();
            // Page transitions below the resident response bound; callers resume
            // from the last native state without interpreting shell syntax.
            while index < chars.len() && rows.len() < 16_384 {
                let start = index;
                index = state.advance(&chars, index);
                let (quote, depth, backtick) = state.snapshot();
                rows.push(json!([
                    start,
                    index,
                    quote,
                    depth,
                    backtick,
                    state.is_top_level()
                ]));
            }
            Ok(json!(rows))
        }
        _ => Err("shell_helpers_invalid_operation"),
    }
}
