//! Transport projection of the source-faithful shell helper kernels.
use crate::{data_flow, shell_command_wrappers, shell_structure};
use serde_json::{json, Value};
use std::path::Path;

pub fn evaluate(action: &str, input: &Value) -> Result<Value, &'static str> {
    evaluate_with_deadline(action, input, None)
}

pub fn evaluate_with_deadline(
    action: &str,
    input: &Value,
    deadline: Option<std::time::Instant>,
) -> Result<Value, &'static str> {
    if matches!(
        action,
        "argument_semantics" | "matches_subcommands" | "flags_all" | "option_advance" | "long_flag"
    ) {
        return evaluate_options(action, input, deadline);
    }
    let allowed: &[&str] = match action {
        "masked_bodies" | "masked_complete" => &["command", "heredocs", "spans_json"],
        "normalization" | "trusted_path" => &["command", "cwd", "home_dir"],
        "trace" => &["command", "state", "index"],
        "top_level" => &["command", "state"],
        "interpreter_payload" => &["command", "parts", "command_index"],
        "invokes_executable" => &["command", "executable"],
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
        // Callers that only need to know whether a command carries an inline
        // script body would otherwise read the paged `heredocs` rows and throw
        // the bodies away, so the hot path pays to ship a whole script across
        // the boundary to compute a yes or no. The owner answers it directly.
        "has_embedded_script" => Ok(json!(!shell_structure::extract_heredocs(command).is_empty())),
        // The package path asks this before it will let a verified shim own
        // an external-archive approval, so the shell parse that decides it
        // stays with the other structure questions rather than beside the
        // caller in a second tokenizer.
        "invokes_executable" => {
            let executable = input
                .get("executable")
                .and_then(Value::as_str)
                .ok_or("shell_helpers_invalid")?;
            Ok(json!(
                crate::package_shim_invocation::command_invokes_executable(command, executable)
            ))
        }
        "embedded_script_evidence" => Ok(json!(
            crate::embedded_script_evidence::embedded_script_evidence_entries(command)
        )),
        "kubernetes_secret_read_source" => Ok(json!(
            crate::sfrs_kubernetes_commands::kubernetes_secret_read_source(command)
        )),
        "substitutions" => Ok(json!(shell_structure::extract_command_substitution_spans(
            command
        ))),
        "expanded_substitutions" => Ok(json!(
            shell_structure::extract_expanded_heredoc_substitution_spans(command)
        )),
        "masked_bodies" | "masked_complete" => {
            if input.get("spans_json").is_some() {
                if input.get("heredocs").is_some() {
                    return Err("shell_helpers_invalid");
                }
                let encoded = input["spans_json"]
                    .as_str()
                    .ok_or("shell_helpers_invalid")?;
                let spans: Vec<[usize; 4]> =
                    serde_json::from_str(encoded).map_err(|_| "shell_helpers_invalid_spans")?;
                let mut chars: Vec<char> = command.chars().collect();
                if spans.len() > 131_072
                    || spans.iter().any(|s| {
                        s[0] > s[1] || s[1] > chars.len() || s[2] > s[3] || s[3] > chars.len()
                    })
                {
                    return Err("shell_helpers_invalid_spans");
                }
                for [start, declaration_end, body_start, end] in spans {
                    for c in &mut chars[body_start..end] {
                        if *c != '\n' {
                            *c = ' ';
                        }
                    }
                    if action == "masked_complete" {
                        for c in &mut chars[start..declaration_end] {
                            if *c != '\n' {
                                *c = ' ';
                            }
                        }
                    }
                }
                return Ok(json!(chars.iter().collect::<String>()));
            }
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

fn evaluate_options(
    action: &str,
    input: &Value,
    deadline: Option<std::time::Instant>,
) -> Result<Value, &'static str> {
    use crate::command_option_parsing as options;
    use std::collections::BTreeSet;
    let object = input.as_object().ok_or("shell_helpers_invalid")?;
    let allowed = [
        "command",
        "arguments",
        "argument",
        "options_with_values",
        "known_flags",
        "inverse_flag_pairs",
        "subcommands",
        "required_flags",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("shell_helpers_invalid");
    }
    let strings = |name: &str| -> Result<Vec<String>, &'static str> {
        serde_json::from_value(input.get(name).cloned().unwrap_or(json!([])))
            .map_err(|_| "shell_helpers_invalid")
    };
    let values: BTreeSet<String> = strings("options_with_values")?.into_iter().collect();
    let flags: BTreeSet<String> = strings("known_flags")?.into_iter().collect();
    let arguments = strings("arguments")?;
    let argument = input.get("argument").and_then(Value::as_str).unwrap_or("");
    Ok(match action {
        "argument_semantics" => {
            let pairs: BTreeSet<(String, String)> = serde_json::from_value(
                input
                    .get("inverse_flag_pairs")
                    .cloned()
                    .unwrap_or(json!([])),
            )
            .map_err(|_| "shell_helpers_invalid")?;
            let semantics = options::argument_semantics(&arguments, &values, &pairs);
            json!({"present_flags":semantics.present_flags,"effective_options":semantics.effective_options})
        }
        "matches_subcommands" => json!(options::matches_subcommands_conservatively_with_deadline(
            &arguments,
            &strings("subcommands")?,
            &values,
            &flags,
            deadline
        )),
        "flags_all" => json!(options::flags_present_in_all_option_parses_with_deadline(
            &arguments,
            &strings("required_flags")?.into_iter().collect(),
            &values,
            &flags,
            deadline
        )),
        "option_advance" => json!(options::known_option_advance(argument, &values, &flags)),
        "long_flag" => json!(options::long_flag_assignment_is_enabled(argument)),
        _ => return Err("shell_helpers_invalid_operation"),
    })
}
