//! Whole-command facade for the existing developer and source-edit kernels.

use crate::sfrs_developer_graph::{
    self as graph, DeveloperShellEffect, DeveloperShellEffectGraph, DeveloperShellSegmentEffect,
    GraphInputs,
};
use crate::sfrs_developer_inspection as inspection;
use crate::sfrs_source_edit as edit;
use crate::sfrs_source_edit_context as edit_context;
use crate::shell_execution_context::{
    shell_execution_context_metadata, shell_execution_segment_hash, ShellExecutionContext,
};
use crate::Ctx;
use serde_json::{json, Value};
use std::path::Path;

const INVALID: &str = "native_developer_inspection_arguments_invalid";
fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    args[key].as_str().ok_or(INVALID)
}
fn path<'a>(args: &'a Value, key: &str) -> Result<&'a Path, &'static str> {
    text(args, key).map(Path::new)
}
fn strings(args: &Value, key: &str) -> Result<Vec<String>, &'static str> {
    serde_json::from_value(args[key].clone()).map_err(|_| INVALID)
}
fn effect(value: &str) -> Result<DeveloperShellEffect, &'static str> {
    Ok(match value {
        "directory" => DeveloperShellEffect::Directory,
        "local-read" => DeveloperShellEffect::LocalRead,
        "remote-read" => DeveloperShellEffect::RemoteRead,
        "stream-filter" => DeveloperShellEffect::StreamFilter,
        "static-output" => DeveloperShellEffect::StaticOutput,
        "syntax-check" => DeveloperShellEffect::SyntaxCheck,
        _ => return Err(INVALID),
    })
}
fn effect_name(value: DeveloperShellEffect) -> &'static str {
    match value {
        DeveloperShellEffect::Directory => "directory",
        DeveloperShellEffect::LocalRead => "local-read",
        DeveloperShellEffect::RemoteRead => "remote-read",
        DeveloperShellEffect::StreamFilter => "stream-filter",
        DeveloperShellEffect::StaticOutput => "static-output",
        DeveloperShellEffect::SyntaxCheck => "syntax-check",
    }
}
fn report(context: &ShellExecutionContext) -> Value {
    json!({"context":context_wire(crate::sfrs_replay_context::encode_context(context)),"context_hash":context.context_hash(),"segment_hashes":context.segments.iter().map(|s|shell_execution_segment_hash(context,s)).collect::<Vec<_>>(),"metadata":shell_execution_context_metadata(context)})
}

fn context_wire(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(key, _)| key != "$type")
                .map(|(key, value)| (key, context_wire(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(context_wire).collect()),
        other => other,
    }
}
fn encode_graph(graph: &DeveloperShellEffectGraph) -> Value {
    json!({"context":report(&graph.context),"segments":graph.segments.iter().map(|s|json!({"index":s.index,"command_name":s.command_name,"effect":effect_name(s.effect)})).collect::<Vec<_>>(),"has_observation":graph.has_observation()})
}

/// Executes nested checks in process rather than crossing helper boundaries.
///
/// # Errors
/// Refuses malformed DTOs or unknown public entries.
pub fn dispatch(entry: &str, args: &Value, ctx: &Ctx) -> Result<Value, &'static str> {
    let home = args["home_dir"].as_str().map(Path::new);
    let cwd = args["cwd"].as_str().map(Path::new);
    let fallback_home = ctx.default_home.to_string();
    let inputs = GraphInputs {
        cwd,
        home_dir: home.unwrap_or(Path::new(&fallback_home)),
        ctx,
        managed_bin_dirs: &[],
        classify_github: crate::github_command_capabilities::classify_github_cli,
    };
    let value = match entry {
        "_compound_developer_effect_graph" => {
            graph::compound_developer_effect_graph(text(args, "command_text")?, &inputs)
                .as_ref()
                .map_or(Value::Null, encode_graph)
        }
        "_low_risk_compound_developer_execution_context" => {
            graph::low_risk_compound_developer_execution_context(
                text(args, "command_text")?,
                &inputs,
            )
            .as_ref()
            .map_or(Value::Null, report)
        }
        "low_risk_compound_developer_execution_context" => {
            edit_context::low_risk_developer_execution_context(text(args, "command_text")?, &inputs)
                .as_ref()
                .map_or(Value::Null, report)
        }
        "_bounded_verified_source_edit_execution_context" => {
            edit_context::bounded_verified_source_edit_execution_context(
                text(args, "command_text")?,
                &inputs,
            )
            .as_ref()
            .map_or(Value::Null, report)
        }
        "_known_context_effect_graph" => {
            let context = crate::sfrs_replay_context::decode_context(&args["context"])
                .map_err(|_| INVALID)?;
            encode_graph(&graph::known_context_effect_graph(
                context,
                effect(text(args, "observation_effect")?)?,
            ))
        }
        "_graph_has_observation" => {
            let context = crate::sfrs_replay_context::decode_context(&args["context"])
                .map_err(|_| INVALID)?;
            let segments = args["segments"]
                .as_array()
                .ok_or(INVALID)?
                .iter()
                .map(|s| {
                    Ok(DeveloperShellSegmentEffect {
                        index: usize::try_from(s["index"].as_u64().ok_or(INVALID)?)
                            .map_err(|_| INVALID)?,
                        command_name: text(s, "command_name")?.to_owned(),
                        effect: effect(text(s, "effect")?)?,
                    })
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            json!(DeveloperShellEffectGraph { context, segments }.has_observation())
        }
        "_read_only_lookup_primary_segment_is_safe" => {
            json!(inspection::read_only_lookup_primary_segment_is_safe(
                text(args, "command")?,
                &strings(args, "args")?,
                home,
                ctx
            ))
        }
        "_read_only_lookup_date_args_are_safe" => json!(
            inspection::read_only_lookup_date_args_are_safe(&strings(args, "args")?)
        ),
        "_read_only_lookup_plain_targets_are_safe" => {
            json!(inspection::read_only_lookup_plain_targets_are_safe(
                &strings(args, "args")?,
                args["allow_dirs"].as_bool().ok_or(INVALID)?,
                home
            ))
        }
        "_read_only_lookup_ls_args_are_safe" => {
            json!(inspection::read_only_lookup_plain_targets_are_safe(
                &strings(args, "args")?,
                true,
                home
            ))
        }
        "_read_only_lookup_search_args_are_safe" => {
            json!(inspection::read_only_lookup_search_args_are_safe(
                text(args, "command")?,
                &strings(args, "args")?,
                home,
                ctx
            ))
        }
        "_read_only_lookup_search_uses_file_input" => {
            json!(inspection::read_only_lookup_search_uses_file_input(
                text(args, "command")?,
                &strings(args, "args")?
            ))
        }
        "_ripgrep_config_is_disabled" => json!(inspection::ripgrep_config_is_disabled(&strings(
            args, "args"
        )?)),
        "_read_only_lookup_fd_args_are_safe" => json!(
            inspection::read_only_lookup_fd_args_are_safe(&strings(args, "args")?, home)
        ),
        "_fd_exec_sed_read_only_args_are_safe" => json!(
            inspection::fd_exec_sed_read_only_args_are_safe(&strings(args, "args")?, home)
        ),
        "_read_only_lookup_find_args_are_safe" => json!(
            inspection::read_only_lookup_find_args_are_safe(&strings(args, "args")?, home)
        ),
        "_find_args_use_write_or_unsafe_exec_action" => json!(
            inspection::find_args_use_write_or_unsafe_exec_action(&strings(args, "args")?)
        ),
        "_find_exec_sed_args_are_read_only" => json!(inspection::find_exec_sed_args_are_read_only(
            &strings(args, "args")?
        )),
        "_find_exec_ls_args_are_read_only" => json!(inspection::find_exec_ls_args_are_read_only(
            &strings(args, "args")?
        )),
        "_find_exec_ls_resolves_safely" => json!(inspection::find_exec_ls_resolves_safely(
            &strings(args, "args")?,
            &strings(args, "prefix_tokens")?,
            path(args, "cwd")?,
            path(args, "home_dir")?,
            ctx
        )),
        "_static_shell_segment_is_safe" => json!(inspection::static_shell_segment_is_safe(
            &strings(args, "args")?
        )),
        "_static_shell_arg_is_safe" => {
            json!(inspection::static_shell_arg_is_safe(text(args, "arg")?))
        }
        "_is_read_only_observer_interpreter_command" => json!(
            crate::sfrs_interpreter_scripts::is_python_interpreter_command(text(
                args,
                "command_name"
            )?)
        ),
        "_bounded_in_place_sed_target" => json!(edit::bounded_in_place_sed_target(
            &strings(args, "args")?,
            path(args, "cwd")?,
            path(args, "workspace_root")?
        )),
        "_literal_sed_script_is_safe" => {
            json!(edit::literal_sed_script_is_safe(text(args, "script")?))
        }
        "_split_literal_sed_commands" => {
            json!(edit::split_literal_sed_commands(text(args, "script")?))
        }
        "_bounded_edit_workspace_is_safe" => json!(edit::bounded_edit_workspace_is_safe(
            path(args, "workspace_root")?,
            path(args, "home_dir")?
        )),
        "_literal_sed_substitution_is_safe" => json!(edit::literal_sed_substitution_is_safe(text(
            args, "script"
        )?)),
        "_sed_pattern_is_literal" | "_sed_replacement_is_literal" => {
            let mut characters = text(args, "delimiter")?.chars();
            let first = characters.next();
            let delimiter = if characters.next().is_none() {
                first
            } else {
                None
            };
            if entry == "_sed_pattern_is_literal" {
                json!(edit::sed_pattern_is_literal_with_delimiter(
                    text(args, "pattern")?,
                    delimiter
                ))
            } else {
                json!(edit::sed_replacement_is_literal_with_delimiter(
                    text(args, "replacement")?,
                    delimiter
                ))
            }
        }
        "_same_workspace_file" => json!(edit::same_workspace_file(
            text(args, "left")?,
            text(args, "right")?,
            path(args, "cwd")?
        )),
        _ => return Err(INVALID),
    };
    Ok(json!({"value":value}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sfrs_token_vectors::NoEnvHost;

    #[test]
    fn context_report_uses_the_production_wire_contract() {
        let context =
            crate::shell_execution_context::model_shell_execution_context("pwd", None, None, None);
        let output = report(&context);
        let wire: guard_contracts::ShellContextV1 =
            serde_json::from_value(output["context"].clone()).unwrap();
        assert_eq!(serde_json::to_value(wire).unwrap(), output["context"]);
    }
    #[test]
    fn pinned_original_python_helpers() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/developer_inspection_authority.json"
        ))
        .unwrap();
        let host = NoEnvHost;
        let ctx = Ctx::new(&host, "/", "/");
        for case in fixture["cases"].as_array().unwrap() {
            let entry = case["call"].as_str().unwrap();
            let names: &[&str] = match entry {
                "_static_shell_arg_is_safe" => &["arg"],
                "_sed_pattern_is_literal" => &["pattern"],
                "_sed_replacement_is_literal" => &["replacement"],
                "_read_only_lookup_search_uses_file_input" => &["command", "args"],
                "_is_read_only_observer_interpreter_command" => &["command_name"],
                "_literal_sed_script_is_safe"
                | "_literal_sed_substitution_is_safe"
                | "_split_literal_sed_commands" => &["script"],
                _ => &["args"],
            };
            let mut args = case["kwargs"].as_object().unwrap().clone();
            for (key, value) in names.iter().zip(case["args"].as_array().unwrap()) {
                args.insert((*key).to_owned(), value.clone());
            }
            assert_eq!(
                dispatch(entry, &Value::Object(args), &ctx).unwrap()["value"],
                case["result"],
                "{case}"
            );
        }
    }
}
