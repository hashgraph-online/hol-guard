//! Parity of the Kubernetes command checks against recorded Python output.
//! Each case is `{fn, args, result}`; tuples are recorded as lists.

use std::io::Read;

use serde_json::Value;

use crate::sfrs_kubernetes_commands as kc;
use crate::sfrs_kubernetes_cp as cp;
use crate::sfrs_kubernetes_heredoc as hd;
use crate::sfrs_kubernetes_heredoc_scan as sc;
use crate::sfrs_kubernetes_support as ks;
use crate::sfrs_kubernetes_support::OptionSets;

fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

fn position(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("index")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array argument")
        .iter()
        .map(|item| text(item).to_string())
        .collect()
}

fn list(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::from).collect())
}

fn opt(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

fn chars(value: &Value) -> Vec<char> {
    text(value).chars().collect()
}

fn pair(left: Option<String>, right: Option<String>) -> Value {
    Value::Array(vec![
        left.map_or(Value::Null, Value::from),
        right.map_or(Value::Null, Value::from),
    ])
}

fn option_sets(variant: &str) -> OptionSets<'static> {
    match variant {
        "kubectl" => ks::KUBECTL_OPTION_SETS,
        "exec" => OptionSets {
            value_flags: &[
                ks::KUBECTL_OPTIONS_WITH_VALUES,
                ks::EXEC_OPTIONS_WITH_VALUES,
            ],
            boolean_flags: &[ks::KUBECTL_BOOLEAN_OPTIONS, ks::EXEC_BOOLEAN_OPTIONS],
            short_cluster: &[ks::EXEC_BOOLEAN_SHORT_CLUSTER],
        },
        "cp" => OptionSets {
            value_flags: &[ks::KUBECTL_OPTIONS_WITH_VALUES, kc::CP_OPTIONS_WITH_VALUES],
            boolean_flags: &[ks::KUBECTL_BOOLEAN_OPTIONS, kc::CP_BOOLEAN_OPTIONS],
            short_cluster: &[ks::EXEC_BOOLEAN_SHORT_CLUSTER],
        },
        "get" => OptionSets {
            value_flags: &[ks::KUBECTL_OPTIONS_WITH_VALUES],
            boolean_flags: &[
                ks::KUBECTL_BOOLEAN_OPTIONS,
                kc::READ_ONLY_GET_BOOLEAN_OPTIONS,
            ],
            short_cluster: &[ks::EXEC_BOOLEAN_SHORT_CLUSTER],
        },
        other => panic!("unknown option set {other}"),
    }
}

fn support(function: &str, args: &[Value]) -> Option<Value> {
    let source = || text(&args[0]);
    Some(match function {
        "s_dumps_env" => ks::script_dumps_process_environment(source()).into(),
        "s_reads_env" => ks::script_reads_sensitive_env(source()).into(),
        "s_sensitive_name" => ks::is_sensitive_env_name(source()).into(),
        "s_proc_environ" => ks::is_proc_environ_path(source()).into(),
        "s_secret_volume" => ks::is_secret_volume_path(source()).into(),
        "s_path_candidates" => list(ks::path_candidates(source())),
        "s_volume_arg" => ks::secret_volume_argument_value(source()).into(),
        "s_strip_redirect" => ks::strip_redirect_prefix(source()).into(),
        "s_redirect_target" => ks::is_output_redirect_target(source(), args[1].as_str()).into(),
        "s_raw_secret" => ks::raw_secret_api_path(source()).into(),
        "s_remote_cp_path" => opt(ks::remote_cp_path(source())),
        "s_resource_secret" => ks::resource_token_includes_secret(source()).into(),
        "s_inline_interp" => ks::is_inline_interpreter_command(source()).into(),
        "s_interp_env" => ks::interpreter_reads_sensitive_env(source(), &strings(&args[1])).into(),
        "s_inline_script" => {
            ks::interpreter_inline_script(&strings(&args[0])).map_or(Value::Null, Value::from)
        }
        "s_exec_remote" => list(ks::exec_remote_tokens_after_resource(&strings(&args[0]))),
        "s_shell_script" => {
            ks::shell_command_script(&strings(&args[0])).map_or(Value::Null, Value::from)
        }
        "s_matching" => {
            let tokens = strings(&args[1]);
            list(match text(&args[0]) {
                "proc" => ks::matching_source_arguments(&tokens, ks::is_proc_environ_path),
                _ => ks::matching_source_arguments(&tokens, ks::is_secret_volume_path),
            })
        }
        "s_skip_options" => ks::skip_kubectl_options(&strings(&args[0]), position(&args[1])).into(),
        "s_option_consumed" => {
            let tokens = strings(&args[1]);
            ks::kubernetes_option_tokens_consumed(
                &tokens,
                position(&args[2]),
                option_sets(text(&args[0])),
            )
            .map_or(Value::Null, Value::from)
        }
        _ => return None,
    })
}

fn heredoc(function: &str, args: &[Value]) -> Option<Value> {
    let source = || text(&args[0]);
    let tokens = || strings(&args[0]);
    Some(match function {
        "h_secret_source" => opt(hd::kubernetes_heredoc_secret_source(source())),
        "h_iter" => Value::Array(
            hd::iter_kubernetes_heredocs(source())
                .into_iter()
                .map(|(a, b, c)| list(vec![a, b, c]))
                .collect(),
        ),
        "h_shell_tokens" => list(hd::shell_tokens(source())),
        "h_remote_kind_cmd" => opt(hd::kubernetes_remote_kind_from_command(source())),
        "h_body_volume" => hd::script_body_reads_secret_volume(source()).into(),
        "h_last_pipe" => hd::last_pipe_segment(source()).into(),
        "h_pipe_segments" => list(hd::pipe_segments(source())),
        "h_background" => {
            let cs = chars(&args[0]);
            let index = position(&args[1]);
            if index >= cs.len() {
                Value::Null
            } else {
                sc::is_background_separator(&cs, index).into()
            }
        }
        "h_looks_heredoc" => {
            sc::looks_like_heredoc_operator(&chars(&args[0]), position(&args[1])).into()
        }
        "h_starts_sep" => sc::starts_command_separator(&chars(&args[0]), position(&args[1])).into(),
        "h_skip_ws" => sc::skip_command_whitespace(&chars(&args[0]), position(&args[1])).into(),
        "h_parse" => match sc::parse_heredoc(&chars(&args[0]), position(&args[1])) {
            Some((tag, a, b, c)) => Value::Array(vec![tag.into(), a.into(), b.into(), c.into()]),
            None => Value::Null,
        },
        "h_body_end" => {
            let start = position(&args[2]);
            match sc::heredoc_body_and_end(&chars(&args[0]), text(&args[1]), start) {
                Some((body, end)) => Value::Array(vec![body.into(), end.into()]),
                None => Value::Array(vec![Value::Null, start.into()]),
            }
        }
        "h_remote_kind" => opt(hd::kubernetes_heredoc_remote_kind(
            text(&args[0]),
            text(&args[1]),
        )),
        "h_interp_stdin" => hd::interpreter_reads_stdin(&tokens()).into(),
        "h_shell_stdin" => hd::shell_reads_stdin(&tokens()).into(),
        "h_segment_volume" => hd::segment_reads_secret_volume(&tokens()).into(),
        "h_exec_remote" => list(hd::kubernetes_exec_remote_tokens(&tokens())),
        "h_unwrap" => {
            let (name, rest) = hd::unwrap_heredoc_remote_command(&tokens());
            Value::Array(vec![name.map_or(Value::Null, Value::from), list(rest)])
        }
        "h_wrapper_option" | "k_option_consumed" => {
            sc::wrapper_option_tokens_consumed(text(&args[0]), text(&args[1])).into()
        }
        _ => return None,
    })
}

fn commands(function: &str, args: &[Value]) -> Option<Value> {
    let tokens = || strings(&args[0]);
    let index = || position(&args[1]);
    Some(match function {
        "k_secret_read_source" => match args[0].as_str() {
            Some(command) => opt(kc::kubernetes_secret_read_source(command)),
            None => Value::Null,
        },
        "k_command_candidates" => list(kc::command_candidates(text(&args[0]), 0)),
        "k_command_candidates_depth" => {
            list(kc::command_candidates(text(&args[0]), position(&args[1])))
        }
        "k_shell_tokens" => list(kc::shell_tokens(text(&args[0]))),
        "k_candidate_source" => opt(kc::secret_read_source_for_candidate(text(&args[0]))),
        "k_inventory_args" => {
            kc::kubernetes_read_only_inventory_args(text(&args[0]), &strings(&args[1])).into()
        }
        "k_get_resource_output" => {
            let (resource, output) = kc::read_only_get_resource_and_output(&tokens());
            pair(resource, output)
        }
        "k_inventory_resource_name" => kc::inventory_resource_name(text(&args[0])).into(),
        "k_source_from_tokens" => opt(kc::kubectl_secret_read_source_from_tokens(&tokens())),
        "k_unwrap_start" => kc::unwrap_command_start(&tokens()).into(),
        "k_exec_secret_source" => opt(kc::kubectl_exec_secret_source(&tokens())),
        "k_exec_remote_tokens" => list(cp::kubectl_exec_remote_tokens(&tokens())),
        "k_pod_env" => kc::remote_command_reads_pod_environment(&tokens(), index()).into(),
        "k_secret_volume" => kc::remote_command_reads_secret_volume(&tokens(), index()).into(),
        "k_cp_reads" => cp::kubectl_cp_reads_secret_volume(&tokens()).into(),
        "k_cp_operands" => list(cp::kubectl_cp_operands(&tokens())),
        "k_remote_copy" => cp::remote_copy_source_reads_secret_volume(&tokens()).into(),
        "k_volume_source_args" => list(cp::secret_volume_source_arguments(&tokens())),
        "k_remote_cp_operands" => list(cp::remote_cp_operands(&tokens())),
        "k_shell_stdin_source" => opt(cp::shell_stdin_secret_source(&tokens())),
        "k_resource_is_secret" => kc::kubectl_resource_is_secret(&tokens(), index()).into(),
        "k_get_raw_path" => kc::kubectl_get_raw_secret_path(&tokens(), index()).into(),
        "k_create_token" => kc::kubectl_create_token(&tokens(), index()).into(),
        _ => return None,
    })
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/kubernetes.json.gz");
    let mut body = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut body)
        .expect("gzip");
    serde_json::from_str(&body).expect("json")
}

#[test]
fn kubernetes_checks_match_recorded_python() {
    let document = fixture();
    let cases = document["cases"].as_array().expect("cases");
    let mut failures: Vec<String> = Vec::new();
    for case in cases {
        let function = text(&case["fn"]);
        let args = case["args"].as_array().expect("args");
        let actual = support(function, args)
            .or_else(|| heredoc(function, args))
            .or_else(|| commands(function, args))
            .unwrap_or_else(|| panic!("unhandled vector function {function}"));
        if actual != case["result"] && failures.len() < 20 {
            failures.push(format!(
                "{function} {args:?}: expected {} got {actual}",
                case["result"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} (of {} cases)\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    assert!(cases.len() > 1000);
}
