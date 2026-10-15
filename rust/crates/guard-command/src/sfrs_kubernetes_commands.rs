//! Kubernetes shell-command secret source detection
//! (`runtime/kubernetes_commands.py`).

#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

use crate::data_flow::{extract_command_segments, extract_input_redirects};
use crate::env_wrapper::parse_env_wrapper;
use crate::hook_adapter_pytext::{py_lower, py_strip};
use crate::sfrs_kubernetes_cp::{
    kubectl_cp_reads_secret_volume, kubectl_exec_remote_tokens,
    remote_copy_source_reads_secret_volume, secret_volume_source_arguments,
    shell_stdin_secret_source,
};
use crate::sfrs_kubernetes_heredoc::kubernetes_heredoc_secret_source;
use crate::sfrs_kubernetes_heredoc_scan::wrapper_option_tokens_consumed;
use crate::sfrs_kubernetes_support::{
    interpreter_reads_sensitive_env, is_assignment, is_proc_environ_path, is_secret_volume_path,
    is_sensitive_env_name, kubernetes_option_tokens_consumed, matching_source_arguments,
    path_name_lower, py_split_whitespace, raw_secret_api_path, resource_token_includes_secret,
    script_reads_sensitive_env, shell_command_script, skip_kubectl_options, OptionSets,
    EXEC_BOOLEAN_SHORT_CLUSTER, KUBECTL_BOOLEAN_OPTIONS, KUBECTL_OPTIONS_WITH_VALUES,
    SHELL_EXECUTABLES, WRAPPER_COMMANDS, WRITE_ONLY_COMMANDS,
};
use crate::shell_command_wrappers::normalize_transparent_shell_command;
use crate::shell_structure::extract_command_substitutions;

pub(crate) const CP_OPTIONS_WITH_VALUES: &[&str] =
    &["--container", "--namespace", "--retries", "-c", "-n"];
pub(crate) const CP_BOOLEAN_OPTIONS: &[&str] = &["--no-preserve"];
const READ_ONLY_INVENTORY_RESOURCES: &[&str] = &[
    "cronjob",
    "cronjobs",
    "cj",
    "daemonset",
    "daemonsets",
    "ds",
    "deploy",
    "deployment",
    "deployments",
    "ep",
    "endpoint",
    "endpoints",
    "endpointslice",
    "endpointslices",
    "event",
    "events",
    "ev",
    "ing",
    "ingress",
    "ingresses",
    "job",
    "jobs",
    "namespace",
    "namespaces",
    "no",
    "node",
    "nodes",
    "ns",
    "po",
    "pod",
    "pods",
    "pv",
    "pvc",
    "persistentvolume",
    "persistentvolumeclaim",
    "persistentvolumeclaims",
    "persistentvolumes",
    "rs",
    "replicaset",
    "replicasets",
    "sts",
    "svc",
    "service",
    "services",
    "statefulset",
    "statefulsets",
];
pub(crate) const READ_ONLY_GET_BOOLEAN_OPTIONS: &[&str] = &[
    "--ignore-not-found",
    "--no-headers",
    "--show-kind",
    "--show-labels",
    "--use-openapi-print-columns",
];
const ENV_CONTROL_TOKENS: &[&str] = &["&&", "||", ";", "|", "|&", "&"];
pub(crate) const SECRET_VOLUME: &str = "Kubernetes secret volume";
pub(crate) const POD_ENVIRONMENT: &str = "Kubernetes pod environment";

static SAFE_JSONPATH_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A\{?\.?(?:items(?:\[-?\d+\]|\[\*\])?\.)?(?:metadata\.(?:name|namespace|uid)|status\.phase)\}?\z",
    )
    .expect("safe jsonpath field pattern")
});

/// `kubernetes_secret_read_source`.
pub(crate) fn kubernetes_secret_read_source(command: &str) -> Option<&'static str> {
    if py_strip(command).is_empty() {
        return None;
    }
    command_candidates(command, 0)
        .iter()
        .find_map(|candidate| secret_read_source_for_candidate(candidate))
}

/// `kubernetes_read_only_inventory_args`.
pub(crate) fn kubernetes_read_only_inventory_args(command_name: &str, args: &[String]) -> bool {
    let name = py_lower(command_name);
    if (name != "kubectl" && name != "oc") || args.is_empty() {
        return false;
    }
    let subcommand_index = skip_kubectl_options(args, 0);
    if subcommand_index >= args.len() || py_lower(&args[subcommand_index]) != "get" {
        return false;
    }
    let (resource, output) = read_only_get_resource_and_output(&args[subcommand_index + 1..]);
    let Some(resource) = resource else {
        return false;
    };
    if !READ_ONLY_INVENTORY_RESOURCES.contains(&resource.as_str()) {
        return false;
    }
    let Some(output) = output else {
        return true;
    };
    if output == "name" || output == "wide" {
        return true;
    }
    let Some((kind, template)) = output.split_once('=') else {
        return false;
    };
    if kind != "jsonpath" && kind != "jsonpath-as-json" {
        return false;
    }
    SAFE_JSONPATH_FIELD.is_match(py_strip(template).trim_matches(['\'', '"']))
}

/// `_read_only_get_resource_and_output`.
pub(crate) fn read_only_get_resource_and_output(
    args: &[String],
) -> (Option<String>, Option<String>) {
    let sets = OptionSets {
        value_flags: &[KUBECTL_OPTIONS_WITH_VALUES],
        boolean_flags: &[KUBECTL_BOOLEAN_OPTIONS, READ_ONLY_GET_BOOLEAN_OPTIONS],
        short_cluster: &[EXEC_BOOLEAN_SHORT_CLUSTER],
    };
    let mut resource: Option<String> = None;
    let mut output: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        let normalized = py_lower(token);
        if token == "--" {
            return (None, None);
        }
        if matches!(normalized.as_str(), "--raw" | "--output" | "-o") {
            if index + 1 >= args.len() || normalized == "--raw" {
                return (None, None);
            }
            output = Some(args[index + 1].clone());
            index += 2;
            continue;
        }
        if normalized.starts_with("--raw=") {
            return (None, None);
        }
        if normalized.starts_with("--output=") {
            output = token.split_once('=').map(|(_, value)| value.to_owned());
            index += 1;
            continue;
        }
        if normalized.starts_with("-o") && token.chars().count() > 2 {
            output = Some(token.chars().skip(2).collect());
            index += 1;
            continue;
        }
        if let Some(consumed) = kubernetes_option_tokens_consumed(args, index, sets) {
            index += consumed;
            continue;
        }
        if token.starts_with('-') {
            return (None, None);
        }
        if resource.is_none() {
            let name = inventory_resource_name(token);
            if name.contains(',') || resource_token_includes_secret(&name) {
                return (None, None);
            }
            resource = Some(name);
        } else if token.contains('/') {
            let additional = inventory_resource_name(token);
            if additional.contains(',')
                || resource_token_includes_secret(&additional)
                || !READ_ONLY_INVENTORY_RESOURCES.contains(&additional.as_str())
            {
                return (None, None);
            }
        }
        index += 1;
    }
    (resource, output)
}

/// `_inventory_resource_name`.
pub(crate) fn inventory_resource_name(token: &str) -> String {
    let lowered = py_lower(token);
    let head = lowered.split('/').next().unwrap_or("");
    head.split('.').next().unwrap_or("").to_owned()
}

/// `_command_candidates`.
pub(crate) fn command_candidates(command: &str, depth: usize) -> Vec<String> {
    if depth > 3 {
        return vec![command.to_owned()];
    }
    let mut candidates: Vec<String> = vec![command.to_owned()];
    let normalized = normalize_transparent_shell_command(command, None, None).normalized_command;
    let normalized = py_strip(&normalized);
    if !normalized.is_empty() && normalized != command {
        candidates.extend(command_candidates(normalized, depth + 1));
    }
    for substitution in extract_command_substitutions(command) {
        candidates.extend(command_candidates(&substitution, depth + 1));
    }
    let mut unique: Vec<String> = Vec::new();
    for candidate in candidates {
        if !py_strip(&candidate).is_empty() && !unique.contains(&candidate) {
            unique.push(candidate);
        }
    }
    unique
}

/// `_kubernetes_secret_read_source_for_candidate`.
pub(crate) fn secret_read_source_for_candidate(command: &str) -> Option<&'static str> {
    if let Some(source) = kubernetes_heredoc_secret_source(command) {
        return Some(source);
    }
    extract_command_segments(command)
        .iter()
        .find_map(|segment| {
            let tokens = shell_tokens(segment);
            if tokens.is_empty() {
                None
            } else {
                kubectl_secret_read_source_from_tokens(&tokens)
            }
        })
}

/// `_shell_tokens` (blank tokens other than the empty string are dropped).
pub(crate) fn shell_tokens(command: &str) -> Vec<String> {
    match crate::codex_output_py::shlex_split(command) {
        Some(tokens) => tokens
            .into_iter()
            .filter(|token| token.is_empty() || !py_strip(token).is_empty())
            .collect(),
        None => py_split_whitespace(command),
    }
}

/// `_kubectl_secret_read_source_from_tokens`.
pub(crate) fn kubectl_secret_read_source_from_tokens(tokens: &[String]) -> Option<&'static str> {
    let index = unwrap_command_start(tokens);
    if index >= tokens.len() {
        return None;
    }
    let command_name = path_name_lower(&tokens[index]);
    if command_name != "kubectl" && command_name != "oc" {
        return None;
    }
    let subcommand_index = skip_kubectl_options(tokens, index + 1);
    if subcommand_index >= tokens.len() {
        return None;
    }
    let subcommand = py_lower(&tokens[subcommand_index]);
    let after = subcommand_index + 1;
    if subcommand == "get" && kubectl_get_raw_secret_path(tokens, after) {
        return Some("Kubernetes Secret resource");
    }
    if command_name == "oc" && subcommand == "extract" && kubectl_resource_is_secret(tokens, after)
    {
        return Some("Kubernetes Secret resource");
    }
    if subcommand == "create" && kubectl_create_token(tokens, after) {
        return Some("Kubernetes service-account token");
    }
    if matches!(subcommand.as_str(), "get" | "describe" | "edit")
        && kubectl_resource_is_secret(tokens, after)
    {
        return Some("Kubernetes Secret resource");
    }
    if subcommand == "exec" || subcommand == "rsh" {
        return kubectl_exec_secret_source(&tokens[after..]);
    }
    if subcommand == "cp" && kubectl_cp_reads_secret_volume(&tokens[after..]) {
        return Some(SECRET_VOLUME);
    }
    None
}

/// `_unwrap_command_start`.
pub(crate) fn unwrap_command_start(tokens: &[String]) -> usize {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if is_assignment(token) {
            index += 1;
            continue;
        }
        let name = path_name_lower(token);
        if !WRAPPER_COMMANDS.contains(&name.as_str()) {
            return index;
        }
        if name == "env" {
            let parsed = parse_env_wrapper(&tokens[index + 1..], None, None);
            let command_index = parsed.command_index;
            let control_next = parsed
                .executable_argv
                .first()
                .is_some_and(|first| ENV_CONTROL_TOKENS.contains(&first.as_str()));
            if parsed.complete && (command_index.is_none() || control_next) {
                return index;
            }
            let Some(command_index) = command_index else {
                return tokens.len();
            };
            if !parsed.complete || !parsed.split_expansions.is_empty() {
                return tokens.len();
            }
            index += command_index + 1;
            continue;
        }
        index += 1;
        while index < tokens.len() {
            let current = tokens[index].as_str();
            if current == "--" {
                index += 1;
                break;
            }
            if is_assignment(current) {
                index += 1;
                continue;
            }
            if !current.starts_with('-') {
                break;
            }
            index += wrapper_option_tokens_consumed(&name, current);
        }
    }
    index
}

/// `_kubectl_resource_is_secret`.
pub(crate) fn kubectl_resource_is_secret(tokens: &[String], index: usize) -> bool {
    let index = skip_kubectl_options(tokens, index);
    index < tokens.len() && resource_token_includes_secret(&tokens[index])
}

/// `_kubectl_get_raw_secret_path`.
pub(crate) fn kubectl_get_raw_secret_path(tokens: &[String], mut index: usize) -> bool {
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--raw" && index + 1 < tokens.len() {
            return raw_secret_api_path(&tokens[index + 1]);
        }
        if let Some(value) = token.strip_prefix("--raw=") {
            return raw_secret_api_path(value);
        }
        index += 1;
    }
    false
}

/// `_kubectl_create_token`.
pub(crate) fn kubectl_create_token(tokens: &[String], index: usize) -> bool {
    let index = skip_kubectl_options(tokens, index);
    index < tokens.len() && py_lower(&tokens[index]) == "token"
}

/// `_kubectl_exec_secret_source`.
pub(crate) fn kubectl_exec_secret_source(tokens: &[String]) -> Option<&'static str> {
    let remote = kubectl_exec_remote_tokens(tokens);
    if remote.is_empty() {
        return None;
    }
    if remote_command_reads_secret_volume(&remote, 0) {
        return Some(SECRET_VOLUME);
    }
    if remote_command_reads_pod_environment(&remote, 0) {
        return Some(POD_ENVIRONMENT);
    }
    None
}

/// Arguments up to the first pipe.
fn before_pipe(args: &[String]) -> &[String] {
    match args.iter().position(|token| token == "|") {
        Some(position) => &args[..position],
        None => args,
    }
}

/// `_remote_command_reads_pod_environment`.
pub(crate) fn remote_command_reads_pod_environment(tokens: &[String], depth: usize) -> bool {
    if depth > 3 || tokens.is_empty() {
        return false;
    }
    let unwrapped = unwrap_command_start(tokens);
    if 0 < unwrapped && unwrapped < tokens.len() {
        return remote_command_reads_pod_environment(&tokens[unwrapped..], depth + 1);
    }
    let name = path_name_lower(&tokens[0]);
    if name == "printenv" {
        let names: Vec<&String> = before_pipe(&tokens[1..])
            .iter()
            .filter(|token| !token.starts_with('-'))
            .collect();
        return names.is_empty() || names.iter().any(|name| is_sensitive_env_name(name));
    }
    if name == "env" {
        return !before_pipe(&tokens[1..])
            .iter()
            .any(|token| !token.starts_with('-') && !is_assignment(token));
    }
    if SHELL_EXECUTABLES.contains(&name.as_str()) {
        if let Some(script) = shell_command_script(&tokens[1..]) {
            if script_reads_sensitive_env(&script) {
                return true;
            }
            return command_candidates(&script, 0).iter().any(|candidate| {
                remote_command_reads_pod_environment(&shell_tokens(candidate), depth + 1)
            });
        }
        return shell_stdin_secret_source(tokens) == Some(POD_ENVIRONMENT);
    }
    if !matching_source_arguments(tokens, is_proc_environ_path).is_empty()
        && !WRITE_ONLY_COMMANDS.contains(&name.as_str())
    {
        return true;
    }
    interpreter_reads_sensitive_env(&name, &tokens[1..])
}

/// `_remote_command_reads_secret_volume`.
pub(crate) fn remote_command_reads_secret_volume(tokens: &[String], depth: usize) -> bool {
    if depth > 3 || tokens.is_empty() {
        return false;
    }
    let unwrapped = unwrap_command_start(tokens);
    if 0 < unwrapped && unwrapped < tokens.len() {
        return remote_command_reads_secret_volume(&tokens[unwrapped..], depth + 1);
    }
    let name = path_name_lower(&tokens[0]);
    if SHELL_EXECUTABLES.contains(&name.as_str()) {
        if let Some(script) = shell_command_script(&tokens[1..]) {
            return command_candidates(&script, 0).iter().any(|candidate| {
                remote_command_reads_secret_volume(&shell_tokens(candidate), depth + 1)
            });
        }
        return shell_stdin_secret_source(tokens) == Some(SECRET_VOLUME);
    }
    if extract_input_redirects(&tokens.join(" "))
        .iter()
        .any(|target| is_secret_volume_path(target))
    {
        return true;
    }
    if name == "cp" {
        return remote_copy_source_reads_secret_volume(&tokens[1..]);
    }
    if secret_volume_source_arguments(tokens).is_empty() {
        return false;
    }
    !WRITE_ONLY_COMMANDS.contains(&name.as_str())
}
