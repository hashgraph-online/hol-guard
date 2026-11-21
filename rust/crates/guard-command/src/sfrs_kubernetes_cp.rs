//! Kubernetes cp and remote copy helpers (`runtime/kubernetes_commands.py`).

#![allow(dead_code)]

use crate::hook_adapter_pytext::py_strip;
use crate::sfrs_kubernetes_commands::{
    remote_command_reads_pod_environment, remote_command_reads_secret_volume, shell_tokens,
    CP_BOOLEAN_OPTIONS, CP_OPTIONS_WITH_VALUES, POD_ENVIRONMENT, SECRET_VOLUME,
};
use crate::sfrs_kubernetes_support::{
    exec_remote_tokens_after_resource, is_output_redirect_target, is_secret_volume_path,
    kubernetes_option_tokens_consumed, matching_source_arguments, remote_cp_path,
    script_reads_sensitive_env, OptionSets, EXEC_BOOLEAN_SHORT_CLUSTER, KUBECTL_BOOLEAN_OPTIONS,
    KUBECTL_OPTIONS_WITH_VALUES,
};

/// `_kubectl_cp_reads_secret_volume`.
pub(crate) fn kubectl_cp_reads_secret_volume(tokens: &[String]) -> bool {
    let operands = kubectl_cp_operands(tokens);
    if operands.len() < 2 {
        return false;
    }
    remote_cp_path(&operands[0]).is_some_and(is_secret_volume_path)
}

/// `_kubectl_cp_operands`.
pub(crate) fn kubectl_cp_operands(tokens: &[String]) -> Vec<String> {
    let sets = OptionSets {
        value_flags: &[KUBECTL_OPTIONS_WITH_VALUES, CP_OPTIONS_WITH_VALUES],
        boolean_flags: &[KUBECTL_BOOLEAN_OPTIONS, CP_BOOLEAN_OPTIONS],
        short_cluster: &[EXEC_BOOLEAN_SHORT_CLUSTER],
    };
    let mut operands = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if let Some(consumed) = kubernetes_option_tokens_consumed(tokens, index, sets) {
            index += consumed;
            continue;
        }
        if !tokens[index].starts_with('-') {
            operands.push(tokens[index].clone());
        }
        index += 1;
    }
    operands
}

/// `_remote_copy_source_reads_secret_volume`.
pub(crate) fn remote_copy_source_reads_secret_volume(tokens: &[String]) -> bool {
    remote_cp_operands(tokens)
        .iter()
        .any(|operand| is_secret_volume_path(operand) && !is_output_redirect_target(operand, None))
}

/// `_remote_cp_operands`.
pub(crate) fn remote_cp_operands(tokens: &[String]) -> Vec<String> {
    let mut operands: Vec<String> = Vec::new();
    let mut has_target_directory = false;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if (token == "--target-directory" || token == "-t") && index + 1 < tokens.len() {
            has_target_directory = true;
            index += 2;
            continue;
        }
        if token.starts_with("--target-directory=") {
            has_target_directory = true;
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        operands.push(token.to_owned());
        index += 1;
    }
    if has_target_directory {
        return operands;
    }
    if operands.len() >= 2 {
        operands.pop();
        operands
    } else {
        Vec::new()
    }
}

/// `_shell_stdin_secret_source`.
pub(crate) fn shell_stdin_secret_source(tokens: &[String]) -> Option<&'static str> {
    if !tokens.iter().skip(1).any(|token| token.starts_with("<<")) {
        return None;
    }
    let mut body: Vec<&str> = tokens
        .iter()
        .skip(1)
        .filter(|token| !token.starts_with("<<"))
        .map(String::as_str)
        .collect();
    body.pop();
    let joined = body.join(" ");
    let script_text = py_strip(&joined);
    if script_text.is_empty() {
        return None;
    }
    let script_tokens = shell_tokens(script_text);
    if remote_command_reads_secret_volume(&script_tokens, 1) {
        return Some(SECRET_VOLUME);
    }
    if script_reads_sensitive_env(script_text) {
        return Some(POD_ENVIRONMENT);
    }
    if remote_command_reads_pod_environment(&script_tokens, 1) {
        return Some(POD_ENVIRONMENT);
    }
    None
}

/// `_kubectl_exec_remote_tokens`.
pub(crate) fn kubectl_exec_remote_tokens(tokens: &[String]) -> Vec<String> {
    exec_remote_tokens_after_resource(tokens)
}

/// `_secret_volume_source_arguments`.
pub(crate) fn secret_volume_source_arguments(tokens: &[String]) -> Vec<String> {
    matching_source_arguments(tokens, is_secret_volume_path)
}
