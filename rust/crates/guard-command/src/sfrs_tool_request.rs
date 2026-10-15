//! `ToolActionRequestMatch` and the Docker request classification
//! (`request_models.py` and `docker_requests.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_py::shlex_join;
use crate::env_wrapper::parse_env_wrapper;
use crate::sfrs_constants::{
    DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS, DOCKER_BUILDX_BUILD_SUBCOMMANDS, DOCKER_BUILD_SUBCOMMANDS,
    DOCKER_COMPOSE_FLAG_OPTIONS, DOCKER_COMPOSE_OPTIONS_WITH_VALUES,
    DOCKER_COMPOSE_SAFE_SUBCOMMANDS, DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS,
    DOCKER_COMPOSE_SUBCOMMAND, DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS,
    DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS, DOCKER_SENSITIVE_CONTEXT_ENV_KEYS,
};
use crate::sfrs_docker_args::{
    docker_attached_short_context_option, docker_build_args_are_sensitive,
    docker_buildx_subcommand_index, docker_global_option_has_value,
    docker_subcommand_help_requested, docker_subcommand_index,
};
use crate::sfrs_patterns::SHELL_ASSIGNMENT_PATTERN;
use crate::sfrs_request_data::SENSITIVE_PATH_REASONS;
use crate::sfrs_requests::classify_sensitive_path;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name,
    shell_command_token_without_attached_redirection, shell_segment_primary_command,
    split_shell_parts,
};

/// `ToolActionRequestMatch`: a sensitive native tool action.
#[derive(Clone, Debug, Default)]
pub(crate) struct ToolActionRequest {
    pub tool_name: String,
    pub normalized_tool_name: String,
    pub command_text: String,
    pub action_class: String,
    pub reason: String,
    pub raw_command_text: Option<String>,
    pub wrapper_chain: Vec<String>,
    pub shell_execution_context_hash: Option<String>,
    pub shell_execution_context_reason_code: Option<String>,
    pub shell_execution_effective_cwds: Vec<String>,
    pub guard_default_action: Option<String>,
    pub reason_code: Option<String>,
    pub restricted_profile_version: Option<String>,
    pub pytest_config_identity_sha256: Option<String>,
    pub pytest_config_sources: Vec<String>,
    pub pytest_config_reason_codes: Vec<String>,
    pub script_read_identity_sha256: Option<String>,
}

impl ToolActionRequest {
    pub(crate) fn new(
        tool_name: &str,
        normalized_tool_name: &str,
        command_text: &str,
        action_class: &str,
        reason: &str,
    ) -> Self {
        Self {
            tool_name: tool_name.to_owned(),
            normalized_tool_name: normalized_tool_name.to_owned(),
            command_text: command_text.to_owned(),
            action_class: action_class.to_owned(),
            reason: reason.to_owned(),
            ..Self::default()
        }
    }
}

const DOCKER_SENSITIVE_REASON: &str = "Guard treats Docker login, run, push, and credential-bearing build actions as sensitive because they can expose credentials or execute privileged container workflows. Docker Compose actions are sensitive when they use subcommands that execute arbitrary commands or copy files (run, exec, cp, push, publish, watch), supply secret-bearing input (--env-file), target a non-default Docker host or context, or carry TLS/credential material through flags or environment variables.";

/// `_docker_sensitive_tool_action_request`.
pub(crate) fn docker_sensitive_tool_action_request(
    tool_name: &str,
    normalized_tool_name: &str,
    command_text: &str,
) -> Option<ToolActionRequest> {
    docker_sensitive_reason(command_text, false)?;
    Some(ToolActionRequest::new(
        tool_name,
        normalized_tool_name,
        command_text,
        "docker-sensitive command",
        DOCKER_SENSITIVE_REASON,
    ))
}

/// `_docker_config_tool_action_request`.
pub(crate) fn docker_config_tool_action_request(
    tool_name: &str,
    normalized_tool_name: &str,
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<ToolActionRequest> {
    docker_config_path_from_command(command_text, cwd, home_dir)?;
    let reason = SENSITIVE_PATH_REASONS
        .iter()
        .find(|(label, _)| *label == "Docker client config")
        .map_or("", |(_, reason)| *reason);
    Some(ToolActionRequest::new(
        tool_name,
        normalized_tool_name,
        command_text,
        "Docker client config access",
        reason,
    ))
}

/// `_docker_config_path_from_command`.
pub(crate) fn docker_config_path_from_command(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<String> {
    if !command_text
        .replace('\\', "/")
        .contains(".docker/config.json")
    {
        return None;
    }
    classify_sensitive_path(".docker/config.json", cwd, home_dir).map(|found| found.path)
}

fn is_assignment(token: &str) -> bool {
    SHELL_ASSIGNMENT_PATTERN.is_match(token).unwrap_or(false)
}

/// `_docker_sensitive_reason`.
pub(crate) fn docker_sensitive_reason(
    command_text: &str,
    inherited_sensitive_env: bool,
) -> Option<String> {
    let parts = split_shell_parts(crate::codex_output_py::py_strip(command_text));
    let mut exported: Vec<(String, bool)> = Vec::new();
    for segment in iter_shell_command_segments(&parts) {
        if !segment.is_empty() && normalized_shell_command_name(&segment[0]) == "env" {
            let parsed = parse_env_wrapper(&segment[1..], None, None);
            if !parsed.complete {
                return Some("env-wrapper-unresolved".to_owned());
            }
            let mut env_sensitive = if parsed.option_effects.ignore_environment {
                false
            } else {
                inherited_sensitive_env
            };
            env_sensitive = env_sensitive
                || docker_env_assignments_are_sensitive(&parsed.environment_delta.assignments);
            if !parsed.executable_argv.is_empty() {
                if let Some(reason) =
                    docker_sensitive_reason(&shlex_join(&parsed.executable_argv), env_sensitive)
                {
                    return Some(reason);
                }
            }
            continue;
        }
        let (command_name, command_index) = shell_segment_primary_command(&segment);
        if command_name.as_deref() == Some("export") {
            if let Some(index) = command_index {
                merge_exported(&mut exported, &segment[..index]);
                merge_exported(&mut exported, &segment[index + 1..]);
                continue;
            }
        }
        let Some(index) = command_index else {
            continue;
        };
        if command_name.as_deref() != Some("docker") {
            continue;
        }
        let sensitive_env_context = inherited_sensitive_env
            || exported.iter().any(|(_, flag)| *flag)
            || docker_env_context_is_sensitive(&segment[..index]);
        let global_tokens = &segment[index + 1..];
        let Some(subcommand_index) = docker_subcommand_index(global_tokens) else {
            continue;
        };
        let sensitive_context = sensitive_env_context
            || docker_global_context_is_sensitive(&global_tokens[..subcommand_index]);
        let args = &global_tokens[subcommand_index..];
        let subcommand = args[0].to_lowercase();
        if docker_subcommand_help_requested(args) {
            continue;
        }
        if DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS.contains(&subcommand.as_str()) {
            return Some(subcommand);
        }
        if DOCKER_BUILD_SUBCOMMANDS.contains(&subcommand.as_str())
            && docker_build_args_are_sensitive(&args[1..])
        {
            return Some("build-sensitive-flags".to_owned());
        }
        if subcommand == DOCKER_COMPOSE_SUBCOMMAND {
            if let Some(reason) = docker_compose_sensitive_reason(&args[1..], sensitive_context) {
                return Some(reason);
            }
            continue;
        }
        if subcommand == "buildx" && args.len() > 1 {
            let Some(buildx_index) = docker_buildx_subcommand_index(&args[1..]) else {
                continue;
            };
            let buildx_args = &args[1 + buildx_index..];
            let buildx_subcommand = buildx_args[0].to_lowercase();
            if DOCKER_BUILDX_BUILD_SUBCOMMANDS.contains(&buildx_subcommand.as_str())
                && docker_build_args_are_sensitive(&buildx_args[1..])
            {
                return Some("buildx-build-sensitive-flags".to_owned());
            }
        }
    }
    None
}

/// `exported_env_context.update(...)`: later keys replace earlier ones in place.
fn merge_exported(exported: &mut Vec<(String, bool)>, tokens: &[String]) {
    for (key, flag) in docker_exported_env_context_sensitivity(tokens) {
        match exported.iter_mut().find(|(name, _)| *name == key) {
            Some(entry) => entry.1 = flag,
            None => exported.push((key, flag)),
        }
    }
}

fn token_matches_option(token: &str, options: &[&str]) -> bool {
    options.iter().any(|option| {
        token == *option
            || token
                .strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

/// `_docker_global_context_is_sensitive`.
pub(crate) fn docker_global_context_is_sensitive(global_tokens: &[String]) -> bool {
    let mut index = 0;
    while index < global_tokens.len() {
        let token = global_tokens[index].as_str();
        if let Some((flag, value)) = docker_attached_short_context_option(token) {
            if docker_global_context_value_is_sensitive(flag, &value) {
                return true;
            }
            index += 1;
            continue;
        }
        if docker_global_option_has_value(token) {
            if let Some((flag, value)) = token.split_once('=') {
                if docker_global_context_value_is_sensitive(flag, value) {
                    return true;
                }
                index += 1;
                continue;
            }
            let value = global_tokens.get(index + 1).map_or("", String::as_str);
            if docker_global_context_value_is_sensitive(token, value) {
                return true;
            }
            index += 2;
            continue;
        }
        if token_matches_option(token, DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS) {
            return true;
        }
        index += 1;
    }
    false
}

fn strip_quotes_and_space(value: &str) -> String {
    let stripped = crate::codex_output_py::py_strip(value);
    stripped.trim_matches(|c| c == '"' || c == '\'').to_owned()
}

/// `_docker_global_context_value_is_sensitive`.
pub(crate) fn docker_global_context_value_is_sensitive(flag: &str, value: &str) -> bool {
    if !DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS.contains(&flag) {
        return false;
    }
    let normalized = strip_quotes_and_space(value);
    if flag == "--context" || flag == "-c" {
        return !matches!(normalized.to_lowercase().as_str(), "" | "default");
    }
    true
}

/// `_docker_env_context_is_sensitive`.
pub(crate) fn docker_env_context_is_sensitive(prefix_tokens: &[String]) -> bool {
    let env_index = prefix_tokens
        .iter()
        .position(|token| normalized_shell_command_name(token) == "env");
    if let Some(index) = env_index {
        let parsed = parse_env_wrapper(&prefix_tokens[index + 1..], None, None);
        if !parsed.complete {
            return true;
        }
        return docker_env_assignments_are_sensitive(&parsed.environment_delta.assignments);
    }
    prefix_tokens.iter().any(|token| {
        docker_env_assignment(token)
            .is_some_and(|(key, value)| docker_env_context_value_is_sensitive(&key, &value))
    })
}

/// `_docker_env_assignments_are_sensitive`.
pub(crate) fn docker_env_assignments_are_sensitive(assignments: &[(String, String)]) -> bool {
    assignments.iter().any(|(name, value)| {
        let upper = name.to_uppercase();
        DOCKER_SENSITIVE_CONTEXT_ENV_KEYS.contains(&upper.as_str())
            && docker_env_context_value_is_sensitive(&upper, value)
    })
}

/// `_docker_exported_env_context_sensitivity`, in first-insertion order.
pub(crate) fn docker_exported_env_context_sensitivity(args: &[String]) -> Vec<(String, bool)> {
    let mut exported: Vec<(String, bool)> = Vec::new();
    for token in args {
        if token.starts_with('-') {
            continue;
        }
        let Some((key, value)) = docker_env_assignment(token) else {
            continue;
        };
        let flag = docker_env_context_value_is_sensitive(&key, &value);
        match exported.iter_mut().find(|(name, _)| *name == key) {
            Some(entry) => entry.1 = flag,
            None => exported.push((key, flag)),
        }
    }
    exported
}

/// `_docker_env_assignment`.
pub(crate) fn docker_env_assignment(token: &str) -> Option<(String, String)> {
    let without_redirect = shell_command_token_without_attached_redirection(token);
    let normalized = crate::codex_output_py::py_strip(&without_redirect);
    if !is_assignment(normalized) {
        return None;
    }
    let (key, value) = normalized.split_once('=')?;
    let key = key.trim_end_matches('+').to_uppercase();
    if !DOCKER_SENSITIVE_CONTEXT_ENV_KEYS.contains(&key.as_str()) {
        return None;
    }
    Some((key, strip_quotes_and_space(value)))
}

/// `_docker_env_context_value_is_sensitive`.
pub(crate) fn docker_env_context_value_is_sensitive(key: &str, value: &str) -> bool {
    let normalized = strip_quotes_and_space(value);
    match key {
        "DOCKER_CONTEXT" => !matches!(normalized.to_lowercase().as_str(), "" | "default"),
        "DOCKER_HOST" => {
            let lowered = normalized.to_lowercase();
            !(normalized.is_empty()
                || lowered.starts_with("unix://")
                || lowered.starts_with("npipe://"))
        }
        "DOCKER_TLS_VERIFY" => !matches!(
            normalized.to_lowercase().as_str(),
            "" | "0" | "false" | "no"
        ),
        _ => !normalized.is_empty(),
    }
}

/// `_docker_compose_sensitive_reason`.
pub(crate) fn docker_compose_sensitive_reason(
    args: &[String],
    sensitive_context: bool,
) -> Option<String> {
    if sensitive_context {
        return Some("compose-sensitive-context".to_owned());
    }
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            let remaining = &args[index + 1..];
            return remaining.first().and_then(|first| {
                docker_compose_subcommand_reason(&first.to_lowercase(), &remaining[1..])
            });
        }
        if token_matches_option(token, DOCKER_COMPOSE_OPTIONS_WITH_VALUES) {
            if docker_compose_option_is_secret_bearing(token) {
                return Some("compose-env-file".to_owned());
            }
            index += if token.contains('=') { 1 } else { 2 };
            continue;
        }
        if token_matches_option(token, DOCKER_COMPOSE_FLAG_OPTIONS) {
            index += 1;
            continue;
        }
        if token.starts_with('-') && !token.starts_with("--") {
            index += 1;
            continue;
        }
        return docker_compose_subcommand_reason(&token.to_lowercase(), &args[index + 1..]);
    }
    None
}

/// `_docker_compose_subcommand_reason`.
pub(crate) fn docker_compose_subcommand_reason(
    compose_subcommand: &str,
    subcommand_args: &[String],
) -> Option<String> {
    if DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS.contains(&compose_subcommand) {
        return Some(format!("compose-{compose_subcommand}"));
    }
    if subcommand_args
        .iter()
        .any(|token| docker_compose_option_is_secret_bearing(token))
    {
        return Some("compose-env-file".to_owned());
    }
    if DOCKER_BUILD_SUBCOMMANDS.contains(&compose_subcommand)
        && docker_build_args_are_sensitive(subcommand_args)
    {
        return Some("compose-build-sensitive-flags".to_owned());
    }
    if DOCKER_COMPOSE_SAFE_SUBCOMMANDS.contains(&compose_subcommand) {
        return None;
    }
    Some("compose-unknown-subcommand".to_owned())
}

/// `_docker_compose_option_is_secret_bearing`.
pub(crate) fn docker_compose_option_is_secret_bearing(token: &str) -> bool {
    token == "--env-file" || token.starts_with("--env-file=")
}
