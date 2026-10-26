//! `secret_file_request_services/tool_action_requests.py`:
//! `extract_sensitive_tool_action_request` and its private helpers
//! (`_kubernetes_or_environment_secret_request`, `_finalize_shell_match`,
//! `_unverified_git_fetch_request`, `_segment_invokes_git_fetch`).

// Consumed by the dispatcher wiring.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::benign_request_api::ToolActionControls;
use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::command_model::CanonicalCommand;
use crate::hook_adapter_value::OValue;
use crate::package_intent_common::candidate_command_texts;
use crate::sfrs_constants::{FILE_WRITE_TOOL_NAMES, SHELL_TOOL_NAMES};
use crate::sfrs_developer_graph::git_segment;
use crate::sfrs_dispatcher_request::{
    model_context, request_with_shell_execution_context, request_with_wrapper_context,
    DispatchError, NativeEvaluationView, ToolActionRequestMatch,
};
use crate::sfrs_environment_secret::environment_secret_dump_request;
use crate::sfrs_git_fetch::{command_is_origin_shaped_git_fetch, git_fetch_operands};
use crate::sfrs_git_index::owned_git_index_inspection_action_class;
use crate::sfrs_kubernetes_commands::kubernetes_secret_read_source;
use crate::sfrs_requests::normalize_tool_name;
use crate::sfrs_shell_classifier::{destructive_shell_tool_action_request, ShellClassifyInputs};
use crate::sfrs_shell_tokens::{shell_normalized_tool_name, shell_segment_primary_command};
use crate::sfrs_tool_request::{
    docker_config_tool_action_request, docker_sensitive_tool_action_request,
};
use crate::shell_command_wrappers::normalize_transparent_shell_command;
use crate::shell_execution_context::ShellExecutionContext;

const GIT_GLOBAL_FLAG_OPTIONS: &[&str] = &[
    "--bare",
    "--literal-pathspecs",
    "--no-advice",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-pager",
    "--no-replace-objects",
    "--paginate",
    "-P",
    "-p",
];
const GIT_GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
    "-C",
    "-c",
];
const COMMAND_ARGUMENT_KEYS: &[&str] = &["command", "cmd", "shell_command", "shellCommand"];

type Outcome = Result<Option<ToolActionRequestMatch>, DispatchError>;

/// The keyword arguments of `extract_sensitive_tool_action_request`.
pub(crate) struct ExtractInputs<'a> {
    pub cwd: Option<&'a Path>,
    pub home_dir: Option<&'a Path>,
    pub canonical_command: Option<&'a CanonicalCommand>,
    pub native_evaluation: Option<&'a NativeEvaluationView>,
    pub controls: Option<&'a ToolActionControls>,
    pub ctx: &'a Ctx<'a>,
}

/// `extract_sensitive_tool_action_request`.
pub(crate) fn extract_sensitive_tool_action_request(
    tool_name: &OValue,
    arguments: &Value,
    inputs: &ExtractInputs,
) -> Outcome {
    let normalized = normalize_tool_name(tool_name);
    let is_shell = normalized
        .as_deref()
        .is_some_and(|name| SHELL_TOOL_NAMES.contains(&name));
    let filtered;
    let command_arguments = match arguments {
        Value::Object(map) if !is_shell => {
            filtered = Value::Object(
                map.iter()
                    .filter(|(key, _)| COMMAND_ARGUMENT_KEYS.contains(&key.as_str()))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
            &filtered
        }
        other => other,
    };
    let command_texts = candidate_command_texts(command_arguments);
    if normalized
        .as_deref()
        .is_some_and(|name| FILE_WRITE_TOOL_NAMES.contains(&name))
    {
        return Ok(None);
    }
    if normalized.is_none() && command_texts.is_empty() {
        return Ok(None);
    }
    let requested = match tool_name {
        OValue::Str(text) if !py_strip(text).is_empty() => py_strip(text).to_owned(),
        _ => "Shell".to_owned(),
    };
    let has_candidates = !candidate_command_texts(arguments).is_empty();
    let Some(effective) = shell_normalized_tool_name(normalized.as_deref(), has_candidates) else {
        return Ok(None);
    };
    for command_text in command_texts {
        if let Some(request) = request_for_candidate(&requested, &effective, &command_text, inputs)?
        {
            return Ok(Some(request));
        }
        if let Some(request) = native_block_request(&requested, &effective, &command_text, inputs) {
            return Ok(Some(request));
        }
    }
    Ok(None)
}

/// The per-candidate request chain, up to the retry on the raw text.
fn request_for_candidate(
    requested: &str,
    effective: &str,
    raw_command_text: &str,
    inputs: &ExtractInputs,
) -> Outcome {
    let (cwd, home_dir, ctx) = (inputs.cwd, inputs.home_dir, inputs.ctx);
    let candidate_canonical = inputs
        .canonical_command
        .filter(|command| command.raw_text == py_strip(raw_command_text));
    let mut command_text = raw_command_text.to_owned();
    let mut wrapper_chain: Vec<String> = Vec::new();
    if SHELL_TOOL_NAMES.contains(&effective) {
        let normalized = normalize_transparent_shell_command(&command_text, cwd, home_dir);
        command_text = normalized.normalized_command;
        wrapper_chain = normalized.wrapper_chain;
    }
    let normalized_command_text = command_text.clone();
    if let Some(request) = unverified_git_fetch_request(requested, effective, &command_text, inputs)
    {
        return Ok(Some(request));
    }
    let wrap = |request: ToolActionRequestMatch| {
        if wrapper_chain.is_empty() {
            request
        } else {
            request_with_wrapper_context(request, raw_command_text, &wrapper_chain)
        }
    };
    if let Some(request) = docker_sensitive_tool_action_request(requested, effective, &command_text)
    {
        let request =
            request_with_shell_execution_context(request.into(), &command_text, cwd, None, ctx);
        return Ok(Some(wrap(request)));
    }
    if raw_command_text != command_text {
        if let Some(request) =
            docker_sensitive_tool_action_request(requested, effective, raw_command_text)
        {
            let request = request_with_shell_execution_context(
                request.into(),
                &normalized_command_text,
                cwd,
                None,
                ctx,
            );
            let request = ToolActionRequestMatch {
                command_text: normalized_command_text.clone(),
                ..request
            };
            return Ok(Some(wrap(request)));
        }
    }
    if let Some(request) =
        docker_config_tool_action_request(requested, effective, &command_text, cwd, home_dir)
    {
        let request =
            request_with_shell_execution_context(request.into(), &command_text, cwd, None, ctx);
        return Ok(Some(wrap(request)));
    }
    let destructive_context = model_context(ctx, &command_text, cwd, cwd, home_dir);
    if let Some(request) = kubernetes_or_environment_secret_request(
        requested,
        effective,
        &command_text,
        inputs,
        &destructive_context,
    )? {
        return Ok(Some(wrap(request)));
    }
    let raw_destructive_context = if raw_command_text != command_text {
        model_context(ctx, raw_command_text, cwd, cwd, home_dir)
    } else {
        destructive_context.clone()
    };
    let bound = candidate_canonical.filter(|command| command.normalized_text == command_text);
    let classified = destructive_shell_tool_action_request(&ShellClassifyInputs {
        tool_name: requested,
        normalized_tool_name: effective,
        command_text: &command_text,
        cwd,
        home_dir,
        canonical_command: bound,
        raw_command_text: Some(raw_command_text),
        execution_context: Some(&destructive_context),
        raw_execution_context: Some(&raw_destructive_context),
        native_evaluation: bound.and(inputs.native_evaluation),
        controls: inputs.controls,
        ctx,
    })?;
    if let Some(request) = classified {
        let request = request_with_shell_execution_context(
            request,
            &command_text,
            cwd,
            Some(&destructive_context),
            ctx,
        );
        return Ok(Some(wrap(request)));
    }
    if wrapper_chain.is_empty() {
        return Ok(None);
    }
    let retried = destructive_shell_tool_action_request(&ShellClassifyInputs {
        tool_name: requested,
        normalized_tool_name: effective,
        command_text: raw_command_text,
        cwd,
        home_dir,
        canonical_command: candidate_canonical,
        raw_command_text: Some(raw_command_text),
        execution_context: Some(&raw_destructive_context),
        raw_execution_context: Some(&raw_destructive_context),
        native_evaluation: inputs.native_evaluation,
        controls: inputs.controls,
        ctx,
    })?;
    let Some(request) = retried else {
        return Ok(None);
    };
    let request =
        request_with_shell_execution_context(request, &normalized_command_text, cwd, None, ctx);
    let request = ToolActionRequestMatch {
        command_text: normalized_command_text,
        ..request
    };
    Ok(Some(request_with_wrapper_context(
        request,
        raw_command_text,
        &wrapper_chain,
    )))
}

/// The bound native rejection that has no semantic rule match to project.
fn native_block_request(
    requested: &str,
    effective: &str,
    raw_command_text: &str,
    inputs: &ExtractInputs,
) -> Option<ToolActionRequestMatch> {
    let (native, canonical) = (inputs.native_evaluation?, inputs.canonical_command?);
    if canonical.raw_text != py_strip(raw_command_text) {
        return None;
    }
    let blocked = native.security_identity == canonical.security_identity()
        && native.minimum_action == crate::command_evaluation::CommandDecisionFloor::Block
        && native.match_default_modes.is_empty()
        && native.has_reason("native.classification-block");
    blocked.then(|| ToolActionRequestMatch {
        canonical_command: Some(canonical.clone()),
        guard_default_action: Some("block".to_owned()),
        reason_code: Some("native-command-classification-block".to_owned()),
        ..ToolActionRequestMatch::new(
            requested,
            effective,
            raw_command_text,
            "unmodeled shell command",
            "HOL Guard blocked this command because the native evaluator could not safely classify it.",
        )
    })
}

/// `_kubernetes_or_environment_secret_request`.
fn kubernetes_or_environment_secret_request(
    requested: &str,
    effective: &str,
    command_text: &str,
    inputs: &ExtractInputs,
    context: &ShellExecutionContext,
) -> Outcome {
    let request = if let Some(source) = kubernetes_secret_read_source(command_text) {
        ToolActionRequestMatch::new(
            requested,
            effective,
            command_text,
            "Kubernetes secret read command",
            &format!(
                "Guard treats {source} reads through Kubernetes CLIs as sensitive because they can expose cluster credentials or application secrets before the user confirms the action."
            ),
        )
    } else {
        let fallback = inputs
            .cwd
            .is_none()
            .then(|| PathBuf::from(inputs.ctx.process_cwd.to_string()));
        let dump = environment_secret_dump_request(
            requested,
            effective,
            command_text,
            inputs.cwd,
            inputs.home_dir,
            fallback.as_deref(),
        )
        .map_err(DispatchError::new)?;
        match dump {
            Some(request) => request.into(),
            None => return Ok(None),
        }
    };
    Ok(Some(request_with_shell_execution_context(
        request,
        command_text,
        inputs.cwd,
        Some(context),
        inputs.ctx,
    )))
}

/// `_unverified_git_fetch_request`.
fn unverified_git_fetch_request(
    requested: &str,
    effective: &str,
    command_text: &str,
    inputs: &ExtractInputs,
) -> Option<ToolActionRequestMatch> {
    if !command_text.contains("git") {
        return None;
    }
    let (cwd, home_dir, ctx) = (inputs.cwd, inputs.home_dir, inputs.ctx);
    let parsing_cwd = cwd.or(home_dir).map_or_else(
        || PathBuf::from(ctx.process_cwd.to_string()),
        Path::to_path_buf,
    );
    let context = model_context(
        ctx,
        command_text,
        Some(&parsing_cwd),
        Some(&parsing_cwd),
        home_dir,
    );
    let invokes: Vec<bool> = context
        .segments
        .iter()
        .map(|segment| segment_invokes_git_fetch(&segment.tokens))
        .collect();
    if !invokes.iter().any(|found| *found) {
        let action_class =
            owned_git_index_inspection_action_class(command_text, cwd, home_dir, ctx)?;
        return Some(ToolActionRequestMatch::new(
            requested,
            effective,
            command_text,
            action_class,
            "Git cached diff needs a repository-bound index inspection Guard can verify. Use git diff --cached with check/stat flags or lockfile excludes, or confirm the exact index read in Guard.",
        ));
    }
    let home_text = home_dir.map(|home| home.to_string_lossy().into_owned());
    let converted: Vec<_> = context.segments.iter().map(git_segment).collect();
    if cwd.is_some()
        && ctx
            .host
            .standalone_git_routine(&converted, context.complete, home_text.as_deref())
    {
        return None;
    }
    if context.complete
        && context
            .segments
            .iter()
            .zip(&invokes)
            .zip(&converted)
            .all(|((_, fetches), segment)| {
                !fetches
                    || ctx
                        .host
                        .git_inspection_segment(segment, home_text.as_deref())
            })
    {
        return None;
    }
    let tokens: Vec<Vec<String>> = context
        .segments
        .iter()
        .map(|segment| segment.tokens.clone())
        .collect();
    let action_class = if command_refreshes_a_named_origin(&tokens) {
        "git origin refresh"
    } else {
        "unverified Git remote refresh"
    };
    Some(ToolActionRequestMatch::new(
        requested,
        effective,
        command_text,
        action_class,
        "Git fetch needs a repository-bound origin Guard can verify. Run it from that repository, or use git -C with a path under your home directory, a named origin, and no force/prune/URL remotes.",
    ))
}

#[cfg(test)]
#[path = "sfrs_dispatcher_fetch_tests.rs"]
mod fetch_tests;

/// Every executable segment refreshes a named origin. The frozen port mirror
/// reads the shape the retired Python read, and the live shape also admits
/// the dry run that reports the same refresh, so a fetch no proof settles
/// still names the action it would perform and carries its network risk.
fn command_refreshes_a_named_origin(segments: &[Vec<String>]) -> bool {
    if command_is_origin_shaped_git_fetch(segments) {
        return true;
    }
    !segments.is_empty()
        && segments.iter().all(|tokens| {
            git_fetch_operands(tokens).is_some_and(|operands| {
                crate::command_compatibility::git_fetch_origin_shaped(&operands)
            })
        })
}

/// `_segment_invokes_git_fetch`.
pub(crate) fn segment_invokes_git_fetch(tokens: &[String]) -> bool {
    let (Some(name), Some(index)) = shell_segment_primary_command(tokens) else {
        return false;
    };
    if name != "git" {
        return false;
    }
    let args = &tokens[index + 1..];
    let mut position = 0;
    while position < args.len() {
        let token = &args[position];
        let (option_name, value) = match token.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (token.as_str(), None),
        };
        if GIT_GLOBAL_FLAG_OPTIONS.contains(&token.as_str()) {
            position += 1;
            continue;
        }
        if GIT_GLOBAL_VALUE_OPTIONS.contains(&option_name) {
            if let Some(value) = value {
                if value.is_empty() {
                    return false;
                }
                position += 1;
                continue;
            }
            if position + 1 >= args.len() {
                return false;
            }
            position += 2;
            continue;
        }
        if token.starts_with('-') {
            position += 1;
            continue;
        }
        return token == "fetch";
    }
    false
}
