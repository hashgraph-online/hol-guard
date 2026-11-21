//! Python interpreter identity resolution (`interpreter_identity.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::{py_strip, PyPath};
use crate::sfrs_constants::SHELL_COMMAND_STRING_INTERPRETERS;
use crate::sfrs_interpreter_launch::{
    ambiguous_python_evidence_from_tokens, normalized_interpreter_cwd,
    python_interpreter_executable_identity, shell_launch_candidate,
    without_interpreter_reuse_nonces, Environment,
};
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_shell_tokens::{
    normalized_shell_command_name, shell_command_token_without_attached_redirection,
    split_shell_parts,
};
use crate::sfrs_substitution::shell_command_substitution_payloads;
use crate::shell_execution_context::{
    model_shell_execution_context, validate_shell_execution_segment, ShellExecutionContext,
};
use crate::shell_secret_read_support::shell_interpreter_command_payload;

/// Arguments of `_python_interpreter_executable_identities` that stay fixed
/// across the recursion.
pub(crate) struct IdentityInputs<'a> {
    pub(crate) cwd: Option<&'a PyPath>,
    pub(crate) home_dir: Option<&'a PyPath>,
    pub(crate) environment: Option<&'a Environment>,
    pub(crate) workspace_root: Option<&'a PyPath>,
    pub(crate) execution_context: Option<&'a ShellExecutionContext>,
}

/// `_python_interpreter_executable_identities`: resolve exact Python tokens
/// without executing candidate interpreters.
pub(crate) fn python_interpreter_executable_identities(
    command_text: &str,
    inputs: &IdentityInputs,
    depth: usize,
    ctx: &Ctx,
) -> Vec<Value> {
    let initial_cwd = normalized_interpreter_cwd(inputs.cwd, ctx);
    let root = normalized_interpreter_cwd(inputs.workspace_root.or(inputs.cwd), ctx);
    let home_dir = inputs.home_dir;
    let inherited: Environment = match inputs.environment {
        Some(environment) => environment.clone(),
        None => ctx.host.environment().into_iter().collect(),
    };
    if depth > 8 {
        return ambiguous_python_evidence_from_tokens(
            &split_shell_parts(command_text),
            &initial_cwd,
            &inherited,
            &root,
            home_dir,
            "nested_shell_depth_exceeded",
            ctx,
        );
    }
    let modeled;
    let execution_context = match inputs.execution_context {
        Some(context) => context,
        None => {
            modeled = model_shell_execution_context(
                command_text,
                Some(Path::new(&initial_cwd.to_string())),
                Some(Path::new(&root.to_string())),
                None,
            );
            &modeled
        }
    };
    let mut evidence: Vec<Value> = Vec::new();
    for segment in &execution_context.segments {
        if segment.directory_operation.is_some() {
            continue;
        }
        let (segment_cwd, context_reason) =
            validate_shell_execution_segment(execution_context, segment);
        let Some(segment_cwd) = segment_cwd.filter(|_| context_reason.is_none()) else {
            evidence.extend(ambiguous_python_evidence_from_tokens(
                &segment.tokens,
                &initial_cwd,
                &inherited,
                &root,
                home_dir,
                context_reason
                    .as_deref()
                    .unwrap_or("interpreter_cwd_unresolved"),
                ctx,
            ));
            continue;
        };
        let segment_cwd = PyPath::new(&segment_cwd.to_string_lossy());
        let Some(candidate) =
            shell_launch_candidate(&segment.tokens, &segment_cwd, &inherited, 0, None, ctx)
        else {
            evidence.extend(ambiguous_python_evidence_from_tokens(
                &segment.tokens,
                &segment_cwd,
                &inherited,
                &root,
                home_dir,
                "interpreter_wrapper_unresolved",
                ctx,
            ));
            continue;
        };
        let raw = shell_command_token_without_attached_redirection(
            &candidate.tokens[candidate.command_index],
        );
        let raw_token = py_strip(&raw);
        if is_python_interpreter_command(raw_token) {
            evidence.push(python_interpreter_executable_identity(
                raw_token,
                &candidate.effective_cwd,
                &candidate.environment,
                &root,
                home_dir,
                candidate.resolution_reason.as_deref(),
                ctx,
            ));
        }
        let command_name = normalized_shell_command_name(raw_token);
        if SHELL_COMMAND_STRING_INTERPRETERS.contains(&command_name.as_str()) {
            if let Some(payload) =
                shell_interpreter_command_payload(&candidate.tokens, candidate.command_index)
            {
                let nested = IdentityInputs {
                    cwd: Some(&candidate.effective_cwd),
                    home_dir,
                    environment: Some(&candidate.environment),
                    workspace_root: Some(&root),
                    execution_context: None,
                };
                evidence.extend(python_interpreter_executable_identities(
                    &payload.script_text,
                    &nested,
                    depth + 1,
                    ctx,
                ));
            }
        }
    }
    for payload in shell_command_substitution_payloads(command_text) {
        let nested = IdentityInputs {
            cwd: Some(&initial_cwd),
            home_dir,
            environment: Some(&inherited),
            workspace_root: Some(&root),
            execution_context: None,
        };
        evidence.extend(python_interpreter_executable_identities(
            &payload,
            &nested,
            depth + 1,
            ctx,
        ));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    evidence
        .into_iter()
        .filter(|item| seen.insert(without_interpreter_reuse_nonces(item).to_string()))
        .collect()
}
