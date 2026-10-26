//! The fail-closed review artifact for a shell command Guard cannot model
//! completely (`commands_support_runtime_artifacts.py::_unmodeled_shell_runtime_artifact`).
//!
//! A shell command whose parse is inexact, or whose working directories
//! cannot be proven, is kept in one review unless a recognized developer or
//! GitHub shape accounts for it. The resident answers the parse, the context
//! models and every recognizer in one request; Python only builds the
//! artifact from the reply.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_env::Ctx;
use crate::command_model::parse_shell_command;
use crate::direct_vitest::{
    direct_local_typescript_execution_context, direct_local_vitest_execution_context,
};
use crate::github_capability_interaction::github_capability_requires_confirmation;
use crate::github_command_capabilities::classify_github_cli;
use crate::sfrs_developer_graph::{starts_with_literal_cd, GraphInputs};
use crate::sfrs_gh_actions_read::is_nonexecuting_github_actions_read_workflow;
use crate::sfrs_gh_ephemeral_body::gh_pr_create_uses_safe_ephemeral_body;
use crate::sfrs_gh_service::classify_github_shell_capabilities;
use crate::sfrs_quote_parsing::literal_cd_execution_context;
use crate::sfrs_source_edit_context::low_risk_developer_execution_context;
use crate::shell_execution_context::{
    model_shell_execution_context_bounded, shell_execution_context_metadata, ShellExecutionContext,
    ShellModelLimits,
};

#[cfg(all(test, unix))]
#[path = "unmodeled_shell_artifact_tests.rs"]
mod tests;

const INVALID: &str = "native_sensitive_request_input_invalid";
const SHELL_CWD_NATIVE_UNAVAILABLE: &str = "shell_cwd_native_unavailable";

/// `model_shell_execution_context` as the request-context op answers it: an
/// undeclared cwd is the caller's process cwd, and a model past the request
/// bounds is the unavailable context.
pub(crate) fn request_shell_context(
    command_text: &str,
    cwd: Option<&Path>,
    workspace_root: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> ShellExecutionContext {
    let process_cwd = PathBuf::from(ctx.process_cwd.to_string());
    let limits = ShellModelLimits {
        max_segments: guard_contracts::MAX_REQUEST_CONTEXT_SEGMENTS,
        max_segment_proofs: guard_contracts::MAX_REQUEST_CONTEXT_SEGMENT_PROOFS,
        max_total_proofs: guard_contracts::MAX_REQUEST_CONTEXT_TOTAL_PROOFS,
        deadline: None,
    };
    let modeled = model_shell_execution_context_bounded(
        command_text,
        Some(cwd.unwrap_or(&process_cwd)),
        workspace_root,
        home_dir,
        &limits,
    );
    let Ok(mut context) = modeled else {
        return ShellExecutionContext {
            command_text: command_text.to_owned(),
            initial_cwd: None,
            workspace_root: None,
            workspace_identity: None,
            segments: Vec::new(),
            complete: false,
            reason_code: Some(SHELL_CWD_NATIVE_UNAVAILABLE.to_owned()),
            directory_change_present: true,
        };
    };
    if cwd.is_none() {
        for segment in &mut context.segments {
            if segment.cwd_source == "workspace" {
                segment.cwd_source = "process".to_owned();
            }
        }
    }
    context
}

/// The literal fragments a direct tool command needs before the resident
/// models it: shell quoting and escapes removed, case folded.
fn has_direct_tool_fragments(command_text: &str, tool: &str) -> bool {
    let folded: String = command_text
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '\n' | '\r'))
        .collect::<String>()
        .to_lowercase()
        .replace('\u{17f}', "s")
        .replace('ß', "ss");
    folded.contains("cd") && folded.contains(tool)
}

fn benign_github_shell(command_text: &str, ctx: &Ctx) -> bool {
    command_text.contains("gh")
        && (is_nonexecuting_github_actions_read_workflow(command_text, None, ctx)
            || gh_pr_create_uses_safe_ephemeral_body(command_text, ctx))
}

/// Whether a recognized developer or GitHub shape accounts for an exact
/// command whose workspace context is incomplete.
fn home_context_accounts_for(
    command_text: &str,
    workspace: Option<&Path>,
    home: &Path,
    ctx: &Ctx,
) -> bool {
    let direct_cwd = workspace.unwrap_or(home);
    let direct = ctx.host.direct_tool_authority().is_some_and(|authority| {
        (has_direct_tool_fragments(command_text, "vitest")
            && direct_local_vitest_execution_context(
                command_text,
                Some(direct_cwd),
                home,
                authority,
            )
            .is_some())
            || (has_direct_tool_fragments(command_text, "tsc")
                && direct_local_typescript_execution_context(
                    command_text,
                    Some(direct_cwd),
                    home,
                    authority,
                )
                .is_some())
    });
    if direct || literal_cd_execution_context(command_text, home, ctx).is_some() {
        return true;
    }
    let graph = GraphInputs {
        cwd: None,
        home_dir: home,
        ctx,
        managed_bin_dirs: &[],
        classify_github: classify_github_cli,
    };
    if low_risk_developer_execution_context(command_text, &graph).is_some() {
        return true;
    }
    let home_context = request_shell_context(command_text, Some(home), Some(home), Some(home), ctx);
    classify_github_shell_capabilities(command_text, Some(home), ctx).is_some_and(|assessment| {
        !github_capability_requires_confirmation(&assessment)
            && starts_with_literal_cd(&home_context)
    })
}

/// The unmodeled-shell artifact for `command_text`, or `null` when the
/// command is modeled completely or a recognized shape accounts for it.
pub fn unmodeled_shell_artifact(input: &Value, ctx: &Ctx) -> Result<Value, &'static str> {
    let command_text = input
        .get("command_text")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let path = |key: &str| match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.contains('\0') => Ok(Some(PathBuf::from(text))),
        Some(_) => Err(INVALID),
    };
    let workspace = path("workspace")?;
    let home = path("home")?.ok_or(INVALID)?;
    let (workspace, home) = (workspace.as_deref(), home.as_path());
    let command = parse_shell_command(
        command_text,
        workspace,
        Some(home),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    let context = request_shell_context(command_text, workspace, workspace, None, ctx);
    let exact = command.confidence == "exact";
    if exact && context.complete {
        return Ok(Value::Null);
    }
    if benign_github_shell(command_text, ctx) {
        return Ok(Value::Null);
    }
    if exact && home_context_accounts_for(command_text, workspace, home, ctx) {
        return Ok(Value::Null);
    }

    let Value::Object(context_metadata) = shell_execution_context_metadata(&context) else {
        return Err(INVALID);
    };
    let reason_code = command
        .uncertainty_reason
        .clone()
        .or_else(|| {
            context_metadata
                .get("shell_execution_context_reason_code")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .map(str::to_owned)
        })
        .or_else(|| {
            context_metadata
                .get("shell_execution_context_reason_codes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|reason| !reason.is_empty())
                .map(str::to_owned)
        })
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "compound_command_incomplete".to_owned());
    let security_identity = command.security_identity();
    let identity = json!({
        "version": 1,
        "command_security_identity": security_identity,
        "shell_execution_context_hash": context.context_hash(),
        "reason_code": reason_code,
    });
    let mut canonical = Vec::new();
    guard_contracts::write_canonical_json(&identity, &mut canonical).map_err(|_| INVALID)?;
    let fingerprint = format!("{:x}", Sha256::digest(&canonical));

    let mut metadata: Vec<(String, Value)> = vec![
        ("action_class".into(), json!("unmodeled shell command")),
        ("guard_default_action".into(), json!("require-reapproval")),
        ("risk_classes".into(), json!(["execution"])),
        (
            "request_summary".into(),
            json!("Requested a shell command that Guard could not model completely."),
        ),
        (
            "runtime_request_signals".into(),
            json!([format!(
                "cannot completely model the shell command: {reason_code}"
            )]),
        ),
        (
            "runtime_request_summary".into(),
            json!("Guard requires one review because part of this shell command is unresolved."),
        ),
        (
            "runtime_request_reason".into(),
            json!(
                "Guard could not prove the complete compound command structure, so it kept the \
                 whole command in one fail-closed review."
            ),
        ),
        ("command_security_identity".into(), json!(security_identity)),
        ("command_parse_confidence".into(), json!(command.confidence)),
        ("command_uncertainty_reason".into(), json!(reason_code)),
    ];
    for (key, value) in context_metadata {
        match metadata.iter_mut().find(|(seen, _)| *seen == key) {
            Some(slot) => slot.1 = value,
            None => metadata.push((key, value)),
        }
    }
    Ok(json!({
        "fingerprint": fingerprint,
        "metadata": metadata
            .into_iter()
            .map(|(key, value)| json!([key, value]))
            .collect::<Vec<_>>(),
    }))
}
