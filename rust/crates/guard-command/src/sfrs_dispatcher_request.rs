//! `ToolActionRequestMatch` (`request_models.py`) with the full field set the
//! dispatcher produces, plus the request transforms of
//! `secret_file_request_services/tool_action_requests.py`
//! (`_request_with_wrapper_context`, `_request_with_shell_execution_context`)
//! and the shell-context model the resident builds for the Python client.

// Consumed by the dispatcher wiring.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::command_evaluation::{CommandDecisionFloor, CompositeCommandEvaluation};
use crate::command_model::CanonicalCommand;
use crate::sfrs_source_edit_context::shell_execution_context_validation_reason;
use crate::sfrs_tool_request::ToolActionRequest;
use crate::shell_execution_context::{model_shell_execution_context, ShellExecutionContext};

/// The Python `ValueError` a classifier raises; the message is the contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchError(pub(crate) String);

impl DispatchError {
    pub(crate) fn new(message: &str) -> Self {
        Self(message.to_owned())
    }
}

fn serialize_command<S: Serializer>(
    command: &Option<CanonicalCommand>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match command {
        Some(command) => command.to_dict().serialize(serializer),
        None => serializer.serialize_none(),
    }
}

/// `ToolActionRequestMatch`: field for field with the Python dataclass.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ToolActionRequestMatch {
    pub tool_name: String,
    pub normalized_tool_name: String,
    pub command_text: String,
    pub action_class: String,
    pub reason: String,
    pub raw_command_text: Option<String>,
    pub wrapper_chain: Vec<String>,
    #[serde(serialize_with = "serialize_command")]
    pub canonical_command: Option<CanonicalCommand>,
    pub shell_execution_context_hash: Option<String>,
    pub shell_execution_context_reason_code: Option<String>,
    pub shell_execution_effective_cwds: Vec<String>,
    pub guard_default_action: Option<String>,
    pub reason_code: Option<String>,
    pub restricted_profile_version: Option<String>,
    pub pytest_config_identity_sha256: Option<String>,
    pub pytest_config_sources: Vec<String>,
    pub pytest_config_reason_codes: Vec<String>,
    pub interpreter_executable_identities: Vec<Value>,
    pub script_read_identity_sha256: Option<String>,
}

impl ToolActionRequestMatch {
    /// The five required positional fields; every other field keeps its default.
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

impl From<ToolActionRequest> for ToolActionRequestMatch {
    fn from(request: ToolActionRequest) -> Self {
        Self {
            tool_name: request.tool_name,
            normalized_tool_name: request.normalized_tool_name,
            command_text: request.command_text,
            action_class: request.action_class,
            reason: request.reason,
            raw_command_text: request.raw_command_text,
            wrapper_chain: request.wrapper_chain,
            canonical_command: None,
            shell_execution_context_hash: request.shell_execution_context_hash,
            shell_execution_context_reason_code: request.shell_execution_context_reason_code,
            shell_execution_effective_cwds: request.shell_execution_effective_cwds,
            guard_default_action: request.guard_default_action,
            reason_code: request.reason_code,
            restricted_profile_version: request.restricted_profile_version,
            pytest_config_identity_sha256: request.pytest_config_identity_sha256,
            pytest_config_sources: request.pytest_config_sources,
            pytest_config_reason_codes: request.pytest_config_reason_codes,
            interpreter_executable_identities: Vec::new(),
            script_read_identity_sha256: request.script_read_identity_sha256,
        }
    }
}

/// The parts of a native `CompositeCommandEvaluation` the legacy classifier
/// reads. `security_identity` stands for `command.normalized_text` and
/// `command.security_identity`, which the identity digest covers.
#[derive(Clone, Debug)]
pub(crate) struct NativeEvaluationView {
    pub security_identity: String,
    pub minimum_action: CommandDecisionFloor,
    /// `owned.match.rule.default_mode` for each match.
    pub match_default_modes: Vec<String>,
    /// `decision_plane.reasons[].reason_code`.
    pub reason_codes: Vec<String>,
    pub explicitly_enabled_permission_ids: Vec<String>,
    pub controlling_action_class: Option<String>,
    pub controlling_reason: Option<String>,
}

impl NativeEvaluationView {
    pub(crate) fn has_reason(&self, code: &str) -> bool {
        self.reason_codes.iter().any(|reason| reason == code)
    }
}

impl From<&CompositeCommandEvaluation> for NativeEvaluationView {
    fn from(evaluation: &CompositeCommandEvaluation) -> Self {
        Self {
            security_identity: evaluation.security_identity.clone(),
            minimum_action: evaluation.minimum_action,
            match_default_modes: evaluation
                .matches
                .iter()
                .map(|owned| owned.rule.default_mode.clone())
                .collect(),
            reason_codes: evaluation
                .decision_plane
                .reasons
                .iter()
                .map(|reason| reason.reason_code.clone())
                .collect(),
            explicitly_enabled_permission_ids: evaluation
                .control_resolution
                .explicitly_enabled_permission_ids
                .clone(),
            controlling_action_class: evaluation.controlling_action_class.clone(),
            controlling_reason: evaluation.controlling_reason.clone(),
        }
    }
}

/// `_request_with_wrapper_context`.
pub(crate) fn request_with_wrapper_context(
    request: ToolActionRequestMatch,
    raw_command_text: &str,
    wrapper_chain: &[String],
) -> ToolActionRequestMatch {
    ToolActionRequestMatch {
        raw_command_text: Some(raw_command_text.to_owned()),
        wrapper_chain: wrapper_chain.to_vec(),
        ..request
    }
}

/// The context the native request-context op builds for the Python client:
/// the declared cwd, else the caller's process cwd (never the resident's), and
/// a workspace root only when one was declared.
pub(crate) fn model_context(
    ctx: &Ctx,
    command_text: &str,
    cwd: Option<&Path>,
    workspace_root: Option<&Path>,
    home_dir: Option<&Path>,
) -> ShellExecutionContext {
    let process_cwd = PathBuf::from(ctx.process_cwd.to_string());
    let effective = cwd.map_or(process_cwd, Path::to_path_buf);
    let mut context =
        model_shell_execution_context(command_text, Some(&effective), workspace_root, home_dir);
    if cwd.is_none() {
        for segment in &mut context.segments {
            if segment.cwd_source == "workspace" {
                segment.cwd_source = "process".to_owned();
            }
        }
    }
    context
}

/// `_request_with_shell_execution_context`.
pub(crate) fn request_with_shell_execution_context(
    request: ToolActionRequestMatch,
    command_text: &str,
    cwd: Option<&Path>,
    context: Option<&ShellExecutionContext>,
    ctx: &Ctx,
) -> ToolActionRequestMatch {
    let modeled;
    let context = match context {
        Some(context) => context,
        None => {
            modeled = model_context(ctx, command_text, cwd, cwd, None);
            &modeled
        }
    };
    if !context.directory_change_present {
        return request;
    }
    ToolActionRequestMatch {
        shell_execution_context_hash: Some(context.context_hash()),
        shell_execution_context_reason_code: shell_execution_context_validation_reason(context),
        shell_execution_effective_cwds: context
            .effective_cwds()
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        ..request
    }
}

/// `tuple(str(path) for path in context.effective_cwds)`.
pub(crate) fn effective_cwd_texts(context: &ShellExecutionContext) -> Vec<String> {
    context
        .effective_cwds()
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}
