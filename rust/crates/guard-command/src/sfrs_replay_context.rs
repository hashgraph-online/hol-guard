//! Replay encoders for shell execution contexts and GitHub assessments.
//!
//! The vectors carry these values with the Python type tags, so the encoders
//! mirror the recorded field names and the decoder accepts the same shape.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::codex_output_env::Ctx;
use crate::github_capability_contract::GitHubCommandAssessment;
use crate::github_command_capabilities::classify_github_cli;
use crate::sfrs_developer_graph::{starts_with_literal_cd, GraphInputs};
use crate::sfrs_gh_service::classify_github_shell_capabilities;
use crate::sfrs_quote_parsing::literal_cd_execution_context;
use crate::sfrs_source_edit_context::low_risk_developer_execution_context;
use crate::shell_execution_context::{ShellExecutionContext, ShellExecutionSegment};
use crate::shell_execution_context_support::{ShellPathIdentity, ShellPathProof};

/// Entries this module replays.
pub(crate) const ENTRIES: &[&str] = &[
    "classify_github_shell_capabilities",
    "literal_cd_execution_context",
    "low_risk_compound_developer_execution_context",
    "shell_execution_context_starts_with_literal_cd",
];

/// Replay one context or GitHub entry, or `None` when `entry` is not one.
pub(crate) fn replay(
    entry: &str,
    args: &Value,
    ctx: &Ctx,
    home: &Path,
) -> Option<Result<Value, String>> {
    let command_text = args
        .get("command_text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let home_dir = args
        .get("home_dir")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let result = match entry {
        "classify_github_shell_capabilities" => {
            Ok(
                classify_github_shell_capabilities(command_text, home_dir.as_deref(), ctx)
                    .map_or(Value::Null, |found| encode_assessment(&found)),
            )
        }
        "literal_cd_execution_context" => Ok(encode_optional(literal_cd_execution_context(
            command_text,
            home_dir.as_deref().unwrap_or(home),
            ctx,
        ))),
        "low_risk_compound_developer_execution_context" => {
            let cwd = args.get("cwd").and_then(Value::as_str).map(PathBuf::from);
            let inputs = GraphInputs {
                cwd: cwd.as_deref(),
                home_dir: home_dir.as_deref().unwrap_or(home),
                ctx,
                managed_bin_dirs: &[],
                classify_github: classify_github_cli,
            };
            Ok(encode_optional(low_risk_developer_execution_context(
                command_text,
                &inputs,
            )))
        }
        "shell_execution_context_starts_with_literal_cd" => {
            decode_context(&args["context"]).map(|context| json!(starts_with_literal_cd(&context)))
        }
        _ => return None,
    };
    Some(result)
}

fn encode_assessment(assessment: &GitHubCommandAssessment) -> Value {
    json!({
        "$type": "GitHubCommandAssessment",
        "capabilities": assessment
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>(),
        "capability": assessment.capability.as_str(),
        "detail": assessment.detail,
        "reason_code": assessment.reason_code,
    })
}

fn encode_optional(context: Option<ShellExecutionContext>) -> Value {
    context.map_or(Value::Null, |context| encode_context(&context))
}

fn path_text(path: &Path) -> Value {
    Value::String(path.to_string_lossy().into_owned())
}

fn optional_path(path: Option<&PathBuf>) -> Value {
    path.map_or(Value::Null, |path| path_text(path))
}

fn encode_identity(identity: &ShellPathIdentity) -> Value {
    json!({
        "$type": "ShellPathIdentity",
        "change_time_ns": identity.change_time_ns,
        "creation_time_ns": identity.creation_time_ns,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    })
}

fn encode_proof(proof: &ShellPathProof) -> Value {
    json!({
        "$type": "ShellPathProof",
        "identity": encode_identity(&proof.identity),
        "lexical_path": path_text(&proof.lexical_path),
        "resolved_path": path_text(&proof.resolved_path),
    })
}

fn encode_segment(segment: &ShellExecutionSegment) -> Value {
    json!({
        "$type": "ShellExecutionSegment",
        "complete": segment.complete,
        "control_after": segment.control_after,
        "control_before": segment.control_before,
        "cwd_identity": segment.cwd_identity.as_ref().map_or(Value::Null, encode_identity),
        "cwd_path_proofs": segment.cwd_path_proofs.iter().map(encode_proof).collect::<Vec<_>>(),
        "cwd_source": segment.cwd_source,
        "directory_operation": segment.directory_operation,
        "directory_stack": segment
            .directory_stack
            .iter()
            .map(|path| path_text(path))
            .collect::<Vec<_>>(),
        "effective_cwd": optional_path(segment.effective_cwd.as_ref()),
        "reason_code": segment.reason_code,
        "segment_index": segment.segment_index,
        "tokens": segment.tokens,
    })
}

pub(crate) fn encode_context(context: &ShellExecutionContext) -> Value {
    json!({
        "$type": "ShellExecutionContext",
        "command_text": context.command_text,
        "complete": context.complete,
        "directory_change_present": context.directory_change_present,
        "initial_cwd": optional_path(context.initial_cwd.as_ref()),
        "reason_code": context.reason_code,
        "segments": context.segments.iter().map(encode_segment).collect::<Vec<_>>(),
        "workspace_identity": context
            .workspace_identity
            .as_ref()
            .map_or(Value::Null, encode_identity),
        "workspace_root": optional_path(context.workspace_root.as_ref()),
    })
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value
        .get(key)
        .ok_or_else(|| format!("context field {key} is missing"))
}

fn text_field(value: &Value, key: &str) -> Result<String, String> {
    field(value, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("context field {key} is not text"))
}

fn optional_text(value: &Value, key: &str) -> Result<Option<String>, String> {
    match field(value, key)? {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(format!("context field {key} is not text")),
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    field(value, key)?
        .as_bool()
        .ok_or_else(|| format!("context field {key} is not a boolean"))
}

fn texts(value: &Value, key: &str) -> Result<Vec<String>, String> {
    field(value, key)?
        .as_array()
        .ok_or_else(|| format!("context field {key} is not a list"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("context field {key} holds a non-text item"))
        })
        .collect()
}

fn decode_identity(value: &Value) -> Result<Option<ShellPathIdentity>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let number = |key: &str| {
        field(value, key)?
            .as_i64()
            .ok_or_else(|| format!("identity field {key} is not an integer"))
    };
    let unsigned = |key: &str| {
        field(value, key)?
            .as_u64()
            .ok_or_else(|| format!("identity field {key} is not an integer"))
    };
    Ok(Some(ShellPathIdentity {
        device: unsigned("device")?,
        inode: unsigned("inode")?,
        mode: u32::try_from(unsigned("mode")?).map_err(|error| error.to_string())?,
        change_time_ns: number("change_time_ns")?,
        creation_time_ns: number("creation_time_ns")?,
    }))
}

fn decode_proof(value: &Value) -> Result<ShellPathProof, String> {
    Ok(ShellPathProof {
        lexical_path: PathBuf::from(text_field(value, "lexical_path")?),
        resolved_path: PathBuf::from(text_field(value, "resolved_path")?),
        identity: decode_identity(field(value, "identity")?)?.ok_or("proof identity is missing")?,
    })
}

fn decode_segment(value: &Value) -> Result<ShellExecutionSegment, String> {
    let proofs = field(value, "cwd_path_proofs")?
        .as_array()
        .ok_or("cwd_path_proofs is not a list")?;
    Ok(ShellExecutionSegment {
        tokens: texts(value, "tokens")?,
        segment_index: usize::try_from(
            field(value, "segment_index")?
                .as_u64()
                .ok_or("segment_index is not an integer")?,
        )
        .map_err(|error| error.to_string())?,
        control_before: texts(value, "control_before")?,
        control_after: texts(value, "control_after")?,
        effective_cwd: optional_text(value, "effective_cwd")?.map(PathBuf::from),
        cwd_identity: decode_identity(field(value, "cwd_identity")?)?,
        cwd_path_proofs: proofs.iter().map(decode_proof).collect::<Result<_, _>>()?,
        cwd_source: text_field(value, "cwd_source")?,
        directory_stack: texts(value, "directory_stack")?
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        complete: bool_field(value, "complete")?,
        reason_code: optional_text(value, "reason_code")?,
        directory_operation: optional_text(value, "directory_operation")?,
    })
}

pub(crate) fn decode_context(value: &Value) -> Result<ShellExecutionContext, String> {
    let segments = field(value, "segments")?
        .as_array()
        .ok_or("segments is not a list")?;
    Ok(ShellExecutionContext {
        command_text: text_field(value, "command_text")?,
        initial_cwd: optional_text(value, "initial_cwd")?.map(PathBuf::from),
        workspace_root: optional_text(value, "workspace_root")?.map(PathBuf::from),
        workspace_identity: decode_identity(field(value, "workspace_identity")?)?,
        segments: segments
            .iter()
            .map(decode_segment)
            .collect::<Result<_, _>>()?,
        complete: bool_field(value, "complete")?,
        reason_code: optional_text(value, "reason_code")?,
        directory_change_present: bool_field(value, "directory_change_present")?,
    })
}
