//! Native consumer approval-context composition.
//!
//! A saved consumer approval binds to the context it was given in: the
//! artifact's identity and launch, its content, its capabilities, the policy
//! that evaluated it and the sandbox requirement. This module builds those
//! components for a detected artifact, or for a removed one from its stored
//! snapshot, and returns the opaque token. Ported from `consumer/service.py`
//! (`_consumer_approval_context_token`, `_removed_consumer_approval_context_token`,
//! `_consumer_execution_identity`, `_consumer_context_metadata`,
//! `_codex_hook_identity` and `_runtime_detector_state`).
//!
//! Python keeps what it owns: the normalized cwd and workspace paths, the
//! policy component read from its config, the detector telemetry fields, and
//! the extension-control digest bound to the evaluation.

use guard_contracts::ContextDigestComponentsV1;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::context_digest::{build_context_token, python_strip};
use crate::hook_approval_context::LaunchRequest;
use crate::resident_diagnostics::{observe_value, Phase};

const ERR_INPUT: &str = "native_context_component_invalid";
const POLICY_VERSION: &str = "consumer-evaluation-v1";
/// Prompt fields that change with every rendering of the same prompt file.
const PROMPT_VOLATILE_METADATA_KEYS: [&str; 6] = [
    "prompt_display_text",
    "prompt_matched_text",
    "prompt_signals",
    "request_summary",
    "runtime_request_reason",
    "runtime_request_summary",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerTokenRequest {
    subject: Subject,
    /// The effective cwd as the launch sees it, before normalization.
    launch_cwd: String,
    /// The normalized effective cwd and configured workspace.
    cwd: String,
    workspace: Option<String>,
    launch_env: Map<String, Value>,
    /// Each runtime detector's `detector_id`, `error_type` and `status`, or
    /// `null` when the detectors did not run.
    detector_telemetry: Option<Vec<Value>>,
    policy: Value,
    sandbox_analysis: Value,
    extension_control_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Subject {
    /// A detected artifact and the detection that found it.
    Artifact {
        artifact: Map<String, Value>,
        detection_harness: Value,
        command_available: Value,
        installed: Value,
        content_hash: Value,
        capability_snapshot: Value,
    },
    /// An artifact that disappeared, from its stored snapshot. `args` are the
    /// snapshot's arguments as Python text.
    Removed {
        harness: Value,
        artifact_id: Value,
        previous: Map<String, Value>,
        previous_hash: Value,
        args: Vec<Value>,
    },
}

pub(crate) fn consumer_token(request: &Value) -> Result<String, &'static str> {
    let request: ConsumerTokenRequest =
        serde_json::from_value(request.clone()).map_err(|_| ERR_INPUT)?;
    build_context_token(&components(&request, &native_launch)?)
}

pub(crate) fn components(
    request: &ConsumerTokenRequest,
    launch: &dyn Fn(&LaunchRequest<'_>) -> Value,
) -> Result<ContextDigestComponentsV1, &'static str> {
    let launch_env = Value::Object(request.launch_env.clone());
    let executable = |command: &Value, args: &[Value], structured_command: bool| {
        execution_identity(
            launch(&LaunchRequest {
                command,
                args,
                structured_command,
                search_path: None,
                cwd: &request.launch_cwd,
                home_dir: None,
                launch_env: &launch_env,
            }),
            command,
        )
    };
    let runtime_detectors = runtime_detector_state(request.detector_telemetry.as_deref());
    let (identity, content, capabilities) = match &request.subject {
        Subject::Artifact {
            artifact,
            detection_harness,
            command_available,
            installed,
            content_hash,
            capability_snapshot,
        } => {
            let field = |key: &str| artifact.get(key).cloned().unwrap_or(Value::Null);
            let metadata = artifact
                .get("metadata")
                .and_then(Value::as_object)
                .ok_or(ERR_INPUT)?;
            let hook_identity = codex_hook_identity(artifact, metadata);
            let mut identity = json!({
                "artifact_id": field("artifact_id"),
                "artifact_name": field("name"),
                "artifact_type": field("artifact_type"),
                "cwd": request.cwd,
                "detection_harness": detection_harness,
                "harness": field("harness"),
                "publisher": field("publisher"),
                "source_scope": field("source_scope"),
                "workspace": request.workspace,
            });
            let content = if let Some(hook_identity) = hook_identity {
                let scope = artifact
                    .get("source_scope")
                    .and_then(Value::as_str)
                    .ok_or(ERR_INPUT)?;
                identity["codex_hook_identity"] = json!(hook_identity);
                identity["config_path"] = json!(format!("codex-hook://{scope}"));
                identity["executable"] = json!({"codex_hook_identity": hook_identity});
                json!({
                    "artifact_hash": content_hash,
                    "codex_hook_identity": hook_identity,
                    "metadata": {
                        "codex_hook_identity_schema": metadata
                            .get("codex_hook_identity_schema")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "codex_hook_identity": hook_identity,
                    },
                })
            } else {
                let command = field("command");
                let args = artifact
                    .get("args")
                    .and_then(Value::as_array)
                    .ok_or(ERR_INPUT)?;
                let structured = artifact.get("artifact_type") == Some(&json!("mcp_server"));
                identity["config_path"] = field("config_path");
                identity["executable"] = executable(&command, args, structured)?;
                json!({
                    "args": args,
                    "artifact_hash": content_hash,
                    "command": command,
                    "metadata": context_metadata(artifact, metadata),
                    "url": field("url"),
                })
            };
            let capabilities = json!({
                "artifact_capabilities": capability_snapshot,
                "command_available": command_available,
                "installed": installed,
                "runtime_detectors": runtime_detectors,
                "scanner_policy_version": POLICY_VERSION,
                "transport": field("transport"),
            });
            (identity, content, capabilities)
        }
        Subject::Removed {
            harness,
            artifact_id,
            previous,
            previous_hash,
            args,
        } => {
            let field = |key: &str| previous.get(key).cloned().unwrap_or(Value::Null);
            let text = |key: &str| match previous.get(key) {
                Some(Value::String(text)) => Value::String(text.clone()),
                _ => Value::Null,
            };
            let structured = previous.get("artifact_type") == Some(&json!("mcp_server"));
            let snapshot = Value::Object(previous.clone());
            let identity = json!({
                "artifact_id": artifact_id,
                "artifact_name": field("name"),
                "artifact_type": field("artifact_type"),
                "config_path": field("config_path"),
                "cwd": request.cwd,
                "executable": executable(&text("command"), args, structured)?,
                "harness": harness,
                "publisher": text("publisher"),
                "source_scope": field("source_scope"),
                "workspace": request.workspace,
            });
            let content =
                json!({"artifact_hash": previous_hash, "removed": true, "snapshot": snapshot});
            let capabilities = json!({
                "removed": true,
                "runtime_detectors": runtime_detectors,
                "snapshot": snapshot,
            });
            (identity, content, capabilities)
        }
    };
    let sandbox_required =
        request.policy.get("current_action").and_then(Value::as_str) == Some("sandbox-required");
    Ok(ContextDigestComponentsV1 {
        identity,
        content,
        capabilities,
        policy: request.policy.clone(),
        sandbox: json!({"analysis": request.sandbox_analysis, "required": sandbox_required}),
        extension_control_digest: request.extension_control_digest.clone(),
    })
}

/// `_codex_hook_identity`: a Codex hook's format-independent identity.
fn codex_hook_identity<'a>(
    artifact: &Map<String, Value>,
    metadata: &'a Map<String, Value>,
) -> Option<&'a str> {
    if artifact.get("harness") != Some(&json!("codex"))
        || artifact.get("artifact_type") != Some(&json!("hook"))
    {
        return None;
    }
    metadata
        .get("codex_hook_identity")
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty())
}

/// `_consumer_context_metadata` for an artifact that is not a Codex hook: a
/// prompt request drops the fields that change with each rendering.
fn context_metadata(artifact: &Map<String, Value>, metadata: &Map<String, Value>) -> Value {
    if artifact.get("artifact_type") != Some(&json!("prompt_request")) {
        return Value::Object(metadata.clone());
    }
    Value::Object(
        metadata
            .iter()
            .filter(|(key, _)| !PROMPT_VOLATILE_METADATA_KEYS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// `_consumer_execution_identity`: the launch identity's binding fields.
fn execution_identity(launch_identity: Value, command: &Value) -> Result<Value, &'static str> {
    let field = |key: &str| launch_identity.get(key).cloned().ok_or(ERR_INPUT);
    let requested = match command {
        Value::String(text) => Value::String(python_strip(text).to_owned()),
        other => other.clone(),
    };
    Ok(json!({
        "requested": requested,
        "argv_sha256": field("argv_sha256")?,
        "entrypoint": field("entrypoint")?,
        "launch_cwd": field("launch_cwd")?,
        "resolved": field("executable")?,
    }))
}

/// `_runtime_detector_state`: whether the detectors ran, and which did not
/// finish. What they found is not part of an approval; whether they ran is.
fn runtime_detector_state(telemetry: Option<&[Value]>) -> Value {
    let Some(telemetry) = telemetry else {
        return json!({"failures": [], "ran": false});
    };
    let failures: Vec<Value> = telemetry
        .iter()
        .filter_map(Value::as_object)
        .filter(|item| item.get("status") != Some(&json!("ok")))
        .map(|item| {
            let field = |key: &str| item.get(key).cloned().unwrap_or(Value::Null);
            json!({
                "detector_id": field("detector_id"),
                "error_type": field("error_type"),
                "status": field("status"),
            })
        })
        .collect();
    json!({"failures": failures, "ran": true})
}

fn native_launch(request: &LaunchRequest<'_>) -> Value {
    observe_value(Phase::ContextRuntimeLaunchIdentity, || {
        guard_command::launch_identity::build_runtime_launch_identity(
            request.command,
            request.args,
            request.structured_command,
            false,
            request.search_path,
            Some(Path::new(request.cwd)),
            request.home_dir.map(Path::new),
            Some(request.launch_env),
        )
    })
}

#[cfg(test)]
#[path = "consumer_approval_context_tests.rs"]
mod tests;
