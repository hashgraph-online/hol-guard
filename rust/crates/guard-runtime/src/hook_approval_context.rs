//! Native hook approval-context composition.
//!
//! A saved hook approval is reusable only while the exact reviewed context
//! holds. This module builds that context for runtime hooks and for the
//! generic fallback hook: path normalization, the shell execution-context
//! branches, configured-environment proof, launch identity, reuse nonces and
//! the five components hashed into the opaque token. Python transports the
//! evaluation's raw facts and receives only the token.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::ContextDigestComponentsV1;
use serde_json::{json, Map, Value};

use crate::context_digest::{
    build_context_token, configured_values_hash, python_strip, CONFIGURED_ENV_HASH_DOMAIN,
};

mod support;

use support::{
    capabilities, envelope, extension_control_digest, field, field_of, optional_normalized,
    optional_string, policy, py_or, sandbox_required, string_map, text, truthy,
    with_native_effects, Paths,
};

const ERR_INPUT: &str = "native_hook_approval_context_invalid";
const ERR_PATH: &str = "native_hook_approval_context_path_unresolved";
const ERR_RANDOM: &str = "native_hook_approval_context_random_failed";
const UNBOUND_PREFIX: &str = "guard-context-unbound:";
const WORKFLOW_BOUND: &str = "github_workflow_capability_bound";
const CODE_LOADING_KEYS: [&str; 6] = [
    "BASH_ENV",
    "ENV",
    "NODE_OPTIONS",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "ZDOTDIR",
];
const POSIX_SHELL_TOOLS: [&str; 5] = ["ash", "bash", "dash", "sh", "zsh"];
const RUNTIME_ENVELOPE_CAPABILITIES: [&str; 11] = [
    "action_type",
    "mcp_server",
    "mcp_tool",
    "network_hosts",
    "package_intent_kind",
    "package_manager",
    "package_name",
    "package_targets",
    "script_name",
    "target_paths",
    "tool_name",
];
const GENERIC_ENVELOPE_CAPABILITIES: [&str; 10] = [
    "action_type",
    "event_name",
    "mcp_server",
    "mcp_tool",
    "network_hosts",
    "package_intent_kind",
    "package_manager",
    "package_targets",
    "target_paths",
    "tool_name",
];
const EVENT_NAME_KEYS: [&str; 4] = ["event", "hook_event_name", "hookEventName", "hook_name"];

/// One `build_runtime_launch_identity` call.
pub(crate) struct LaunchRequest<'a> {
    pub command: &'a Value,
    pub args: &'a [Value],
    pub structured_command: bool,
    pub search_path: Option<&'a str>,
    pub cwd: &'a str,
    pub home_dir: Option<&'a str>,
    pub launch_env: &'a Value,
}

/// Filesystem and entropy effects, injectable so parity vectors replay.
pub(crate) struct Effects<'a> {
    pub launch: &'a dyn Fn(&LaunchRequest<'_>) -> Value,
    pub nonce: &'a mut dyn FnMut() -> Result<String, &'static str>,
}

pub(crate) fn runtime_hook_token(inputs: &Value) -> Result<String, &'static str> {
    with_native_effects(|effects| build_context_token(&runtime_hook_components(inputs, effects)?))
}

pub(crate) fn generic_hook_token(inputs: &Value) -> Result<String, &'static str> {
    with_native_effects(|effects| build_context_token(&generic_hook_components(inputs, effects)?))
}

/// `_runtime_hook_approval_context_token`.
pub(crate) fn runtime_hook_components(
    inputs: &Value,
    effects: &mut Effects<'_>,
) -> Result<ContextDigestComponentsV1, &'static str> {
    let input = inputs.as_object().ok_or(ERR_INPUT)?;
    let paths = Paths::from_host(field(input, "host"))?;
    let artifact = field(input, "artifact").as_object().ok_or(ERR_INPUT)?;
    let empty = Map::new();
    let metadata = field(input, "metadata").as_object().unwrap_or(&empty);
    let shell_present = truthy(metadata.get("shell_execution_context_hash"))
        || truthy(metadata.get("shell_execution_context_hashes"));
    let shell_complete =
        metadata.get("shell_execution_context_complete") == Some(&Value::Bool(true));
    let effective_cwds = match metadata.get("shell_execution_effective_cwds") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .filter(|text| !python_strip(text).is_empty())
            .map(|text| paths.normalized(text))
            .collect::<Result<Vec<_>, _>>()?,
        _ => Vec::new(),
    };
    let runtime_workspace = text(input, "runtime_workspace")?;
    let launch_cwd = match (effective_cwds.last(), runtime_workspace) {
        (Some(cwd), _) => cwd.clone(),
        (None, Some(workspace)) => workspace.to_owned(),
        (None, None) => paths.cwd()?.to_owned(),
    };
    let effective_cwd = match effective_cwds.last() {
        Some(cwd) => Value::String(cwd.clone()),
        None if shell_present => Value::Null,
        None => {
            let workspace = match runtime_workspace {
                Some(workspace) => workspace,
                None => paths.cwd()?,
            };
            Value::String(paths.normalized(workspace)?)
        }
    };
    let configured_workspace = optional_normalized(&paths, text(input, "configured_workspace")?)?;
    let envelope = envelope(input)?;
    let envelope_workspace = match envelope.map(|envelope| field(envelope, "workspace")) {
        None | Some(Value::Null) => None,
        Some(Value::String(workspace)) => Some(paths.normalized(workspace)?),
        Some(_) => return Err(ERR_INPUT),
    };
    let record = field(input, "workflow_record");
    let (executable, shell_executables) = if shell_present && !shell_complete {
        let identity = json!({
            "status": "unresolved_shell_execution_context",
            "reason_code": py_or(
                metadata.get("shell_execution_context_reason_code"),
                metadata.get("shell_execution_context_reason_codes"),
            ),
            "reuse_nonce": (effects.nonce)()?,
        });
        let shell = json!([{"cwd": null, "identity": identity}]);
        (identity, shell)
    } else if !record.is_null() {
        let identity = json!({
            "launch_cwd": paths.normalized(&launch_cwd)?,
            "record": record,
            "status": WORKFLOW_BOUND,
        });
        let shell = shell_present.then(|| {
            effective_cwds
                .iter()
                .map(|cwd| {
                    json!({
                        "cwd": cwd,
                        "identity": {"launch_cwd": cwd, "record": record, "status": WORKFLOW_BOUND},
                    })
                })
                .collect::<Vec<_>>()
        });
        (identity, json!(shell))
    } else {
        let identity = executable_identity(input, artifact, metadata, &launch_cwd, effects)?;
        let shell = if shell_present {
            let mut identities = Vec::with_capacity(effective_cwds.len());
            for cwd in &effective_cwds {
                let identity = executable_identity(input, artifact, metadata, cwd, effects)?;
                identities.push(json!({"cwd": cwd, "identity": identity}));
            }
            Value::Array(identities)
        } else {
            Value::Null
        };
        (identity, shell)
    };
    let guard_home = paths.normalized(text(input, "guard_home")?.ok_or(ERR_INPUT)?)?;
    let content_keys = [
        "command_security_identity",
        "interpreter_executable_identities",
        "shell_execution_context_hash",
        "shell_execution_context_hashes",
        "shell_execution_context_reason_code",
        "shell_execution_context_reason_codes",
    ];
    let mut content: Map<String, Value> = content_keys
        .iter()
        .map(|key| ((*key).to_owned(), field(metadata, key).clone()))
        .collect();
    content.insert(
        "artifact_content_hash".to_owned(),
        field(input, "content_hash").clone(),
    );
    Ok(ContextDigestComponentsV1 {
        identity: json!({
            "artifact_id": field(artifact, "artifact_id"),
            "artifact_name": field(artifact, "name"),
            "artifact_type": field(artifact, "artifact_type"),
            "config_path": field(artifact, "config_path"),
            "configured_workspace": configured_workspace,
            "cwd": effective_cwd,
            "shell_effective_cwds": effective_cwds,
            "shell_executables": shell_executables,
            "envelope_workspace": envelope_workspace,
            "envelope_workspace_hash": envelope.map_or(&Value::Null, |envelope| field(envelope, "workspace_hash")),
            "executable": executable,
            "guard_home": guard_home,
            "harness": field(artifact, "harness"),
            "publisher": field(artifact, "publisher"),
            "source_scope": field(artifact, "source_scope"),
        }),
        content: Value::Object(content),
        capabilities: json!({
            "action_envelope": envelope.map(|envelope| capabilities(envelope, &RUNTIME_ENVELOPE_CAPABILITIES)),
            "artifact_type": field(artifact, "artifact_type"),
            "data_flow_signals": field(input, "data_flow_signals"),
            "risk_classes": field(input, "risk_classes"),
            "scanner_evidence": field(input, "scanner_evidence"),
            "transport": field(artifact, "transport"),
        }),
        policy: policy(input),
        sandbox: json!({
            "analysis": field(input, "sandbox_analysis"),
            "permission_mode": envelope.and_then(|envelope| {
                optional_string(field(envelope, "permission_mode"))
                    .or_else(|| optional_string(field(envelope, "permissionMode")))
            }),
            "required": sandbox_required(input),
        }),
        extension_control_digest: extension_control_digest(input)?,
    })
}

/// `_runtime_hook_executable_identity`.
fn executable_identity(
    input: &Map<String, Value>,
    artifact: &Map<String, Value>,
    metadata: &Map<String, Value>,
    launch_cwd: &str,
    effects: &mut Effects<'_>,
) -> Result<Value, &'static str> {
    let pairs: Vec<(&str, &str)> = match metadata.get("env") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|pair| {
                let pair = pair.as_array()?;
                Some((pair.first()?.as_str()?, pair.get(1)?.as_str()?))
            })
            .collect(),
        _ => Vec::new(),
    };
    let configured: BTreeMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let mut key_set: BTreeSet<String> = configured.keys().cloned().collect();
    if let Some(Value::Array(items)) = metadata.get("env_keys") {
        key_set.extend(
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|key| !key.is_empty())
                .map(str::to_owned),
        );
    }
    let keys: Vec<String> = key_set.into_iter().collect();
    let provided = optional_string(&py_or(
        metadata.get("env_values_hash"),
        metadata.get("envValuesHash"),
    ));
    let computed = if !configured.is_empty() || keys.is_empty() {
        let values = Value::Array(
            pairs
                .iter()
                .map(|(key, value)| json!([key, value]))
                .collect(),
        );
        Some(configured_values_hash(
            Some(&values),
            Some(&keys),
            CONFIGURED_ENV_HASH_DOMAIN,
        )?)
    } else {
        None
    };
    let ambient = string_map(field(input, "ambient_env"))?;
    let launch_env =
        guard_command::mcp_launch_environment::build_launch_environment(&ambient, &configured);
    let launch_env_value = Value::Object(
        launch_env
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    );
    let args = field(artifact, "args").as_array().ok_or(ERR_INPUT)?;
    let command = field(artifact, "command");
    let launch = (effects.launch)(&LaunchRequest {
        command,
        args,
        structured_command: field(artifact, "artifact_type").as_str()
            != Some("tool_action_request"),
        search_path: launch_env.get("PATH").map(String::as_str),
        cwd: launch_cwd,
        home_dir: None,
        launch_env: &launch_env_value,
    });
    let missing: Vec<&String> = keys
        .iter()
        .filter(|key| !configured.contains_key(*key))
        .collect();
    let unproven = (!missing.is_empty() && provided.is_none())
        || missing
            .iter()
            .any(|key| CODE_LOADING_KEYS.contains(&key.as_str()));
    let matches = match (&provided, &computed) {
        (Some(provided), Some(computed))
            if !provided.starts_with(UNBOUND_PREFIX) && !computed.starts_with(UNBOUND_PREFIX) =>
        {
            Value::Bool(provided == computed)
        }
        _ => Value::Null,
    };
    let mut environment = json!({
        "computed_values_hash": computed,
        "keys": keys,
        "provided_values_hash": provided,
        "values_hash": if missing.is_empty() { &computed } else { &provided },
        "provided_values_hash_matches": matches,
        "status": if unproven { "unproven" } else { "verified" },
    });
    if unproven {
        environment["reuse_nonce"] = Value::String((effects.nonce)()?);
    }
    Ok(json!({
        "artifact_command": command,
        "artifact_tool": field(metadata, "tool_name"),
        "configured_environment": environment,
        "launch_argv_sha256": field_of(&launch, "argv_sha256"),
        "launch_cwd": field_of(&launch, "launch_cwd"),
        "resolved_artifact_command": field_of(&launch, "executable"),
        "resolved_entrypoint": field_of(&launch, "entrypoint"),
        "transport": field(artifact, "transport"),
    }))
}

/// `_generic_hook_approval_context_token`.
pub(crate) fn generic_hook_components(
    inputs: &Value,
    effects: &mut Effects<'_>,
) -> Result<ContextDigestComponentsV1, &'static str> {
    let input = inputs.as_object().ok_or(ERR_INPUT)?;
    let paths = Paths::from_host(field(input, "host"))?;
    let payload = field(input, "payload").as_object().ok_or(ERR_INPUT)?;
    let envelope = envelope(input)?;
    let workspace = match text(input, "runtime_workspace")? {
        Some(workspace) => workspace,
        None => paths.cwd()?,
    };
    let runtime_launch = generic_launch(input, payload, envelope, workspace, effects)?;
    let event_name = EVENT_NAME_KEYS
        .iter()
        .find_map(|key| optional_string(field(payload, key)))
        .map(|name| match name.to_lowercase().as_str() {
            "userpromptsubmitted" => "UserPromptSubmit".to_owned(),
            "pretooluse" => "PreToolUse".to_owned(),
            "posttooluse" => "PostToolUse".to_owned(),
            "permissionrequest" | "permissionrequestv2" => "PermissionRequest".to_owned(),
            _ => name,
        });
    let changed_capabilities: Vec<&Value> = match field(payload, "changed_capabilities") {
        Value::Array(items) => items
            .iter()
            .filter(|item| {
                item.as_str()
                    .is_some_and(|text| !python_strip(text).is_empty())
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(ContextDigestComponentsV1 {
        identity: json!({
            "artifact_id": field(input, "artifact_id"),
            "artifact_name": field(input, "artifact_name"),
            "canonical_harness": field(input, "canonical_harness"),
            "harness": field(input, "harness"),
            "publisher": field(input, "publisher"),
            "runtime_launch": runtime_launch,
            "source_scope": optional_string(field(payload, "source_scope")).unwrap_or_else(|| "project".to_owned()),
            "workspace": paths.normalized(workspace)?,
        }),
        content: json!({
            "payload_digest": field(input, "payload_digest"),
            "provided_artifact_hash": optional_string(field(payload, "artifact_hash")),
        }),
        capabilities: json!({
            "action_envelope": envelope.map(|envelope| capabilities(envelope, &GENERIC_ENVELOPE_CAPABILITIES)),
            "changed_capabilities": changed_capabilities,
            "event_name": event_name.unwrap_or_else(|| "PreToolUse".to_owned()),
            "tool_name": optional_string(field(payload, "tool_name")),
        }),
        policy: policy(input),
        sandbox: json!({
            "analysis": field(input, "sandbox_analysis"),
            "required": sandbox_required(input),
        }),
        extension_control_digest: extension_control_digest(input)?,
    })
}

/// `_generic_hook_runtime_launch_identity`: the envelope command wins, then
/// the payload command, then the tool input; an explicit POSIX shell tool
/// binds the shell itself with `-c`.
fn generic_launch(
    input: &Map<String, Value>,
    payload: &Map<String, Value>,
    envelope: Option<&Map<String, Value>>,
    launch_cwd: &str,
    effects: &mut Effects<'_>,
) -> Result<Value, &'static str> {
    let tool_command = optional_string(field(input, "tool_command"));
    let mut source: Option<&str> = None;
    let mut command: Option<String> = None;
    if let Some(text) = envelope.and_then(|envelope| optional_string(field(envelope, "command"))) {
        (source, command) = (Some("action_envelope"), Some(text));
    } else if let Some(text) = optional_string(field(payload, "command")) {
        (source, command) = (Some("payload"), Some(text));
    } else if let Some(text) = tool_command.clone() {
        (source, command) = (Some("payload_tool_input"), Some(text));
    }
    let tool_name = field(payload, "tool_name")
        .as_str()
        .map(|name| python_strip(name).to_lowercase());
    let home_dir = text(input, "home_dir")?;
    let launch_env = field(input, "ambient_env");
    let shell = tool_name
        .as_deref()
        .filter(|name| POSIX_SHELL_TOOLS.contains(name));
    let resolved = match (shell, tool_command) {
        (Some(shell), Some(text)) => {
            source = Some("payload_tool_input_shell");
            let args = [json!("-c"), json!(text)];
            command = Some(text);
            (effects.launch)(&LaunchRequest {
                command: &json!(shell),
                args: &args,
                structured_command: true,
                search_path: None,
                cwd: launch_cwd,
                home_dir,
                launch_env,
            })
        }
        _ => (effects.launch)(&LaunchRequest {
            command: &json!(command),
            args: &[],
            structured_command: false,
            search_path: None,
            cwd: launch_cwd,
            home_dir,
            launch_env,
        }),
    };
    Ok(json!({"command": command, "command_source": source, "resolved_launch": resolved}))
}

#[cfg(test)]
#[path = "hook_approval_context_tests.rs"]
mod tests;
