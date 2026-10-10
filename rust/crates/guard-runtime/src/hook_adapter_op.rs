//! `HookAdapter` — resident per-harness hook payload adapter.
//!
//! Python forwards the raw harness hook payload and the host facts Rust may not
//! read (home, cwd, `PATH`); this op owns payload preparation, the typed action
//! envelope (transparent-shell normalization, redaction, target paths, network
//! hosts, package intent, action identity), and the command text views. Package
//! intent runs in-process on the resident's own parser, so the envelope costs
//! one round trip. Every failure is typed and fail closed.

use std::collections::BTreeMap;
use std::path::Path;

use guard_command::hook_adapter_envelope::{
    apply_patch_paths, command_detail_text, command_text, normalize_harness_envelope,
    workspace_label, EnvelopeRequest, IntentSummary,
};
use guard_command::hook_adapter_paths::PathEnv;
use guard_command::hook_adapter_prepare::{prepare_payload, AdapterError};
use guard_command::hook_adapter_value::{OMap, OValue};
use guard_command::package_intent_parser::parse_package_intent;
use guard_contracts::{
    ActionEnvelopeQueryV1, HookAdapterHostV1, HookAdapterQueryV1, HookAdapterRequestV1,
    HookAdapterResultV1, HOOK_ADAPTER_REQUEST_SCHEMA, HOOK_ADAPTER_RESULT_SCHEMA,
};
use serde_json::{json, Value};

/// A typed failure: `code` plus an optional detail the Python side maps back
/// to the exception the old in-process path raised.
struct Failure {
    code: String,
    payload: Option<Value>,
}

impl Failure {
    fn code(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            payload: None,
        }
    }
}

impl From<AdapterError> for Failure {
    fn from(error: AdapterError) -> Self {
        match error {
            AdapterError::ClinePayload(message) => Self {
                code: "native_hook_adapter_cline_payload".to_owned(),
                payload: Some(json!({ "message": message })),
            },
            AdapterError::UnsupportedHarness(harness) => Self {
                code: "native_hook_adapter_unsupported_harness".to_owned(),
                payload: Some(json!({ "harness": harness })),
            },
            AdapterError::Unsupported(code) => Self::code(code),
        }
    }
}

pub(crate) fn evaluate_hook_adapter_request(
    request: &HookAdapterRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != HOOK_ADAPTER_REQUEST_SCHEMA {
        return Err("native_hook_adapter_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match answer(&request.query) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(failure) => ("error", failure.code, failure.payload),
    };
    let result = |status: &str, code: String, payload: Option<Value>| HookAdapterResultV1 {
        schema: HOOK_ADAPTER_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.clone(),
        status: status.to_owned(),
        code,
        payload,
    };
    match crate::resident_protocol::encode_response(&result(status, code, payload)) {
        Ok(bytes) => Ok(bytes),
        Err(_) => crate::resident_protocol::encode_response(&result(
            "error",
            "native_hook_adapter_response_too_large".to_owned(),
            None,
        )),
    }
}

fn request_digest(request: &HookAdapterRequestV1) -> Result<String, String> {
    let invalid = || "native_hook_adapter_request_invalid".to_owned();
    let material = serde_json::to_value(request).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn ordered(value: &Value) -> Result<OValue, Failure> {
    OValue::from_wire(value).map_err(Failure::code)
}

fn ordered_map(value: &Value) -> Result<OMap, Failure> {
    match ordered(value)? {
        OValue::Map(map) => Ok(map),
        _ => Err(Failure::code("native_hook_adapter_wire_invalid")),
    }
}

fn path_env(host: &HookAdapterHostV1) -> PathEnv {
    PathEnv {
        tilde_home: host.tilde_home.clone(),
        default_home: host.default_home.clone(),
        cwd: host.cwd.clone(),
    }
}

fn answer(query: &HookAdapterQueryV1) -> Result<Value, Failure> {
    match query {
        HookAdapterQueryV1::PreparePayload {
            harness,
            payload,
            devin_project_dir,
        } => {
            let prepared = prepare_payload(
                harness,
                &ordered_map(payload)?,
                devin_project_dir.as_deref(),
            )?;
            Ok(OValue::Map(prepared).to_wire())
        }
        HookAdapterQueryV1::ActionEnvelope(query) => action_envelope(query),
        HookAdapterQueryV1::CommandDetail {
            text,
            home_dir,
            host,
        } => {
            let detail = command_detail_text(text, home_dir.as_deref(), &path_env(host))?;
            Ok(json!({ "text": detail }))
        }
        HookAdapterQueryV1::CommandText {
            tool_name,
            tool_input,
        } => {
            let input = match ordered(tool_input)? {
                OValue::Map(map) => Some(map),
                _ => None,
            };
            let text = input.and_then(|input| command_text(tool_name.as_str(), &input));
            Ok(json!({ "text": text }))
        }
        HookAdapterQueryV1::WorkspaceLabel {
            workspace,
            home_dir,
            host,
        } => {
            let label = workspace_label(workspace, home_dir.as_deref(), &path_env(host))?;
            Ok(json!({ "text": label }))
        }
        HookAdapterQueryV1::ApplyPatchPaths { tool_input } => {
            let paths = match ordered(tool_input)? {
                OValue::Map(map) => apply_patch_paths(&map),
                _ => Vec::new(),
            };
            Ok(json!({ "paths": paths }))
        }
    }
}

fn action_envelope(query: &ActionEnvelopeQueryV1) -> Result<Value, Failure> {
    let payload = ordered_map(&query.payload)?;
    let environment: Option<BTreeMap<String, String>> = query
        .path_env
        .as_ref()
        .map(|path| BTreeMap::from([("PATH".to_owned(), path.clone())]));
    let mut provider = |command: &str, workspace: Option<&Path>, home: Option<&Path>| {
        parse_package_intent(command, workspace, home, None, environment.as_ref()).map(|intent| {
            IntentSummary {
                package_manager: intent.package_manager,
                intent_kind: intent.intent_kind.to_owned(),
                targets: intent
                    .targets
                    .into_iter()
                    .map(|target| (target.raw_spec, target.package_name))
                    .collect(),
            }
        })
    };
    let request = EnvelopeRequest {
        harness: &query.harness,
        event_name: &query.event_name,
        payload: &payload,
        workspace: query.workspace.as_deref(),
        home_dir: query.home_dir.as_deref(),
        devin_project_dir: query.devin_project_dir.as_deref(),
        env: path_env(&query.host),
    };
    let envelope = normalize_harness_envelope(&request, &mut provider)?;
    Ok(OValue::Map(envelope).to_wire())
}

#[cfg(test)]
#[path = "hook_adapter_op_tests.rs"]
mod tests;
