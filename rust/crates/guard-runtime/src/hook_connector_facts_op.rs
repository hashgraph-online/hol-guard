//! Resident-owned launch facts for queued connector setup reviews.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::hook_payload_facts_op::{command, tool_input};
use crate::resident_protocol::encode_response;

pub(crate) const HOOK_CONNECTOR_FACTS_FEATURE: &str = "hook-connector-facts-v1";
const REQUEST_SCHEMA: &str = "guard-hook-connector-facts-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-connector-facts-result.v1";
const MAX_LOOKUP_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookConnectorFactsRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) payload: Value,
    pub(crate) reason_code: String,
    pub(crate) workspace: Option<String>,
    pub(crate) home_dir: Option<String>,
    pub(crate) user_home: String,
    pub(crate) env: BTreeMap<String, String>,
}

fn launch_cwd(payload: &Map<String, Value>, workspace: Option<&str>) -> Option<String> {
    let payload_cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|value| !crate::claude_hook_bridge_render::py_strip(value).is_empty());
    let candidate = payload_cwd.or_else(|| {
        workspace.filter(|value| !crate::claude_hook_bridge_render::py_strip(value).is_empty())
    })?;
    let path = Path::new(candidate);
    if !path.is_absolute() {
        return None;
    }
    let resolved = path.canonicalize().ok()?;
    resolved
        .is_dir()
        .then(|| resolved.to_string_lossy().into_owned())
}

fn stamped_path(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("guard_execution_environment")
        .and_then(Value::as_object)
        .and_then(|environment| environment.get("path"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .map(ToOwned::to_owned)
}

pub(crate) fn evaluate(request: &HookConnectorFactsRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.user_home.is_empty()
        || request.user_home.contains('\0')
        || request
            .env
            .iter()
            .any(|(key, value)| key.contains('\0') || value.contains('\0'))
    {
        return Err("hook_connector_facts_payload_invalid".to_owned());
    }
    let payload = request
        .payload
        .as_object()
        .ok_or_else(|| "hook_connector_facts_payload_invalid".to_owned())?;
    let connector_lookup = if matches!(
        request.reason_code.as_str(),
        "native_command_review_required" | "native_workspace_containment_executable_outside_roots"
    ) {
        let input = tool_input(payload);
        let command = command(payload, input.as_ref());
        let cwd = launch_cwd(payload, request.workspace.as_deref());
        match (command, cwd) {
            (Some(command), Some(cwd)) => {
                let mut env = request.env.clone();
                if let Some(path) = stamped_path(payload) {
                    env.insert("PATH".to_owned(), path);
                }
                let lookup = json!({
                    "command": command,
                    "cwd": cwd,
                    "home_dir": request.home_dir,
                    "user_home": request.user_home,
                    "env": env,
                });
                (serde_json::to_vec(&lookup)
                    .ok()
                    .filter(|bytes| bytes.len() <= MAX_LOOKUP_BYTES))
                .map(|_| lookup)
            }
            _ => None,
        }
    } else {
        None
    };
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "connector_lookup": connector_lookup,
        },
    }))
}

#[cfg(test)]
#[path = "hook_connector_facts_op_tests.rs"]
mod tests;
