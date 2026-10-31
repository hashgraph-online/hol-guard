//! `managed-policy-load --stdin`: the machine-managed policy for the Python
//! command surfaces that still report or compose it.
//!
//! `managed_policy_load` reads the machine authority and `managed_policy`
//! parses it; this command only frames a request and writes the state back as
//! JSON. A `load` answers what the machine says (or what an explicit file
//! says), and a `parse` validates a document the caller already holds, so a
//! malformed policy is rejected by the same parser the runtime enforces with.

use std::io::Read;
use std::path::PathBuf;

use guard_command::egress_caller_policy::ProxyMode;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::managed_policy::{parse_managed_policy, ManagedPolicy};
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource, ManagedPolicyState};

const SCHEMA: &str = "managed-policy-load.v1";
/// A policy document is bounded at 1 MiB; the request framing it may carry
/// one for a `parse`, escaped.
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    policy_path: Option<PathBuf>,
    #[serde(default = "default_write_cache")]
    write_cache: bool,
    #[serde(default)]
    payload: Option<Value>,
}

fn default_write_cache() -> bool {
    true
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "managed-policy-load"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "managed_policy_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("managed_policy_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "managed_policy_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("managed_policy_request_invalid".to_owned());
    }
    let response = respond(request)?;
    serde_json::to_vec(&response).map_err(|_| "managed_policy_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Result<Value, String> {
    match (request.op.as_str(), request.payload) {
        ("load", None) => {
            let mut source = ManagedPolicySource::native();
            source.policy_path = request.policy_path;
            source.write_cache = request.write_cache;
            Ok(json!({"ok": true, "state": state_json(&load_managed_policy(&source))}))
        }
        // A rejected document is an answer, not a failed request: the caller
        // raises the parser's own message.
        ("parse", Some(payload)) if request.policy_path.is_none() => {
            Ok(match parse_managed_policy(&payload) {
                Ok(policy) => json!({"ok": true, "policy": policy_json(&policy)}),
                Err(message) => json!({"ok": false, "rejected": message}),
            })
        }
        _ => Err("managed_policy_request_invalid".to_owned()),
    }
}

pub(crate) fn state_json(state: &ManagedPolicyState) -> Value {
    json!({
        "status": state.status.as_str(),
        "source": state.source,
        "policy": state.policy.as_ref().map(policy_json),
        "reason_code": state.reason_code,
        "detail": state.detail,
    })
}

fn proxy_mode(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::None => "none",
        ProxyMode::System => "system",
        ProxyMode::Explicit => "explicit",
    }
}

/// The parsed document in `mdm/contracts.py`'s field names. Release keys
/// travel as hex: they are public trust anchors, and JSON has no bytes.
pub(crate) fn policy_json(policy: &ManagedPolicy) -> Value {
    let network = &policy.network;
    let update = &policy.update;
    let trust = &policy.integrity_trust;
    let release_public_keys: Map<String, Value> = trust
        .release_public_keys
        .iter()
        .map(|(key_id, key)| (key_id.clone(), Value::from(hex::encode(key))))
        .collect();
    json!({
        "schema_version": policy.schema_version,
        "settings": policy.settings,
        "locked_settings": policy.locked_settings,
        "required_harnesses": policy.required_harnesses,
        "network": {
            "proxy_mode": proxy_mode(network.proxy_mode),
            "proxy_url": network.proxy_url,
            "ca_bundle_path": network
                .ca_bundle_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            "allow_public_registries": network.allow_public_registries,
        },
        "update": {
            "owner": update.owner.as_str(),
            "channel": update.channel,
            "minimum_version": update.minimum_version,
            "maximum_version": update.maximum_version,
            "allow_downgrade": update.allow_downgrade,
            "index_url": update.index_url,
        },
        "integrity_trust": {
            "release_public_keys": release_public_keys,
            "macos_team_id": trust.macos_team_id,
            "windows_signer_thumbprints": trust.windows_signer_thumbprints,
        },
        "daemon_startup": policy.daemon_startup.as_str(),
        "content_hash": policy.content_hash,
        "policy_bundle_keyring": policy.policy_bundle_keyring,
    })
}

#[cfg(test)]
#[path = "managed_policy_load_command_tests.rs"]
mod tests;
