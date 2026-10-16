//! `guard-config-update --stdin`: the Guard home `config.toml` writer.
//!
//! Owns the settings write, the update-channel write and the settings reset
//! that `guard/config.py` performed. The caller resolves the managed policy
//! and the cloud-sync entitlement, gates the write on approval, then reloads
//! the config through `guard-config-load` and records posture events from the
//! returned previous state.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_secure_fs::read_stable;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::guard_config_load::coerce_config;
use crate::guard_config_managed::{apply_managed_policy, ManagedInput};
use crate::guard_config_update_settings as settings;
use crate::guard_config_update_value::{from_toml_table, render, set, Tv};
use crate::package_authority_config::{merge_config_payload, HOME_CONFIG_FILENAME};
use crate::pyjson::{self, PyVal};

const SCHEMA: &str = "guard-config-update.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    schema: String,
    guard_home: PathBuf,
    kind: String,
    /// `json.dumps` of the settings payload or the update channel.
    value_text: String,
    #[serde(default)]
    managed: Option<ManagedInput>,
    #[serde(default)]
    cloud_sync_entitled: bool,
}

/// Why a write was refused.
#[derive(Debug, PartialEq)]
pub(crate) enum Failure {
    /// The request itself is invalid; Python raises `ValueError(message)`.
    Invalid(String),
    /// The stored config cannot be trusted or read.
    Error(String),
}

/// The text to write, and for a settings write the state before it.
pub(crate) struct Computed {
    pub(crate) text: String,
    pub(crate) previous: Option<Value>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "guard-config-update"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_config_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_config_request_too_large".to_owned());
    }
    let request: UpdateRequest =
        serde_json::from_slice(&bytes).map_err(|_| "guard_config_request_invalid".to_owned())?;
    if request.schema != SCHEMA
        || !matches!(request.kind.as_str(), "settings" | "channel" | "reset")
    {
        return Err("guard_config_request_invalid".to_owned());
    }
    let value = pyjson::parse(&request.value_text)
        .map_err(|_| "guard_config_request_invalid".to_owned())?;
    let response = match write(&request, &value) {
        Ok(previous) => json!({"ok": true, "previous": previous}),
        Err(Failure::Invalid(message)) => json!({"ok": false, "invalid": message}),
        Err(Failure::Error(reason)) => json!({"ok": false, "error": reason}),
    };
    serde_json::to_vec(&response).map_err(|_| "guard_config_response_encode_failed".to_owned())
}

fn write(request: &UpdateRequest, value: &PyVal) -> Result<Value, Failure> {
    if request.kind == "channel" {
        channel(value)?;
    }
    let home = &request.guard_home;
    fs::create_dir_all(home).map_err(|_| Failure::Error("config_file_unavailable".to_owned()))?;
    let stored = read_home_config(home)?;
    let computed = compute(
        &request.kind,
        stored.as_deref(),
        value,
        request.managed.as_ref(),
        request.cloud_sync_entitled,
        &now_iso(),
    )?;
    fs::write(home.join(HOME_CONFIG_FILENAME), computed.text)
        .map_err(|_| Failure::Error("config_write_failed".to_owned()))?;
    Ok(computed.previous.unwrap_or(Value::Null))
}

/// `read_config_file_bytes` for the home config; `None` when it is absent.
fn read_home_config(home: &Path) -> Result<Option<String>, Failure> {
    let path = home.join(HOME_CONFIG_FILENAME);
    let unavailable = |reason: &str| Failure::Error(reason.to_owned());
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable("config_file_unavailable")),
    }
    let read = read_stable(&path, MAX_CONFIG_BYTES, false)
        .map_err(|_| unavailable("config_file_unavailable_or_changed"))?;
    String::from_utf8(read.bytes)
        .map(Some)
        .map_err(|_| unavailable("config_not_utf8"))
}

/// `_utc_now_iso`: whole seconds, `+00:00`.
fn now_iso() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let micros = i64::try_from(seconds)
        .unwrap_or(0)
        .saturating_mul(1_000_000);
    crate::policy_bundle_time::micros_to_utc_isoformat(micros, "+00:00").unwrap_or_default()
}

fn channel(value: &PyVal) -> Result<&str, Failure> {
    value
        .as_str()
        .filter(|channel| matches!(*channel, "stable" | "alpha"))
        .ok_or_else(|| Failure::Invalid("Update channel must be stable or alpha.".to_owned()))
}

/// The new `config.toml` text for one write. Pure: no filesystem access.
pub(crate) fn compute(
    kind: &str,
    stored_text: Option<&str>,
    value: &PyVal,
    managed: Option<&ManagedInput>,
    cloud_sync_entitled: bool,
    now: &str,
) -> Result<Computed, Failure> {
    let channel_value = match kind {
        "channel" => Some(channel(value)?),
        _ => None,
    };
    let table: toml::Table = stored_text
        .unwrap_or_default()
        .parse()
        .map_err(|_| Failure::Error("config_malformed".to_owned()))?;
    let stored_json = match serde_json::to_value(&table) {
        Ok(Value::Object(map)) => map,
        _ => return Err(Failure::Error("config_malformed".to_owned())),
    };
    let stored = from_toml_table(table);
    match kind {
        "reset" => Ok(Computed {
            text: render(&settings::reset(&stored)),
            previous: None,
        }),
        "channel" => {
            let locked = managed.is_some_and(|policy| {
                policy
                    .locked_settings
                    .iter()
                    .any(|key| key == "update_channel")
            });
            if locked {
                return Err(Failure::Invalid(
                    "Managed policy locks the update channel.".to_owned(),
                ));
            }
            let mut next = stored;
            let channel_value = channel_value.unwrap_or("stable");
            set(
                &mut next,
                "update_channel",
                Tv::Str(channel_value.to_owned()),
            );
            Ok(Computed {
                text: render(&next),
                previous: None,
            })
        }
        _ => {
            let PyVal::Dict(payload) = value else {
                return Err(Failure::Invalid(
                    "Guard settings must be an object.".to_owned(),
                ));
            };
            let current = current_config(&stored_json, managed);
            let write = settings::update(
                &stored,
                &current,
                payload,
                managed,
                cloud_sync_entitled,
                now,
            )
            .map_err(Failure::Invalid)?;
            Ok(Computed {
                text: render(&write.next),
                previous: Some(write.previous),
            })
        }
    }
}

/// `load_guard_config(guard_home)` over the already-read home config.
fn current_config(stored: &Map<String, Value>, managed: Option<&ManagedInput>) -> Value {
    let mut merged = merge_config_payload(stored, &Map::new());
    if let Some(policy) = managed {
        merged = apply_managed_policy(&merged, policy);
    }
    coerce_config(&merged, managed)
}

#[cfg(test)]
#[path = "guard_config_update_tests.rs"]
mod tests;
