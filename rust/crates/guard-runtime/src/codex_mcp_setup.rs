//! Version-bound MCP setup and rollback through the supported Codex config API:
//! the retired Python `runtime/codex_mcp_setup.py`.
//!
//! Codex owns its `config.toml`. Guard adds or removes one `mcp_servers.<name>`
//! entry through `config/batchWrite`, always bound to the version of the user
//! layer it just read, so an edit made in the meantime is never overwritten.
//! A write whose outcome is unclear is never replayed and never removed
//! without a version receipt that proves what was written.
//!
//! `codex-mcp-setup --stdin` takes one of two requests:
//! - `install`: checks the name is free in every layer, writes the entry,
//!   reads it back, and answers the receipt. When the read-back disagrees it
//!   removes the entry again and answers `codex_setup_rolled_back` with the
//!   version chain of the two writes it made.
//! - `rollback`: removes the entry a receipt names, if the user layer is
//!   still at the receipt's version and still holds exactly that entry.
//!
//! The caller keeps the receipt and runs its own bookkeeping between the two.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::codex_config_rpc::{ConfigHost, ConfigRpc, Reason, CHANGED, DEFAULT_TIMEOUT, READONLY};

const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LAYERS: usize = 32;
const MAX_ENTRY_ITEMS: usize = 65_536;
const UNCERTAIN: Reason = "codex_setup_outcome_uncertain";
const ROLLED_BACK: Reason = "codex_setup_rolled_back";
const EXISTS: Reason = "codex_connection_already_exists";
const INVALID_SELECTION: Reason = "invalid_codex_setup_selection";
const INVALID_RECEIPT: Reason = "codex_setup_receipt_invalid";

pub(crate) fn is_command(command: &str) -> bool {
    command == "codex-mcp-setup"
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub(crate) name: String,
    pub(crate) file_path: String,
    pub(crate) version: String,
    pub(crate) entry_json: String,
    #[serde(default)]
    pub(crate) previous_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Install {
        executable: String,
        cwd: String,
        environment: BTreeMap<String, String>,
        name: String,
        entry_json: String,
    },
    Rollback {
        executable: String,
        cwd: String,
        environment: BTreeMap<String, String>,
        receipt: Receipt,
    },
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "codex_mcp_setup_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("codex_mcp_setup_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "codex_mcp_setup_request_invalid".to_owned())?;
    serde_json::to_vec(&answer(request))
        .map_err(|_| "codex_mcp_setup_response_encode_failed".to_owned())
}

fn answer(request: Request) -> Value {
    match request {
        Request::Install {
            executable,
            cwd,
            environment,
            name,
            entry_json,
        } => {
            if !valid_name(&name) {
                return failure(INVALID_SELECTION);
            }
            let Some(entry) = parse_entry(&entry_json) else {
                return failure(INVALID_RECEIPT);
            };
            let mut host = match open(&executable, &cwd, environment) {
                Ok(host) => host,
                Err(reason) => return failure(reason),
            };
            let outcome = install(&mut host, &name, &entry, &entry_json);
            host.close();
            match outcome {
                Ok(receipt) => json!({"receipt": receipt}),
                Err(error) => {
                    let mut reply = failure(error.reason);
                    if let Some((file_path, chain)) = error.chain {
                        reply["version_chain"] = json!({"file_path": file_path, "pairs": chain});
                    }
                    reply
                }
            }
        }
        Request::Rollback {
            executable,
            cwd,
            environment,
            receipt,
        } => {
            if !valid_name(&receipt.name) {
                return failure(INVALID_SELECTION);
            }
            let Some(entry) = parse_entry(&receipt.entry_json) else {
                return failure(INVALID_RECEIPT);
            };
            let mut host = match open(&executable, &cwd, environment) {
                Ok(host) => host,
                Err(reason) => return failure(reason),
            };
            let outcome = rollback(&mut host, &receipt, &entry);
            host.close();
            match outcome {
                Ok(version) => json!({"version": version}),
                Err(reason) => failure(reason),
            }
        }
    }
}

fn failure(reason: Reason) -> Value {
    json!({"error": reason})
}

fn open(
    executable: &str,
    cwd: &str,
    environment: BTreeMap<String, String>,
) -> Result<ConfigRpc, Reason> {
    let environment: Vec<(String, String)> = environment.into_iter().collect();
    ConfigRpc::open(
        executable,
        Some(Path::new(cwd)),
        &environment,
        DEFAULT_TIMEOUT,
    )
}

/// `[a-z0-9][a-z0-9_-]{0,63}`: a name that cannot reach beyond its own key.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= 64
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn parse_entry(text: &str) -> Option<Value> {
    crate::strict_json::parse_with_collection_limit(text.as_bytes(), MAX_ENTRY_ITEMS).ok()
}

fn version_fits(version: &str) -> bool {
    (1..=256).contains(&version.chars().count())
}

/// What `config/read` says, once it is known to be shaped as expected.
struct Layers {
    layers: Vec<Map<String, Value>>,
    user: usize,
}

impl Layers {
    fn user(&self) -> &Map<String, Value> {
        &self.layers[self.user]
    }

    fn user_version(&self) -> &str {
        self.user()
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    fn user_file(&self) -> &str {
        self.user()
            .get("name")
            .and_then(|name| name.get("file"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The entry the user layer holds for `name`; null when it holds none.
    fn user_entry(&self, name: &str) -> &Value {
        servers(self.user())
            .and_then(|servers| servers.get(name))
            .unwrap_or(&Value::Null)
    }

    /// Whether any layer other than the user layer defines `name`.
    fn other_layers_contain(&self, name: &str) -> bool {
        self.layers
            .iter()
            .enumerate()
            .any(|(index, layer)| index != self.user && contains(layer, name))
    }

    fn any_layer_contains(&self, name: &str) -> bool {
        self.layers.iter().any(|layer| contains(layer, name))
    }
}

fn servers(layer: &Map<String, Value>) -> Option<&Map<String, Value>> {
    layer
        .get("config")
        .and_then(Value::as_object)
        .and_then(|config| config.get("mcp_servers"))
        .and_then(Value::as_object)
}

/// Whether a validated layer defines `name`, even as null metadata.
fn contains(layer: &Map<String, Value>, name: &str) -> bool {
    servers(layer).is_some_and(|servers| servers.contains_key(name))
}

fn read_layers(host: &mut dyn ConfigHost) -> Result<Layers, Reason> {
    let payload = host.request("config/read", &json!({"includeLayers": true}))?;
    let raw = match payload.get("layers") {
        Some(Value::Array(layers)) if layers.is_empty() => return Err("codex_config_no_layers"),
        Some(Value::Array(layers)) if layers.len() <= MAX_LAYERS => layers,
        _ => return Err("codex_config_layers_unavailable"),
    };
    let mut layers = Vec::with_capacity(raw.len());
    let mut users = Vec::new();
    for layer in raw {
        let Some(layer) = layer.as_object() else {
            return Err("codex_config_invalid_layer");
        };
        let Some(config) = layer.get("config").and_then(Value::as_object) else {
            return Err("codex_config_invalid_layer");
        };
        if config
            .get("mcp_servers")
            .is_some_and(|servers| !servers.is_object())
        {
            return Err("codex_config_invalid_servers");
        }
        let is_user = layer.get("name").is_some_and(|source| {
            source.get("type").and_then(Value::as_str) == Some("user")
                && source.get("profile").is_none_or(Value::is_null)
        });
        if is_user {
            users.push(layers.len());
        }
        layers.push(layer.clone());
    }
    let user = match users.as_slice() {
        [] => return Err("codex_config_no_user_layer"),
        [only] => *only,
        _ => return Err("codex_config_multiple_user_layers"),
    };
    let layer = &layers[user];
    let version = layer.get("version").and_then(Value::as_str);
    if !version.is_some_and(version_fits) {
        return Err("codex_config_invalid_user_version");
    }
    let file = layer
        .get("name")
        .and_then(|source| source.get("file"))
        .and_then(Value::as_str);
    if !file.is_some_and(|file| Path::new(file).is_absolute()) {
        return Err("codex_config_invalid_user_path");
    }
    if layer
        .get("disabledReason")
        .is_some_and(|reason| !reason.is_null())
    {
        return Err("codex_config_user_layer_disabled");
    }
    Ok(Layers { layers, user })
}

/// One `config/batchWrite` of `mcp_servers.<name>`; `None` removes the entry.
/// Anything but a version conflict or a read-only layer leaves the outcome unclear.
fn write(
    host: &mut dyn ConfigHost,
    receipt: &Receipt,
    value: Option<&Value>,
) -> Result<String, Reason> {
    let params = json!({
        "filePath": receipt.file_path,
        "expectedVersion": receipt.version,
        "reloadUserConfig": false,
        "edits": [{
            "keyPath": format!("mcp_servers.{}", receipt.name),
            "value": value,
            "mergeStrategy": "replace",
        }],
    });
    let response = match host.request("config/batchWrite", &params) {
        Ok(response) => response,
        Err(reason) if reason == CHANGED || reason == READONLY => return Err(reason),
        Err(_) => return Err(UNCERTAIN),
    };
    let version = response.get("version").and_then(Value::as_str);
    let acknowledged = response.get("status").and_then(Value::as_str) == Some("ok")
        && response.get("filePath").and_then(Value::as_str) == Some(receipt.file_path.as_str())
        && version.is_some_and(version_fits)
        && response
            .get("overriddenMetadata")
            .is_none_or(Value::is_null);
    match version {
        Some(version) if acknowledged => Ok(version.to_owned()),
        _ => Err(UNCERTAIN),
    }
}

/// Removes the entry `receipt` names, if nothing else changed; the new version.
pub(crate) fn rollback(
    host: &mut dyn ConfigHost,
    receipt: &Receipt,
    entry: &Value,
) -> Result<String, Reason> {
    let layers = read_layers(host)?;
    if layers.user_file() != receipt.file_path
        || layers.user_version() != receipt.version
        || layers.user_entry(&receipt.name) != entry
        || layers.other_layers_contain(&receipt.name)
    {
        return Err(CHANGED);
    }
    let version = write(host, receipt, None)?;
    let after = read_layers(host)?;
    if after.user_version() != version || after.any_layer_contains(&receipt.name) {
        return Err(UNCERTAIN);
    }
    Ok(version)
}

#[derive(Debug)]
pub(crate) struct InstallFailure {
    pub(crate) reason: Reason,
    /// The file and its `(from, to)` version pairs, when two writes were made and undone.
    pub(crate) chain: Option<(String, Vec<(String, String)>)>,
}

impl From<Reason> for InstallFailure {
    fn from(reason: Reason) -> Self {
        Self {
            reason,
            chain: None,
        }
    }
}

/// Adds `name` unless a layer already defines it, and reads it back.
pub(crate) fn install(
    host: &mut dyn ConfigHost,
    name: &str,
    entry: &Value,
    entry_json: &str,
) -> Result<Receipt, InstallFailure> {
    let layers = read_layers(host)?;
    if layers.any_layer_contains(name) {
        return Err(EXISTS.into());
    }
    let before = Receipt {
        name: name.to_owned(),
        file_path: layers.user_file().to_owned(),
        version: layers.user_version().to_owned(),
        entry_json: entry_json.to_owned(),
        previous_version: None,
    };
    let version = write(host, &before, Some(entry))?;
    let installed = Receipt {
        version: version.clone(),
        previous_version: Some(before.version.clone()),
        ..before.clone()
    };
    if verify(host, &layers, &version, name, entry).is_ok() {
        return Ok(installed);
    }
    match rollback(host, &installed, entry) {
        Ok(removed) => Err(InstallFailure {
            reason: ROLLED_BACK,
            chain: Some((
                before.file_path,
                vec![(before.version, version.clone()), (version, removed)],
            )),
        }),
        Err(_) => Err(UNCERTAIN.into()),
    }
}

/// The read-back after a write: same user layer, at the written version, holding
/// the written entry, and no other layer defining the name.
fn verify(
    host: &mut dyn ConfigHost,
    before: &Layers,
    version: &str,
    name: &str,
    entry: &Value,
) -> Result<(), Reason> {
    let verified = read_layers(host)?;
    if verified.user_version() != version
        || verified.user().get("name") != before.user().get("name")
        || verified.user_entry(name) != entry
        || verified.other_layers_contain(name)
    {
        return Err(UNCERTAIN);
    }
    Ok(())
}

#[cfg(test)]
#[path = "codex_mcp_setup_tests.rs"]
mod tests;
