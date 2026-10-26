//! `runner_authority` kind `hermes_detect`: the filesystem discovery of
//! `HermesHarnessAdapter.detect`. Python resolves the Hermes home, the host
//! home mirror and the managed server names; this walks the skills, parses the
//! configuration files, applies the host-home and manifest fallbacks, and
//! returns the artifacts, the config paths that were found, and the warnings.
//! Every refusal is a stable code and never a partial inventory.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_op::absolute;
use super::aibom_paths::{file_name_string, is_dir, is_file, resolve};
use super::context_digest::python_strip;
use super::hermes_inspect::{inspect_config, ConfigInspection, Syntax};
use super::hermes_skills::{scan_skills, Identities};
use super::hermes_text::looks_like_secret;
use super::pyjson::PyVal;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{pair_value, Fields, Scope};
use super::zcode_detect::json_payload;

const HARNESS: &str = "hermes";
const ERR_VALUE: &str = "native_runner_authority_hermes_value_unrepresentable";
const ERR_ROOT: &str = "native_runner_authority_hermes_root_unresolvable";
const SCOPE: Scope<'static> = Scope {
    harness: HARNESS,
    scope: "global",
};
const AUTH_TOKENS: [&str; 5] = ["auth", "token", "key", "secret", "bearer"];
const SMALL_CONFIG_BYTES: u64 = 300;

#[derive(Default)]
pub(crate) struct Found {
    pub(crate) artifacts: Vec<Value>,
    pub(crate) paths: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `_hermes_home_has_artifacts`.
fn home_has_artifacts(home: &Path) -> Result<bool, &'static str> {
    for name in ["config.yaml", "config.toml"] {
        let path = home.join(name);
        if is_file(&path)
            && fs::metadata(&path).is_ok_and(|metadata| metadata.len() > SMALL_CONFIG_BYTES)
        {
            return Ok(true);
        }
    }
    let yaml = home.join("config.yaml");
    if is_file(&yaml) {
        let inspection = inspect_config(&yaml, Syntax::Yaml)?;
        // An unreadable or malformed primary config is still an artifact.
        let Some(payload) = inspection.payload.as_ref() else {
            return Ok(true);
        };
        if !yaml_servers(payload).is_empty() {
            return Ok(true);
        }
    }
    let json_path = home.join("mcp_servers.json");
    if is_file(&json_path) {
        let inspection = inspect_config(&json_path, Syntax::Json)?;
        let Some(payload) = inspection.payload.as_ref() else {
            return Ok(true);
        };
        if payload.iter().any(|(_, config)| config.as_dict().is_some()) {
            return Ok(true);
        }
    }
    let skills = home.join("skills");
    if is_dir(&skills) {
        let Ok(categories) = fs::read_dir(&skills) else {
            return Ok(false);
        };
        for category in categories {
            let Ok(category) = category else {
                return Ok(false);
            };
            let category = category.path();
            if !is_dir(&category) {
                continue;
            }
            let Ok(skill_dirs) = fs::read_dir(&category) else {
                return Ok(false);
            };
            for skill in skill_dirs {
                let Ok(skill) = skill else {
                    return Ok(false);
                };
                let skill = skill.path();
                if is_dir(&skill) && is_file(&skill.join("SKILL.md")) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// `_mcp_servers_from_payload`.
fn yaml_servers(payload: &[(String, PyVal)]) -> Vec<(&str, &PyVal)> {
    payload
        .iter()
        .find(|(name, _)| name == "mcp_servers")
        .and_then(|(_, value)| value.as_dict())
        .map(|entries| {
            entries
                .iter()
                .filter(|(_, config)| config.as_dict().is_some())
                .map(|(name, config)| (name.as_str(), config))
                .collect()
        })
        .unwrap_or_default()
}

/// `_config_failure_artifact` and `_config_failure_warning`.
fn config_failure(
    path: &Path,
    source: &str,
    inspection: &ConfigInspection,
    found: &mut Found,
) -> Result<(), &'static str> {
    let reason = inspection.reason.unwrap_or("config_parse_error");
    let label = source.to_uppercase();
    let mut metadata = Map::new();
    for (key, value) in inspection.file.metadata() {
        metadata.insert(key, value.to_json().ok_or(ERR_VALUE)?);
    }
    metadata.insert("config_parse_complete".to_owned(), json!(false));
    metadata.insert("config_reason".to_owned(), json!(reason));
    metadata.insert(
        "runtime_request_signals".to_owned(),
        json!([format!(
            "Hermes {label} configuration inspection is incomplete ({reason}); review is required."
        )]),
    );
    found.artifacts.push(SCOPE.wire(
        format!("hermes:config:{source}:incomplete"),
        &format!("Incomplete Hermes {label} configuration"),
        "configuration",
        path,
        Fields::default(),
        metadata,
    ));
    found.warnings.push(format!(
        "Hermes config {} was not accepted ({reason}); no partial configuration was applied.",
        file_name_string(path)
    ));
    Ok(())
}

fn json_of(value: Option<&PyVal>) -> Result<Value, &'static str> {
    value.map_or(Ok(Value::Null), |value| value.to_json().ok_or(ERR_VALUE))
}

fn sorted_strings(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

/// `_mcp_artifacts`.
fn mcp_artifacts(
    servers: &[(&str, &PyVal)],
    config_path: &Path,
    source: &str,
    found: &mut Found,
) -> Result<(), &'static str> {
    const EMPTY: &[(String, PyVal)] = &[];
    for (name, config) in servers {
        if matches!(config.get("enabled"), Some(PyVal::Bool(false))) {
            continue;
        }
        let command = config.get("command").and_then(PyVal::as_str);
        let url = config.get("url").and_then(PyVal::as_str);
        let args: Vec<String> = config
            .get("args")
            .and_then(PyVal::as_list)
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect();
        let env = config.get("env").and_then(PyVal::as_dict).unwrap_or(EMPTY);
        let headers = config
            .get("headers")
            .and_then(PyVal::as_dict)
            .unwrap_or(EMPTY);
        let sampling = config
            .get("sampling")
            .filter(|value| value.as_dict().is_some());
        let transport = if url.is_some() { "http" } else { "stdio" };

        let header_keys: Vec<String> = headers.iter().map(|(key, _)| key.clone()).collect();
        let auth_header_keys: Vec<String> = header_keys
            .iter()
            .filter(|key| {
                let lower = key.to_lowercase();
                AUTH_TOKENS.iter().any(|token| lower.contains(token))
            })
            .cloned()
            .collect();
        let (sampling_enabled, sampling_model) = match sampling {
            Some(sampling) => (
                match sampling.get("enabled") {
                    Some(value) => value.to_json().ok_or(ERR_VALUE)?,
                    None => json!(true),
                },
                json_of(sampling.get("model"))?,
            ),
            None => (Value::Null, Value::Null),
        };
        let env_keys = sorted_strings(env.iter().map(|(key, _)| key.clone()).collect());
        let configured = |entries: &[(String, PyVal)]| -> BTreeMap<String, String> {
            let mut pairs = BTreeMap::new();
            for (key, value) in entries {
                let key = python_strip(key);
                if let (false, Some(item)) = (key.is_empty(), value.as_str()) {
                    pairs.insert(key.to_owned(), item.to_owned());
                }
            }
            pairs
        };
        let secret_keys = |entries: &[(String, PyVal)]| -> Vec<String> {
            sorted_strings(
                entries
                    .iter()
                    .filter(|(_, value)| value.as_str().is_some_and(looks_like_secret))
                    .map(|(key, _)| key.clone())
                    .collect(),
            )
        };
        let configured_env = configured(env);
        let configured_headers = configured(headers);

        let mut metadata = Map::new();
        metadata.insert("source".to_owned(), json!(source));
        metadata.insert("env_keys".to_owned(), json!(env_keys));
        metadata.insert(
            "header_keys".to_owned(),
            json!(sorted_strings(header_keys.clone())),
        );
        metadata.insert(
            "headers_keys".to_owned(),
            json!(sorted_strings(header_keys.clone())),
        );
        metadata.insert(
            "auth_header_keys".to_owned(),
            json!(sorted_strings(auth_header_keys.clone())),
        );
        metadata.insert("sampling_enabled".to_owned(), sampling_enabled);
        metadata.insert("sampling_model".to_owned(), sampling_model);
        metadata.insert("envConfigurationPresent".to_owned(), json!(!env.is_empty()));
        metadata.insert(
            "has_auth_headers".to_owned(),
            json!(!auth_header_keys.is_empty()),
        );
        let env_hints = secret_keys(env);
        if !env_hints.is_empty() {
            metadata.insert("env_value_secret_keys".to_owned(), json!(env_hints));
        }
        let header_hints = secret_keys(headers);
        if !header_hints.is_empty() {
            metadata.insert("header_value_secret_keys".to_owned(), json!(header_hints));
        }

        let enriched = enrich(&McpMetadataInput {
            command: command.map(str::to_owned),
            args: args.clone(),
            url: url.map(str::to_owned),
            transport: Some(transport.to_owned()),
            env_keys: env_keys.clone(),
            headers_keys: sorted_strings(header_keys),
            env: pair_value(&configured_env),
            headers: pair_value(&configured_headers),
            env_values_hash: None,
            header_values_hash: None,
            label: "mcp".to_owned(),
        })
        .map_err(|_| ERR_METADATA)?;
        for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
            metadata.insert(key.clone(), value.clone());
        }
        found.artifacts.push(SCOPE.wire(
            format!("hermes:mcp:{source}:{name}"),
            name,
            "mcp_server",
            config_path,
            Fields {
                command,
                args,
                url,
                transport: Some(transport),
                publisher: None,
            },
            metadata,
        ));
    }
    Ok(())
}

/// `_scan_mcp_servers`.
fn scan_mcp(
    home: &Path,
    managed_names: &HashSet<String>,
    found: &mut Found,
) -> Result<(), &'static str> {
    let yaml = home.join("config.yaml");
    if is_file(&yaml) {
        found.paths.push(text(&yaml));
        let inspection = inspect_config(&yaml, Syntax::Yaml)?;
        match inspection.payload.as_ref() {
            Some(payload) => {
                let servers: Vec<(&str, &PyVal)> = yaml_servers(payload)
                    .into_iter()
                    .filter(|(name, _)| !managed_names.contains(*name))
                    .collect();
                mcp_artifacts(&servers, &yaml, "yaml", found)?;
            }
            None => config_failure(&yaml, "yaml", &inspection, found)?,
        }
    }
    let json_path = home.join("mcp_servers.json");
    if is_file(&json_path) {
        found.paths.push(text(&json_path));
        let inspection = inspect_config(&json_path, Syntax::Json)?;
        match inspection.payload.as_ref() {
            Some(payload) => {
                let servers: Vec<(&str, &PyVal)> = payload
                    .iter()
                    .filter(|(_, config)| config.as_dict().is_some())
                    .map(|(name, config)| (name.as_str(), config))
                    .collect();
                mcp_artifacts(&servers, &json_path, "json", found)?;
            }
            None => config_failure(&json_path, "json", &inspection, found)?,
        }
    }
    Ok(())
}

/// `_scan_manifest_mcp_servers`.
fn scan_manifest(manifest: &Path, found: &mut Found) -> Result<(), &'static str> {
    if !is_file(manifest) {
        return Ok(());
    }
    let payload = json_payload(manifest)?;
    let Some(servers) = payload
        .get("servers")
        .and_then(PyVal::as_dict)
        .filter(|servers| !servers.is_empty())
    else {
        return Ok(());
    };
    found.paths.push(text(manifest));
    // Re-key by the real server name; a repeated name keeps its first position
    // and takes its latest value, as a dict assignment does.
    let mut keyed: Vec<(&str, &PyVal)> = Vec::new();
    for (key, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        let name = match config.get("name").and_then(PyVal::as_str) {
            Some(real) if !real.is_empty() => real,
            _ => key.as_str(),
        };
        match keyed.iter_mut().find(|(existing, _)| *existing == name) {
            Some(slot) => slot.1 = config,
            None => keyed.push((name, config)),
        }
    }
    mcp_artifacts(&keyed, manifest, "manifest", found)
}

fn optional_absolute(value: Option<&Value>) -> Result<Option<std::path::PathBuf>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        other => Ok(Some(absolute(other).map_err(|_| ERR_INVALID)?)),
    }
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.get("harness").and_then(Value::as_str) != Some(HARNESS) {
        return Err(ERR_INVALID);
    }
    let home = absolute(args.get("hermes_home")).map_err(|_| ERR_INVALID)?;
    let host_home = optional_absolute(args.get("host_home"))?;
    let manifest = optional_absolute(args.get("manifest_path"))?;
    let managed_names: HashSet<String> = args
        .get("managed_names")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|name| name.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect::<Result<_, _>>()?;
    let identities: Identities<'_> = match args.get("skill_identities") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => return Err(ERR_INVALID),
    };

    let mut found = Found::default();
    for name in ["config.yaml", "config.toml"] {
        let path = home.join(name);
        if is_file(&path) {
            found.paths.push(text(&path));
        }
    }
    scan_skills(&home.join("skills"), &mut found, identities)?;
    scan_mcp(&home, &managed_names, &mut found)?;

    if let Some(host) = host_home {
        let distinct =
            resolve(&host).map_err(|()| ERR_ROOT)? != resolve(&home).map_err(|()| ERR_ROOT)?;
        if distinct && !home_has_artifacts(&home)? {
            scan_skills(&host.join("skills"), &mut found, identities)?;
            scan_mcp(&host, &HashSet::new(), &mut found)?;
        }
    }
    if !found
        .artifacts
        .iter()
        .any(|artifact| artifact.get("artifact_type").and_then(Value::as_str) == Some("mcp_server"))
    {
        if let Some(manifest) = manifest {
            scan_manifest(&manifest, &mut found)?;
        }
    }
    let mut seen = HashSet::new();
    let warnings: Vec<String> = found
        .warnings
        .into_iter()
        .filter(|warning| seen.insert(warning.clone()))
        .collect();
    Ok(json!({
        "artifacts": found.artifacts,
        "found_paths": found.paths,
        "warnings": warnings,
    }))
}
