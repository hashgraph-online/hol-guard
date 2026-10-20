//! ZCode inventory artifacts built from parsed config JSON (`zcode_config.py`):
//! MCP servers, enabled plugins, hook groups, plugin manifests, skills,
//! commands and marketplaces. Every artifact is the wire form of a
//! `GuardArtifact`; values keep the Python scalar and truthiness semantics the
//! rules were written against.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::context_digest::python_strip;
use super::pyjson::PyVal;

pub(crate) const ERR_UNREPRESENTABLE: &str = "native_runner_authority_zcode_value_unrepresentable";

const HOOK_EVENT_NAMES: [&str; 7] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
];
const MANAGED_MARKER: &str = "HOL_GUARD_MANAGED_ZCODE";

pub(crate) struct Scope<'a> {
    pub(crate) harness: &'a str,
    pub(crate) scope: &'a str,
}

#[derive(Default)]
pub(crate) struct Fields<'a> {
    pub(crate) command: Option<&'a str>,
    pub(crate) args: Vec<String>,
    pub(crate) url: Option<&'a str>,
    pub(crate) transport: Option<&'a str>,
    pub(crate) publisher: Option<&'a str>,
}

impl Scope<'_> {
    pub(crate) fn wire(
        &self,
        artifact_id: String,
        name: &str,
        artifact_type: &str,
        config_path: &Path,
        fields: Fields<'_>,
        metadata: Map<String, Value>,
    ) -> Value {
        json!({
            "artifact_id": artifact_id,
            "name": name,
            "harness": self.harness,
            "artifact_type": artifact_type,
            "source_scope": self.scope,
            "config_path": config_path.to_string_lossy(),
            "command": fields.command,
            "args": fields.args,
            "url": fields.url,
            "transport": fields.transport,
            "publisher": fields.publisher,
            "metadata": metadata,
        })
    }
}

fn python_lower(text: &str) -> String {
    text.to_lowercase()
}

/// `_string_args`: strings and numbers and booleans, rendered as `str()`.
pub(crate) fn scalar_args(config: &PyVal) -> Vec<String> {
    config
        .get("args")
        .and_then(PyVal::as_list)
        .map(|items| items.iter().filter_map(PyVal::scalar_text).collect())
        .unwrap_or_default()
}

/// `_mcp_transport`.
pub(crate) fn transport(config: &PyVal) -> String {
    if let Some(text) = config.get("transport").and_then(PyVal::as_str) {
        if !python_strip(text).is_empty() {
            return python_strip(text).to_owned();
        }
    }
    if let Some(text) = config.get("url").and_then(PyVal::as_str) {
        if !python_strip(text).is_empty() {
            return "http".to_owned();
        }
    }
    "stdio".to_owned()
}

/// Stripped, non-empty string keys with string values; a later duplicate wins.
pub(crate) fn string_pairs(value: &PyVal) -> BTreeMap<String, String> {
    let mut pairs = BTreeMap::new();
    for (key, item) in value.as_dict().unwrap_or_default() {
        let key = python_strip(key);
        if let (false, Some(text)) = (key.is_empty(), item.as_str()) {
            pairs.insert(key.to_owned(), text.to_owned());
        }
    }
    pairs
}

pub(crate) fn mcp_environment(config: &PyVal) -> BTreeMap<String, String> {
    for field in ["env", "environment"] {
        if let Some(value) = config.get(field).filter(|value| value.as_dict().is_some()) {
            return string_pairs(value);
        }
    }
    BTreeMap::new()
}

pub(crate) fn pair_value(pairs: &BTreeMap<String, String>) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(key, value)| json!([key, value]))
            .collect(),
    )
}

/// One MCP server definition, or `None` when it names neither command nor url.
pub(crate) fn mcp_server(
    scope: &Scope<'_>,
    server_name: &str,
    config: &PyVal,
    config_path: &Path,
    plugin: Option<&str>,
) -> Result<Option<Value>, &'static str> {
    let command = config.get("command").and_then(PyVal::as_str);
    let url = config.get("url").and_then(PyVal::as_str);
    if command.is_none() && url.is_none() {
        return Ok(None);
    }
    let args = scalar_args(config);
    let transport = transport(config);
    let environment = mcp_environment(config);
    let headers = config.get("headers").map(string_pairs).unwrap_or_default();
    let env_keys: Vec<String> = environment.keys().cloned().collect();
    let headers_keys: Vec<String> = headers.keys().cloned().collect();
    let enriched = enrich(&McpMetadataInput {
        command: command.map(str::to_owned),
        args: args.clone(),
        url: url.map(str::to_owned),
        transport: Some(transport.clone()),
        env_keys: env_keys.clone(),
        headers_keys: headers_keys.clone(),
        env: pair_value(&environment),
        headers: pair_value(&headers),
        env_values_hash: None,
        header_values_hash: None,
        label: server_name.to_owned(),
    })
    .map_err(|_| ERR_METADATA)?;
    let mut metadata = Map::new();
    metadata.insert("name".to_owned(), json!(server_name));
    metadata.insert("env_keys".to_owned(), json!(env_keys));
    metadata.insert("headers_keys".to_owned(), json!(headers_keys));
    if let Some(plugin) = plugin {
        metadata.insert("plugin".to_owned(), json!(plugin));
    }
    for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
        metadata.insert(key.clone(), value.clone());
    }
    let artifact_id = match plugin {
        Some(plugin) => format!(
            "{}:{}:plugin:{plugin}:mcp:{server_name}",
            scope.harness, scope.scope
        ),
        None => format!("{}:{}:mcp:{server_name}", scope.harness, scope.scope),
    };
    Ok(Some(scope.wire(
        artifact_id,
        server_name,
        "mcp_server",
        config_path,
        Fields {
            command,
            args,
            url,
            transport: Some(&transport),
            publisher: None,
        },
        metadata,
    )))
}

/// `is_guard_managed_hook_command`.
fn is_managed(command: &str) -> bool {
    command.contains(MANAGED_MARKER)
        || (command.contains("codex_plugin_scanner.cli")
            && command.contains("'guard', 'hook'")
            && command.contains("--harness', 'zcode'"))
}

/// `hook_event_groups`: nested `hooks.events` first, then the legacy flat
/// layout, with equal duplicate entries dropped per event.
pub(crate) fn hook_event_groups(hooks: &PyVal) -> Vec<(String, Vec<PyVal>)> {
    let mut groups: Vec<(String, Vec<PyVal>)> = Vec::new();
    let mut extend = |name: &str, entries: &[PyVal]| match groups
        .iter_mut()
        .find(|(existing, _)| existing == name)
    {
        Some((_, items)) => items.extend_from_slice(entries),
        None => groups.push((name.to_owned(), entries.to_vec())),
    };
    if let Some(events) = hooks.get("events").and_then(PyVal::as_dict) {
        for (name, entries) in events {
            if let Some(entries) = entries.as_list() {
                extend(name, entries);
            }
        }
    }
    for (name, entries) in hooks.as_dict().unwrap_or_default() {
        if name == "events" || !HOOK_EVENT_NAMES.contains(&name.as_str()) {
            continue;
        }
        if let Some(entries) = entries.as_list() {
            extend(name, entries);
        }
    }
    for (_, entries) in &mut groups {
        let mut seen = std::collections::HashSet::new();
        entries.retain(|entry| seen.insert(entry.canonical_key()));
    }
    groups
}

/// Direct event arrays of a plugin hooks file, with no layout handling.
pub(crate) fn raw_hook_groups(hooks: &PyVal) -> Vec<(String, Vec<PyVal>)> {
    hooks
        .as_dict()
        .unwrap_or_default()
        .iter()
        .filter_map(|(name, entries)| {
            entries
                .as_list()
                .map(|items| (name.clone(), items.to_vec()))
        })
        .collect()
}

fn hook_name(event: &str, matcher: Option<&PyVal>) -> String {
    match matcher.and_then(PyVal::as_str) {
        Some(text) if !text.is_empty() => format!("{event}:{text}"),
        _ => event.to_owned(),
    }
}

fn non_blank_command(entry: &PyVal) -> Option<&str> {
    entry
        .get("command")
        .and_then(PyVal::as_str)
        .filter(|text| !python_strip(text).is_empty())
}

/// `_append_hook_groups`.
pub(crate) fn hook_artifacts(
    scope: &Scope<'_>,
    groups: &[(String, Vec<PyVal>)],
    config_path: &Path,
) -> Result<Vec<Value>, &'static str> {
    let mut artifacts = Vec::new();
    for (event, entries) in groups {
        let lowered = python_lower(event);
        for (index, entry) in entries.iter().enumerate() {
            if entry.as_dict().is_none() {
                continue;
            }
            let matcher = entry.get("matcher");
            let mut collected: Vec<(String, &str)> = Vec::new();
            if let Some(command) = non_blank_command(entry) {
                collected.push((format!("{lowered}:{index}"), command));
            }
            for (nested, hook) in entry
                .get("hooks")
                .and_then(PyVal::as_list)
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                if let Some(command) = non_blank_command(hook).filter(|_| hook.as_dict().is_some())
                {
                    collected.push((format!("{lowered}:{index}:{nested}"), command));
                }
            }
            for (suffix, command) in collected {
                let mut metadata = Map::new();
                metadata.insert("event".to_owned(), json!(event));
                let matcher_json = match matcher {
                    Some(value) => value.to_json().ok_or(ERR_UNREPRESENTABLE)?,
                    None => Value::Null,
                };
                metadata.insert("matcher".to_owned(), matcher_json);
                metadata.insert("managed".to_owned(), json!(is_managed(command)));
                artifacts.push(scope.wire(
                    format!("{}:{}:hook:{suffix}", scope.harness, scope.scope),
                    &hook_name(event, matcher),
                    "hook",
                    config_path,
                    Fields {
                        command: Some(command),
                        ..Fields::default()
                    },
                    metadata,
                ));
            }
        }
    }
    Ok(artifacts)
}

/// `append_cli_config_artifacts`.
pub(crate) fn cli_config_artifacts(
    scope: &Scope<'_>,
    payload: &PyVal,
    config_path: &Path,
) -> Result<Vec<Value>, &'static str> {
    let mut artifacts = Vec::new();
    let servers = payload
        .get("mcp")
        .and_then(|section| section.get("servers"))
        .and_then(PyVal::as_dict);
    for (name, config) in servers.unwrap_or_default() {
        if config.as_dict().is_none() {
            continue;
        }
        artifacts.extend(mcp_server(scope, name, config, config_path, None)?);
    }
    let enabled = payload
        .get("plugins")
        .and_then(|section| section.get("enabledPlugins"))
        .and_then(PyVal::as_dict);
    for (handle, state) in enabled.unwrap_or_default() {
        let mut metadata = Map::new();
        metadata.insert("enabled".to_owned(), json!(state.truthy()));
        artifacts.push(scope.wire(
            format!("{}:{}:plugin:{handle}", scope.harness, scope.scope),
            handle,
            "plugin",
            config_path,
            Fields::default(),
            metadata,
        ));
    }
    if let Some(hooks) = payload
        .get("hooks")
        .filter(|hooks| hooks.as_dict().is_some())
    {
        artifacts.extend(hook_artifacts(
            scope,
            &hook_event_groups(hooks),
            config_path,
        )?);
    }
    Ok(artifacts)
}

pub(crate) fn plugin_artifact(
    scope: &Scope<'_>,
    artifact_id: String,
    name: &str,
    config_path: &Path,
    publisher: Option<&str>,
    metadata: Map<String, Value>,
) -> Value {
    scope.wire(
        artifact_id,
        name,
        "plugin",
        config_path,
        Fields {
            publisher,
            ..Fields::default()
        },
        metadata,
    )
}

pub(crate) fn skill_artifact(scope: &Scope<'_>, relative: &str, path: &Path) -> Value {
    scope.wire(
        format!("{}:{}:skill:{relative}", scope.harness, scope.scope),
        relative,
        "skill",
        path,
        Fields::default(),
        Map::new(),
    )
}

pub(crate) fn command_artifact(scope: &Scope<'_>, stem: &str, path: &Path) -> Value {
    scope.wire(
        format!("{}:{}:command:{stem}", scope.harness, scope.scope),
        stem,
        "command",
        path,
        Fields::default(),
        Map::new(),
    )
}

pub(crate) fn marketplace_artifact(
    scope: &Scope<'_>,
    name: &str,
    path: &Path,
    entries: usize,
) -> Value {
    let mut metadata = Map::new();
    metadata.insert("entries".to_owned(), json!(entries));
    scope.wire(
        format!("{}:{}:marketplace:{name}", scope.harness, scope.scope),
        name,
        "marketplace",
        path,
        Fields::default(),
        metadata,
    )
}
