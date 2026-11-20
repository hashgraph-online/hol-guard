//! `runner_authority` kind `cline_detect`: the file-reading half of
//! `ClineHarnessAdapter.detect`. It lists the VS Code and JetBrains host
//! installs under the home, the MCP servers of every settings file Python
//! names in `mcp_settings`, and the hook and plugin directories that exist.
//! Python keeps the settings path resolution (`CLINE_MCP_SETTINGS_PATH`,
//! `CLINE_DATA_DIR`), the CLI lookup and version probe, the managed
//! transport state and the MCP firewall. Each MCP artifact carries the
//! unredacted `args` and `env` Python's managed-proxy install reads, under
//! `runtime_private_metadata`. Every refusal is a stable code and never a
//! partial inventory.

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use guard_command::artifact_hash::redact_arg;
use guard_command::redacted_command_tokens::redact_text;
use serde_json::{json, Map, Value};

use super::adapter_inventory::{
    json_document, json_payload, Inventory, Request, ERR_NAME, ERR_STAT,
};
use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_paths::py_path;
use super::claude_guard_question::python_lower;
use super::codex_detect::is_guard_proxy;
use super::context_digest::python_strip;
use super::pyjson::PyVal;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{string_pairs, Fields, Scope};

const HARNESS: &str = "cline";
const EXTENSION_PREFIX: &str = "saoudrizwan.claude-dev-";
const JETBRAINS_WARNING: &str = "Cline JetBrains was detected, but Guard does not mark that IDE protected until a live pre-tool deny proof is observed.";

/// `Path.is_dir` where a directory the process may not search counts as
/// absent: `Path.glob` swallows the `PermissionError`.
fn is_searchable_dir(inventory: &Inventory, path: &Path) -> Result<bool, &'static str> {
    match fs::metadata(inventory.fs(path)) {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => Ok(false),
        _ => inventory.is_dir(path),
    }
}

/// The entry names of `dir`. `Path.glob` yields them in the order the
/// filesystem returns them; sorting is the one deterministic order. A
/// directory the process may not read lists nothing, as `glob` swallows that
/// `PermissionError`.
fn child_names(inventory: &Inventory, dir: &Path) -> Result<Vec<OsString>, &'static str> {
    let entries = match fs::read_dir(inventory.fs(dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return Ok(Vec::new()),
        Err(_) => return Err(ERR_STAT),
    };
    let mut names = entries
        .map(|entry| entry.map(|entry| entry.file_name()).map_err(|_| ERR_STAT))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

/// `_package_version`: the stripped `version` of a `package.json`.
fn package_version(inventory: &Inventory, path: &Path) -> Result<Option<String>, &'static str> {
    let document = json_document(&inventory.fs(path))?;
    Ok(document
        .as_ref()
        .and_then(|payload| payload.get("version"))
        .and_then(PyVal::as_str)
        .map(python_strip)
        .filter(|version| !version.is_empty())
        .map(str::to_owned))
}

/// `_vscode_extension_versions`: each installed Cline extension's version,
/// once, in the order the extension roots and directory names give.
fn vscode_versions(inventory: &Inventory, home: &Path) -> Result<Vec<String>, &'static str> {
    let mut versions: Vec<String> = Vec::new();
    for editor in [".vscode", ".vscode-insiders", ".cursor"] {
        let root = home.join(editor).join("extensions");
        if !inventory.is_dir(&root)? {
            continue;
        }
        for name in child_names(inventory, &root)? {
            if !name
                .as_encoded_bytes()
                .starts_with(EXTENSION_PREFIX.as_bytes())
            {
                continue;
            }
            let name = name.to_str().ok_or(ERR_NAME)?;
            let manifest = root.join(name).join("package.json");
            if let Some(version) = package_version(inventory, &manifest)? {
                if !versions.contains(&version) {
                    versions.push(version);
                }
            }
        }
    }
    Ok(versions)
}

/// `_jetbrains_paths`: the `*/plugins/*` entries of each JetBrains config
/// root whose name mentions Cline.
fn jetbrains_paths(inventory: &Inventory, home: &Path) -> Result<Vec<PathBuf>, &'static str> {
    let roots = [
        home.join(".local").join("share").join("JetBrains"),
        home.join("Library")
            .join("Application Support")
            .join("JetBrains"),
        home.join(".config").join("JetBrains"),
    ];
    let mut found = Vec::new();
    for root in &roots {
        if !inventory.is_dir(root)? {
            continue;
        }
        for ide in child_names(inventory, root)? {
            let ide_dir = root.join(&ide);
            let plugins = ide_dir.join("plugins");
            if !is_searchable_dir(inventory, &ide_dir)? || !is_searchable_dir(inventory, &plugins)?
            {
                continue;
            }
            for plugin in child_names(inventory, &plugins)? {
                if !plugin.to_string_lossy().to_lowercase().contains("cline") {
                    continue;
                }
                let path = plugins.join(&plugin);
                if inventory.exists(&path)? {
                    if ide.to_str().is_none() || plugin.to_str().is_none() {
                        return Err(ERR_NAME);
                    }
                    found.push(path);
                }
            }
        }
    }
    Ok(found)
}

/// The host artifacts `_host_artifacts` built for the VS Code and JetBrains
/// installs; Python adds the CLI one.
fn host_artifacts(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    home: &Path,
) -> Result<(), &'static str> {
    let extensions = home.join(".vscode").join("extensions");
    for version in vscode_versions(inventory, home)? {
        let mut metadata = Map::new();
        metadata.insert("version".to_owned(), json!(version));
        metadata.insert("surface".to_owned(), json!("vscode"));
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:host:vscode:{version}"),
            "Cline VS Code",
            "harness_host",
            &extensions,
            Fields::default(),
            metadata,
        ));
    }
    let jetbrains = jetbrains_paths(inventory, home)?;
    for (index, path) in jetbrains.iter().enumerate() {
        let mut metadata = Map::new();
        metadata.insert("surface".to_owned(), json!("jetbrains"));
        metadata.insert("protection_status".to_owned(), json!("unverified"));
        inventory.artifacts.push(scope.wire(
            format!("{HARNESS}:host:jetbrains:{index}"),
            "Cline JetBrains",
            "harness_host",
            path,
            Fields::default(),
            metadata,
        ));
    }
    if !jetbrains.is_empty() {
        inventory.warn(JETBRAINS_WARNING.to_owned());
    }
    Ok(())
}

/// `raw.get(first) or raw.get(second)`: the second value is returned as is
/// when the first is missing or falsy.
fn first_truthy<'a>(raw: &'a PyVal, first: &str, second: &str) -> Option<&'a PyVal> {
    raw.get(first)
        .filter(|value| value.truthy())
        .or_else(|| raw.get(second))
}

/// `_transport`, which `cline_install_plan` shares for the MCP proxy install.
pub(crate) fn transport(raw: &PyVal) -> String {
    if let Some(kind) = first_truthy(raw, "type", "transport").and_then(PyVal::as_str) {
        let kind = python_strip(kind);
        if !kind.is_empty() {
            return python_lower(kind);
        }
    }
    let remote = first_truthy(raw, "url", "endpoint")
        .and_then(PyVal::as_str)
        .is_some_and(|url| !python_strip(url).is_empty());
    (if remote { "http" } else { "stdio" }).to_owned()
}

/// One entry of the `mcpServers` (or `mcp`) object of a settings file.
fn mcp_server(
    scope: &Scope<'_>,
    path: &Path,
    name: &str,
    raw: &PyVal,
) -> Result<Value, &'static str> {
    let command = raw.get("command").and_then(PyVal::as_str);
    let raw_args: Vec<String> = raw
        .get("args")
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(PyVal::as_str)
        .map(str::to_owned)
        .collect();
    let args: Vec<String> = raw_args
        .iter()
        .map(|item| redact_arg(&redact_text(item).text))
        .collect();
    let url = first_truthy(raw, "url", "endpoint").and_then(PyVal::as_str);
    let transport = transport(raw);
    let environment = raw
        .get("env")
        .or_else(|| raw.get("environment"))
        .map(string_pairs)
        .unwrap_or_default();
    let mut headers_keys: Vec<String> = raw
        .get("headers")
        .and_then(PyVal::as_dict)
        .unwrap_or_default()
        .iter()
        .filter(|(_, value)| value.as_str().is_some())
        .map(|(key, _)| key.clone())
        .collect();
    headers_keys.sort();
    let env_keys: Vec<String> = environment.keys().cloned().collect();
    let enriched = enrich(&McpMetadataInput {
        command: command.map(str::to_owned),
        args: args.clone(),
        url: url.map(str::to_owned),
        transport: Some(transport.clone()),
        env_keys: env_keys.clone(),
        headers_keys: headers_keys.clone(),
        env: Value::Null,
        headers: Value::Array(
            headers_keys
                .iter()
                .map(|key| json!([key, "[configured]"]))
                .collect(),
        ),
        env_values_hash: None,
        header_values_hash: None,
        label: name.to_owned(),
    })?;
    let mut metadata = Map::new();
    metadata.insert("name".to_owned(), json!(name));
    metadata.insert("env_keys".to_owned(), json!(env_keys));
    metadata.insert("headers_keys".to_owned(), json!(headers_keys));
    metadata.insert(
        "enabled".to_owned(),
        json!(!matches!(raw.get("disabled"), Some(PyVal::Bool(true)))),
    );
    metadata.insert(
        "guard_managed_proxy".to_owned(),
        json!(is_guard_proxy(command, &raw_args)),
    );
    for (key, value) in enriched.as_object().ok_or(ERR_METADATA)? {
        metadata.insert(key.clone(), value.clone());
    }
    let mut artifact = scope.wire(
        format!("{HARNESS}:{}:{name}", scope.scope),
        name,
        "mcp_server",
        path,
        Fields {
            command,
            args,
            url,
            transport: Some(transport.as_str()),
            publisher: None,
        },
        metadata,
    );
    artifact["runtime_private_metadata"] = json!({"mcp_args": raw_args, "mcp_env": environment});
    Ok(artifact)
}

/// `_servers_object`: the first of `mcpServers` and `mcp` that is an object,
/// even an empty one.
fn servers(payload: &PyVal) -> &[(String, PyVal)] {
    ["mcpServers", "mcp"]
        .into_iter()
        .find_map(|key| payload.get(key).and_then(PyVal::as_dict))
        .unwrap_or_default()
}

/// `detect_cline_mcp`: the servers of each settings file that holds a
/// non-empty object.
fn mcp_servers(
    inventory: &mut Inventory,
    scope: &Scope<'_>,
    settings: &[PathBuf],
) -> Result<(), &'static str> {
    for path in settings {
        if !inventory.is_file(path)? {
            continue;
        }
        let payload = json_payload(&inventory.fs(path))?;
        if !payload.truthy() {
            continue;
        }
        inventory.found(path);
        for (name, raw) in servers(&payload) {
            if raw.as_dict().is_some() {
                let artifact = mcp_server(scope, path, name, raw)?;
                inventory.artifacts.push(artifact);
            }
        }
    }
    Ok(())
}

/// The settings paths Python resolved, each a string without NUL.
fn settings_paths(inventory: &Inventory, args: &Value) -> Result<Vec<PathBuf>, &'static str> {
    args_object(args)?
        .get("mcp_settings")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| {
            let path = item
                .as_str()
                .filter(|path| !path.contains('\0'))
                .map(py_path)
                .ok_or(ERR_INVALID)?;
            if !path.is_absolute() && !inventory.has_cwd() {
                return Err(ERR_INVALID);
            }
            Ok(path)
        })
        .collect()
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let mut inventory = Inventory::new(&request);
    let settings = settings_paths(&inventory, args)?;
    let scope = Scope {
        harness: HARNESS,
        scope: "global",
    };
    host_artifacts(&mut inventory, &scope, &request.home)?;
    mcp_servers(&mut inventory, &scope, &settings)?;
    for dir in [
        request.home.join(".cline").join("hooks"),
        request.home.join(".cline").join("plugins"),
        request.home.join("Documents").join("Cline").join("Hooks"),
        request.home.join("Documents").join("Cline").join("Plugins"),
    ] {
        if inventory.exists(&dir)? {
            inventory.found(&dir);
        }
    }
    inventory.finish()
}
