//! `mcp_tool_call_evaluation.py` + `runtime/mcp_protection.py` — decision
//! composition and verdict evaluation for MCP tool calls.
//!
//! `mcp_protection` ports as concrete code: stable server/tool identity
//! primitives with secret-safe configured-env binding, package-launcher
//! resolution, package-source tokens, and URL userinfo redaction.
//!
//! `mcp_tool_call_evaluation` keeps the same orchestration as Python but
//! depends on two seams — `McpToolStore` (`.store.GuardStore`) and
//! `McpToolCallsApi` (`.mcp_tool_calls`) — since neither is ported here.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::action_lattice::most_restrictive_guard_action;
use crate::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CLAIM_FAILED,
};
use crate::effect_decision::GuardAction;
use crate::local_supply_chain::GuardConfig;
use crate::package_intent_common::GuardArtifact;

// ===========================================================================
// runtime/mcp_protection.py — MCP identity primitives
// ===========================================================================

/// `McpServerIdentity` (:15-27) — stable identity for a local MCP server
/// definition.
#[derive(Debug, Clone)]
pub struct McpServerIdentity {
    pub config_path: String,
    pub command: String,
    pub args_hash: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub package_source: String,
    pub transport: String,
    pub env_keys: Vec<String>,
    pub env_values_hash: String,
    pub identity_hash: String,
}

/// `McpToolIdentity` (:30-38) — stable identity for a tool exposed by an MCP
/// server.
#[derive(Debug, Clone)]
pub struct McpToolIdentity {
    pub server_hash: String,
    pub tool_name: String,
    pub schema_hash: String,
    pub description_hash: String,
    pub identity_hash: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// `_canonical_material_bytes` (native_context.py :383-388) → canonical JSON
/// UTF-8 bytes (sorted keys, compact separators, ensure_ascii).
fn canonical_material_bytes(material: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    if guard_contracts::write_canonical_json(material, &mut out).is_err() {
        return Vec::new();
    }
    out
}

/// Native canonical JSON SHA-256 used by MCP identity construction.
fn context_sha256_digest_local(material: &Value, prefix: Option<&str>) -> String {
    let bytes = canonical_material_bytes(material);
    format!("{}{}", prefix.unwrap_or(""), sha256_hex(&bytes))
}

/// CPython `str.strip()` whitespace set: the ASCII controls 0x09-0x0d and
/// 0x1c-0x1f plus every Unicode code point whose `isspace` is true.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// `str.partition` → `(before, found, after)`.
fn py_partition<'a>(value: &'a str, sep: &str) -> (&'a str, bool, &'a str) {
    match value.split_once(sep) {
        Some((before, after)) => (before, true, after),
        None => (value, false, ""),
    }
}

/// `str.rpartition` → `(before, found, after)`.
fn py_rpartition<'a>(value: &'a str, sep: &str) -> (&'a str, bool, &'a str) {
    match value.rsplit_once(sep) {
        Some((before, after)) => (before, true, after),
        None => ("", false, value),
    }
}

/// `_PACKAGE_LAUNCHERS` (:40).
const PACKAGE_LAUNCHERS: &[&str] = &["bunx", "npm", "npx", "pnpm", "uvx", "yarn", "pipx"];

/// `build_mcp_server_identity` (:41-87) — stable server identity with
/// secret-safe configured env binding.
pub fn build_mcp_server_identity(
    config_path: &str,
    command: &str,
    args: &[String],
    transport: &str,
    env: Option<&Map<String, Value>>,
    env_keys: &[String],
) -> McpServerIdentity {
    let (package_name, package_version) = package_identity(command, args);
    let package_source = package_source_token(command, args);
    let transport = python_strip(transport).to_lowercase();
    let mut env_key_set: std::collections::BTreeSet<String> = env_keys
        .iter()
        .map(|key| python_strip(key).to_owned())
        .filter(|key| !key.is_empty())
        .collect();
    if let Some(env_map) = env {
        env_key_set.extend(
            env_map
                .keys()
                .map(|key| python_strip(key).to_owned())
                .filter(|key| !key.is_empty()),
        );
    }
    let env_keys: Vec<String> = env_key_set.iter().cloned().collect();
    let env_values_hash = build_configured_environment_hash(env, Some(&env_keys));
    let args_material = Value::Array(args.iter().cloned().map(Value::String).collect());
    let args_hash = stable_digest(&args_material);
    let payload = json!({
        // The display-oriented command name is intentionally lossy (for a URL
        // it is only the final path segment). The complete configured command
        // is bound separately via `command_hash` so host, scheme, path, and
        // executable-path drift cannot inherit a saved server/tool approval.
        "command": command_name(command),
        "command_hash": stable_digest(&Value::String(command.to_owned())),
        "args_hash": args_hash,
        "package_name": package_name,
        "package_version": package_version,
        "transport": transport,
        "env_keys": env_keys,
        "env_values_hash": env_values_hash,
    });
    let identity_hash = stable_digest(&payload);
    McpServerIdentity {
        config_path: config_path.to_owned(),
        command: command.to_owned(),
        args_hash,
        package_name,
        package_version,
        package_source,
        transport,
        env_keys,
        env_values_hash,
        identity_hash,
    }
}

/// `build_mcp_tool_identity` (:88-113) — stable identity for one MCP tool
/// definition.
pub fn build_mcp_tool_identity(
    server_hash: &str,
    tool_name: &str,
    schema: Option<&Value>,
    description: Option<&str>,
) -> McpToolIdentity {
    let schema_hash = stable_digest(schema.unwrap_or(&Value::Null));
    let description_hash = stable_digest(&Value::String(
        python_strip(description.unwrap_or("")).to_owned(),
    ));
    let payload = json!({
        "server_hash": server_hash,
        "tool_name": tool_name,
        "schema_hash": schema_hash,
        "description_hash": description_hash,
    });
    let identity_hash = stable_digest(&payload);
    McpToolIdentity {
        server_hash: server_hash.to_owned(),
        tool_name: tool_name.to_owned(),
        schema_hash,
        description_hash,
        identity_hash,
    }
}

/// `_non_secret_mcp_server_command` (:114-121) — serialization-safe MCP
/// command without URL credentials.
fn non_secret_mcp_server_command(command: &str) -> String {
    if !command.contains("://") {
        return command.to_owned();
    }
    sanitize_package_url(command)
}

/// `mcp_server_identity_metadata` (:122-138) — serialize an MCP server
/// identity into non-secret Guard metadata.
pub fn mcp_server_identity_metadata(identity: &McpServerIdentity) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("config_path".to_owned(), json!(identity.config_path));
    out.insert(
        "command".to_owned(),
        json!(non_secret_mcp_server_command(&identity.command)),
    );
    out.insert("args_hash".to_owned(), json!(identity.args_hash));
    out.insert("package_name".to_owned(), json!(identity.package_name));
    out.insert(
        "package_version".to_owned(),
        json!(identity.package_version),
    );
    out.insert("package_source".to_owned(), json!(identity.package_source));
    out.insert("transport".to_owned(), json!(identity.transport));
    out.insert("env_keys".to_owned(), json!(identity.env_keys));
    out.insert(
        "env_values_hash".to_owned(),
        json!(identity.env_values_hash),
    );
    out.insert("identity_hash".to_owned(), json!(identity.identity_hash));
    out
}

/// `mcp_tool_identity_metadata` (:139-153) — serialize an MCP tool identity
/// into Guard metadata.
pub fn mcp_tool_identity_metadata(identity: &McpToolIdentity) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("server_hash".to_owned(), json!(identity.server_hash));
    out.insert("tool_name".to_owned(), json!(identity.tool_name));
    out.insert("schema_hash".to_owned(), json!(identity.schema_hash));
    out.insert(
        "description_hash".to_owned(),
        json!(identity.description_hash),
    );
    out.insert("identity_hash".to_owned(), json!(identity.identity_hash));
    out
}

pub fn portal_mcp_server_descriptor(
    request: &guard_contracts::McpServerDescriptorRequestV1,
) -> Map<String, Value> {
    let identity = &request.identity;
    let publisher_source = request
        .publisher
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            request
                .install_source
                .as_deref()
                .filter(|value| !value.is_empty())
        })
        .or(identity.package_name.as_deref());
    let publisher = publisher_source
        .map(|value| python_strip(value).to_lowercase())
        .filter(|value| !value.is_empty())
        .map(|value| format!("publisher:{}", stable_digest(&json!(value))));
    let dependency = identity
        .package_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|name| {
            stable_digest(&json!({
                "ecosystem": null,
                "packageName": python_strip(name),
                "version": identity.package_version.as_deref().map(python_strip)
                    .filter(|value| !value.is_empty()),
            }))
        });
    let transport = python_strip(&identity.transport).to_lowercase();
    let transport = if transport.is_empty() {
        "unknown"
    } else {
        &transport
    };
    let mut result = Map::new();
    result.insert("argsHash".to_owned(), json!(identity.args_hash));
    result.insert("command".to_owned(), json!(identity.command));
    result.insert(
        "commandHash".to_owned(),
        json!(stable_digest(&json!({
            "args": request.args,
            "command": command_name(&identity.command),
        }))),
    );
    result.insert("configPath".to_owned(), json!(request.config_path));
    result.insert("dependencyHash".to_owned(), json!(dependency));
    result.insert("envKeys".to_owned(), json!(identity.env_keys));
    result.insert("envValuesHash".to_owned(), json!(identity.env_values_hash));
    result.insert("identityHash".to_owned(), json!(identity.identity_hash));
    result.insert("packageName".to_owned(), json!(identity.package_name));
    result.insert("packageSource".to_owned(), json!(identity.package_source));
    result.insert("packageVersion".to_owned(), json!(identity.package_version));
    result.insert("publisherStableId".to_owned(), json!(publisher));
    result.insert("transport".to_owned(), json!(identity.transport));
    result.insert(
        "transportHash".to_owned(),
        json!(stable_digest(&json!(transport))),
    );
    result
}

pub fn portal_mcp_tool_descriptor(
    request: &guard_contracts::McpToolDescriptorRequestV1,
) -> Map<String, Value> {
    let identity = &request.identity;
    let full = request.schema.is_some()
        || request
            .description
            .as_deref()
            .is_some_and(|value| !python_strip(value).is_empty());
    let mut result = Map::new();
    result.insert(
        "descriptionHash".to_owned(),
        json!((!identity.description_hash.is_empty()).then_some(&identity.description_hash)),
    );
    result.insert(
        "descriptorHash".to_owned(),
        json!((!identity.description_hash.is_empty()).then_some(&identity.description_hash)),
    );
    result.insert(
        "hashScope".to_owned(),
        json!(if full { "full" } else { "manifest" }),
    );
    result.insert("identityHash".to_owned(), json!(identity.identity_hash));
    result.insert(
        "schemaHash".to_owned(),
        json!((!identity.schema_hash.is_empty()).then_some(&identity.schema_hash)),
    );
    result.insert("serverHash".to_owned(), json!(identity.server_hash));
    result.insert("toolName".to_owned(), json!(identity.tool_name));
    result
}

fn persisted_mcp_digest(material: &Value) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    guard_contracts::write_python_default_json(material, &mut bytes)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

pub fn mcp_tool_content_digest(
    request: &guard_contracts::McpToolContentDigestRequestV1,
) -> Result<String, &'static str> {
    persisted_mcp_digest(&json!({
        "arguments": request.arguments,
        "artifact_id": request.artifact_id,
        "config_path": request.config_path,
    }))
}

pub fn mcp_tool_approval_digest(
    request: &guard_contracts::McpToolApprovalDigestRequestV1,
) -> Result<String, &'static str> {
    let mut material = Map::new();
    material.insert("arguments".to_owned(), json!(request.content.arguments));
    material.insert("artifact_id".to_owned(), json!(request.content.artifact_id));
    material.insert("config_path".to_owned(), json!(request.content.config_path));
    material.insert(
        "server_fingerprint".to_owned(),
        json!(request.server_fingerprint),
    );
    material.insert("server_identity".to_owned(), json!(request.server_identity));
    material.insert("tool_identity".to_owned(), json!(request.tool_identity));
    material.insert("transport".to_owned(), json!(request.transport));
    if let Some(value) = &request.authority_hash {
        if !value.is_null() {
            material.insert("tool_authority_hash".to_owned(), value.clone());
        }
    }
    if let Some(value) = &request.provider_hash {
        if !value.is_null() {
            material.insert("provider_catalog_hash".to_owned(), value.clone());
        }
    }
    if let Some(workspace) = &request.workspace {
        material.insert("workspace".to_owned(), json!(workspace));
    }
    persisted_mcp_digest(&Value::Object(material))
}

/// `package_launcher_name` (:154-160) — canonical package-launcher basename,
/// if this command is one.
pub fn package_launcher_name(command: &str) -> Option<String> {
    let name = command_name(command);
    if PACKAGE_LAUNCHERS.contains(&name.as_str()) {
        Some(name)
    } else {
        None
    }
}

/// `resolved_package_launcher_executable` (:161-185) — resolve a package
/// launcher to a real executable, or `None` if unknown.
pub fn resolved_package_launcher_executable(command: &str) -> Option<PathBuf> {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolved_package_launcher_executable_in(command, &path_value, home.as_deref())
}

/// Same resolution against a caller-supplied `PATH` and home directory, for a
/// resident that must resolve launchers as the calling process would.
pub fn resolved_package_launcher_executable_in(
    command: &str,
    path_value: &str,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let launcher = package_launcher_name(command)?;
    let candidate = expand_user_in(command, home);
    let resolved = if candidate.is_absolute() {
        std::fs::canonicalize(&candidate).ok()?
    } else {
        let found = which_package_launcher(command, path_value, home)
            .or_else(|| which_package_launcher(&launcher, path_value, home))?;
        std::fs::canonicalize(Path::new(&found)).ok()?
    };
    if !resolved.is_file() {
        return None;
    }
    Some(resolved)
}

/// `_which_package_launcher` (:186-195) — resolve a launcher on PATH,
/// skipping Guard package shims.
fn which_package_launcher(launcher: &str, path_value: &str, home: Option<&Path>) -> Option<String> {
    // Platform separator (`;` on Windows, `:` elsewhere), like `os.pathsep`.
    let parts: Vec<PathBuf> = std::env::split_paths(path_value)
        .filter(|part| !part.as_os_str().is_empty() && !is_guard_package_shim_dir(part, home))
        .collect();
    if parts.is_empty() {
        return None;
    }
    which_in(launcher, &parts)
}

/// `shutil.which` over explicit PATH entries: first executable file wins.
fn which_in(launcher: &str, parts: &[PathBuf]) -> Option<String> {
    let names = launcher_file_names(launcher);
    for dir in parts {
        for name in &names {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// File names tried per directory. Windows applies `PATHEXT` the way
/// `shutil.which` does: a name already carrying a listed extension is tried
/// as-is, otherwise each extension is appended.
fn launcher_file_names(launcher: &str) -> Vec<String> {
    if !cfg!(windows) {
        return vec![launcher.to_owned()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_default();
    let pathext = if pathext.is_empty() {
        ".COM;.EXE;.BAT;.CMD".to_owned()
    } else {
        pathext
    };
    windows_launcher_file_names(launcher, &pathext)
}

fn windows_launcher_file_names(launcher: &str, pathext: &str) -> Vec<String> {
    let extensions: Vec<&str> = pathext.split(';').filter(|ext| !ext.is_empty()).collect();
    let lowered = launcher.to_lowercase();
    if extensions
        .iter()
        .any(|ext| lowered.ends_with(&ext.to_lowercase()))
    {
        return vec![launcher.to_owned()];
    }
    extensions
        .iter()
        .map(|ext| format!("{launcher}{ext}"))
        .collect()
}

fn is_executable_file(candidate: &Path) -> bool {
    if !candidate.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        candidate
            .metadata()
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `_is_guard_package_shim_dir` (:196-208).
fn is_guard_package_shim_dir(part: &Path, home: Option<&Path>) -> bool {
    let expanded = expand_user_in(&part.to_string_lossy(), home);
    // `Path.as_posix()`: Windows separators compare as `/`.
    let mut posix = expanded.to_string_lossy().into_owned();
    if cfg!(windows) {
        posix = posix.replace('\\', "/");
    }
    while posix.ends_with('/') {
        posix.pop();
    }
    posix.ends_with("/package-shims/bin") || posix.contains("/.hol-guard/package-shims/")
}

/// `Path.expanduser` — only `~`/`~user` at the head expand.
fn expand_user_in(value: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = value.strip_prefix('~') {
        let separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
        if rest.is_empty() || rest.starts_with(separator) {
            if let Some(home) = home {
                return home.join(rest.trim_start_matches(separator));
            }
        }
    }
    PathBuf::from(value)
}

/// Canonical package-source token, including launcher configuration indirection.
pub fn package_source_token(command: &str, args: &[String]) -> String {
    crate::mcp_package_sources::package_source_token(command, args)
}

/// `_package_identity` (:234-243) — `(name, version)` for launcher-backed
/// commands, else `(None, None)`.
fn package_identity(command: &str, args: &[String]) -> (Option<String>, Option<String>) {
    let Some(name) = package_launcher_name(command) else {
        return (None, None);
    };
    let Some(token) = package_token(&name, args) else {
        return (None, None);
    };
    split_package_token(&token)
}

/// `_package_token` (:244-296).
pub fn package_token(command_name: &str, args: &[String]) -> Option<String> {
    let mut index = 0usize;
    let mut positional_index = 0usize;
    let package_selector_flags = package_selector_flags(command_name);
    let mut selected_package: Option<String> = None;
    while index < args.len() {
        let value = python_strip(&args[index]).to_owned();
        if value.is_empty() {
            index += 1;
            continue;
        }
        if positional_index == 0
            && launcher_non_package_subcommands(command_name).contains(value.as_str())
        {
            return None;
        }
        if positional_index == 0 && launcher_subcommands(command_name).contains(value.as_str()) {
            index += 1;
            positional_index += 1;
            continue;
        }
        if package_selector_flags.contains(value.as_str()) && index + 1 < args.len() {
            let candidate = python_strip(&args[index + 1]).to_owned();
            if !candidate.is_empty() {
                selected_package = Some(candidate);
            }
            index += 2;
            continue;
        }
        if package_selector_flags.contains("--package") && value.starts_with("--package=") {
            let (_, _, after) = py_partition(&value, "=");
            let package = python_strip(after).to_owned();
            if !package.is_empty() {
                selected_package = Some(package);
            }
            index += 1;
            continue;
        }
        if (value == "--spec" || value == "--from") && index + 1 < args.len() {
            let package = python_strip(&args[index + 1]).to_owned();
            if !package.is_empty() {
                selected_package = Some(package);
            }
            index += 2;
            continue;
        }
        if value.starts_with("--spec=") || value.starts_with("--from=") {
            let (_, _, after) = py_partition(&value, "=");
            let package = python_strip(after).to_owned();
            if !package.is_empty() {
                selected_package = Some(package);
            }
            index += 1;
            continue;
        }
        if option_takes_value(command_name, &value) {
            index += 2;
            continue;
        }
        if value.starts_with('-') {
            index += 1;
            continue;
        }
        if looks_like_runtime_path(&value) {
            index += 1;
            positional_index += 1;
            continue;
        }
        if selected_package.is_some() {
            index += 1;
            positional_index += 1;
            continue;
        }
        return Some(value);
    }
    selected_package
}

/// `_split_package_token` (:297-316) — `(name, version)` out of a package
/// specifier.
fn split_package_token(value: &str) -> (Option<String>, Option<String>) {
    let (pip_style_name, pip_style_version) = split_pip_style_specifier(value);
    if pip_style_name.is_some() {
        return (pip_style_name, pip_style_version);
    }
    if value.starts_with('@') {
        let (scope, slash, remainder) = py_partition(value, "/");
        if !slash || remainder.is_empty() {
            return (Some(value.to_owned()), None);
        }
        let (name, at_sign, version) = py_rpartition(remainder, "@");
        if !at_sign || name.is_empty() {
            return (Some(value.to_owned()), None);
        }
        let version = if version.is_empty() {
            None
        } else {
            Some(version.to_owned())
        };
        return (Some(format!("{scope}/{name}")), version);
    }
    if value.contains("://") {
        return (Some(sanitize_package_url(value)), None);
    }
    let (name, at_sign, version) = py_rpartition(value, "@");
    if !at_sign || name.is_empty() {
        return (Some(value.to_owned()), None);
    }
    let version = if version.is_empty() {
        None
    } else {
        Some(version.to_owned())
    };
    (Some(name.to_owned()), version)
}

/// `_command_name` (:317-323) — final path segment, lowercased, script
/// suffixes stripped.
fn command_name(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    // `PurePath.name` ignores a trailing separator.
    let basename = normalized
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if basename.ends_with(".cmd")
        || basename.ends_with(".exe")
        || basename.ends_with(".bat")
        || basename.ends_with(".ps1")
    {
        // `PurePath.stem` removes the final suffix only.
        return basename
            .rsplit_once('.')
            .map(|(stem, _)| stem.to_owned())
            .unwrap_or(basename);
    }
    basename
}

/// `_split_pip_style_specifier` (:324-340) — `(name, version)` for
/// `name==ver`-style specifiers.
fn split_pip_style_specifier(value: &str) -> (Option<String>, Option<String>) {
    if value.contains("://") {
        return (None, None);
    }
    for separator in ["===", "==", "~=", "!=", "<=", ">=", "<", ">", "="] {
        let (name, matched, version) = py_partition(value, separator);
        if !matched {
            continue;
        }
        let normalized_name = python_strip(name);
        let normalized_version = python_strip(version);
        if normalized_name.is_empty() || normalized_version.is_empty() {
            continue;
        }
        if separator == "=" || separator == "==" || separator == "===" {
            return (
                Some(normalized_name.to_owned()),
                Some(normalized_version.to_owned()),
            );
        }
        return (
            Some(normalized_name.to_owned()),
            Some(format!("{separator}{normalized_version}")),
        );
    }
    (None, None)
}

/// `_url_authority_contains_userinfo` (:341-349).
fn url_authority_contains_userinfo(value: &str) -> bool {
    let Some((authority_start, authority_end)) = url_authority_bounds(value) else {
        return false;
    };
    value[authority_start..authority_end].contains('@')
}

/// `_sanitize_package_url` (:350-357) — strip fragment/query and redact
/// userinfo credentials.
fn sanitize_package_url(value: &str) -> String {
    let without_fragment = value.split('#').next().unwrap_or("");
    let without_query = without_fragment.split('?').next().unwrap_or("");
    if url_authority_contains_userinfo(without_query) {
        return redact_url_userinfo(without_query);
    }
    without_query.to_owned()
}

/// `_redact_url_userinfo` (:358-370) — drop `user:pass@` from the authority.
fn redact_url_userinfo(value: &str) -> String {
    let Some((authority_start, authority_end)) = url_authority_bounds(value) else {
        return value.to_owned();
    };
    let authority = &value[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return value.to_owned();
    };
    let redacted_authority = &authority[at_index + 1..];
    format!(
        "{}{}{}",
        &value[..authority_start],
        redacted_authority,
        &value[authority_end..]
    )
}

/// `_url_authority_bounds` (:371-383) — `(start, end)` of the `://authority`
/// span, ending before `/`, `?`, or `#`.
fn url_authority_bounds(value: &str) -> Option<(usize, usize)> {
    let scheme_index = value.find("://")?;
    let authority_start = scheme_index + 3;
    let mut authority_end = value.len();
    for delimiter in ["/", "?", "#"] {
        if let Some(delimiter_index) = value[authority_start..].find(delimiter) {
            authority_end = authority_end.min(authority_start + delimiter_index);
        }
    }
    Some((authority_start, authority_end))
}

/// `_option_takes_value` (:384-392).
fn option_takes_value(command_name: &str, option: &str) -> bool {
    let option_name = python_strip(option);
    if !option_name.starts_with('-') {
        return false;
    }
    if option_name.starts_with("--") && option_name.contains('=') {
        return false;
    }
    crate::mcp_package_sources::source_option_name(command_name, option_name).is_some()
        || value_options_for_command(command_name).contains(option_name)
}

/// `_launcher_subcommands` (:393-402) — package-launcher subcommand prefixes.
fn launcher_subcommands(command_name: &str) -> std::collections::HashSet<&'static str> {
    match command_name {
        "npm" => ["exec", "x"].into_iter().collect(),
        "pipx" => ["run"].into_iter().collect(),
        "pnpm" => ["dlx"].into_iter().collect(),
        "yarn" => ["dlx"].into_iter().collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// `_launcher_non_package_subcommands` (:403-411) — launcher subcommands that
/// are not package specifiers.
fn launcher_non_package_subcommands(command_name: &str) -> std::collections::HashSet<&'static str> {
    match command_name {
        "npm" => ["ci", "install", "run", "start", "stop", "restart", "test"]
            .into_iter()
            .collect(),
        "pnpm" => ["exec", "run"].into_iter().collect(),
        "yarn" => ["exec", "run"].into_iter().collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// `_package_selector_flags` (:412-421).
fn package_selector_flags(command_name: &str) -> std::collections::HashSet<&'static str> {
    match command_name {
        "bunx" => ["--package", "-p"].into_iter().collect(),
        "npm" => ["--package"].into_iter().collect(),
        "npx" => ["--package", "-p"].into_iter().collect(),
        "pnpm" => ["--package"].into_iter().collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// `_value_options_for_command` (:422-491) — options that consume the next
/// argv slot as a value.
fn value_options_for_command(command_name: &str) -> std::collections::HashSet<&'static str> {
    let mut options: std::collections::HashSet<&'static str> = [
        "--cache",
        "--cache-dir",
        "--call",
        "--cwd",
        "--prefix",
        "--python",
        "--registry",
        "--userconfig",
    ]
    .into_iter()
    .collect();
    let specific: &[&str] = match command_name {
        "bunx" => &["-c", "--config", "--package"],
        "npm" | "npx" => &["-c", "-w", "--workspace"],
        "pipx" => &["-i", "--index-url", "--pip-args", "--suffix", "--with"],
        "pnpm" => &["-C", "--allow-build", "--dir", "--filter", "--reporter"],
        "uvx" => &[
            "-P",
            "-b",
            "-C",
            "-c",
            "-f",
            "-i",
            "-p",
            "-w",
            "--allow-insecure-host",
            "--cache-dir",
            "--color",
            "--config-file",
            "--config-setting",
            "--config-settings-package",
            "--default-index",
            "--build-constraints",
            "--constraints",
            "--directory",
            "--env-file",
            "--extra-index-url",
            "--exclude-newer",
            "--exclude-newer-package",
            "--find-links",
            "--fork-strategy",
            "--from",
            "--index",
            "--index-url",
            "--index-strategy",
            "--keyring-provider",
            "--link-mode",
            "--no-binary-package",
            "--no-build-isolation-package",
            "--no-sources-package",
            "--overrides",
            "--prerelease",
            "--project",
            "--python-platform",
            "--refresh-package",
            "--reinstall-package",
            "--resolution",
            "--torch-backend",
            "--upgrade-package",
            "--with",
            "--with-editable",
            "--with-requirements",
        ],
        "yarn" => &["--cwd", "--use-yarnrc"],
        _ => &[],
    };
    options.extend(specific.iter().copied());
    options
}

/// `_looks_like_runtime_path` (:492-501) — script/path positional that must
/// not be treated as a package name.
fn looks_like_runtime_path(value: &str) -> bool {
    let normalized = python_strip(value).replace('\\', "/");
    if normalized.starts_with("./")
        || normalized.starts_with("../")
        || normalized.starts_with("~/")
        || normalized.starts_with('/')
    {
        return true;
    }
    // `PurePath.suffix`: final segment after the last '.', only when the dot
    // sits strictly inside the name (`0 < i < len-1`) — dotfiles have none.
    let name = normalized.rsplit('/').next().unwrap_or("");
    let suffix = match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => name[index..].to_lowercase(),
        _ => String::new(),
    };
    if !matches!(
        suffix.as_str(),
        ".cjs" | ".js" | ".json" | ".mjs" | ".py" | ".ts"
    ) {
        return false;
    }
    normalized.contains('/') && !normalized.starts_with('@')
}

/// Canonical JSON SHA-256 for native MCP identity and descriptor material.
pub(super) fn stable_digest(value: &Value) -> String {
    context_sha256_digest_local(value, None)
}

/// `build_configured_environment_hash` (runtime/approval_context.py
/// :834-850). The Python resident delegates to the `configured_environment_hash`
/// native op; in-process Rust is the worker, so this ports the worker
/// algorithm (`guard-runtime context_digest.configured_values_hash`, domain
/// `hol.guard.configured-environment:v1\0`) directly. Non-mapping `values`
/// inputs surface as the `native_context_values_invalid` TypeError boundary
/// upstream; env is statically `Option<&Map>` here, so that boundary is
/// unreachable.
pub fn build_configured_environment_hash(
    env: Option<&Map<String, Value>>,
    configured_keys: Option<&[String]>,
) -> String {
    const DOMAIN: &[u8] = b"hol.guard.configured-environment:v1\0";

    // Python `(values or {})`: falsy inputs normalize to an empty mapping.
    let mut normalized: Map<String, Value> = Map::new();
    if let Some(env_map) = env {
        for (raw_key, entry) in env_map {
            let stripped = python_strip(raw_key);
            if stripped.is_empty() {
                continue;
            }
            normalized.insert(stripped.to_owned(), entry.clone());
        }
    }
    let mut keys: Vec<String> = match configured_keys {
        None => normalized.keys().cloned().collect(),
        Some(configured) => configured
            .iter()
            .map(|key| python_strip(key).to_owned())
            .filter(|key| !key.is_empty())
            .collect(),
    };
    keys.sort();
    keys.dedup();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for key in keys {
        let key_bytes = key.as_bytes();
        hasher.update((key_bytes.len() as u64).to_be_bytes());
        hasher.update(key_bytes);
        match normalized.get(&key) {
            None => hasher.update([0x00]),
            Some(Value::String(text)) => {
                hasher.update([0x01]);
                let value_bytes = text.as_bytes();
                hasher.update((value_bytes.len() as u64).to_be_bytes());
                hasher.update(value_bytes);
            }
            // Non-str values hit the Python `.encode` AttributeError boundary;
            // env values are statically str upstream so emit the null tag
            // rather than panic.
            Some(_) => hasher.update([0x00]),
        }
    }
    hex::encode(hasher.finalize())
}

// ===========================================================================
// mcp_tool_call_evaluation.py — decision composition
// ===========================================================================

/// `ApprovalReuseClaimDisposition` = `Literal["consumed", "retained"]`
/// (mcp_tool_calls.py :62).
pub type ApprovalReuseClaimDisposition = &'static str;

/// `ToolCallDecision` mirror (mcp_tool_calls.py :143-160) — attribute access
/// in Python maps to JSON keys here.
#[derive(Debug, Clone)]
pub struct ToolCallDecision {
    pub value: Value,
}

impl ToolCallDecision {
    pub fn new(value: Value) -> Self {
        Self { value }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.value.get(key)
    }

    /// `decision.action` as the raw `Value` — lattice helpers normalize it.
    pub fn action_value(&self) -> Value {
        self.get("action").cloned().unwrap_or(Value::Null)
    }

    /// `current.action == "block"`.
    pub fn is_block(&self) -> bool {
        self.get("action").and_then(Value::as_str) == Some("block")
    }

    /// `replace(current, action=, source=, summary=)` — dataclass replace
    /// maps to key overrides on the JSON mirror.
    pub fn replaced(&self, action: GuardAction, source: &str, summary: &str) -> Self {
        let mut value = self.value.clone();
        if let Value::Object(ref mut map) = value {
            map.insert("action".to_owned(), json!(action.as_str()));
            map.insert("source".to_owned(), json!(source));
            map.insert("summary".to_owned(), json!(summary));
        }
        Self { value }
    }
}

/// `_ClaimedToolApproval` (:20-23) — claim already committed; carried out of
/// `_evaluate_tool_call` for post-claim revalidation.
#[derive(Debug, Clone)]
pub struct ClaimedToolApproval {
    pub decision: Value,
    pub disposition: Option<String>,
}

/// Result of `_evaluate_tool_call` — either a finished `ToolCallDecision` or
/// a committed claim awaiting revalidation.
#[derive(Debug, Clone)]
pub enum ToolCallEvaluation {
    Decision(ToolCallDecision),
    Claimed(ClaimedToolApproval),
}

/// `.store.GuardStore` seam — the storage surface `_evaluate_tool_call`
/// touches.
pub trait McpToolStore {
    /// `store.read_mcp_provider_authority_hash() -> str | None`
    fn read_mcp_provider_authority_hash(&self) -> Option<String>;

    /// `store.resolve_policy_decision_lookup_with_memory_pattern(...) ->
    /// {"decision": dict|None, "ignored_local_integrity": object|None}`
    #[allow(clippy::too_many_arguments)]
    fn resolve_policy_decision_lookup_with_memory_pattern(
        &self,
        harness: &str,
        artifact_id: &str,
        artifact_hash: Option<&str>,
        workspace: Option<&str>,
        publisher: Option<&str>,
        runtime_exact_match_context: Option<&str>,
        memory_command: Option<&str>,
        memory_artifact_type: Option<&str>,
        memory_artifact_name: Option<&str>,
        consume_one_shot: bool,
    ) -> Value;

    /// `store.approval_reuse_validation_reason(harness, artifact_id,
    /// artifact_hash, workspace, publisher) -> str | None`
    fn approval_reuse_validation_reason(
        &self,
        harness: &str,
        artifact_id: &str,
        artifact_hash: &str,
        workspace: Option<&str>,
        publisher: Option<&str>,
    ) -> Option<String>;

    /// `store.approval_reuse_claim_disposition(decision) -> "consumed" |
    /// "retained" | None`
    fn approval_reuse_claim_disposition(&self, decision: &Value) -> Option<String>;

    /// `store.claim_approval_reuse_decision(decision) -> bool`
    fn claim_approval_reuse_decision(&self, decision: &Value) -> bool;

    /// `store.connection_scope()` — enter/exit a storage lease. The default
    /// is a no-op lease for stores that scope internally.
    fn enter_connection_scope(&self) {}
    fn exit_connection_scope(&self) {}
}

/// `.mcp_tool_calls` seam — the evaluation helpers `_evaluate_tool_call`
/// composes. Implementations live with the mcp_tool_calls port.
pub trait McpToolCallsApi {
    /// `calls.composio_requires_action_review(command) -> bool`
    /// (runtime.composio_contract).
    fn composio_requires_action_review(&self, command: &str) -> bool;

    /// `calls._evaluate_current_tool_call(config=, artifact=, arguments=)`
    fn evaluate_current_tool_call(
        &self,
        config: &GuardConfig,
        artifact: &GuardArtifact,
        arguments: &Value,
    ) -> ToolCallDecision;

    /// `calls._apply_temporary_mcp_grant(store=, artifact=, artifact_hash=,
    /// arguments=, current=)`
    fn apply_temporary_mcp_grant(
        &self,
        store: &dyn McpToolStore,
        artifact: &GuardArtifact,
        artifact_hash: &str,
        arguments: &Value,
        current: ToolCallDecision,
    ) -> ToolCallDecision;

    /// `calls._browser_runtime_exact_match_context(artifact, arguments) ->
    /// str | None`
    fn browser_runtime_exact_match_context(
        &self,
        artifact: &GuardArtifact,
        arguments: &Value,
    ) -> Option<String>;

    /// `calls._tool_call_saved_allow_validation_reason(saved_decision,
    /// artifact_hash=) -> ApprovalReuseValidationFailure | None`
    fn tool_call_saved_allow_validation_reason(
        &self,
        saved_decision: &Value,
        artifact_hash: &str,
    ) -> Option<String>;

    /// `calls._tool_call_decision_with_reuse(current, reuse,
    /// pending_decision=, claim_disposition=)`
    fn tool_call_decision_with_reuse(
        &self,
        current: ToolCallDecision,
        reuse: &ApprovalReuseDecision,
        pending_decision: Option<&Value>,
        claim_disposition: Option<&str>,
    ) -> ToolCallDecision;

    /// `calls._revalidate_claimed_tool_call_approval(store=,
    /// initial_artifact=, initial_artifact_hash=, initial_arguments=,
    /// initial_config=, claimed_decision=, claim_disposition=,
    /// fresh_authority_provider=)`
    #[allow(clippy::too_many_arguments)]
    fn revalidate_claimed_tool_call_approval(
        &self,
        store: &dyn McpToolStore,
        initial_artifact: &GuardArtifact,
        initial_artifact_hash: &str,
        initial_arguments: &Value,
        initial_config: &GuardConfig,
        claimed_decision: &Value,
        claim_disposition: Option<&str>,
        fresh_authority_provider: Option<&dyn FreshAuthorityProvider>,
    ) -> ToolCallDecision;
}

/// `fresh_authority_provider` — `Callable[[], tuple[GuardConfig,
/// GuardArtifact, str, object] | None]`. Returns `(config, artifact,
/// artifact_hash, arguments)` mirroring the tuple, or `None` when no fresh
/// authority is available.
pub trait FreshAuthorityProvider {
    fn fresh_authority(&self) -> Option<(GuardConfig, GuardArtifact, String, Value)>;
}

/// `evaluate_tool_call` (:24-60) — evaluate under a storage lease; if the
/// saved approval was claimed, refresh authority without a storage lease and
/// re-read policy before deciding whether it still allows.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_tool_call(
    store: &dyn McpToolStore,
    calls: &dyn McpToolCallsApi,
    config: &GuardConfig,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    arguments: &Value,
    claim_saved_approval: bool,
    fresh_authority_provider: Option<&dyn FreshAuthorityProvider>,
) -> ToolCallDecision {
    store.enter_connection_scope();
    let result = evaluate_tool_call_inner(
        store,
        calls,
        config,
        artifact,
        artifact_hash,
        arguments,
        claim_saved_approval,
    );
    store.exit_connection_scope();
    let claimed = match result {
        ToolCallEvaluation::Decision(decision) => return decision,
        ToolCallEvaluation::Claimed(claimed) => claimed,
    };

    // The claim is already committed. Refresh authority without a storage
    // lease, then re-read policy in a new scope before deciding whether it
    // still allows.
    calls.revalidate_claimed_tool_call_approval(
        store,
        artifact,
        artifact_hash,
        arguments,
        config,
        &claimed.decision,
        claimed.disposition.as_deref(),
        fresh_authority_provider,
    )
}

/// `_evaluate_tool_call` (:61-187) — the leased evaluation body.
#[allow(clippy::too_many_arguments)]
fn evaluate_tool_call_inner(
    store: &dyn McpToolStore,
    calls: &dyn McpToolCallsApi,
    config: &GuardConfig,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    arguments: &Value,
    claim_saved_approval: bool,
) -> ToolCallEvaluation {
    let current = calls.evaluate_current_tool_call(config, artifact, arguments);
    let current =
        calls.apply_temporary_mcp_grant(store, artifact, artifact_hash, arguments, current);
    // `metadata.get("mcp_provider_catalog_hash")` is `str | None | <other>`;
    // Python `!=` is strict inequality across types — only an equal `str`
    // matches.
    let provider_catalog_hash = artifact.metadata.get("mcp_provider_catalog_hash");
    let catalog_hash_changed = match (
        store.read_mcp_provider_authority_hash(),
        provider_catalog_hash,
    ) {
        (Some(saved), Some(value)) => value.as_str() != Some(saved.as_str()),
        (Some(_), None) => true,
        (None, Some(_)) => true,
        (None, None) => false,
    };
    if calls.composio_requires_action_review(artifact.command.as_deref().unwrap_or(""))
        && !current.is_block()
        && catalog_hash_changed
    {
        let action = most_restrictive_guard_action(
            &[current.action_value(), json!("require-reapproval")],
            GuardAction::Review,
        );
        return ToolCallEvaluation::Decision(current.replaced(
            action,
            "composio-schema-reapproval",
            "The app action inventory changed. Rebuild this call and review it again.",
        ));
    }
    let runtime_exact_match_context =
        calls.browser_runtime_exact_match_context(artifact, arguments);
    // `config.workspace` — `Path | None`; `str(workspace)` stringifies the
    // path. The GuardConfig mirror keeps unported fields in `extra`.
    let workspace = config
        .extra
        .get("workspace")
        .and_then(|value| value.as_str().map(str::to_owned));
    let policy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        &artifact.harness,
        &artifact.artifact_id,
        Some(artifact_hash),
        workspace.as_deref(),
        artifact.publisher.as_deref(),
        runtime_exact_match_context.as_deref(),
        artifact.command.as_deref(),
        Some(artifact.artifact_type.as_str()),
        Some(artifact.name.as_str()),
        false,
    );
    let saved_decision = policy_lookup
        .get("decision")
        .cloned()
        .filter(|decision| !decision.is_null());
    let ignored_integrity = policy_lookup
        .get("ignored_local_integrity")
        .cloned()
        .filter(|value| !value.is_null());

    let saved_action: Option<Value>;
    let mut validation_reason: Option<String>;
    if saved_decision.is_none() && ignored_integrity.is_none() {
        let diagnosed_reason = store.approval_reuse_validation_reason(
            &artifact.harness,
            &artifact.artifact_id,
            artifact_hash,
            workspace.as_deref(),
            artifact.publisher.as_deref(),
        );
        let Some(diagnosed_reason) = diagnosed_reason else {
            return ToolCallEvaluation::Decision(current);
        };
        saved_action = Some(json!("allow"));
        validation_reason = Some(diagnosed_reason);
    } else {
        saved_action = match &saved_decision {
            Some(decision) => decision.get("action").cloned(),
            None => {
                if ignored_integrity.is_some() {
                    Some(json!("require-reapproval"))
                } else {
                    None
                }
            }
        };
        validation_reason = if ignored_integrity.is_some() {
            Some("approval_reuse_integrity_failure".to_owned())
        } else {
            saved_decision.as_ref().and_then(|decision| {
                calls.tool_call_saved_allow_validation_reason(decision, artifact_hash)
            })
        };
    }

    if validation_reason.is_none()
        && saved_decision.is_some()
        && saved_action.as_ref().and_then(Value::as_str) == Some("allow")
        && calls.composio_requires_action_review(artifact.command.as_deref().unwrap_or(""))
        && store
            .approval_reuse_claim_disposition(saved_decision.as_ref().expect("checked is_some"))
            .as_deref()
            != Some("consumed")
    {
        // No supported account resolver exists for this profile. A retained
        // wrapper approval could silently follow a changed default account.
        // Fresh single-use review remains available; durable reuse does not.
        validation_reason = Some("approval_reuse_provider_account_unverified".to_owned());
    }
    let mut reuse = evaluate_approval_reuse(
        &current.action_value(),
        saved_action.as_ref(),
        Some(true),
        validation_reason.as_deref(),
        false,
        false,
    );
    let mut pending_decision: Option<Value> = None;
    let mut claim_disposition: Option<ApprovalReuseClaimDisposition> = None;
    if reuse.should_claim && saved_decision.is_some() {
        let decision = saved_decision.as_ref().expect("checked is_some");
        let raw_claim_disposition = store.approval_reuse_claim_disposition(decision);
        if let Some("consumed" | "retained") = raw_claim_disposition.as_deref() {
            claim_disposition = match raw_claim_disposition.as_deref() {
                Some("consumed") => Some("consumed"),
                _ => Some("retained"),
            };
        }
        if claim_saved_approval {
            if !store.claim_approval_reuse_decision(decision) {
                reuse = evaluate_approval_reuse(
                    &current.action_value(),
                    saved_action.as_ref(),
                    Some(true),
                    Some(APPROVAL_REUSE_CLAIM_FAILED),
                    false,
                    false,
                );
            } else {
                return ToolCallEvaluation::Claimed(ClaimedToolApproval {
                    decision: decision.clone(),
                    disposition: claim_disposition.map(str::to_owned),
                });
            }
        } else {
            pending_decision = saved_decision.clone();
        }
    }
    ToolCallEvaluation::Decision(calls.tool_call_decision_with_reuse(
        current,
        &reuse,
        pending_decision.as_ref(),
        claim_disposition,
    ))
}

#[cfg(test)]
#[path = "mcp_decision_launcher_tests.rs"]
mod launcher_tests;
