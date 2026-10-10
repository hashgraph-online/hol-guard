//! Port of `apply_contributed_mcp_decision` (`runtime/mcp_server_grants.py`).
//!
//! A catalog MCP contribution can tighten a live `tools/call` (block or
//! review) or, only for a reviewed package launcher, relax it to allow. The
//! contributions are the packaged command program's MCP extensions; callers
//! supply the identity fields recorded in artifact metadata and the verified
//! extension-control layers. Python `str` semantics (strip, lower, casefold,
//! `isalnum`) are reproduced explicitly.

use serde_json::{Map, Value};

use crate::command_option_parsing::{python_is_alphanumeric, python_is_whitespace};
use crate::contributed_mcp_url::remote_mcp_endpoint_identity;
use crate::extension_control::{
    compose_control_layers, ControlLayerKind, ControlState, ControlTargetKind,
    ExtensionControlLayer,
};
use crate::mcp_decision::package_launcher_name;
use crate::native_command_program::{NativeCommandProgram, ProgramMcp, ProgramMcpLaunch};

/// Source recorded on every contributed decision.
pub const CONTRIBUTED_MCP_SOURCE: &str = "catalog-mcp-extension";
const BLOCK_REASON: &str = "This MCP tool is blocked by a catalog MCP server on this device.";
const REVIEW_REASON: &str =
    "This MCP tool requires review under a catalog MCP server enabled on this device.";
const ALLOW_REASON: &str = "This MCP tool is allowed by a catalog MCP server on this device.";

const DIRECT_RESERVED: &[&str] = &[
    "bunx",
    "npx",
    "npm",
    "pnpm",
    "uvx",
    "yarn",
    "pipx",
    "bash",
    "busybox",
    "bun",
    "cargo",
    "cmd",
    "csh",
    "dash",
    "deno",
    "docker",
    "dotnet",
    "env",
    "fish",
    "go",
    "java",
    "ksh",
    "lua",
    "node",
    "nodejs",
    "perl",
    "php",
    "podman",
    "powershell",
    "pwsh",
    "py",
    "python",
    "python3",
    "pythonw",
    "ruby",
    "sh",
    "sudo",
    "tcsh",
    "ts-node",
    "tsx",
    "uv",
    "wsl",
    "zsh",
];
const DIRECT_VERSIONED_BASES: &[&str] = &[
    "java", "lua", "node", "nodejs", "perl", "php", "py", "python", "pythonw", "ruby",
];
const PACKAGE_CONFIG_ENV_PREFIXES: &[&str] = &["npm_config_", "yarn_", "uv_", "pip_", "pipx_"];

/// One packaged MCP contribution.
pub struct Contribution<'a> {
    /// `command.mcp-<id>`.
    pub catalog_id: &'a str,
    pub trust_class: &'a str,
    pub mcp: &'a ProgramMcp,
}

/// Non-authoritative inputs recorded in artifact metadata.
pub struct ContributedMcpInput<'a> {
    pub current_action: &'a str,
    pub server_identity: Option<&'a Map<String, Value>>,
    pub artifact_transport: Option<&'a Value>,
    pub server_name: Option<&'a Value>,
    pub tool_name: Option<&'a Value>,
    pub layers: &'a [ExtensionControlLayer],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributedMcpOutcome {
    pub action: &'static str,
    pub source: &'static str,
    pub reason: &'static str,
}

/// The packaged program's MCP contributions in program order.
pub fn contributions(program: &NativeCommandProgram) -> Vec<Contribution<'_>> {
    program
        .extensions
        .iter()
        .filter_map(|extension| {
            extension.mcp.as_ref().map(|mcp| Contribution {
                catalog_id: extension.extension_id.as_str(),
                trust_class: extension.trust_class.as_str(),
                mcp,
            })
        })
        .collect()
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(python_is_whitespace)
}

fn as_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

/// `apply_contributed_mcp_decision` after the contribution list is fixed.
pub fn decide_contributed_mcp(
    contributions: &[Contribution<'_>],
    input: &ContributedMcpInput<'_>,
) -> Option<ContributedMcpOutcome> {
    let contribution = matching_contribution(contributions, input)?;
    if !extension_is_active(contribution, input.layers) {
        return None;
    }
    let tool_name = identity_tool_name(input)?;
    let state = mcp_tool_state(contribution.mcp, tool_name);
    let lockdown = input.layers.iter().any(|layer| layer.global_lockdown);
    let current = input.current_action;
    let outcome = |action, reason| {
        Some(ContributedMcpOutcome {
            action,
            source: CONTRIBUTED_MCP_SOURCE,
            reason,
        })
    };
    match state {
        "block" if current == "block" => None,
        "block" => outcome("block", BLOCK_REASON),
        "review" if matches!(current, "allow" | "warn") => outcome("review", REVIEW_REASON),
        "review" => None,
        _ if !matches!(current, "review" | "require-reapproval" | "warn") => None,
        "allow"
            if !lockdown
                && matches_package_launch_for_allow(input, &contribution.mcp.mcp_launch) =>
        {
            outcome("allow", ALLOW_REASON)
        }
        _ => None,
    }
}

/// `extension_is_active` with `required=False`.
fn extension_is_active(contribution: &Contribution<'_>, layers: &[ExtensionControlLayer]) -> bool {
    if contribution.trust_class != "external" {
        return true;
    }
    let composed = compose_control_layers(layers);
    if composed.state_for(ControlTargetKind::Extension, contribution.catalog_id)
        == ControlState::Disabled
    {
        return false;
    }
    layers.iter().any(|layer| {
        layer.kind == ControlLayerKind::LocalAdmin
            && layer.controls.iter().any(|control| {
                control.target.kind == ControlTargetKind::Extension
                    && control.target.target_id == contribution.catalog_id
                    && control.state == ControlState::Enabled
            })
    })
}

/// `_mcp_identity_tool_name`: a non-blank string, stripped.
fn identity_tool_name<'a>(input: &ContributedMcpInput<'a>) -> Option<&'a str> {
    let name = python_strip(as_str(input.tool_name)?);
    (!name.is_empty()).then_some(name)
}

/// `_normalized_tool_name`: lowercase alphanumeric runs joined by `-`.
fn normalized_tool_name(name: &str) -> String {
    let mut output = String::new();
    let mut pending_separator = false;
    for character in name.chars() {
        if python_is_alphanumeric(character) {
            if pending_separator && !output.is_empty() {
                output.push('-');
            }
            pending_separator = false;
            output.extend(character.to_lowercase());
        } else {
            pending_separator = true;
        }
    }
    output
}

/// `mcp_tool_state`.
fn mcp_tool_state(mcp: &ProgramMcp, tool_name: &str) -> &'static str {
    let wanted = normalized_tool_name(tool_name);
    let mut fallback = "inherit";
    for tool in &mcp.mcp_tools {
        let Some(state) = tool_state(&tool.state) else {
            continue;
        };
        let normalized = normalized_tool_name(&tool.name);
        if normalized == "other" {
            fallback = state;
        }
        if normalized == wanted {
            return state;
        }
    }
    fallback
}

fn tool_state(state: &str) -> Option<&'static str> {
    ["inherit", "allow", "review", "block"]
        .into_iter()
        .find(|known| *known == state)
}

fn identity_field<'a>(input: &ContributedMcpInput<'a>, key: &str) -> Option<&'a Value> {
    input.server_identity?.get(key)
}

/// `_package_name`: non-blank string, stripped and lowercased.
fn package_name(input: &ContributedMcpInput<'_>) -> Option<String> {
    let package = python_strip(as_str(identity_field(input, "package_name"))?);
    (!package.is_empty()).then(|| package.to_lowercase())
}

/// `_mcp_transport`: `http` for any remote spelling.
fn transport(input: &ContributedMcpInput<'_>) -> Option<String> {
    let candidates = [identity_field(input, "transport"), input.artifact_transport];
    for value in candidates {
        if let Some(text) = as_str(value) {
            let stripped = python_strip(text);
            if !stripped.is_empty() {
                let normalized = stripped.to_lowercase();
                return Some(match normalized.as_str() {
                    "http" | "https" | "remote" | "sse" | "streamable-http" | "streamable_http" => {
                        "http".to_owned()
                    }
                    _ => normalized,
                });
            }
        }
    }
    None
}

fn matching_contribution<'a, 'b>(
    contributions: &'b [Contribution<'a>],
    input: &ContributedMcpInput<'_>,
) -> Option<&'b Contribution<'a>> {
    let package = package_name(input);
    if let Some(package) = &package {
        let found = contributions.iter().find(|item| {
            let launch = &item.mcp.mcp_launch;
            launch.kind == "package-launcher"
                && launch
                    .package
                    .as_deref()
                    .is_some_and(|declared| python_strip(declared).to_lowercase() == *package)
        });
        if found.is_some() {
            return found;
        }
    }
    contributions.iter().find(|item| {
        let launch = &item.mcp.mcp_launch;
        match launch.kind.as_str() {
            "direct-command" => {
                package.is_none()
                    && transport(input).as_deref() == Some("stdio")
                    && identity_tool_name(input).is_some()
                    && as_str(identity_field(input, "command")).and_then(direct_mcp_command_name)
                        == launch.command.as_deref().map(str::to_owned)
            }
            "remote-http" => matches_remote_http(input, launch),
            _ => false,
        }
    })
}

fn reserved_direct_command(name: &str) -> bool {
    if DIRECT_RESERVED.contains(&name) {
        return true;
    }
    DIRECT_VERSIONED_BASES.iter().any(|base| {
        name.strip_prefix(base).is_some_and(|suffix| {
            suffix.starts_with(|c: char| c.is_ascii_digit())
                && suffix.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
    })
}

/// `direct_mcp_command_name`.
pub fn direct_mcp_command_name(value: &str) -> Option<String> {
    if value.is_empty() || value.contains("://") {
        return None;
    }
    let normalized = value.replace('\\', "/");
    let mut name = normalized.rsplit('/').next().unwrap_or("").to_lowercase();
    for suffix in [".exe", ".cmd", ".bat"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            name = stem.to_owned();
            break;
        }
    }
    let portable = name.chars().count() <= 128
        && name.split('.').enumerate().all(|(index, segment)| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                && (index > 0 || segment.as_bytes()[0].is_ascii_alphanumeric())
        });
    (portable && !reserved_direct_command(&name)).then_some(name)
}

/// `normalized_remote_server_name`.
fn normalized_remote_server_name(value: &str) -> Option<String> {
    let folded = caseless::default_case_fold_str(python_strip(value));
    let joined = folded
        .split(python_is_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then_some(joined)
}

/// `_matches_remote_http_contribution`.
fn matches_remote_http(input: &ContributedMcpInput<'_>, launch: &ProgramMcpLaunch) -> bool {
    if transport(input).as_deref() != Some("http") {
        return false;
    }
    let Some(remote) = launch.url.as_deref().and_then(remote_mcp_endpoint_identity) else {
        return false;
    };
    match identity_field(input, "command").filter(|value| !value.is_null()) {
        Some(command) => as_str(Some(command))
            .and_then(remote_mcp_endpoint_identity)
            .is_some_and(|identity| identity == remote),
        None => {
            let Some(name) = as_str(input.server_name).and_then(normalized_remote_server_name)
            else {
                return false;
            };
            launch
                .server_names
                .iter()
                .filter_map(|declared| normalized_remote_server_name(declared))
                .any(|declared| declared == name)
        }
    }
}

/// `_matches_package_launch_for_allow`.
fn matches_package_launch_for_allow(
    input: &ContributedMcpInput<'_>,
    launch: &ProgramMcpLaunch,
) -> bool {
    let Some(identity) = input.server_identity else {
        return false;
    };
    if launch.kind != "package-launcher" || !identity.contains_key("package_version") {
        return false;
    }
    let Some(command) = as_str(identity.get("command")) else {
        return false;
    };
    !command.contains("://")
        && package_launcher_name(command)
            .is_some_and(|name| Some(name.as_str()) == launch.command.as_deref())
        && as_str(identity.get("package_source")) == Some("default")
        && as_str(identity.get("transport")) == Some("stdio")
        && registry_package_selector(identity.get("package_version"))
        && default_package_environment(identity.get("env_keys"))
}

/// `_registry_package_selector`.
fn registry_package_selector(version: Option<&Value>) -> bool {
    let selector = match version {
        None | Some(Value::Null) => return true,
        Some(Value::String(text)) => python_strip(text),
        Some(_) => return false,
    };
    let bytes = selector.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"*^~<>=|_+-".contains(b));
    let rest_ok = bytes
        .iter()
        .skip(1)
        .all(|b| b.is_ascii_alphanumeric() || b"*^~<>=|.+ _-".contains(b));
    let archive = [".tgz", ".tar", ".tar.gz", ".zip", ".whl"]
        .iter()
        .any(|suffix| {
            bytes.len() >= suffix.len()
                && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
        });
    first_ok && rest_ok && !archive
}

/// `_default_package_environment`.
fn default_package_environment(env_keys: Option<&Value>) -> bool {
    let Some(Value::Array(keys)) = env_keys else {
        return false;
    };
    keys.iter().all(|key| {
        let Some(text) = key.as_str() else {
            return false;
        };
        let stripped = python_strip(text);
        if stripped.is_empty() {
            return false;
        }
        let normalized = stripped.to_lowercase();
        !(PACKAGE_CONFIG_ENV_PREFIXES
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
            || normalized.ends_with(":registry"))
    })
}

#[cfg(test)]
#[path = "contributed_mcp_decision_tests.rs"]
mod tests;
