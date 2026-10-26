//! Argument parsing for the native MCP stdio relay.
//!
//! The relay receives the same Python argv the installer writes for a
//! `guard <harness>-mcp-proxy` launch (`<python> -m codex_plugin_scanner.cli
//! guard codex-mcp-proxy --guard-home ... --command ... --arg=...`). It reads
//! the proxy flags from that argv so one installed command line serves both
//! runtimes. Flags accept `--flag value` and `--flag=value`; a repeated scalar
//! flag keeps the last value, like argparse.

use std::path::{Path, PathBuf};

/// `(proxy command, harness, default transport, elicitation-capable)`.
const PROXIES: [(&str, &str, &str, bool); 4] = [
    ("codex-mcp-proxy", "codex", "stdio", true),
    ("copilot-mcp-proxy", "copilot", "stdio", true),
    ("cursor-mcp-proxy", "cursor", "stdio", true),
    ("opencode-mcp-proxy", "opencode", "local", false),
];

/// One parsed proxy launch. The server-identity fields (`home`, `server_id`,
/// `source_scope`, `config_path`, `transport`) are parsed and validated now
/// and feed the native decision authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct RelayArgs {
    pub(crate) harness: &'static str,
    /// Whether the harness proxy may ask for approval through elicitation.
    pub(crate) elicitation_capable: bool,
    pub(crate) guard_home: PathBuf,
    pub(crate) home: Option<PathBuf>,
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) server_name: String,
    pub(crate) server_id: Option<String>,
    pub(crate) source_scope: String,
    pub(crate) config_path: String,
    pub(crate) transport: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) server_env_keys: Vec<String>,
}

#[derive(Default)]
struct Scalars {
    guard_home: Option<String>,
    home: Option<String>,
    workspace: Option<String>,
    server_name: Option<String>,
    server_id: Option<String>,
    source_scope: Option<String>,
    config_path: Option<String>,
    transport: Option<String>,
    command: Option<String>,
}

impl Scalars {
    fn slot(&mut self, flag: &str) -> Option<&mut Option<String>> {
        Some(match flag {
            "--guard-home" => &mut self.guard_home,
            "--home" => &mut self.home,
            "--workspace" => &mut self.workspace,
            "--server-name" => &mut self.server_name,
            "--server-id" => &mut self.server_id,
            "--source-scope" => &mut self.source_scope,
            "--config-path" => &mut self.config_path,
            "--transport" => &mut self.transport,
            "--command" => &mut self.command,
            _ => return None,
        })
    }
}

/// Parse the Python proxy argv. Any unknown flag, a missing value, or a
/// missing required flag is an error: the relay never guesses a launch.
pub(crate) fn parse(argv: &[String]) -> Result<RelayArgs, String> {
    let position = argv
        .windows(2)
        .position(|pair| pair[0] == "guard" && proxy(&pair[1]).is_some())
        .ok_or_else(|| "mcp_relay_proxy_command_missing".to_owned())?;
    let (_, harness, default_transport, elicitation_capable) =
        proxy(&argv[position + 1]).ok_or_else(|| "mcp_relay_proxy_command_missing".to_owned())?;
    let mut scalars = Scalars::default();
    let mut args = Vec::new();
    let mut server_env_keys = Vec::new();
    let mut rest = argv[position + 2..].iter();
    while let Some(token) = rest.next() {
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_owned())),
            _ => (token.as_str(), None),
        };
        if !flag.starts_with("--") {
            return Err("mcp_relay_argument_unexpected".to_owned());
        }
        let value = match inline {
            Some(value) => value,
            None => rest
                .next()
                .cloned()
                .ok_or_else(|| "mcp_relay_argument_value_missing".to_owned())?,
        };
        match flag {
            "--arg" => args.push(value),
            "--server-env-key" => server_env_keys.push(value),
            other => {
                *scalars
                    .slot(other)
                    .ok_or_else(|| "mcp_relay_argument_unknown".to_owned())? = Some(value);
            }
        }
    }
    let required = |value: Option<String>| {
        value
            .filter(|text| !text.is_empty())
            .ok_or_else(|| "mcp_relay_argument_required".to_owned())
    };
    let home = scalars.home.filter(|h| !h.is_empty()).map(PathBuf::from);
    Ok(RelayArgs {
        harness,
        elicitation_capable,
        // `resolve_guard_home(--guard-home or --home)`: the installer always
        // writes `--guard-home`; a bare `--home` is not resolved here.
        guard_home: PathBuf::from(required(scalars.guard_home)?),
        home,
        workspace: scalars.workspace.as_deref().and_then(normalize_workspace),
        server_name: required(scalars.server_name)?,
        server_id: scalars.server_id,
        source_scope: scalars.source_scope.unwrap_or_else(|| "project".to_owned()),
        config_path: required(scalars.config_path)?,
        transport: scalars
            .transport
            .unwrap_or_else(|| default_transport.to_owned()),
        command: required(scalars.command)?,
        args,
        server_env_keys: env_keys(server_env_keys),
    })
}

/// `tuple(dict.fromkeys(key.strip() for key in keys if key.strip()))`.
fn env_keys(keys: Vec<String>) -> Vec<String> {
    let mut unique: Vec<String> = Vec::with_capacity(keys.len());
    for key in keys {
        let key = crate::context_digest::python_strip(&key);
        if !key.is_empty() && !unique.iter().any(|seen| seen == key) {
            unique.push(key.to_owned());
        }
    }
    unique
}

fn proxy(command: &str) -> Option<(&'static str, &'static str, &'static str, bool)> {
    PROXIES.iter().copied().find(|entry| entry.0 == command)
}

/// `_normalize_explicit_workspace_path`: drop sentinel values and a trailing
/// `None` segment, expand `~`, and resolve when the path exists.
pub(crate) fn normalize_workspace(value: &str) -> Option<PathBuf> {
    let stripped = value.trim();
    if stripped.is_empty() || matches!(stripped.to_ascii_lowercase().as_str(), "none" | "null") {
        return None;
    }
    let mut path = expand_user(stripped);
    if path.file_name().is_some_and(|name| name == "None") {
        path = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if path.as_os_str().is_empty() {
            return None;
        }
    }
    Some(absolute(&path))
}

fn expand_user(value: &str) -> PathBuf {
    let home = std::env::var_os("HOME").filter(|home| !home.is_empty());
    match (value.strip_prefix('~'), home) {
        (Some(""), Some(home)) => PathBuf::from(home),
        (Some(rest), Some(home)) if rest.starts_with('/') => {
            PathBuf::from(home).join(rest.trim_start_matches('/'))
        }
        _ => PathBuf::from(value),
    }
}

/// `Path.resolve()` (non-strict): canonical when it exists, else absolute.
fn absolute(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
#[path = "mcp_relay_args_tests.rs"]
mod tests;
