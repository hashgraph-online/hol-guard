//! The Guard proxy wrappers in an OpenCode `mcp` entry, for the
//! `opencode_install_plan` kind: `_restore_local_server_from_guard_proxy`,
//! `_command_parts` and `is_guard_proxy_command` in Python before they moved.

use serde_json::{Map, Value};

use super::codex_detect::{is_guard_launcher, is_guard_proxy, PROXY_COMMANDS};

const OPENCODE_PROXY: &str = "opencode-mcp-proxy";
const NATIVE_RELAY: &str = "mcp-relay";

/// The local argv an old in-place `opencode-mcp-proxy` wrapper carried: the
/// last `--command` value, then every `--arg=` value.
pub(crate) fn restored_command(entry: &Map<String, Value>) -> Option<Vec<&str>> {
    let tokens: Vec<&str> = string_items(
        entry
            .get("command")
            .and_then(|command| command.as_array())?,
    );
    if !tokens.contains(&OPENCODE_PROXY) {
        return None;
    }
    let mut command: Option<&str> = None;
    let mut args: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if token == "--command" && index + 1 < tokens.len() {
            command = Some(tokens[index + 1]);
            index += 2;
            continue;
        }
        if let Some(arg) = token.strip_prefix("--arg=") {
            args.push(arg);
        }
        index += 1;
    }
    let mut argv: Vec<&str> = vec![command?];
    argv.extend(args);
    Some(argv)
}

/// Whether the entry launches a Guard MCP proxy (`is_guard_proxy_command`
/// over `_command_parts`).
pub(crate) fn is_guard_entry(entry: &Map<String, Value>) -> bool {
    let (command, args) = command_parts(entry);
    is_guard_command(command, &args)
}

/// `_command_parts`: a command list, or a command string with its args.
fn command_parts(entry: &Map<String, Value>) -> (Option<&str>, Vec<&str>) {
    match entry.get("command") {
        Some(Value::Array(items)) => {
            let list = string_items(items);
            match list.split_first() {
                Some((first, rest)) => (Some(*first), rest.to_vec()),
                None => (None, Vec::new()),
            }
        }
        Some(Value::String(command)) => {
            let args = match entry.get("args") {
                Some(Value::Array(items)) => string_items(items),
                _ => Vec::new(),
            };
            (Some(command.as_str()), args)
        }
        _ => (None, Vec::new()),
    }
}

/// The string items of a list, others skipped.
fn string_items(items: &[Value]) -> Vec<&str> {
    items.iter().filter_map(|item| item.as_str()).collect()
}

/// `is_guard_proxy_command`. `codex_detect::is_guard_proxy` does not read
/// `proxy_argument_tail`'s relay form, `<launcher> mcp-relay <python> -m
/// codex_plugin_scanner.cli guard <proxy> ...`, which never falls through.
pub(crate) fn is_guard_command(command: Option<&str>, args: &[&str]) -> bool {
    if let Some(launcher) = command {
        if args.len() > 2 && args[0] == NATIVE_RELAY && is_guard_launcher(launcher) {
            let relayed = &args[2..];
            return relayed.len() >= 4
                && relayed[0] == "-m"
                && relayed[1] == "codex_plugin_scanner.cli"
                && relayed[2] == "guard"
                && PROXY_COMMANDS.contains(&relayed[3]);
        }
    }
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    is_guard_proxy(command, &owned)
}
