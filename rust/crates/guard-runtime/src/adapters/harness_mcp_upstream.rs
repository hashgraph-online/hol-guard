//! The `harness_mcp_discovery` `upstream` op: `read_managed_mcp_upstream`,
//! which recovers the upstream launch from a Guard MCP proxy's generated argv
//! and checks it against the configured connection.
//!
//! Python keeps the env values. The request names the configured env keys,
//! and the answer names the ones the proxy forwards. The recovered fields
//! describe inventory; they never carry tool schemas or execution permission.

use std::collections::{BTreeSet, HashMap};

use serde_json::{json, Map, Value};

use super::{exact_keys, optional_text, text};
use crate::cloud_request_text::py_strip;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const UPSTREAM_KEYS: [&str; 11] = [
    "op",
    "commands",
    "harness",
    "name",
    "transport",
    "source_scope",
    "config_path",
    "args",
    "saved_origin",
    "saved_guard_home",
    "env_names",
];
const REQUIRED_OPTIONS: [&str; 7] = [
    "--guard-home",
    "--server-name",
    "--server-id",
    "--source-scope",
    "--config-path",
    "--transport",
    "--command",
];
const OPTIONAL_OPTIONS: [&str; 2] = ["--home", "--workspace"];
const ARG: &str = "--arg";
const ENV_KEY: &str = "--server-env-key";
const MAX_PROXY_ARGS: usize = 512;
const MAX_PROXY_ARGS_BYTES: usize = 262_144;
const RELAY_COMMAND: &str = "mcp-relay";
const MODULE_PREFIX: [&str; 3] = ["-m", "codex_plugin_scanner.cli", "guard"];
/// `PROXY_LAUNCHER_ENV_KEYS`: the launcher persists these from the
/// installer's env, so a server's env never injects them.
const LAUNCHER_ENV_KEYS: [&str; 9] = [
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONBREAKPOINT",
    "__PYVENV_LAUNCHER__",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
    "HOL_GUARD_TEST_MODE",
];
const PROXY_HARNESSES: [(&str, &str); 6] = [
    ("cline-mcp-proxy", "cline"),
    ("codex-mcp-proxy", "codex"),
    ("opencode-mcp-proxy", "opencode"),
    ("copilot-mcp-proxy", "copilot"),
    ("cursor-mcp-proxy", "cursor"),
    ("hermes-mcp-proxy", "hermes"),
];

/// The configured connection a proxy's argv must describe.
pub(super) struct Connection<'a> {
    pub(super) harness: &'a str,
    pub(super) name: &'a str,
    pub(super) transport: &'a str,
    pub(super) source_scope: &'a str,
    pub(super) config_path: &'a str,
    pub(super) saved_origin: &'a Value,
    pub(super) saved_guard_home: Option<&'a str>,
}

pub(super) fn upstream(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &UPSTREAM_KEYS)?;
    let commands = strings(map, "commands")?;
    let args = strings(map, "args")?;
    let env_names = strings(map, "env_names")?;
    let saved_origin = map.get("saved_origin").ok_or(ERR_INVALID)?;
    if !saved_origin.is_null() && !saved_origin.is_array() {
        return Err(ERR_INVALID);
    }
    let connection = Connection {
        harness: text(map, "harness")?,
        name: text(map, "name")?,
        transport: text(map, "transport")?,
        source_scope: text(map, "source_scope")?,
        config_path: text(map, "config_path")?,
        saved_origin,
        saved_guard_home: optional_text(map, "saved_guard_home")?,
    };
    Ok(json!({"upstream": read(&connection, &args, &commands, &env_names)}))
}

pub(super) fn read(
    connection: &Connection<'_>,
    args: &[&str],
    commands: &[&str],
    env_names: &[&str],
) -> Value {
    if args.len() > MAX_PROXY_ARGS
        || args.iter().map(|value| value.len()).sum::<usize>() > MAX_PROXY_ARGS_BYTES
    {
        return Value::Null;
    }
    let Some((proxy, tail)) = argument_tail(args, commands) else {
        return Value::Null;
    };
    if PROXY_HARNESSES
        .iter()
        .any(|(command, harness)| *command == proxy && *harness != connection.harness)
    {
        return Value::Null;
    }
    let Some(parsed) = parse_options(tail) else {
        return Value::Null;
    };
    let options = &parsed.options;
    if !REQUIRED_OPTIONS.iter().all(|key| options.contains_key(key))
        || options["--server-name"] != connection.name
        || options["--transport"] != connection.transport
    {
        return Value::Null;
    }
    let origin = (options["--source-scope"], options["--config-path"]);
    if origin != (connection.source_scope, connection.config_path) {
        // Cursor's installer copies workspace proxies into its global file.
        // Only Guard's saved install state binds this exception; an origin
        // claimed in a server's argv is never enough.
        let saved = connection.saved_origin.as_array().map(Vec::as_slice);
        let saved_matches = matches!(
            saved,
            Some([Value::String(scope), Value::String(path)])
                if (scope.as_str(), path.as_str()) == origin
        );
        if connection.harness != "cursor"
            || !saved_matches
            || connection.saved_guard_home != Some(options["--guard-home"])
        {
            return Value::Null;
        }
    }
    let mut forwarded: Vec<&str> = Vec::new();
    for key in &parsed.env_keys {
        if LAUNCHER_ENV_KEYS.contains(&key.to_uppercase().as_str()) {
            continue;
        }
        if !env_names.contains(key) {
            return Value::Null;
        }
        forwarded.push(*key);
    }
    json!({
        "command": options["--command"],
        "args": parsed.args,
        "env_names": forwarded,
        "server_id": options["--server-id"],
        "source_scope": origin.0,
        "config_path": origin.1,
    })
}

/// `proxy_argument_tail`: the proxy subcommand and the argv after it.
fn argument_tail<'s, 'a>(
    args: &'s [&'a str],
    commands: &[&str],
) -> Option<(&'a str, &'s [&'a str])> {
    if args.len() > 2 && args[0] == RELAY_COMMAND {
        // `<runtime> mcp-relay <python> <proxy argv>` carries the module argv unchanged.
        return module_tail(&args[2..], commands);
    }
    if let Some(first) = args.first().filter(|first| commands.contains(*first)) {
        return Some((*first, &args[1..]));
    }
    if args.len() >= 2 && args[0] == "guard" && commands.contains(&args[1]) {
        return Some((args[1], &args[2..]));
    }
    module_tail(args, commands)
}

fn module_tail<'s, 'a>(args: &'s [&'a str], commands: &[&str]) -> Option<(&'a str, &'s [&'a str])> {
    if args.len() >= 4 && args[..3] == MODULE_PREFIX[..] && commands.contains(&args[3]) {
        Some((args[3], &args[4..]))
    } else {
        None
    }
}

struct Parsed<'a> {
    options: HashMap<&'a str, &'a str>,
    args: Vec<&'a str>,
    env_keys: BTreeSet<&'a str>,
}

/// The generated `--key value` / `--key=value` grammar; anything else is unknown.
fn parse_options<'a>(tail: &[&'a str]) -> Option<Parsed<'a>> {
    let mut parsed = Parsed {
        options: HashMap::new(),
        args: Vec::new(),
        env_keys: BTreeSet::new(),
    };
    let mut index = 0;
    while index < tail.len() {
        let (key, value) = match tail[index].split_once('=') {
            Some(pair) => pair,
            None => {
                let key = tail[index];
                index += 1;
                let value = *tail.get(index)?;
                if value.starts_with("--") {
                    return None;
                }
                (key, value)
            }
        };
        if !allowed(key) || value.contains('\0') {
            return None;
        }
        if key == ARG {
            parsed.args.push(value);
        } else if key == ENV_KEY {
            if value.is_empty()
                || py_strip(value) != value
                || value.contains('=')
                || !parsed.env_keys.insert(value)
            {
                return None;
            }
        } else if value.is_empty() || parsed.options.insert(key, value).is_some() {
            return None;
        }
        index += 1;
    }
    Some(parsed)
}

fn allowed(key: &str) -> bool {
    key == ARG
        || key == ENV_KEY
        || REQUIRED_OPTIONS.contains(&key)
        || OPTIONAL_OPTIONS.contains(&key)
}

fn strings<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Vec<&'a str>, &'static str> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<&str>, &'static str>>()
}

#[cfg(test)]
#[path = "harness_mcp_upstream_tests.rs"]
mod tests;
