//! `runner_authority` kind `opencode_launch`: the OpenCode command line and
//! launch environment `hol-guard opencode` starts the harness with.
//!
//! `argv` shapes the passthrough arguments: a known subcommand passes through
//! untouched, anything else opens the interactive TUI in the workspace with
//! the trailing words joined into one `--prompt`. Arguments travel joined by
//! NUL, which no command-line argument can contain, so a long prompt is one
//! string rather than a request array past the transport's width bound.
//!
//! `environment` merges the managed runtime overlay over the caller's
//! `OPENCODE_CONFIG_CONTENT` and spells the result the way `json.dumps`
//! did: insertion order, the default separators, ASCII only. The overlay is
//! read from the Guard home the resident verified for the request, never
//! from a path in the arguments.

use guard_command::local_tool_eligibility::python_digit::python_isdigit;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::opencode_plugin_render::dumps;
use super::pyjson::{parse, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::workspace_inventory_files::read_text;

const EXECUTABLE: &str = "opencode";
const SEPARATOR: char = '\0';
/// `runtime_config_path`, under the Guard home.
const OVERLAY_DIR: &str = "opencode";
const OVERLAY_FILE: &str = "runtime-config.json";
const SUBCOMMANDS: [&str; 19] = [
    "completion",
    "acp",
    "mcp",
    "attach",
    "run",
    "auth",
    "agent",
    "upgrade",
    "uninstall",
    "serve",
    "web",
    "models",
    "stats",
    "export",
    "import",
    "github",
    "pr",
    "session",
    "db",
];
const REQUIRED_VALUE_OPTIONS: [&str; 19] = [
    "--hostname",
    "--mdns-domain",
    "--cors",
    "--model",
    "-m",
    "--session",
    "-s",
    "--prompt",
    "--agent",
    "--variant",
    "--log-level",
    "--command",
    "--format",
    "--file",
    "-f",
    "--attach",
    "--password",
    "-p",
    "--dir",
];

pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("argv") if map.len() == 4 => argv(map),
        Some("environment") if map.len() == 2 => environment(map, guard_home),
        _ => Err(ERR_INVALID),
    }
}

fn optional_text<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match map.get(key) {
        Some(Value::String(text)) => Ok(Some(text)),
        Some(Value::Null) => Ok(None),
        _ => Err(ERR_INVALID),
    }
}

/// `launch_command`.
fn argv(map: &Map<String, Value>) -> KindResult {
    let joined = map.get("args").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let count = map
        .get("count")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let workspace = optional_text(map, "workspace")?;
    let args: Vec<&str> = if count == 0 {
        Vec::new()
    } else {
        joined.split(SEPARATOR).collect()
    };
    if (count == 0 && !joined.is_empty()) || u64::try_from(args.len()) != Ok(count) {
        return Err(ERR_INVALID);
    }
    let mut command = vec![EXECUTABLE.to_owned()];
    match args.first() {
        Some(first) if SUBCOMMANDS.contains(first) => {
            command.extend(args.iter().map(|arg| (*arg).to_owned()));
        }
        first => {
            command.extend(workspace.map(str::to_owned));
            if first.is_some() {
                command.extend(interactive_args(&args));
            }
        }
    }
    Ok(json!({ "argv": command.join("\0"), "count": command.len() }))
}

/// `_interactive_args`: options stay in place and the first word that is
/// not an option, with everything after it, becomes the `--prompt` value.
/// A literal `--` ends the options without joining the prompt itself.
fn interactive_args(args: &[&str]) -> Vec<String> {
    if args
        .iter()
        .any(|arg| *arg == "--prompt" || arg.starts_with("--prompt="))
    {
        return args.iter().map(|arg| (*arg).to_owned()).collect();
    }
    let mut normalized = Vec::new();
    let mut prompt: &[&str] = &[];
    let mut index = 0;
    while index < args.len() {
        let value = args[index];
        if value == "--" {
            prompt = &args[index + 1..];
            break;
        }
        if value.starts_with('-') {
            normalized.push(value.to_owned());
            if consumes_next_value(value, args, index) {
                index += 1;
                normalized.push(args[index].to_owned());
            }
            index += 1;
            continue;
        }
        prompt = &args[index..];
        break;
    }
    if !prompt.is_empty() {
        normalized.push("--prompt".to_owned());
        normalized.push(prompt.join(" "));
    }
    normalized
}

/// `_consumes_next_value`: `--port` takes the next word only when it is a
/// number and `--title` only when it is not another option.
fn consumes_next_value(value: &str, args: &[&str], index: usize) -> bool {
    if index + 1 >= args.len() || value.contains('=') {
        return false;
    }
    if REQUIRED_VALUE_OPTIONS.contains(&value) {
        return true;
    }
    let next = args[index + 1];
    match value {
        "--port" => python_isdigit(next),
        "--title" => !next.starts_with('-'),
        _ => false,
    }
}

/// `launch_environment`: no content when the overlay is missing or is not a
/// JSON object, since there is nothing managed to apply.
fn environment(map: &Map<String, Value>, guard_home: &str) -> KindResult {
    if guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    let inline = optional_text(map, "inline")?;
    let path = Path::new(guard_home).join(OVERLAY_DIR).join(OVERLAY_FILE);
    let overlay = match read_text(&path).map(|text| parse(&text)) {
        Some(Ok(PyVal::Dict(entries))) => entries,
        _ => return Ok(json!({ "content": null })),
    };
    let merged = merge(inline_config(inline), overlay);
    Ok(json!({ "content": dumps(&PyVal::Dict(merged)) }))
}

/// `_inline_config`: the caller's config object, or nothing when it is empty,
/// unreadable or not an object.
fn inline_config(raw: Option<&str>) -> Vec<(String, PyVal)> {
    match raw.filter(|text| !text.is_empty()).map(parse) {
        Some(Ok(PyVal::Dict(entries))) => entries,
        _ => Vec::new(),
    }
}

/// `_merge_configs`: an object over an object merges key by key, anything
/// else replaces. A replaced key keeps its position; a new key goes last.
fn merge(mut base: Vec<(String, PyVal)>, overlay: Vec<(String, PyVal)>) -> Vec<(String, PyVal)> {
    for (key, value) in overlay {
        match base.iter_mut().find(|(name, _)| *name == key) {
            Some((_, existing)) => {
                *existing = match (std::mem::replace(existing, PyVal::Null), value) {
                    (PyVal::Dict(nested), PyVal::Dict(over)) => PyVal::Dict(merge(nested, over)),
                    (_, value) => value,
                };
            }
            None => base.push((key, value)),
        }
    }
    base
}

#[cfg(test)]
#[path = "opencode_launch_tests.rs"]
mod tests;
