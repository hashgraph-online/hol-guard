//! `runner_authority` kind `copilot_detect`: the config parsing and artifact
//! discovery of `CopilotHarnessAdapter.detect`. Python resolves the candidate
//! files, their scopes and the `.github/hooks` listing; this reads each one
//! (or its captured generation), parses it the way `json.loads` with the JSONC
//! fallback does, and returns the hook and MCP server artifacts and the config
//! paths that were found. Every refusal is a stable code and never a partial
//! inventory.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_paths::{file_name_string, stem};
use super::codex_detect::is_guard_proxy;
use super::codex_sources::{read_source, Raw};
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal, LONE_SURROGATE_MARK};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};

const ERR_TEXT: &str = "native_runner_authority_copilot_text_undecodable";
const ERR_VALUE: &str = "native_runner_authority_copilot_value_unrepresentable";

const HARNESS: &str = "copilot";
const DETECTABLE_HOOK_EVENTS: [&str; 8] = [
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "permissionRequest",
    "permissionRequestV2",
    "errorOccurred",
];
const HOOK_SHELLS: [&str; 3] = ["command", "bash", "powershell"];

/// What a source contributes: a config file counts as found whenever it holds
/// a non-empty object, a `.github/hooks` file only when it yields a hook.
#[derive(PartialEq)]
enum Kind {
    Config,
    Mcp,
    Hooks,
}

struct Source<'a> {
    path: &'a str,
    scope: &'a str,
    kind: Kind,
}

fn sources(args: &Map<String, Value>) -> Result<Vec<Source<'_>>, &'static str> {
    args.get("sources")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| {
            let text = |key: &str| entry.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
            let kind = match text("kind")? {
                "config" => Kind::Config,
                "mcp" => Kind::Mcp,
                "hooks" => Kind::Hooks,
                _ => return Err(ERR_INVALID),
            };
            Ok(Source {
                path: text("path")?,
                scope: text("scope")?,
                kind,
            })
        })
        .collect()
}

/// `strip_jsonc_comments` with double-quoted strings: `//` and `/* */`
/// comments go, the newlines inside them stay.
fn strip_jsonc(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(character) = chars.next() {
        if in_string {
            output.push(character);
            if escape {
                escape = false;
            } else if character == '\\' {
                escape = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match (character, chars.peek()) {
            ('"', _) => {
                in_string = true;
                output.push(character);
            }
            ('/', Some('/')) => {
                chars.next();
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        output.push(skipped);
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                while let Some(skipped) = chars.next() {
                    if skipped == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                    if skipped == '\n' {
                        output.push(skipped);
                    }
                }
            }
            _ => output.push(character),
        }
    }
    output
}

/// `str.read_text`'s universal newlines: `\r\n` and a lone `\r` read as `\n`.
fn universal_newlines(text: String) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text
    }
}

fn object_or_empty(value: PyVal) -> PyVal {
    match value {
        value @ PyVal::Dict(_) => value,
        _ => PyVal::Dict(Vec::new()),
    }
}

/// `_parse_copilot_json_text(...) or {}`: the object the text holds, retrying
/// with comments stripped on a syntax error. Text `json.loads` raises a
/// non-`JSONDecodeError` on is refused rather than read as empty.
fn parse_payload(text: &str) -> Result<PyVal, &'static str> {
    match parse_marking_lone_surrogates(text) {
        Ok(value) => Ok(object_or_empty(value)),
        Err(JsonFailure::Syntax) => match parse_marking_lone_surrogates(&strip_jsonc(text)) {
            Ok(value) => Ok(object_or_empty(value)),
            Err(JsonFailure::Syntax) => Ok(PyVal::Dict(Vec::new())),
            Err(_) => Err(ERR_VALUE),
        },
        Err(_) => Err(ERR_VALUE),
    }
}

/// A missing, unreadable or empty source is an empty object; bytes that are
/// not UTF-8 are refused, as `decode("utf-8")` raises on them.
fn payload(raw: Raw, from_disk: bool) -> Result<PyVal, &'static str> {
    let Some(bytes) = raw.bytes.filter(|_| raw.present) else {
        return Ok(PyVal::Dict(Vec::new()));
    };
    let text = String::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    let text = if from_disk {
        universal_newlines(text)
    } else {
        text
    };
    parse_payload(&text)
}

/// A string the inventory carries; a lone surrogate CPython would keep but
/// never encode is refused.
fn kept(text: &str) -> Result<&str, &'static str> {
    if text.contains(LONE_SURROGATE_MARK) {
        Err(ERR_VALUE)
    } else {
        Ok(text)
    }
}

/// `_hook_artifacts`: a `hooks` object, or the payload itself, keyed by event.
fn hook_artifacts(
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<Vec<Value>, &'static str> {
    let hooks = match payload.get("hooks") {
        Some(hooks @ PyVal::Dict(_)) => hooks,
        _ => payload,
    };
    let path_stem = stem(&file_name_string(path)).to_owned();
    let mut artifacts = Vec::new();
    for event in DETECTABLE_HOOK_EVENTS {
        let Some(entries) = hooks.get(event).and_then(PyVal::as_list) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            if entry.as_dict().is_none() {
                continue;
            }
            for shell in HOOK_SHELLS {
                let Some(command) = entry.get(shell).and_then(PyVal::as_str) else {
                    continue;
                };
                let mut metadata = Map::new();
                metadata.insert("shell".to_owned(), json!(shell));
                artifacts.push(scope.wire(
                    format!(
                        "copilot:{}:hook:{}:{}:{index}:{shell}",
                        scope.scope,
                        kept(&path_stem)?,
                        event.to_lowercase()
                    ),
                    event,
                    "hook",
                    path,
                    Fields {
                        command: Some(kept(command)?),
                        ..Fields::default()
                    },
                    metadata,
                ));
            }
        }
    }
    Ok(artifacts)
}

/// `_mcp_payload_key` and `_mcp_servers_payload`.
fn mcp_servers<'a>(path: &Path, payload: &'a PyVal) -> Option<&'a PyVal> {
    let has = |key: &str| payload.get(key).is_some();
    let preferred = if has("mcpServers") && !has("servers") {
        "mcpServers"
    } else if has("servers") && !has("mcpServers") {
        "servers"
    } else if matches!(
        file_name_string(path).as_str(),
        ".mcp.json" | "mcp-config.json"
    ) {
        "mcpServers"
    } else {
        "servers"
    };
    let fallback = if preferred == "mcpServers" {
        "servers"
    } else {
        "mcpServers"
    };
    [preferred, fallback]
        .into_iter()
        .find_map(|key| payload.get(key).filter(|value| value.as_dict().is_some()))
}

/// `_command_parts`: a string command, or the first string of a list command
/// with the rest ahead of the string `args`.
fn command_parts(config: &PyVal) -> (Option<&str>, Vec<String>) {
    let args: Vec<String> = config
        .get("args")
        .and_then(PyVal::as_list)
        .map(|items| {
            items
                .iter()
                .filter_map(PyVal::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    match config.get("command") {
        Some(PyVal::Str(command)) => (Some(command), args),
        Some(PyVal::List(items)) => {
            let parts: Vec<&str> = items.iter().filter_map(PyVal::as_str).collect();
            match parts.split_first() {
                Some((first, rest)) => (
                    Some(first),
                    rest.iter()
                        .map(|part| (*part).to_owned())
                        .chain(args)
                        .collect(),
                ),
                None => (None, args),
            }
        }
        _ => (None, args),
    }
}

/// `_mcp_artifacts`: every server but Guard's own proxy entries.
fn mcp_artifacts(
    scope: &Scope<'_>,
    path: &Path,
    payload: &PyVal,
) -> Result<Vec<Value>, &'static str> {
    let Some(servers) = mcp_servers(path, payload).and_then(PyVal::as_dict) else {
        return Ok(Vec::new());
    };
    let mut artifacts = Vec::new();
    for (name, config) in servers {
        if config.as_dict().is_none() {
            continue;
        }
        let (command, args) = command_parts(config);
        if is_guard_proxy(command, &args) {
            continue;
        }
        let url = config.get("url").and_then(PyVal::as_str);
        let environment = match config.get("env") {
            Some(env @ PyVal::Dict(_)) => Some(env),
            _ => config.get("environment"),
        };
        let mut env = Map::new();
        for (key, value) in environment.and_then(PyVal::as_dict).unwrap_or_default() {
            if let Some(text) = value.as_str() {
                env.insert(kept(key)?.to_owned(), json!(kept(text)?));
            }
        }
        for arg in &args {
            kept(arg)?;
        }
        let mut metadata = Map::new();
        metadata.insert("env".to_owned(), Value::Object(env));
        artifacts.push(scope.wire(
            format!("copilot:{}:{}", scope.scope, kept(name)?),
            name,
            "mcp_server",
            path,
            Fields {
                command: command.map(kept).transpose()?,
                args,
                url: url.map(kept).transpose()?,
                transport: Some(if url.is_some() { "http" } else { "stdio" }),
                publisher: None,
            },
            metadata,
        ));
    }
    Ok(artifacts)
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.get("harness").and_then(Value::as_str) != Some(HARNESS) {
        return Err(ERR_INVALID);
    }
    let sources = sources(args)?;
    let contents = match args.get("contents") {
        None | Some(Value::Null) => None,
        Some(Value::Object(captured)) => Some(captured),
        Some(_) => return Err(ERR_INVALID),
    };

    let mut artifacts = Vec::new();
    let mut found: Vec<&str> = Vec::new();
    for source in &sources {
        let payload = payload(read_source(source.path, contents)?, contents.is_none())?;
        if !payload.truthy() {
            continue;
        }
        let path = Path::new(source.path);
        let scope = Scope {
            harness: HARNESS,
            scope: source.scope,
        };
        let hooks = hook_artifacts(&scope, path, &payload)?;
        if source.kind == Kind::Hooks {
            if hooks.is_empty() {
                continue;
            }
            found.push(source.path);
            artifacts.extend(hooks);
            continue;
        }
        found.push(source.path);
        artifacts.extend(hooks);
        if source.kind == Kind::Mcp {
            artifacts.extend(mcp_artifacts(&scope, path, &payload)?);
        }
    }
    Ok(json!({
        "artifacts": artifacts,
        "found_paths": found,
        "warnings": [],
    }))
}

#[cfg(test)]
mod tests {
    use super::strip_jsonc;

    #[test]
    fn strip_jsonc_keeps_strings_and_comment_newlines() {
        assert_eq!(strip_jsonc("{\"a\": 1} // c\n"), "{\"a\": 1} \n");
        assert_eq!(
            strip_jsonc("{/* a\nb */\"u\": \"//x\"}"),
            "{\n\"u\": \"//x\"}"
        );
        assert_eq!(strip_jsonc("{\"q\": \"\\\"/*\"}"), "{\"q\": \"\\\"/*\"}");
        assert_eq!(strip_jsonc("{} /* open"), "{} ");
        assert_eq!(strip_jsonc("// tail"), "");
    }
}
