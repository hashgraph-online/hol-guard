//! `runner_authority` kind `local_mcp_probe`: the deterministic steps around
//! a stdio MCP probe (`local_mcp_probe.py` `_resolve_launch_argv`,
//! `_absolute_existing_path` and `_tools_from_payload`, and
//! `local_cli_commands.py` `slug_local_cli_command_id`, before they moved here).
//!
//! Python keeps the probe orchestration and the search path it builds; the
//! catalog transport is already native.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::grok_executable_paths::strip_verbatim;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::runtime_identity_launch::{is_regular_file, which, Environment};

const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";
/// `MAX_MCP_PROBE_TOOLS`: listed tools kept before the Other-tools row.
const MAX_PROBE_TOOLS: usize = 100;
const MAX_COMMAND_DEPTH: usize = 4;
const MAX_COMMAND_NAME_TAIL: usize = 40;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("launch") if map.len() == 4 => launch(map),
        Some("tools") if map.len() == 3 => tools(map),
        Some("slugs") if map.len() == 2 => {
            let ids: Vec<String> = strings(map, "names")?.into_iter().map(slug).collect();
            Ok(json!({ "ids": ids }))
        }
        _ => Err(ERR_INVALID),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn strings<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Vec<&'a str>, &'static str> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect()
}

/// `_resolve_launch_argv`: the executable a probe launches and its arguments,
/// with relative arguments that name existing files made absolute. A Guard
/// package shim is looked up again by name so the probe never runs the shim.
fn launch(map: &Map<String, Value>) -> KindResult {
    let tokens = strings(map, "tokens")?;
    let cwd = Path::new(text(map, "cwd")?);
    let search_path = text(map, "search_path")?;
    let (first, arguments) = tokens.split_first().ok_or(ERR_INVALID)?;
    let environment = BTreeMap::new();
    let lookup = |name: &str| which(name, Some(search_path), &Environment(&environment));
    let first_path = Path::new(first);
    let resolved = if is_package_shim(first_path) {
        first_path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(lookup)
    } else if first_path.is_absolute() {
        Some((*first).to_owned())
    } else {
        // Only a bare name is looked up; a relative path names a file under `cwd`.
        let found = if first_path.components().count() == 1 {
            lookup(first)
        } else {
            None
        };
        found.or_else(|| {
            let candidate = cwd.join(first_path);
            is_regular_file(&candidate).then(|| candidate.to_string_lossy().into_owned())
        })
    };
    let Some(resolved) = resolved else {
        return Ok(json!({ "argv": null }));
    };
    let mut argv = vec![resolved];
    argv.extend(arguments.iter().map(|token| absolute_existing(token, cwd)));
    Ok(json!({ "argv": argv }))
}

/// `is_package_shim_executable`: a file in Guard's `package-shims/bin`.
fn is_package_shim(path: &Path) -> bool {
    let parent = path.parent();
    parent
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        == Some("bin")
        && parent
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("package-shims")
}

/// `_absolute_existing_path`: an option, package spec or URL is kept; a
/// relative path that exists under `cwd` becomes its resolved path.
fn absolute_existing(token: &str, cwd: &Path) -> String {
    if token.starts_with('-')
        || token.starts_with('@')
        || token.contains("://")
        || Path::new(token).is_absolute()
    {
        return token.to_owned();
    }
    let candidate = cwd.join(token);
    if std::fs::metadata(&candidate).is_err() {
        return token.to_owned();
    }
    std::fs::canonicalize(&candidate).map_or_else(
        |_| token.to_owned(),
        |resolved| strip_verbatim(resolved).to_string_lossy().into_owned(),
    )
}

/// `_tools_from_payload`: one catalog row per listed tool, deduplicated by
/// command id and capped, then the Other-tools row that covers the rest.
fn tools(map: &Map<String, Value>) -> KindResult {
    let listed = map
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let server_name = text(map, "server_name")?;
    let mut seen = BTreeSet::from([OTHER_COMMAND_ID.to_owned()]);
    let mut rows = Vec::new();
    for item in listed {
        let item = item.as_object().ok_or(ERR_INVALID)?;
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let name = py_strip(name);
        if name.is_empty() {
            continue;
        }
        let command_id = slug(name);
        if !seen.insert(command_id.clone()) {
            continue;
        }
        let description = item
            .get("description")
            .and_then(Value::as_str)
            .map_or_else(String::new, |text| prefix(py_strip(text), 240));
        rows.push(json!({
            "command_id": command_id,
            "name": prefix(name, 120),
            "usage": prefix(name, 160),
            "description": description,
        }));
        if rows.len() >= MAX_PROBE_TOOLS {
            break;
        }
    }
    rows.push(json!({
        "command_id": OTHER_COMMAND_ID,
        "name": "Other tools",
        "usage": format!("{server_name} …"),
        "description": "Any other tool this MCP server did not list.",
    }));
    Ok(json!({ "tools": rows }))
}

/// `slug_local_cli_command_id`: a tool name that is already a command path is
/// its own id; any other becomes a lower-case slug with a digest suffix, so a
/// tool name never turns into an option id.
fn slug(name: &str) -> String {
    let stripped = py_strip(name);
    if stripped != ROOT_COMMAND_ID && stripped != OTHER_COMMAND_ID && is_command_path(stripped) {
        return stripped.to_owned();
    }
    let mut compact = String::new();
    for character in stripped.chars() {
        if is_py_alnum(character) {
            // Per character, as Python's `ch.lower()`: no final-sigma context.
            compact.extend(character.to_lowercase());
        } else {
            compact.push('-');
        }
    }
    let compact = compact
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let digest = hex::encode(Sha256::digest(stripped.as_bytes()));
    let base = if compact.is_empty() { "tool" } else { &compact };
    let candidate = format!("{}-{}", prefix(base, 31), &digest[..8]);
    if is_command_path(&candidate) {
        candidate
    } else {
        OTHER_COMMAND_ID.to_owned()
    }
}

/// `_is_command_path`: `root`, `other`, or one to four dotted command names.
fn is_command_path(value: &str) -> bool {
    if value == ROOT_COMMAND_ID || value == OTHER_COMMAND_ID {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() <= MAX_COMMAND_DEPTH && parts.iter().all(|part| is_command_name(part))
}

fn is_command_name(part: &str) -> bool {
    let mut characters = part.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && part.len() <= MAX_COMMAND_NAME_TAIL + 1
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

/// Python's `str.isalnum` for one character: a letter or a number.
fn is_py_alnum(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_alphanumeric();
    }
    static LETTER_OR_NUMBER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pattern = LETTER_OR_NUMBER
        .get_or_init(|| Regex::new(r"^[\p{L}\p{N}]$").expect("letter-or-number pattern compiles"));
    pattern.is_match(character.encode_utf8(&mut [0; 4]))
}

/// Python's `str.strip()`: Unicode white space plus the ASCII separators
/// `\x1c`..`\x1f` that Python also counts as space.
fn py_strip(text: &str) -> &str {
    text.trim_matches(|character: char| {
        character.is_whitespace() || ('\x1c'..='\x1f').contains(&character)
    })
}

/// The first `limit` characters, as a Python slice counts them.
fn prefix(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

#[cfg(test)]
#[path = "local_mcp_probe_tests.rs"]
mod tests;
