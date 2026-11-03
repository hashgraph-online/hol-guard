//! `mcp_registry_setup` runner-authority kind: the reviewed Codex MCP setup a
//! registry selection describes. Ported from `mcp_registry_setup.py`
//! (`reviewed_codex_setup_candidate`, `reviewed_codex_package_candidate`).
//!
//! A selection names a registry server, its version and either a remote
//! endpoint (`"kind": "remote"`) or a pinned package recipe (`"package"`).
//! Python fetches the registry listing and resolves the recipe's runtimes on
//! `PATH`; this checks the selection, binds it to exactly one active listing
//! entry and digests what Codex will be told to run.
//!
//! - `{"kind", "selection"}` answers `{"query": str}`, the bounded registry
//!   search for the selection, or `{"error": code}` before anything is fetched.
//! - `{"kind", "selection", "results", "commands": {name: absolute path}}`
//!   answers `{"candidate": {...}}` or `{"error": code}`.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::consumer_url::{url_hostname, url_scheme};
use crate::guard_store_json::dumps_sorted;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const LISTING_CHANGED: &str = "registry_setup_listing_changed";
const QUERY_CHARS: usize = 80;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let selection = args
        .get("selection")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let package = match args.get("kind").and_then(Value::as_str) {
        Some("remote") => false,
        Some("package") => true,
        _ => return Err(ERR_INVALID),
    };
    let checked = if package {
        package_selection(selection)
    } else {
        remote_selection(selection)
    };
    let selection = match checked {
        Ok(selection) => selection,
        Err(code) => return Ok(json!({ "error": code })),
    };
    let Some(results) = args.get("results") else {
        return Ok(json!({ "query": registry_query(selection.registry_name) }));
    };
    let commands = match args.get("commands") {
        Some(Value::Object(commands)) if package => Some(commands),
        None if !package => None,
        _ => return Err(ERR_INVALID),
    };
    let candidate = match commands {
        Some(commands) => package_candidate(&selection, results, commands),
        None => remote_candidate(&selection, results),
    };
    Ok(match candidate {
        Ok(candidate) => json!({ "candidate": candidate }),
        Err(code) => json!({ "error": code }),
    })
}

/// The fields a selection binds; `target` is the endpoint or the package
/// identifier and `pin` is unused for a remote server.
struct Selection<'a> {
    registry_name: &'a str,
    version: &'a str,
    target: &'a str,
    pin: &'a str,
    setup_name: &'a str,
}

fn text<'a>(selection: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    selection.get(key).and_then(Value::as_str)
}

fn chars_within(value: &str, low: usize, high: usize) -> bool {
    (low..=high).contains(&value.chars().count())
}

/// `[a-z0-9][a-z0-9_-]{0,63}\Z`.
fn setup_name_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && name.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// The registry name and version every selection carries, plus its setup name.
fn common(selection: &Map<String, Value>) -> Option<(&str, &str, &str)> {
    let registry_name =
        text(selection, "registry_name").filter(|name| chars_within(name, 1, 256))?;
    let version = text(selection, "version").filter(|version| chars_within(version, 1, 80))?;
    let setup_name = text(selection, "setup_name").filter(|name| setup_name_ok(name))?;
    Some((registry_name, version, setup_name))
}

fn remote_selection(selection: &Map<String, Value>) -> Result<Selection<'_>, &'static str> {
    let fields = common(selection)
        .zip(text(selection, "endpoint").filter(|endpoint| endpoint.chars().count() <= 2048));
    let Some(((registry_name, version, setup_name), endpoint)) = fields else {
        return Err("invalid_codex_setup_selection");
    };
    if !endpoint_ok(endpoint) {
        return Err("invalid_codex_setup_endpoint");
    }
    Ok(Selection {
        registry_name,
        version,
        target: endpoint,
        pin: "",
        setup_name,
    })
}

fn package_selection(selection: &Map<String, Value>) -> Result<Selection<'_>, &'static str> {
    let fields = common(selection)
        .zip(text(selection, "package_identifier").zip(text(selection, "package_version")));
    let Some(((registry_name, version, setup_name), (identifier, package_version))) = fields else {
        return Err("invalid_codex_package_selection");
    };
    Ok(Selection {
        registry_name,
        version,
        target: identifier,
        pin: package_version,
        setup_name,
    })
}

/// An `https` URL with a host and no credentials, query or fragment, as
/// `urlsplit` reads it; a URL `urlsplit` refuses is never one.
fn endpoint_ok(endpoint: &str) -> bool {
    if url_scheme(endpoint).as_deref() != Some("https") || url_hostname(endpoint).is_none() {
        return false;
    }
    let cleaned: String = endpoint
        .trim_start_matches(|character: char| character <= ' ')
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    let rest = cleaned
        .split_once("//")
        .map_or("", |(_, after_slashes)| after_slashes);
    let netloc_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (netloc, tail) = rest.split_at(netloc_end);
    let (before_fragment, fragment) = tail.split_once('#').unwrap_or((tail, ""));
    let query = before_fragment
        .split_once('?')
        .map_or("", |(_, query)| query);
    let (username, password) = netloc.rsplit_once('@').map_or(("", ""), |(userinfo, _)| {
        userinfo.split_once(':').unwrap_or((userinfo, ""))
    });
    username.is_empty() && password.is_empty() && query.is_empty() && fragment.is_empty()
}

/// Search is a bounded substring lookup; exact full-name matching follows.
fn registry_query(registry_name: &str) -> String {
    let count = registry_name.chars().count();
    registry_name
        .chars()
        .skip(count.saturating_sub(QUERY_CHARS))
        .collect()
}

/// The active listing entries for exactly this server and version.
fn listed<'a>(
    selection: &Selection<'_>,
    results: &'a Value,
) -> Result<Vec<&'a Map<String, Value>>, &'static str> {
    let results = results.as_array().ok_or(LISTING_CHANGED)?;
    Ok(results
        .iter()
        .filter_map(Value::as_object)
        .filter(|entry| {
            text(entry, "name") == Some(selection.registry_name)
                && text(entry, "version") == Some(selection.version)
                && text(entry, "status") == Some("active")
        })
        .collect())
}

fn digest(parts: Value) -> Result<String, &'static str> {
    let encoded = dumps_sorted(&parts).ok_or(ERR_INVALID)?;
    Ok(hex::encode(Sha256::digest(encoded.as_bytes())))
}

fn remote_candidate(selection: &Selection<'_>, results: &Value) -> Result<Value, &'static str> {
    let endpoint = selection.target;
    let matching = listed(selection, results)?
        .into_iter()
        .filter(|entry| {
            entry
                .get("remote_endpoints")
                .and_then(Value::as_array)
                .is_some_and(|remotes| {
                    remotes.iter().filter_map(Value::as_object).any(|remote| {
                        text(remote, "url") == Some(endpoint)
                            && text(remote, "transport") == Some("streamable-http")
                    })
                })
        })
        .count();
    if matching != 1 {
        return Err(LISTING_CHANGED);
    }
    let selection_digest = digest(json!([
        "codex",
        selection.registry_name,
        selection.version,
        endpoint,
        selection.setup_name,
    ]))?;
    Ok(json!({
        "host": "codex",
        "kind": "remote",
        "registry_name": selection.registry_name,
        "version": selection.version,
        "endpoint": endpoint,
        "setup_name": selection.setup_name,
        "selection_digest": selection_digest,
        "account_binding": "unverified",
    }))
}

fn package_candidate(
    selection: &Selection<'_>,
    results: &Value,
    commands: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let (identifier, package_version) = (selection.target, selection.pin);
    let matches: Vec<&Map<String, Value>> = listed(selection, results)?
        .into_iter()
        .filter_map(|entry| entry.get("package_options").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_object)
        .filter(|option| {
            text(option, "identifier") == Some(identifier)
                && text(option, "version") == Some(package_version)
        })
        .collect();
    let [option] = matches.as_slice() else {
        return Err(LISTING_CHANGED);
    };
    let command_name = text(option, "command").ok_or(LISTING_CHANGED)?;
    let arguments = option
        .get("arguments")
        .and_then(Value::as_array)
        .filter(|arguments| arguments.iter().all(Value::is_string))
        .ok_or(LISTING_CHANGED)?;
    let registry_type = option.get("registry_type").ok_or(LISTING_CHANGED)?;
    let command = commands
        .get(command_name)
        .and_then(Value::as_str)
        .ok_or("package_runtime_unavailable")?;
    let selection_digest = digest(json!([
        "codex-package",
        selection.registry_name,
        selection.version,
        identifier,
        package_version,
        selection.setup_name,
        command,
        arguments,
    ]))?;
    Ok(json!({
        "host": "codex",
        "kind": "package",
        "registry_name": selection.registry_name,
        "version": selection.version,
        "package_identifier": identifier,
        "package_version": package_version,
        "registry_type": registry_type,
        "setup_name": selection.setup_name,
        "command": command,
        "arguments": arguments,
        "selection_digest": selection_digest,
        "account_binding": "unverified",
        "verified_package": false,
    }))
}

#[cfg(test)]
#[path = "mcp_registry_setup_tests.rs"]
mod tests;
