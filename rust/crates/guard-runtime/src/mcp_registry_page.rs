//! `mcp_registry_page` runner-authority kind: one search page of the official
//! public MCP server registry, read into the listing Guard shows.
//!
//! Python fetches the page from the fixed registry origin with a bounded body;
//! this reads it.
//!
//! - `{"body": str}`, the response body base64 encoded, answers
//!   `{"listing": {...}}` with the page's `results`, `count` and
//!   `more_available`, or `{"error": "registry_response_invalid"}` when the
//!   body is not a well-formed registry page: not UTF-8 JSON, a repeated
//!   object key, a non-finite number, more than 20 servers, or a server entry
//!   missing its name, version or official registry metadata.
//!
//! Only pinned, literal stdio recipes Codex can own become `package_options`:
//! an `npx` npm package or a `uvx` PyPI package from its default registry,
//! with a pinned version, literal positional arguments and no declared
//! environment variables or runtime arguments. Nothing on the page is
//! verified or installed, so every result says so.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::pyjson::{parse_unique, PyVal};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_BODY_BYTES: usize = 512_000;
const MAX_SERVERS: usize = 20;
const MAX_REMOTES: usize = 8;
const MAX_PACKAGES: usize = 8;
const MAX_PACKAGE_COUNT: usize = 100;
const MAX_PACKAGE_ARGUMENTS: usize = 16;
const OFFICIAL_META: &str = "io.modelcontextprotocol.registry/official";
const SOURCE: &str = "official-mcp-registry";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let body = args_object(args)?
        .get("body")
        .and_then(Value::as_str)
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .filter(|body| body.len() <= MAX_BODY_BYTES)
        .ok_or(ERR_INVALID)?;
    Ok(match listing(&body) {
        Some(listing) => json!({ "listing": listing }),
        None => json!({ "error": "registry_response_invalid" }),
    })
}

fn listing(body: &[u8]) -> Option<Value> {
    let page = parse_unique(std::str::from_utf8(body).ok()?).ok()?;
    if !finite(&page) {
        return None;
    }
    let servers = page.get("servers")?.as_list()?;
    let metadata = page
        .get("metadata")
        .filter(|value| value.as_dict().is_some())?;
    if servers.len() > MAX_SERVERS {
        return None;
    }
    let results = servers
        .iter()
        .map(server_result)
        .collect::<Option<Vec<Value>>>()?;
    Some(json!({
        "results": results,
        "source": SOURCE,
        "coverage": "search-page",
        "count": results.len(),
        "more_available": matches!(metadata.get("nextCursor"), Some(PyVal::Str(_))),
    }))
}

/// Whether no number in `value` is NaN or infinite.
fn finite(value: &PyVal) -> bool {
    match value {
        PyVal::Float(number) => number.is_finite(),
        PyVal::List(items) => items.iter().all(finite),
        PyVal::Dict(entries) => entries.iter().all(|(_, member)| finite(member)),
        _ => true,
    }
}

fn server_result(entry: &PyVal) -> Option<Value> {
    let server = entry
        .get("server")
        .filter(|value| value.as_dict().is_some())?;
    let official = entry
        .get("_meta")
        .and_then(|meta| meta.get(OFFICIAL_META))
        .filter(|value| value.as_dict().is_some())?;
    let name = server
        .get("name")
        .and_then(PyVal::as_str)
        .filter(|name| server_name(name))?;
    let version = server
        .get("version")
        .and_then(PyVal::as_str)
        .filter(|version| version.chars().count() <= 80)?;
    let title = server.get("title").and_then(PyVal::as_str).unwrap_or(name);
    let description = server
        .get("description")
        .and_then(PyVal::as_str)
        .unwrap_or("");
    let remotes = list_or_empty(server.get("remotes"))?;
    let packages = list_or_empty(server.get("packages"))?;
    let status = official
        .get("status")
        .and_then(PyVal::as_str)
        .filter(|status| matches!(*status, "active" | "deprecated"))
        .unwrap_or("unknown");
    Some(json!({
        "name": name,
        "version": version,
        "title": title.chars().take(120).collect::<String>(),
        "description": description.chars().take(500).collect::<String>(),
        "status": status,
        "remote_endpoints": remotes.iter().take(MAX_REMOTES).filter_map(remote_endpoint).collect::<Vec<_>>(),
        "package_count": packages.len().min(MAX_PACKAGE_COUNT),
        "package_options": package_options(packages),
        "provenance": SOURCE,
        "verified_package": false,
        "configured": false,
        "installed": false,
    }))
}

/// A member that defaults to an empty list when absent; any other non-list
/// value refuses the page.
fn list_or_empty(value: Option<&PyVal>) -> Option<&[PyVal]> {
    match value {
        None => Some(&[]),
        Some(value) => value.as_list(),
    }
}

fn remote_endpoint(remote: &PyVal) -> Option<Value> {
    let url = remote
        .get("url")
        .and_then(PyVal::as_str)
        .filter(|url| url.chars().count() <= 2048 && url.starts_with("https://"))?;
    let transport = remote
        .get("type")
        .and_then(PyVal::as_str)
        .filter(|transport| matches!(*transport, "streamable-http" | "sse"))?;
    Some(json!({ "url": url, "transport": transport }))
}

fn package_options(packages: &[PyVal]) -> Vec<Value> {
    let mut options: Vec<Value> = Vec::new();
    for option in packages
        .iter()
        .take(MAX_PACKAGES)
        .filter_map(package_option)
    {
        if !options.contains(&option) {
            options.push(option);
        }
    }
    options
}

fn package_option(package: &PyVal) -> Option<Value> {
    let text = |key: &str| package.get(key).and_then(PyVal::as_str);
    let identifier = text("identifier")?;
    let version = text("version").filter(|version| pinned(version))?;
    if package
        .get("transport")
        .and_then(|transport| transport.get("type"))
        .and_then(PyVal::as_str)
        != Some("stdio")
    {
        return None;
    }
    let raw_arguments = list_or_empty(package.get("packageArguments"))?;
    // Empty declarations are inert; any populated environment or runtime
    // arguments need a separate reviewed setup flow before this recipe can be
    // offered.
    if raw_arguments.len() > MAX_PACKAGE_ARGUMENTS
        || package
            .get("environmentVariables")
            .is_some_and(PyVal::truthy)
        || package.get("runtimeArguments").is_some_and(PyVal::truthy)
    {
        return None;
    }
    let default_registry = |origin: &str| match package.get("registryBaseUrl") {
        None | Some(PyVal::Null) => true,
        Some(base) => base.as_str() == Some(origin),
    };
    let registry_type = text("registryType")?;
    let (command, mut arguments) = match (registry_type, text("runtimeHint")) {
        ("npm", Some("npx"))
            if default_registry("https://registry.npmjs.org") && npm_name(identifier) =>
        {
            (
                "npx",
                vec!["-y".to_owned(), format!("{identifier}@{version}")],
            )
        }
        ("pypi", Some("uvx")) if default_registry("https://pypi.org") && pypi_name(identifier) => {
            ("uvx", vec![format!("{identifier}@{version}")])
        }
        _ => return None,
    };
    for argument in raw_arguments {
        let value = argument
            .get("type")
            .and_then(PyVal::as_str)
            .filter(|kind| *kind == "positional")
            .and_then(|_| argument.get("value"))
            .and_then(PyVal::as_str)
            .filter(|value| literal_argument(value))?;
        arguments.push(value.to_owned());
    }
    Some(json!({
        "registry_type": registry_type,
        "identifier": identifier,
        "version": version,
        "command": command,
        "arguments": arguments,
        "transport": "stdio",
        "verified_package": false,
    }))
}

fn literal_argument(value: &str) -> bool {
    (1..=160).contains(&value.chars().count())
        && !value.chars().any(|c| c < ' ')
        && !value.contains("${")
}

/// `[A-Za-z0-9][A-Za-z0-9._/-]{0,255}`.
fn server_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 256
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

/// `[0-9][A-Za-z0-9._+-]{0,79}`: a version that starts with a digit, so not
/// a dist-tag such as `latest`.
fn pinned(version: &str) -> bool {
    let mut chars = version.chars();
    version.len() <= 80
        && chars.next().is_some_and(|first| first.is_ascii_digit())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// `(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*`.
fn npm_name(identifier: &str) -> bool {
    match identifier.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, name)| npm_segment(scope) && npm_segment(name)),
        None => npm_segment(identifier),
    }
}

fn npm_segment(segment: &str) -> bool {
    let lower = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let mut chars = segment.chars();
    chars.next().is_some_and(lower) && chars.all(|c| lower(c) || matches!(c, '.' | '_' | '-'))
}

/// `[A-Za-z0-9][A-Za-z0-9._-]*`.
fn pypi_name(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
#[path = "mcp_registry_page_tests.rs"]
mod tests;
