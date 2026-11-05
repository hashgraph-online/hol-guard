//! `runner_authority` kind `harness_mcp_discovery`: the stdio MCP server
//! grouping, identities, redacted launch labels and observation matching that
//! `guard/adapters/harness_mcp_discovery.py` computed before they moved here.
//!
//! Python keeps the harness reads, env values and store writes. One `group`
//! request carries every server a discovery pass found; the answer names each
//! kept server by the index of the entry that first declared it. One `match`
//! request answers the index of the single server an observation names.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_strip;
use crate::context_digest_local_cli::python_path_name;
use crate::copilot_hook_config::{list2cmdline, shlex_join};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
#[path = "harness_mcp_select.rs"]
mod select;
#[path = "harness_mcp_upstream.rs"]
mod upstream;

const MAX_SERVERS: usize = 16_384;
/// `UnlistedCliIdentity.name` keeps this many characters.
const NAME_CHARS: usize = 120;
/// A presentation label keeps this many characters; the launch never shrinks.
const LABEL_CHARS: usize = 160;
const REDACTED: &str = "*****";
const SECRET_FLAG_NAMES: [&str; 11] = [
    "access-token",
    "api-key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "client-secret",
    "password",
    "passwd",
    "secret",
    "token",
];
const SECRET_FLAG_SUFFIXES: [&str; 3] = ["-token", "-secret", "-password"];
const EMBEDDED_SECRETS: [&str; 5] = ["apikey=", "api_key=", "api-key=", "token=", "secret="];
const GROUP_KEYS: [&str; 4] = ["op", "windows", "limit", "servers"];
const SERVER_KEYS: [&str; 11] = [
    "harness",
    "label",
    "name",
    "command",
    "args",
    "source_scope",
    "config_path",
    "identity_hash",
    "package_name",
    "server_command",
    "args_hash",
];
const MATCH_KEYS: [&str; 3] = ["op", "servers", "query"];
const OBSERVED_KEYS: [&str; 5] = [
    "cli_id",
    "identity_hash",
    "command",
    "args_hash",
    "source_label",
];
const QUERY_KEYS: [&str; 5] = [
    "cli_id",
    "server_command",
    "args_hash",
    "server_identity_hash",
    "source_label",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("group") => group(map),
        Some("match") => matching(map),
        Some("upstream") => upstream::upstream(map),
        Some("select") => select::select(map),
        Some("server_id") => select::server_ids(map),
        _ => Err(ERR_INVALID),
    }
}

/// `build_mcp_connection_identity`: the configuration hash and the identity
/// hash of one configured connection.
pub(crate) fn connection_identity_hash(
    host: &str,
    source_scope: &str,
    config_path: &str,
    server_name: &str,
    server_identity_hash: &str,
    error: &'static str,
) -> Result<(String, String), &'static str> {
    let configuration_hash = guard_policy_snapshot::digest_bytes(config_path.as_bytes());
    let payload = json!({
        "version": 1,
        "host": host,
        "source_scope": source_scope,
        "configuration_hash": configuration_hash,
        "server_name": server_name,
        "server_identity_hash": server_identity_hash,
    });
    let mut bytes = Vec::with_capacity(256);
    guard_contracts::write_canonical_json_with_limit(&payload, &mut bytes, usize::MAX, error)?;
    let identity_hash = guard_policy_snapshot::digest_bytes(&bytes);
    Ok((configuration_hash, identity_hash))
}

struct Server<'a> {
    harness: &'a str,
    label: &'a str,
    name: &'a str,
    command: &'a str,
    args: Vec<&'a str>,
    source_scope: &'a str,
    config_path: &'a str,
    identity_hash: &'a str,
    package_name: Option<&'a str>,
    server_command: &'a str,
    args_hash: &'a str,
}

struct Group {
    index: usize,
    name: String,
    identity_hash: String,
    configuration_hash: String,
    example_label: String,
    launch_command: String,
    labels: Vec<String>,
    server_command: String,
    args_hash: String,
}

struct Ranked {
    label_key: String,
    name_key: String,
    source_label: String,
    group: Group,
}

fn group(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &GROUP_KEYS)?;
    let windows = map["windows"].as_bool().ok_or(ERR_INVALID)?;
    let limit = map["limit"]
        .as_u64()
        .and_then(|limit| usize::try_from(limit).ok())
        .ok_or(ERR_INVALID)?;
    let entries = bounded_list(&map["servers"])?;
    let mut groups: Vec<Group> = Vec::new();
    let mut by_hash: HashMap<String, usize> = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let server = server(entry)?;
        if py_strip(server.command).is_empty() {
            continue;
        }
        let (configuration_hash, identity_hash) = connection_identity_hash(
            server.harness,
            server.source_scope,
            server.config_path,
            server.name,
            server.identity_hash,
            ERR_INVALID,
        )?;
        if let Some(position) = by_hash.get(&identity_hash).copied() {
            let labels = &mut groups[position].labels;
            if !labels.iter().any(|label| label == server.label) {
                labels.push(server.label.to_owned());
            }
            continue;
        }
        by_hash.insert(identity_hash.clone(), groups.len());
        let mut tokens = vec![server.command];
        tokens.extend(server.args.iter().copied());
        groups.push(Group {
            index,
            name: display_name(&server),
            identity_hash,
            configuration_hash,
            example_label: launch_label(&tokens, windows),
            launch_command: join_tokens(&tokens, windows),
            labels: vec![server.label.to_owned()],
            server_command: server.server_command.to_owned(),
            args_hash: server.args_hash.to_owned(),
        });
    }
    let mut ranked: Vec<Ranked> = groups
        .into_iter()
        .map(|group| {
            let source_label = join_labels(&group.labels);
            Ranked {
                label_key: source_label.to_lowercase(),
                name_key: group.name.to_lowercase(),
                source_label,
                group,
            }
        })
        .collect();
    ranked.sort_by(|left, right| {
        left.label_key
            .cmp(&right.label_key)
            .then_with(|| left.name_key.cmp(&right.name_key))
            .then_with(|| left.group.server_command.cmp(&right.group.server_command))
            .then_with(|| left.group.args_hash.cmp(&right.group.args_hash))
    });
    ranked.truncate(limit);
    let servers: Vec<Value> = ranked.into_iter().map(answer).collect();
    Ok(json!({ "servers": servers }))
}

fn answer(ranked: Ranked) -> Value {
    let group = ranked.group;
    json!({
        "index": group.index,
        "cli_id": format!("local-cli.mcp-{}", group.identity_hash),
        "name": group.name,
        "identity_hash": group.identity_hash,
        "configuration_hash": group.configuration_hash,
        "example_label": group.example_label,
        "launch_command": group.launch_command,
        "source_label": ranked.source_label,
    })
}

fn server(value: &Value) -> Result<Server<'_>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    exact_keys(map, &SERVER_KEYS)?;
    let args = map["args"]
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|arg| arg.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<&str>, &'static str>>()?;
    Ok(Server {
        harness: text(map, "harness")?,
        label: text(map, "label")?,
        name: text(map, "name")?,
        command: text(map, "command")?,
        args,
        source_scope: text(map, "source_scope")?,
        config_path: text(map, "config_path")?,
        identity_hash: text(map, "identity_hash")?,
        package_name: optional_text(map, "package_name")?,
        server_command: text(map, "server_command")?,
        args_hash: text(map, "args_hash")?,
    })
}

/// The configured name, else the package, else the command's file name.
fn display_name(server: &Server<'_>) -> String {
    let stripped = py_strip(server.name);
    let package = server.package_name.unwrap_or("");
    let name = if !stripped.is_empty() {
        stripped.to_owned()
    } else if !package.is_empty() {
        package.to_owned()
    } else {
        python_path_name(server.command)
    };
    if name.is_empty() {
        return "mcp-server".to_owned();
    }
    name.chars().take(NAME_CHARS).collect()
}

/// `_join_labels`: up to three distinct labels, then a count.
pub(crate) fn join_labels(labels: &[String]) -> String {
    let mut unique: Vec<&str> = Vec::new();
    for label in labels {
        if !py_strip(label).is_empty() && !unique.contains(&label.as_str()) {
            unique.push(label.as_str());
        }
    }
    if unique.len() <= 3 {
        return unique.join(", ");
    }
    format!(
        "{}, {}, and {} more",
        unique[0],
        unique[1],
        unique.len() - 2
    )
}

/// `_raw_launch_label`: the exact argv, quoted for the host shell.
fn join_tokens(tokens: &[&str], windows: bool) -> String {
    if windows {
        return list2cmdline(tokens);
    }
    shlex_join(tokens)
}

/// `_launch_label`: the redacted argv, shortened for display.
pub(crate) fn launch_label(tokens: &[&str], windows: bool) -> String {
    let redacted = redact_launch_tokens(tokens);
    let borrowed: Vec<&str> = redacted.iter().map(String::as_str).collect();
    join_tokens(&borrowed, windows)
        .chars()
        .take(LABEL_CHARS)
        .collect()
}

/// `_redact_launch_tokens`: hide secret flag values and embedded assignments.
pub(crate) fn redact_launch_tokens(tokens: &[&str]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(tokens.len());
    let mut hide_next = false;
    for token in tokens {
        if hide_next {
            redacted.push(REDACTED.to_owned());
            hide_next = false;
            continue;
        }
        if let Some((key, _value)) = token.split_once('=') {
            if is_secret_flag(key) {
                redacted.push(format!("{key}={REDACTED}"));
                continue;
            }
        }
        if token.starts_with('-') && is_secret_flag(token) {
            redacted.push((*token).to_owned());
            hide_next = true;
            continue;
        }
        redacted.push(redact_embedded_assignment(token));
    }
    redacted
}

fn redact_embedded_assignment(value: &str) -> String {
    let lower = value.to_lowercase();
    if EMBEDDED_SECRETS.iter().any(|secret| lower.contains(secret)) {
        if let Some((key, _rest)) = value.split_once('=') {
            return format!("{key}={REDACTED}");
        }
    }
    value.to_owned()
}

pub(crate) fn is_secret_flag(value: &str) -> bool {
    let name = py_strip(value)
        .trim_start_matches('-')
        .to_lowercase()
        .replace('_', "-");
    SECRET_FLAG_NAMES.contains(&name.as_str())
        || SECRET_FLAG_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

struct Observed<'a> {
    cli_id: &'a str,
    identity_hash: &'a str,
    command: &'a str,
    args_hash: &'a str,
    source_label: &'a str,
}

/// The stored observation; Python treats an empty string as absent.
struct Query<'a> {
    cli_id: Option<&'a str>,
    server_command: Option<&'a str>,
    args_hash: Option<&'a str>,
    server_identity_hash: Option<&'a str>,
    source_label: Option<&'a str>,
}

fn matching(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &MATCH_KEYS)?;
    let servers = bounded_list(&map["servers"])?
        .iter()
        .map(observed)
        .collect::<Result<Vec<Observed<'_>>, &'static str>>()?;
    let query = map["query"].as_object().ok_or(ERR_INVALID)?;
    exact_keys(query, &QUERY_KEYS)?;
    let query = Query {
        cli_id: present(query, "cli_id")?,
        server_command: present(query, "server_command")?,
        args_hash: present(query, "args_hash")?,
        server_identity_hash: present(query, "server_identity_hash")?,
        source_label: present(query, "source_label")?,
    };
    Ok(json!({ "index": pick(&servers, &query) }))
}

fn observed(value: &Value) -> Result<Observed<'_>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    exact_keys(map, &OBSERVED_KEYS)?;
    Ok(Observed {
        cli_id: text(map, "cli_id")?,
        identity_hash: text(map, "identity_hash")?,
        command: text(map, "command")?,
        args_hash: text(map, "args_hash")?,
        source_label: text(map, "source_label")?,
    })
}

/// `discovered_server_for_observation`: the one server the observation names.
fn pick(servers: &[Observed<'_>], query: &Query<'_>) -> Option<usize> {
    let found = if let Some(cli_id) = query.cli_id {
        let direct = positions(servers, |server| {
            server.cli_id == cli_id
                && same_or_absent(server.identity_hash, query.server_identity_hash)
        });
        if direct.is_empty() && legacy_launch(cli_id, query) {
            positions(servers, |server| {
                query.server_identity_hash == Some(server.identity_hash)
                    && query.server_command == Some(server.command)
                    && query.args_hash == Some(server.args_hash)
                    && query.source_label == Some(server.source_label)
            })
        } else {
            direct
        }
    } else if let Some(hash) = query.server_identity_hash {
        positions(servers, |server| server.identity_hash == hash)
    } else {
        match (query.server_command, query.args_hash) {
            (Some(command), Some(args_hash)) => positions(servers, |server| {
                server.command == command && server.args_hash == args_hash
            }),
            _ => Vec::new(),
        }
    };
    if found.len() == 1 {
        return Some(found[0]);
    }
    None
}

fn same_or_absent(value: &str, expected: Option<&str>) -> bool {
    match expected {
        Some(expected) => value == expected,
        None => true,
    }
}

/// A pre-connection id (`local-cli.mcp-<server hash prefix>`) still finds its
/// server by the full launch it recorded.
fn legacy_launch(cli_id: &str, query: &Query<'_>) -> bool {
    match (
        query.server_identity_hash,
        query.server_command,
        query.args_hash,
        query.source_label,
    ) {
        (Some(hash), Some(_), Some(_), Some(_)) => {
            let prefix: String = hash.chars().take(8).collect();
            cli_id.strip_prefix("local-cli.mcp-") == Some(prefix.as_str())
        }
        _ => false,
    }
}

fn positions<F>(servers: &[Observed<'_>], keep: F) -> Vec<usize>
where
    F: Fn(&Observed<'_>) -> bool,
{
    let mut found = Vec::new();
    for (position, server) in servers.iter().enumerate() {
        if keep(server) {
            found.push(position);
        }
    }
    found
}

fn bounded_list(value: &Value) -> Result<&Vec<Value>, &'static str> {
    let list = value.as_array().ok_or(ERR_INVALID)?;
    if list.len() > MAX_SERVERS {
        return Err(ERR_INVALID);
    }
    Ok(list)
}

fn exact_keys(map: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    Ok(())
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn optional_text<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        _ => Err(ERR_INVALID),
    }
}

/// A query field that is a non-empty string, else absent.
fn present<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, &'static str> {
    let value = optional_text(map, key)?;
    Ok(value.filter(|value| !value.is_empty()))
}
