//! What a Hermes install reads: the MCP servers configured in `config.yaml`
//! and `mcp_servers.json`, the overlay entry Guard launches for each, the
//! manifest's server summary and the Guard Cloud consumer URL from the store.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};

use super::files::{text, Doc};
use super::{path_text, Ctx, Failure, Step};
use crate::guard_store_json::py_strip;
use crate::hermes_inspect::{inspect_config, Syntax};
use crate::pyjson::{self, PyVal};

const SERVER_PREFIX: &str = "guard-";
const PROXY_MARKERS: [[&str; 5]; 2] = [
    [
        "-m",
        "codex_plugin_scanner.cli",
        "hermes",
        "mcp-proxy",
        "--guard-home",
    ],
    [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "hermes-mcp-proxy",
        "--guard-home",
    ],
];

/// A source server, keyed `yaml:<name>` or `json:<name>`.
pub(super) type Source = (String, Vec<(String, PyVal)>);
type Entries = Vec<(String, PyVal)>;

fn field<'a>(server: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    server
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `str(value or default)`; a mapping or list falls back to the default.
fn str_or(value: Option<&PyVal>, default: &str) -> String {
    value
        .filter(|value| value.truthy())
        .and_then(PyVal::scalar_text)
        .unwrap_or_else(|| default.to_owned())
}

fn url(server: &[(String, PyVal)]) -> Option<&str> {
    field(server, "url").and_then(PyVal::as_str)
}

/// The complete mapping in a config, or the error Python raised.
fn parsed(ctx: &Ctx, path: &Path, syntax: Syntax) -> Step<Entries> {
    let inspection = inspect_config(&ctx.absolute(path), syntax);
    let reason = match inspection {
        Ok(inspection) => match inspection.payload.filter(|_| inspection.file.complete) {
            Some(payload) => return Ok(payload),
            None => inspection.reason.unwrap_or("config_parse_error"),
        },
        Err(_) => "file_unreadable",
    };
    Err(Failure::Refusal(format!(
        "Hermes config inspection failed for {}: {reason}",
        path_text(path)
    )))
}

/// The `mcp_servers` mapping of a parsed `config.yaml`, mapping entries only.
pub(super) fn yaml_servers(payload: &[(String, PyVal)]) -> Entries {
    match field(payload, "mcp_servers") {
        Some(PyVal::Dict(servers)) => servers
            .iter()
            .filter(|(_, config)| config.as_dict().is_some())
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// `_load_mcp_server_sources`: enabled servers Guard did not generate.
pub(super) fn load_sources(ctx: &Ctx, home: &Path) -> Step<Vec<Source>> {
    let mut sources = Vec::new();
    let yaml = home.join("config.yaml");
    let json_path = home.join("mcp_servers.json");
    let mut found = Vec::new();
    if ctx.absolute(&yaml).is_file() {
        found.push((
            "yaml",
            &yaml,
            yaml_servers(&parsed(ctx, &yaml, Syntax::Yaml)?),
        ));
    }
    if ctx.absolute(&json_path).is_file() {
        let payload = parsed(ctx, &json_path, Syntax::Json)?;
        let servers = payload
            .into_iter()
            .filter(|(_, config)| config.as_dict().is_some())
            .collect();
        found.push(("json", &json_path, servers));
    }
    for (source, path, servers) in found {
        for (name, config) in servers {
            let config = config.as_dict().unwrap_or_default();
            if matches!(field(config, "enabled"), Some(PyVal::Bool(false)))
                || name.starts_with(SERVER_PREFIX)
            {
                continue;
            }
            let mut entry = Doc::default();
            entry
                .set("name", text(name.clone()))
                .set("source", text(source))
                .set("config_path", text(path_text(path)))
                .spread(config);
            sources.push((format!("{source}:{name}"), entry.0));
        }
    }
    Ok(sources)
}

fn manifest_args(server: &[(String, PyVal)]) -> Vec<String> {
    field(server, "args")
        .and_then(PyVal::as_list)
        .map(|args| args.iter().filter_map(PyVal::scalar_text).collect())
        .unwrap_or_default()
}

fn manifest_env(server: &[(String, PyVal)]) -> Vec<(String, String)> {
    field(server, "env")
        .and_then(PyVal::as_dict)
        .map(|env| {
            env.iter()
                .filter_map(|(key, value)| value.scalar_text().map(|value| (key.clone(), value)))
                .collect()
        })
        .unwrap_or_default()
}

fn strings(values: Vec<String>) -> PyVal {
    PyVal::List(values.into_iter().map(text).collect())
}

fn pairs(values: Vec<(String, String)>) -> PyVal {
    PyVal::Dict(
        values
            .into_iter()
            .map(|(key, value)| (key, text(value)))
            .collect(),
    )
}

fn optional(value: Option<&str>) -> PyVal {
    value.map_or(PyVal::Null, text)
}

/// `_manifest_servers`: what each source launches, without its secrets' shape.
pub(super) fn manifest_servers(sources: &[Source]) -> PyVal {
    let servers = sources.iter().map(|(key, server)| {
        let command = field(server, "command").and_then(PyVal::as_str);
        let headers = field(server, "headers")
            .and_then(PyVal::as_dict)
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|value| (name.clone(), value.to_owned()))
                    })
                    .collect()
            });
        let mut entry = Doc::default();
        entry
            .set("name", text(str_or(field(server, "name"), key)))
            .set("source", text(str_or(field(server, "source"), "unknown")))
            .set(
                "config_path",
                text(str_or(field(server, "config_path"), "")),
            )
            .set(
                "transport",
                text(if url(server).is_some() {
                    "http"
                } else {
                    "stdio"
                }),
            )
            .set("command", optional(command))
            .set("args", strings(manifest_args(server)))
            .set("url", optional(url(server)))
            .set("env", pairs(manifest_env(server)))
            .set("headers", pairs(headers.unwrap_or_default()));
        (key.clone(), entry.value())
    });
    PyVal::Dict(servers.collect())
}

/// The local stdio servers whose proxy launch Python builds, in order.
fn stdio(sources: &[Source]) -> impl Iterator<Item = &Source> {
    sources.iter().filter(|(_, server)| {
        let command = field(server, "command").and_then(PyVal::as_str);
        url(server).is_none() && command.is_some_and(|command| !py_strip(command).is_empty())
    })
}

/// The `launchers` reply: each stdio server's `ManagedMcpServer` fields.
fn launcher_requests(sources: &[Source]) -> Value {
    let requests = stdio(sources).map(|(key, server)| {
        json!({
            "name": str_or(field(server, "name"), key),
            "config_path": str_or(field(server, "config_path"), ""),
            "command": field(server, "command").and_then(PyVal::as_str),
            "args": manifest_args(server),
            "env": manifest_env(server).into_iter().map(|(key, value)| [key, value]).collect::<Vec<_>>(),
        })
    });
    Value::Array(requests.collect())
}

/// `proxy_launcher_entry` for each stdio server and the Guard CLI launcher,
/// as Python answered the `launchers` reply for these exact requests.
fn launchers(
    fields: &serde_json::Map<String, Value>,
    sources: &[Source],
) -> Step<(String, Vec<Entries>)> {
    let requests = launcher_requests(sources);
    let answer = fields
        .get("launchers")
        .and_then(Value::as_str)
        .and_then(|answer| pyjson::parse(answer).ok())
        .filter(|answer| {
            answer.get("requests").and_then(PyVal::to_json).as_ref() == Some(&requests)
        });
    let Some(answer) = answer else {
        return Err(Failure::Reply(json!({ "launchers": requests })));
    };
    let guard_cli = answer
        .get("guard_cli")
        .and_then(PyVal::as_str)
        .ok_or(Failure::Invalid)?;
    let entries = answer
        .get("entries")
        .and_then(PyVal::as_list)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|entry| entry.as_dict().map(<[_]>::to_vec).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    if entries.len() != requests.as_array().map_or(0, Vec::len) {
        return Err(Failure::Invalid);
    }
    Ok((guard_cli.to_owned(), entries))
}

/// The `hermes mcp-proxy` launch for a remote server or one without a command.
fn proxy_args(ctx: &Ctx, key: &str) -> PyVal {
    let mut args: Vec<String> = [
        "-m",
        "codex_plugin_scanner.cli",
        "hermes",
        "mcp-proxy",
        "--guard-home",
    ]
    .iter()
    .map(|part| (*part).to_owned())
    .collect();
    args.push(path_text(&ctx.guard_home));
    if !ctx.default_home() {
        args.extend(["--home".into(), path_text(&ctx.home)]);
    }
    if let Some(workspace) = &ctx.workspace {
        args.extend(["--workspace".into(), path_text(workspace)]);
    }
    args.extend(["--server".into(), key.to_owned(), "--stdio".into()]);
    strings(args)
}

/// `_overlay_servers`: the overlay entry for each source under its overlay name.
pub(super) fn overlay(
    ctx: &Ctx,
    fields: &serde_json::Map<String, Value>,
    sources: &[Source],
) -> Step<Entries> {
    if sources.is_empty() {
        return Ok(Vec::new());
    }
    let (guard_cli, entries) = launchers(fields, sources)?;
    let request: Vec<Value> = sources
        .iter()
        .map(|(key, server)| json!([key, field(server, "name").and_then(PyVal::as_str)]))
        .collect();
    let answer =
        crate::hermes_install_plan::dispatch(&json!({"op": "overlay_names", "servers": request}))
            .map_err(|_| Failure::Invalid)?;
    let names = super::hermes::strings(answer.get("names"));
    if names.len() != sources.len() {
        return Err(Failure::Invalid);
    }
    let mut launched = entries.into_iter();
    let mut overlay = Vec::with_capacity(sources.len());
    for (name, source) in names.into_iter().zip(sources) {
        let (key, server) = source;
        let mut entry = Doc::default();
        if stdio(std::slice::from_ref(source)).next().is_some() {
            entry.spread(&launched.next().ok_or(Failure::Invalid)?);
        } else {
            entry
                .set("command", text(guard_cli.clone()))
                .set("args", proxy_args(ctx, key));
        }
        let mut metadata = Doc::default();
        metadata
            .set("guard_server_key", text(key.clone()))
            .set(
                "guard_transport",
                text(if url(server).is_some() {
                    "remote"
                } else {
                    "stdio"
                }),
            )
            .set(
                "guard_config_path",
                text(str_or(field(server, "config_path"), "")),
            );
        entry
            .set("transport", text("stdio"))
            .set("metadata", metadata.value());
        overlay.push((name, entry.value()));
    }
    Ok(overlay)
}

/// `_resolve_guard_consumer_base_url`: from the connected OAuth issuer in the
/// Guard store, the default when there is none or it cannot be read.
pub(super) fn consumer_base_url(ctx: &Ctx) -> String {
    let path = ctx.absolute(&ctx.guard_home.join("guard.db"));
    let stored = path.exists().then(|| stored_credentials(&path)).flatten();
    let issuer = stored
        .and_then(|payload| pyjson::parse(&payload).ok())
        .and_then(|payload| {
            payload
                .get("issuer")
                .and_then(PyVal::as_str)
                .map(str::to_owned)
        });
    crate::hermes_install_plan::consumer_base_url(issuer.as_deref())
}

fn stored_credentials(path: &Path) -> Option<String> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags).ok()?;
    connection
        .query_row(
            "select payload_json from sync_state where state_key = 'oauth_local_credentials'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .flatten()
}

/// `_guard_proxy_home`: the Guard home a generated proxy launch names, either
/// the Python argv or the native relay's `mcp-relay <python>` prefix over it.
fn proxy_home(args: &[PyVal]) -> Option<&str> {
    PROXY_MARKERS
        .iter()
        .find_map(|marker| {
            [0, 2].into_iter().find_map(|start| {
                let window = args.get(start..start + marker.len())?;
                let matches = window
                    .iter()
                    .zip(marker)
                    .all(|(arg, part)| arg.as_str() == Some(part));
                matches.then(|| args.get(start + marker.len())).flatten()
            })
        })
        .and_then(PyVal::as_str)
}

/// `_safe_legacy_cleanup_values`: for a manifest that does not authenticate,
/// the servers whose proxy launch names this Guard home, and the current
/// `guard` section.
pub(super) fn legacy_cleanup(ctx: &Ctx, config: &Path) -> (Vec<String>, Option<PyVal>) {
    let Ok(inspection) = inspect_config(&ctx.absolute(config), Syntax::Yaml) else {
        return (Vec::new(), None);
    };
    let Some(payload) = inspection.payload.filter(|_| inspection.file.complete) else {
        return (Vec::new(), None);
    };
    let homes = [
        path_text(&ctx.guard_home),
        path_text(&ctx.resolved(&ctx.guard_home)),
    ];
    let servers = match field(&payload, "mcp_servers") {
        Some(PyVal::Dict(servers)) => servers.as_slice(),
        _ => &[],
    };
    let managed = servers
        .iter()
        .filter(|(_, config)| {
            config
                .get("args")
                .and_then(PyVal::as_list)
                .and_then(proxy_home)
                .is_some_and(|home| homes.iter().any(|candidate| candidate == home))
        })
        .map(|(name, _)| name.clone())
        .collect();
    let guard = field(&payload, "guard")
        .filter(|guard| guard.as_dict().is_some())
        .cloned();
    (managed, guard)
}
