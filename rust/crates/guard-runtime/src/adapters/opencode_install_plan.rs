//! `runner_authority` kind `opencode_install_plan`: the `permission` and
//! `mcp` values Guard writes to the OpenCode root config and the runtime
//! overlay (`_persisted_mcp_with_guard_companions`, `_proxy_permission_rules`,
//! `_proxy_mcp_overrides` and `runtime_overlay` before they moved here).
//! serde_json drops object order, so every answer object is a build spec
//! (`value`, `ref`, `object`, `merge`, `launch`) that
//! `guard/adapters/opencode_install_plan.py` evaluates over its own objects.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::opencode_proxy_entry::{is_guard_entry, restored_command};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const REQUEST_KEYS: [&str; 9] = [
    "op",
    "workspace",
    "servers",
    "skipped",
    "artifacts",
    "workspace_servers",
    "permission",
    "mcp",
    "mcp_keys",
];
const SERVER_KEYS: [&str; 8] = [
    "name",
    "source_scope",
    "command",
    "args",
    "env",
    "enabled",
    "proxy_environment",
    "source",
];
/// `GUARD_MCP_COMPANION_PREFIX`.
const COMPANION_PREFIX: &str = "hol-guard::";
const OPENCODE_SCHEMA: &str = "https://opencode.ai/config.json";
/// `_DEFAULT_BASH_PERMISSION`, in order.
const DEFAULT_BASH: [(&str, &str); 11] = [
    ("*", "allow"),
    ("git checkout *", "deny"),
    ("git checkout", "deny"),
    ("git revert *", "deny"),
    ("git revert", "deny"),
    ("git restore *", "deny"),
    ("git restore", "deny"),
    ("git reset *", "deny"),
    ("git reset", "deny"),
    ("rm -rf *", "deny"),
    ("rm -r *", "deny"),
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.get("op").and_then(Value::as_str) != Some("plan")
        || map.len() != REQUEST_KEYS.len()
        || !REQUEST_KEYS.iter().all(|key| map.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    let workspace = map["workspace"].as_bool().ok_or(ERR_INVALID)?;
    let servers = map["servers"]
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(parse_server)
        .collect::<Result<Vec<Server<'_>>, &'static str>>()?;
    let skipped = texts(&map["skipped"])?;
    let artifacts = texts(&map["artifacts"])?;
    let workspace_servers: BTreeSet<&str> = texts(&map["workspace_servers"])?.into_iter().collect();
    let mcp_keys = texts(&map["mcp_keys"])?;
    check_keys(&map["mcp"], &mcp_keys)?;
    let managed: Vec<usize> = servers
        .iter()
        .enumerate()
        .filter(|(_, server)| !server.name.starts_with(COMPANION_PREFIX))
        .map(|(index, _)| index)
        .collect();
    let plan = Plan {
        workspace,
        servers,
        managed,
        workspace_servers,
    };
    let rules = plan.rules();
    let permission = permission_spec(&map["permission"], &rules);
    let mcp = plan.mcp_spec(&map["mcp"], &mcp_keys);
    let overlay = plan.overlay_spec(&rules);
    Ok(json!({
        "managed": plan.managed,
        "skipped": skipped_names(&skipped, &artifacts),
        "permission": permission,
        "mcp": mcp,
        "overlay": overlay,
    }))
}

/// A list of strings.
fn texts(value: &Value) -> Result<Vec<&str>, &'static str> {
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect()
}

/// An object whose values are all strings.
fn text_map(value: &Value) -> Result<&Map<String, Value>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    map.values()
        .all(|item| item.is_string())
        .then_some(map)
        .ok_or(ERR_INVALID)
}

/// `mcp_keys` is the exact key order of an `mcp` object, and empty otherwise.
fn check_keys(mcp: &Value, keys: &[&str]) -> Result<(), &'static str> {
    let distinct: BTreeSet<&str> = keys.iter().copied().collect();
    let valid = match mcp.as_object() {
        Some(object) => {
            distinct.len() == keys.len()
                && keys.len() == object.len()
                && keys.iter().all(|key| object.contains_key(*key))
        }
        None => keys.is_empty(),
    };
    valid.then_some(()).ok_or(ERR_INVALID)
}

/// One `ManagedMcpServer`, with its proxy environment and source entry.
struct Server<'a> {
    name: &'a str,
    scope: &'a str,
    command: &'a str,
    args: Vec<&'a str>,
    has_env: bool,
    has_proxy_env: bool,
    enabled: bool,
    source: Option<&'a Map<String, Value>>,
}

fn parse_server(value: &Value) -> Result<Server<'_>, &'static str> {
    let map = value.as_object().ok_or(ERR_INVALID)?;
    if map.len() != SERVER_KEYS.len() || !SERVER_KEYS.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let source = match &map["source"] {
        Value::Null => None,
        Value::Object(object) => Some(object),
        _ => return Err(ERR_INVALID),
    };
    Ok(Server {
        name: text_field(map, "name")?,
        scope: text_field(map, "source_scope")?,
        command: text_field(map, "command")?,
        args: texts(&map["args"])?,
        has_env: !text_map(&map["env"])?.is_empty(),
        has_proxy_env: !text_map(&map["proxy_environment"])?.is_empty(),
        enabled: map["enabled"].as_bool().ok_or(ERR_INVALID)?,
        source,
    })
}

/// The string at `key` of a server object.
fn text_field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

impl Server<'_> {
    fn project(&self) -> bool {
        self.scope == "project"
    }

    fn companion(&self) -> String {
        format!("{COMPANION_PREFIX}{}", self.name)
    }
}

/// `skipped_servers`: the skipped names, then the sorted companion-named
/// artifacts, each once.
fn skipped_names(skipped: &[&str], artifacts: &[&str]) -> Vec<String> {
    let companions: BTreeSet<&str> = artifacts
        .iter()
        .copied()
        .filter(|name| name.starts_with(COMPANION_PREFIX))
        .collect();
    let mut names: Vec<String> = Vec::new();
    for name in skipped.iter().copied().chain(companions) {
        if !names.iter().any(|seen| seen == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// An object under construction, with Python's assignment order: a new key
/// is appended, an existing key keeps its place.
#[derive(Default)]
struct Pairs {
    entries: Vec<(String, Value)>,
}

impl Pairs {
    fn set(&mut self, key: &str, spec: Value) {
        match self.entries.iter().position(|(name, _)| name == key) {
            Some(index) => self.entries[index].1 = spec,
            None => self.entries.push((key.to_owned(), spec)),
        }
    }

    fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, spec)| spec)
    }

    fn into_spec(self) -> Value {
        let pairs: Vec<Value> = self
            .entries
            .into_iter()
            .map(|(key, spec)| json!([key, spec]))
            .collect();
        json!(["object", pairs])
    }
}

fn value(literal: Value) -> Value {
    json!(["value", literal])
}

fn reference(path: &[Value]) -> Value {
    json!(["ref", path])
}

fn merge(parts: Vec<Value>) -> Value {
    json!(["merge", parts])
}

/// A fresh copy of the object at `path` (`dict(entry)`).
fn copy(path: &[Value]) -> Value {
    merge(vec![reference(path)])
}

fn child(path: &[Value], key: &str) -> Vec<Value> {
    let mut longer = path.to_vec();
    longer.push(json!(key));
    longer
}

/// `_merge_default_bash_permission` after `_coerce_permission_payload` and
/// the proxy rules: the coerced permission, the rules, then `bash`.
fn permission_spec(permission: &Value, rules: &[String]) -> Value {
    let root = vec![json!("permission")];
    let mut parts: Vec<Value> = Vec::new();
    let mut wildcard: Option<Value> = None;
    let mut bash: Option<&Value> = None;
    match permission {
        Value::Object(object) => {
            parts.push(copy(&root));
            bash = object.get("bash");
            if object.get("*").is_some_and(|star| star.is_string()) {
                wildcard = Some(reference(&child(&root, "*")));
            }
        }
        Value::String(_) => {
            let mut coerced = Pairs::default();
            coerced.set("*", reference(&root));
            parts.push(coerced.into_spec());
            wildcard = Some(reference(&root));
        }
        _ => {}
    }
    let mut asks = Pairs::default();
    for rule in rules {
        asks.set(rule, value(json!("ask")));
    }
    parts.push(asks.into_spec());
    let bash_path = child(&root, "bash");
    let bash_spec = match bash {
        Some(Value::String(_)) => default_bash(Some(reference(&bash_path))).into_spec(),
        Some(Value::Object(_)) => {
            merge(vec![default_bash(None).into_spec(), reference(&bash_path)])
        }
        _ => default_bash(wildcard).into_spec(),
    };
    let mut last = Pairs::default();
    last.set("bash", bash_spec);
    parts.push(last.into_spec());
    merge(parts)
}

/// `_DEFAULT_BASH_PERMISSION`, with `*` replaced when `star` is given.
fn default_bash(star: Option<Value>) -> Pairs {
    let mut pairs = Pairs::default();
    for (key, action) in DEFAULT_BASH {
        pairs.set(key, value(json!(action)));
    }
    if let Some(spec) = star {
        pairs.set("*", spec);
    }
    pairs
}

struct Plan<'a> {
    workspace: bool,
    servers: Vec<Server<'a>>,
    /// The servers Guard manages: none named like a companion.
    managed: Vec<usize>,
    workspace_servers: BTreeSet<&'a str>,
}

impl Plan<'_> {
    /// `should_skip_workspace_override`: a workspace entry of the same name
    /// shadows a non-project server (a global one keeps its companion).
    fn shadowed(&self, server: &Server<'_>, for_companion: bool) -> bool {
        if !self.workspace || server.project() || (for_companion && server.scope == "global") {
            return false;
        }
        self.workspace_servers.contains(server.name)
    }

    /// `_proxy_permission_rules`: the tool patterns kept on native ask.
    fn rules(&self) -> Vec<String> {
        let mut rules: Vec<String> = Vec::new();
        let mut add = |rule: String| {
            if !rules.contains(&rule) {
                rules.push(rule);
            }
        };
        for index in &self.managed {
            let server = &self.servers[*index];
            let companion = format!("{}_*", server.companion());
            if self.shadowed(server, false) {
                if server.enabled && !server.project() {
                    add(companion);
                }
                continue;
            }
            if !server.enabled {
                continue;
            }
            add(format!("{}_*", server.name));
            if !server.project() {
                add(companion);
            }
        }
        rules
    }

    /// A Guard proxy entry for one server (`companion` or `override`).
    fn proxy_entry(&self, index: usize, launch: &str) -> Value {
        let server = &self.servers[index];
        let mut entry = Pairs::default();
        entry.set("type", value(json!("local")));
        entry.set("command", json!(["launch", index, launch]));
        entry.set("enabled", value(json!(server.enabled)));
        if server.has_proxy_env {
            entry.set(
                "environment",
                reference(&[json!("servers"), json!(index), json!("proxy_environment")]),
            );
        }
        entry.into_spec()
    }

    /// `_persisted_mcp_with_guard_companions`.
    fn mcp_spec(&self, mcp: &Value, keys: &[&str]) -> Value {
        let mut persisted = persisted_entries(mcp, keys);
        for index in &self.managed {
            let server = &self.servers[*index];
            if server.project()
                || self.shadowed(server, false)
                || persisted.get(server.name).is_some()
                || server.command.is_empty()
            {
                continue;
            }
            persisted.set(server.name, native_entry(server, *index));
        }
        for index in &self.managed {
            let server = &self.servers[*index];
            if server.project() || self.shadowed(server, true) {
                continue;
            }
            persisted.set(&server.companion(), self.proxy_entry(*index, "companion"));
            let native = persisted.get(server.name).cloned();
            if let Some(native) = native {
                let mut disabled = Pairs::default();
                disabled.set("enabled", value(json!(false)));
                persisted.set(server.name, merge(vec![native, disabled.into_spec()]));
            }
        }
        persisted.into_spec()
    }

    /// `runtime_overlay` over `_proxy_permission_rules` and
    /// `_proxy_mcp_overrides`.
    fn overlay_spec(&self, rules: &[String]) -> Value {
        let mut permission = Pairs::default();
        for rule in rules {
            permission.set(rule, value(json!("ask")));
        }
        let mut overrides = Pairs::default();
        for index in &self.managed {
            let server = &self.servers[*index];
            if self.shadowed(server, false) {
                continue;
            }
            overrides.set(server.name, self.proxy_entry(*index, "override"));
        }
        let mut overlay = Pairs::default();
        overlay.set("$schema", value(json!(OPENCODE_SCHEMA)));
        overlay.set("permission", permission.into_spec());
        if !overrides.entries.is_empty() {
            overlay.set("mcp", overrides.into_spec());
        }
        overlay.into_spec()
    }
}

/// `_ensure_native_mcp_entries` for one server: its source entry with
/// Guard's command, `enabled` and environment.
fn native_entry(server: &Server<'_>, index: usize) -> Value {
    let base = [json!("servers"), json!(index)];
    let source_path = child(&base, "source");
    let mut parts: Vec<Value> = Vec::new();
    let mut kind = value(json!("local"));
    if let Some(source) = server.source {
        parts.push(reference(&source_path));
        if source.contains_key("type") {
            kind = reference(&child(&source_path, "type"));
        }
    }
    let mut argv: Vec<&str> = vec![server.command];
    argv.extend(server.args.iter().copied());
    let mut fields = Pairs::default();
    fields.set("type", kind);
    fields.set("command", value(json!(argv)));
    fields.set("enabled", value(json!(server.enabled)));
    if server.has_env {
        fields.set("environment", reference(&child(&base, "env")));
    }
    parts.push(fields.into_spec());
    merge(parts)
}

/// `_persisted_mcp_payload`: user entries in order, legacy in-place proxy
/// wrappers restored and other Guard proxies dropped.
fn persisted_entries(mcp: &Value, keys: &[&str]) -> Pairs {
    let mut persisted = Pairs::default();
    let Some(object) = mcp.as_object() else {
        return persisted;
    };
    for key in keys {
        let Some(entry) = object.get(*key).and_then(|item| item.as_object()) else {
            continue;
        };
        let path = [json!("mcp"), json!(key)];
        if key.starts_with(COMPANION_PREFIX) {
            persisted.set(key, copy(&path));
            continue;
        }
        if let Some(restored) = restored_entry(entry, &path) {
            persisted.set(key, restored);
            continue;
        }
        if !is_guard_entry(entry) {
            persisted.set(key, copy(&path));
        }
    }
    persisted
}

/// `_restore_local_server_from_guard_proxy`: the local entry an old
/// in-place `opencode-mcp-proxy` wrapper carried.
fn restored_entry(entry: &Map<String, Value>, path: &[Value]) -> Option<Value> {
    let argv = restored_command(entry)?;
    let field = |key: &str, default: Value| {
        if entry.contains_key(key) {
            reference(&child(path, key))
        } else {
            value(default)
        }
    };
    let mut restored = Pairs::default();
    restored.set("type", field("type", json!("local")));
    restored.set("command", value(json!(argv)));
    restored.set("enabled", field("enabled", json!(true)));
    if entry.get("environment").is_some_and(|env| env.is_object()) {
        restored.set("environment", reference(&child(path, "environment")));
    }
    Some(restored.into_spec())
}
