//! `runner_authority` kind `cline_install_plan`: the decisions the Cline
//! adapter makes while it installs an enforcement transport
//! (`_auto_transport`, the cleanup choice in `_reconcile_transport`,
//! `_coverage_label` and `_blind_spots` in `adapters/cline.py` before they
//! moved here). Python keeps the file writes, the probes and the state it
//! reads, and sends booleans:
//!
//! - `transport` picks the transport for a normalized surface and says whether
//!   a failed plugin install may fall back to native hooks.
//! - `reconcile` says whether the other managed transport is removed and
//!   whether the switch still waits for a live proof.
//! - `posture` names the coverage label and the blind spots of an install.
//! - `mcp_proxy` picks the servers of one MCP settings file that
//!   `install_cline_mcp_proxies` wraps in the Guard proxy, and the remote ones
//!   it skips (`_managed_server` and its helpers in `adapters/cline_mcp.py`
//!   before they moved here). Python sends the parsed settings as
//!   `json.dumps` text and keeps the proxy entry, the backup and the write.

use serde_json::{json, Map, Value};

use super::cline_detect::transport as mcp_transport;
use super::context_digest::python_strip;
use super::cursor_editor_plan::is_guard_proxy;
use super::hook_env_stamp::{dumps, set_member};
use super::pyjson::{self, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const SURFACES: [&str; 5] = ["auto", "hooks", "plugin", "cli", "all"];
const HOOKS_BLIND_SPOT: &str =
    "Native PostToolUse is observation-only; use the plugin transport for model-visible output replacement.";
const JETBRAINS_BLIND_SPOT: &str =
    "JetBrains runtime protection is unverified until Guard observes a live pre-tool deny proof.";
const SERVER_KEYS: [&str; 2] = ["mcpServers", "mcp"];
const LOCAL_TRANSPORTS: [&str; 2] = ["stdio", "local"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "transport" => &["op", "surface", "frozen", "cli", "vscode", "jetbrains"],
        "reconcile" => &["op", "target_ready", "other_installed", "other_ready"],
        "posture" => &["op", "transport", "hook_ready", "plugin_ready", "jetbrains"],
        "mcp_proxy" => &["op", "settings"],
        _ => return Err(ERR_INVALID),
    };
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    match op {
        "transport" => transport(fields),
        "reconcile" => reconcile(fields),
        "posture" => posture(fields),
        _ => mcp_proxy(fields),
    }
}

fn flag(fields: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    fields.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// An explicit `hooks` or `plugin` surface is honoured. Otherwise a frozen
/// Desktop runtime, or a CLI-only host, takes the durable plugin and every
/// other host takes native hooks. Only an implicit plugin choice may fall
/// back to hooks when the plugin fails its probe.
fn transport(fields: &Map<String, Value>) -> KindResult {
    let surface = text(fields, "surface")?;
    if !SURFACES.contains(&surface) {
        return Err(ERR_INVALID);
    }
    let frozen = flag(fields, "frozen")?;
    let cli = flag(fields, "cli")?;
    let vscode = flag(fields, "vscode")?;
    let jetbrains = flag(fields, "jetbrains")?;
    let transport = match surface {
        "hooks" | "plugin" => surface,
        _ if frozen || (cli && !vscode && !jetbrains) => "plugin",
        _ => "hooks",
    };
    let fallback = matches!(surface, "auto" | "all" | "cli") && transport != "hooks";
    Ok(json!({"transport": transport, "fallback": fallback}))
}

/// The other transport is removed once the target is ready, or when the other
/// one is not ready either; until then the switch waits for a live proof.
fn reconcile(fields: &Map<String, Value>) -> KindResult {
    let target_ready = flag(fields, "target_ready")?;
    let other_installed = flag(fields, "other_installed")?;
    let other_ready = flag(fields, "other_ready")?;
    let remove_other = other_installed && (target_ready || !other_ready);
    let transition_pending = other_installed && !target_ready && !remove_other;
    Ok(json!({"remove_other": remove_other, "transition_pending": transition_pending}))
}

fn posture(fields: &Map<String, Value>) -> KindResult {
    let transport = text(fields, "transport")?;
    let hook_ready = flag(fields, "hook_ready")?;
    let plugin_ready = flag(fields, "plugin_ready")?;
    let jetbrains = flag(fields, "jetbrains")?;
    let coverage = match transport {
        "plugin" if plugin_ready => "full",
        "plugin" => "pending-live-proof",
        "hooks" if hook_ready => "pre-execution",
        "hooks" if jetbrains => "unverified",
        "hooks" => "pending-live-proof",
        _ => return Err(ERR_INVALID),
    };
    let mut blind_spots: Vec<&str> = Vec::new();
    if transport == "hooks" {
        blind_spots.push(HOOKS_BLIND_SPOT);
    }
    if jetbrains {
        blind_spots.push(JETBRAINS_BLIND_SPOT);
    }
    Ok(json!({"coverage": coverage, "blind_spots": blind_spots}))
}

/// The servers object of a settings file sits under the first of
/// `mcpServers` and `mcp` that holds an object. A local server with a command
/// that is not disabled and not already a Guard proxy is managed; a server on
/// any other transport is remote. The answer is `json.dumps` text, so a lone
/// surrogate in a name, an argument or an env value reaches Python intact.
fn mcp_proxy(fields: &Map<String, Value>) -> KindResult {
    let parsed = pyjson::parse_mapping_lone_surrogates(text(fields, "settings")?)
        .map_err(|_| ERR_INVALID)?;
    // With a lone surrogate mapped, a genuine character in the stand-in range
    // could not be told apart from one, so the settings are refused.
    if parsed.mapped && parsed.collision {
        return Err(ERR_INVALID);
    }
    let settings = parsed.value;
    if settings.as_dict().is_none() {
        return Err(ERR_INVALID);
    }
    let (key, servers) = SERVER_KEYS
        .into_iter()
        .find_map(|key| {
            settings
                .get(key)
                .and_then(PyVal::as_dict)
                .map(|servers| (key, servers))
        })
        .unwrap_or((SERVER_KEYS[0], &[]));
    let mut managed: Vec<PyVal> = Vec::new();
    let mut remote: Vec<PyVal> = Vec::new();
    for (name, raw) in servers {
        if raw.as_dict().is_none() {
            continue;
        }
        let kind = mcp_transport(raw);
        if !LOCAL_TRANSPORTS.contains(&kind.as_str()) {
            remote.push(PyVal::Str(name.clone()));
            continue;
        }
        if let Some(server) = managed_server(name, raw, kind) {
            managed.push(server);
        }
    }
    let plan = PyVal::Dict(vec![
        ("key".to_owned(), PyVal::Str(key.to_owned())),
        ("managed".to_owned(), PyVal::List(managed)),
        ("remote".to_owned(), PyVal::List(remote)),
    ]);
    let mut answer = String::new();
    dumps(&plan, false, parsed.mapped, &mut answer);
    Ok(json!({ "plan": answer }))
}

/// `_managed_server` for a local server: the command must be a non-blank
/// string and `disabled` must not be `true`.
fn managed_server(name: &str, raw: &PyVal, kind: String) -> Option<PyVal> {
    let command = raw.get("command").and_then(PyVal::as_str)?;
    if python_strip(command).is_empty() || matches!(raw.get("disabled"), Some(PyVal::Bool(true))) {
        return None;
    }
    let args: Vec<String> = raw
        .get("args")
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(PyVal::as_str)
        .map(str::to_owned)
        .collect();
    if is_guard_proxy(Some(command), &args) {
        return None;
    }
    Some(PyVal::Dict(vec![
        ("name".to_owned(), PyVal::Str(name.to_owned())),
        ("command".to_owned(), PyVal::Str(command.to_owned())),
        (
            "args".to_owned(),
            PyVal::List(args.into_iter().map(PyVal::Str).collect()),
        ),
        ("transport".to_owned(), PyVal::Str(kind)),
        ("env".to_owned(), PyVal::Dict(string_env(raw))),
    ]))
}

/// `_string_env` of `raw.get("env", raw.get("environment"))`: string values
/// under non-blank keys, keyed by the stripped key. Two keys that strip alike
/// keep the first place and the last value, as the dict comprehension does.
fn string_env(raw: &PyVal) -> Vec<(String, PyVal)> {
    let source = raw.get("env").or_else(|| raw.get("environment"));
    let mut env: Vec<(String, PyVal)> = Vec::new();
    for (key, item) in source.and_then(PyVal::as_dict).unwrap_or_default() {
        let stripped = python_strip(key);
        if !stripped.is_empty() && matches!(item, PyVal::Str(_)) {
            set_member(&mut env, stripped, item.clone());
        }
    }
    env
}
