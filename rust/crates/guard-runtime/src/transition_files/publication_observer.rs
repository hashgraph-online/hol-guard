//! The installed Codex hook a transition observer may launch, ported from
//! `_observe_configured_codex_hook`.
//!
//! An observer proves protection by running the exact pre-tool command the
//! authenticated manifest registered. Before it launches anything, the
//! runtime authenticates the manifest, finds the one Guard pre-tool binding,
//! checks that the live config holds that group exactly once, splits its
//! command and authenticates the launch the bridge config names. The answer
//! is the argv and environment to run, the observation channel, and digests
//! of the config and manifest the caller rechecks around the launch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::inspect::resolve_lenient;
use super::publication::Call;
use super::publication_generation::package_roots;
use super::{Fault, Step};
use crate::codex_hook_bridge::decode_config_argument;
use crate::codex_hook_launch_trust::{self, LAUNCH_INVALID};
use crate::codex_hook_manifest_auth as manifest_auth;
use crate::cursor_hook_command::Syntax;
use crate::guard_config_update_value::{from_toml_table, py_eq, table_to_json};
use crate::pyjson::{self, PyVal};

type Object = Map<String, Value>;

/// `_CODEX_GUARD_TOOL_MATCHER`.
const TOOL_MATCHER: &str = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*";
pub(super) const MISSING: &str = "admission_hook_authority_missing";
pub(super) const INVALID: &str = "admission_hook_binding_invalid";
const CHANNEL: [&str; 2] = ["hook_probe", "native_receipt"];

pub(super) fn invalid() -> Fault {
    Fault::Transition(INVALID)
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The bridge config fields `bridge_config_from_argv` checks with no grace.
struct Bridge {
    state_path: String,
    manifest_path: String,
    fallback_command: Vec<String>,
    start_command: Vec<String>,
}

/// The launch the observer may run, and the digests it rechecks around it.
pub(super) struct Launch {
    pub(super) argv: Vec<String>,
    pub(super) environment: Object,
    pub(super) modern: bool,
    pub(super) manifest_path: String,
    pub(super) config_sha256: String,
    pub(super) manifest_sha256: String,
}

/// The command syntax the request names: this host's, with the long spelling
/// of every short path the caller already resolved.
pub(super) fn syntax_of(call: &Call<'_>) -> Step<Syntax> {
    let windows = call.args.get("windows").and_then(Value::as_bool);
    let long_paths = call.args.get("long_paths").and_then(Value::as_object);
    let (Some(windows), Some(long_paths)) = (windows, long_paths) else {
        return Err(Fault::Transition("files_invalid"));
    };
    let long_paths: BTreeMap<String, String> = long_paths
        .iter()
        .map(|(short, long)| long.as_str().map(|long| (short.clone(), long.to_owned())))
        .collect::<Option<_>>()
        .ok_or(Fault::Transition("files_invalid"))?;
    Ok(Syntax::new(windows, long_paths))
}

pub(super) fn observed(call: &mut Call<'_>, syntax: &mut Syntax) -> Step<Launch> {
    let home = call.home()?;
    let config_path = call.path("config")?;
    let (manifest_path, _) = Call::targets(&home, &call.canonical(&config_path)?);
    let config_bytes = call.snapshot(&config_path)?;
    let manifest_bytes = call.snapshot(&manifest_path)?;
    let (Some(config_bytes), Some(manifest_bytes)) = (config_bytes, manifest_bytes) else {
        return Err(Fault::Transition(MISSING));
    };
    let home_text = home.to_str().ok_or(Fault::Transition("files_invalid"))?;
    // The caller words a manifest refusal from its reason.
    let manifest = manifest_auth::load_path(home_text, &manifest_path)
        .map(manifest_auth::unsigned)
        .map_err(|reason| Fault::Integrity(reason.to_owned(), reason.to_owned()))?;
    call.budget.hook()?;
    let config = std::str::from_utf8(&config_bytes)
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(text).ok())
        .map(|table| table_to_json(&from_toml_table(table)))
        .ok_or_else(invalid)?;
    let (argv, environment, modern) = installed(&manifest, &config, syntax)?;
    let bridge = bridge_config(&argv[argv.len() - 1]).ok_or_else(invalid)?;
    if resolve_lenient(Path::new(&bridge.manifest_path)) != resolve_lenient(&manifest_path) {
        return Err(invalid());
    }
    let roots: Vec<PathBuf> = package_roots(call.args)?
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let mut launch = Object::new();
    for key in ["runtime_path", "frozen"] {
        if let Some(value) = call.args.get(key) {
            launch.insert(key.to_owned(), value.clone());
        }
    }
    launch.insert("manifest_path".to_owned(), json!(bridge.manifest_path));
    launch.insert("state_path".to_owned(), json!(bridge.state_path));
    launch.insert(
        "fallback_command".to_owned(),
        json!(bridge.fallback_command),
    );
    launch.insert("start_command".to_owned(), json!(bridge.start_command));
    launch.insert("config_json".to_owned(), json!(argv[argv.len() - 1]));
    codex_hook_launch_trust::launch(&launch, &roots).map_err(|(reason, message)| {
        if reason == LAUNCH_INVALID {
            invalid()
        } else {
            Fault::Integrity(reason, message)
        }
    })?;
    Ok(Launch {
        argv,
        environment,
        modern,
        manifest_path: bridge.manifest_path,
        config_sha256: sha256(&config_bytes),
        manifest_sha256: sha256(&manifest_bytes),
    })
}

/// The one Guard pre-tool binding, as the manifest and the live config
/// both hold it: its argv, its environment, and whether the package
/// carries the probe observation channel.
fn installed(
    manifest: &Object,
    config: &Object,
    syntax: &mut Syntax,
) -> Step<(Vec<String>, Object, bool)> {
    if let Some(Value::Object(features)) = config.get("features") {
        if features.get("hooks") == Some(&Value::Bool(false)) {
            return Err(invalid());
        }
    }
    let events = manifest
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut bindings = events
        .iter()
        .filter_map(Value::as_object)
        .filter(|entry| entry.get("event").and_then(Value::as_str) == Some("PreToolUse"));
    let (Some(binding), None) = (bindings.next(), bindings.next()) else {
        return Err(invalid());
    };
    let group = binding.get("group").and_then(Value::as_object);
    let handler = binding.get("handler").and_then(Value::as_object);
    let (Some(group), Some(handler)) = (group, handler) else {
        return Err(invalid());
    };
    let index = binding.get("handler_index").unwrap_or(&Value::Null);
    if group.get("matcher").and_then(Value::as_str) != Some(TOOL_MATCHER)
        || !group
            .get("hooks")
            .is_some_and(|hooks| py_eq(hooks, &json!([handler])))
        || !py_eq(index, &json!(0))
        || handler.get("type").and_then(Value::as_str) != Some("command")
    {
        return Err(invalid());
    }
    let group = Value::Object(group.clone());
    let configured = config
        .get("hooks")
        .and_then(Value::as_object)
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if configured.iter().filter(|live| py_eq(live, &group)).count() != 1 {
        return Err(invalid());
    }
    let argv = handler
        .get("command")
        .and_then(Value::as_str)
        .and_then(|command| syntax.split_hook(command))
        .filter(|argv| argv.len() >= 3)
        .ok_or_else(invalid)?;
    if binding.get("argv") != Some(&json!(argv)) {
        return Err(invalid());
    }
    let environment = match handler.get("env") {
        None => Object::new(),
        Some(Value::Object(env)) if env.values().all(Value::is_string) => env.clone(),
        Some(_) => return Err(invalid()),
    };
    let packaged = manifest
        .get("packaged_files")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let held = |role: &str| {
        packaged
            .iter()
            .any(|entry| entry.get("role").and_then(Value::as_str) == Some(role))
    };
    let modern = CHANNEL.iter().all(|role| held(role));
    if !modern && CHANNEL.iter().any(|role| held(role)) {
        return Err(invalid());
    }
    Ok((argv, environment, modern))
}

/// `bridge_config_from_argv(..., timeout_grace_seconds=0)`, as far as an
/// observer reads it.
fn bridge_config(argument: &str) -> Option<Bridge> {
    let text = decode_config_argument(argument)?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    if parsed.mapped {
        return None;
    }
    let payload = parsed.value;
    let strings = |key: &str| {
        payload
            .get(key)?
            .as_list()
            .filter(|items| !items.is_empty())?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    };
    let state_path = payload.get("state_path")?.as_str()?.to_owned();
    let manifest_path = payload.get("manifest_path")?.as_str()?.to_owned();
    payload.get("query")?.as_str()?;
    let fallback_command = strings("fallback_command")?;
    let start_command = strings("start_command")?;
    let positive = |value: &PyVal| match value {
        PyVal::Int(digits) => {
            !digits.starts_with('-') && !digits.trim_start_matches('0').is_empty()
        }
        PyVal::Bool(flag) => *flag,
        _ => false,
    };
    let timeouts = payload.get("hook_timeouts")?.as_dict()?;
    if manifest_path.is_empty() || !timeouts.iter().any(|(_, value)| positive(value)) {
        return None;
    }
    Some(Bridge {
        state_path,
        manifest_path,
        fallback_command,
        start_command,
    })
}

#[cfg(test)]
#[path = "tests_publication_observer.rs"]
mod tests;
