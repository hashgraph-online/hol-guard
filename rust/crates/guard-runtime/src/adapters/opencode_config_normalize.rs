//! `runner_authority` kind `opencode_config_normalize`: an OpenCode config with
//! Guard's MCP wrappers taken back off (`_normalized_config_payload` and the
//! proxy-binding checks in `opencode_install_snapshot` before they moved here).
//!
//! A `hol-guard::<name>` companion entry is trusted only when its proxy launch
//! names this Guard home, this config file and scope, and the server id of the
//! server it wraps; a trusted companion folds back into that server's entry.
//! Any other in-place `opencode-mcp-proxy` wrapper is restored to the command
//! it wrapped. The install derives Guard's entries again from the result.
//!
//! The config travels as JSON text so its key order survives:
//! `{"config": <JSON text>, "scope": str, "config_path": str,
//! "guard_home": str, "cwd": str}` answers `{"config": <JSON text>}`. `cwd` is
//! the caller's working directory, which a relative path resolves against; an
//! empty one leaves a relative path unresolvable, as `os.getcwd()` failing did.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::claude_guard_question::python_lower;
use crate::harness_coverage_artifacts::resolve_lenient;
use crate::hook_env_stamp::{dumps, set_member};
use crate::opencode_proxy_entry::is_guard_command;
use crate::opencode_server_id::server_identifier;
use crate::pyjson::{self, in_surrogate_plane, PyVal};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const REQUEST_KEYS: [&str; 5] = ["config", "scope", "config_path", "guard_home", "cwd"];
/// `GUARD_MCP_COMPANION_PREFIX`.
const COMPANION_PREFIX: &str = "hol-guard::";
const OPENCODE_PROXY: &str = "opencode-mcp-proxy";
const REQUIRED_OPTIONS: [&str; 7] = [
    "--guard-home",
    "--server-name",
    "--server-id",
    "--source-scope",
    "--config-path",
    "--transport",
    "--command",
];

type Entry = Vec<(String, PyVal)>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != REQUEST_KEYS.len()
        || !REQUEST_KEYS.iter().all(|key| fields.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    let text = |key: &str| fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let parsed = pyjson::parse_mapping_lone_surrogates(text("config")?).map_err(|_| ERR_INVALID)?;
    // With a lone surrogate mapped, a genuine character in the stand-in range
    // could not be told apart from one, so the config is refused.
    if parsed.mapped && parsed.collision {
        return Err(ERR_INVALID);
    }
    let PyVal::Dict(config) = parsed.value else {
        return Err(ERR_INVALID);
    };
    let cwd = text("cwd")?;
    let place = Place {
        scope: text("scope")?,
        config_path: resolved(text("config_path")?, cwd),
        guard_home: resolved(text("guard_home")?, cwd),
        cwd,
        mapped: parsed.mapped,
    };
    let mut answer = String::new();
    dumps(
        &PyVal::Dict(normalized_config(config, &place)),
        false,
        parsed.mapped,
        &mut answer,
    );
    Ok(json!({ "config": answer }))
}

/// Where the config sits: what a companion's proxy launch must name.
struct Place<'a> {
    scope: &'a str,
    config_path: Option<PathBuf>,
    guard_home: Option<PathBuf>,
    cwd: &'a str,
    mapped: bool,
}

/// A verified companion's proxy launch (`_ProxyBinding`).
struct Binding<'a> {
    native_name: &'a str,
    transport: &'a str,
    command: &'a str,
    args: Vec<&'a str>,
    env_keys: Vec<&'a str>,
    enabled: bool,
}

/// `_normalized_config_payload`: the config with every `mcp` entry that is
/// not an object dropped, trusted companions folded into the servers they
/// wrap and legacy wrappers restored.
fn normalized_config(mut config: Entry, place: &Place<'_>) -> Entry {
    let Some(slot) = config.iter().position(|(key, _)| key == "mcp") else {
        return config;
    };
    let PyVal::Dict(mcp) = &config[slot].1 else {
        return config;
    };
    config[slot].1 = PyVal::Dict(rebuilt_mcp(mcp, place));
    config
}

/// The `mcp` object rebuilt by assignment, in the order of its entries.
fn rebuilt_mcp(mcp: &Entry, place: &Place<'_>) -> Entry {
    let entries: Vec<(&str, &Entry)> = mcp
        .iter()
        .filter_map(|(name, entry)| match entry {
            PyVal::Dict(entry) => Some((name.as_str(), entry)),
            _ => None,
        })
        .collect();
    let lookup: HashMap<&str, &Entry> = entries.iter().copied().collect();
    let mut trusted: HashMap<&str, Binding<'_>> = HashMap::new();
    for &(name, entry) in &entries {
        let Some(binding) = verified_binding(name, entry, place) else {
            continue;
        };
        if let Some(native) = lookup.get(binding.native_name) {
            if !binding_matches_native(&binding, native) {
                continue;
            }
        }
        trusted.insert(name, binding);
    }
    let guarded: HashSet<&str> = trusted
        .values()
        .map(|binding| binding.native_name)
        .collect();
    let mut rebuilt = Members::default();
    for &(name, entry) in &entries {
        if let Some(binding) = trusted.get(name) {
            let native = lookup.get(binding.native_name).copied();
            rebuilt.set(
                binding.native_name,
                native_entry_from_binding(binding, native, entry),
            );
        } else if guarded.contains(name) {
            if !rebuilt.places.contains_key(name) {
                rebuilt.set(name, PyVal::Dict(entry.clone()));
            }
        } else {
            let restored = restore_legacy_proxy(entry).unwrap_or_else(|| entry.clone());
            rebuilt.set(name, PyVal::Dict(restored));
        }
    }
    rebuilt.entries
}

/// A dict built by assignment: a repeated key keeps its first place.
#[derive(Default)]
struct Members {
    entries: Entry,
    places: HashMap<String, usize>,
}

impl Members {
    fn set(&mut self, key: &str, value: PyVal) {
        match self.places.get(key) {
            Some(&place) => self.entries[place].1 = value,
            None => {
                self.places.insert(key.to_owned(), self.entries.len());
                self.entries.push((key.to_owned(), value));
            }
        }
    }
}

/// `_verified_proxy_binding`.
fn verified_binding<'a>(name: &'a str, entry: &'a Entry, place: &Place<'_>) -> Option<Binding<'a>> {
    let native_name = name.strip_prefix(COMPANION_PREFIX)?;
    if native_name.is_empty() || native_name.starts_with(COMPANION_PREFIX) {
        return None;
    }
    let (command, args) = command_parts(entry);
    if !is_guard_command(command, &args) || !args.contains(&OPENCODE_PROXY) {
        return None;
    }
    let options = proxy_options(&args);
    let single = |key: &str| match options.get(key) {
        Some(values) if values.len() == 1 => Some(values[0]),
        _ => None,
    };
    if !REQUIRED_OPTIONS.iter().all(|key| single(key).is_some()) {
        return None;
    }
    if single("--server-name")? != native_name || single("--source-scope")? != place.scope {
        return None;
    }
    if !same_place(single("--guard-home")?, place.guard_home.as_deref(), place) {
        return None;
    }
    let transport = single("--transport")?;
    if transport != "local" && transport != "stdio" {
        return None;
    }
    let config_path = single("--config-path")?;
    if !same_place(config_path, place.config_path.as_deref(), place)
        || !Path::new(config_path).is_absolute()
    {
        return None;
    }
    let command = single("--command")?;
    let args = options.get("--arg").cloned().unwrap_or_default();
    let identifier = server_identifier(
        native_name,
        place.scope,
        command,
        &args,
        transport,
        place.mapped,
    );
    if single("--server-id")? != identifier {
        return None;
    }
    let enabled = match member(entry, "enabled") {
        Some(PyVal::Bool(enabled)) => *enabled,
        _ => true,
    };
    Some(Binding {
        native_name,
        transport,
        command,
        args,
        env_keys: options.get("--server-env-key").cloned().unwrap_or_default(),
        enabled,
    })
}

/// Whether a path a proxy launch spelled resolves to `expected`, as
/// `Path(spelled).resolve() == expected.resolve()` decides it. A path holding
/// a lone surrogate can never match: no request could have carried one.
fn same_place(spelled: &str, expected: Option<&Path>, place: &Place<'_>) -> bool {
    if place.mapped && spelled.chars().any(in_surrogate_plane) {
        return false;
    }
    match (resolved(spelled, place.cwd), expected) {
        (Some(left), Some(right)) => same_path(&left, right),
        _ => false,
    }
}

/// `Path(path).resolve()`, or `None` where that raises: a relative path with
/// no working directory, or an embedded NUL.
fn resolved(path: &str, cwd: &str) -> Option<PathBuf> {
    if path.contains('\0') {
        return None;
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Some(resolve_lenient(path));
    }
    if cwd.is_empty() {
        return None;
    }
    Some(resolve_lenient(&Path::new(cwd).join(path)))
}

/// `PurePath.__eq__`: Windows paths compare without case.
fn same_path(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        python_lower(&left.to_string_lossy()) == python_lower(&right.to_string_lossy())
    } else {
        left == right
    }
}

/// `_proxy_options`: `--arg=` and `--server-env-key=` values, and every other
/// `--` token paired with the token after it.
fn proxy_options<'a>(args: &[&'a str]) -> HashMap<&'a str, Vec<&'a str>> {
    let mut options: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let token = args[index];
        if let Some(value) = token.strip_prefix("--arg=") {
            options.entry("--arg").or_default().push(value);
        } else if let Some(value) = token.strip_prefix("--server-env-key=") {
            options.entry("--server-env-key").or_default().push(value);
        } else if token.starts_with("--") && index + 1 < args.len() {
            options.entry(token).or_default().push(args[index + 1]);
            index += 1;
        }
        index += 1;
    }
    options
}

/// `_binding_matches_native`: the server entry, unwrapped, runs the command
/// the companion says it guards.
fn binding_matches_native(binding: &Binding<'_>, entry: &Entry) -> bool {
    let restored = restore_legacy_proxy(entry);
    let (command, args) = command_parts(restored.as_ref().unwrap_or(entry));
    command == Some(binding.command) && args == binding.args
}

/// `_native_entry_from_binding`.
fn native_entry_from_binding(
    binding: &Binding<'_>,
    native: Option<&Entry>,
    companion: &Entry,
) -> PyVal {
    let mut restored = match native {
        Some(native) => restore_legacy_proxy(native).unwrap_or_else(|| native.clone()),
        None => {
            let mut command = vec![PyVal::Str(binding.command.to_owned())];
            command.extend(binding.args.iter().map(|arg| PyVal::Str((*arg).to_owned())));
            let mut entry: Entry = vec![
                ("type".to_owned(), PyVal::Str(binding.transport.to_owned())),
                ("command".to_owned(), PyVal::List(command)),
            ];
            let environment = selected_environment(companion, &binding.env_keys);
            if !environment.is_empty() {
                entry.push(("environment".to_owned(), PyVal::Dict(environment)));
            }
            entry
        }
    };
    set_member(&mut restored, "enabled", PyVal::Bool(binding.enabled));
    PyVal::Dict(restored)
}

/// `_restore_legacy_proxy`: the entry an in-place proxy wrapper replaced.
fn restore_legacy_proxy(entry: &Entry) -> Option<Entry> {
    let (command, args) = command_parts(entry);
    if !is_guard_command(command, &args) || !args.contains(&OPENCODE_PROXY) {
        return None;
    }
    let options = proxy_options(&args);
    let wrapped = match options.get("--command") {
        Some(commands) if commands.len() == 1 => commands[0],
        _ => return None,
    };
    let mut argv = vec![PyVal::Str(wrapped.to_owned())];
    if let Some(values) = options.get("--arg") {
        argv.extend(values.iter().map(|value| PyVal::Str((*value).to_owned())));
    }
    let mut restored: Entry = vec![
        (
            "type".to_owned(),
            member(entry, "type")
                .cloned()
                .unwrap_or_else(|| PyVal::Str("local".to_owned())),
        ),
        ("command".to_owned(), PyVal::List(argv)),
        (
            "enabled".to_owned(),
            member(entry, "enabled")
                .cloned()
                .unwrap_or(PyVal::Bool(true)),
        ),
    ];
    if let Some(environment @ PyVal::Dict(_)) = member(entry, "environment") {
        restored.push(("environment".to_owned(), environment.clone()));
    }
    Some(restored)
}

/// `_selected_environment`: the named string values, in the order named.
fn selected_environment(entry: &Entry, keys: &[&str]) -> Entry {
    let Some(PyVal::Dict(raw)) = member(entry, "environment") else {
        return Vec::new();
    };
    let mut selected = Members::default();
    for key in keys {
        if let Some(PyVal::Str(value)) = member(raw, key) {
            selected.set(key, PyVal::Str(value.clone()));
        }
    }
    selected.entries
}

/// `_command_parts`: a command list, or a command string with its args.
fn command_parts(entry: &Entry) -> (Option<&str>, Vec<&str>) {
    match member(entry, "command") {
        Some(PyVal::List(items)) => {
            let list = string_items(items);
            match list.split_first() {
                Some((first, rest)) => (Some(*first), rest.to_vec()),
                None => (None, Vec::new()),
            }
        }
        Some(PyVal::Str(command)) => {
            let args = match member(entry, "args") {
                Some(PyVal::List(items)) => string_items(items),
                _ => Vec::new(),
            };
            (Some(command.as_str()), args)
        }
        _ => (None, Vec::new()),
    }
}

fn string_items(items: &[PyVal]) -> Vec<&str> {
    items
        .iter()
        .filter_map(|item| match item {
            PyVal::Str(text) => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn member<'a>(entry: &'a Entry, key: &str) -> Option<&'a PyVal> {
    entry
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}
