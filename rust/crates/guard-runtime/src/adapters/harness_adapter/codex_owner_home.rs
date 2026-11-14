//! Codex: the handlers an earlier generation of this same install left.
//!
//! A bridge launcher names the Guard home it serves inside its config
//! operand. Naming this home proves only that someone knew where Guard lives,
//! so an entry is claimed only when its program also sits in a root Guard
//! controls: the native bridge under the Guard home, or the bridge script in
//! this install's package (`codex_hook_self_binding`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::codex::text;
use super::codex_merge::{get, Entries};
use super::codex_owners::{binding, tokens, EVENTS, NULL};
use super::{Failure, Step};
use crate::cursor_hook_command::{py_space, Syntax};
use crate::harness_coverage::resolve_lenient;
use crate::pyjson::{self, PyVal};
use crate::runner_sync_url::parse_qsl;

const NATIVE_COMMAND: &str = "codex-hook-bridge";
const BRIDGE_SCRIPT: &str = "codex_daemon_hook_bridge.py";
const STATE_NAME: &str = "daemon-state.json";
const OPTION: &str = "--guard-home";

/// The caller's working directory, against which Python resolves a
/// relative path; `None` when it has none, so a relative path resolves to
/// nothing.
pub(super) struct Cwd(Option<PathBuf>);

impl Cwd {
    pub(super) fn parse(fields: &Map<String, Value>) -> Step<Self> {
        match fields.get("cwd") {
            Some(Value::Null) => Ok(Self(None)),
            Some(Value::String(text)) if Path::new(text).is_absolute() && !text.contains('\0') => {
                Ok(Self(Some(PathBuf::from(text))))
            }
            _ => Err(Failure::Invalid),
        }
    }

    fn absolute(&self, path: &Path) -> Option<PathBuf> {
        if path.is_absolute() {
            return Some(path.to_path_buf());
        }
        self.0.as_ref().map(|cwd| cwd.join(path))
    }

    /// `_resolved`: the stripped text resolved leniently, `None` when blank.
    fn resolved(&self, value: &str) -> Option<PathBuf> {
        let text = value.trim_matches(py_space);
        if text.is_empty() || text.contains('\0') {
            return None;
        }
        self.absolute(Path::new(text))
            .map(|path| resolve_lenient(&path))
    }
}

/// This install's Guard home and package directory, made absolute.
pub(super) struct Home {
    cwd: Cwd,
    guard_home: Option<PathBuf>,
    package_root: Option<PathBuf>,
}

impl Home {
    pub(super) fn parse(fields: &Map<String, Value>) -> Step<Self> {
        let cwd = Cwd::parse(fields)?;
        let path = |key| {
            let value = text(fields, key)?;
            if value.is_empty() || value.contains('\0') {
                return Err(Failure::Invalid);
            }
            Ok(cwd.absolute(Path::new(value)))
        };
        let (guard_home, package_root) = (path("guard_home")?, path("package_root")?);
        Ok(Self {
            cwd,
            guard_home,
            package_root,
        })
    }
}

/// `self_bound_hook_bindings`: a group that is itself the handler binds as
/// the whole group; a handler inside a group binds under its matcher alone,
/// so a group holding someone else's handler loses only ours.
pub(super) fn self_bindings(
    hooks: &Entries,
    home: &Home,
    recorded: &BTreeSet<String>,
    syntax: &mut Syntax,
) -> Vec<PyVal> {
    let mut bindings = Vec::new();
    for event in EVENTS {
        let Some(PyVal::List(groups)) = get(hooks, event) else {
            continue;
        };
        for group in groups {
            let Some(entries) = group.as_dict() else {
                continue;
            };
            let Some(PyVal::List(handlers)) = get(entries, "hooks") else {
                if claims(entries, home, recorded, syntax) {
                    bindings.push(binding(event, group.clone(), group.clone()));
                }
                continue;
            };
            let matcher = get(entries, "matcher").unwrap_or(&NULL).clone();
            for handler in handlers {
                if handler
                    .as_dict()
                    .is_some_and(|entry| claims(entry, home, recorded, syntax))
                {
                    let key = PyVal::Dict(vec![("matcher".to_owned(), matcher.clone())]);
                    bindings.push(binding(event, key, handler.clone()));
                }
            }
        }
    }
    bindings
}

fn claims(
    entry: &[(String, PyVal)],
    home: &Home,
    recorded: &BTreeSet<String>,
    syntax: &mut Syntax,
) -> bool {
    match get(entry, "command") {
        Some(PyVal::Str(command)) => !recorded.contains(command) && binds(command, home, syntax),
        _ => false,
    }
}

/// `codex_hook_binds_guard_home`: the launcher names this home alone and
/// runs a program inside a root this install controls.
pub(super) fn binds(command: &str, home: &Home, syntax: &mut Syntax) -> bool {
    let (Some(bound), Some(guard_home)) =
        (guard_home(command, &home.cwd, syntax), &home.guard_home)
    else {
        return false;
    };
    if key(&bound) != key(&resolve_lenient(guard_home)) {
        return false;
    }
    let tokens = tokens(syntax, command);
    let inside = |candidate: &str, root: &Option<PathBuf>| {
        root.as_deref()
            .is_some_and(|root| path_is_inside(candidate, root))
    };
    inside(&tokens[0], &home.guard_home)
        || launch(&tokens).is_some_and(|launch| inside(&launch[2], &home.package_root))
}

/// `codex_hook_guard_home`: the one Guard home a bridge launcher names.
pub(super) fn guard_home(command: &str, cwd: &Cwd, syntax: &mut Syntax) -> Option<PathBuf> {
    let tokens = tokens(syntax, command);
    let launch = launch(&tokens)?;
    if launch[1] != "-I" || syntax.name(&launch[2]) != BRIDGE_SCRIPT {
        return None;
    }
    let config = crate::codex_hook_bridge::decode_config_argument(&launch[3])?;
    let Ok(PyVal::Dict(payload)) = pyjson::parse(&config) else {
        return None;
    };
    let mut homes = payload_homes(&payload, cwd);
    if homes.len() != 1 {
        return None;
    }
    homes.pop_first().map(|(_, path)| path)
}

/// `_bridge_launch_tokens`: the interpreter argv once a native wrapper goes.
fn launch(tokens: &[String]) -> Option<&[String]> {
    match tokens.len() {
        6 if tokens[1] == NATIVE_COMMAND => Some(&tokens[2..]),
        4 => Some(tokens),
        _ => None,
    }
}

/// `_payload_guard_home`, keyed as Python compares the paths.
fn payload_homes(payload: &[(String, PyVal)], cwd: &Cwd) -> BTreeMap<String, PathBuf> {
    let mut homes = BTreeMap::new();
    let mut add = |path: PathBuf| {
        homes.insert(key(&path), path);
    };
    if let Some(PyVal::Str(query)) = get(payload, "query") {
        for (name, value) in parse_qsl(query) {
            if name != "guard-home" || value.is_empty() {
                continue;
            }
            if let Some(path) = cwd.resolved(&value) {
                add(path);
            }
        }
    }
    if let Some(state) = get(payload, "state_path").and_then(PyVal::as_str) {
        if let Some(path) = cwd.resolved(state) {
            match path.parent() {
                Some(parent) if path.file_name().is_some_and(|name| name == STATE_NAME) => {
                    add(parent.to_path_buf());
                }
                _ => {}
            }
        }
    }
    for field in ["fallback_command", "start_command"] {
        let Some(PyVal::List(items)) = get(payload, field) else {
            continue;
        };
        let items: Vec<&str> = items.iter().filter_map(PyVal::as_str).collect();
        for (index, token) in items.iter().enumerate() {
            let value = match token.strip_prefix(OPTION) {
                Some("") => items.get(index + 1).copied(),
                Some(rest) => rest.strip_prefix('='),
                None => None,
            };
            if let Some(path) = value.and_then(|value| cwd.resolved(value)) {
                add(path);
            }
        }
    }
    homes
}

/// `Path.__eq__`: Windows paths compare without case.
fn key(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.into_owned()
    }
}

/// `path_is_inside`: an absolute candidate that resolves to a file under
/// `root`, compared as files, not as text.
pub(super) fn path_is_inside(candidate: &str, root: &Path) -> bool {
    let text = candidate.trim_matches(py_space);
    let path = Path::new(text);
    if text.is_empty() || !path.is_absolute() {
        return false;
    }
    let (Ok(resolved), Ok(root)) = (fs::canonicalize(path), fs::canonicalize(root)) else {
        return false;
    };
    resolved
        .ancestors()
        .skip(1)
        .any(|parent| same_file(parent, &root))
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(left), fs::metadata(right)) {
        (Ok(left), Ok(right)) => (left.dev(), left.ino()) == (right.dev(), right.ino()),
        _ => false,
    }
}

/// Both sides are canonical, so the same file has the same spelling.
#[cfg(not(unix))]
fn same_file(left: &Path, right: &Path) -> bool {
    left == right
}
