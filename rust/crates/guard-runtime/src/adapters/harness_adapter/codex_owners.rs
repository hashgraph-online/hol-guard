//! Codex: which hook handlers a Guard install owns, and removing them.
//!
//! Hooks and bindings cross as order-preserving JSON text in which a scalar
//! JSON cannot carry is a token, equal values sharing one (`_Wire`), so
//! comparing tokens compares values. A Windows command naming an 8.3 short
//! path is answered with `{"reply": {"expand": [...]}}`: the host resolves
//! each name and asks again with `long_paths`.
//!
//! `remove` drops the handlers a manifest authenticates, `legacy` finds the
//! pre-manifest registrations of the current package, `unlaunchable` drops
//! legacy Guard handlers whose program is gone, and `strip` runs the whole
//! cleanup an install applies before it writes its own groups. The handlers
//! an earlier generation of the same install left are in `codex_owner_home`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{compact, dict, flag, text};
use super::codex_merge::{get, pop, py_eq, set, Entries};
use super::codex_owner_home::{self as home, Cwd, Home};
use super::{Failure, Step};
use crate::cursor_hook_command::{py_space, Syntax};
use crate::pyjson::{self, PyVal};

/// `MANAGED_CODEX_HOOK_EVENTS`.
pub(super) const EVENTS: [&str; 4] = [
    "PreToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PostToolUse",
];
const COMMON: [&str; 3] = ["op", "windows", "long_paths"];
const LEGACY: [&str; 4] = ["expected", "argv", "legacy_argv", "statuses"];
pub(super) const NULL: PyVal = PyVal::Null;

fn op_fields(op: &str) -> Option<Vec<&'static str>> {
    let fields = match op {
        "remove" => vec!["hooks", "bindings"],
        "unlaunchable" => vec!["hooks", "statuses"],
        "legacy" => [&["hooks"][..], &LEGACY].concat(),
        "self" => vec!["hooks", "cwd", "guard_home", "package_root", "recorded"],
        "guard_home" => vec!["command", "cwd"],
        "binds" => vec!["command", "cwd", "guard_home", "package_root"],
        "strip" => [
            &["hooks", "owned", "cwd", "guard_home", "package_root"][..],
            &LEGACY,
            &["unlaunchable", "hold_recorded"],
        ]
        .concat(),
        _ => return None,
    };
    Some(fields)
}

pub(super) fn dispatch(fields: &Map<String, Value>) -> Step<Value> {
    let op = text(fields, "op")?;
    let wanted = op_fields(op).ok_or(Failure::Invalid)?;
    let unknown = fields
        .keys()
        .any(|key| !COMMON.contains(&key.as_str()) && !wanted.contains(&key.as_str()));
    if unknown || wanted.iter().any(|key| !fields.contains_key(*key)) {
        return Err(Failure::Invalid);
    }
    let long_paths = long_paths(fields)?;
    let known: BTreeSet<String> = long_paths.keys().cloned().collect();
    let mut syntax = Syntax::new(flag(fields, "windows")?, long_paths);
    let answer = run(op, fields, &mut syntax)?;
    let missing: Vec<&String> = syntax
        .short_tokens()
        .iter()
        .filter(|token| !known.contains(*token))
        .collect();
    if missing.is_empty() {
        Ok(answer)
    } else {
        Err(Failure::Reply(json!({ "expand": missing })))
    }
}

fn run(op: &str, fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<Value> {
    match op {
        "guard_home" => {
            let found = home::guard_home(text(fields, "command")?, &Cwd::parse(fields)?, syntax);
            let found = found.map(|path| path.to_string_lossy().into_owned());
            return Ok(json!({ "home": found }));
        }
        "binds" => {
            let binds = home::binds(text(fields, "command")?, &Home::parse(fields)?, syntax);
            return Ok(json!({ "binds": binds }));
        }
        _ => {}
    }
    let mut hooks = dict(fields, "hooks")?;
    let bindings = match op {
        "legacy" => Legacy::parse(fields)?.bindings(&hooks, syntax),
        "self" => {
            let recorded = strings(fields, "recorded")?.into_iter().collect();
            home::self_bindings(&hooks, &Home::parse(fields)?, &recorded, syntax)
        }
        _ => {
            let changed = match op {
                "remove" => remove(&mut hooks, &list(fields, "bindings")?),
                "unlaunchable" => unlaunchable(&mut hooks, &statuses(fields)?, syntax),
                _ => strip(&mut hooks, fields, syntax)?,
            };
            let hooks = compact(&PyVal::Dict(hooks), false);
            return Ok(json!({ "hooks": hooks, "changed": changed }));
        }
    };
    Ok(json!({ "bindings": compact(&PyVal::List(bindings), false) }))
}

fn long_paths(fields: &Map<String, Value>) -> Step<BTreeMap<String, String>> {
    let entries = fields
        .get("long_paths")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    entries
        .iter()
        .map(|(short, long)| match long.as_str() {
            Some(long) => Ok((short.clone(), long.to_owned())),
            None => Err(Failure::Invalid),
        })
        .collect()
}

fn list(fields: &Map<String, Value>, key: &str) -> Step<Vec<PyVal>> {
    match pyjson::parse(text(fields, key)?) {
        Ok(PyVal::List(items)) => Ok(items),
        _ => Err(Failure::Invalid),
    }
}

pub(super) fn strings(fields: &Map<String, Value>, key: &str) -> Step<Vec<String>> {
    let items = fields
        .get(key)
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn statuses(fields: &Map<String, Value>) -> Step<BTreeSet<String>> {
    Ok(strings(fields, "statuses")?.into_iter().collect())
}

/// `statusMessage in legacy_status_messages`.
fn status_in(handler: &[(String, PyVal)], statuses: &BTreeSet<String>) -> bool {
    get(handler, "statusMessage")
        .and_then(PyVal::as_str)
        .is_some_and(|status| statuses.contains(status))
}

/// `hook_command_tokens`: the hook argv, or the text split on whitespace.
pub(super) fn tokens(syntax: &mut Syntax, command: &str) -> Vec<String> {
    syntax.split_hook(command).unwrap_or_else(|| {
        command
            .split(py_space)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

/// `has_codex_harness_tokens`.
fn has_codex_harness(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        token == "--harness=codex"
            || (token == "--harness" && tokens.get(index + 1).is_some_and(|next| next == "codex"))
    })
}

/// The event's groups once `keep` has rewritten each dict group's handler
/// list, a group left with no handler being dropped and an event left with no
/// group popped. Whether any handler went.
fn rewrite_handlers(
    hooks: &mut Entries,
    event: &str,
    mut keep: impl FnMut(&PyVal) -> bool,
) -> bool {
    let Some(PyVal::List(groups)) = get(hooks, event).cloned() else {
        return false;
    };
    let mut changed = false;
    let mut remaining = Vec::new();
    for group in groups {
        let handlers = match &group {
            PyVal::Dict(entries) => match get(entries, "hooks") {
                Some(PyVal::List(handlers)) => handlers.clone(),
                _ => {
                    remaining.push(group);
                    continue;
                }
            },
            _ => {
                remaining.push(group);
                continue;
            }
        };
        let kept: Vec<PyVal> = handlers.iter().filter(|h| keep(h)).cloned().collect();
        changed |= kept.len() != handlers.len();
        if let (false, PyVal::Dict(mut entries)) = (kept.is_empty(), group) {
            set(&mut entries, "hooks", PyVal::List(kept));
            remaining.push(PyVal::Dict(entries));
        }
    }
    put_groups(hooks, event, remaining);
    changed
}

fn put_groups(hooks: &mut Entries, event: &str, groups: Vec<PyVal>) {
    if groups.is_empty() {
        pop(hooks, event);
    } else {
        set(hooks, event, PyVal::List(groups));
    }
}

/// `remove_unlaunchable_guard_hook_events`.
fn unlaunchable(hooks: &mut Entries, statuses: &BTreeSet<String>, syntax: &mut Syntax) -> bool {
    let mut changed = false;
    for event in EVENTS {
        changed |= rewrite_handlers(hooks, event, |handler| {
            !is_unlaunchable(handler, statuses, syntax)
        });
    }
    changed
}

/// `_is_unlaunchable_legacy_guard_handler`: a legacy Guard handler for this
/// host whose absolute program does not exist.
fn is_unlaunchable(handler: &PyVal, statuses: &BTreeSet<String>, syntax: &mut Syntax) -> bool {
    let Some(entries) = handler.as_dict() else {
        return false;
    };
    let Some(PyVal::Str(command)) = get(entries, "command") else {
        return false;
    };
    if !status_in(entries, statuses) || syntax.windows() != cfg!(windows) {
        return false;
    }
    let mut tokens = tokens(syntax, command);
    let program = tokens.first().cloned().unwrap_or_default();
    if let Some(PyVal::List(arguments)) = get(entries, "args") {
        // `str()` of a non-string never spells a harness token.
        let spelled = arguments.iter().map(|item| item.as_str().unwrap_or(""));
        tokens.extend(spelled.map(str::to_owned));
    }
    if !has_codex_harness(&tokens) {
        return false;
    }
    let path = Path::new(&program);
    path.is_absolute()
        && matches!(
            fs::metadata(path),
            Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
        )
}

/// `remove_manifest_bound_hook_events`: each binding removes its exact group,
/// or else its exact handler from the first group with its matcher.
pub(super) fn remove(hooks: &mut Entries, bindings: &[PyVal]) -> bool {
    let mut changed = false;
    for binding in bindings.iter().filter_map(PyVal::as_dict) {
        let (Some(PyVal::Str(event)), Some(expected @ PyVal::Dict(group)), Some(handler)) = (
            get(binding, "event"),
            get(binding, "group"),
            get(binding, "handler"),
        ) else {
            continue;
        };
        if !EVENTS.contains(&event.as_str()) || handler.as_dict().is_none() {
            continue;
        }
        let Some(PyVal::List(groups)) = get(hooks, event).cloned() else {
            continue;
        };
        let matcher = get(group, "matcher").unwrap_or(&NULL);
        let mut remaining = Vec::new();
        let mut removed = false;
        for candidate in groups {
            let entries = match &candidate {
                PyVal::Dict(entries) if !removed => entries,
                _ => {
                    remaining.push(candidate);
                    continue;
                }
            };
            if py_eq(&candidate, expected) {
                removed = true;
                continue;
            }
            let handlers = match get(entries, "hooks") {
                Some(PyVal::List(handlers))
                    if py_eq(get(entries, "matcher").unwrap_or(&NULL), matcher) =>
                {
                    handlers
                }
                _ => {
                    remaining.push(candidate);
                    continue;
                }
            };
            let Some(index) = handlers.iter().position(|item| py_eq(item, handler)) else {
                remaining.push(candidate);
                continue;
            };
            removed = true;
            let mut rest = handlers.clone();
            rest.remove(index);
            if !rest.is_empty() {
                let mut entries = entries.clone();
                set(&mut entries, "hooks", PyVal::List(rest));
                remaining.push(PyVal::Dict(entries));
            }
        }
        changed |= removed;
        put_groups(hooks, event, remaining);
    }
    changed
}

/// What `exact_legacy_hook_bindings` matches a pre-manifest handler against.
struct Legacy {
    expected: Vec<PyVal>,
    argvs: Vec<Vec<String>>,
    statuses: BTreeSet<String>,
}

impl Legacy {
    fn parse(fields: &Map<String, Value>) -> Step<Self> {
        Ok(Self {
            expected: list(fields, "expected")?,
            argvs: vec![strings(fields, "argv")?, strings(fields, "legacy_argv")?],
            statuses: statuses(fields)?,
        })
    }

    /// `exact_legacy_hook_bindings`: per event, the first group with the
    /// expected matcher holding a handler that runs an accepted argv under a
    /// legacy status message.
    fn bindings(&self, hooks: &Entries, syntax: &mut Syntax) -> Vec<PyVal> {
        let mut accepted = self.argvs.clone();
        if syntax.windows() {
            // Earlier Windows installs passed the config as plain JSON.
            accepted.extend(self.argvs.iter().map(|argv| plain_json(argv)));
        }
        let mut by_event: BTreeMap<&str, &[(String, PyVal)]> = BTreeMap::new();
        for binding in self.expected.iter().filter_map(PyVal::as_dict) {
            if let Some(PyVal::Str(event)) = get(binding, "event") {
                by_event.insert(event.as_str(), binding);
            }
        }
        let mut bindings = Vec::new();
        for event in EVENTS {
            let expected = by_event
                .get(event)
                .and_then(|binding| get(binding, "group"));
            let (Some(PyVal::List(groups)), Some(PyVal::Dict(expected))) =
                (get(hooks, event), expected)
            else {
                continue;
            };
            let matcher = get(expected, "matcher").unwrap_or(&NULL);
            for group in groups {
                let Some(entries) = group.as_dict() else {
                    continue;
                };
                if !py_eq(get(entries, "matcher").unwrap_or(&NULL), matcher) {
                    continue;
                }
                let Some(PyVal::List(handlers)) = get(entries, "hooks") else {
                    continue;
                };
                let found = handlers
                    .iter()
                    .find(|item| self.accepts(item, &accepted, syntax));
                if let Some(handler) = found {
                    bindings.push(binding(event, group.clone(), handler.clone()));
                    break;
                }
            }
        }
        bindings
    }

    fn accepts(&self, item: &PyVal, accepted: &[Vec<String>], syntax: &mut Syntax) -> bool {
        let Some(entries) = item.as_dict() else {
            return false;
        };
        let Some(PyVal::Str(command)) = get(entries, "command") else {
            return false;
        };
        syntax
            .split_hook(command)
            .is_some_and(|argv| accepted.contains(&argv))
            && status_in(entries, &self.statuses)
    }
}

/// `plain_json_hook_argv`.
fn plain_json(argv: &[String]) -> Vec<String> {
    let Some((last, head)) = argv.split_last() else {
        return Vec::new();
    };
    match crate::codex_hook_bridge::decode_config_argument(last) {
        Some(config) => [head, &[config.into_owned()]].concat(),
        None => argv.to_vec(),
    }
}

pub(super) fn binding(event: &str, group: PyVal, handler: PyVal) -> PyVal {
    PyVal::Dict(vec![
        ("event".to_owned(), PyVal::Str(event.to_owned())),
        ("group".to_owned(), group),
        ("handler".to_owned(), handler),
    ])
}

/// `_recorded_handler_commands`.
fn recorded_commands(bindings: &[PyVal]) -> BTreeSet<String> {
    bindings
        .iter()
        .filter_map(PyVal::as_dict)
        .filter_map(|binding| get(binding, "handler").and_then(PyVal::as_dict))
        .filter_map(|handler| get(handler, "command").and_then(PyVal::as_str))
        .map(str::to_owned)
        .collect()
}

/// `_strip_owned_hooks`: the owned handlers, then this package's legacy
/// registrations, optionally the unlaunchable ones, then this install's own
/// earlier generations. `hold_recorded` keeps a handler still running a
/// command the owned bindings record.
fn strip(hooks: &mut Entries, fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<bool> {
    let owned = list(fields, "owned")?;
    let legacy = Legacy::parse(fields)?;
    let home = Home::parse(fields)?;
    let mut changed = remove(hooks, &owned);
    let found = legacy.bindings(hooks, syntax);
    changed |= remove(hooks, &found);
    if flag(fields, "unlaunchable")? {
        changed |= unlaunchable(hooks, &legacy.statuses, syntax);
    }
    let recorded = if flag(fields, "hold_recorded")? {
        recorded_commands(&owned)
    } else {
        BTreeSet::new()
    };
    let found = home::self_bindings(hooks, &home, &recorded, syntax);
    changed |= remove(hooks, &found);
    Ok(changed)
}
