//! Guard hook signatures and the pruning `hook-removal-sweep` applies to a
//! parsed config payload or, for TOML, to the document itself
//! (`hook_removal_sweep.rs` reads and writes the files).

use toml_edit::{DocumentMut, Item, TableLike};

use crate::local_mcp_grant_identity::shlex_split;
use crate::pyjson::{float_repr, PyVal};

const COMMAND_KEYS: [&str; 5] = ["command", "bash", "powershell", "script", "cmd"];
const GUARD_EXECUTABLES: [&str; 5] = [
    "hol-guard",
    "hol-guard.exe",
    "hol guard",
    "plugin-guard",
    "plugin-guard.exe",
];
const GUARD_MARKERS: [&str; 12] = [
    "hol_guard_managed",
    "hol guard managed",
    "hol_guard_claude_daemon_hook",
    "hol_guard_claude_session_start_hook",
    "hol-guard-codex-hook",
    "hol-guard-cursor-hook",
    "hol_guard_hook_argv",
    "__guard-bounded-hook",
    "codex_daemon_hook_bridge",
    "claude_daemon_hook_bridge",
    "bounded_cli_hook_bridge",
    "managed/bounded-hooks/",
];
/// A TOML datetime has no JSON form; this tag keeps it distinct from any
/// string while payloads are compared.
const DATETIME_TAG: &str = "\u{0}datetime:";

// --- Guard signatures -------------------------------------------------------

pub(crate) fn text_is_guard(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }
    let lowered = command.to_lowercase().replace("\\\"", "\"");
    if GUARD_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return true;
    }
    let tokens = shlex_split(command)
        .unwrap_or_else(|| command.split_whitespace().map(str::to_owned).collect());
    tokens_are_guard(&tokens)
}

fn tokens_are_guard(tokens: &[String]) -> bool {
    let Some((first, rest)) = tokens.split_first() else {
        return false;
    };
    let first = base_name(&first.replace('\\', "/")).to_lowercase();
    let rest: Vec<String> = rest.iter().map(|token| token.to_lowercase()).collect();
    let has = |word: &str| rest.iter().any(|token| token == word);
    if GUARD_EXECUTABLES.contains(&first.as_str()) && has("hook") {
        return true;
    }
    let joined = rest.join(" ");
    if !joined.contains("codex_plugin_scanner.cli") {
        return false;
    }
    (has("guard") && has("hook")) || joined.contains("'guard', 'hook'")
}

/// `pathlib.Path(path).name` for a slash-separated path.
fn base_name(path: &str) -> &str {
    let path = match path.as_bytes() {
        [drive, b':', ..] if cfg!(windows) && drive.is_ascii_alphabetic() => &path[2..],
        _ => path,
    };
    path.rsplit('/')
        .find(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

fn is_handler(node: &PyVal) -> bool {
    matches!(node, PyVal::Dict(_))
        && COMMAND_KEYS
            .iter()
            .any(|key| matches!(node.get(key), Some(PyVal::Str(_))))
}

fn handler_is_guard(handler: &PyVal) -> bool {
    let string = |key: &str| handler.get(key).and_then(PyVal::as_str);
    if COMMAND_KEYS
        .iter()
        .any(|key| string(key).is_some_and(text_is_guard))
    {
        return true;
    }
    // Claude's exec form splits the argv into `command` plus an `args` list.
    let (Some(command), Some(PyVal::List(args))) = (string("command"), handler.get("args")) else {
        return false;
    };
    let Some(args) = args
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
    else {
        return false;
    };
    // Match each argv entry on its own. Joining them would let a marker form
    // across plain words the user passed separately.
    let argv: Vec<String> = std::iter::once(command.to_owned()).chain(args).collect();
    if argv.iter().any(|arg| {
        let lowered = arg.to_lowercase().replace("\\\"", "\"");
        GUARD_MARKERS.iter().any(|marker| lowered.contains(marker))
    }) {
        return true;
    }
    tokens_are_guard(&argv)
}

// --- Pruning a parsed payload -------------------------------------------------

/// Drop Guard handlers (and matcher groups they leave empty) from one event
/// list.
fn prune_entries(entries: &[PyVal], removed: &mut Vec<String>, event: &str) -> Vec<PyVal> {
    let mut kept = Vec::new();
    for item in entries {
        let PyVal::Dict(fields) = item else {
            kept.push(item.clone());
            continue;
        };
        if is_handler(item) {
            if handler_is_guard(item) {
                removed.push(event.to_owned());
            } else {
                kept.push(item.clone());
            }
            continue;
        }
        let Some(PyVal::List(inner)) = item.get("hooks") else {
            kept.push(item.clone());
            continue;
        };
        let before = removed.len();
        let pruned = prune_entries(inner, removed, event);
        if removed.len() == before {
            kept.push(item.clone());
        } else if !pruned.is_empty() {
            let fields = fields
                .iter()
                .map(|(key, value)| match key.as_str() {
                    "hooks" => (key.clone(), PyVal::List(pruned.clone())),
                    _ => (key.clone(), value.clone()),
                })
                .collect();
            kept.push(PyVal::Dict(fields));
        }
        // A group left with no handlers has nothing to run; drop it.
    }
    kept
}

/// The payload without Guard handlers under its `hooks` key, plus the event
/// of each removed handler; `None` when nothing is Guard's.
pub(crate) fn prune_guard_hooks(payload: &PyVal) -> Option<(PyVal, Vec<String>)> {
    let PyVal::Dict(fields) = payload else {
        return None;
    };
    let mut removed = Vec::new();
    let pruned = match payload.get("hooks")? {
        PyVal::List(entries) => PyVal::List(prune_entries(entries, &mut removed, "")),
        PyVal::Dict(events) => {
            let mut kept = Vec::new();
            for (name, entries) in events {
                let PyVal::List(entries) = entries else {
                    kept.push((name.clone(), entries.clone()));
                    continue;
                };
                let before = removed.len();
                let pruned = prune_entries(entries, &mut removed, name);
                if removed.len() > before && pruned.is_empty() {
                    continue;
                }
                kept.push((name.clone(), PyVal::List(pruned)));
            }
            PyVal::Dict(kept)
        }
        _ => return None,
    };
    if removed.is_empty() {
        return None;
    }
    let empty = matches!(&pruned, PyVal::List(items) if items.is_empty())
        || matches!(&pruned, PyVal::Dict(items) if items.is_empty());
    let fields = fields
        .iter()
        .filter_map(|(key, value)| match key.as_str() {
            "hooks" if empty => None,
            "hooks" => Some((key.clone(), pruned.clone())),
            _ => Some((key.clone(), value.clone())),
        })
        .collect();
    Some((PyVal::Dict(fields), removed))
}

// --- Pruning a TOML document in place -------------------------------------------

/// Remove Guard handlers from the document's `hooks`, returning how many went.
pub(crate) fn prune_document(document: &mut DocumentMut) -> usize {
    let mut removed = 0;
    let root = document.as_table_mut();
    let Some(hooks) = root.get_mut("hooks") else {
        return 0;
    };
    let empty = if is_list(hooks) {
        prune_list(hooks, &mut removed);
        list_len(hooks) == 0
    } else if let Some(events) = hooks.as_table_like_mut() {
        let names: Vec<String> = events.iter().map(|(name, _)| name.to_owned()).collect();
        for name in names {
            let Some(entries) = events.get_mut(&name) else {
                continue;
            };
            if !is_list(entries) {
                continue;
            }
            let before = removed;
            prune_list(entries, &mut removed);
            if removed > before && list_len(entries) == 0 {
                events.remove(&name);
            }
        }
        events.is_empty()
    } else {
        return 0;
    };
    if removed > 0 && empty {
        root.remove("hooks");
    }
    removed
}

fn is_list(item: &Item) -> bool {
    item.is_array_of_tables() || item.is_array()
}

fn list_len(item: &Item) -> usize {
    item.as_array_of_tables()
        .map(|tables| tables.len())
        .or_else(|| item.as_array().map(|array| array.len()))
        .unwrap_or(0)
}

fn prune_list(item: &mut Item, removed: &mut usize) {
    if let Some(tables) = item.as_array_of_tables_mut() {
        let mut index = 0;
        while index < tables.len() {
            let drop = tables
                .get_mut(index)
                .is_some_and(|table| prune_element(table, removed));
            if drop {
                tables.remove(index);
            } else {
                index += 1;
            }
        }
    } else if let Some(array) = item.as_array_mut() {
        let mut index = 0;
        while index < array.len() {
            let drop = array
                .get_mut(index)
                .and_then(|value| value.as_inline_table_mut())
                .is_some_and(|table| prune_element(table, removed));
            if drop {
                array.remove(index);
            } else {
                index += 1;
            }
        }
    }
}

/// Whether one list element goes: a Guard handler, or a group whose
/// handlers were all Guard's.
fn prune_element(table: &mut dyn TableLike, removed: &mut usize) -> bool {
    let view = table_value(&*table);
    if is_handler(&view) {
        if handler_is_guard(&view) {
            *removed += 1;
            return true;
        }
        return false;
    }
    let Some(inner) = table.get_mut("hooks") else {
        return false;
    };
    if !is_list(inner) {
        return false;
    }
    let before = *removed;
    prune_list(inner, removed);
    *removed > before && list_len(inner) == 0
}

// --- Values ---------------------------------------------------------------------

pub(crate) fn table_value(table: &dyn TableLike) -> PyVal {
    PyVal::Dict(
        table
            .iter()
            .filter_map(|(key, item)| item_value(item).map(|value| (key.to_owned(), value)))
            .collect(),
    )
}

fn item_value(item: &Item) -> Option<PyVal> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(toml_value(value)),
        Item::Table(table) => Some(table_value(table)),
        Item::ArrayOfTables(tables) => Some(PyVal::List(
            tables.iter().map(|table| table_value(table)).collect(),
        )),
    }
}

fn toml_value(value: &toml_edit::Value) -> PyVal {
    match value {
        toml_edit::Value::String(text) => PyVal::Str(text.value().clone()),
        toml_edit::Value::Integer(number) => PyVal::Int(number.value().to_string()),
        toml_edit::Value::Float(number) => PyVal::Float(*number.value()),
        toml_edit::Value::Boolean(flag) => PyVal::Bool(*flag.value()),
        toml_edit::Value::Datetime(stamp) => PyVal::Str(format!("{DATETIME_TAG}{}", stamp.value())),
        toml_edit::Value::Array(items) => PyVal::List(items.iter().map(toml_value).collect()),
        toml_edit::Value::InlineTable(table) => table_value(table),
    }
}

/// Python `==` on parsed payloads: mappings compare without regard to order.
pub(crate) fn same(left: &PyVal, right: &PyVal) -> bool {
    match (left, right) {
        (PyVal::Dict(left), PyVal::Dict(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .iter()
                        .any(|(other, item)| other == key && same(value, item))
                })
        }
        (PyVal::List(left), PyVal::List(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| same(a, b))
        }
        _ => left == right,
    }
}

/// `json.dumps(value, indent=2)`: `ensure_ascii`, CPython float spelling.
pub(crate) fn write_indented(value: &PyVal, depth: usize, out: &mut Vec<u8>) -> Option<()> {
    let indent = |out: &mut Vec<u8>, depth: usize| {
        out.push(b'\n');
        out.extend(std::iter::repeat_n(b' ', depth * 2));
    };
    match value {
        PyVal::Null => out.extend_from_slice(b"null"),
        PyVal::Bool(true) => out.extend_from_slice(b"true"),
        PyVal::Bool(false) => out.extend_from_slice(b"false"),
        PyVal::Int(digits) => out.extend_from_slice(digits.as_bytes()),
        PyVal::Float(number) if number.is_nan() => out.extend_from_slice(b"NaN"),
        PyVal::Float(number) if number.is_infinite() && *number > 0.0 => {
            out.extend_from_slice(b"Infinity");
        }
        PyVal::Float(number) if number.is_infinite() => out.extend_from_slice(b"-Infinity"),
        PyVal::Float(number) => out.extend_from_slice(float_repr(*number).as_bytes()),
        PyVal::Str(text) => guard_contracts::write_json_string(text, out),
        PyVal::List(items) if items.is_empty() => out.extend_from_slice(b"[]"),
        PyVal::List(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                indent(out, depth + 1);
                write_indented(item, depth + 1, out)?;
            }
            indent(out, depth);
            out.push(b']');
        }
        PyVal::Dict(entries) if entries.is_empty() => out.extend_from_slice(b"{}"),
        PyVal::Dict(entries) => {
            out.push(b'{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                indent(out, depth + 1);
                guard_contracts::write_json_string(key, out);
                out.extend_from_slice(b": ");
                write_indented(item, depth + 1, out)?;
            }
            indent(out, depth);
            out.push(b'}');
        }
    }
    Some(())
}
