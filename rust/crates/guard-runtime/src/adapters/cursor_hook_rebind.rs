//! The `cursor_hook_config` ops that decide whether Guard's managed Cursor
//! hook must be rewritten (`rebind_stale_cursor_hooks` and
//! `cursor_hook_script_bakes_ephemeral_cli` in `guard/cursor_hook_rebind.py`
//! before they moved here).
//!
//! Python keeps the file reads, the live-script path checks, the attested CLI
//! identity and the install itself. It sends the live and managed script
//! sources, the source an install would write now, the structured commands
//! whose live script exists, and whether an isolated Python and the native
//! bridge are available. These ops decide.
//!
//! `ephemeral` answers `{"ephemeral": bool}` for one script source: whether a
//! managed script bakes a Desktop Core launcher below `versions/` or
//! `bundled/`, which Desktop can prune on update.
//!
//! `rebind` answers `{"rebind": bool}`. Python still skips the install when
//! the answer is false and the hook state already names the attested CLI.

use serde_json::{json, Map, Value};

use super::cursor_hook_command::Syntax;
use super::cursor_hook_config::is_managed_script;
use super::runner_authority_op::ERR_INVALID;

const NATIVE_COMMAND: &str = "cursor-hook-bridge";
const BAKED_ARGV: [&str; 2] = ["GUARD_CLI", "GUARD_RECOVERY_COMMAND"];
pub(crate) const REBIND_KEYS: &[&str] = &[
    "live",
    "managed",
    "expected",
    "commands",
    "isolated_python",
    "native_bridge",
];
/// Python's `str.splitlines()` terminators.
const LINE_BREAKS: [char; 10] = [
    '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}',
];

fn text(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or(ERR_INVALID)
}

fn flag(value: &Value) -> Result<bool, &'static str> {
    value.as_bool().ok_or(ERR_INVALID)
}

/// `[[command, frozen], ...]`: the structured managed commands whose live
/// script Python found on disk.
fn commands(value: &Value) -> Result<Vec<(&str, bool)>, &'static str> {
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| match item.as_array().map(Vec::as_slice) {
            Some([Value::String(command), Value::Bool(frozen)]) => Ok((command.as_str(), *frozen)),
            _ => Err(ERR_INVALID),
        })
        .collect()
}

pub(crate) fn ephemeral(syntax: &Syntax, source: &str) -> Value {
    json!({ "ephemeral": bakes_ephemeral_cli(source, syntax.windows()) })
}

pub(crate) fn rebind(
    syntax: &mut Syntax,
    fields: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let live = text(&fields["live"])?;
    let managed = match &fields["managed"] {
        Value::Null => None,
        value => Some(text(value)?),
    };
    let expected = text(&fields["expected"])?;
    let commands = commands(&fields["commands"])?;
    let isolated_python = flag(&fields["isolated_python"])?;
    let native_bridge = flag(&fields["native_bridge"])?;
    let windows = syntax.windows();
    let stale = |source: &str| source != expected || bakes_ephemeral_cli(source, windows);
    let rebind = stale(live)
        || managed.is_some_and(stale)
        || (isolated_python && commands.iter().any(|(_, frozen)| *frozen))
        || (native_bridge
            && commands
                .iter()
                .any(|(command, _)| skips_native_bridge(syntax, command)));
    Ok(json!({ "rebind": rebind }))
}

/// A managed command that starts the client directly instead of through the
/// native bridge.
fn skips_native_bridge(syntax: &mut Syntax, command: &str) -> bool {
    let tokens = syntax.split_cursor(command).unwrap_or_default();
    tokens.get(1).map(String::as_str) != Some(NATIVE_COMMAND)
}

/// `cursor_hook_script_bakes_ephemeral_cli`.
pub(crate) fn bakes_ephemeral_cli(source: &str, windows: bool) -> bool {
    is_managed_script(source)
        && BAKED_ARGV.iter().any(|name| {
            assignment_argv(source, name)
                .and_then(|argv| argv.into_iter().next())
                .is_some_and(|argv0| ephemeral_desktop_cli(&argv0, windows))
        })
}

/// `_assignment_argv`: the JSON string list on the first `NAME = ` line.
fn assignment_argv(source: &str, name: &str) -> Option<Vec<String>> {
    let prefix = format!("{name} = ");
    let line = source
        .split_inclusive(LINE_BREAKS)
        .map(|line| line.trim_end_matches(LINE_BREAKS))
        .find(|line| line.starts_with(&prefix))?;
    match serde_json::from_str::<Value>(&line[prefix.len()..]).ok()? {
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::String(text) => Some(text),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// `argv0_is_ephemeral_desktop_cli`: a `hol-guard` launcher at
/// `versions/<release>/`, `versions/<release>/bundle/`,
/// `bundled/<release>/bin/` or `bundled/<release>/lib/hol-guard-core/`.
pub(crate) fn ephemeral_desktop_cli(argv0: &str, windows: bool) -> bool {
    let parts: Vec<&str> = argv0
        .split(|ch| ch == '/' || (windows && ch == '\\'))
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some(name) = parts.last() else {
        return false;
    };
    if !["hol-guard", "hol-guard.exe"].contains(&name.to_lowercase().as_str()) {
        return false;
    }
    (0..parts.len() - 1).any(|at| {
        let relative = &parts[at + 1..];
        match parts[at].to_lowercase().as_str() {
            "versions" => relative.len() == 2 || (relative.len() == 3 && relative[1] == "bundle"),
            "bundled" => {
                (relative.len() == 3 && relative[1] == "bin")
                    || (relative.len() == 4 && relative[1..3] == ["lib", "hol-guard-core"])
            }
            _ => false,
        }
    })
}
