//! `runner_authority` kind `cursor_hook_script`: the Cursor hook client
//! Guard installs and the daemon recovery command baked into it.
//!
//! `render` fills the client template with the six constants the native
//! bridge reads back (`cursor_hook_bridge_script`): the resolved Guard home,
//! the attested CLI, the recovery command, the hook argv, the environment
//! the hook inherits and its timeout. Placeholders are replaced in order the
//! way `str.replace` did, each value spelled as `json.dumps` writes it.
//!
//! `recovery` builds the isolated Python bootstrap that recovers the daemon
//! after a hook failure from the attested interpreter and its import roots.
//!
//! Python keeps the path resolution and the attestation: it sends the
//! resolved paths, the CLI argv and whether the home differs from the
//! user's own, so every op here is lexical.

use serde_json::{json, Map, Value};

use super::context_digest_local_cli::python_path_name;
use super::hermes_printable::is_printable;
use super::opencode_plugin_render::dumps;
use super::pyjson::PyVal;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// The client template; its SHA-256 is `CURSOR_SCRIPT_SHA256`, which the
/// native bridge reader is reviewed against.
const TEMPLATE: &str = r#"#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""
import json
import sys

GUARD_HOME = __GUARD_HOME__
GUARD_CLI = __GUARD_CLI__
GUARD_RECOVERY_COMMAND = __GUARD_RECOVERY_COMMAND__
GUARD_HOOK_ARGV = __GUARD_HOOK_ARGV__
GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__
GUARD_HOOK_TIMEOUT_SECONDS = __GUARD_HOOK_TIMEOUT_SECONDS__
_OBSERVER_EVENTS = frozenset({"aftershellexecution", "aftermcpexecution"})
_UNAVAILABLE_REASON = "HOL Guard could not complete the native hook decision safely."


def _hook_event() -> str:
    args = sys.argv
    if "--cursor-hook-event" not in args:
        return ""
    index = args.index("--cursor-hook-event") + 1
    return str(args[index]) if index < len(args) else ""


def main() -> int:
    """Answer a hook Guard's native runtime did not answer in front of this client."""

    compact = _hook_event().strip().lower().replace("_", "").replace("-", "")
    if compact in _OBSERVER_EVENTS:
        print("{}")
        return 0
    print(json.dumps({"permission": "deny", "user_message": _UNAVAILABLE_REASON}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
"#;
const INHERIT_ENV_KEYS: [&str; 19] = [
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",
    "CURSOR_PROJECT_DIR",
    "CURSOR_VERSION",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    "HOL_GUARD_SRC",
    "HOL_GUARD_TEST_MODE",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
];
/// The Cursor timeout of each managed hook entry; the client gives its own
/// hook three seconds less so Cursor never kills it first.
const HOOK_ENTRY_TIMEOUT_SECONDS: u64 = 45;
/// CLI names that expose `hook` without a `guard` prefix.
const TOP_LEVEL_NAMES: [&str; 7] = [
    "hol-guard",
    "hol-guard.exe",
    "plugin-guard",
    "plugin-guard.exe",
    "current-hol-guard",
    "current-hol-guard.cmd",
    "current-hol-guard.exe",
];
const RENDER_KEYS: [&str; 6] = [
    "op",
    "guard_home",
    "guard_home_resolved",
    "home",
    "guard_cli",
    "recovery_command",
];
const RECOVERY_KEYS: [&str; 5] = ["op", "python", "import_roots", "guard_home", "home"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("render") if exact(map, &RENDER_KEYS) => render(map),
        Some("recovery") if exact(map, &RECOVERY_KEYS) => recovery(map),
        _ => Err(ERR_INVALID),
    }
}

fn exact(map: &Map<String, Value>, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

fn text(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or(ERR_INVALID)
}

fn strings(value: &Value) -> Result<Vec<&str>, &'static str> {
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(text)
        .collect()
}

/// `json.dumps` of a list of strings.
fn dumps_list(items: &[&str]) -> String {
    dumps(&PyVal::List(
        items
            .iter()
            .map(|item| PyVal::Str((*item).to_owned()))
            .collect(),
    ))
}

/// `stable_guard_cli.uses_top_level_hook_command`.
fn uses_top_level_hook_command(guard_cli: &[&str]) -> bool {
    guard_cli.first().is_some_and(|argv0| {
        let name = python_path_name(argv0).to_lowercase();
        TOP_LEVEL_NAMES.contains(&name.as_str())
    })
}

/// `cursor_hook_script_source`. `home` is null when the Cursor home is the
/// user's own, so the hook argv names no `--home`.
fn render(map: &Map<String, Value>) -> KindResult {
    let guard_home = text(&map["guard_home"])?;
    let resolved = text(&map["guard_home_resolved"])?;
    let home = match &map["home"] {
        Value::Null => None,
        value => Some(text(value)?),
    };
    let guard_cli = strings(&map["guard_cli"])?;
    let recovery = strings(&map["recovery_command"])?;
    let mut argv = vec![
        "hook",
        "--guard-home",
        guard_home,
        "--harness",
        "cursor",
        "--json",
    ];
    if let Some(home) = home {
        argv.extend(["--home", home]);
    }
    if !uses_top_level_hook_command(&guard_cli) {
        argv.insert(0, "guard");
    }
    let timeout = HOOK_ENTRY_TIMEOUT_SECONDS.saturating_sub(3).max(1);
    let source = TEMPLATE
        .replace("__GUARD_HOME__", &dumps(&PyVal::Str(resolved.to_owned())))
        .replace("__GUARD_CLI__", &dumps_list(&guard_cli))
        .replace("__GUARD_RECOVERY_COMMAND__", &dumps_list(&recovery))
        .replace("__GUARD_HOOK_ARGV__", &dumps_list(&argv))
        .replace("__GUARD_INHERIT_ENV_KEYS__", &dumps_list(&INHERIT_ENV_KEYS))
        .replace("__GUARD_HOOK_TIMEOUT_SECONDS__", &timeout.to_string());
    Ok(json!({ "source": source }))
}

/// `_cursor_recovery_command` for an attested interpreter: `python` is its
/// target path, `guard_home` and `home` are resolved.
fn recovery(map: &Map<String, Value>) -> KindResult {
    let python = text(&map["python"])?;
    let roots = dumps_list(&strings(&map["import_roots"])?);
    let guard_home = py_repr(text(&map["guard_home"])?);
    let home = py_repr(text(&map["home"])?);
    let bootstrap = format!(
        "import json,sys;sys.path[:0]={roots};from pathlib import Path;\
         from codex_plugin_scanner.guard.daemon import recover_guard_daemon_after_hook_failure;\
         recover_guard_daemon_after_hook_failure(Path({guard_home}),\
         home_dir=Path({home}),failure_kind=sys.argv[1])"
    );
    Ok(json!({ "command": [python, "-I", "-S", "-s", "-c", bootstrap] }))
}

/// `repr(str)`: characters `str.isprintable()` rejects are escaped.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            ch if !is_printable(ch) => {
                let code = ch as u32;
                if code < 0x100 {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code < 0x1_0000 {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
#[path = "cursor_hook_script_tests.rs"]
mod tests;
