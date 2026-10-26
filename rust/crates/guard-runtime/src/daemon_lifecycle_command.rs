//! Classification of daemon command lines: which are Guard daemon serve
//! invocations, which guard home and port they name, and whether two of them
//! are the same invocation.

use guard_contracts::{
    DaemonCommandIdentityQueryV1, DaemonInspectCommandQueryV1, DaemonInspectPartsQueryV1,
    DaemonSameInvocationQueryV1,
};
use serde_json::{json, Value};

use crate::daemon_lifecycle_facts::{is_launcher, Ctx};
use crate::daemon_lifecycle_text::python_int;

const HOOK_LAUNCHER_ARGS: [&str; 2] = ["__guard-bounded-hook", "__guard-cursor-hook"];
const MODULE: &str = "codex_plugin_scanner.cli";

/// `_guard_daemon_command_parts_match`.
pub(crate) fn parts_match(ctx: &Ctx, parts: &[String]) -> bool {
    if parts
        .iter()
        .any(|part| HOOK_LAUNCHER_ARGS.contains(&part.as_str()))
    {
        return false;
    }
    if ctx.frozen_context(parts).is_some() {
        return true;
    }
    for index in 0..parts.len().saturating_sub(1) {
        let window = |width: usize| -> Option<&[String]> { parts.get(index..index + width) };
        let serve = window(2).is_some_and(|slice| slice[0] == "daemon" && slice[1] == "--serve");
        let guard_serve = window(3).is_some_and(|slice| {
            slice[0] == "guard" && slice[1] == "daemon" && slice[2] == "--serve"
        });
        if !serve && !guard_serve {
            continue;
        }
        if parts[..index].iter().any(|part| part == MODULE) {
            return true;
        }
        if index > 0 && is_launcher(&parts[index - 1]) {
            return true;
        }
    }
    false
}

/// `_guard_home_from_command_parts`.
pub(crate) fn home_from_parts(ctx: &Ctx, parts: &[String]) -> Option<String> {
    if let Some((home, _port)) = ctx.frozen_context(parts) {
        return Some(home);
    }
    for (index, part) in parts.iter().enumerate() {
        if part == "--guard-home" && index + 1 < parts.len() {
            return non_empty_path(ctx, &parts[index + 1]);
        }
        if let Some(value) = part.strip_prefix("--guard-home=") {
            return non_empty_path(ctx, value);
        }
    }
    None
}

fn non_empty_path(ctx: &Ctx, value: &str) -> Option<String> {
    (!value.is_empty()).then(|| ctx.path_text(value))
}

fn positive_port(text: &str) -> Option<i64> {
    python_int(text).filter(|port| *port > 0)
}

/// `_guard_daemon_port_from_command`.
pub(crate) fn port_from_parts(ctx: &Ctx, parts: &[String]) -> Option<i64> {
    if let Some((_home, port)) = ctx.frozen_context(parts) {
        return Some(port);
    }
    for (index, part) in parts.iter().enumerate() {
        if let Some(value) = part.strip_prefix("--port=") {
            return positive_port(value);
        }
        if part != "--port" || index + 1 >= parts.len() {
            continue;
        }
        return positive_port(&parts[index + 1]);
    }
    None
}

pub(crate) fn inspect_command(ctx: &Ctx, query: &DaemonInspectCommandQueryV1) -> Value {
    let Some(parts) = ctx.split_command(&query.command) else {
        return json!({"split_ok": false, "matches": false, "guard_home": null, "port": null});
    };
    json!({
        "split_ok": true,
        "matches": parts_match(ctx, &parts),
        "guard_home": home_from_parts(ctx, &parts),
        "port": port_from_parts(ctx, &parts),
    })
}

/// `_split_process_command`: the argv of a command line, or null.
pub(crate) fn split_command(ctx: &Ctx, query: &DaemonInspectCommandQueryV1) -> Value {
    json!({"parts": ctx.split_command(&query.command)})
}

/// The parts-level classification used by the frozen bootloader proof.
pub(crate) fn inspect_parts(ctx: &Ctx, query: &DaemonInspectPartsQueryV1) -> Value {
    json!({
        "matches": parts_match(ctx, &query.parts),
        "guard_home": home_from_parts(ctx, &query.parts),
    })
}

/// `_guard_daemon_pid_command_identity`: whether a pid's command line is the
/// expected daemon (`true`), another process (`false`) or unresolvable (null).
pub(crate) fn command_identity(ctx: &Ctx, query: &DaemonCommandIdentityQueryV1) -> Value {
    let Some(parts) = query
        .command
        .as_deref()
        .and_then(|command| ctx.split_command(command))
    else {
        return json!({"identity": null});
    };
    if !parts_match(ctx, &parts) {
        return json!({"identity": false});
    }
    let Some(expected) = &query.expected_home else {
        return json!({"identity": true});
    };
    let home = home_from_parts(ctx, &parts).unwrap_or_else(|| ctx.path_text(&query.implicit_home));
    json!({"identity": ctx.same_path(&home, expected)})
}

/// `_same_daemon_invocation`.
pub(crate) fn same_invocation(ctx: &Ctx, query: &DaemonSameInvocationQueryV1) -> Value {
    let left = ctx.split_command(&query.left);
    let right = ctx.split_command(&query.right);
    let same = match (left, right) {
        (Some(left), Some(right)) => same_parts(ctx, &left, &right),
        _ => false,
    };
    json!({"same": same})
}

fn same_parts(ctx: &Ctx, left: &[String], right: &[String]) -> bool {
    if !parts_match(ctx, left) || !parts_match(ctx, right) {
        return false;
    }
    let (left_home, right_home) = (home_from_parts(ctx, left), home_from_parts(ctx, right));
    let (left_port, right_port) = (port_from_parts(ctx, left), port_from_parts(ctx, right));
    match (left_home, right_home, left_port, right_port) {
        (Some(left_home), Some(right_home), Some(left_port), Some(right_port)) => {
            ctx.same_path(&left_home, &right_home) && left_port == right_port
        }
        _ => false,
    }
}
