//! Process-inventory proof: which running processes are daemons of one guard
//! home, whether any competes with the caller, and which belong to ephemeral
//! (test) homes.

use guard_contracts::{
    DaemonCompetingQueryV1, DaemonEphemeralHomeQueryV1, DaemonEphemeralProcessesQueryV1,
    DaemonProcessInventoryQueryV1,
};
use serde_json::{json, Value};

use crate::daemon_lifecycle_command::{home_from_parts, parts_match, port_from_parts};
use crate::daemon_lifecycle_facts::Ctx;
use crate::daemon_lifecycle_malformed::may_launch_guard;
use crate::daemon_lifecycle_text::{py_isspace, py_splitlines, py_strip, python_int};

/// Leading `^\s*(\d+)\s+` of a process listing line: the pid and the rest.
fn pid_prefix(line: &str) -> Option<(i64, &str)> {
    let line = line.trim_start_matches(py_isspace);
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = &line[digits..];
    let trimmed = rest.trim_start_matches(py_isspace);
    if trimmed.len() == rest.len() {
        return None;
    }
    Some((line[..digits].parse().ok()?, trimmed))
}

fn listing_entries(output: &str) -> Vec<(i64, String)> {
    py_splitlines(output)
        .into_iter()
        .filter_map(|line| pid_prefix(line).map(|(pid, rest)| (pid, py_strip(rest).to_owned())))
        .collect()
}

fn unknown() -> Value {
    json!({"known": false, "processes": []})
}

pub(crate) fn process_inventory(ctx: &Ctx, query: &DaemonProcessInventoryQueryV1) -> Value {
    let entries = match (&query.ps_output, &query.entries) {
        (Some(output), _) => listing_entries(output),
        (None, Some(entries)) => entries.clone(),
        (None, None) => return unknown(),
    };
    let mut processes: Vec<(i64, i64)> = Vec::new();
    for (pid, command_line) in &entries {
        let Some(parts) = ctx.split_command(command_line) else {
            // A missing argv is requested with the rest of this round. Treating
            // it as a parse failure stops the walk at the first daemon and
            // makes each later daemon cost another round.
            if ctx.argv_pending(command_line) {
                continue;
            }
            let lowered = command_line.to_lowercase();
            let mentions_guard =
                lowered.contains("codex_plugin_scanner") || lowered.contains("guard");
            if mentions_guard && may_launch_guard(command_line) {
                return unknown();
            }
            continue;
        };
        if !parts_match(ctx, &parts) {
            continue;
        }
        let home =
            home_from_parts(ctx, &parts).unwrap_or_else(|| ctx.path_text(&query.implicit_home));
        if !ctx.same_path(&home, &query.guard_home) {
            continue;
        }
        let Some(port) = port_from_parts(ctx, &parts) else {
            // A serving process may request the OS-assigned port (or omit it).
            // It cannot compete with itself; other unresolved pids stay unknown.
            if *pid == query.own_pid {
                continue;
            }
            if query.frozen_runtime && *pid == query.parent_pid {
                // Exact executable/home bootloader proof before the parent's
                // dynamic port can turn the inventory unknown.
                let trusted = ctx
                    .fact("frozen_parent_trusted".to_owned())
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if trusted {
                    continue;
                }
            }
            return unknown();
        };
        processes.push((*pid, port));
    }
    processes.sort_by_key(|(_pid, port)| *port);
    json!({"known": true, "processes": processes})
}

pub(crate) fn competing_daemon(query: &DaemonCompetingQueryV1) -> Value {
    let competing = query
        .inventory
        .iter()
        .any(|(pid, _port)| *pid != query.own_pid && Some(*pid) != query.launcher_parent);
    json!({"competing": competing})
}

/// `_elapsed_seconds_from_ps` for `[[dd-]hh:]mm:ss`; `None` is `ValueError`.
fn elapsed_seconds(value: &str) -> Option<f64> {
    let trimmed = py_strip(value);
    if trimmed.is_empty() {
        return Some(0.0);
    }
    let (days, time_part) = match trimmed.split_once('-') {
        Some((days, rest)) => (python_int(days)?, rest),
        None => (0, trimmed),
    };
    let fields = time_part
        .split(':')
        .map(python_int)
        .collect::<Option<Vec<i64>>>()?;
    let (hours, minutes, seconds) = match fields.as_slice() {
        [hours, minutes, seconds] => (*hours, *minutes, *seconds),
        [minutes, seconds] => (0, *minutes, *seconds),
        [seconds, ..] => (0, 0, *seconds),
        [] => return None,
    };
    let total = (days.checked_mul(24)?.checked_add(hours)?)
        .checked_mul(60)?
        .checked_add(minutes)?
        .checked_mul(60)?
        .checked_add(seconds)?;
    Some(total as f64)
}

/// `^\s*(\d+)\s+(\S+)\s+(.*)$`: the pid, the elapsed token and the command.
fn ps_line(line: &str) -> Option<(i64, &str, &str)> {
    let (pid, rest) = pid_prefix(line)?;
    let token_end = rest.find(py_isspace)?;
    if token_end == 0 {
        return None;
    }
    let command = rest[token_end..].trim_start_matches(py_isspace);
    Some((pid, &rest[..token_end], command))
}

fn is_ephemeral(ctx: &Ctx, guard_home: &str) -> bool {
    let normalized = ctx.path_text(guard_home);
    let text = if ctx.nt {
        normalized.replace('\\', "/")
    } else {
        normalized
    };
    text.split('/')
        .any(|part| part.starts_with("pytest-") || part.contains("pytest-of-"))
}

pub(crate) fn ephemeral_processes(ctx: &Ctx, query: &DaemonEphemeralProcessesQueryV1) -> Value {
    if ctx.nt {
        return json!({"processes": []});
    }
    let mut processes: Vec<Value> = Vec::new();
    for line in py_splitlines(&query.ps_output) {
        let Some((pid, elapsed, command)) = ps_line(line) else {
            continue;
        };
        let Some(seconds) = elapsed_seconds(elapsed) else {
            return json!({"raises": "ValueError"});
        };
        let command = py_strip(command);
        let Some(parts) = ctx.split_command(command) else {
            continue;
        };
        if !parts_match(ctx, &parts) {
            continue;
        }
        let Some(home) = home_from_parts(ctx, &parts) else {
            continue;
        };
        if is_ephemeral(ctx, &home) {
            processes.push(json!([pid, home, seconds]));
        }
    }
    json!({"processes": processes})
}

pub(crate) fn ephemeral_home(ctx: &Ctx, query: &DaemonEphemeralHomeQueryV1) -> Value {
    json!({"ephemeral": is_ephemeral(ctx, &query.guard_home)})
}
