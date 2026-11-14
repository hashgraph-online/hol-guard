//! The lane flags the Python launcher puts ahead of the config argument,
//! and the frozen macOS Desktop lane they select.
//!
//! A transition probe on that lane must be answered by the signed bundle
//! executable, not by this runtime, so the bridge reads the hook, and when it
//! is a probe hands the stamped body and the paths the signed command needs
//! back to the launcher (exit code [`PROBE_HANDOFF_EXIT`]) instead of asking
//! the daemon. Any other hook is reviewed here as on every other lane.
//!
//! The launcher authenticates the hook's registration before it starts this
//! runtime, but on the Desktop lane it cannot read the body first, so a
//! registration that failed reaches here as `--guard-registration-failure`
//! and the hook fails closed once it is known not to be a probe.

use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use serde_json::json;

use crate::codex_hook_response::{fail_closed, PRE_TOOL_USE};
use crate::pyjson::{self, PyVal};
use crate::runner_sync_url::parse_qsl;

use super::{observation, prepare, write_stdout, BridgeConfig, Unprepared, STATE_FILE};

const DESKTOP_FLAG: &str = "--guard-desktop-lane";
const FAILURE_FLAG: &str = "--guard-registration-failure=";
const PROBE_HANDOFF_SCHEMA: &str = "hol-guard.codex-desktop-probe.v1";
const BRIDGE_FAILURE_SCHEMA: &str = "hol-guard.codex-bridge-failure.v1";
/// `EX_TEMPFAIL`: the launcher runs the signed probe command itself.
pub(super) const PROBE_HANDOFF_EXIT: i32 = 75;

/// What the launcher said about this call before the config argument.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Lane {
    desktop: bool,
    registration_failure: Option<String>,
}

/// A stable reason code: what `_write_failure_cause` may write.
fn reason_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// The lane flags at the front of `argv`, and the argv after them. An
/// installed registration starts with an interpreter path, never a flag.
pub(super) fn split_lane(argv: &[String]) -> (Lane, &[String]) {
    let mut lane = Lane::default();
    let mut rest = argv;
    while let Some((first, tail)) = rest.split_first() {
        if first == DESKTOP_FLAG && !lane.desktop {
            lane.desktop = true;
        } else if let Some(code) = first.strip_prefix(FAILURE_FLAG) {
            if lane.registration_failure.is_some() {
                break;
            }
            // A cause that is not a reason code still fails the hook closed.
            let code = if reason_code(code) {
                code
            } else {
                "codex_hook_launch_unauthenticated"
            };
            lane.registration_failure = Some(code.to_owned());
        } else {
            break;
        }
        rest = tail;
    }
    (lane, rest)
}

/// The exit code when the lane settles this hook before the daemon is asked.
pub(super) fn settle(
    lane: &Lane,
    config: &BridgeConfig,
    raw_data: &str,
    input_ready: Instant,
) -> Option<i32> {
    let prepared = prepare(raw_data, &config.hook_timeouts);
    if lane.desktop {
        if let Ok(prepared) = &prepared {
            if let Some(code) = probe_handoff(config, &prepared.data, prepared.timeout, input_ready)
            {
                return Some(code);
            }
        }
    }
    let reason = lane.registration_failure.as_deref()?;
    let event_name = match &prepared {
        Ok(prepared) => prepared.event_name.as_str(),
        Err(Unprepared::Refused(event_name)) => event_name.as_str(),
    };
    write_stdout(&fail_closed(event_name));
    write_failure_cause(reason);
    Some(0)
}

/// `_write_failure_cause`: the reason behind a denial already on stdout.
fn write_failure_cause(reason: &str) {
    let document = json!({"schema": BRIDGE_FAILURE_SCHEMA, "causes": [{"reason_code": reason}]});
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{document}").and_then(|()| stderr.flush());
}

/// An absolute path with no NUL, as the signed command takes it.
fn usable_path(text: &str) -> Option<&str> {
    (!text.contains('\0') && Path::new(text).is_absolute()).then_some(text)
}

/// The probe handoff for a `PreToolUse` probe, or `None` when the hook is
/// not one. A probe the signed command cannot be built for fails closed.
fn probe_handoff(
    config: &BridgeConfig,
    data: &str,
    timeout: std::time::Duration,
    input_ready: Instant,
) -> Option<i32> {
    let payload = pyjson::parse_mapping_lone_surrogates(data).ok()?.value;
    if payload.get("hook_event_name").and_then(PyVal::as_str) != Some(PRE_TOOL_USE) {
        return None;
    }
    observation::probe(&payload)?;
    let Some(handoff) = handoff_document(config, &payload, data, timeout, input_ready) else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return Some(1);
    };
    write_stdout(&handoff.to_string());
    Some(PROBE_HANDOFF_EXIT)
}

fn handoff_document(
    config: &BridgeConfig,
    payload: &PyVal,
    data: &str,
    timeout: std::time::Duration,
    input_ready: Instant,
) -> Option<serde_json::Value> {
    let state = Path::new(&config.state_path);
    let guard_home = if state.file_name().is_some_and(|name| name == STATE_FILE) {
        state.parent()?
    } else {
        state
    };
    let guard_home = usable_path(guard_home.to_str()?)?;
    let configured = config
        .hook_timeouts
        .iter()
        .find(|(event, _)| event == PRE_TOOL_USE)
        .map(|(_, seconds)| *seconds)
        .filter(|seconds| *seconds > 0)?;
    let homes: Vec<String> = parse_qsl(&config.query)
        .into_iter()
        .filter_map(|(name, value)| (name == "home").then_some(value))
        .collect();
    let [home] = homes.as_slice() else {
        return None;
    };
    let home = usable_path(home)?;
    let workspace = usable_path(payload.get("cwd")?.as_str()?)?;
    let remaining = timeout.saturating_sub(input_ready.elapsed()).as_secs_f64();
    Some(json!({
        "schema": PROBE_HANDOFF_SCHEMA,
        "data": data,
        "guard_home": guard_home,
        "home": home,
        "workspace": workspace,
        "timeout_seconds": configured,
        "remaining_seconds": remaining,
    }))
}

#[cfg(test)]
#[path = "codex_hook_bridge_desktop_tests.rs"]
mod tests;
