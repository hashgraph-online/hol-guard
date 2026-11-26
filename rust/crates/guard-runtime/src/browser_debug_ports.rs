//! Session-scoped browser debugging ports (BP-T032).
//!
//! A browser launched with `--remote-debugging-port=N` (or Firefox's
//! `--start-debugger-server N`) answers on loopback port `N` with full control
//! of that browser: its pages, its cookies and every site it is signed in to.
//! The loopback readers already refuse the conventional debugger ports
//! (`9222`, `9229`), but a launch may name any port, and a port no service
//! claims by default is otherwise reachable as a dev server the agent chose.
//!
//! When a tool call names such a port, the port is recorded on a browser
//! session of the calling harness session in the native browser session store.
//! A later call in that harness session that names a loopback destination on a
//! recorded port is held for review, the same way a request to a listed admin
//! port is. Ports named in the same call count too.
//!
//! The overlay only raises: recording a port can never lift a decision, an
//! unreadable store leaves the verdict as it was, and the review keeps Allow
//! once and Always allow.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_contracts::{BrowserProfileModeV1, GuardHookEnvelopeV2, PreToolResultV1};
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::browser_session_store::{
    ensure_browser_session_schema, known_debugging_ports, record_browser_session,
    BrowserSessionObservation, MAX_DEBUGGING_PORTS_PER_SESSION,
};
use crate::local_store_read::{open_read_only, table_exists, STORE_FILE_NAME};
use crate::policy_enforcement::ActionFloor;

const DEBUG_PORT_REVIEW: &str = "browser_debug_port";
const DEBUG_PORT_REASON: &str = "This reaches the debugging port of a browser launched earlier in \
     this session. That port controls the browser, its cookies and the sites it is signed in to.";
/// Destinations read per call; the debugging port check needs only loopback ones.
const MAX_TARGETS: usize = 64;
/// The driver identity of a browser launched from a shell command.
const SHELL_LAUNCH_DRIVER: &str = "shell-launch";
/// Flags that open a browser's debugging protocol on a loopback port.
const DEBUG_PORT_FLAGS: [&str; 2] = ["remote-debugging-port", "start-debugger-server"];
const SESSIONS_TABLE: &str = "guard_browser_sessions";
const WRITE_BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// Whether `reason_code` is this overlay's review. It matched a port a launch
/// in this harness session named, so it holds the hook verdict at review.
pub(crate) fn is_review_finding(reason_code: &str) -> bool {
    reason_code == DEBUG_PORT_REVIEW
}

pub(crate) fn apply_to_envelope(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    apply(
        Path::new(&envelope.source.guard_home),
        harness,
        &envelope.raw_payload,
        now_unix(),
        result,
    )
}

/// Records the debugging ports the call names, then raises the result to a
/// review when the call reaches a loopback port a launch in this harness
/// session named.
pub(crate) fn apply(
    guard_home: &Path,
    harness: &str,
    payload: &Value,
    now_unix: i64,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    if result.action.event == "UserPromptSubmit" {
        return result;
    }
    let Some(harness_session) = harness_session_digest(harness, payload) else {
        return result;
    };
    let command = command_text(payload);
    let launched = command
        .as_deref()
        .map(debugging_ports_in)
        .unwrap_or_default();
    if !launched.is_empty() {
        record(guard_home, harness, &harness_session, &launched, now_unix);
    }
    if result.minimum_action == "block" {
        return result;
    }
    let mut reached: Vec<u16> =
        guard_command::pretool::generic::network_targets(payload, MAX_TARGETS)
            .iter()
            .filter_map(|target| loopback_port(target))
            .collect();
    if let Some(command) = command.as_deref() {
        reached.extend(schemeless_loopback_ports(command));
    }
    if reached.is_empty() {
        return result;
    }
    let mut known = recorded_ports(guard_home, harness, &harness_session, now_unix);
    known.extend(&launched);
    if reached.iter().any(|port| known.contains(port)) {
        raise(result)
    } else {
        result
    }
}

/// The harness session the call belongs to. A call without a session id has
/// no session to scope a port to, so nothing is recorded or matched.
fn harness_session_digest(harness: &str, payload: &Value) -> Option<String> {
    let session = payload
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|session| !session.is_empty())?;
    Some(hex_digest(&format!("{harness}\0{session}")))
}

fn hex_digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn command_text(payload: &Value) -> Option<String> {
    guard_command::pretool::generic::extract_untrusted_command_context(payload)
        .ok()
        .and_then(|context| context.command)
}

fn command_words(command: &str) -> Vec<&str> {
    command
        .split(|character: char| character.is_whitespace() || matches!(character, ';' | '&' | '|'))
        .map(|word| word.trim_matches(|character| matches!(character, '"' | '\'' | '`')))
        .filter(|word| !word.is_empty())
        .collect()
}

/// Loopback ports named without a scheme, such as `curl 127.0.0.1:9333/json`,
/// which curl reads as `http://`.
fn schemeless_loopback_ports(command: &str) -> Vec<u16> {
    command_words(command)
        .into_iter()
        .filter(|word| !word.contains("://") && !word.starts_with('-') && word.contains(':'))
        .filter_map(|word| loopback_port(&format!("http://{word}")))
        .take(MAX_TARGETS)
        .collect()
}

/// Debugging ports the command text names, without duplicates. Port `0` asks
/// the browser to pick one, which no later request can be matched against,
/// so it is skipped.
pub(crate) fn debugging_ports_in(command: &str) -> Vec<u16> {
    let words = command_words(command);
    let mut ports = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let flag = word.trim_start_matches('-');
        if flag.len() == word.len() {
            continue;
        }
        let (name, value) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (flag, words.get(index + 1).copied()),
        };
        if !DEBUG_PORT_FLAGS
            .iter()
            .any(|known| name.eq_ignore_ascii_case(known))
        {
            continue;
        }
        let port = value
            .map(|value| value.trim_matches(|character| matches!(character, '"' | '\'')))
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port != 0);
        if let Some(port) = port {
            if !ports.contains(&port) && ports.len() < MAX_DEBUGGING_PORTS_PER_SESSION {
                ports.push(port);
            }
        }
    }
    ports
}

/// The port of a destination on this machine, or `None` for any other host.
pub(crate) fn loopback_port(target: &str) -> Option<u16> {
    let (scheme, rest) = target.split_once("://")?;
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = match host_port.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed.split_once(']')?;
            (host, after.strip_prefix(':'))
        }
        None => match host_port.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        },
    };
    if !loopback_host(&host.trim_end_matches('.').to_ascii_lowercase()) {
        return None;
    }
    match port {
        Some(port) => port.parse::<u16>().ok().filter(|port| *port != 0),
        None => match scheme.to_ascii_lowercase().as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        },
    }
}

fn loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
        || host.parse::<Ipv6Addr>().is_ok_and(|address| {
            address.is_loopback()
                || address.is_unspecified()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback() || mapped.is_unspecified())
        })
}

/// Records each port on the harness session's shell-launched browser. A store
/// that cannot be opened or written records nothing; the call is judged on
/// the ports it names itself.
fn record(guard_home: &Path, harness: &str, harness_session: &str, ports: &[u16], now_unix: i64) {
    let Ok(connection) = Connection::open(guard_home.join(STORE_FILE_NAME)) else {
        return;
    };
    if connection.busy_timeout(WRITE_BUSY_TIMEOUT).is_err()
        || ensure_browser_session_schema(&connection).is_err()
    {
        return;
    }
    let session_digest = hex_digest(&format!("{SHELL_LAUNCH_DRIVER}\0{harness_session}"));
    let driver_identity_hash = hex_digest(SHELL_LAUNCH_DRIVER);
    for port in ports {
        let _ = record_browser_session(
            &connection,
            &BrowserSessionObservation {
                session_digest: &session_digest,
                harness,
                harness_session_digest: harness_session,
                driver_identity_hash: &driver_identity_hash,
                profile_mode: BrowserProfileModeV1::RemoteDebugging,
                origin: None,
                debugging_port: Some(*port),
                now_unix,
            },
        );
    }
}

fn recorded_ports(
    guard_home: &Path,
    harness: &str,
    harness_session: &str,
    now_unix: i64,
) -> Vec<u16> {
    let Ok(Some(connection)) = open_read_only(&guard_home.join(STORE_FILE_NAME)) else {
        return Vec::new();
    };
    if !table_exists(&connection, SESSIONS_TABLE).unwrap_or(false) {
        return Vec::new();
    }
    known_debugging_ports(&connection, harness, harness_session, now_unix).unwrap_or_default()
}

fn raise(mut result: PreToolResultV1) -> PreToolResultV1 {
    let (Some(minimum), Some(policy)) = (
        ActionFloor::parse(&result.minimum_action),
        ActionFloor::parse(&result.policy_action),
    ) else {
        return result;
    };
    if minimum > ActionFloor::Review {
        return result;
    }
    if minimum < ActionFloor::Review {
        result.minimum_action = "review".into();
        result.decision = "deny".into();
    }
    if policy < ActionFloor::Review {
        result.policy_action = "review".into();
    }
    result.explicitly_benign = false;
    result.reason_code = DEBUG_PORT_REVIEW.into();
    result.reason = DEBUG_PORT_REASON.into();
    result
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "browser_debug_ports_tests.rs"]
mod tests;
