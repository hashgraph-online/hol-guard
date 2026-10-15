//! Native Codex hook bridge: the fast path of `main` in
//! `adapters/codex_daemon_hook_bridge.py`. Codex runs
//! `guard-runtime codex-hook-bridge <python> -I <bridge.py> <config>` once
//! per hook. The native bridge forwards the hook to the authenticated
//! loopback Guard daemon and shapes its answer for Codex.
//!
//! A clean daemon answer is rendered here. A daemon that is down, does not
//! answer or reports a process failure is started with the install-time
//! `start_command` and asked once more inside the hook deadline (see
//! `restart`); when that fails too, or the daemon is overloaded, the hook
//! fails closed. Codex Desktop, binding capture and an unsendable query are
//! served here too (see `client`).
//!
//! Every daemon answer is settled here (see `handoff`): a sandbox
//! requirement is routed into contained execution (see `contain`), a
//! `PreToolUse` deny that names a pending browser approval is held until the
//! browser decides or the hook deadline passes (see `approval`), and a
//! transition observation is written to stderr (see `observation`).
//!
//! The native bridge never decides a verdict, and Python never decides one
//! for it: without a daemon answer the hook fails closed.

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_identity::current_process_identity;
use crate::codex_hook_response::{
    codex_hook_response, fail_closed, runtime_hook_event_name, PRE_TOOL_USE,
};
use crate::hook_env_stamp::{current_environment, dumps, set_member, stamp_hook_input_text, Stamp};
use crate::pyjson::{self, in_surrogate_plane, PyVal};

pub(crate) const BRIDGE_COMMAND: &str = "codex-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "codex-hook-bridge-v1";

const MAX_HOOK_INPUT_BYTES: usize = 1_000_000;
const HOOK_TIMEOUT_GRACE_SECONDS: i64 = 2;
const RPC_TIMEOUT: Duration = Duration::from_secs(4);
const PROMPT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_APPROVAL_WAIT_SECONDS: i64 = 600;
const BROWSER_WAIT_PROCESS_KEY: &str = "guard_codex_browser_wait_process";
const BROWSER_WAIT_TIMEOUT_KEY: &str = "guard_codex_browser_wait_timeout_seconds";
const STATE_FILE: &str = "daemon-state.json";
const START_FAILED_MARKER: &str = "daemon-start-failed.json";
const DAEMON_PROCESS_FAILURE_PREFIX: &str = "daemon_hook_process_";

/// The fields of `bridge_config_from_argv` the native bridge reads, after
/// every check Python applies, so an argument Python refuses is delegated.
#[derive(Debug, PartialEq)]
pub(crate) struct BridgeConfig {
    pub(crate) state_path: String,
    pub(crate) query: String,
    pub(crate) hook_timeouts: Vec<(String, i64)>,
    /// The daemon-start command run when the daemon is unreachable.
    pub(crate) start_command: Vec<String>,
    /// The isolated Python fallback; its interpreter and bootstrap start
    /// the contained-execution sink.
    pub(crate) fallback_command: Vec<String>,
}

fn non_empty_strings(value: Option<&PyVal>) -> bool {
    value
        .and_then(PyVal::as_list)
        .is_some_and(|items| !items.is_empty() && items.iter().all(|item| item.as_str().is_some()))
}

/// `decode_bridge_config_argument`: POSIX installs pass the JSON itself,
/// Windows installs unpadded base64url of its UTF-8. Anything Python
/// refuses is `None`.
fn decode_config_argument(argument: &str) -> Option<Cow<'_, str>> {
    if argument.starts_with('{') {
        return Some(Cow::Borrowed(argument));
    }
    let text = String::from_utf8(base64url_decode_unpadded(argument)?).ok()?;
    text.starts_with('{').then_some(Cow::Owned(text))
}

/// `base64.urlsafe_b64decode(argument + "=" * (-len(argument) % 4))` behind
/// Python's `[A-Za-z0-9_-]+` full match. A length one past a multiple of
/// four is refused, and the unused low bits of the last character are
/// ignored, as `binascii` ignores them.
fn base64url_decode_unpadded(argument: &str) -> Option<Vec<u8>> {
    if argument.is_empty() || argument.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(argument.len() / 4 * 3 + 2);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in argument.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `bridge_config_from_argv` for JSON and base64url arguments. Anything
/// Python would refuse returns `None`, so the Python bridge answers it.
pub(crate) fn parse_config(argument: &str) -> Option<BridgeConfig> {
    let argument = decode_config_argument(argument)?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&argument).ok()?;
    if parsed.mapped {
        return None;
    }
    let payload = parsed.value;
    let state_path = payload.get("state_path")?.as_str()?.to_owned();
    let manifest_path = payload.get("manifest_path")?.as_str()?;
    let query = payload.get("query")?.as_str()?.to_owned();
    let start_command = payload.get("start_command");
    if manifest_path.is_empty()
        || !non_empty_strings(payload.get("fallback_command"))
        || !non_empty_strings(start_command)
    {
        return None;
    }
    let strings = |value: &PyVal| {
        value
            .as_list()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    };
    let start_command = strings(start_command?)?;
    let fallback_command = strings(payload.get("fallback_command")?)?;
    let mut hook_timeouts = Vec::new();
    for (key, value) in payload.get("hook_timeouts")?.as_dict()? {
        let PyVal::Int(digits) = value else {
            continue;
        };
        let Ok(timeout) = digits.parse::<i64>() else {
            return None;
        };
        if timeout > HOOK_TIMEOUT_GRACE_SECONDS {
            hook_timeouts.push((key.clone(), timeout));
        }
    }
    if hook_timeouts.is_empty() {
        return None;
    }
    Some(BridgeConfig {
        state_path,
        query,
        hook_timeouts,
        start_command,
        fallback_command,
    })
}

/// `_request_timeout(event_name, hook_timeouts)` in whole seconds.
fn request_timeout_seconds(event_name: &str, hook_timeouts: &[(String, i64)]) -> i64 {
    let configured = hook_timeouts
        .iter()
        .find(|(key, _)| key == event_name)
        .map(|(_, timeout)| *timeout)
        .or_else(|| hook_timeouts.iter().map(|(_, timeout)| *timeout).min())
        .unwrap_or(10);
    (configured - HOOK_TIMEOUT_GRACE_SECONDS).max(1)
}

/// `bounded_hook_input`: `None` when Codex sent more than the limit.
pub(crate) fn bounded_hook_input(raw: &[u8]) -> Option<String> {
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        return None;
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = String::from_utf8_lossy(body).into_owned();
    Some(if py_strip(&text).is_empty() {
        "{}".to_owned()
    } else {
        text
    })
}

/// `<guard home>` when `state_path` is an absolute `daemon-state.json`.
fn guard_home(state_path: &str) -> Option<PathBuf> {
    let path = Path::new(state_path);
    (path.is_absolute() && path.file_name().is_some_and(|name| name == STATE_FILE))
        .then(|| path.parent().map(Path::to_path_buf))
        .flatten()
}

/// `clear_start_failure(state_path)`.
fn clear_start_failure(state_path: &str) {
    let path = Path::new(state_path);
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let _ = std::fs::remove_file(parent.join(START_FAILED_MARKER));
}

/// The hook as `_bound_hook_input` forwards it, or `None` to delegate.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) event_name: String,
    pub(crate) data: String,
    pub(crate) timeout: Duration,
}

/// `_with_browser_wait_process`, rendered as Python's `json.dumps`.
fn with_browser_wait_process(
    mut entries: Vec<(String, PyVal)>,
    mapped: bool,
    wait_seconds: i64,
) -> String {
    match current_process_identity() {
        Some((pid, token)) => {
            let identity = PyVal::Dict(vec![
                ("pid".to_owned(), PyVal::Int(pid.to_string())),
                ("startToken".to_owned(), PyVal::Str(token)),
            ]);
            set_member(&mut entries, BROWSER_WAIT_PROCESS_KEY, identity);
            let bounded = wait_seconds.clamp(1, MAX_APPROVAL_WAIT_SECONDS);
            set_member(
                &mut entries,
                BROWSER_WAIT_TIMEOUT_KEY,
                PyVal::Int(bounded.to_string()),
            );
        }
        None => entries
            .retain(|(key, _)| key != BROWSER_WAIT_PROCESS_KEY && key != BROWSER_WAIT_TIMEOUT_KEY),
    }
    let mut text = String::new();
    dumps(&PyVal::Dict(entries), true, mapped, &mut text);
    text
}

/// A hook the native bridge does not forward as it was read.
#[derive(Debug, PartialEq)]
pub(crate) enum Unprepared {
    /// Refused with the client's fail-closed answer for this event.
    Refused(String),
}

pub(crate) fn prepare(
    raw_data: &str,
    hook_timeouts: &[(String, i64)],
) -> Result<Prepared, Unprepared> {
    // `_event_name` reads anything but a JSON object as PreToolUse, and every
    // Codex hook is an object, so anything else is refused.
    let refused = || Unprepared::Refused(PRE_TOOL_USE.to_owned());
    let parsed = pyjson::parse_mapping_lone_surrogates(raw_data).map_err(|_| refused())?;
    let PyVal::Dict(entries) = parsed.value else {
        return Err(refused());
    };
    let event_name = runtime_hook_event_name(&entries);
    // A lone surrogate is forwarded re-escaped, as Python's `json.dumps`
    // writes it. One beside a genuine U+F0000..U+F07FF character cannot be
    // told apart from it, and an event name holding one cannot cross the
    // identity challenge (see `hook_event_name`), so both fail closed.
    if parsed.mapped && (parsed.collision || event_name.chars().any(in_surrogate_plane)) {
        return Err(Unprepared::Refused(event_name));
    }
    let seconds = request_timeout_seconds(&event_name, hook_timeouts);
    let forwarded = if event_name == PRE_TOOL_USE {
        with_browser_wait_process(entries, parsed.mapped, (seconds - 1).max(1))
    } else {
        raw_data.to_owned()
    };
    // Nesting Python cannot read, or text it cannot round-trip, is refused.
    let Stamp::Text(data) = stamp_hook_input_text(&forwarded, &current_environment()) else {
        return Err(Unprepared::Refused(event_name));
    };
    Ok(Prepared {
        event_name,
        data,
        timeout: Duration::from_secs(seconds.unsigned_abs()),
    })
}

/// What the native bridge does with one hook.
#[derive(Debug, PartialEq)]
pub(crate) enum Route {
    /// Write this hook JSON and exit zero.
    Respond(String),
    /// A transition observation (the answer's
    /// `guard_transition_observation`) to write before settling the route.
    Observed(PyVal, Box<Route>),
    /// Wait for the browser's decision on a pending approval: write the
    /// allow once the daemon records one, this rendered deny otherwise.
    AwaitApproval(approval::Pending, String),
    /// The daemon reported a process failure: restart it and ask once more.
    Restart,
    /// A `PreToolUse` sandbox requirement (parsed, surrogate-mapped) for
    /// `contain::settle`.
    Contain(PyVal, bool),
}

/// Route one daemon answer, as Python's fast path would render it. An answer
/// that cannot be rendered is refused with the fail-closed answer.
pub(crate) fn route_response(text: &str, event_name: &str) -> Route {
    let unrendered = Route::Respond(fail_closed(event_name));
    let Ok(parsed) = pyjson::parse_mapping_lone_surrogates(text) else {
        return unrendered;
    };
    if parsed.mapped && parsed.collision {
        return unrendered;
    }
    let PyVal::Dict(entries) = &parsed.value else {
        return unrendered;
    };
    if matches!(parsed.value.get("reason_code"), Some(PyVal::Str(code)) if code.starts_with(DAEMON_PROCESS_FAILURE_PREFIX))
    {
        return Route::Restart;
    }
    let route = match handoff::post_render(&parsed.value, event_name) {
        handoff::Post::Contain => Route::Contain(parsed.value.clone(), parsed.mapped),
        post => {
            let mut rendered = String::new();
            dumps(
                &codex_hook_response(entries, event_name),
                true,
                parsed.mapped,
                &mut rendered,
            );
            match post {
                handoff::Post::Approval(pending) => Route::AwaitApproval(pending, rendered),
                _ => Route::Respond(rendered),
            }
        }
    };
    match parsed.value.get("guard_transition_observation") {
        Some(envelope @ PyVal::Dict(_)) => Route::Observed(envelope.clone(), Box::new(route)),
        _ => route,
    }
}

/// The full native decision for one hook, given its config argument.
pub(crate) fn route_hook(
    config: &BridgeConfig,
    raw_data: &str,
    input_ready: Instant,
) -> (Route, Option<Prepared>) {
    let prepared = match prepare(raw_data, &config.hook_timeouts) {
        Ok(prepared) => prepared,
        Err(Unprepared::Refused(event_name)) => {
            return (Route::Respond(fail_closed(&event_name)), None)
        }
    };
    client::record_ingress(&config.state_path, raw_data, &prepared);
    if !client::query_is_sendable(&config.query) {
        let route = Route::Respond(fail_closed(&prepared.event_name));
        return (route, Some(prepared));
    }
    let deadline = input_ready + prepared.timeout;
    let cap = if prepared.event_name == "UserPromptSubmit" {
        PROMPT_RPC_TIMEOUT
    } else {
        RPC_TIMEOUT
    };
    let route = match restart::daemon_route(config, &prepared, deadline, cap) {
        // Written first, as Python writes it before rendering the answer.
        Some(Route::Observed(envelope, route)) => {
            observation::write(&prepared.data, &envelope);
            Some(*route)
        }
        route => route,
    };
    let route = match route {
        Some(Route::Contain(response, mapped)) => {
            contain::settle(config, &prepared, response, mapped, deadline)
        }
        Some(route) => route,
        None => Route::Respond(fail_closed(&prepared.event_name)),
    };
    (route, Some(prepared))
}

fn write_stdout(text: &str) {
    let mut stdout = io::stdout().lock();
    let _ = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush());
}

/// `guard-runtime codex-hook-bridge <python argv...> <config>`: the exit
/// code Codex sees.
pub(crate) fn run(python_argv: &[String]) -> i32 {
    let mut raw = Vec::new();
    let read = io::stdin()
        .lock()
        .take(MAX_HOOK_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut raw);
    let Some(config_argument) = python_argv.last() else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return 0;
    };
    // A config Python would refuse, or one this bridge does not read, leaves
    // no daemon to ask: the hook fails closed.
    let Some(config) = parse_config(config_argument) else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return 0;
    };
    // A hook that cannot be read, or is too large, is refused as the client
    // refuses it.
    let raw_data = read.ok().and_then(|_| bounded_hook_input(&raw));
    let Some(raw_data) = raw_data else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return 0;
    };
    let input_ready = Instant::now();
    match route_hook(&config, &raw_data, input_ready) {
        (Route::Respond(text), _) => {
            write_stdout(&text);
            0
        }
        (Route::AwaitApproval(pending, deny), prepared) => {
            let approved = prepared.is_some_and(|prepared| {
                approval::approved(
                    Path::new(&config.state_path),
                    &pending,
                    &prepared.data,
                    input_ready + prepared.timeout,
                )
            });
            write_stdout(&if approved {
                approval::allow_rendered()
            } else {
                deny
            });
            0
        }
        // `route_hook` settles every restart, containment and observation;
        // one that escaped fails closed.
        (Route::Restart | Route::Contain(..) | Route::Observed(..), prepared) => {
            let event_name = prepared
                .as_ref()
                .map_or(PRE_TOOL_USE, |p| p.event_name.as_str());
            write_stdout(&fail_closed(event_name));
            0
        }
    }
}

#[path = "codex_hook_bridge_approval.rs"]
mod approval;
#[path = "codex_hook_bridge_client.rs"]
mod client;
#[path = "codex_hook_bridge_contain.rs"]
mod contain;
#[path = "codex_hook_bridge_handoff.rs"]
mod handoff;
#[path = "codex_hook_bridge_observation.rs"]
mod observation;
#[path = "codex_hook_bridge_restart.rs"]
mod restart;

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_tests.rs"]
mod tests;
