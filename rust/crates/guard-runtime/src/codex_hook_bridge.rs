//! Native Codex hook bridge: the fast path of `main` in
//! `adapters/codex_daemon_hook_bridge.py`. Codex runs
//! `guard-runtime codex-hook-bridge <python> -I <bridge.py> <config>` once
//! per hook. The native bridge forwards the hook to the authenticated
//! loopback Guard daemon and shapes its answer for Codex.
//!
//! Only a clean daemon answer is rendered here. Every other path runs the
//! Python bridge it was given:
//! - a raw delegate (the original argv and stdin) for anything the native
//!   bridge does not handle exactly as Python does, including every daemon
//!   failure, so recovery, fallback and denial wording stay in Python;
//! - a handoff (`--native-handoff` with the daemon's answer on stdin) for
//!   answers that need Python's post-processing: browser approval waits,
//!   containment routing and transition observations.
//!
//! The native bridge never decides a verdict. The daemon decides; the
//! Python bridge decides whenever the daemon cannot.

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http::remaining;
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct::{direct_answer, CODEX};
use crate::codex_hook_bridge_transport::authenticated_codex_hook_response;
use crate::codex_hook_identity::current_process_identity;
use crate::codex_hook_response::{
    codex_hook_response, fail_closed, runtime_hook_event_name, PRE_TOOL_USE,
};
use crate::hook_bridge_exit::exit_code;
use crate::hook_env_stamp::{
    current_environment, dumps, json_string, set_member, stamp_hook_input_text, Stamp,
};
use crate::pyjson::{self, in_surrogate_plane, PyVal};

pub(crate) const BRIDGE_COMMAND: &str = "codex-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "codex-hook-bridge-v1";
pub(crate) const HANDOFF_FLAG: &str = "--native-handoff";
pub(crate) const HANDOFF_SCHEMA: &str = "hol-guard.codex-native-handoff.v1";
pub(crate) const ELAPSED_ENV: &str = "HOL_GUARD_CODEX_NATIVE_ELAPSED_MS";

const MAX_HOOK_INPUT_BYTES: usize = 1_000_000;
const HOOK_TIMEOUT_GRACE_SECONDS: i64 = 2;
const RPC_TIMEOUT: Duration = Duration::from_secs(4);
const PROMPT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_APPROVAL_WAIT_SECONDS: i64 = 600;
const BROWSER_WAIT_PROCESS_KEY: &str = "guard_codex_browser_wait_process";
const BROWSER_WAIT_TIMEOUT_KEY: &str = "guard_codex_browser_wait_timeout_seconds";
const STATE_FILE: &str = "daemon-state.json";
const START_FAILED_MARKER: &str = "daemon-start-failed.json";
const CAPTURE_MARKER: [&str; 2] = ["diagnostics", "codex-binding-capture.v2.json"];
const DAEMON_PROCESS_FAILURE_PREFIX: &str = "daemon_hook_process_";

/// The fields of `bridge_config_from_argv` the native bridge reads, after
/// every check Python applies, so an argument Python refuses is delegated.
#[derive(Debug, PartialEq)]
pub(crate) struct BridgeConfig {
    pub(crate) state_path: String,
    pub(crate) query: String,
    pub(crate) hook_timeouts: Vec<(String, i64)>,
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
    if manifest_path.is_empty()
        || !non_empty_strings(payload.get("fallback_command"))
        || !non_empty_strings(payload.get("start_command"))
    {
        return None;
    }
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

fn binding_capture_requested(state_path: &str) -> bool {
    guard_home(state_path).is_some_and(|home| {
        let marker = home.join(CAPTURE_MARKER[0]).join(CAPTURE_MARKER[1]);
        std::fs::symlink_metadata(marker).is_ok()
    })
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

/// The query goes into the request line verbatim; `http.client` refuses
/// controls, spaces and non-ASCII, which Python handles as a failure.
fn query_is_sendable(query: &str) -> bool {
    query.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// The hook as `_bound_hook_input` forwards it, or `None` to delegate.
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

pub(crate) fn prepare(raw_data: &str, hook_timeouts: &[(String, i64)]) -> Option<Prepared> {
    let parsed = pyjson::parse_mapping_lone_surrogates(raw_data).ok()?;
    let PyVal::Dict(entries) = parsed.value else {
        return None;
    };
    let event_name = runtime_hook_event_name(&entries);
    if parsed.mapped && (parsed.collision || event_name.chars().any(in_surrogate_plane)) {
        return None;
    }
    let seconds = request_timeout_seconds(&event_name, hook_timeouts);
    let forwarded = if event_name == PRE_TOOL_USE {
        with_browser_wait_process(entries, parsed.mapped, (seconds - 1).max(1))
    } else {
        raw_data.to_owned()
    };
    let Stamp::Text(data) = stamp_hook_input_text(&forwarded, &current_environment()) else {
        return None;
    };
    Some(Prepared {
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
    /// Run the Python bridge on the original argv and stdin.
    Delegate,
    /// Run the Python bridge on the daemon's answer.
    Handoff(String),
}

fn needs_python(response: &PyVal, event_name: &str) -> bool {
    if matches!(
        response.get("guard_transition_observation"),
        Some(PyVal::Dict(_))
    ) {
        return true;
    }
    if event_name != PRE_TOOL_USE {
        return false;
    }
    let decision = response
        .get("hookSpecificOutput")
        .and_then(|output| output.get("permissionDecision"));
    matches!(decision, Some(PyVal::Str(text)) if text == "deny")
        || matches!(response.get("policy_action"), Some(PyVal::Str(text)) if text == "sandbox-required")
}

/// Route one daemon answer, as Python's fast path would render it.
pub(crate) fn route_response(text: &str, event_name: &str) -> Route {
    let Ok(parsed) = pyjson::parse_mapping_lone_surrogates(text) else {
        return Route::Delegate;
    };
    if parsed.mapped && parsed.collision {
        return Route::Delegate;
    }
    let PyVal::Dict(entries) = &parsed.value else {
        return Route::Delegate;
    };
    if matches!(parsed.value.get("reason_code"), Some(PyVal::Str(code)) if code.starts_with(DAEMON_PROCESS_FAILURE_PREFIX))
    {
        return Route::Delegate;
    }
    if needs_python(&parsed.value, event_name) {
        return Route::Handoff(text.to_owned());
    }
    let mut rendered = String::new();
    dumps(
        &codex_hook_response(entries, event_name),
        true,
        parsed.mapped,
        &mut rendered,
    );
    Route::Respond(rendered)
}

/// The handoff envelope the Python bridge reads on stdin.
pub(crate) fn handoff_envelope(
    prepared: &Prepared,
    daemon_response: &str,
    elapsed: Duration,
) -> String {
    format!(
        "{{\"schema\":\"{HANDOFF_SCHEMA}\",\"hook_input\":{},\"event_name\":{},\
\"daemon_response\":{},\"elapsed_ms\":{}}}",
        json_string(&prepared.data, true, false),
        json_string(&prepared.event_name, true, false),
        json_string(daemon_response, true, false),
        elapsed.as_millis(),
    )
}

/// The full native decision for one hook, given its config argument.
pub(crate) fn route_hook(
    config: &BridgeConfig,
    raw_data: &str,
    input_ready: Instant,
) -> (Route, Option<Prepared>) {
    if std::env::var_os("HOL_GUARD_DESKTOP").is_some_and(|value| value == "1")
        || binding_capture_requested(&config.state_path)
        || !query_is_sendable(&config.query)
    {
        return (Route::Delegate, None);
    }
    let Some(prepared) = prepare(raw_data, &config.hook_timeouts) else {
        return (Route::Delegate, None);
    };
    let deadline = input_ready + prepared.timeout;
    let cap = if prepared.event_name == "UserPromptSubmit" {
        PROMPT_RPC_TIMEOUT
    } else {
        RPC_TIMEOUT
    };
    let rpc_deadline = Instant::now() + remaining(deadline).min(cap);
    if let Some(text) = guard_home(&config.state_path).and_then(|home| {
        direct_answer(
            CODEX,
            &home,
            &config.query,
            &prepared.event_name,
            &prepared.data,
            rpc_deadline,
        )
    }) {
        // A resident answer never touched the daemon, so its start-failure
        // marker stays as it was.
        return (route_response(&text, &prepared.event_name), Some(prepared));
    }
    let Ok(text) = authenticated_codex_hook_response(
        Path::new(&config.state_path),
        &config.query,
        &prepared.data,
        rpc_deadline,
    ) else {
        return (Route::Delegate, Some(prepared));
    };
    let route = route_response(&text, &prepared.event_name);
    if route != Route::Delegate {
        clear_start_failure(&config.state_path);
    }
    (route, Some(prepared))
}

/// Run the Python bridge with `stdin`, inheriting stdout, stderr, cwd and
/// the environment; `None` when it could not start.
fn run_python(argv: &[String], stdin: &[u8], elapsed: Duration) -> Option<i32> {
    let (program, args) = argv.split_first()?;
    let mut child = Command::new(program)
        .args(args)
        .env(ELAPSED_ENV, elapsed.as_millis().to_string())
        .stdin(Stdio::piped())
        .spawn()
        .ok()?;
    if let Some(mut pipe) = child.stdin.take() {
        // A child that exits without reading its input still answers.
        let _ = pipe.write_all(stdin);
    }
    child.wait().ok().map(exit_code)
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
    let started = Instant::now();
    let mut raw = Vec::new();
    let read = io::stdin()
        .lock()
        .take(MAX_HOOK_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut raw);
    let Some(config_argument) = python_argv.last() else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return 0;
    };
    let delegate = |event_name: &str| {
        run_python(python_argv, &raw, started.elapsed()).unwrap_or_else(|| {
            write_stdout(&fail_closed(event_name));
            0
        })
    };
    if read.is_err() {
        return delegate(PRE_TOOL_USE);
    }
    let Some(config) = parse_config(config_argument) else {
        return delegate(PRE_TOOL_USE);
    };
    let Some(raw_data) = bounded_hook_input(&raw) else {
        write_stdout(&fail_closed(PRE_TOOL_USE));
        return 0;
    };
    let input_ready = Instant::now();
    match route_hook(&config, &raw_data, input_ready) {
        (Route::Respond(text), _) => {
            write_stdout(&text);
            0
        }
        (Route::Handoff(response), Some(prepared)) => {
            let mut argv = python_argv[..python_argv.len() - 1].to_vec();
            argv.push(HANDOFF_FLAG.to_owned());
            argv.push(config_argument.clone());
            let envelope = handoff_envelope(&prepared, &response, input_ready.elapsed());
            run_python(&argv, envelope.as_bytes(), started.elapsed()).unwrap_or_else(|| {
                write_stdout(&fail_closed(&prepared.event_name));
                0
            })
        }
        (_, prepared) => {
            let event_name = prepared.map_or_else(|| PRE_TOOL_USE.to_owned(), |p| p.event_name);
            delegate(&event_name)
        }
    }
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_tests.rs"]
mod tests;
