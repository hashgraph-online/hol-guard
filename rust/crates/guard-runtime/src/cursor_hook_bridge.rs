//! Native answers for Cursor's managed hook client.
//!
//! Guard installs Cursor's hooks as `guard-runtime cursor-hook-bridge
//! <python> -I <script> --cursor-hook-event <event>`. For a `PreToolUse`
//! hook (Cursor's `preToolUse`, `beforeShellExecution`,
//! `beforeMCPExecution` and `beforeReadFile`) or a prompt the daemon reviews
//! as a `UserPromptSubmit` that a live resident allows, denies or pauses for
//! review, the bridge prints the client's own answer without starting
//! Python. For Cursor's `afterShellExecution` and `afterMCPExecution`
//! observers, which the daemon records as a `PostToolUse` and the client
//! always answers with `{}`, the bridge prints `{}` once the resident has
//! answered (and so queued the record). A hook the client could not parse,
//! which it denies (or answers with `{}` for an observer) before it asks
//! the daemon anything, gets that answer without Python or the daemon. A
//! hook the bridge cannot read or send exactly as the client would (another
//! client event, or JSON the port does not represent) fails closed with the
//! client's `_cursor_unavailable_response`, never more permissively than
//! the client would answer it.
//!
//! When no live resident answers, the bridge posts the request to the
//! loopback daemon itself, over the transport, auth token and deadlines the
//! bounded bridge uses, and renders the daemon's answer the same way. A
//! daemon that is unreachable, does not answer in time or answers with a
//! body the client refuses is recovered with the client's own
//! `GUARD_RECOVERY_COMMAND` and asked once more; an overloaded daemon is
//! not. An answer the bridge cannot render, and anything else, gets the
//! client's fail-closed `_cursor_unavailable_response`: the client's CLI
//! fallback, which reviewed the hook in Python, never runs.
//!
//! The client also sends an `after*` observer proof and approval binding in
//! `hook_env`; the daemon drops `hook_env` before it reviews a hook, and the
//! bridge reads no key.
//!
//! The bridge reproduces the client's steps up to its daemon request:
//! `_read_hook_input`, `json.loads`, `_prepare_cursor_hook_payload`,
//! `_workspace_from_cursor_input`, `stamp_hook_input_text` and the query
//! `_daemon_hook_result` sends. The resident answers the request the
//! daemon would have forwarded, so a verdict is never decided here. A lone
//! surrogate escape the client's `json.loads` keeps is sent and rendered as
//! its `json.dumps` writes it; a path holding one is never a workspace, as
//! the client's `Path.is_dir()` cannot encode it.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_adapter_prepare::{cursor_client_event, first_truthy, prepare_payload};
use guard_command::hook_adapter_value::{OMap, OValue, PyJsonError};

use crate::bounded_hook_bridge::{read_hook_input, write_stdout, Input, MAX_HOOK_INPUT_BYTES};
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct::{direct_answer, CURSOR};
use crate::codex_hook_response::{POST_TOOL_USE, PRE_TOOL_USE};
use crate::cursor_hook_bridge_response::{
    python_document, read_python_document, rendered, unavailable_output, unmapped_json,
    unparseable_output, AFTER_EVENTS, AFTER_STDOUT,
};
use crate::cursor_hook_bridge_script::read_client_constants;
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};
use crate::pyjson::in_surrogate_plane;

pub(crate) const BRIDGE_COMMAND: &str = "cursor-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "cursor-hook-bridge-v1";
const EVENT_FLAG: &str = "--cursor-hook-event";
/// The harness name of the client's daemon route, `/v1/hooks/cursor`.
const DAEMON_HARNESS: &str = "cursor";
const PROJECT_DIR_ENV: &str = "CURSOR_PROJECT_DIR";
/// The names `_prepare_cursor_hook_payload` gives the `after*` observers.
const PREPARED_AFTER_EVENTS: [&str; 2] = ["afterShellExecution", "afterMCPExecution"];
/// The event the bridge names a prompt for the resident.
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
/// The keys the daemon reads a hook's event from before `hook_event_name`.
const EARLIER_EVENT_KEYS: [&str; 2] = ["event", "eventName"];
/// The prompt names the daemon reviews as a `UserPromptSubmit`, compacted.
const PROMPT_EVENTS: [&str; 3] = ["prompt", "userpromptsubmit", "userpromptsubmitted"];

/// The client's fail-closed reply for a hook it names `event`.
fn fail_closed(event: &str) -> Reply {
    let (stdout, code) = unavailable_output(event);
    Reply::Answered(stdout.to_owned(), code)
}

fn unavailable(event: &str) -> i32 {
    let (stdout, code) = unavailable_output(event);
    write_stdout(stdout);
    code
}

/// `urllib.parse.urlencode` for one value: unreserved bytes kept, a space
/// as `+`, everything else percent-encoded.
fn quote_plus(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The query `_daemon_hook_result` sends.
pub(crate) fn hook_query(guard_home: &str, workspace: Option<&str>, home: Option<&str>) -> String {
    let mut fields = vec![("guard-home", guard_home)];
    fields.extend(workspace.map(|workspace| ("workspace", workspace)));
    fields.extend(home.map(|home| ("home", home)));
    fields
        .iter()
        .map(|(name, value)| format!("{name}={}", quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A stripped, non-blank candidate that `Path(candidate).is_dir()`. With
/// `mapped`, one holding a lone surrogate is not: `is_dir()` cannot encode
/// it and answers `False`.
fn directory_candidate(value: &str, mapped: bool) -> Option<String> {
    let candidate = py_strip(value);
    let unencodable = mapped && candidate.chars().any(in_surrogate_plane);
    (!candidate.is_empty() && !unencodable && Path::new(candidate).is_dir())
        .then(|| candidate.to_owned())
}

/// `_workspace_from_cursor_input` for a payload read with lone surrogates
/// when `mapped`. `Err` when `CURSOR_PROJECT_DIR` is not text the bridge can
/// read as Python does.
pub(crate) fn workspace(
    payload: &OMap,
    project_dir: Option<std::ffi::OsString>,
    mapped: bool,
) -> Result<Option<String>, ()> {
    if let Some(project_dir) = project_dir {
        let project_dir = project_dir.into_string().map_err(|_| ())?;
        if let Some(candidate) = directory_candidate(&project_dir, false) {
            return Ok(Some(candidate));
        }
    }
    let roots = first_truthy(
        payload.get("workspace_roots"),
        payload.get("workspaceRoots"),
    );
    if let Some(roots) = roots.and_then(OValue::as_list) {
        for root in roots {
            let candidate = root
                .as_str()
                .and_then(|root| directory_candidate(root, mapped));
            if let Some(candidate) = candidate {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(payload
        .get_str("cwd")
        .and_then(|cwd| directory_candidate(cwd, mapped)))
}

/// What the bridge needs of the client.
struct Client {
    guard_home: String,
    home: Option<String>,
    /// `GUARD_RECOVERY_COMMAND`, run when the daemon does not answer.
    recovery_command: Vec<String>,
    /// `_cursor_hook_event_from_argv`.
    event: String,
    deadline: Instant,
}

/// Which of the client's answers a request gets.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Kind {
    /// Rendered by `_emit_cursor_response`.
    PreToolUse,
    /// A prompt the daemon reviews as a `UserPromptSubmit`, rendered by
    /// `_emit_cursor_response` as a tool hook is.
    Prompt,
    /// An `after*` observer: `{}` once the daemon reviewed it.
    After,
}

/// A hook the bridge can send as the client would.
#[derive(Debug, PartialEq)]
struct Request {
    /// The stamped payload.
    data: String,
    query: String,
    /// The event the client names its answer for.
    event: String,
    kind: Kind,
}

/// The client's `hook_event_name.strip().lower()` check for an observer,
/// for ASCII names; any other name runs the client.
fn client_after_event(event: &str) -> bool {
    let stripped = py_strip(event);
    stripped.is_ascii() && AFTER_EVENTS.contains(&stripped.to_ascii_lowercase().as_str())
}

/// Whether a prepared hook name is one the daemon reviews as a
/// `UserPromptSubmit`: stripped, without `_` and `-`, and lowercased.
fn prompt_event(name: &str) -> bool {
    let compact: String = py_strip(name)
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect();
    compact.is_ascii() && PROMPT_EVENTS.contains(&compact.to_ascii_lowercase().as_str())
}

/// Why the bridge does not send a hook it read.
#[derive(Debug, PartialEq)]
enum Unread {
    /// Input `_main_inner` hands to `_exit_unparseable_cursor_input`.
    Unparseable,
    /// JSON `json.loads` reads that the port cannot represent.
    Unported,
}

/// The object `_read_hook_input` and `json.loads` read from `raw`.
fn hook_object(raw: &[u8]) -> Result<(OMap, bool), Unread> {
    // `_read_hook_input` raises for a longer hook and for anything
    // `decode("utf-8-sig")` refuses; `main` answers both as unparseable.
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        return Err(Unread::Unparseable);
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body).map_err(|_| Unread::Unparseable)?;
    if py_strip(text).is_empty() {
        return Err(Unread::Unparseable);
    }
    // `json.loads` skips only JSON whitespace around the document.
    let document = text.trim_matches([' ', '\t', '\n', '\r']);
    match read_python_document(document) {
        Ok((OValue::Map(payload), mapped)) => Ok((payload, mapped)),
        Ok(_) | Err(PyJsonError::Decode) => Err(Unread::Unparseable),
        Err(PyJsonError::Unsupported) => Err(Unread::Unported),
    }
}

/// The request the client would send for `raw`, as [`request_for`].
#[cfg(test)]
fn prepared_request(client: &Client, raw: &[u8]) -> Option<Request> {
    let (payload, mapped) = hook_object(raw).ok()?;
    request_for(client, &payload, mapped)
}

/// The request the client would send for a `PreToolUse` hook, a prompt or
/// an `after*` observer, or `None` to run the client. `mapped` says the
/// payload holds lone surrogates as their mapped characters.
fn request_for(client: &Client, payload: &OMap, mapped: bool) -> Option<Request> {
    // Cursor's `after*` hooks prepare as themselves; one is sent only where
    // the client would also answer it as an observer.
    let event = cursor_client_event(payload)?;
    let prepared = prepare_payload("cursor", payload, None).ok()?;
    let kind = match prepared.get_str("hook_event_name") {
        Some(PRE_TOOL_USE) => Kind::PreToolUse,
        // The daemon reads `event` and `eventName` before this name.
        Some(name)
            if prompt_event(name)
                && !EARLIER_EVENT_KEYS
                    .iter()
                    .any(|key| prepared.contains_key(key)) =>
        {
            Kind::Prompt
        }
        Some(name) if PREPARED_AFTER_EVENTS.contains(&name) && client_after_event(&event) => {
            Kind::After
        }
        _ => return None,
    };
    let workspace = workspace(&prepared, std::env::var_os(PROJECT_DIR_ENV), mapped).ok()?;
    let compact = OValue::Map(prepared).compact_json();
    // The stamp writes the surrogates back only when it reads them as such.
    let serialized = if mapped {
        unmapped_json(&compact)?
    } else {
        compact
    };
    let Stamp::Text(data) = stamp_hook_input_text(&serialized, &current_environment()) else {
        return None;
    };
    let query = hook_query(
        &client.guard_home,
        workspace.as_deref(),
        client.home.as_deref(),
    );
    Some(Request {
        data,
        query,
        event,
        kind,
    })
}

/// The client's answer for a resident's harness response: `json.loads` of
/// the body the daemon would return, rendered by `_emit_cursor_response`
/// with `guard_home` the client's `GUARD_HOME`; for an observer, `{}` once
/// `_daemon_hook_result` accepts the body as a JSON object, whatever it
/// holds.
fn answer(kind: Kind, event: &str, response: &str, guard_home: &Path) -> Option<(String, i32)> {
    let body = match kind {
        Kind::PreToolUse | Kind::Prompt => response,
        Kind::After => py_strip(response),
    };
    let (OValue::Map(response), unmap) = python_document(body)? else {
        return None;
    };
    match kind {
        Kind::PreToolUse | Kind::Prompt => rendered(event, &response, guard_home, unmap),
        Kind::After => Some((AFTER_STDOUT.to_owned(), 0)),
    }
}

/// What the bridge does with one hook.
#[derive(Debug, PartialEq)]
enum Reply {
    /// The client's stdout and exit code.
    Answered(String, i32),
}

/// The client's stdout and exit code for the hook, answered by a live
/// resident, the daemon or the fail-closed answer.
#[cfg(test)]
fn respond(client: &Client, raw: &[u8]) -> Option<(String, i32)> {
    let Reply::Answered(stdout, code) = reply(client, raw);
    Some((stdout, code))
}

/// The event whose fail-closed answer settles a hook the bridge cannot
/// send: the hook's own event, unless it is an observer, which gets `{}`
/// only when the client was also installed as one. Never more permissive
/// than the client, which would have asked the daemon.
fn closed_event(client: &Client, payload_event: Option<String>) -> String {
    match payload_event {
        Some(event) if unavailable_output(&event).1 == 0 => client.event.clone(),
        Some(event) => event,
        None => "preToolUse".to_owned(),
    }
}

/// The bridge's reply to the hook: the client's own answer to input it
/// cannot parse, else a live resident's answer, else the daemon's, as
/// `daemon::daemon_reply` settles them. A hook the bridge cannot read
/// exactly, or cannot send as the client would, fails closed: the daemon
/// is never asked without the exact request.
fn reply(client: &Client, raw: &[u8]) -> Reply {
    let (payload, mapped) = match hook_object(raw) {
        Ok(read) => read,
        Err(Unread::Unparseable) => {
            let (stdout, code) = unparseable_output(&client.event, client.deadline);
            return Reply::Answered(stdout.to_owned(), code);
        }
        Err(Unread::Unported) => return fail_closed(&client.event),
    };
    let Some(request) = request_for(client, &payload, mapped) else {
        return fail_closed(&closed_event(client, cursor_client_event(&payload)));
    };
    let event_name = match request.kind {
        Kind::PreToolUse => PRE_TOOL_USE,
        Kind::Prompt => USER_PROMPT_SUBMIT,
        Kind::After => POST_TOOL_USE,
    };
    let resident = direct_answer(
        CURSOR,
        Path::new(&client.guard_home),
        &request.query,
        event_name,
        &request.data,
        client.deadline,
    );
    daemon::daemon_reply(client, &request, resident)
}

/// The client the installer's argv runs, or `None` for any other argv or
/// for a script whose constants cannot be read.
fn client(python_argv: &[String], started: Instant) -> Option<Client> {
    let [_, isolated, script, flag, event] = python_argv else {
        return None;
    };
    if isolated != "-I" || flag != EVENT_FLAG {
        return None;
    }
    let constants = read_client_constants(Path::new(script))?;
    let budget = Duration::from_secs(constants.timeout_seconds);
    Some(Client {
        guard_home: constants.guard_home,
        home: constants.home,
        recovery_command: constants.recovery_command,
        // `sys.argv` starts at the script, so a script named as the flag
        // is the one the client reads its event after.
        event: py_strip(if script == EVENT_FLAG { flag } else { event }).to_owned(),
        deadline: started.checked_add(budget)?,
    })
}

/// Answer one Cursor hook. `python_argv` is the client's command.
pub(crate) fn run(python_argv: &[String]) -> i32 {
    let started = Instant::now();
    let event = python_argv
        .iter()
        .position(|argument| argument == EVENT_FLAG)
        .and_then(|index| python_argv.get(index + 1))
        .map_or("", |event| py_strip(event));
    // No install writes a client this bridge cannot read, so the hook fails
    // closed rather than running Python.
    let Some(client) = client(python_argv, started) else {
        return unavailable(event);
    };
    let raw = match read_hook_input(client.deadline) {
        Input::Read(raw) => raw,
        Input::Failed if Instant::now() >= client.deadline => return unavailable(event),
        // The client reads an empty hook and answers its unparseable input.
        Input::Failed => Vec::new(),
    };
    let Reply::Answered(stdout, code) = reply(&client, &raw);
    write_stdout(&stdout);
    code
}

#[path = "cursor_hook_bridge_daemon.rs"]
mod daemon;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_daemon_tests.rs"]
mod daemon_tests;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_restart_tests.rs"]
mod restart_tests;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_surrogate_tests.rs"]
mod surrogate_tests;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_unparsed_tests.rs"]
mod unparsed_tests;
