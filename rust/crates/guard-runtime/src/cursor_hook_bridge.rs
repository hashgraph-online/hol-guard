//! Native answers for Cursor's managed hook client.
//!
//! Guard installs Cursor's hooks as `guard-runtime cursor-hook-bridge
//! <python> -I <script> --cursor-hook-event <event>`. For a `PreToolUse`
//! hook (Cursor's `preToolUse`, `beforeShellExecution`,
//! `beforeMCPExecution` and `beforeReadFile`) or a prompt the daemon reviews
//! as a `UserPromptSubmit` that a live resident allows, denies or pauses for
//! review, the bridge prints the client's own answer without starting
//! Python; a review whose loopback link the client may sign with Guard's
//! Python is the client's to answer. For Cursor's `afterShellExecution` and
//! `afterMCPExecution` observers, which the daemon records as a `PostToolUse`
//! and the client always answers with `{}`, the bridge prints `{}` once the
//! resident has answered (and so queued the record). The client's other
//! hooks, every other verdict and anything the bridge cannot reproduce
//! exactly run the Python client unchanged, with the hook it already read
//! and the time it already spent.
//!
//! The client also sends an `after*` observer proof and approval binding in
//! `hook_env`; the daemon drops `hook_env` before it reviews a hook, so only
//! the client's CLI fallback reads them, and the bridge reads no key.
//!
//! The bridge reproduces the client's steps up to its daemon request:
//! `_read_hook_input`, `json.loads`, `_prepare_cursor_hook_payload`,
//! `_workspace_from_cursor_input`, `stamp_hook_input_text` and the query
//! `_daemon_hook_result` sends. The resident answers the request the
//! daemon would have forwarded, so a verdict is never decided here.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_adapter_prepare::{cursor_client_event, first_truthy, prepare_payload};
use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};

use crate::bounded_hook_bridge::{
    read_hook_input, run_python, write_stdout, Input, MAX_HOOK_INPUT_BYTES,
};
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct::{direct_answer, CURSOR};
use crate::codex_hook_response::{POST_TOOL_USE, PRE_TOOL_USE};
use crate::cursor_hook_bridge_response::rendered;
use crate::cursor_hook_bridge_script::read_ported_script;
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};

pub(crate) const BRIDGE_COMMAND: &str = "cursor-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "cursor-hook-bridge-v1";
const EVENT_FLAG: &str = "--cursor-hook-event";
const PROJECT_DIR_ENV: &str = "CURSOR_PROJECT_DIR";
const AFTER_EVENTS: [&str; 2] = ["aftershellexecution", "aftermcpexecution"];
/// The names `_prepare_cursor_hook_payload` gives the `after*` observers.
const PREPARED_AFTER_EVENTS: [&str; 2] = ["afterShellExecution", "afterMCPExecution"];
/// The client's answer to an `after*` observer the daemon reviewed.
const AFTER_STDOUT: &str = "{}\n";
/// The event the bridge names a prompt for the resident.
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
/// The keys the daemon reads a hook's event from before `hook_event_name`.
const EARLIER_EVENT_KEYS: [&str; 2] = ["event", "eventName"];
/// The prompt names the daemon reviews as a `UserPromptSubmit`, compacted.
const PROMPT_EVENTS: [&str; 3] = ["prompt", "userpromptsubmit", "userpromptsubmitted"];
const UNAVAILABLE_STDOUT: &str = "{\"permission\": \"deny\", \"user_message\": \"HOL Guard could not complete the native hook decision safely.\"}\n";

/// `_cursor_unavailable_response` for a hook whose input could not be read
/// before the deadline: its stdout and exit code.
fn unavailable_output(event: &str) -> (&'static str, i32) {
    let compact: String = py_strip(event)
        .to_lowercase()
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect();
    if AFTER_EVENTS.contains(&compact.as_str()) {
        return ("{}\n", 0);
    }
    (UNAVAILABLE_STDOUT, 2)
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

/// A stripped, non-blank candidate that `Path(candidate).is_dir()`.
fn directory_candidate(value: &str) -> Option<String> {
    let candidate = py_strip(value);
    (!candidate.is_empty() && Path::new(candidate).is_dir()).then(|| candidate.to_owned())
}

/// `_workspace_from_cursor_input`. `Err` when `CURSOR_PROJECT_DIR` is not
/// text the bridge can read as Python does.
pub(crate) fn workspace(
    payload: &OMap,
    project_dir: Option<std::ffi::OsString>,
) -> Result<Option<String>, ()> {
    if let Some(project_dir) = project_dir {
        let project_dir = project_dir.into_string().map_err(|_| ())?;
        if let Some(candidate) = directory_candidate(&project_dir) {
            return Ok(Some(candidate));
        }
    }
    let roots = first_truthy(
        payload.get("workspace_roots"),
        payload.get("workspaceRoots"),
    );
    if let Some(roots) = roots.and_then(OValue::as_list) {
        for root in roots {
            if let Some(candidate) = root.as_str().and_then(directory_candidate) {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(payload.get_str("cwd").and_then(directory_candidate))
}

/// What the bridge needs of the ported client.
struct Client {
    guard_home: String,
    home: Option<String>,
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

/// The request the client would send for a `PreToolUse` hook, a prompt or
/// an `after*` observer, or `None` to run the client.
fn prepared_request(client: &Client, raw: &[u8]) -> Option<Request> {
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        return None;
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body).ok()?;
    if py_strip(text).is_empty() {
        return None;
    }
    // `json.loads` skips only JSON whitespace around the document.
    let document = text.trim_matches([' ', '\t', '\n', '\r']);
    let OValue::Map(payload) = parse_python_json(document).ok()? else {
        return None;
    };
    // Cursor's `after*` hooks prepare as themselves; one is sent only where
    // the client would also answer it as an observer.
    let event = cursor_client_event(&payload)?;
    let prepared = prepare_payload("cursor", &payload, None).ok()?;
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
    let workspace = workspace(&prepared, std::env::var_os(PROJECT_DIR_ENV)).ok()?;
    let serialized = OValue::Map(prepared).compact_json();
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
    let OValue::Map(response) = parse_python_json(body).ok()? else {
        return None;
    };
    match kind {
        Kind::PreToolUse | Kind::Prompt => rendered(event, &response, guard_home),
        Kind::After => Some((AFTER_STDOUT.to_owned(), 0)),
    }
}

/// The exit code once the bridge answered the hook, or `None` to run the
/// client.
fn route(client: &Client, raw: &[u8]) -> Option<i32> {
    let request = prepared_request(client, raw)?;
    let event_name = match request.kind {
        Kind::PreToolUse => PRE_TOOL_USE,
        Kind::Prompt => USER_PROMPT_SUBMIT,
        Kind::After => POST_TOOL_USE,
    };
    let guard_home = Path::new(&client.guard_home);
    let answered = direct_answer(
        CURSOR,
        guard_home,
        &request.query,
        event_name,
        &request.data,
        client.deadline,
    )?;
    let (stdout, code) = answer(request.kind, &request.event, &answered, guard_home)?;
    write_stdout(&stdout);
    Some(code)
}

/// The ported client the installer's argv runs, or `None` for any other
/// argv or script.
fn client(python_argv: &[String], started: Instant) -> Option<Client> {
    let [_, isolated, script, flag, _event] = python_argv else {
        return None;
    };
    if isolated != "-I" || flag != EVENT_FLAG {
        return None;
    }
    let constants = read_ported_script(Path::new(script))?;
    let budget = Duration::from_secs(constants.timeout_seconds);
    Some(Client {
        guard_home: constants.guard_home,
        home: constants.home,
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
    let Some(client) = client(python_argv, started) else {
        return run_python(python_argv, None, started.elapsed(), false)
            .unwrap_or_else(|| unavailable(event));
    };
    let raw = match read_hook_input(client.deadline) {
        Input::Read(raw) => raw,
        Input::Failed if Instant::now() >= client.deadline => return unavailable(event),
        // The client reads an empty hook and answers its unparseable input.
        Input::Failed => Vec::new(),
    };
    if let Some(code) = route(&client, &raw) {
        return code;
    }
    run_python(python_argv, Some(&raw), started.elapsed(), false)
        .unwrap_or_else(|| unavailable(event))
}

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_tests.rs"]
mod tests;
