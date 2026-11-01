//! Native Cline hook worker (`cline-hook-worker-v1`).
//!
//! Each managed Cline hook slot runs `guard-runtime cline-hook-worker
//! <config>` with the hook payload on stdin, in place of the Python worker
//! Guard used to generate beside it. The config names the hook event, the
//! Guard argv that reviews one payload, the live-proof file and the adapter
//! state that says which Cline transport is active.
//!
//! The worker reads the payload as `json.loads` would, refuses one that is
//! oversized, too deep or not an object, splits a `run_commands` call into
//! one review per command, and runs the Guard argv once per payload. It
//! answers Cline with one JSON line. A blocking `PreToolUse` cancels on any
//! denial, ambiguous decision or unavailable review; the other events only
//! observe. Every failure fails closed, and the worker always exits 0 so
//! Cline reads its answer.
//!
//! A payload CPython reads but the port cannot hold (a lone surrogate,
//! `NaN`, nesting past the parser's bound) is refused as invalid.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue, PyJsonError};
use guard_contracts::{python_float_repr, write_json_string};
use serde::Deserialize;

use crate::claude_hook_bridge_render::py_strip;

#[path = "cline_hook_worker_decision.rs"]
mod decision;

use decision::{blocked, explicitly_allows, parse_output, reason};

pub(crate) const WORKER_COMMAND: &str = "cline-hook-worker";
pub(crate) const WORKER_FEATURE: &str = "cline-hook-worker-v1";
const MARKER: &str = "HOL_GUARD_MANAGED_CLINE_HOOK_V1";
const SCHEMA: &str = "cline-hook-worker.v1";
const EVENTS: [&str; 6] = [
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "TaskStart",
    "TaskError",
    "SessionShutdown",
];
const MAX_BYTES: u64 = 256 * 1024;
const MAX_PRETOOL_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 48;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 1024 * 1024;
/// Guard's own answer is one JSON line; far more is not a decision.
const MAX_DECISION_BYTES: u64 = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(9);
const CANARY_ENV: &str = "HOL_GUARD_CLINE_CANARY";

const CONFIG_UNAVAILABLE: &str =
    "HOL Guard Cline hook configuration is unavailable; this action was not allowed to proceed.";
const OVERSIZED: &str = "HOL Guard rejected an oversized Cline hook request.";
const UNPARSEABLE: &str = "HOL Guard could not parse the Cline hook request safely.";
const INVALID: &str = "HOL Guard rejected an invalid Cline hook request.";
const OVERSIZED_PRETOOL: &str = "HOL Guard rejected an oversized Cline pre-tool request.";
const TRANSPORT_UNAVAILABLE: &str =
    "HOL Guard Cline transport state is unavailable; this action was not allowed to proceed safely.";
const EVALUATION_UNAVAILABLE: &str =
    "HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed.";
const INVALID_DECISION: &str =
    "HOL Guard returned an invalid decision; this Cline action was not allowed to proceed.";
const AMBIGUOUS: &str = "HOL Guard returned an ambiguous decision; this action was withheld.";

/// The config Guard writes beside each managed slot.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    marker: String,
    schema: String,
    event: String,
    guard: Vec<String>,
    proof: String,
    adapter_state: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Config {
    event: String,
    guard: Vec<String>,
    proof: PathBuf,
    adapter_state: PathBuf,
}

impl Config {
    fn blocking(&self) -> bool {
        self.event == "PreToolUse"
    }
}

pub(crate) fn parse_config(bytes: &[u8]) -> Option<Config> {
    let raw: RawConfig = serde_json::from_slice(bytes).ok()?;
    let proof = PathBuf::from(raw.proof);
    let adapter_state = PathBuf::from(raw.adapter_state);
    let valid = raw.marker == MARKER
        && raw.schema == SCHEMA
        && EVENTS.contains(&raw.event.as_str())
        && raw.guard.first().is_some_and(|program| !program.is_empty())
        && proof.is_absolute()
        && adapter_state.is_absolute();
    valid.then_some(Config {
        event: raw.event,
        guard: raw.guard,
        proof,
        adapter_state,
    })
}

fn read_capped(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

fn load_config(path: &Path) -> Option<Config> {
    if !path.is_absolute() {
        return None;
    }
    parse_config(&read_capped(path, MAX_CONFIG_BYTES)?)
}

/// Runs one hook and returns the process exit status, always 0.
pub(crate) fn run(config_path: &str) -> i32 {
    let path = Path::new(config_path);
    let answer = match load_config(path) {
        Some(config) => {
            let canary = std::env::var_os(CANARY_ENV).is_some_and(|value| value == "1");
            let mut input = Vec::new();
            let read = io::stdin()
                .lock()
                .take(MAX_BYTES + 1)
                .read_to_end(&mut input);
            if read.is_err() {
                input.clear();
            }
            answer(&config, &input, canary, &mut review)
        }
        // A config that cannot be read still answers in the shape its slot
        // expects; only the pre-tool slot cancels.
        None => failure(
            path.file_stem().and_then(|stem| stem.to_str()) == Some("PreToolUse"),
            CONFIG_UNAVAILABLE,
        ),
    };
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(answer.as_bytes());
    let _ = stdout.flush();
    0
}

/// The worker's whole answer for one payload. `review` runs the Guard argv
/// with one payload and returns its stdout, or `None` when it could not run
/// or answer in time.
pub(crate) fn answer(
    config: &Config,
    input: &[u8],
    canary: bool,
    review: &mut dyn FnMut(&[String], &str) -> Option<Vec<u8>>,
) -> String {
    let blocking = config.blocking();
    if input.len() as u64 > MAX_BYTES {
        return failure(blocking, OVERSIZED);
    }
    let value = match std::str::from_utf8(input).map(parse_python_json) {
        Ok(Ok(value)) => value,
        Ok(Err(PyJsonError::Unsupported)) => return failure(blocking, INVALID),
        Ok(Err(PyJsonError::Decode)) | Err(_) => return failure(blocking, UNPARSEABLE),
    };
    let Some(map) = value.as_map().filter(|_| depth_ok(&value, 1)) else {
        return failure(blocking, INVALID);
    };
    if blocking && !pretool_size_ok(map) {
        return failure(blocking, OVERSIZED_PRETOOL);
    }
    match active_transport(&config.adapter_state, canary).as_deref() {
        Some("hooks") => {}
        Some(_) => {
            return emit(&[
                ("cancel", OValue::Bool(false)),
                ("errorMessage", OValue::str("")),
                ("contextModification", OValue::str("")),
            ])
        }
        None => return failure(blocking, TRANSPORT_UNAVAILABLE),
    }
    let payloads = if blocking {
        match command_payloads(map) {
            Some(payloads) => payloads,
            None => return failure(blocking, INVALID),
        }
    } else {
        vec![value.clone()]
    };
    let mut why: Option<String> = None;
    for payload in &payloads {
        let Some(stdout) = review(&config.guard, &python_dumps(payload)) else {
            return failure(blocking, EVALUATION_UNAVAILABLE);
        };
        let Some(decision) = std::str::from_utf8(&stdout).ok().and_then(parse_output) else {
            return failure(blocking, INVALID_DECISION);
        };
        if blocked(&decision) {
            why = Some(reason(&decision).to_owned());
            break;
        }
        if !explicitly_allows(&decision) {
            why = Some(AMBIGUOUS.to_owned());
            break;
        }
    }
    let outcome = match (blocking, why.is_some()) {
        (true, true) => "blocked",
        (true, false) => "allowed",
        (false, _) => "observed",
    };
    if !canary {
        write_proof(&config.proof, &config.event, outcome);
    }
    let message = OValue::str(why.unwrap_or_default());
    if blocking {
        let cancel = OValue::Bool(outcome == "blocked");
        emit(&[
            ("cancel", cancel),
            ("errorMessage", message.clone()),
            ("contextModification", message),
        ])
    } else {
        emit(&[
            ("cancel", OValue::Bool(false)),
            ("contextModification", message),
        ])
    }
}

/// `sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")`.
fn emit(fields: &[(&str, OValue)]) -> String {
    let mut map = OMap::new();
    for (key, value) in fields {
        map.insert(key, value.clone());
    }
    OValue::Map(map).compact_json() + "\n"
}

fn failure(blocking: bool, message: &str) -> String {
    emit(&[
        ("cancel", OValue::Bool(blocking)),
        (
            "errorMessage",
            OValue::str(if blocking { message } else { "" }),
        ),
        ("contextModification", OValue::str(message)),
    ])
}

/// Every value, scalars included, sits at most [`MAX_DEPTH`] deep.
fn depth_ok(value: &OValue, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match value {
        OValue::Map(map) => map.iter().all(|(_, item)| depth_ok(item, depth + 1)),
        OValue::List(items) => items.iter().all(|item| depth_ok(item, depth + 1)),
        _ => true,
    }
}

/// The pre-tool action, as compact ASCII JSON, fits [`MAX_PRETOOL_BYTES`].
fn pretool_size_ok(map: &OMap) -> bool {
    let action = [map.get("tool_call"), map.get("preToolUse")]
        .into_iter()
        .flatten()
        .find(|item| item.as_map().is_some());
    let size = match action {
        Some(action) => action.compact_json().len(),
        None => OValue::Map(map.clone()).compact_json().len(),
    };
    size <= MAX_PRETOOL_BYTES
}

/// The adapter state's `active_transport`, or `"hooks"` for the install
/// canary. `None` when the state cannot be read.
fn active_transport(path: &Path, canary: bool) -> Option<String> {
    if canary {
        return Some("hooks".to_owned());
    }
    let bytes = read_capped(path, MAX_STATE_BYTES)?;
    let value = parse_python_json(std::str::from_utf8(&bytes).ok()?).ok()?;
    Some(
        value
            .as_map()?
            .get("active_transport")?
            .as_str()?
            .to_owned(),
    )
}

/// `dict.get(key, default)`: the key's value when present, even `null`.
fn get_or<'a>(map: &'a OMap, key: &str, default: Option<&'a OValue>) -> Option<&'a OValue> {
    map.get(key).or(default)
}

/// One review payload per command of a `run_commands` call, else the
/// payload itself. `None` when the commands are JSON the port cannot read.
fn command_payloads(map: &OMap) -> Option<Vec<OValue>> {
    let whole = || Some(vec![OValue::Map(map.clone())]);
    let current = map.get("tool_call").and_then(OValue::as_map);
    let legacy = map.get("preToolUse").and_then(OValue::as_map);
    let name = current
        .and_then(|call| call.get("name"))
        .filter(|name| !name.is_null())
        .or_else(|| legacy.and_then(|call| call.get("toolName")));
    if name.and_then(OValue::as_str) != Some("run_commands") {
        return whole();
    }
    let raw = current
        .and_then(|call| call.get("input"))
        .filter(|raw| !raw.is_null())
        .or_else(|| legacy.and_then(|call| call.get("parameters")));
    let mut commands = raw.cloned();
    if let Some(OValue::Map(raw)) = raw {
        commands = get_or(raw, "commands", get_or(raw, "command", raw.get("cmd"))).cloned();
    }
    if let Some(OValue::Str(text)) = &commands {
        commands = Some(match parse_python_json(text) {
            Ok(OValue::Str(decoded)) => OValue::List(vec![OValue::Str(decoded)]),
            Ok(decoded) => decoded,
            Err(PyJsonError::Decode) => OValue::List(vec![OValue::Str(text.clone())]),
            Err(PyJsonError::Unsupported) => return None,
        });
    }
    let Some(OValue::List(items)) = commands else {
        return whole();
    };
    let command_id = current
        .map(|call| call.get("id").cloned().unwrap_or_else(|| OValue::str("")))
        .unwrap_or_else(|| OValue::str(""));
    let cwd = map
        .get("cwd")
        .and_then(OValue::as_str)
        .map(py_strip)
        .filter(|cwd| !cwd.is_empty());
    let mut out = Vec::new();
    for item in &items {
        let item = match item {
            OValue::Map(entry) => get_or(entry, "command", entry.get("cmd")),
            other => Some(other),
        };
        let Some(command) = item.and_then(OValue::as_str) else {
            continue;
        };
        if py_strip(command).is_empty() {
            continue;
        }
        let mut input = OMap::new();
        input.insert("command", OValue::str(command));
        let mut call = OMap::new();
        call.insert("id", command_id.clone());
        call.insert("name", OValue::str("run_command"));
        call.insert("input", OValue::Map(input));
        let mut entry = OMap::new();
        entry.insert("hookName", OValue::str("PreToolUse"));
        entry.insert("hook_event_name", OValue::str("PreToolUse"));
        entry.insert("tool_call", OValue::Map(call));
        if let Some(cwd) = cwd {
            entry.insert("cwd", OValue::str(cwd));
        }
        out.push(OValue::Map(entry));
    }
    if out.is_empty() {
        return whole();
    }
    Some(out)
}

/// `json.dumps(value)`: insertion order, `", "` and `": "` separators,
/// `ensure_ascii`.
fn python_dumps(value: &OValue) -> String {
    let mut out = Vec::new();
    write_default(value, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

fn write_default(value: &OValue, out: &mut Vec<u8>) {
    match value {
        OValue::List(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(b", ");
                }
                write_default(item, out);
            }
            out.push(b']');
        }
        OValue::Map(map) => {
            out.push(b'{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(b", ");
                }
                write_json_string(key, out);
                out.extend_from_slice(b": ");
                write_default(item, out);
            }
            out.push(b'}');
        }
        scalar => out.extend_from_slice(scalar.compact_json().as_bytes()),
    }
}

/// Runs the Guard argv with `payload` on stdin and returns its stdout once
/// it closes and the process exits, inside [`TIMEOUT`]. The exit status is
/// not read: the answer is.
fn review(argv: &[String], payload: &str) -> Option<Vec<u8>> {
    let (program, rest) = argv.split_first()?;
    let deadline = Instant::now() + TIMEOUT;
    let mut child = Command::new(program)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
    let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let body = payload.as_bytes().to_vec();
    // A reviewer that never reads its stdin must not hold the worker past
    // its deadline, so the write runs beside the wait.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout.take(MAX_DECISION_BYTES + 1).read_to_end(&mut bytes);
        let _ = sender.send(read.ok().map(|_| bytes));
    });
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
        .flatten();
    let exited = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if bytes.is_some() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => break false,
        }
    };
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    bytes.filter(|bytes| bytes.len() as u64 <= MAX_DECISION_BYTES)
}

/// Records the hook's outcome for Guard's live-proof check; a failure to
/// write it never changes the answer.
fn write_proof(path: &Path, event: &str, outcome: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64());
    let mut body = Vec::new();
    body.extend_from_slice(b"{\"event\": ");
    write_json_string(event, &mut body);
    body.extend_from_slice(b", \"outcome\": ");
    write_json_string(outcome, &mut body);
    body.extend_from_slice(b", \"schema_version\": 1, \"source\": \"cline\", \"timestamp\": ");
    body.extend_from_slice(python_float_repr(timestamp).as_bytes());
    body.push(b'}');
    let Some(parent) = path.parent() else {
        return;
    };
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    if fs::create_dir_all(parent).is_ok() && fs::write(&temporary, &body).is_ok() {
        let _ = fs::rename(&temporary, path);
    }
}

#[cfg(test)]
#[path = "cline_hook_worker_tests.rs"]
mod tests;
