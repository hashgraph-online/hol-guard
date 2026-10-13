//! Native bounded hook bridge: the daemon path of `main_from_argv` in
//! `adapters/bounded_cli_hook_bridge.py` for Copilot, Kimi, Devin, ZCode and
//! OpenClaw. Those harnesses run
//! `guard-runtime bounded-hook-bridge <python> -I -c <bootstrap> <config>`
//! once per hook. The native bridge reads the hook within its deadline,
//! posts it to the loopback Guard daemon with the daemon auth token and
//! renders the daemon's answer for the harness. Grok runs its generated
//! client instead, `<python> -I <script> <config>`, which
//! `bounded_hook_bridge_grok` answers.
//!
//! Only a clean daemon answer is rendered here. Every other path runs the
//! Python bridge it was given, with the original argv and stdin:
//! - before the daemon was asked, Python runs the whole hook again;
//! - once the daemon was asked, Python skips the daemon and runs the
//!   isolated CLI hook, so one hook never reaches the daemon twice.
//!
//! Past the hook deadline, or when stdin cannot be read in time, the native
//! bridge writes the same fixed fail-closed payload Python writes. The
//! native bridge never decides a verdict.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::bounded_hook_bridge_render::{
    daemon_response_to_native, event_name, failure_output, Rendered, NATIVE_HARNESSES,
};
use crate::claude_hook_bridge_auth::{private_file_text, LOOPBACK_HOSTS};
use crate::claude_hook_bridge_http::{remaining, LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::hook_bridge_exit::exit_code;
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};
use crate::pyjson::{self, PyVal};

#[cfg(unix)]
#[path = "bounded_hook_bridge_input.rs"]
mod input;
#[cfg(windows)]
#[path = "bounded_hook_bridge_input_windows.rs"]
mod input;
pub(crate) use input::read_hook_input;

pub(crate) const BRIDGE_COMMAND: &str = "bounded-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "bounded-hook-bridge-v1";
pub(crate) const ELAPSED_ENV: &str = "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS";
pub(crate) const DAEMON_TRIED_ENV: &str = "HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED";

pub(crate) const MAX_HOOK_INPUT_BYTES: usize = 1_000_000;
const READ_CHUNK: usize = 65_536;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 4096;
const DAEMON_BUDGET: Duration = Duration::from_secs(5);
const PROMPT_DAEMON_BUDGET: Duration = Duration::from_secs(10);
const STATE_FILE: &str = "daemon-state.json";
const TOKEN_FILE: &str = "daemon-auth-token";
const MANAGED_MARKER: &str = "HOL_GUARD_MANAGED_ZCODE";
const DEFAULT_EVENT: &str = "PreToolUse";
const HOOK_DEADLINE: &str = "daemon hook deadline exhausted";

/// The fields of the install-time config the native bridge reads, after
/// every check `run_bounded_cli_hook` applies.
#[derive(Debug, PartialEq)]
pub(crate) struct BridgeConfig {
    pub(crate) harness: String,
    pub(crate) guard_home: PathBuf,
    pub(crate) timeout: Duration,
}

/// The config argument of `[python, "-I", "-c", bootstrap, config]`, with
/// ZCode's trailing `# HOL_GUARD_MANAGED_ZCODE` when a shell kept it.
pub(crate) fn config_argument(python_argv: &[String]) -> Option<&str> {
    let shaped = match python_argv {
        [_, isolated, code, _, _] => isolated == "-I" && code == "-c",
        [_, isolated, code, _, _, hash, marker] => {
            isolated == "-I" && code == "-c" && hash == "#" && marker == MANAGED_MARKER
        }
        _ => false,
    };
    shaped.then(|| python_argv[4].as_str())
}

fn positive_seconds(value: Option<&PyVal>) -> Option<Duration> {
    let seconds = match value? {
        PyVal::Int(digits) => digits.parse::<f64>().ok()?,
        PyVal::Float(number) => *number,
        _ => return None,
    };
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(seconds).ok()
}

/// The config a POSIX install wrote, or `None` for anything Python would
/// refuse or handle in a step the native bridge does not port.
pub(crate) fn parse_config(argument: &str) -> Option<BridgeConfig> {
    let parsed = pyjson::parse_mapping_lone_surrogates(argument).ok()?;
    if parsed.mapped {
        return None;
    }
    let payload = parsed.value;
    payload.as_dict()?;
    payload.get("python_executable")?.as_str()?;
    payload.get("package_root")?.as_str()?;
    let guard_home = payload.get("guard_home")?.as_str()?;
    let cli_args = payload.get("cli_args")?.as_list()?;
    let harness = payload.get("harness")?.as_str()?;
    let timeout = positive_seconds(payload.get("timeout_seconds"))?;
    let launcher_ok = matches!(
        payload.get("frozen_launcher"),
        None | Some(PyVal::Bool(false))
    );
    if !launcher_ok
        || !cli_args.iter().all(|item| item.as_str().is_some())
        || !NATIVE_HARNESSES.contains(&harness)
        || !Path::new(guard_home).is_absolute()
    {
        return None;
    }
    Some(BridgeConfig {
        harness: harness.to_owned(),
        guard_home: PathBuf::from(guard_home),
        timeout,
    })
}

#[derive(Debug, PartialEq)]
pub(crate) enum Input {
    Read(Vec<u8>),
    /// The deadline passed or stdin failed: Python's `_emit_failure`.
    Failed,
}

/// A hook the daemon can be asked about: the stamped text and its event.
#[derive(Debug, PartialEq)]
pub(crate) struct Prepared {
    pub(crate) data: String,
    pub(crate) event_name: String,
}

/// `read_hook_input`'s decode and `stamp_hook_input_text`, for input the
/// native bridge forwards exactly as Python would. `None` hands the hook to
/// Python unchanged: oversized, undecodable, non-object or unstampable.
pub(crate) fn prepare(raw: &[u8]) -> Option<Prepared> {
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        return None;
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body).ok()?;
    let Stamp::Text(data) = stamp_hook_input_text(text, &current_environment()) else {
        return None;
    };
    let parsed = pyjson::parse_mapping_lone_surrogates(&data).ok()?;
    if parsed.mapped || parsed.value.as_dict().is_none() {
        return None;
    }
    let event_name = event_name(&data, &parsed.value);
    Some(Prepared { data, event_name })
}

/// `_daemon_hook_endpoint`: the loopback host and port the daemon state
/// names, after the URL check `try_daemon_hook` applies.
fn daemon_endpoint(guard_home: &Path, harness: &str) -> Option<(String, u16)> {
    let path = guard_home.join(STATE_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_STATE_BYTES {
        return None;
    }
    let text = private_file_text(&path, "Guard daemon state").ok()?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    if parsed.mapped {
        return None;
    }
    let host = parsed.value.get("host")?.as_str()?;
    let Some(PyVal::Int(digits)) = parsed.value.get("port") else {
        return None;
    };
    let port = digits.parse::<u16>().ok().filter(|port| *port >= 1)?;
    if !LOOPBACK_HOSTS.contains(&host) {
        return None;
    }
    let rendered_host = if host == "::1" {
        "[::1]".to_owned()
    } else {
        host.to_owned()
    };
    assert_loopback_http_url(&format!("http://{rendered_host}:{port}/v1/hooks/{harness}")).ok()?;
    Some((host.to_owned(), port))
}

/// `load_guard_daemon_auth_token`, limited to tokens urllib sends as is.
fn daemon_auth_token(guard_home: &Path) -> Option<String> {
    let path = guard_home.join(TOKEN_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let token = private_file_text(&path, "Guard daemon auth token").ok()?;
    let sendable = token
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
    (!token.is_empty() && sendable).then_some(token)
}

/// `post_hook_json`: the daemon's JSON object, or `None` for any failure.
fn post_hook(
    host: &str,
    port: u16,
    harness: &str,
    token: &str,
    data: &str,
    deadline: Instant,
) -> Option<Vec<(String, PyVal)>> {
    let mut connection = LoopbackConnection::new(host, port);
    let head = connection
        .post(
            &format!("/v1/hooks/{harness}"),
            &[
                ("Content-Type", "application/json"),
                ("Connection", "close"),
                ("X-Guard-Token", token),
            ],
            data.as_bytes(),
            deadline,
        )
        .ok()?;
    if head.status != 200 {
        return None;
    }
    let body = connection
        .read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
        .ok()?;
    if Instant::now() >= deadline || body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return None;
    }
    if body.starts_with(b"\xef\xbb\xbf") {
        return None;
    }
    let text = std::str::from_utf8(&body).ok()?;
    let parsed = pyjson::parse_mapping_lone_surrogates(text).ok()?;
    match parsed.value {
        PyVal::Dict(entries) if !parsed.mapped => Some(entries),
        _ => None,
    }
}

/// What the native bridge does with one hook.
#[derive(Debug, PartialEq)]
pub(crate) enum Route {
    /// Write the rendered daemon answer.
    Respond {
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
    /// Write Python's fixed fail-closed payload for this event.
    Fail(String),
    /// Run the Python bridge; `daemon_tried` once the daemon was asked.
    Delegate { daemon_tried: bool },
}

/// The daemon path of `run_bounded_cli_hook` after the input was read.
pub(crate) fn route_hook(config: &BridgeConfig, raw: &[u8], deadline: Instant) -> Route {
    let delegate = Route::Delegate {
        daemon_tried: false,
    };
    let Some(prepared) = prepare(raw) else {
        return delegate;
    };
    if Instant::now() >= deadline {
        return Route::Fail(prepared.event_name);
    }
    let budget = if prepared.event_name == "UserPromptSubmit" {
        PROMPT_DAEMON_BUDGET
    } else {
        DAEMON_BUDGET
    };
    if let Some(route) = direct_route(config, &prepared, deadline, budget) {
        return route;
    }
    let left = remaining(deadline);
    let Some((host, port)) = daemon_endpoint(&config.guard_home, &config.harness) else {
        return delegate;
    };
    let Some(token) = daemon_auth_token(&config.guard_home) else {
        return delegate;
    };
    let now = Instant::now();
    let transport_deadline = deadline.min(now + (left / 2).min(budget));
    if transport_deadline <= now {
        return delegate;
    }
    let answer = post_hook(
        &host,
        port,
        &config.harness,
        &token,
        &prepared.data,
        transport_deadline,
    );
    let rendered = answer.and_then(|response| {
        daemon_response_to_native(&response, &config.harness, &prepared.event_name)
    });
    answered_route(rendered, prepared.event_name, deadline)
}

/// The route for an answer the daemon or its resident gave. A recorded
/// answer the bridge cannot render runs Python without the daemon, so the
/// hook is never reviewed twice.
fn answered_route(rendered: Option<Rendered>, event_name: String, deadline: Instant) -> Route {
    if Instant::now() >= deadline {
        return Route::Fail(event_name);
    }
    match rendered {
        Some(rendered) => Route::Respond {
            stdout: rendered.stdout,
            stderr: rendered.stderr,
            exit_code: rendered.exit_code,
        },
        None => Route::Delegate { daemon_tried: true },
    }
}

/// The route for a hook a live resident answered directly, rendered as the
/// daemon's identical answer would be, or `None` to ask the daemon.
fn direct_route(
    config: &BridgeConfig,
    prepared: &Prepared,
    deadline: Instant,
    budget: Duration,
) -> Option<Route> {
    let rpc_deadline = deadline.min(Instant::now() + (remaining(deadline) / 2).min(budget));
    let answer = crate::codex_hook_bridge_direct::bounded_direct_answer(
        &config.harness,
        &config.guard_home,
        &prepared.event_name,
        &prepared.data,
        rpc_deadline,
    )?;
    // The resident answered and queued the evidence; from here the hook
    // never reaches the daemon.
    let rendered = pyjson::parse_mapping_lone_surrogates(&answer)
        .ok()
        .and_then(|parsed| match parsed.value {
            PyVal::Dict(entries) if !parsed.mapped => Some(entries),
            _ => None,
        })
        .and_then(|response| {
            daemon_response_to_native(&response, &config.harness, &prepared.event_name)
        });
    Some(answered_route(
        rendered,
        prepared.event_name.clone(),
        deadline,
    ))
}

/// Run the Python bridge. `stdin` is the hook already read, or `None` to
/// let Python read the hook itself.
pub(crate) fn run_python(
    argv: &[String],
    stdin: Option<&[u8]>,
    elapsed: Duration,
    daemon_tried: bool,
) -> Option<i32> {
    let (program, args) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env(ELAPSED_ENV, elapsed.as_millis().to_string())
        .env_remove(DAEMON_TRIED_ENV);
    if daemon_tried {
        command.env(DAEMON_TRIED_ENV, "1");
    }
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let mut child = command.spawn().ok()?;
    if let (Some(mut pipe), Some(data)) = (child.stdin.take(), stdin) {
        let _ = pipe.write_all(data);
    }
    child.wait().ok().map(exit_code)
}

pub(crate) fn write_stdout(text: &str) {
    let mut stdout = io::stdout().lock();
    let _ = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush());
}

fn write_stderr_line(text: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr
        .write_all(text.as_bytes())
        .and_then(|()| stderr.write_all(b"\n"))
        .and_then(|()| stderr.flush());
}

fn fail(harness: &str, event_name: &str) -> i32 {
    let (payload, code) = failure_output(harness, event_name);
    write_stdout(&payload);
    code
}

pub(crate) fn run(python_argv: &[String]) -> i32 {
    let started = Instant::now();
    if python_argv.len() == 4 && python_argv[1] == "-I" && python_argv[2] != "-c" {
        return crate::bounded_hook_bridge_grok::run(python_argv, started);
    }
    let config = config_argument(python_argv).and_then(parse_config);
    let Some(config) = config else {
        return run_python(python_argv, None, started.elapsed(), false)
            .unwrap_or_else(|| fail("unknown", DEFAULT_EVENT));
    };
    let Some(deadline) = started.checked_add(config.timeout) else {
        return run_python(python_argv, None, started.elapsed(), false)
            .unwrap_or_else(|| fail(&config.harness, DEFAULT_EVENT));
    };
    let Input::Read(raw) = read_hook_input(deadline) else {
        return fail(&config.harness, DEFAULT_EVENT);
    };
    match route_hook(&config, &raw, deadline) {
        Route::Respond {
            stdout,
            stderr,
            exit_code,
        } => {
            write_stdout(&stdout);
            if !stderr.is_empty() {
                write_stderr_line(&stderr);
            }
            exit_code
        }
        Route::Fail(event_name) => fail(&config.harness, &event_name),
        Route::Delegate { daemon_tried } => {
            run_python(python_argv, Some(&raw), started.elapsed(), daemon_tried).unwrap_or_else(
                || {
                    let event_name =
                        prepare(&raw).map_or_else(|| DEFAULT_EVENT.to_owned(), |p| p.event_name);
                    fail(&config.harness, &event_name)
                },
            )
        }
    }
}

#[cfg(all(test, unix))]
#[path = "bounded_hook_bridge_tests.rs"]
mod tests;
