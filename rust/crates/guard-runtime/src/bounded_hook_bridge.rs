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
//! A hook that is too large, cannot be decoded or is not a JSON object gets
//! the fixed fail-closed payload Python writes for it, and so does a daemon
//! answer the bridge cannot render. A clean daemon answer is rendered here.
//! When no daemon is reachable, or the daemon did not answer, the bridge
//! runs the install-time `start_command` and sends the hook once to a daemon
//! that came up since; a daemon that was already asked is never asked
//! twice. Without such an answer the hook fails closed. An install whose
//! config predates `start_command` gets the command that install would
//! write, built from its config. A lone surrogate is forwarded and rendered
//! as the `\udXXX` escape Python's `json.dumps` writes for it.
//!
//! Past the hook deadline, or when stdin cannot be read in time, the native
//! bridge writes the same fixed fail-closed payload Python writes. The
//! native bridge never decides a verdict, and Python never decides one for
//! it.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::bounded_hook_bridge_render::{
    daemon_response_to_native, event_name, failure_output, failure_output_for, Rendered,
    FAILURE_REASON, NATIVE_HARNESSES,
};
use crate::claude_hook_bridge_http::remaining;
use crate::guard_store_json::py_repr_str;
use crate::hook_bridge_daemon_start::{await_daemon, start_daemon, Attempt, TRANSPORT_FAILURE};
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};
use crate::pyjson::{self, PyVal, SurrogateMapped};

#[cfg(unix)]
#[path = "bounded_hook_bridge_input.rs"]
mod input;
#[cfg(windows)]
#[path = "bounded_hook_bridge_input_windows.rs"]
mod input;
pub(crate) use input::read_hook_input;
#[path = "bounded_hook_bridge_daemon.rs"]
mod daemon;
use daemon::post_hook;
pub(crate) use daemon::{
    daemon_target, post_hook_reply, transport_deadline, DaemonTarget, PostFailure,
};

pub(crate) const BRIDGE_COMMAND: &str = "bounded-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "bounded-hook-bridge-v1";

pub(crate) const MAX_HOOK_INPUT_BYTES: usize = 1_000_000;
const READ_CHUNK: usize = 65_536;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 4096;
pub(crate) const DAEMON_BUDGET: Duration = Duration::from_secs(5);
pub(crate) const PROMPT_DAEMON_BUDGET: Duration = Duration::from_secs(10);
const STATE_FILE: &str = "daemon-state.json";
const TOKEN_FILE: &str = "daemon-auth-token";
const MANAGED_MARKER: &str = "HOL_GUARD_MANAGED_ZCODE";
const OVERSIZE_REASON: &str =
    "HOL Guard blocked this action because hook input exceeded the safe size limit.";
const DEFAULT_EVENT: &str = "PreToolUse";
const HOOK_DEADLINE: &str = "daemon hook deadline exhausted";

/// The fields of the install-time config the native bridge reads, after
/// every check `run_bounded_cli_hook` applies.
#[derive(Debug, PartialEq)]
pub(crate) struct BridgeConfig {
    pub(crate) harness: String,
    pub(crate) guard_home: PathBuf,
    pub(crate) timeout: Duration,
    /// The daemon-start command, empty when the install wrote none.
    pub(crate) start_command: Vec<String>,
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
    let python_executable = payload.get("python_executable")?.as_str()?;
    let package_root = payload.get("package_root")?.as_str()?;
    let guard_home = payload.get("guard_home")?.as_str()?;
    let cli_args = payload.get("cli_args")?.as_list()?;
    let harness = payload.get("harness")?.as_str()?;
    let timeout = positive_seconds(payload.get("timeout_seconds"))?;
    let start_command = match payload.get("start_command") {
        None => {
            let cli_args: Vec<&str> = cli_args.iter().filter_map(PyVal::as_str).collect();
            daemon_start_command(python_executable, package_root, guard_home, &cli_args)
        }
        Some(value) => value
            .as_list()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
    };
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
        start_command,
    })
}

/// `daemon_start_command(python_executable, package_root, guard_home,
/// cli_args)` (`bounded_cli_hook_native.py`) for an install whose config
/// predates `start_command`: the config already holds the resolved package
/// root and Guard home, and the canonical home is the `--home` argument,
/// else `Path.home()`.
fn daemon_start_command(
    python_executable: &str,
    package_root: &str,
    guard_home: &str,
    cli_args: &[&str],
) -> Vec<String> {
    let home_dir = cli_args
        .windows(2)
        .find(|pair| pair[0] == "--home")
        .map(|pair| pair[1].to_owned())
        .or_else(python_home);
    let Some(home_dir) = home_dir else {
        return Vec::new();
    };
    let bootstrap = format!(
        "import os,sys;\
sys.path.insert(0, {});\
from pathlib import Path;\
from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;\
failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');\
failure_kind=failure_kind if failure_kind in \
{{'overload','transport-failure','authenticated-control-plane-failure'}} \
else 'transport-failure';\
schedule_guard_daemon_recovery(Path({}),home_dir=Path({}),failure_kind=failure_kind)",
        py_repr_str(package_root),
        py_repr_str(guard_home),
        py_repr_str(&home_dir),
    );
    vec![
        python_executable.to_owned(),
        "-I".to_owned(),
        "-c".to_owned(),
        bootstrap,
    ]
}

/// `str(Path.home())`: `HOME` on POSIX, `USERPROFILE` on Windows.
fn python_home() -> Option<String> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(name).ok().filter(|home| !home.is_empty())
}

#[derive(Debug, PartialEq)]
pub(crate) enum Input {
    Read(Vec<u8>),
    /// The deadline passed or stdin failed: Python's `_emit_failure`.
    Failed,
}

/// A hook the daemon can be asked about: the stamped text and its event.
/// `mapped` when it held a lone surrogate; `collision` when it held a
/// genuine U+F0000..U+F07FF character, which a mapped one would mimic.
#[derive(Debug, PartialEq)]
pub(crate) struct Prepared {
    pub(crate) data: String,
    pub(crate) event_name: String,
    pub(crate) mapped: bool,
    pub(crate) collision: bool,
}

impl Prepared {
    fn failed(&self) -> Route {
        Route::Fail {
            event_name: self.event_name.clone(),
            unmap: self.mapped,
        }
    }

    /// `_daemon_response_to_native` for `answer`, `None` for an answer that
    /// is not an object or whose lone surrogates cannot be told apart.
    fn render(&self, harness: &str, answer: &SurrogateMapped) -> Option<Rendered> {
        let PyVal::Dict(entries) = &answer.value else {
            return None;
        };
        let unmap = self.mapped || answer.mapped;
        if unmap && (self.collision || answer.collision) {
            return None;
        }
        daemon_response_to_native(entries, harness, &self.event_name, unmap)
    }
}

/// `_event_name(text)`, for text that may not parse as an object, and
/// whether a lone surrogate in it is written back as its escape.
fn text_event_name(text: &str) -> (String, bool) {
    match pyjson::parse_mapping_lone_surrogates(text) {
        Ok(parsed) => (
            event_name(text, &parsed.value),
            parsed.mapped && !parsed.collision,
        ),
        Err(_) => (event_name(text, &PyVal::Null), false),
    }
}

/// `read_hook_input`'s decode and `stamp_hook_input_text`, for input the
/// native bridge forwards exactly as Python would; anything else is the
/// `Route::Refuse` Python answers it with.
pub(crate) fn prepare(raw: &[u8]) -> Result<Prepared, Route> {
    let refused = |text: &str, reason| {
        let (event_name, unmap) = text_event_name(text);
        Route::Refuse {
            event_name,
            reason,
            unmap,
        }
    };
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        // `_HookInputError.prefix`: the first bytes, decoded leniently.
        let prefix = String::from_utf8_lossy(&raw[..MAX_HOOK_INPUT_BYTES]);
        return Err(refused(&prefix, OVERSIZE_REASON));
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    // Undecodable input is `_emit_failure(input_text="{}")`.
    let text = std::str::from_utf8(body).map_err(|_| refused("{}", FAILURE_REASON))?;
    // Nesting Python cannot read, or text it cannot round-trip, is refused.
    let Stamp::Text(data) = stamp_hook_input_text(text, &current_environment()) else {
        return Err(refused(text, FAILURE_REASON));
    };
    let Ok(parsed) = pyjson::parse_mapping_lone_surrogates(&data) else {
        return Err(refused(&data, FAILURE_REASON));
    };
    // Every harness sends an object; anything else is refused. The stamp
    // already refused a lone surrogate beside a genuine mapped-range one.
    if parsed.value.as_dict().is_none() || (parsed.mapped && parsed.collision) {
        return Err(refused(&data, FAILURE_REASON));
    }
    let event_name = event_name(&data, &parsed.value);
    Ok(Prepared {
        data,
        event_name,
        mapped: parsed.mapped,
        collision: parsed.collision,
    })
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
    Fail { event_name: String, unmap: bool },
    /// Write Python's fail-closed payload for this event and reason;
    /// `unmap` writes a lone surrogate in the event back as its escape.
    Refuse {
        event_name: String,
        reason: &'static str,
        unmap: bool,
    },
}

/// The daemon path of `run_bounded_cli_hook` after the input was read.
pub(crate) fn route_hook(config: &BridgeConfig, raw: &[u8], deadline: Instant) -> Route {
    let prepared = match prepare(raw) {
        Ok(prepared) => prepared,
        Err(refused) => return refused,
    };
    if Instant::now() >= deadline {
        return prepared.failed();
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
    let failed = match daemon_target(&config.guard_home, &config.harness) {
        None => None,
        Some(target) => {
            // Too little time for a request means the deadline is all but spent.
            let Some(transport) = transport_deadline(deadline, left, budget) else {
                return prepared.failed();
            };
            match post_hook(&target, &config.harness, &prepared.data, transport) {
                Some(answer) => {
                    let rendered = prepared.render(&config.harness, &answer);
                    return answered_route(rendered, &prepared, deadline);
                }
                None => Some(target),
            }
        }
    };
    restarted_route(config, prepared, deadline, budget, failed.as_ref())
}

/// The route once no daemon answered: start one with the configured
/// command and send the hook once to a daemon that came up since. The
/// daemon that `failed` already saw the hook, so it is never sent to again.
fn restarted_route(
    config: &BridgeConfig,
    prepared: Prepared,
    deadline: Instant,
    budget: Duration,
    failed: Option<&DaemonTarget>,
) -> Route {
    // An empty command (no home to start the daemon for) fails closed.
    if config.start_command.is_empty()
        || !start_daemon(&config.start_command, TRANSPORT_FAILURE, deadline)
    {
        return prepared.failed();
    }
    let started = await_daemon(deadline, || {
        match daemon_target(&config.guard_home, &config.harness) {
            Some(target) if failed.is_none_or(|old| !old.same_daemon(&target)) => {
                Attempt::Settled(target)
            }
            _ => Attempt::NotUp,
        }
    });
    let answer = started.and_then(|target| {
        let transport = transport_deadline(deadline, remaining(deadline), budget)?;
        post_hook(&target, &config.harness, &prepared.data, transport)
    });
    let Some(answer) = answer else {
        return prepared.failed();
    };
    let rendered = prepared.render(&config.harness, &answer);
    answered_route(rendered, &prepared, deadline)
}

/// The route for an answer the daemon or its resident gave. An answer the
/// bridge cannot render fails closed: it was recorded, so it is never
/// reviewed again.
fn answered_route(rendered: Option<Rendered>, prepared: &Prepared, deadline: Instant) -> Route {
    match rendered {
        Some(rendered) if Instant::now() < deadline => Route::Respond {
            stdout: rendered.stdout,
            stderr: rendered.stderr,
            exit_code: rendered.exit_code,
        },
        _ => prepared.failed(),
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
        .and_then(|parsed| prepared.render(&config.harness, &parsed));
    Some(answered_route(rendered, prepared, deadline))
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

fn fail(harness: &str, event_name: &str, unmap: bool) -> i32 {
    let (payload, code) = failure_output(harness, event_name, unmap);
    write_stdout(&payload);
    code
}

fn refuse(harness: &str, event_name: &str, reason: &str, unmap: bool) -> i32 {
    let (payload, code) = failure_output_for(harness, event_name, reason, unmap);
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
        return refuse_config(config_argument(python_argv), started);
    };
    let Some(deadline) = started.checked_add(config.timeout) else {
        return fail(&config.harness, DEFAULT_EVENT, false);
    };
    let Input::Read(raw) = read_hook_input(deadline) else {
        return fail(&config.harness, DEFAULT_EVENT, false);
    };
    emit(&config.harness, route_hook(&config, &raw, deadline))
}

/// `main_from_argv` for a config the native bridge does not serve: the
/// `_emit_failure` answer Python gives a config it refuses. Python fails
/// one without a usable timeout before reading the hook, and any other
/// for the event the hook names. No install writes such a config for the
/// native bridge, so the hook fails closed rather than running Python.
fn refuse_config(argument: Option<&str>, started: Instant) -> i32 {
    let payload = argument
        .and_then(|text| pyjson::parse_mapping_lone_surrogates(text).ok())
        .map(|parsed| parsed.value)
        .filter(|value| value.as_dict().is_some());
    let harness = payload
        .as_ref()
        .and_then(|value| value.get("harness")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    let deadline = payload
        .as_ref()
        .and_then(|value| positive_seconds(value.get("timeout_seconds")))
        .and_then(|timeout| started.checked_add(timeout));
    let Some(deadline) = deadline else {
        return fail(&harness, DEFAULT_EVENT, false);
    };
    let Input::Read(raw) = read_hook_input(deadline) else {
        return fail(&harness, DEFAULT_EVENT, false);
    };
    let route = match prepare(&raw) {
        Ok(prepared) => prepared.failed(),
        Err(refused) => refused,
    };
    emit(&harness, route)
}

/// Write the answer for `route` and return its exit code.
fn emit(harness: &str, route: Route) -> i32 {
    match route {
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
        Route::Fail { event_name, unmap } => fail(harness, &event_name, unmap),
        Route::Refuse {
            event_name,
            reason,
            unmap,
        } => refuse(harness, &event_name, reason, unmap),
    }
}

#[cfg(all(test, unix))]
#[path = "bounded_hook_bridge_tests.rs"]
mod tests;
