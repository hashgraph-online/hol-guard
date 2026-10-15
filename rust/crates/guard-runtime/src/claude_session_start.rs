//! Native Claude Code SessionStart hook (`claude-session-start-v1`).
//!
//! The Python SessionStart hook (`run_session_start_from_argv` in
//! `adapters/claude_hook_argv.py`) starts the Guard daemon when it is down,
//! rewrites the managed hook entries in `~/.claude/settings.json` inside the
//! owned installation transaction, and prints the SessionStart context. On
//! most session starts the daemon is already live and the entries are
//! already current, so that work is a no-op that still costs an interpreter
//! start, an installation lock and a settings write.
//!
//! This lane answers only that no-op case, read-only. It requires every one
//! of these, in process:
//! - the installer's config parses, it was written for this runtime build,
//!   and the session environment matches the one the installer described
//!   (same home, not running inside Cursor);
//! - the Guard entries of the settings file already equal what the Python
//!   refresh would write, per `claude_session_start_contract`;
//! - the daemon is verified live by `claude_session_start_live`: the
//!   authenticated state of a daemon of this package version on
//!   `127.0.0.1`, the bound auth token, the live-state gate, a signed
//!   identity challenge, a current `/healthz` and an unchanged generation.
//!
//! Only then does it print the context. Any failure, including a parse
//! error, replaces this process with the installer's Python SessionStart
//! command (same argv, same environment, same stdin), so the Python
//! transaction runs exactly as before inside the same hook timeout. This
//! lane never starts the daemon, never writes settings, never reads or
//! writes the installation journal, and never mints the auth token.
//!
//! The config pins the runtime build (`PACKAGE_VERSION+BUILD_SHA`) that
//! described the hook entries. After a Guard upgrade the bundled runtime
//! differs, so every session start hands off and the Python refresh rewrites
//! the entries the new version wants, exactly as before this lane existed.
//!
//! A daemon left running from another package version is never accepted,
//! so the Python hook restarts it.
//!
//! Known gap, same-version tree changes only: the daemon's runtime tree
//! signature is not checked here. A developer editable install where only
//! Python files changed (so the package version and runtime build are
//! unchanged) keeps the running daemon and the installed hook entries until
//! a session start hands off to Python.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::claude_hook_bridge::home_directory;
use crate::claude_hook_bridge_render::py_strip;
use crate::claude_session_start_contract::{contract, settings_current, DaemonHookTemplate};
use crate::claude_session_start_live::verified_daemon_url;
use crate::hook_bridge_fallback::{self, Fallback};
use crate::hook_env_stamp::json_string;

/// argv mode and marker that select this lane, after `claude-hook-bridge`.
pub(crate) const SESSION_START_MODE: &str = "session-start";
pub(crate) const SESSION_START_MARKER: &str = "HOL_GUARD_CLAUDE_SESSION_START_HOOK";
pub(crate) const SESSION_START_FEATURE: &str = "claude-session-start-v1";

/// Budget for every check, leaving the Python fallback most of the
/// 10 second hook timeout.
const CHECK_BUDGET: Duration = Duration::from_secs(2);
const MAX_SETTINGS_BYTES: u64 = 4 * 1024 * 1024;
const CURSOR_ENV_MARKERS: [&str; 5] = [
    "CURSOR_VERSION",
    "CURSOR_PROJECT_DIR",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
];
const INVALID_CONFIG: &str = "claude session start configuration is invalid";

/// The installer's JSON config.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SessionStartConfig {
    /// The Python SessionStart command this lane hands off to.
    pub(crate) fallback_command: Vec<String>,
    /// `str(Path.home())` when the installer wrote this command.
    pub(crate) home: String,
    /// The runtime build that described the hook entries.
    pub(crate) runtime_build: String,
    /// The Claude home whose settings the Python refresh rewrites.
    pub(crate) home_dir: String,
    /// The daemon hook the Python refresh writes, less the live URL.
    pub(crate) daemon_hook: DaemonHookTemplate,
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn object(text: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str(text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The fallback command alone, so a config that fails later checks still
/// hands off to Python.
pub(crate) fn fallback_command(text: &str) -> Option<Vec<String>> {
    strings(object(text)?.get("fallback_command")).filter(|argv| !argv.is_empty())
}

/// The Guard home holding the bridge's absolute state path, for the
/// fallback log.
fn guard_home(text: &str) -> Option<PathBuf> {
    let payload = object(text)?;
    let state_path = Path::new(payload.get("bridge_config")?.get("state_path")?.as_str()?);
    state_path
        .is_absolute()
        .then(|| state_path.parent().map(Path::to_path_buf))
        .flatten()
}

pub(crate) fn parse_config(text: &str) -> Option<SessionStartConfig> {
    let payload = object(text)?;
    let field = |key: &str| payload.get(key)?.as_str().map(str::to_owned);
    let command = strings(payload.get("daemon_hook_command")).filter(|argv| !argv.is_empty())?;
    let bridge_config = payload.get("bridge_config")?.as_object()?.clone();
    Some(SessionStartConfig {
        fallback_command: fallback_command(text)?,
        home: field("home").filter(|home| !home.is_empty())?,
        runtime_build: field("runtime_build").filter(|build| !build.is_empty())?,
        home_dir: field("home_dir").filter(|home| !home.is_empty())?,
        daemon_hook: DaemonHookTemplate {
            command,
            bridge_config,
        },
    })
}

/// `PACKAGE_VERSION+BUILD_SHA` of this binary, as the installer records it
/// from the runtime's capabilities.
pub(crate) fn runtime_build() -> String {
    format!("{}+{}", crate::PACKAGE_VERSION, crate::BUILD_SHA)
}

/// What the session's environment says about the Python refresh.
#[derive(Debug)]
pub(crate) struct SessionEnvironment {
    /// The session's `Path.home()`.
    pub(crate) home: Option<PathBuf>,
    /// `cursor_runtime_detected()`: the Python refresh adds Cursor
    /// attribution to the hook query, which this lane does not reproduce.
    pub(crate) cursor: bool,
}

impl SessionEnvironment {
    fn current() -> Self {
        Self {
            home: home_directory(),
            cursor: CURSOR_ENV_MARKERS.iter().any(|key| {
                std::env::var_os(key)
                    .is_some_and(|value| !py_strip(&value.to_string_lossy()).is_empty())
            }),
        }
    }
}

/// The session's `Path.home()` is the installer's, and it resolves to the
/// Claude home, so the Python refresh would omit `--home` and `home=`.
fn home_matches(config: &SessionStartConfig, home: Option<&Path>) -> bool {
    let Some(home) = home else {
        return false;
    };
    if home.to_str() != Some(config.home.as_str()) {
        return false;
    }
    match (fs::canonicalize(home), fs::canonicalize(&config.home_dir)) {
        (Ok(home), Ok(home_dir)) => home == home_dir,
        _ => false,
    }
}

/// The settings document, read only when it stays inside the Claude home.
fn read_settings(home_dir: &Path, relative: &str) -> Result<Value, String> {
    let path: PathBuf = home_dir.join(relative);
    let resolved = fs::canonicalize(&path).map_err(|_| "settings are unavailable")?;
    let root = fs::canonicalize(home_dir).map_err(|_| "Claude home is unavailable")?;
    if !resolved.starts_with(&root) {
        return Err("settings resolve outside the Claude home".to_owned());
    }
    let metadata = fs::metadata(&resolved).map_err(|_| "settings are unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_SETTINGS_BYTES {
        return Err("settings are not a bounded regular file".to_owned());
    }
    let bytes = fs::read(&resolved).map_err(|_| "settings are unreadable")?;
    serde_json::from_slice(&bytes).map_err(|_| "settings are not JSON".to_owned())
}

/// `{"hookSpecificOutput":{...}}` exactly as the Python hook prints it.
pub(crate) fn context_output(event: &str, context: &str) -> String {
    format!(
        "{{\"hookSpecificOutput\":{{\"hookEventName\":{},\"additionalContext\":{}}}}}\n",
        json_string(event, true, false),
        json_string(context, true, false),
    )
}

/// The context to print when every check passes, or why one failed.
pub(crate) fn no_op_output(
    config_text: &str,
    environment: &SessionEnvironment,
    deadline: Instant,
) -> Result<String, String> {
    let config = parse_config(config_text).ok_or(INVALID_CONFIG)?;
    if config.runtime_build != runtime_build() {
        return Err("hook entries were described by another runtime build".to_owned());
    }
    if environment.cursor {
        return Err("Cursor attribution needs the Python refresh".to_owned());
    }
    if !home_matches(&config, environment.home.as_deref()) {
        return Err("session home differs from the installed home".to_owned());
    }
    let contract = contract()?;
    let settings = read_settings(Path::new(&config.home_dir), &contract.settings_path)?;
    let state_path = config
        .daemon_hook
        .bridge_config
        .get("state_path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or(INVALID_CONFIG)?;
    let daemon_url = verified_daemon_url(
        Path::new(state_path),
        &contract.session_start_event,
        deadline,
    )?;
    if !settings_current(&contract, &settings, &config.daemon_hook, &daemon_url) {
        return Err("managed hook entries differ from the contract".to_owned());
    }
    Ok(context_output(
        &contract.session_start_event,
        &contract.session_start_context,
    ))
}

/// The Python SessionStart command, inheriting argv order, environment,
/// stdin, stdout and stderr.
pub(crate) fn fallback_process(argv: &[String]) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command
}

/// Replace this process with the Python SessionStart command.
fn hand_off(argv: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    let error = fallback_process(argv).exec();
    let _ = writeln!(
        io::stderr(),
        "claude session start fallback could not start: {error}"
    );
    1
}

/// Run the lane; the exit status when this process is not replaced.
pub(crate) fn run(config_text: &str) -> i32 {
    let deadline = Instant::now() + CHECK_BUDGET;
    let Some(fallback) = fallback_command(config_text) else {
        let _ = writeln!(io::stderr(), "{INVALID_CONFIG}");
        return 2;
    };
    match no_op_output(config_text, &SessionEnvironment::current(), deadline) {
        Ok(output) => {
            let mut stdout = io::stdout().lock();
            match stdout
                .write_all(output.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
        Err(_) => {
            if let Some(home) = guard_home(config_text) {
                hook_bridge_fallback::note(&home, "claude-code", Fallback::ContractDrift);
            }
            hand_off(&fallback)
        }
    }
}

#[cfg(test)]
#[path = "claude_session_start_tests.rs"]
mod tests;
