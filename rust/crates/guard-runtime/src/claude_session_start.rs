//! Native Claude Code SessionStart hook (`claude-session-start-v1`).
//!
//! The Python SessionStart hook (`_run_session_start_from_argv` in
//! `claude_hook_entry.py`) starts the Guard daemon when it is down,
//! rewrites the managed hook entries in `~/.claude/settings.json` inside the
//! owned installation transaction, and prints the SessionStart context. On
//! most session starts the daemon is already live and the entries are
//! already current, so that work is a no-op that still costs an interpreter
//! start, an installation lock and a settings write.
//!
//! This lane answers that no-op case, and the common daemon-down case after
//! a reboot or a crash. It requires every one of these, in process:
//! - the installer's config parses, it was written for this runtime build,
//!   and the session environment matches the one the installer described
//!   (same home; the bridge, not the settings, says whether Cursor runs it);
//! - the Guard entries of the settings file already equal what the Python
//!   refresh would write, per `claude_session_start_contract`;
//! - the daemon is verified live by `claude_session_start_live`: the
//!   authenticated state of a daemon of this package version on
//!   `127.0.0.1`, the bound auth token, the live-state gate, a signed
//!   identity challenge, a current `/healthz` and an unchanged generation.
//!
//! Only then does it print the context. When the daemon is not live but is
//! provably down (`stopped_daemon_url`: the authenticated state of a daemon
//! of this package version on `127.0.0.1` whose pid no longer runs), and
//! the entries are current for that daemon's URL, the lane runs the bridge's
//! own `recovery_command` once, the same start a hook bridge runs when its
//! daemon is unreachable, and prints the context when it exits zero. That
//! command only schedules the start; the first tool hook's bridge waits for
//! the daemon as it always does. A daemon restarted on another port is
//! drift at the next session start, which hands off and rewrites the URL.
//!
//! Any other failure, including a parse error, a pid that still runs but
//! does not answer, or a start that fails, hands off to the installer's
//! Python SessionStart command (same argv, same environment, and the event
//! this lane read from stdin written to its stdin), so the Python transaction
//! runs exactly as before inside the same hook timeout. It runs as a child
//! that this lane exits with; with no event read, Unix replaces this process
//! and Windows runs the child on the same stdio. This lane never writes settings, never reads or
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
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::claude_hook_bridge::home_directory;
use crate::claude_session_start_contract::{contract, settings_current, DaemonHookTemplate};
use crate::claude_session_start_live::{stopped_daemon_url, verified_daemon_url};
use crate::hook_bridge_daemon_start::{start_daemon, TRANSPORT_FAILURE};
use crate::hook_bridge_fallback::{self, Fallback};
use crate::hook_env_stamp::json_string;

/// argv mode and marker that select this lane, after `claude-hook-bridge`.
pub(crate) const SESSION_START_MODE: &str = "session-start";
pub(crate) const SESSION_START_MARKER: &str = "HOL_GUARD_CLAUDE_SESSION_START_HOOK";
pub(crate) const SESSION_START_FEATURE: &str = "claude-session-start-v1";

/// Budget for every check, leaving the Python fallback most of the
/// 10 second hook timeout.
const CHECK_BUDGET: Duration = Duration::from_secs(2);
/// Budget for the checks and a daemon start together; the start keeps its
/// own one second retry reserve, so a failed start still leaves the Python
/// fallback four seconds of the hook timeout.
const START_BUDGET: Duration = Duration::from_secs(6);
const MAX_SETTINGS_BYTES: u64 = 4 * 1024 * 1024;
const INVALID_CONFIG: &str = "claude session start configuration is invalid";
/// The resident's state base under the Guard home, as the Python client
/// derives it (`native_resident_client._client_pool_for`).
const RESIDENT_STATE_DIRECTORY: &str = "native-runtime";
/// The lane's own argv for the detached prewarm.
const PREWARM_MODE: &str = "resident-prewarm";

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
}

impl SessionEnvironment {
    fn current() -> Self {
        Self {
            home: home_directory(),
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

/// The bridge's daemon-start command, as the hook bridges run it.
fn recovery_command(bridge_config: &Map<String, Value>) -> Option<Vec<String>> {
    strings(bridge_config.get("recovery_command")).filter(|argv| !argv.is_empty())
}

/// The context to print when every check passes, or why one failed.
/// `start` runs the recovery command for a daemon that is provably down;
/// `true` means it scheduled the start.
pub(crate) fn session_output(
    config_text: &str,
    environment: &SessionEnvironment,
    deadline: Instant,
    start: impl FnOnce(&[String]) -> bool,
) -> Result<String, String> {
    let config = parse_config(config_text).ok_or(INVALID_CONFIG)?;
    if config.runtime_build != runtime_build() {
        return Err("hook entries were described by another runtime build".to_owned());
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
    let state_path = Path::new(state_path);
    let (daemon_url, stopped) =
        match verified_daemon_url(state_path, &contract.session_start_event, deadline) {
            Ok(url) => (url, false),
            Err(error) => (stopped_daemon_url(state_path).map_err(|_| error)?, true),
        };
    if !settings_current(&contract, &settings, &config.daemon_hook, &daemon_url) {
        return Err("managed hook entries differ from the contract".to_owned());
    }
    if stopped {
        let command = recovery_command(&config.daemon_hook.bridge_config).ok_or(INVALID_CONFIG)?;
        if !start(&command) {
            return Err("daemon start failed".to_owned());
        }
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

/// Hand off to the Python SessionStart command with the event this lane read
/// on its stdin, the late reader's bytes once a slow caller closes stdin, or,
/// with neither, this process's stdin.
fn hand_off(argv: &[String], event: &[u8], late: Option<LateEvent>) -> i32 {
    if event.is_empty() && late.is_none() {
        return replace(argv);
    }
    let mut command = fallback_process(argv);
    command.stdin(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "claude session start fallback could not start: {error}"
            );
            return 1;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let event = event.to_vec();
        std::thread::spawn(move || {
            if let Ok(Ok(event)) = late.map_or(Ok(Ok(event)), |late| late.recv()) {
                let _ = stdin.write_all(&event);
            }
        });
    }
    child
        .wait()
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(1)
}

/// Replace this process with the Python SessionStart command.
#[cfg(unix)]
fn replace(argv: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    let error = fallback_process(argv).exec();
    let _ = writeln!(
        io::stderr(),
        "claude session start fallback could not start: {error}"
    );
    1
}

/// Windows has no `exec`: run the Python SessionStart command with this
/// process's stdin, stdout and stderr, and exit with its status.
#[cfg(not(unix))]
fn replace(argv: &[String]) -> i32 {
    match fallback_process(argv).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "claude session start fallback could not start: {error}"
            );
            1
        }
    }
}

/// Run the lane; the exit status when this process is not replaced.
/// Start this runtime's resident off to the side, so the session's first
/// tool hook finds it up instead of paying for the start, and ask it to wake
/// a resting CIGAR worker, so the first prompt gets project context.
///
/// The child is this same runtime (`resident-prewarm`), detached into its
/// own process group with no stdio, and never waited for: the lane's own
/// answer, its budget and its hand-off are exactly what they were without
/// it. A resident another client already holds, a runtime whose restart
/// budget is paused, and a spawn that fails all end the same way, silently.
fn prewarm_resident(config_text: &str, restarted: Option<&str>) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(mut command) = prewarm_command(config_text, &executable, restarted) else {
        return;
    };
    let _ = command.spawn();
}

/// The detached prewarm for this session's Guard home, or `None` when the
/// configuration names no home to warm. `restarted` names a session Claude
/// Code just compacted or cleared, so the resident forgets which code it
/// already showed that session.
fn prewarm_command(
    config_text: &str,
    executable: &Path,
    restarted: Option<&str>,
) -> Option<Command> {
    let state_directory = guard_home(config_text)?.join(RESIDENT_STATE_DIRECTORY);
    let mut command = Command::new(executable);
    command
        .arg(PREWARM_MODE)
        .arg("--state-dir")
        .arg(state_directory);
    if let Some(session) = restarted {
        command.arg(RESTARTED_SESSION_FLAG).arg(session);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The hold outlives this hook, so the prewarm must not be in the hook's
    // process group: the harness may end that group when the hook returns.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    Some(command)
}

/// The prewarm argument that carries a restarted session's id.
pub(crate) const RESTARTED_SESSION_FLAG: &str = "--restarted-session";
/// Claude Code's SessionStart event is a few hundred bytes.
const EVENT_LIMIT: u64 = 64 * 1024;
/// Claude Code writes the event and closes stdin before it waits on the
/// hook; a caller that leaves stdin open costs the hook no more than this.
const EVENT_WAIT: Duration = Duration::from_millis(200);

/// The reader of an event that took longer than `EVENT_WAIT`.
type LateEvent = std::sync::mpsc::Receiver<io::Result<Vec<u8>>>;

/// The SessionStart event on stdin, or nothing when stdin is a terminal or
/// unreadable; past `EVENT_WAIT`, nothing plus the reader still holding it.
fn read_event() -> (Vec<u8>, Option<LateEvent>) {
    use std::io::{IsTerminal, Read};
    if io::stdin().is_terminal() {
        return (Vec::new(), None);
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut event = Vec::new();
        let read = io::stdin().take(EVENT_LIMIT).read_to_end(&mut event);
        let _ = sender.send(read.map(|_| event));
    });
    match receiver.recv_timeout(EVENT_WAIT) {
        Ok(read) => (read.unwrap_or_default(), None),
        Err(_) => (Vec::new(), Some(receiver)),
    }
}

/// The id of a session Claude Code compacted or cleared, from its
/// SessionStart event. The agent no longer holds what the session was shown,
/// so CIGAR must send that code again. A resumed or new session gives none.
pub(crate) fn restarted_session(event: &[u8]) -> Option<String> {
    let event: Value = serde_json::from_slice(event).ok()?;
    if !matches!(
        event.get("source").and_then(Value::as_str),
        Some("compact" | "clear")
    ) {
        return None;
    }
    let id = event.get("session_id")?.as_str()?.trim();
    (!id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_graphic()))
        .then(|| id.to_owned())
}

pub(crate) fn run(config_text: &str) -> i32 {
    let started = Instant::now();
    let deadline = started + CHECK_BUDGET;
    let Some(fallback) = fallback_command(config_text) else {
        let _ = writeln!(io::stderr(), "{INVALID_CONFIG}");
        return 2;
    };
    // Before the checks, so a session that hands off to Python warms too.
    // The hand-off passes the event on to the Python command.
    let (event, late) = read_event();
    prewarm_resident(config_text, restarted_session(&event).as_deref());
    let home = guard_home(config_text);
    let start = |command: &[String]| {
        start_daemon(
            command,
            TRANSPORT_FAILURE,
            started + START_BUDGET,
            home.as_deref(),
        )
    };
    match session_output(config_text, &SessionEnvironment::current(), deadline, start) {
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
            if let Some(home) = &home {
                hook_bridge_fallback::note(home, "claude-code", Fallback::ContractDrift);
            }
            hand_off(&fallback, &event, late)
        }
    }
}

#[cfg(all(test, unix))]
#[path = "claude_session_start_tests.rs"]
mod tests;
