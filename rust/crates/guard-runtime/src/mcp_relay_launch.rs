//! Child launch for the native MCP relay (`_prepare_launch`/`_start_process`).
//!
//! The scrubbed environment, the runtime launch identity, the verified
//! executable and the post-spawn identity check all come from the same
//! `guard_command` authorities the resident serves to the Python proxy; the
//! relay calls them in-process and launches only the verified executable.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use guard_command::launch_identity::{
    build_runtime_launch_identity, resolved_runtime_launch_executable,
    runtime_launch_identity_matches,
};
use guard_command::mcp_launch_environment::build_launch_environment;
use guard_command::mcp_stdio_session::{LiveMcpSession, QuietEdge, SessionEvent};
use serde_json::Value;

use crate::mcp_relay_args::RelayArgs;
use crate::mcp_relay_core::{ChildEof, ChildLink, Quiet};

const ORIGIN_HARNESS_ENV: &str = "HOL_GUARD_ORIGIN_HARNESS";
const UNVERIFIED: &str = "Guard runtime MCP server executable could not be verified.";
const IDENTITY_CHANGED: &str =
    "Guard runtime MCP server launch identity changed while the child process was starting.";
/// How long a child may take to exit after its input closes.
const EXIT_GRACE: Duration = Duration::from_secs(5);
const EXIT_POLL: Duration = Duration::from_millis(25);

/// A verified launch, ready to spawn.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Launch {
    pub(crate) argv: Vec<String>,
    pub(crate) launch_env: BTreeMap<String, String>,
    pub(crate) child_env: BTreeMap<String, String>,
    pub(crate) identity: Value,
    pub(crate) cwd: PathBuf,
}

/// The process environment as UTF-8 pairs (non-UTF-8 entries are dropped).
pub(crate) fn inherited_environment() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

fn env_value(env: &BTreeMap<String, String>) -> Value {
    Value::Object(
        env.iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    )
}

fn arg_values(args: &RelayArgs) -> Vec<Value> {
    args.args.iter().cloned().map(Value::String).collect()
}

/// `_prepare_launch` plus the executable check of `_start_process`.
pub(crate) fn prepare(
    args: &RelayArgs,
    inherited: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Launch, String> {
    let configured: BTreeMap<String, String> = args
        .server_env_keys
        .iter()
        .filter_map(|key| Some((key.clone(), inherited.get(key)?.clone())))
        .collect();
    let launch_env = build_launch_environment(inherited, &configured);
    let mut child_env = launch_env.clone();
    child_env.insert(ORIGIN_HARNESS_ENV.to_owned(), args.harness.to_owned());
    let identity = build_runtime_launch_identity(
        &Value::String(args.command.clone()),
        &arg_values(args),
        true,
        false,
        launch_env.get("PATH").map(String::as_str),
        Some(cwd),
        None,
        Some(&env_value(&launch_env)),
    );
    let executable = resolved_runtime_launch_executable(&identity)
        .filter(|executable| !executable.is_empty())
        .ok_or_else(|| UNVERIFIED.to_owned())?;
    let mut argv = vec![executable];
    argv.extend(args.args.iter().cloned());
    Ok(Launch {
        argv,
        launch_env,
        child_env,
        identity,
        cwd: cwd.to_path_buf(),
    })
}

/// `_verify_post_spawn_launch_identity`.
fn identity_still_matches(args: &RelayArgs, launch: &Launch) -> bool {
    runtime_launch_identity_matches(
        &launch.identity,
        &Value::String(args.command.clone()),
        &arg_values(args),
        true,
        false,
        launch.launch_env.get("PATH").map(String::as_str),
        Some(&launch.cwd),
        Some(&env_value(&launch.launch_env)),
    )
}

/// Spawn the verified executable and re-check its launch identity.
pub(crate) fn spawn(args: &RelayArgs, launch: &Launch) -> Result<LiveChild, String> {
    let home = launch
        .child_env
        .get("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    let (session, process) = LiveMcpSession::spawn(
        &launch.argv,
        Some(&launch.child_env),
        home.as_deref(),
        Some(&launch.cwd),
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut child = LiveChild { session, process };
    if !identity_still_matches(args, launch) {
        child.quarantine();
        return Err(IDENTITY_CHANGED.to_owned());
    }
    Ok(child)
}

/// The spawned MCP server and its stdio session.
pub(crate) struct LiveChild {
    session: LiveMcpSession,
    process: Child,
}

/// `int(process.returncode or 0)` as the Python CLI's exit status.
/// A Windows process always has an exit code; a signal exists only on unix.
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        status
            .code()
            .unwrap_or_else(|| status.signal().map_or(1, |signal| (256 - signal) & 0xff))
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(1)
    }
}

impl LiveChild {
    /// Close the child's input, give it `EXIT_GRACE` to exit, then stop it.
    /// Returns the relay's exit status.
    pub(crate) fn shutdown(mut self) -> i32 {
        self.session.close_input();
        let deadline = Instant::now() + EXIT_GRACE;
        let status = loop {
            match self.process.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(EXIT_POLL),
                Ok(None) | Err(_) => break None,
            }
        };
        self.session.close(&mut self.process);
        status.map_or(1, exit_code)
    }
}

impl ChildLink for LiveChild {
    fn send(&mut self, message: &Value) -> Result<(), String> {
        self.session.write(message)
    }

    fn next(&mut self, timeout: Duration) -> Result<Option<Value>, ChildEof> {
        self.session
            .next_event(timeout)
            .map(|event| event.map(event_frame))
            .map_err(|_| ChildEof)
    }

    fn next_quiet(&mut self, quiet: Duration) -> Result<Quiet, ChildEof> {
        Ok(
            match self.session.next_event_quiet(quiet).map_err(|_| ChildEof)? {
                QuietEdge::Silent => Quiet::Silent,
                QuietEdge::Event(event) => Quiet::Frame(event_frame(event)),
                QuietEdge::Busy => Quiet::Busy,
            },
        )
    }

    fn quarantine(&mut self) {
        self.session.close(&mut self.process);
    }
}

fn event_frame(event: SessionEvent) -> Value {
    match event {
        SessionEvent::ChildResponse(frame)
        | SessionEvent::ChildRequest(frame)
        | SessionEvent::ChildNotification(frame) => frame,
    }
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_launch_tests.rs"]
mod tests;
