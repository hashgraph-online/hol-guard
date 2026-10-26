//! The direct lane a native MCP relay session depends on.
//!
//! Only the daemon's policy publisher binds the resident's direct lane, and it
//! binds a workspace once a hook (or this relay) asks the daemon to prepare
//! it. A session that started before any hook would otherwise defer, and
//! refuse, every `tools/call`. So before the relay reads the host's input or
//! starts the MCP server it asks the resident whether the lane is ready for
//! its workspace and harness. When it is not, the relay asks the daemon to
//! prepare the workspace through the hook readiness route and waits a short,
//! bounded time. A daemon that is down gets one detached `guard daemon
//! ensure`. A lane that is not ready only because the daemon has not
//! prepared it yet (`warms_up`) keeps the session native: the first
//! `tools/call` waits, within `WARM_UP_BUDGET`, for the daemon to bind it,
//! and a call the lane still cannot decide is refused. Every other reason,
//! including one this module does not know, hands the session to the Python
//! proxy (`hands_off`): the relay execs the exact proxy argv it was given,
//! with its environment unchanged (on Windows it runs the proxy as a child
//! on the same stdio and returns its exit status).
//!
//! The readiness answer only steers which launcher runs. Each call is still
//! admitted by the resident's `mcp_relay_decide`, which repeats every check
//! and refuses what it does not decide, and the binding, its integrity state
//! and its key still come only from the daemon.

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::claude_hook_bridge_auth::{private_file_raw, LOOPBACK_HOSTS};
use crate::claude_hook_bridge_http::{remaining, LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::mcp_relay_args::RelayArgs;
use crate::mcp_relay_servers::SERVER_UNKNOWN;

/// How long a session may wait for the lane before it is handed off.
pub(crate) const STARTUP_BUDGET: Duration = Duration::from_millis(500);
/// How long one deferred call may wait for the daemon before it is retried.
pub(crate) const RETRY_BUDGET: Duration = Duration::from_millis(250);
/// How long the first call of a session that started before its lane was
/// ready waits for the daemon to bind it: past one kick interval, so a
/// daemon the startup kick had to start is asked once more.
pub(crate) const WARM_UP_BUDGET: Duration = Duration::from_secs(8);
/// The daemon is asked at most once per interval within a session.
const KICK_INTERVAL: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Time the startup kick leaves for the probes that follow it.
const PROBE_RESERVE: Duration = Duration::from_millis(100);
const STATE_FILE: &str = "daemon-state.json";
const TOKEN_FILE: &str = "daemon-auth-token";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 4096;
const READINESS_FAILED: &str = "daemon readiness request failed";
const LINE_PREFIX: &str = "hol-guard mcp-relay: ";
/// The daemon could not be reached; one detached ensure was started.
pub(crate) const DAEMON_UNREACHABLE: &str = "mcp_relay_daemon_unreachable";
/// The daemon would not prepare the workspace for this harness.
pub(crate) const DAEMON_REFUSED: &str = "mcp_relay_daemon_refused";

/// What asking the daemon to prepare the workspace did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kick {
    /// The daemon took the readiness request; it may still be preparing.
    Requested,
    /// The daemon could not be reached.
    DaemonUnreachable,
    /// The daemon answered that it will not prepare the workspace.
    Refused,
    /// The daemon was not asked: the kick interval has not passed, or no
    /// time was left before the deadline.
    Skipped,
}

/// Asks the daemon to bind the lane for the session's workspace.
pub(crate) trait LaneKick {
    fn kick(&mut self, deadline: Instant) -> Kick;
}

/// The reasons the daemon can clear by preparing the workspace: a lane it
/// has not bound yet, and a resident it has not started yet.
pub(crate) fn kickable(code: &str) -> bool {
    (code.starts_with("direct_lane_") && code != "direct_lane_unsupported")
        || matches!(
            code,
            "mcp_relay_harness_unbound"
                | "mcp_relay_view_missing"
                | "mcp_relay_resident_unreachable"
        )
}

/// The reasons a session stays native while its lane is not ready: the
/// ones the daemon clears by preparing the workspace, a daemon that is still
/// starting, and a server the resident has no catalog report of yet, which
/// the session reports itself (`mcp_relay_servers.rs`).
pub(crate) fn warms_up(code: &str) -> bool {
    kickable(code) || matches!(code, DAEMON_UNREACHABLE | SERVER_UNKNOWN)
}

/// The reasons the native lane cannot serve a session however long it
/// waits, so it runs as the Python proxy: features the relay has not ported
/// (`mcp_relay_session_review_mode`, `mcp_relay_saved_remote_policy`,
/// `mcp_relay_session_server_proxy_tools`, ...), a binding or store the
/// resident cannot use as it is (`mcp_relay_evidence_undrained`,
/// `mcp_relay_binding_incomplete`, `mcp_relay_store_unreadable`, ...), a
/// superseded runtime, an answer the relay cannot read, and a daemon that
/// will not prepare the native lane. A reason not named by `warms_up` hands
/// off, so a new readiness code never leaves a session waiting on a kick
/// that cannot clear it.
pub(crate) fn hands_off(code: &str) -> bool {
    !warms_up(code)
}

/// How the session starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gate {
    /// The lane was ready; `kicked` when the daemon had to prepare it first.
    Relay { kicked: bool, elapsed: Duration },
    /// The lane was not ready, for the named reason.
    NotReady(String),
}

/// Ask `ready` until the lane is ready or `budget` is spent, asking the
/// daemon to prepare the workspace once when the lane is not ready yet.
pub(crate) fn startup(
    ready: &mut dyn FnMut(Instant) -> Result<(), String>,
    kick: &mut dyn LaneKick,
    budget: Duration,
) -> Gate {
    let started = Instant::now();
    let deadline = started + budget;
    let mut code = match ready(deadline) {
        Ok(()) => {
            return Gate::Relay {
                kicked: false,
                elapsed: started.elapsed(),
            }
        }
        Err(code) => code,
    };
    if !kickable(&code) {
        return Gate::NotReady(code);
    }
    let kick_deadline = deadline
        .checked_sub(PROBE_RESERVE)
        .map_or(started, |kick_deadline| kick_deadline.max(started));
    let kicked = match kick.kick(kick_deadline) {
        Kick::Requested => true,
        // A daemon that was not asked may still bind the lane by itself.
        Kick::Skipped => false,
        Kick::DaemonUnreachable => return Gate::NotReady(DAEMON_UNREACHABLE.to_owned()),
        Kick::Refused => return Gate::NotReady(DAEMON_REFUSED.to_owned()),
    };
    loop {
        match ready(deadline) {
            Ok(()) => {
                return Gate::Relay {
                    kicked,
                    elapsed: started.elapsed(),
                }
            }
            Err(next) if kickable(&next) => code = next,
            Err(next) => return Gate::NotReady(next),
        }
        let left = remaining(deadline);
        if left.is_zero() {
            return Gate::NotReady(code);
        }
        std::thread::sleep(left.min(POLL_INTERVAL));
    }
}

/// The stderr line naming how the session started.
pub(crate) fn gate_line(gate: &Gate) -> String {
    match gate {
        Gate::Relay { kicked, elapsed } => format!(
            "{LINE_PREFIX}lane ready: {} {} ms\n",
            if *kicked { "kicked" } else { "start" },
            elapsed.as_millis()
        ),
        Gate::NotReady(code) if hands_off(code) => format!("{LINE_PREFIX}python proxy: {code}\n"),
        Gate::NotReady(code) => format!("{LINE_PREFIX}lane not ready: {code}\n"),
    }
}

/// Name how the session started; a closed stderr never affects it.
pub(crate) fn note(gate: &Gate) {
    let _ = std::io::stderr().write_all(gate_line(gate).as_bytes());
}

/// Replace this process with the Python proxy it was launched for. Runs
/// before any stdin byte is read and before the MCP server is started, so
/// the proxy gets the host's untouched stdio, argv and environment. Returns
/// only when the exec failed.
#[cfg(unix)]
pub(crate) fn hand_off(python_argv: &[String]) -> i32 {
    let Some((program, args)) = python_argv.split_first() else {
        return 2;
    };
    let error = Command::new(program).args(args).exec();
    eprintln!("{LINE_PREFIX}python proxy launch failed: {error}");
    1
}

/// Windows has no exec: run the Python proxy on the inherited stdio, argv
/// and environment and return its exit status. The proxy joins a
/// kill-on-close JobObject, so it cannot outlive this process.
#[cfg(windows)]
pub(crate) fn hand_off(python_argv: &[String]) -> i32 {
    let Some((program, args)) = python_argv.split_first() else {
        return 2;
    };
    let spawned = Command::new(program)
        .args(args)
        .creation_flags(guard_runtime_windows_process::CHILD_TREE_CREATION_FLAGS)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            eprintln!("{LINE_PREFIX}python proxy launch failed: {error}");
            return 1;
        }
    };
    let tree = match guard_runtime_windows_process::ChildTree::adopt_suspended(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("{LINE_PREFIX}python proxy launch failed: {error}");
            return 1;
        }
    };
    let status = child.wait();
    drop(tree);
    match status {
        Ok(status) => crate::mcp_relay_launch::exit_code(status),
        Err(error) => {
            eprintln!("{LINE_PREFIX}python proxy wait failed: {error}");
            1
        }
    }
}

/// The daemon the session's Guard home names, with its token.
struct Daemon {
    host: String,
    port: u16,
    token: String,
}

/// Asks the session's daemon to prepare its workspace.
pub(crate) struct DaemonKick {
    guard_home: PathBuf,
    workspace: String,
    readiness_path: String,
    /// `<python> ... guard daemon ensure ...`, when the argv names the proxy.
    ensure: Option<Vec<String>>,
    last: Option<Instant>,
}

impl DaemonKick {
    pub(crate) fn new(args: &RelayArgs, python_argv: &[String], workspace: &Path) -> Self {
        Self {
            guard_home: args.guard_home.clone(),
            workspace: workspace.to_string_lossy().into_owned(),
            readiness_path: format!("/v1/hooks/{}/readiness", args.harness),
            ensure: ensure_argv(args, python_argv),
            last: None,
        }
    }

    fn daemon(&self) -> Option<Daemon> {
        let state = read_private(&self.guard_home.join(STATE_FILE), MAX_STATE_BYTES)?;
        let token = read_private(&self.guard_home.join(TOKEN_FILE), MAX_TOKEN_BYTES)?;
        let state: Value = serde_json::from_str(&state).ok()?;
        let host = state.get("host")?.as_str()?;
        if !LOOPBACK_HOSTS.contains(&host) {
            return None;
        }
        let port = u16::try_from(state.get("port")?.as_u64()?)
            .ok()
            .filter(|port| *port >= 1)?;
        let token = token.trim();
        let sendable = token
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
        (!token.is_empty() && sendable).then(|| Daemon {
            host: host.to_owned(),
            port,
            token: token.to_owned(),
        })
    }

    /// POST the hook readiness route: `None` when the daemon could not be
    /// reached, else whether it took the request. A daemon that is still
    /// preparing when the deadline passes keeps going after the relay stops
    /// waiting, so a request that times out still counts as taken.
    fn request(&self, daemon: &Daemon, deadline: Instant) -> Option<bool> {
        let rendered = if daemon.host == "::1" {
            "[::1]"
        } else {
            daemon.host.as_str()
        };
        let url = format!("http://{rendered}:{}{}", daemon.port, self.readiness_path);
        if assert_loopback_http_url(&url).is_err() || !listening(daemon, deadline) {
            return None;
        }
        let Ok(body) = serde_json::to_vec(&json!({"workspace": self.workspace})) else {
            return Some(false);
        };
        let headers = [
            ("X-Guard-Token", daemon.token.as_str()),
            ("Content-Type", "application/json"),
            ("Connection", "close"),
        ];
        let mut connection = LoopbackConnection::new(&daemon.host, daemon.port);
        let Ok(head) = connection.post(&self.readiness_path, &headers, &body, deadline) else {
            return Some(true);
        };
        if head.status != 200 {
            return Some(head.status == 503);
        }
        let raw = connection
            .read_body(&head, deadline, READINESS_FAILED, READINESS_FAILED)
            .ok();
        Some(raw.is_none_or(|raw| {
            raw.len() <= MAX_DAEMON_RESPONSE_BYTES
                && serde_json::from_slice::<Value>(&raw)
                    .ok()
                    .and_then(|answer| answer.get("native_required").and_then(Value::as_bool))
                    != Some(false)
        }))
    }

    /// Start `guard daemon ensure` detached; the session never waits on it.
    #[cfg(unix)]
    fn spawn_ensure(&mut self) {
        let Some(argv) = self.ensure.take() else {
            return;
        };
        // `sh` backgrounds the ensure and exits at once, so it is reparented
        // instead of staying a child of the proxy this process may become.
        let spawned = Command::new("/bin/sh")
            .arg("-c")
            .arg("\"$@\" </dev/null >/dev/null 2>&1 &")
            .arg("sh")
            .args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
        if let Ok(mut shell) = spawned {
            let _ = shell.wait();
        }
    }

    /// Start `guard daemon ensure` detached, in its own process group and,
    /// where the job allows it, outside the relay's job, as the Python daemon
    /// launcher does; the session never waits on it.
    #[cfg(windows)]
    fn spawn_ensure(&mut self) {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        let Some((program, args)) = self.ensure.take().and_then(|argv| {
            let (program, args) = argv.split_first()?;
            Some((program.clone(), args.to_vec()))
        }) else {
            return;
        };
        let detached = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        for flags in [detached | CREATE_BREAKAWAY_FROM_JOB, detached] {
            let spawned = Command::new(&program)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(flags)
                .spawn();
            if spawned.is_ok() {
                return;
            }
        }
    }
}

impl LaneKick for DaemonKick {
    fn kick(&mut self, deadline: Instant) -> Kick {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < KICK_INTERVAL)
        {
            return Kick::Skipped;
        }
        if remaining(deadline).is_zero() {
            return Kick::Skipped;
        }
        self.last = Some(now);
        let answered = self
            .daemon()
            .and_then(|daemon| self.request(&daemon, deadline));
        match answered {
            Some(true) => Kick::Requested,
            Some(false) => Kick::Refused,
            None => {
                self.spawn_ensure();
                Kick::DaemonUnreachable
            }
        }
    }
}

/// `<python> <args up to guard> daemon ensure --guard-home .. [--home ..]`.
fn ensure_argv(args: &RelayArgs, python_argv: &[String]) -> Option<Vec<String>> {
    let proxy = format!("{}-mcp-proxy", args.harness);
    let guard = python_argv
        .windows(2)
        .position(|pair| pair[0] == "guard" && pair[1] == proxy)?;
    let mut argv = python_argv[..=guard].to_vec();
    argv.extend(["daemon", "ensure", "--guard-home"].map(str::to_owned));
    argv.push(args.guard_home.to_string_lossy().into_owned());
    if let Some(home) = &args.home {
        argv.push("--home".to_owned());
        argv.push(home.to_string_lossy().into_owned());
    }
    Some(argv)
}

/// Whether the daemon accepts connections at all: a refused connect is a
/// daemon that is down, which a timed-out request is not.
fn listening(daemon: &Daemon, deadline: Instant) -> bool {
    let Ok(addresses) = (daemon.host.as_str(), daemon.port).to_socket_addrs() else {
        return false;
    };
    addresses
        .filter(|address| address.ip().is_loopback())
        .any(|address| {
            let left = remaining(deadline);
            !left.is_zero() && TcpStream::connect_timeout(&address, left).is_ok()
        })
}

/// An owner-only private file no larger than `max` bytes.
fn read_private(path: &Path, max: u64) -> Option<String> {
    if std::fs::symlink_metadata(path).ok()?.len() > max {
        return None;
    }
    private_file_raw(path, "Guard file").ok()
}

#[cfg(test)]
#[path = "mcp_relay_lane_tests.rs"]
mod tests;
