//! Processes the contained-workspace sink starts: the sandboxed command, the
//! launcher that limits it, and the bounded host Git calls around it.
//!
//! The sandboxed command runs in its own session under `sandbox-exec`, with
//! its output captured to private files that are replayed once it exits, as
//! `guard execute-contained-test` did. An interrupt or termination the sink
//! receives goes to the command's process group; with no command running the
//! sink removes its scratch directory and any overlay layers a Linux run had
//! already made, then exits as the signal would have.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::signal::{kill, killpg, SigSet, Signal};
use nix::unistd::Pid;

use super::denial::{denial_note, loopback_denied};
use super::output::Shaping;
use super::{envelope, Failure, Outcome, LAUNCH_COMMAND, SANDBOX_UNAVAILABLE};

const CEILING_BUDGET: Duration = Duration::from_secs(5);
/// The launcher's `CEILING` for a host step, which runs without limits.
pub(super) const HOST_STEP: &str = "host";
/// The word in front of a Node run's argv: the launcher bounds its writable
/// memory instead of its whole address space (`limits`).
pub(super) const NODE_MEMORY: &str = "node-memory";
/// Lowers the process ceiling the launcher passes as `$1`, then runs the
/// rest: Apple targets expose `RLIMIT_NPROC` only through the shell.
#[cfg(target_vendor = "apple")]
const PROCESS_LIMIT_SCRIPT: &str = concat!(
    "c=$1; shift; ",
    "s=$(ulimit -S -u); if [ \"$s\" = unlimited ] || [ \"$s\" -gt \"$c\" ]; then ulimit -S -u \"$c\"; fi 2>/dev/null; ",
    "h=$(ulimit -H -u); if [ \"$h\" = unlimited ] || [ \"$h\" -gt \"$c\" ]; then ulimit -H -u \"$c\"; fi 2>/dev/null; ",
    "exec \"$@\""
);

#[derive(Default)]
struct Running {
    child: Option<i32>,
    scratch: Vec<PathBuf>,
    overlay: Option<PathBuf>,
}

/// Interrupts and terminations, held for the sink and forwarded to the
/// running command.
pub(super) struct Signals {
    running: Arc<Mutex<Running>>,
    /// The redirections of the wrapper being run.
    pub(super) output: Shaping,
}

impl Signals {
    /// Block `SIGINT` and `SIGTERM` in this thread, and so in every thread it
    /// starts, then wait for them on a thread of their own.
    pub(super) fn install() -> Self {
        let running = Arc::new(Mutex::new(Running::default()));
        let mut set = SigSet::empty();
        set.add(Signal::SIGINT);
        set.add(Signal::SIGTERM);
        if set.thread_block().is_ok() {
            let shared = Arc::clone(&running);
            let _ = std::thread::Builder::new()
                .name("contained-sink-signals".to_owned())
                .spawn(move || loop {
                    let Ok(signal) = set.wait() else {
                        return;
                    };
                    forward(&shared, signal);
                });
        }
        Self {
            running,
            output: Shaping::default(),
        }
    }

    /// Remove `scratch` should a signal end the sink between commands.
    pub(super) fn clean_up(&self, scratch: PathBuf) {
        if let Ok(mut running) = self.running.lock() {
            running.scratch.push(scratch);
        }
    }

    /// Remove `overlay` should a signal end the sink before the command
    /// starts. A run's layers are removed by the overlay root's own drop,
    /// which an exit from the signal thread would skip; a root already gone
    /// by then is removed again harmlessly, and a second run replaces this
    /// path before it makes layers of its own.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn clean_up_overlay(&self, overlay: PathBuf) {
        if let Ok(mut running) = self.running.lock() {
            running.overlay = Some(overlay);
        }
    }

    /// Signals that nothing waits on, for a test that starts a command.
    #[cfg(test)]
    pub(super) fn idle() -> Self {
        Self {
            running: Arc::new(Mutex::new(Running::default())),
            output: Shaping::default(),
        }
    }

    fn track(&self, child: Option<i32>) {
        if let Ok(mut running) = self.running.lock() {
            running.child = child;
        }
    }
}

fn forward(running: &Mutex<Running>, signal: Signal) {
    let Ok(running) = running.lock() else {
        std::process::exit(128 + signal as i32);
    };
    match running.child {
        Some(child) => {
            if killpg(Pid::from_raw(child), signal).is_err() {
                let _ = kill(Pid::from_raw(child), signal);
            }
        }
        None => {
            for scratch in &running.scratch {
                let _ = std::fs::remove_dir_all(scratch);
            }
            if let Some(overlay) = &running.overlay {
                guard_command::restricted_pytest::remove_workspace_overlay_root(overlay);
            }
            std::process::exit(128 + signal as i32);
        }
    }
}

/// The note a failed run's output earns.
pub(super) enum Notes<'a> {
    /// The workspace sandbox's notes, read from the output; the callback
    /// hears of a blocked connection to this machine.
    Workspace(&'a dyn Fn()),
    /// A fixed note for output that names a denied write.
    ReadOnly(&'static str),
    /// No note.
    Silent,
}

/// Run `backend` (the `sandbox-exec` argv) in its own session under the
/// sandbox's resource limits, replay its output, and answer its exit code.
pub(super) fn run_backend(
    backend: &[String],
    environment: &BTreeMap<String, String>,
    workspace: &Path,
    scratch: &Path,
    signals: &Signals,
    timeout_seconds: u64,
    notes: Notes<'_>,
) -> Outcome<i32> {
    let ceiling = ceiling()?;
    let launcher = std::env::current_exe().map_err(|error| not_started(&error))?;
    let stdout = capture_file(scratch, "stdout")?;
    let stderr = capture_file(scratch, "stderr")?;
    // A merged run writes both streams to one file, in the order written.
    let merge = signals.output.merges();
    let mut command = Command::new(launcher);
    command
        .arg(LAUNCH_COMMAND)
        .arg(ceiling.to_string())
        .args(backend)
        .env_clear()
        .envs(environment)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .stdout(clone(&stdout)?)
        .stderr(clone(if merge { &stdout } else { &stderr })?);
    let (status, timed_out) = run_tracked(&mut command, signals, timeout_seconds, true)
        .map_err(|error| not_started(&error))?;
    let stdout_text = signals.output.replay_out(stdout);
    let stderr_text = signals.output.replay_err(stderr);
    if timed_out {
        return Err(Failure::with_exit(
            "pytest_restricted_timeout",
            format!("Restricted pytest exceeded its {timeout_seconds}-second execution deadline."),
            124,
        ));
    }
    let code = status.map_or(1, exit_code);
    let outputs = [stdout_text.as_slice(), stderr_text.as_slice()];
    let note = match notes {
        _ if code == 0 => None,
        Notes::Workspace(on_loopback_denied) => {
            let note = denial_note(&outputs);
            if note.is_some() && loopback_denied(&outputs) {
                on_loopback_denied();
            }
            note
        }
        Notes::ReadOnly(note) => super::readonly::names_denied_write(&outputs).then_some(note),
        Notes::Silent => None,
    };
    if let Some(note) = note {
        signals
            .output
            .err(format!("\n[HOL Guard] {note}\n").as_bytes());
    }
    Ok(code)
}

/// The process ceiling the launcher lowers a sandboxed command to.
fn ceiling() -> Outcome<u64> {
    let deadline = std::time::Instant::now() + CEILING_BUDGET;
    envelope(crate::restricted_process_ceiling::evaluate(deadline))?
        .as_u64()
        .ok_or_else(|| super::unavailable("invalid_reply"))
}

/// The argv that starts `backend` through the launcher, under the
/// sandbox's resource limits, for a caller that captures its output.
pub(super) fn launcher_argv(backend: &[String]) -> Outcome<Vec<String>> {
    let launcher = std::env::current_exe().map_err(|error| not_started(&error))?;
    let launcher = launcher
        .into_os_string()
        .into_string()
        .map_err(|_| super::unavailable("launcher_path"))?;
    let mut argv = vec![launcher, LAUNCH_COMMAND.to_owned(), ceiling()?.to_string()];
    argv.extend(backend.iter().cloned());
    Ok(argv)
}

/// Start `command`, which the launcher makes a session of its own, and wait
/// up to `timeout_seconds`. The child is tracked under the lock, so a signal
/// never meets a child that started but is not yet tracked. Its group is
/// killed when the time runs out, and also once it exits when `sweep`. The
/// status, and whether the time ran out.
pub(super) fn run_tracked(
    command: &mut Command,
    signals: &Signals,
    timeout_seconds: u64,
    sweep: bool,
) -> std::io::Result<(Option<ExitStatus>, bool)> {
    let child = {
        let mut running = signals
            .running
            .lock()
            .map_err(|_| std::io::Error::other("the sandbox state is unavailable"))?;
        let child = command.spawn()?;
        running.child = i32::try_from(child.id()).ok();
        child
    };
    let group = i32::try_from(child.id()).ok().map(Pid::from_raw);
    let (sender, receiver) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let mut child = child;
        let _ = sender.send(child.wait());
    });
    let waited = receiver.recv_timeout(Duration::from_secs(timeout_seconds));
    let timed_out = waited.is_err();
    if let Some(group) = group.filter(|_| sweep || timed_out) {
        let _ = killpg(group, Signal::SIGKILL);
    }
    let status = match waited {
        Ok(status) => status.ok(),
        Err(_) => receiver.recv().ok().and_then(Result::ok),
    };
    let _ = waiter.join();
    signals.track(None);
    Ok((status, timed_out))
}

fn not_started(error: &std::io::Error) -> Failure {
    Failure::new(
        SANDBOX_UNAVAILABLE,
        format!("Restricted pytest sandbox could not start; execution was not started: {error}"),
    )
}

/// A new owner-only file in `scratch`, unlinked once open so only the
/// descriptors hold it.
pub(super) fn capture_file(scratch: &Path, name: &str) -> Outcome<File> {
    let path = scratch.join(name);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| not_started(&error))?;
    let _ = std::fs::remove_file(&path);
    Ok(file)
}

fn clone(file: &File) -> Outcome<File> {
    file.try_clone().map_err(|error| not_started(&error))
}

/// The shell's view of `status`: the code, or 128 plus the signal.
pub(super) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// What a bounded host command printed and how it exited.
pub(super) struct Captured {
    pub(super) code: i32,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// Run `command` with only `environment`, inside `timeout`. `None` when it
/// could not start or ran out of time (it is killed then).
pub(super) fn run_captured(
    command: &[String],
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    scratch: &Path,
    timeout: Duration,
) -> Option<Captured> {
    let (program, arguments) = command.split_first()?;
    let unique = format!("captured-{}", std::process::id());
    let directory = scratch.join(unique);
    std::fs::DirBuilder::new().create(&directory).ok()?;
    let outcome = run_captured_in(program, arguments, environment, cwd, &directory, timeout);
    let _ = std::fs::remove_dir_all(&directory);
    outcome
}

fn run_captured_in(
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    directory: &Path,
    timeout: Duration,
) -> Option<Captured> {
    let stdout = capture_file(directory, "stdout").ok()?;
    let stderr = capture_file(directory, "stderr").ok()?;
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().ok()?)
        .stderr(stderr.try_clone().ok()?)
        .spawn()
        .ok()?;
    let pid = child.id();
    let (sender, receiver) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = sender.send(child.wait());
    });
    let status = match receiver.recv_timeout(timeout) {
        Ok(status) => status.ok(),
        Err(_) => {
            if let Ok(pid) = i32::try_from(pid) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
            let _ = receiver.recv();
            None
        }
    };
    let _ = waiter.join();
    let status = status?;
    Some(Captured {
        code: exit_code(status),
        stdout: read_all(stdout),
        stderr: read_all(stderr),
    })
}

pub(super) fn read_all(mut file: File) -> Vec<u8> {
    let mut raw = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let _ = file.read_to_end(&mut raw);
    }
    raw
}

/// `contained-workspace-launch CEILING [node-memory] ARGV...`: start a
/// session, apply the sandbox's resource limits, and exec `ARGV`. With
/// `host` for `CEILING`, a host step: the session only. Returns only on
/// failure.
pub(crate) fn launch(args: &[String]) -> i32 {
    let Some((ceiling, argv)) = args.split_first() else {
        return launch_failed("missing command");
    };
    if let (HOST_STEP, Some((program, arguments))) = (ceiling.as_str(), argv.split_first()) {
        let _ = nix::unistd::setsid();
        release_forwarded_signals();
        let error = Command::new(program).args(arguments).exec();
        return launch_failed(&error.to_string());
    }
    let (node, argv) = match argv.split_first() {
        Some((word, rest)) if word == NODE_MEMORY => (true, rest),
        _ => (false, argv),
    };
    let (Ok(ceiling), Some(_)) = (ceiling.parse::<u64>(), argv.first()) else {
        return launch_failed("invalid launch arguments");
    };
    let _ = nix::unistd::setsid();
    release_forwarded_signals();
    if !limits::apply(ceiling, node) {
        return launch_failed("Linux Node memory limits are unavailable");
    }
    #[cfg(target_vendor = "apple")]
    let error = Command::new("/bin/sh")
        .arg("-c")
        .arg(PROCESS_LIMIT_SCRIPT)
        .arg("sh")
        .arg(ceiling.to_string())
        .args(argv)
        .exec();
    #[cfg(not(target_vendor = "apple"))]
    let error = Command::new(&argv[0]).args(&argv[1..]).exec();
    launch_failed(&error.to_string())
}

/// Take `SIGINT` and `SIGTERM` back in the process the contained command
/// will become.
///
/// The sink blocks both so its own thread can wait on them, and a blocked
/// signal stays blocked across `exec`. Left that way, the signal the sink
/// forwards to the command's process group would never be delivered and an
/// interrupted run would wait for the timeout instead of stopping.
pub(super) fn release_forwarded_signals() {
    let mut held = SigSet::empty();
    held.add(Signal::SIGINT);
    held.add(Signal::SIGTERM);
    let _ = held.thread_unblock();
}

fn launch_failed(detail: &str) -> i32 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "{SANDBOX_UNAVAILABLE}: Restricted pytest sandbox could not start; execution was not started: {detail}"
    );
    let _ = stderr.flush();
    126
}

#[path = "contained_workspace_sink_limits.rs"]
mod limits;

#[cfg(test)]
#[path = "contained_workspace_sink_process_tests.rs"]
mod tests;
