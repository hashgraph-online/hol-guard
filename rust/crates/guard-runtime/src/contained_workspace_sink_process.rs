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
use super::{envelope, Failure, Outcome, LAUNCH_COMMAND, SANDBOX_UNAVAILABLE};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const TRUNCATED: &str = "\n[HOL Guard truncated restricted pytest output]\n";
const CPU_SECONDS: u64 = 1200;
const ADDRESS_SPACE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const FILE_SIZE_BYTES: u64 = 256 * 1024 * 1024;
const OPEN_FILES: u64 = 256;
const CEILING_BUDGET: Duration = Duration::from_secs(5);
/// The launcher's `CEILING` for a host step, which runs without limits.
pub(super) const HOST_STEP: &str = "host";
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
    scratch: Option<PathBuf>,
    overlay: Option<PathBuf>,
}

/// Interrupts and terminations, held for the sink and forwarded to the
/// running command.
pub(super) struct Signals {
    running: Arc<Mutex<Running>>,
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
        Self { running }
    }

    /// Remove `scratch` should a signal end the sink between commands.
    pub(super) fn clean_up(&self, scratch: PathBuf) {
        if let Ok(mut running) = self.running.lock() {
            running.scratch = Some(scratch);
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
            if let Some(scratch) = &running.scratch {
                let _ = std::fs::remove_dir_all(scratch);
            }
            if let Some(overlay) = &running.overlay {
                guard_command::restricted_pytest::remove_workspace_overlay_root(overlay);
            }
            std::process::exit(128 + signal as i32);
        }
    }
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
    on_loopback_denied: &dyn Fn(),
) -> Outcome<i32> {
    let deadline = std::time::Instant::now() + CEILING_BUDGET;
    let ceiling = envelope(crate::restricted_process_ceiling::evaluate(deadline))?
        .as_u64()
        .ok_or_else(|| super::unavailable("invalid_reply"))?;
    let launcher = std::env::current_exe().map_err(|error| not_started(&error))?;
    let stdout = capture_file(scratch, "stdout")?;
    let stderr = capture_file(scratch, "stderr")?;
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
        .stderr(clone(&stderr)?);
    let (status, timed_out) = run_tracked(&mut command, signals, timeout_seconds, true)
        .map_err(|error| not_started(&error))?;
    let stdout_text = replay(stdout, &mut std::io::stdout());
    let stderr_text = replay(stderr, &mut std::io::stderr());
    if timed_out {
        return Err(Failure::with_exit(
            "pytest_restricted_timeout",
            format!("Restricted pytest exceeded its {timeout_seconds}-second execution deadline."),
            124,
        ));
    }
    let code = status.map_or(1, exit_code);
    let outputs = [stdout_text.as_slice(), stderr_text.as_slice()];
    let note = (code != 0).then(|| denial_note(&outputs)).flatten();
    if note.is_some() && loopback_denied(&outputs) {
        on_loopback_denied();
    }
    if let Some(note) = note {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "\n[HOL Guard] {note}");
        let _ = stderr.flush();
    }
    Ok(code)
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
fn capture_file(scratch: &Path, name: &str) -> Outcome<File> {
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

/// Write up to `OUTPUT_LIMIT` bytes of `file` to `out` as display text;
/// the raw bytes read, for the denial check.
fn replay(mut file: File, out: &mut impl Write) -> Vec<u8> {
    let mut raw = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let limit = u64::try_from(OUTPUT_LIMIT).unwrap_or(u64::MAX);
        let _ = (&mut file).take(limit + 1).read_to_end(&mut raw);
    }
    let truncated = raw.len() > OUTPUT_LIMIT;
    raw.truncate(OUTPUT_LIMIT);
    let mut text = display_text(&raw);
    if truncated {
        text.push_str(TRUNCATED);
    }
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
    raw
}

/// Output as text a terminal shows safely: CRLF folded, and control
/// characters other than newline and tab replaced.
fn display_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .replace("\r\n", "\n")
        .chars()
        .map(|character| {
            if character == '\n' || character == '\t' || u32::from(character) >= 32 {
                character
            } else {
                '\u{fffd}'
            }
        })
        .collect()
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

fn read_all(mut file: File) -> Vec<u8> {
    let mut raw = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let _ = file.read_to_end(&mut raw);
    }
    raw
}

/// `contained-workspace-launch CEILING ARGV...`: start a session, apply the
/// sandbox's resource limits, and exec `ARGV`. With `host` for `CEILING`,
/// a host step: the session only. Returns only on failure.
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
    let (Ok(ceiling), Some(_)) = (ceiling.parse::<u64>(), argv.first()) else {
        return launch_failed("invalid launch arguments");
    };
    let _ = nix::unistd::setsid();
    release_forwarded_signals();
    limit_resources(ceiling);
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

fn limit_resources(ceiling: u64) {
    use nix::sys::resource::Resource;
    lower(Resource::RLIMIT_CPU, CPU_SECONDS);
    lower(Resource::RLIMIT_AS, ADDRESS_SPACE_BYTES);
    lower(Resource::RLIMIT_FSIZE, FILE_SIZE_BYTES);
    lower(Resource::RLIMIT_NOFILE, OPEN_FILES);
    #[cfg(not(target_vendor = "apple"))]
    lower(Resource::RLIMIT_NPROC, ceiling);
    #[cfg(target_vendor = "apple")]
    let _ = ceiling;
}

/// Lower `resource` to `requested` without raising either limit; a limit
/// the platform refuses is left as it is.
fn lower(resource: nix::sys::resource::Resource, requested: u64) {
    let Ok((soft, hard)) = nix::sys::resource::getrlimit(resource) else {
        return;
    };
    let (soft, hard) = lowered(soft, hard, requested);
    let _ = nix::sys::resource::setrlimit(resource, soft, hard);
}

fn lowered(soft: u64, hard: u64, requested: u64) -> (u64, u64) {
    let infinite = libc::RLIM_INFINITY;
    let hard = if hard == infinite {
        requested
    } else {
        requested.min(hard)
    };
    let soft = if soft == infinite {
        hard
    } else {
        requested.min(soft).min(hard)
    };
    (soft, hard)
}

#[cfg(test)]
#[path = "contained_workspace_sink_process_tests.rs"]
mod tests;
