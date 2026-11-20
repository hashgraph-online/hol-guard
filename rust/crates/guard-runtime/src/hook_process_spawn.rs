//! Isolated, resource-bounded subprocess kernel for managed hook helpers.
//!
//! Port of `codex_hook_launch_runtime.py` + `codex_hook_process_runtime.py`:
//! the generic bounded-spawn primitive that `native_runtime.py::_run_native_
//! process` and `native_archive_inspection.py` consume. Distinct from
//! `managed_resident_containment` (which self-spawns the supervise-managed
//! binary): this kernel runs an arbitrary command with a private env
//! allowlist, bounded combined output, a hard deadline, a cooperative
//! stop flag, and process-group containment + quarantine-on-leak.
//!
//! On Windows the child starts suspended and joins a Job Object
//! (`guard_runtime_windows_process::ChildTree`) before it resumes; on unix it
//! leads its own process group and `killpg(SIGKILL)` contains the tree.
//! `hook_launch_cli` is the one-shot entry Python calls instead of spawning
//! the child itself.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[allow(dead_code)]
const HOOK_SUBPROCESS_OUTPUT_LIMIT: usize = 1_000_000;
#[allow(dead_code)]
const REAP_TIMEOUT: Duration = Duration::from_millis(200);
#[allow(dead_code)]
const FINAL_REAP_TIMEOUT: Duration = Duration::from_millis(100);
#[allow(dead_code)]
const IO_JOIN_TIMEOUT: Duration = Duration::from_millis(50);
#[allow(dead_code)]
const FINAL_IO_JOIN_TIMEOUT: Duration = Duration::from_millis(1000);
#[allow(dead_code)]
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// `BoundedHookProcessResult` (`codex_hook_launch_runtime.py:78-88`).
#[derive(Debug, Clone, PartialEq)]
pub struct BoundedHookProcessResult {
    pub returncode: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_limit_exceeded: bool,
    pub timed_out: bool,
    pub containment_failed: bool,
}

// ---------------------------------------------------------------------------
// Bounded spawn kernel
// ---------------------------------------------------------------------------

#[path = "hook_process_containment.rs"]
mod containment;
#[path = "hook_process_environment.rs"]
mod environment;
#[path = "hook_process_output.rs"]
mod output;

#[cfg(test)]
use containment::quarantine_lock;
use containment::{
    containment_failed_flag, kill_tree, quarantine_child, retry_quarantined, Tree, WaitTimeout,
};
pub use containment::{quarantined_pids, settle_quarantine};
pub(crate) use environment::desktop_hook_proxy_context;
#[cfg(test)]
use environment::HOOK_ENVIRONMENT_KEYS;
pub use environment::{
    isolated_daemon_start_command, isolated_guard_cli_command, isolated_hook_environment,
    private_hook_runtime_cwd,
};
#[cfg(test)]
use output::truncate_decoded;
use output::{decode_combined_output, drain_stream, write_input, OutputBound};

/// What one launch asks for beyond the plain bounded run.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct LaunchExtras {
    /// Pass the child a pipe that stays open until it ends
    /// (`HOL_GUARD_PARENT_LIVENESS_FD`); unix only.
    pub parent_liveness: bool,
    /// Let a Windows child leave its Job (`allow_windows_breakaway`).
    pub allow_breakaway: bool,
    /// Kill the Windows Job's members when its handle closes.
    pub kill_on_close: bool,
    /// Windows Job-wide memory ceiling in bytes.
    pub job_memory_limit_bytes: Option<usize>,
    /// Windows Job active-process ceiling.
    pub active_process_limit: Option<u32>,
}

impl Default for LaunchExtras {
    fn default() -> Self {
        Self {
            parent_liveness: false,
            allow_breakaway: false,
            kill_on_close: true,
            job_memory_limit_bytes: None,
            active_process_limit: None,
        }
    }
}

/// One finished launch: the result plus the raw bytes behind its decoded text.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchOutcome {
    pub result: BoundedHookProcessResult,
    pub stdout_raw: Vec<u8>,
    pub stderr_raw: Vec<u8>,
    pub capture_incomplete: bool,
}

fn refused_outcome(timed_out: bool, containment_failed: bool) -> LaunchOutcome {
    LaunchOutcome {
        result: BoundedHookProcessResult {
            returncode: None,
            stdout: String::new(),
            stderr: String::new(),
            output_limit_exceeded: false,
            timed_out,
            containment_failed,
        },
        stdout_raw: Vec::new(),
        stderr_raw: Vec::new(),
        capture_incomplete: false,
    }
}

/// The write end of the parent-liveness pipe; closing it is the signal.
#[cfg(unix)]
type Liveness = Option<std::os::fd::OwnedFd>;
#[cfg(not(unix))]
type Liveness = Option<()>;

/// Start the child inside its containment (`_spawn_hook_process`).
fn spawn_contained(
    command: &[String],
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    extras: &LaunchExtras,
) -> std::io::Result<(Child, Tree, Liveness)> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        // Own process group, so killpg(pid) contains the tree.
        cmd.process_group(0);
        let mut liveness: Liveness = None;
        let mut read_end = None;
        if extras.parent_liveness {
            let (read, write) = nix::unistd::pipe().map_err(std::io::Error::from)?;
            // The child inherits the read end only.
            nix::fcntl::fcntl(
                &write,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .map_err(std::io::Error::from)?;
            cmd.env("HOL_GUARD_PARENT_LIVENESS_FD", read.as_raw_fd().to_string());
            liveness = Some(write);
            read_end = Some(read);
        }
        let child = cmd.spawn()?;
        drop(read_end);
        Ok((child, Tree::default(), liveness))
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP, plus suspended: the Job holds the child
        // before its first instruction.
        cmd.creation_flags(guard_runtime_windows_process::CHILD_TREE_CREATION_FLAGS | 0x0000_0200);
        let mut child = cmd.spawn()?;
        let options = guard_runtime_windows_process::ChildTreeOptions {
            kill_on_close: extras.kill_on_close,
            allow_breakaway: extras.allow_breakaway,
            job_memory_limit_bytes: extras.job_memory_limit_bytes,
            active_process_limit: extras.active_process_limit,
        };
        match guard_runtime_windows_process::ChildTree::adopt_suspended_with(&child, options) {
            Ok(job) => Ok((child, Tree { job: Some(job) }, None)),
            Err(error) => {
                // `_cleanup_failed_spawn`: the suspended child must not outlive the refusal.
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }
}

/// `run_isolated_hook_process` (`codex_hook_launch_runtime.py`), the plain
/// form the runtime's own callers use.
///
/// `deadline` (absolute `Instant`) is authoritative when given — startup and
/// stream cleanup consume the caller's existing budget; `timeout_seconds` is
/// used only when no absolute deadline is supplied. `stop_event` lets a
/// long-lived reviewed helper terminate through the same group-kill path.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn run_isolated_hook_process(
    command: &[String],
    input_text: &str,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    timeout_seconds: Option<f64>,
    output_limit: Option<usize>,
    stop_event: Option<Arc<AtomicBool>>,
    deadline: Option<Instant>,
) -> BoundedHookProcessResult {
    run_isolated_hook_process_extended(
        command,
        input_text,
        cwd,
        environment,
        timeout_seconds,
        output_limit,
        stop_event,
        deadline,
        &LaunchExtras::default(),
    )
    .result
}

/// The whole kernel: `run_isolated_hook_process` with its containment
/// options and the raw output bytes.
#[allow(clippy::too_many_arguments)]
pub fn run_isolated_hook_process_extended(
    command: &[String],
    input_text: &str,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    timeout_seconds: Option<f64>,
    output_limit: Option<usize>,
    stop_event: Option<Arc<AtomicBool>>,
    deadline: Option<Instant>,
    extras: &LaunchExtras,
) -> LaunchOutcome {
    if command.is_empty() {
        return refused_outcome(false, false);
    }
    if stop_event
        .as_ref()
        .is_some_and(|e| e.load(Ordering::SeqCst))
    {
        return refused_outcome(false, false);
    }
    let output_limit = output_limit.unwrap_or(HOOK_SUBPROCESS_OUTPUT_LIMIT);
    let deadline = match deadline {
        Some(d) => d,
        None => match timeout_seconds {
            None => return refused_outcome(false, false),
            Some(t) => {
                let t = if t.is_nan() {
                    0.0
                } else {
                    t.clamp(0.0, 86_400.0)
                };
                Instant::now() + Duration::from_secs_f64(t)
            }
        },
    };
    if Instant::now() >= deadline {
        return refused_outcome(true, containment_failed_flag().load(Ordering::SeqCst));
    }
    // Retry containment on any previously-quarantined leak before spawning.
    if containment_failed_flag().load(Ordering::SeqCst) && !retry_quarantined() {
        return refused_outcome(false, true);
    }

    let (mut child, tree, liveness) = match spawn_contained(command, cwd, environment, extras) {
        Ok(spawned) => spawned,
        Err(_) => return refused_outcome(false, false),
    };

    // start_hook_io: bounded stdout/stderr readers + a stdin writer.
    let bound = Arc::new(OutputBound {
        count: AtomicU64::new(0),
        limit: output_limit as u64,
        exceeded: AtomicBool::new(false),
        capture_error: AtomicBool::new(false),
    });
    let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let readers_done = Arc::new(AtomicBool::new(false));

    let mut io_handles: Vec<JoinHandle<()>> = Vec::new();
    if let Some(out) = child.stdout.take() {
        let d = readers_done.clone();
        io_handles.push(drain_stream(out, stdout_buf.clone(), bound.clone(), d));
    }
    if let Some(err) = child.stderr.take() {
        let d = readers_done.clone();
        io_handles.push(drain_stream(err, stderr_buf.clone(), bound.clone(), d));
    }
    if let Some(stdin) = child.stdin.take() {
        io_handles.push(write_input(stdin, input_text.as_bytes().to_vec()));
    }

    // wait_for_hook_process: poll stop / output-limit / deadline, terminate
    // the group on the first trigger, then reap.
    let mut timed_out = false;
    let mut termination_requested = false;
    let mut containment_confirmed = true;
    loop {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        let stopped = stop_event
            .as_ref()
            .is_some_and(|e| e.load(Ordering::SeqCst));
        let over = bound.exceeded.load(Ordering::SeqCst);
        let late = Instant::now() >= deadline;
        if stopped || over || late {
            timed_out = late && !stopped && !over;
            termination_requested = true;
            containment_confirmed = kill_tree(&mut child, &tree);
            break;
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
    let returncode = match child.wait_timeout(REAP_TIMEOUT) {
        Some(s) => s.code(),
        None => {
            containment_confirmed = kill_tree(&mut child, &tree) && containment_confirmed;
            match child.wait_timeout(FINAL_REAP_TIMEOUT) {
                Some(s) => s.code(),
                None => {
                    containment_confirmed = false;
                    None
                }
            }
        }
    };
    if !timed_out && Instant::now() >= deadline {
        timed_out = true;
    }
    let result_failed = returncode.is_none()
        || returncode != Some(0)
        || bound.exceeded.load(Ordering::SeqCst)
        || timed_out
        || stop_event
            .as_ref()
            .is_some_and(|e| e.load(Ordering::SeqCst));
    if result_failed && (!termination_requested || !containment_confirmed) {
        termination_requested = true;
        containment_confirmed = kill_tree(&mut child, &tree) && containment_confirmed;
    }

    // join_and_cleanup_hook_process: join IO threads on a deadline; if a
    // reader is still alive past the final join the process is uncontained.
    let io_join_deadline = Instant::now() + IO_JOIN_TIMEOUT;
    for h in &io_handles {
        let _ = wait_handle(h, io_join_deadline);
    }
    if io_handles.iter().any(|h| !h.is_finished()) {
        if !termination_requested || !containment_confirmed {
            containment_confirmed = kill_tree(&mut child, &tree) && containment_confirmed;
        }
        let final_join_deadline = Instant::now() + FINAL_IO_JOIN_TIMEOUT;
        for h in &io_handles {
            let _ = wait_handle(h, final_join_deadline);
        }
        if io_handles.iter().any(|h| !h.is_finished()) {
            containment_confirmed = false;
        }
    }

    if !containment_confirmed {
        quarantine_child(child, tree, readers_done);
    }
    // The liveness pipe closes now the child is done (or quarantined).
    drop(liveness);
    // Drain joinable handles (they're detached-safe; finishing is enough).
    for h in io_handles {
        // A reader that outlived the final join belongs to a quarantined child;
        // joining it would block the answer on the very process we failed to stop.
        if h.is_finished() {
            let _ = h.join();
        }
    }

    let stdout_raw = stdout_buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stderr_raw = stderr_buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (stdout_decoded, stderr_decoded) =
        decode_combined_output(&stdout_raw, &stderr_raw, output_limit);

    LaunchOutcome {
        result: BoundedHookProcessResult {
            returncode: if containment_confirmed {
                returncode
            } else {
                None
            },
            stdout: stdout_decoded,
            stderr: stderr_decoded,
            output_limit_exceeded: bound.exceeded.load(Ordering::SeqCst),
            timed_out,
            containment_failed: !containment_confirmed,
        },
        stdout_raw,
        stderr_raw,
        capture_incomplete: bound.capture_error.load(Ordering::SeqCst),
    }
}

/// Join a `JoinHandle` by polling `is_finished` until `deadline`. Returns
/// `true` if the thread finished in time. (`JoinHandle::join` blocks
/// unconditionally; we only need the finish signal within the budget.)
#[allow(dead_code)]
fn wait_handle(h: &JoinHandle<()>, deadline: Instant) -> bool {
    while !h.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    h.is_finished()
}

#[cfg(test)]
#[path = "hook_process_spawn_kernel_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "hook_process_spawn_tests.rs"]
mod capture_tests;
