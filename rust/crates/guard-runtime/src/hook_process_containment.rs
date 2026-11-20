//! Containment of a hook child: the quarantine that holds a child the launcher
//! could not prove stopped, the kill of its whole tree, and the bounded wait on
//! it. Split from `hook_process_spawn` as a `#[path]` child module.

use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use super::{FINAL_REAP_TIMEOUT, WAIT_POLL_INTERVAL};

/// A child that could not be proven contained — retained so the next call can
/// retry containment before admitting a new process. Mirrors
/// `_HOOK_PROCESS_QUARANTINE` (`codex_hook_launch_runtime.py:99`).
#[allow(dead_code)]
pub(super) struct Quarantined {
    child: Child,
    tree: Tree,
    readers_done: Arc<AtomicBool>,
}

/// What contains one child's whole tree: its process group on unix, a Job
/// Object on Windows (`_HOOK_PROCESS_QUARANTINE`'s `windows_job`).
#[derive(Default)]
pub(super) struct Tree {
    #[cfg(windows)]
    pub(super) job: Option<guard_runtime_windows_process::ChildTree>,
}

#[allow(dead_code)]
fn quarantine() -> &'static Mutex<Vec<Quarantined>> {
    static Q: OnceLock<Mutex<Vec<Quarantined>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(Vec::new()))
}

#[allow(dead_code)]
pub(super) fn quarantine_lock() -> MutexGuard<'static, Vec<Quarantined>> {
    quarantine().lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(dead_code)]
pub(super) fn containment_failed_flag() -> &'static AtomicBool {
    static F: OnceLock<AtomicBool> = OnceLock::new();
    F.get_or_init(|| AtomicBool::new(false))
}

/// `_retry_quarantined_hook_processes` (`codex_hook_launch_runtime.py:102`).
/// Re-kill each quarantined child; drop only provably-contained entries.
/// Returns true when the quarantine drains clean.
#[allow(dead_code)]
pub(super) fn retry_quarantined() -> bool {
    let mut q = quarantine_lock();
    let mut survivors = Vec::new();
    for mut entry in q.drain(..) {
        let mut contained = kill_tree(&mut entry.child, &entry.tree);
        if entry.child.try_wait().ok().flatten().is_none() {
            // Still running after kill attempt.
            if entry.child.wait_timeout(FINAL_REAP_TIMEOUT).is_none() {
                contained = false;
            }
        }
        if contained
            && entry.child.try_wait().ok().flatten().is_some()
            && entry.readers_done.load(Ordering::SeqCst)
        {
            // contained: drop the handle
        } else {
            survivors.push(entry);
        }
    }
    *q = survivors;
    let drained = q.is_empty();
    containment_failed_flag().store(!drained, Ordering::SeqCst);
    drained
}

/// Retry the quarantine until it drains or `window` closes. The one-shot
/// launcher calls this before it exits, since no later call can retry for it.
pub fn settle_quarantine(window: Duration) -> bool {
    let end = Instant::now() + window;
    loop {
        if retry_quarantined() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(WAIT_POLL_INTERVAL * 5);
    }
}

#[allow(dead_code)]
pub(super) fn quarantine_child(child: Child, tree: Tree, readers_done: Arc<AtomicBool>) {
    let mut q = quarantine_lock();
    q.push(Quarantined {
        child,
        tree,
        readers_done,
    });
    containment_failed_flag().store(true, Ordering::SeqCst);
}

/// The pids still quarantined: survivors the caller can later check for exit.
pub fn quarantined_pids() -> Vec<u32> {
    quarantine_lock()
        .iter()
        .map(|entry| entry.child.id())
        .collect()
}

/// `_kill_hook_process` / `_kill_hook_process_group` (unix leg): SIGKILL the
/// process group. `process_group(0)` at spawn makes the child PID the group
/// ID, so `killpg(pid)` reaches the whole tree.
#[cfg(unix)]
#[allow(dead_code)]
fn kill_process_group(child: &mut Child) -> bool {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    match kill(Pid::from_raw(-(child.id() as i32)), Signal::SIGKILL) {
        Ok(()) => true,
        Err(nix::errno::Errno::ESRCH) => child.try_wait().ok().flatten().is_some(),
        Err(_) => {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                false
            } else {
                true
            }
        }
    }
}

/// `_kill_hook_process`: end the whole tree; `true` only when that is proven.
#[cfg(unix)]
pub(super) fn kill_tree(child: &mut Child, _tree: &Tree) -> bool {
    kill_process_group(child)
}

#[cfg(windows)]
pub(super) fn kill_tree(child: &mut Child, tree: &Tree) -> bool {
    if let Some(job) = &tree.job {
        if job.terminate().is_ok() {
            return true;
        }
    }
    if child.try_wait().ok().flatten().is_some() {
        return tree.job.is_none();
    }
    child.kill().is_ok() && tree.job.is_none()
}

/// Extension: bounded `wait` on a `Child` with a `Duration` — returns
/// `Some(status)` if reaped, `None` on timeout.
#[allow(dead_code)]
pub(super) trait WaitTimeout {
    fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus>;
}
impl WaitTimeout for Child {
    fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_wait() {
                Ok(Some(s)) => return Some(s),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return None,
            }
        }
    }
}
