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
//! Windows Job-object legs (`spawn_windows_hook_process`, `WindowsHookJob`)
//! are `cfg(windows)`-gated; the unix path uses `process_group(0)` +
//! `killpg(SIGKILL)` for containment.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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

/// `_HOOK_ENVIRONMENT_KEYS` (`codex_hook_launch_runtime.py:30-52`): the only
/// base-env keys forwarded to a contained hook process. `LC_*` is a prefix
/// allowlist on top.
#[allow(dead_code)]
const HOOK_ENVIRONMENT_KEYS: [&str; 18] = [
    "CODEX_HOME",
    "COMSPEC",
    "HOME",
    "HOL_GUARD_HOOK_FAILURE_KIND",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    "HOL_GUARD_TEST_MODE",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
    "LANG",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
    // 18th slot reserved for future OS keys; keep count honest.
    "HOL_GUARD_RUNTIME_DIR",
];

#[allow(dead_code)]
fn env_key_allowed(name: &str) -> bool {
    let upper = name.to_uppercase();
    HOOK_ENVIRONMENT_KEYS.iter().any(|k| upper == *k) || upper.starts_with("LC_")
}

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

/// `isolated_hook_environment` (`codex_hook_launch_runtime.py:216-224`).
#[allow(dead_code)]
pub fn isolated_hook_environment(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    source
        .iter()
        .filter(|(k, _)| env_key_allowed(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `isolated_guard_cli_command` (`codex_hook_launch_runtime.py:171-184`):
/// the exact isolated fallback contract pinned to one package root.
#[allow(dead_code)]
pub fn isolated_guard_cli_command(
    python_executable: &str,
    package_root: &Path,
    guard_args: &[String],
) -> Vec<String> {
    let bootstrap = format!(
        "import sys;sys.path.insert(0, {});from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
        py_repr(&canonical_or_self(package_root)),
    );
    let mut cmd = vec![
        python_executable.to_string(),
        "-I".to_string(),
        "-c".to_string(),
        bootstrap,
    ];
    cmd.extend(guard_args.iter().cloned());
    cmd
}

/// `isolated_daemon_start_command` (`codex_hook_launch_runtime.py:187-213`).
/// `home_dir` is the authenticated canonical home; `None` = `Path.home()`.
#[allow(dead_code)]
pub fn isolated_daemon_start_command(
    python_executable: &str,
    package_root: &Path,
    guard_home: &Path,
    home_dir: Option<&Path>,
) -> Vec<String> {
    let resolved_home = home_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(home_fallback);
    let bootstrap = format!(
        "import os,sys;sys.path.insert(0, {});from pathlib import Path;\
from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;\
failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');\
failure_kind=failure_kind if failure_kind in \
{{'overload','transport-failure','authenticated-control-plane-failure'}} \
else 'transport-failure';\
schedule_guard_daemon_recovery(Path({}),home_dir=Path({}),failure_kind=failure_kind)",
        py_repr(&canonical_or_self(package_root)),
        py_repr(guard_home),
        py_repr(&resolved_home),
    );
    vec![
        python_executable.to_string(),
        "-I".to_string(),
        "-c".to_string(),
        bootstrap,
    ]
}

#[allow(dead_code)]
fn home_fallback() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[allow(dead_code)]
fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Python `repr()` of a path string — `Path('…')` needs a quoted literal.
#[allow(dead_code)]
fn py_repr(p: &Path) -> String {
    let s = p.as_os_str().to_string_lossy();
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// `private_hook_runtime_cwd` (`codex_hook_launch_runtime.py:227-247`):
/// return the authenticated manifest's private Guard-owned directory.
/// Errors map to `Err("…")` mirroring the Python `ValueError` messages.
#[allow(dead_code)]
pub fn private_hook_runtime_cwd(manifest_path: &Path) -> Result<PathBuf, String> {
    let parent = manifest_path
        .parent()
        .ok_or_else(|| "managed Codex hook runtime directory is unavailable".to_string())?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;
    let resolved = std::fs::canonicalize(parent)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;
    let _resolved_meta = std::fs::symlink_metadata(&resolved)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;

    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err("managed Codex hook runtime directory is not a regular directory".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (parent_meta.dev(), parent_meta.ino()) != (_resolved_meta.dev(), _resolved_meta.ino()) {
            return Err(
                "managed Codex hook runtime directory changed during validation".to_string(),
            );
        }
        let current_uid = nix::unistd::getuid().as_raw();
        if parent_meta.uid() != current_uid {
            return Err("managed Codex hook runtime directory has an unexpected owner".to_string());
        }
        if parent_meta.mode() & 0o077 != 0 {
            return Err("managed Codex hook runtime directory is not owner-only".to_string());
        }
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Bounded spawn kernel
// ---------------------------------------------------------------------------

/// A child that could not be proven contained — retained so the next call can
/// retry containment before admitting a new process. Mirrors
/// `_HOOK_PROCESS_QUARANTINE` (`codex_hook_launch_runtime.py:99`).
#[allow(dead_code)]
struct Quarantined {
    child: Child,
    readers_done: Arc<AtomicBool>,
}

#[allow(dead_code)]
fn quarantine() -> &'static Mutex<Vec<Quarantined>> {
    static Q: OnceLock<Mutex<Vec<Quarantined>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(Vec::new()))
}

#[allow(dead_code)]
fn quarantine_lock() -> MutexGuard<'static, Vec<Quarantined>> {
    quarantine().lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(dead_code)]
fn containment_failed_flag() -> &'static AtomicBool {
    static F: OnceLock<AtomicBool> = OnceLock::new();
    F.get_or_init(|| AtomicBool::new(false))
}

/// `_retry_quarantined_hook_processes` (`codex_hook_launch_runtime.py:102`).
/// Re-kill each quarantined child; drop only provably-contained entries.
/// Returns true when the quarantine drains clean.
#[allow(dead_code)]
fn retry_quarantined() -> bool {
    let mut q = quarantine_lock();
    let mut survivors = Vec::new();
    for mut entry in q.drain(..) {
        let mut contained = kill_process_group(&mut entry.child);
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

#[allow(dead_code)]
fn quarantine_child(child: Child, readers_done: Arc<AtomicBool>) {
    let mut q = quarantine_lock();
    q.push(Quarantined {
        child,
        readers_done,
    });
    containment_failed_flag().store(true, Ordering::SeqCst);
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

#[cfg(not(unix))]
fn kill_process_group(child: &mut Child) -> bool {
    if child.try_wait().ok().flatten().is_some() {
        return true;
    }
    child.kill().is_ok()
}

/// Shared output counters across the two drain readers — Python's
/// `output_count`/`output_lock`/`output_limit_exceeded`.
#[allow(dead_code)]
struct OutputBound {
    count: AtomicU64,
    limit: u64,
    exceeded: AtomicBool,
}

#[allow(dead_code)]
impl OutputBound {
    fn take(&self, chunk_len: usize) -> usize {
        // Reserve up-front so two readers cannot both pass under the limit.
        let prev = self.count.fetch_add(chunk_len as u64, Ordering::SeqCst);
        let accepted = self.limit.saturating_sub(prev).min(chunk_len as u64) as usize;
        if prev + chunk_len as u64 > self.limit {
            self.exceeded.store(true, Ordering::SeqCst);
        }
        accepted
    }
}

/// Drain one stream into `target`, accepting only up to the shared limit.
#[allow(dead_code)]
fn drain_stream<R: Read + Send + 'static>(
    mut stream: R,
    target: Arc<Mutex<Vec<u8>>>,
    bound: Arc<OutputBound>,
    done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let accepted = bound.take(n);
                    if accepted > 0 {
                        if let Ok(mut t) = target.lock() {
                            t.extend_from_slice(&buf[..accepted]);
                        }
                    }
                }
            }
        }
        done.store(true, Ordering::SeqCst);
    })
}

/// Write `input_text` into the child's stdin then close it.
#[allow(dead_code)]
fn write_input(mut stream: std::process::ChildStdin, input: Vec<u8>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = stream.write_all(&input);
        let _ = stream.flush();
        // dropping `stream` closes stdin (EOF to child)
    })
}

/// `_truncate_decoded_output` (`codex_hook_launch_runtime.py:55-61`):
/// keep the decoded UTF-8 within `limit` bytes after replacement decoding.
#[allow(dead_code)]
fn truncate_decoded(value: String, limit: usize) -> String {
    let encoded = value.as_bytes();
    if encoded.len() <= limit {
        return value;
    }
    // Re-encode-bound: decode only the prefix that fits, ignoring the cut.
    String::from_utf8_lossy(&encoded[..limit]).into_owned()
}

/// `_decode_combined_output` (`codex_hook_launch_runtime.py:64-75`): decode
/// both streams preserving their shared byte bound (stdout consumes first).
#[allow(dead_code)]
fn decode_combined_output(stdout: &[u8], stderr: &[u8], output_limit: usize) -> (String, String) {
    let remaining = output_limit;
    let stdout_str = truncate_decoded(String::from_utf8_lossy(stdout).into_owned(), remaining);
    let remaining = remaining.saturating_sub(stdout_str.len());
    let stderr_str = truncate_decoded(String::from_utf8_lossy(stderr).into_owned(), remaining);
    (stdout_str, stderr_str)
}

/// Extension: bounded `wait` on a `Child` with a `Duration` — returns
/// `Some(status)` if reaped, `None` on timeout.
#[allow(dead_code)]
trait WaitTimeout {
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

/// `run_isolated_hook_process` (`codex_hook_launch_runtime.py:299-377`).
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
    // Retry containment on any previously-quarantined leak before spawning.
    if containment_failed_flag().load(Ordering::SeqCst) && !retry_quarantined() {
        return BoundedHookProcessResult {
            returncode: None,
            stdout: String::new(),
            stderr: String::new(),
            output_limit_exceeded: false,
            timed_out: false,
            containment_failed: true,
        };
    }
    let output_limit = output_limit.unwrap_or(HOOK_SUBPROCESS_OUTPUT_LIMIT);
    let deadline = match deadline {
        Some(d) => d,
        None => match timeout_seconds {
            None => {
                return BoundedHookProcessResult {
                    returncode: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    output_limit_exceeded: false,
                    timed_out: false,
                    containment_failed: false,
                }
            }
            Some(t) => Instant::now() + Duration::from_secs_f64(t.max(0.0)),
        },
    };

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
        use std::os::unix::process::CommandExt;
        // New session + own process group so killpg(pid) contains the tree.
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return BoundedHookProcessResult {
                returncode: None,
                stdout: String::new(),
                stderr: String::new(),
                output_limit_exceeded: false,
                timed_out: false,
                containment_failed: false,
            }
        }
    };

    // start_hook_io: bounded stdout/stderr readers + a stdin writer.
    let bound = Arc::new(OutputBound {
        count: AtomicU64::new(0),
        limit: output_limit as u64,
        exceeded: AtomicBool::new(false),
    });
    let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let readers_done = Arc::new(AtomicBool::new(false));

    let mut io_handles: Vec<JoinHandle<()>> = Vec::new();
    let mut readers_pending = 2;
    if let Some(out) = child.stdout.take() {
        let d = readers_done.clone();
        io_handles.push(drain_stream(out, stdout_buf.clone(), bound.clone(), d));
    } else {
        readers_pending -= 1;
    }
    if let Some(err) = child.stderr.take() {
        let d = readers_done.clone();
        io_handles.push(drain_stream(err, stderr_buf.clone(), bound.clone(), d));
    } else {
        readers_pending -= 1;
    }
    if let Some(stdin) = child.stdin.take() {
        io_handles.push(write_input(stdin, input_text.as_bytes().to_vec()));
    }
    let _ = readers_pending;

    // wait_for_hook_process: poll stop / output-limit / deadline, terminate
    // the group on the first trigger, then reap.
    let mut timed_out = false;
    let mut termination_requested = false;
    let mut containment_confirmed = true;
    loop {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        if stop_event
            .as_ref()
            .is_some_and(|e| e.load(Ordering::SeqCst))
        {
            termination_requested = true;
            containment_confirmed = kill_process_group(&mut child);
            break;
        }
        if bound.exceeded.load(Ordering::SeqCst) {
            termination_requested = true;
            containment_confirmed = kill_process_group(&mut child);
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            termination_requested = true;
            containment_confirmed = kill_process_group(&mut child);
            break;
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
    let returncode = match child.wait_timeout(REAP_TIMEOUT) {
        Some(s) => s.code(),
        None => {
            containment_confirmed = kill_process_group(&mut child) && containment_confirmed;
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
        containment_confirmed = kill_process_group(&mut child) && containment_confirmed;
    }

    // join_and_cleanup_hook_process: join IO threads on a deadline; if a
    // reader is still alive past the final join the process is uncontained.
    let io_join_deadline = Instant::now() + IO_JOIN_TIMEOUT;
    for h in &io_handles {
        let _ = wait_handle(h, io_join_deadline);
    }
    if io_handles.iter().any(|h| !h.is_finished()) {
        if !termination_requested || !containment_confirmed {
            termination_requested = true;
            containment_confirmed = kill_process_group(&mut child) && containment_confirmed;
            let _ = termination_requested;
        }
        let final_join_deadline = Instant::now() + FINAL_IO_JOIN_TIMEOUT;
        for h in &io_handles {
            let _ = wait_handle(h, final_join_deadline);
        }
        if io_handles.iter().any(|h| !h.is_finished()) {
            containment_confirmed = false;
        }
    }
    if io_handles.iter().any(|h| !h.is_finished()) {
        containment_confirmed = false;
    }

    if !containment_confirmed {
        quarantine_child(child, readers_done);
    }
    // Drain joinable handles (they're detached-safe; finishing is enough).
    for h in io_handles {
        let _ = h.join();
    }

    let stdout_lock = stdout_buf.lock().unwrap_or_else(|e| e.into_inner());
    let stderr_lock = stderr_buf.lock().unwrap_or_else(|e| e.into_inner());
    let (stdout_decoded, stderr_decoded) =
        decode_combined_output(&stdout_lock, &stderr_lock, output_limit);
    drop(stdout_lock);
    drop(stderr_lock);

    BoundedHookProcessResult {
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
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn env() -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        e.insert(
            "PATH".to_string(),
            std::env::var("PATH").unwrap_or_default(),
        );
        e
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("hps-{}-{}-{}", std::process::id(), tag, n));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::canonicalize(&p).unwrap_or(p)
    }

    #[test]
    fn environment_allowlist_filters() {
        let mut src = BTreeMap::new();
        src.insert("HOME".to_string(), "/u".to_string());
        src.insert("LC_ALL".to_string(), "C".to_string());
        src.insert("AWS_SECRET".to_string(), "x".to_string());
        src.insert("LD_PRELOAD".to_string(), "/e.so".to_string());
        src.insert("PATH".to_string(), "/bin".to_string());
        let e = isolated_hook_environment(&src);
        assert!(e.contains_key("HOME"));
        assert!(e.contains_key("LC_ALL"));
        assert!(e.contains_key("PATH"));
        assert!(!e.contains_key("AWS_SECRET"));
        assert!(!e.contains_key("LD_PRELOAD"));
    }

    #[cfg(unix)]
    #[test]
    fn runs_simple_command_to_completion() {
        let dir = tmp_dir("simple");
        let result = run_isolated_hook_process(
            &["/bin/echo".to_string(), "hello".to_string()],
            "",
            &dir,
            &env(),
            Some(5.0),
            Some(1024),
            None,
            None,
        );
        assert_eq!(result.returncode, Some(0));
        assert!(!result.timed_out);
        assert!(!result.containment_failed);
        assert!(result.stdout.trim().contains("hello"));
    }

    #[cfg(unix)]
    #[test]
    fn deadline_kills_long_running_process() {
        let dir = tmp_dir("timeout");
        let start = Instant::now();
        let result = run_isolated_hook_process(
            &["/bin/sleep".to_string(), "10".to_string()],
            "",
            &dir,
            &env(),
            Some(0.5),
            Some(1024),
            None,
            None,
        );
        let elapsed = start.elapsed();
        assert!(result.timed_out);
        assert!(elapsed < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn output_limit_marks_exceeded() {
        let dir = tmp_dir("limit");
        // Emit well over the limit.
        let result = run_isolated_hook_process(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "head -c 20000 /dev/zero | tr '\\0' 'a'".to_string(),
            ],
            "",
            &dir,
            &env(),
            Some(5.0),
            Some(1024),
            None,
            None,
        );
        assert!(result.output_limit_exceeded);
    }

    #[cfg(unix)]
    #[test]
    fn process_group_kill_reaches_children() {
        // Spawn a shell that forks a grandchild; group kill must reap both.
        let dir = tmp_dir("group");
        let result = run_isolated_hook_process(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 30 & sleep 30".to_string(),
            ],
            "",
            &dir,
            &env(),
            Some(0.5),
            Some(1024),
            None,
            None,
        );
        assert!(result.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn stdin_input_reaches_child() {
        let dir = tmp_dir("stdin");
        let result = run_isolated_hook_process(
            &["/bin/cat".to_string()],
            "ping",
            &dir,
            &env(),
            Some(5.0),
            Some(1024),
            None,
            None,
        );
        assert_eq!(result.returncode, Some(0));
        assert!(result.stdout.contains("ping"));
    }

    #[test]
    fn nonexistent_command_returns_null_resultcode() {
        let dir = tmp_dir("badcmd");
        let result = run_isolated_hook_process(
            &["/definitely/not/a/binary".to_string()],
            "",
            &dir,
            &env(),
            Some(1.0),
            Some(64),
            None,
            None,
        );
        assert_eq!(result.returncode, None);
        assert!(!result.containment_failed);
    }

    // World-writable rejection uses Unix mode bits. Windows has no 0o777
    // equivalent in this helper, so the fixture cannot provoke the error.
    #[cfg(unix)]
    #[test]
    fn private_runtime_cwd_rejects_world_writable_dir() {
        let dir = tmp_dir("cwdpub");
        // 0o777 parent → not owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let manifest = dir.join("manifest.json");
        std::fs::write(&manifest, b"{}").unwrap();
        let r = private_hook_runtime_cwd(&manifest);
        assert!(r.is_err());
        // Restore for cleanup safety.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn guard_cli_command_pinned_bootstrap() {
        let cmd = isolated_guard_cli_command(
            "/usr/bin/python3",
            Path::new("/pkg/root"),
            &["guard".to_string(), "check".to_string()],
        );
        assert_eq!(cmd[0], "/usr/bin/python3");
        assert_eq!(cmd[1], "-I");
        assert_eq!(cmd[2], "-c");
        assert!(cmd[3].contains("codex_plugin_scanner.cli"));
        assert_eq!(cmd[4], "guard");
        assert_eq!(cmd[5], "check");
    }
}
