//! Guard library calls the daemon makes through the resident Guard CLI
//! process (`desktop library-serve`).
//!
//! The daemon owns every route; work that still lives in the Python library
//! (approval resolution, scope contracts, continuations) runs as one call:
//! `{"id": n, "call": name, "args": {...}}` on one line of standard input, and
//! `{"ok": value}` or `{"error": {"kind": ..., ...}}` on standard output. The daemon writes the
//! status and body from that answer.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use super::reads::ReadConfig;
use crate::onefile_open_paths::{isolate_group, kill_group};

/// How long one call may take: an approval may wait on the approval gate.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest answer a call may print.
const MAX_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// Why a library call gave no value.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum CallError {
    /// No CLI to run, or the call never reached it. Nothing has happened,
    /// so the request can be relayed.
    Unavailable,
    /// The call reached the library but no answer came back in time as one
    /// JSON object. It may have run, so the request must not be replayed.
    NoAnswer,
    /// The call raised: `{"kind", "type", "message", ...}`.
    Raised(Map<String, Value>),
}

#[cfg(test)]
impl CallError {
    /// The kind the library named for a raised error.
    pub(in crate::daemon_edge) fn kind(&self) -> Option<&str> {
        match self {
            Self::Unavailable | Self::NoAnswer => None,
            Self::Raised(error) => error.get("kind").and_then(Value::as_str),
        }
    }
}

/// Runs `call` with `args` and returns its value.
pub(in crate::daemon_edge) fn call(
    config: &ReadConfig,
    name: &str,
    args: Value,
) -> Result<Value, CallError> {
    call_resident(config, name, args)
}

/// The value or error one answer carries.
pub(in crate::daemon_edge) fn decode(answer: &[u8]) -> Result<Value, CallError> {
    let Ok(Value::Object(mut answer)) = serde_json::from_slice::<Value>(answer) else {
        return Err(CallError::NoAnswer);
    };
    if let Some(value) = answer.remove("ok") {
        return Ok(value);
    }
    match answer.remove("error") {
        Some(Value::Object(error)) => Err(CallError::Raised(error)),
        _ => Err(CallError::NoAnswer),
    }
}

/// The CLI arguments for the resident library process.
pub(in crate::daemon_edge) fn serve_args(guard_home: &str) -> [String; 4] {
    [
        "desktop".to_owned(),
        "library-serve".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
    ]
}

/// One `desktop library-serve` child. Each call goes in as one line carrying
/// an `id`, and its answer comes back as one line with the same `id`, in
/// whatever order the calls finish, so a slow call (a browser sign-in
/// starting) never holds up the others. Call lines go to the process through
/// one writer thread, so a caller hands its line over and waits only on its
/// own deadline, never on the pipe: a burst of calls cannot hold every
/// connection thread in a write while the process catches up.
struct Resident {
    child: Mutex<Option<Child>>,
    input: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<Pending>>,
    next_id: AtomicU64,
}

/// The callers waiting on a resident's answers, by call id. `None` once its
/// output has ended, so a late caller is told at once.
type Pending = Option<HashMap<u64, mpsc::Sender<Vec<u8>>>>;

impl Resident {
    fn stop(&self) {
        let child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(child) = child {
            stop(child);
        }
    }
}

/// The resident process for each Guard home this daemon has served.
fn residents() -> &'static Mutex<HashMap<String, Arc<Resident>>> {
    static RESIDENTS: OnceLock<Mutex<HashMap<String, Arc<Resident>>>> = OnceLock::new();
    RESIDENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Runs `call` with `args` in the resident library process, whose state
/// outlives one request: an extension-control preview's proof waits there for
/// its apply, and a Guard Cloud sign-in another request started is joined
/// rather than started twice. Calls run side by side. A process that does
/// not answer one in time is stopped and the next call starts another.
pub(in crate::daemon_edge) fn call_resident(
    config: &ReadConfig,
    name: &str,
    args: Value,
) -> Result<Value, CallError> {
    call_resident_within(config, name, args, CALL_TIMEOUT)
}

/// `call_resident` for a caller with its own deadline. A call that outlasts
/// a wait shorter than the usual one is given up on without stopping the
/// resident: the hook it served is answered fail-safe, and the process and
/// its caches stay for the next hook.
pub(in crate::daemon_edge) fn call_resident_within(
    config: &ReadConfig,
    name: &str,
    args: Value,
    wait: Duration,
) -> Result<Value, CallError> {
    // One budget covers both attempts, including the time either spends
    // finding or starting a process before it sends the call.
    let deadline = Instant::now() + wait;
    match call_resident_once(config, name, args.clone(), wait, deadline) {
        // The process was already gone, so the call never reached it. Under
        // host load a child that died (or was stopped by an earlier call that
        // gave up on it) is the usual reason the next hook found no resident;
        // the replacement starts here instead of failing this hook and
        // leaving the start to the one after it. A call that was delivered and
        // then lost its answer is not repeated: it may have run.
        Err(CallError::Unavailable) => {
            if Instant::now() >= deadline {
                return Err(CallError::Unavailable);
            }
            call_resident_once(config, name, args, wait, deadline)
        }
        other => other,
    }
}

fn call_resident_once(
    config: &ReadConfig,
    name: &str,
    args: Value,
    wait: Duration,
    deadline: Instant,
) -> Result<Value, CallError> {
    let (_, guard_home, _) = config.cli().ok_or(CallError::Unavailable)?;
    let guard_home = guard_home.to_owned();
    let resident = {
        let mut residents = residents()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match residents.get(&guard_home) {
            Some(resident) => Arc::clone(resident),
            None => {
                let resident = Arc::new(start_resident(config).ok_or(CallError::Unavailable)?);
                residents.insert(guard_home.clone(), Arc::clone(&resident));
                resident
            }
        }
    };
    let id = resident.next_id.fetch_add(1, Ordering::Relaxed);
    let expires_in = deadline
        .saturating_duration_since(Instant::now())
        .min(CALL_TIMEOUT);
    let request = request_line(id, expires_in, name, &args).ok_or(CallError::Unavailable)?;
    let (sender, receiver) = mpsc::channel();
    let registered = match resident
        .pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        Some(pending) => {
            pending.insert(id, sender);
            true
        }
        None => false,
    };
    let written = registered && resident.input.send(request).is_ok();
    let answer = if written {
        receiver
            .recv_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(CALL_TIMEOUT),
            )
            .ok()
    } else {
        None
    };
    match answer {
        Some(answer) => decode(&answer),
        None => {
            if let Some(pending) = resident
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                pending.remove(&id);
            }
            if written && wait < CALL_TIMEOUT {
                return Err(CallError::NoAnswer);
            }
            let mut residents = residents()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if residents
                .get(&guard_home)
                .is_some_and(|current| Arc::ptr_eq(current, &resident))
            {
                residents.remove(&guard_home);
            }
            drop(residents);
            resident.stop();
            Err(if written {
                CallError::NoAnswer
            } else {
                CallError::Unavailable
            })
        }
    }
}

fn start_resident(config: &ReadConfig) -> Option<Resident> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(serve_args(guard_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    let (Some(input), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(child);
        return None;
    };
    let (lines, queued) = mpsc::channel::<Vec<u8>>();
    let writer = thread::Builder::new()
        .name("daemon-library-writer".into())
        .spawn(move || {
            let mut input = input;
            for line in queued {
                if input.write_all(&line).and_then(|()| input.flush()).is_err() {
                    break;
                }
            }
            // Returning closes the process's input; ending early also drops
            // the queue, so the next caller is told the process is gone.
        });
    if writer.is_err() {
        stop(child);
        return None;
    }
    let pending: Arc<Mutex<Pending>> = Arc::new(Mutex::new(Some(HashMap::new())));
    let answers = Arc::clone(&pending);
    thread::spawn(move || {
        let mut lines = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            let read = (&mut lines)
                .take(MAX_ANSWER_BYTES + 1)
                .read_until(b'\n', &mut line);
            if !matches!(read, Ok(read) if read > 0 && line.last() == Some(&b'\n')) {
                break;
            }
            let Some(id) = answer_id(&line) else {
                continue;
            };
            let waiter = answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .and_then(|pending| pending.remove(&id));
            if let Some(waiter) = waiter {
                let _ = waiter.send(line);
            }
        }
        // Dropping every waiter's sender tells it the process is gone.
        answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    });
    Some(Resident {
        child: Mutex::new(Some(child)),
        input: lines,
        pending,
        next_id: AtomicU64::new(1),
    })
}

/// One call line: `expires_in_ms` comes before the arguments so the process
/// can drop a call its caller has stopped waiting for without decoding it.
fn request_line(id: u64, expires_in: Duration, name: &str, args: &Value) -> Option<Vec<u8>> {
    let mut line = format!(
        "{{\"id\":{id},\"expires_in_ms\":{},\"call\":",
        expires_in.as_millis()
    )
    .into_bytes();
    serde_json::to_writer(&mut line, name).ok()?;
    line.extend_from_slice(b",\"args\":");
    serde_json::to_writer(&mut line, args).ok()?;
    line.extend_from_slice(b"}\n");
    Some(line)
}

/// The call id an answer line names.
fn answer_id(line: &[u8]) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Head {
        id: u64,
    }
    serde_json::from_slice::<Head>(line)
        .ok()
        .map(|head| head.id)
}

/// The CLI arguments for the worker host.
pub(in crate::daemon_edge) fn host_args(guard_home: &str) -> [String; 4] {
    [
        "desktop".to_owned(),
        "daemon-workers".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
    ]
}

/// Runs the worker host until it exits and returns `None` when it could not
/// be started. Its standard input stays open while this process lives.
/// `ready` hears once the host has made its first policy publication.
pub(in crate::daemon_edge) fn run_host(
    config: &ReadConfig,
    ready: Option<mpsc::Sender<()>>,
) -> Option<()> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(host_args(guard_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    // Held, never written: the host stops when this end closes.
    let _input = child.stdin.take();
    if let Some(output) = child.stdout.take() {
        let journal = std::path::PathBuf::from(guard_home);
        let _ = thread::Builder::new()
            .name("daemon-worker-host-output".into())
            .spawn(move || {
                let mut lines = BufReader::new(output);
                read_host_start(&mut lines, &journal, ready);
                // Anything later is drained so the host never blocks on it.
                let _ = std::io::copy(&mut lines, &mut std::io::sink());
            });
    }
    let _ = child.wait();
    Some(())
}

/// The most start steps one host may journal before it says `ready`.
const MAX_HOST_PHASES: usize = 16;

/// Reads the host's start lines up to `ready`. Each `phase <step>` line is
/// journaled as `host_<step>`, so a slow start names the step that spent it;
/// `ready` is heard once, and any other line ends the start without it.
pub(in crate::daemon_edge) fn read_host_start(
    lines: &mut impl BufRead,
    guard_home: &std::path::Path,
    ready: Option<mpsc::Sender<()>>,
) {
    let mut line = String::new();
    for _ in 0..=MAX_HOST_PHASES {
        line.clear();
        if !matches!(lines.read_line(&mut line), Ok(read) if read > 0) {
            return;
        }
        let text = line.trim_end();
        if text == "ready" {
            if let Some(ready) = ready {
                let _ = ready.send(());
            }
            return;
        }
        let Some(step) = text.strip_prefix("phase ") else {
            return;
        };
        super::lifecycle::record(guard_home, &format!("host_{step}"), None, None, None);
    }
}

fn stop(mut child: Child) {
    kill_group(&child);
    let _ = child.kill();
    thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_library_tests.rs"]
mod tests;
