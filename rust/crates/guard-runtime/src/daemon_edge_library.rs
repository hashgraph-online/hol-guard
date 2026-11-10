//! Guard library calls the daemon makes through a short-lived Guard CLI
//! process (`desktop library-call`).
//!
//! The daemon owns every route; work that still lives in the Python library
//! (approval resolution, scope contracts, continuations) runs as one call:
//! `{"call": name, "args": {...}}` on standard input, and `{"ok": value}` or
//! `{"error": {"kind": ..., ...}}` on standard output. The daemon writes the
//! status and body from that answer.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::reads::ReadConfig;
use crate::onefile_open_paths::{isolate_group, kill_group};

/// How long one call may take: an approval may wait on the approval gate.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest answer a call may print.
const MAX_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// Why a library call gave no value.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum CallError {
    /// No CLI to run, or it did not answer in time with one JSON object.
    /// Nothing is known to have happened, so the request can be relayed.
    Unavailable,
    /// The call raised: `{"kind", "type", "message", ...}`.
    Raised(Map<String, Value>),
}

#[cfg(test)]
impl CallError {
    /// The kind the library named for a raised error.
    pub(in crate::daemon_edge) fn kind(&self) -> Option<&str> {
        match self {
            Self::Unavailable => None,
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
    let request = serde_json::to_vec(&json!({"call": name, "args": args}))
        .map_err(|_| CallError::Unavailable)?;
    let answer = run(config, request).ok_or(CallError::Unavailable)?;
    decode(&answer)
}

/// The value or error one answer carries.
pub(in crate::daemon_edge) fn decode(answer: &[u8]) -> Result<Value, CallError> {
    let Ok(Value::Object(mut answer)) = serde_json::from_slice::<Value>(answer) else {
        return Err(CallError::Unavailable);
    };
    if let Some(value) = answer.remove("ok") {
        return Ok(value);
    }
    match answer.remove("error") {
        Some(Value::Object(error)) => Err(CallError::Raised(error)),
        _ => Err(CallError::Unavailable),
    }
}

/// The CLI arguments for one call.
pub(in crate::daemon_edge) fn call_args(guard_home: &str) -> [String; 4] {
    [
        "desktop".to_owned(),
        "library-call".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
    ]
}

fn run(config: &ReadConfig, request: Vec<u8>) -> Option<Vec<u8>> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(call_args(guard_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(child);
        return None;
    };
    thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout
            .take(MAX_ANSWER_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_ok();
        let _ = sender.send(read.then_some(bytes));
    });
    match receiver.recv_timeout(CALL_TIMEOUT) {
        Ok(Some(bytes)) if bytes.len() as u64 <= MAX_ANSWER_BYTES => {
            thread::spawn(move || {
                let _ = child.wait();
            });
            Some(bytes)
        }
        _ => {
            stop(child);
            None
        }
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
/// starting) never holds up the others.
struct Resident {
    child: Mutex<Option<Child>>,
    input: Mutex<ChildStdin>,
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
    let mut request = serde_json::to_vec(&json!({"id": id, "call": name, "args": args}))
        .map_err(|_| CallError::Unavailable)?;
    request.push(b'\n');
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
    let written = registered && {
        let mut input = resident
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        input
            .write_all(&request)
            .and_then(|()| input.flush())
            .is_ok()
    };
    let answer = if written {
        receiver.recv_timeout(wait.min(CALL_TIMEOUT)).ok()
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
                return Err(CallError::Unavailable);
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
            Err(CallError::Unavailable)
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
        input: Mutex::new(input),
        pending,
        next_id: AtomicU64::new(1),
    })
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
        let _ = thread::Builder::new()
            .name("daemon-worker-host-output".into())
            .spawn(move || {
                let mut lines = BufReader::new(output);
                let mut line = String::new();
                if lines.read_line(&mut line).is_ok() && line.trim_end() == "ready" {
                    if let Some(ready) = ready {
                        let _ = ready.send(());
                    }
                }
                // Anything later is drained so the host never blocks on it.
                let _ = std::io::copy(&mut lines, &mut std::io::sink());
            });
    }
    let _ = child.wait();
    Some(())
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
