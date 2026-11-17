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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
/// Call bytes that may wait for the resident to read them. A resident that
/// stops reading fills this, and the next call replaces it rather than
/// letting abandoned calls pile up in memory.
const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;

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
    input: mpsc::Sender<Queued>,
    queued_bytes: Arc<AtomicUsize>,
    pending: Arc<Mutex<Pending>>,
    next_id: AtomicU64,
}

/// One call waiting for the writer. Its deadline travels with it: the writer
/// drops a call whose caller has already given up, and tells the process how
/// long is left when it writes the line, not when the call was queued.
struct Queued {
    id: u64,
    deadline: Instant,
    call: Vec<u8>,
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
    let call = call_body(name, &args).ok_or(CallError::Unavailable)?;
    let size = call.len();
    let deadline = deadline.min(Instant::now() + CALL_TIMEOUT);
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
    // A full queue means the process stopped reading: the call is refused
    // and the process replaced, as for one that closed its input.
    let room = registered
        && resident
            .queued_bytes
            .fetch_add(size, Ordering::SeqCst)
            .saturating_add(size)
            <= MAX_QUEUED_BYTES;
    let written = room && resident.input.send(Queued { id, deadline, call }).is_ok();
    if registered && !written {
        resident.queued_bytes.fetch_sub(size, Ordering::SeqCst);
    }
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
    let (lines, queued) = mpsc::channel::<Queued>();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let written_bytes = Arc::clone(&queued_bytes);
    let writer = thread::Builder::new()
        .name("daemon-library-writer".into())
        .spawn(move || {
            let mut input = input;
            for call in queued {
                written_bytes.fetch_sub(call.call.len(), Ordering::SeqCst);
                let left = call.deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    continue;
                }
                let head = request_head(call.id, left);
                if input
                    .write_all(&head)
                    .and_then(|()| input.write_all(&call.call))
                    .and_then(|()| input.flush())
                    .is_err()
                {
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
        queued_bytes,
        pending,
        next_id: AtomicU64::new(1),
    })
}

/// One call line: `expires_in_ms` comes before the arguments so the process
/// can drop a call its caller has stopped waiting for without decoding it.
#[cfg(test)]
fn request_line(id: u64, expires_in: Duration, name: &str, args: &Value) -> Option<Vec<u8>> {
    let mut line = request_head(id, expires_in);
    line.extend(call_body(name, args)?);
    Some(line)
}

/// The start of a call line: its id, then how long its caller still waits,
/// so the process can drop it unrun once that has passed.
fn request_head(id: u64, expires_in: Duration) -> Vec<u8> {
    format!(
        "{{\"id\":{id},\"expires_in_ms\":{},",
        expires_in.as_millis()
    )
    .into_bytes()
}

/// The rest of a call line: the call and its arguments.
fn call_body(name: &str, args: &Value) -> Option<Vec<u8>> {
    let mut body = b"\"call\":".to_vec();
    serde_json::to_writer(&mut body, name).ok()?;
    body.extend_from_slice(b",\"args\":");
    serde_json::to_writer(&mut body, args).ok()?;
    body.extend_from_slice(b"}\n");
    Some(body)
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
