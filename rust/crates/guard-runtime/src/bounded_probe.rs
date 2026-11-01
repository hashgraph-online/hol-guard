//! `bounded-probe --stdin`: run one probe command with no stdin, a hard
//! deadline and a bounded share of output
//! (`guard/adapters/hook_python_subprocess.py` frames the request).
//!
//! - Off Windows the probe leads its own process group. A timeout, an output
//!   overrun, or a pipe a descendant still holds open at the deadline kills
//!   the whole group.
//! - On Windows the probe starts suspended inside a job object, and the job is
//!   terminated once the probe exits or overruns its budget.
//! - stdout and stderr share one byte budget. The bytes kept before an overrun
//!   are returned base64 encoded.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "bounded-probe.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 128 * 1024;
const MAX_TIMEOUT_SECONDS: f64 = 3600.0;
const MAX_ARGUMENTS: usize = 256;
const MAX_ENVIRONMENT: usize = 256;
#[cfg(unix)]
const REAP_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(unix)]
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    argv: Vec<String>,
    cwd: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    timeout_seconds: f64,
    output_limit_bytes: usize,
}

struct Probe {
    returncode: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    output_overflow: bool,
    capture_incomplete: bool,
}

impl Probe {
    fn to_json(&self) -> Value {
        let engine = base64::engine::general_purpose::STANDARD;
        json!({
            "returncode": self.returncode,
            "stdout": engine.encode(&self.stdout),
            "stderr": engine.encode(&self.stderr),
            "timed_out": self.timed_out,
            "output_overflow": self.output_overflow,
            "capture_incomplete": self.capture_incomplete,
        })
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "bounded-probe"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "bounded_probe_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("bounded_probe_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    validate(&request)?;
    let deadline = Instant::now() + Duration::from_secs_f64(request.timeout_seconds);
    let answer = match run(&request, deadline) {
        Ok(probe) => probe.to_json(),
        Err(()) => json!({ "error": "execution_failed" }),
    };
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "bounded_probe_request_invalid".to_owned()
}

fn validate(request: &Request) -> Result<(), String> {
    let timeout = request.timeout_seconds;
    let valid = request.schema == SCHEMA
        && !request.argv.is_empty()
        && request.argv.len() <= MAX_ARGUMENTS
        && request.env.len() <= MAX_ENVIRONMENT
        && Path::new(&request.cwd).is_absolute()
        && timeout.is_finite()
        && timeout > 0.0
        && timeout <= MAX_TIMEOUT_SECONDS
        && (1..=MAX_OUTPUT_BYTES).contains(&request.output_limit_bytes);
    if valid {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(unix)]
mod capture {
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    /// The output both streams share, and whether either overran it or
    /// failed to read.
    pub(super) struct Budget {
        limit: usize,
        streams: Mutex<[Vec<u8>; 2]>,
        pub(super) overflow: AtomicBool,
        pub(super) failed: AtomicBool,
    }

    impl Budget {
        pub(super) fn new(limit: usize) -> Arc<Self> {
            Arc::new(Self {
                limit,
                streams: Mutex::new([Vec::new(), Vec::new()]),
                overflow: AtomicBool::new(false),
                failed: AtomicBool::new(false),
            })
        }

        /// Keep what fits of `chunk` for stream `index`; `false` once the
        /// budget is spent.
        fn retain(&self, index: usize, chunk: &[u8]) -> bool {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let retained = streams[0].len() + streams[1].len();
            let kept = chunk.len().min(self.limit.saturating_sub(retained));
            streams[index].extend_from_slice(&chunk[..kept]);
            if kept != chunk.len() {
                self.overflow.store(true, Ordering::SeqCst);
                return false;
            }
            true
        }

        pub(super) fn take(&self) -> [Vec<u8>; 2] {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *streams)
        }
    }

    pub(super) fn drain(
        mut stream: impl Read + Send + 'static,
        index: usize,
        budget: Arc<Budget>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut chunk = [0_u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => return,
                    Ok(count) => {
                        if !budget.retain(index, &chunk[..count]) {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        budget.failed.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            }
        })
    }
}

/// `SIGKILL` the probe's process group; `false` when the signal could not
/// be delivered for a reason other than the group being gone.
#[cfg(unix)]
fn kill_group(child: &std::process::Child) -> bool {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;
    let Ok(group) = i32::try_from(child.id()) else {
        return false;
    };
    match killpg(Pid::from_raw(group), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => true,
        Err(_) => false,
    }
}

#[cfg(unix)]
fn run(request: &Request, deadline: Instant) -> Result<Probe, ()> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;

    let mut child = Command::new(&request.argv[0])
        .args(&request.argv[1..])
        .current_dir(&request.cwd)
        .env_clear()
        .envs(&request.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| ())?;
    let budget = capture::Budget::new(request.output_limit_bytes);
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(capture::drain(stdout, 0, budget.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(capture::drain(stderr, 1, budget.clone()));
    }
    let mut status = None;
    let mut timed_out = false;
    let mut capture_incomplete = false;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(found) => status = found,
                Err(_) => capture_incomplete = true,
            }
        }
        let drained = readers.iter().all(|reader| reader.is_finished());
        if budget.overflow.load(Ordering::SeqCst) || (status.is_some() && drained) {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let overflow = budget.overflow.load(Ordering::SeqCst);
    if (status.is_none() || timed_out || overflow) && !kill_group(&child) {
        capture_incomplete = true;
        let _ = child.kill();
    }
    let reap_deadline = Instant::now() + REAP_TIMEOUT;
    while status.is_none() && Instant::now() < reap_deadline {
        match child.try_wait() {
            Ok(found) => status = found,
            Err(_) => break,
        }
        if status.is_none() {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    while readers.iter().any(|reader| !reader.is_finished()) && Instant::now() < reap_deadline {
        std::thread::sleep(POLL_INTERVAL);
    }
    capture_incomplete = capture_incomplete
        || status.is_none()
        || budget.failed.load(Ordering::SeqCst)
        || readers.iter().any(|reader| !reader.is_finished());
    for reader in readers {
        if reader.is_finished() {
            let _ = reader.join();
        }
    }
    let [stdout, stderr] = budget.take();
    let returncode = status.map_or(-1, |status| {
        status
            .code()
            .unwrap_or_else(|| status.signal().map_or(-1, |signal| -signal))
    });
    Ok(Probe {
        returncode,
        stdout,
        stderr,
        timed_out,
        output_overflow: overflow,
        capture_incomplete,
    })
}

#[cfg(windows)]
fn run(request: &Request, deadline: Instant) -> Result<Probe, ()> {
    use std::ffi::{OsStr, OsString};
    use std::sync::atomic::AtomicBool;

    let args: Vec<&OsStr> = request.argv[1..].iter().map(OsStr::new).collect();
    let environment: Vec<(OsString, OsString)> = request
        .env
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect();
    let cancellation = AtomicBool::new(false);
    let output = guard_runtime_windows_process::capture_managed_child(
        guard_runtime_windows_process::CaptureCommand {
            executable: Path::new(&request.argv[0]),
            args: &args,
            cwd: Path::new(&request.cwd),
            environment: &environment,
        },
        &[],
        request.output_limit_bytes,
        deadline,
        &cancellation,
    )
    .map_err(|_| ())?;
    Ok(Probe {
        returncode: output.exit_code.unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        timed_out: output.timed_out,
        output_overflow: output.output_limited,
        capture_incomplete: output.cancelled,
    })
}

#[cfg(not(any(unix, windows)))]
fn run(_request: &Request, _deadline: Instant) -> Result<Probe, ()> {
    Err(())
}

#[cfg(test)]
#[path = "bounded_probe_tests.rs"]
mod tests;
