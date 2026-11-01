//! Bounded private SDK transport. No shell, inherited environment or PATH lookup.
use crate::{RuntimeError, RuntimeSelection};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const SCHEMA: &str = "guard-cigar-bridge.v1";
type Job = (Vec<u8>, SyncSender<Result<Vec<u8>, RuntimeError>>);

pub(crate) struct JsonProcess {
    child: Child,
    jobs: Option<SyncSender<Job>>,
    io_thread: Option<JoinHandle<()>>,
    next_id: u64,
    stopped: bool,
    cancel: Arc<AtomicBool>,
}

fn command(
    selection: &RuntimeSelection,
    script: &str,
    cancel: &AtomicBool,
) -> Result<Command, RuntimeError> {
    crate::private_python::check_selection(selection, None, Some(cancel))?;
    // Windows needs a qualified Job Object implementation before activation.
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(RuntimeError::PlatformUnqualified);
    }
    let mut cmd = Command::new(&selection.python);
    cmd.args(["-I", "-S", "-B", "-u", "-c", script])
        .env_clear()
        .current_dir(&selection.work_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    Ok(cmd)
}

impl JsonProcess {
    #[cfg(test)]
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
    #[cfg(test)]
    pub(crate) fn spawn(selection: &RuntimeSelection, script: &str) -> Result<Self, RuntimeError> {
        Self::spawn_cancellable(selection, script, Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn spawn_cancellable(
        selection: &RuntimeSelection,
        script: &str,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, RuntimeError> {
        if cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let mut cmd = command(selection, script, &cancel)?;
        cmd.arg(&selection.site_packages);
        let mut child = cmd.spawn().map_err(|_| RuntimeError::LaunchFailed)?;
        let mut stdin = child.stdin.take().ok_or(RuntimeError::LaunchFailed)?;
        let stdout = child.stdout.take().ok_or(RuntimeError::LaunchFailed)?;
        let (jobs, rx): (SyncSender<Job>, Receiver<Job>) = mpsc::sync_channel(1);
        let io_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            while let Ok((frame, reply)) = rx.recv() {
                let result = (|| {
                    stdin
                        .write_all(&frame)
                        .map_err(|_| RuntimeError::TransportFailed)?;
                    stdin.flush().map_err(|_| RuntimeError::TransportFailed)?;
                    let mut response = Vec::new();
                    reader
                        .by_ref()
                        .take((MAX_RESPONSE + 1) as u64)
                        .read_until(b'\n', &mut response)
                        .map_err(|_| RuntimeError::TransportFailed)?;
                    if response.len() > MAX_RESPONSE || !response.ends_with(b"\n") {
                        return Err(RuntimeError::TransportFailed);
                    }
                    Ok(response)
                })();
                let failed = result.is_err();
                let _ = reply.send(result);
                if failed {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            jobs: Some(jobs),
            io_thread: Some(io_thread),
            next_id: 0,
            stopped: false,
            cancel,
        })
    }

    pub(crate) fn rpc(&mut self, request: Value, timeout: Duration) -> Result<Value, RuntimeError> {
        if self.stopped {
            return Err(RuntimeError::RuntimeClosed);
        }
        if self.cancel.load(Ordering::Acquire) {
            self.stop();
            return Err(RuntimeError::Cancelled);
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RuntimeError::RuntimeClosed)?;
        let mut frame =
            serde_json::to_vec(&json!({"schema": SCHEMA, "id": self.next_id, "request": request}))
                .map_err(|_| RuntimeError::RequestInvalid)?;
        frame.push(b'\n');
        if frame.len() > MAX_REQUEST {
            return Err(RuntimeError::RequestTooLarge);
        }
        let (tx, rx) = mpsc::sync_channel(1);
        self.jobs
            .as_ref()
            .ok_or(RuntimeError::RuntimeClosed)?
            .try_send((frame, tx))
            .map_err(|_| RuntimeError::Busy)?;
        let result = receive(&rx, timeout, &self.cancel)
            .and_then(|value| value)
            .and_then(|bytes| self.decode(&bytes));
        // Unknown outcomes close the whole bridge/domain. The caller must
        // rebuild/reconcile rather than retry a mutation against hidden state.
        if matches!(
            result,
            Err(RuntimeError::DeadlineExceeded
                | RuntimeError::TransportFailed
                | RuntimeError::Cancelled)
        ) {
            self.stop();
        }
        result
    }

    fn decode(&self, bytes: &[u8]) -> Result<Value, RuntimeError> {
        let response: Value =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::TransportFailed)?;
        if response["schema"] != SCHEMA || response["id"].as_u64() != Some(self.next_id) {
            return Err(RuntimeError::TransportFailed);
        }
        match response["ok"].as_bool() {
            Some(true) => response
                .get("result")
                .cloned()
                .ok_or(RuntimeError::TransportFailed),
            Some(false) => match response["error"].as_str() {
                Some("AccessDenied") => Err(RuntimeError::ScopeDenied),
                Some("Closed") => Err(RuntimeError::RuntimeClosed),
                Some("Stale" | "Expired") => Err(RuntimeError::ContextStale),
                Some("Conflict") => Err(RuntimeError::ContextConflict),
                Some("Quota") => Err(RuntimeError::ResourceLimit),
                Some(
                    "RequiredUnavailable"
                    | "BudgetUnsatisfiable"
                    | "InvalidInput"
                    | "LimitExceeded"
                    | "Integrity"
                    | "BaseMismatch",
                ) => Err(RuntimeError::WorkerRejected),
                _ => Err(RuntimeError::TransportFailed),
            },
            _ => Err(RuntimeError::TransportFailed),
        }
    }

    pub(crate) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.jobs.take();
        terminate(&mut self.child);
        if self.io_thread.as_ref().is_some_and(|t| t.is_finished()) {
            if let Some(thread) = self.io_thread.take() {
                let _ = thread.join();
            }
        }
    }
}

// Keep exclusive child wait custody; signal before reap so this process-group
// identifier cannot be reused. The bundled SDK workers inherit the group.
fn terminate(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(id) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(id),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for JsonProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn probe(
    selection: &RuntimeSelection,
    script: &str,
    cancel: &AtomicBool,
) -> Result<Value, RuntimeError> {
    if cancel.load(Ordering::Acquire) {
        return Err(RuntimeError::Cancelled);
    }
    let mut cmd = command(selection, script, cancel)?;
    cmd.stdin(Stdio::null());
    let mut child = cmd.spawn().map_err(|_| RuntimeError::LaunchFailed)?;
    let stdout = child.stdout.take().ok_or(RuntimeError::LaunchFailed)?;
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout.take(64 * 1024 + 1).read_to_end(&mut bytes);
        let _ = tx.send(read.map(|_| bytes));
    });
    let result = receive(&rx, Duration::from_secs(3), cancel);
    terminate(&mut child);
    let bytes = result?.map_err(|_| RuntimeError::TransportFailed)?;
    if bytes.len() > 64 * 1024 {
        return Err(RuntimeError::TransportFailed);
    }
    serde_json::from_slice(&bytes).map_err(|_| RuntimeError::TransportFailed)
}

fn receive<T>(rx: &Receiver<T>, timeout: Duration, cancel: &AtomicBool) -> Result<T, RuntimeError> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RuntimeError::DeadlineExceeded);
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(value) => return Ok(value),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(RuntimeError::TransportFailed),
        }
    }
}
