//! One serialized line-JSON pipe to a worker child process.
//!
//! The child is this executable started in worker mode, so there is no second
//! binary to find or verify. Each call has a deadline; a timeout, a broken or
//! oversized reply, or a reply that does not decode closes the channel,
//! because the worker may already have applied the command and its stream can
//! no longer be trusted to line up with the next request.

use crate::frames::read_line;
use serde_json::{json, Value};
use std::io::{BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// Largest request line the host side of the worker accepts.
pub(crate) const MAX_HOST_FRAME: usize = 32 * 1024 * 1024;
/// Largest reply line the host side of the worker sends.
pub(crate) const MAX_HOST_RESPONSE: usize = 64 * 1024 * 1024;
/// Per-call deadline, matching what the Python adapters used.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(3);
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// Turns one decoded reply into a result or a content-free error code.
/// `Err(None)` means the reply was malformed and the channel must close.
pub(crate) type Decode = fn(&Value, u32) -> Result<Value, Option<&'static str>>;

pub(crate) struct Channel {
    child: Child,
    frames: Option<Sender<Vec<u8>>>,
    replies: Receiver<Option<Vec<u8>>>,
    next_id: u32,
    closed: bool,
    decode: Decode,
}

impl Channel {
    /// Start `<this executable> __guard-cigar-worker [extra]`.
    pub(crate) fn spawn(extra: &[&str], decode: Decode) -> Result<Self, &'static str> {
        let program = std::env::current_exe().map_err(|_| "WorkerUnavailable")?;
        let mut command = Command::new(program);
        command
            .arg(crate::WORKER_COMMAND)
            .args(extra)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
            // Winsock cannot load its providers without SystemRoot, and the
            // broker worker listens on loopback.
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
        }
        let mut child = command.spawn().map_err(|_| "WorkerUnavailable")?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("WorkerUnavailable");
        };
        let frames = spawn_writer(stdin);
        let (reply_tx, replies) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let line = read_line(&mut reader, MAX_HOST_RESPONSE);
                let end = line.is_none();
                if reply_tx.send(line).is_err() || end {
                    return;
                }
            }
        });
        Ok(Self {
            child,
            frames: Some(frames),
            replies,
            next_id: 0,
            closed: false,
            decode,
        })
    }

    /// Send one command and wait for its reply.
    pub(crate) fn call(&mut self, command: Value) -> Result<Value, &'static str> {
        if self.closed {
            return Err("Closed");
        }
        let deadline = Instant::now() + CALL_TIMEOUT;
        self.next_id = (self.next_id % u32::MAX) + 1;
        let id = self.next_id;
        let mut frame = serde_json::to_vec(&json!({"id": id, "command": command}))
            .map_err(|_| "InvalidInput")?;
        frame.push(b'\n');
        if frame.len() > MAX_HOST_FRAME {
            return Err("LimitExceeded");
        }
        let sent = self
            .frames
            .as_ref()
            .is_some_and(|frames| frames.send(frame).is_ok());
        if !sent {
            self.abort();
            return Err("Transport");
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        let line = match self.replies.recv_timeout(wait) {
            Ok(Some(line)) => line,
            Err(RecvTimeoutError::Timeout) => {
                self.abort();
                return Err("Timeout");
            }
            Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                self.abort();
                return Err("Transport");
            }
        };
        let decoded = serde_json::from_slice::<Value>(&line)
            .map_err(|_| None)
            .and_then(|reply| (self.decode)(&reply, id));
        match decoded {
            Ok(result) => Ok(result),
            Err(Some(code)) => Err(code),
            Err(None) => {
                self.abort();
                Err("Transport")
            }
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// Kill the worker at once, for a call whose outcome is unknown.
    fn abort(&mut self) {
        self.closed = true;
        self.frames = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// End the worker: close its input so it can finish and exit, then kill
    /// it if it has not exited after a short grace period.
    pub(crate) fn close(&mut self) {
        if self.closed {
            let _ = self.child.try_wait();
            return;
        }
        self.closed = true;
        self.frames = None;
        let deadline = Instant::now() + CLOSE_GRACE;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.close();
    }
}

/// Writes frames on their own thread, so a worker that stops reading cannot
/// hold a call past its deadline. Dropping the sender closes the worker's stdin.
fn spawn_writer(mut stdin: ChildStdin) -> Sender<Vec<u8>> {
    let (frames, jobs) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        while let Ok(frame) = jobs.recv() {
            if stdin
                .write_all(&frame)
                .and_then(|()| stdin.flush())
                .is_err()
            {
                return;
            }
        }
    });
    frames
}
