//! Bounded, independently cancellable writes to a persistent MCP child.
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

type WriteRequest = (Vec<u8>, mpsc::Sender<Result<(), String>>);
const POLL: Duration = Duration::from_millis(25);

pub(super) struct SessionWriter {
    requests: mpsc::SyncSender<WriteRequest>,
}

impl SessionWriter {
    pub(super) fn spawn(mut stdin: impl Write + Send + 'static) -> Result<Self, String> {
        let (requests, receiver) = mpsc::sync_channel::<WriteRequest>(1);
        std::thread::Builder::new()
            .name("guard-mcp-stdin".to_owned())
            .spawn(move || {
                while let Ok((frame, reply)) = receiver.recv() {
                    let result = stdin
                        .write_all(&frame)
                        .and_then(|_| stdin.flush())
                        .map_err(|_| "child_write_failed".to_owned());
                    let failed = result.is_err();
                    let _ = reply.send(result);
                    if failed {
                        break;
                    }
                }
            })
            .map_err(|_| "child_writer_unavailable".to_owned())?;
        Ok(Self { requests })
    }

    /// Completion, not queue admission, acknowledges a frame. On any error the
    /// session owner cancels and kills the child: a partial frame is not retried.
    pub(super) fn write(
        &self,
        frame: Vec<u8>,
        cancellation: &Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<(), String> {
        if cancellation.load(Ordering::Acquire) {
            return Err("session_cancelled".to_owned());
        }
        let (reply, completion) = mpsc::channel();
        self.requests
            .try_send((frame, reply))
            .map_err(|_| "child_writer_unavailable".to_owned())?;
        let deadline = Instant::now() + timeout;
        loop {
            if cancellation.load(Ordering::Acquire) {
                return Err("session_cancelled".to_owned());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("child_write_timeout".to_owned());
            }
            match completion.recv_timeout(remaining.min(POLL)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("child_write_failed".to_owned())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct BlockedWriter(mpsc::Receiver<()>);
    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn blocked_writer_obeys_deadline() {
        let (release, wait) = mpsc::channel();
        let writer = SessionWriter::spawn(BlockedWriter(wait)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let result = writer.write(vec![1], &cancel, Duration::from_millis(40));
        let _ = release.send(());
        assert_eq!(result.unwrap_err(), "child_write_timeout");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn blocked_writer_observes_independent_cancel() {
        let (release, wait) = mpsc::channel();
        let writer = SessionWriter::spawn(BlockedWriter(wait)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancel);
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            signal.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let result = writer.write(vec![1], &cancel, Duration::from_secs(10));
        let _ = release.send(());
        thread.join().unwrap();
        assert_eq!(result.unwrap_err(), "session_cancelled");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn successful_write_is_acknowledged_after_flush() {
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = SessionWriter::spawn(Capture(Arc::clone(&output))).unwrap();
        writer
            .write(
                b"frame\n".to_vec(),
                &Arc::new(AtomicBool::new(false)),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(*output.lock().unwrap(), b"frame\n");
    }
}
