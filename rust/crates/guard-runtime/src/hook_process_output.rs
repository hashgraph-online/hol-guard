//! The bounded capture of a hook child's output: the shared byte bound, the
//! readers that drain its pipes, the stdin writer and the decoding that keeps
//! the two streams within one limit. Split from `hook_process_spawn` as a
//! `#[path]` child module.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Shared output counters across the two drain readers — Python's
/// `output_count`/`output_lock`/`output_limit_exceeded`.
#[allow(dead_code)]
pub(super) struct OutputBound {
    pub(super) count: AtomicU64,
    pub(super) limit: u64,
    pub(super) exceeded: AtomicBool,
    /// A read failed before EOF: the captured bytes are not the whole output.
    pub(super) capture_error: AtomicBool,
}

#[allow(dead_code)]
impl OutputBound {
    pub(super) fn take(&self, chunk_len: usize) -> usize {
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
pub(super) fn drain_stream<R: Read + Send + 'static>(
    mut stream: R,
    target: Arc<Mutex<Vec<u8>>>,
    bound: Arc<OutputBound>,
    done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Err(_) => {
                    bound.capture_error.store(true, Ordering::SeqCst);
                    break;
                }
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
pub(super) fn write_input(mut stream: std::process::ChildStdin, input: Vec<u8>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = stream.write_all(&input);
        let _ = stream.flush();
        // dropping `stream` closes stdin (EOF to child)
    })
}

/// `_truncate_decoded_output` (`codex_hook_launch_runtime.py:55-61`):
/// keep the decoded UTF-8 within `limit` bytes after replacement decoding.
pub(super) fn truncate_decoded(value: String, limit: usize) -> String {
    let encoded = value.as_bytes();
    if encoded.len() <= limit {
        return value;
    }
    // Python decodes the cut prefix with `errors="ignore"`: a character split
    // by the cut is dropped, never replaced (U+FFFD would add bytes past the bound).
    let prefix = &encoded[..limit];
    let valid = match std::str::from_utf8(prefix) {
        Ok(text) => text.len(),
        Err(error) => error.valid_up_to(),
    };
    String::from_utf8_lossy(&prefix[..valid]).into_owned()
}

/// `_decode_combined_output` (`codex_hook_launch_runtime.py:64-75`): decode
/// both streams preserving their shared byte bound (stdout consumes first).
pub(super) fn decode_combined_output(
    stdout: &[u8],
    stderr: &[u8],
    output_limit: usize,
) -> (String, String) {
    let remaining = output_limit;
    let stdout_str = truncate_decoded(String::from_utf8_lossy(stdout).into_owned(), remaining);
    let remaining = remaining.saturating_sub(stdout_str.len());
    let stderr_str = truncate_decoded(String::from_utf8_lossy(stderr).into_owned(), remaining);
    (stdout_str, stderr_str)
}
