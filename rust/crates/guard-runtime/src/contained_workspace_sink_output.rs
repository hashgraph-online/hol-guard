//! Where a contained run's output goes while a peeled wrapper shapes it.
//!
//! Guard's own sink redirects its streams around the core of a wrapped call:
//! a trailing `2>&1` sends standard error to standard output, and a filter
//! chain captures standard output (with standard error, when merged) so the
//! chain can run over it once the core ends. Every write this sink makes on
//! a run's behalf goes through here, so the same redirections hold.

use std::io::Write;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The redirections of the wrapper being run, when one is.
#[derive(Default)]
pub(super) struct Shaping(Mutex<Option<Frame>>);

struct Frame {
    merge: bool,
    captured: Option<Vec<u8>>,
}

impl Shaping {
    /// Start shaping: with `merge`, standard error joins standard output;
    /// with `capture`, standard output is held instead of written. `false`
    /// when a wrapper is already being shaped.
    pub(super) fn enter(&self, merge: bool, capture: bool) -> bool {
        let mut frame = self.frame();
        if frame.is_some() {
            return false;
        }
        *frame = Some(Frame {
            merge,
            captured: capture.then(Vec::new),
        });
        true
    }

    /// Stop shaping: the output held since `enter`.
    pub(super) fn leave(&self) -> Vec<u8> {
        self.frame()
            .take()
            .and_then(|frame| frame.captured)
            .unwrap_or_default()
    }

    /// Whether standard error joins standard output.
    pub(super) fn merges(&self) -> bool {
        self.frame().as_ref().is_some_and(|frame| frame.merge)
    }

    /// Write `bytes` to standard output.
    pub(super) fn out(&self, bytes: &[u8]) {
        match self.frame().as_mut() {
            Some(Frame {
                captured: Some(captured),
                ..
            }) => captured.extend_from_slice(bytes),
            _ => write(&mut std::io::stdout().lock(), bytes),
        }
    }

    /// Write `bytes` to standard error.
    pub(super) fn err(&self, bytes: &[u8]) {
        match self.frame().as_mut() {
            Some(Frame {
                merge: true,
                captured: Some(captured),
            }) => captured.extend_from_slice(bytes),
            Some(Frame { merge: true, .. }) => write(&mut std::io::stdout().lock(), bytes),
            _ => write(&mut std::io::stderr().lock(), bytes),
        }
    }

    fn frame(&self) -> MutexGuard<'_, Option<Frame>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn write(stream: &mut impl Write, bytes: &[u8]) {
    if !bytes.is_empty() {
        let _ = stream.write_all(bytes);
    }
    let _ = stream.flush();
}
