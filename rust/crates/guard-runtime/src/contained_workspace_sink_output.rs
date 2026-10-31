//! Where a contained run's output goes while a peeled wrapper shapes it.
//!
//! Guard's own sink redirects its streams around the core of a wrapped call:
//! a trailing `2>&1` sends standard error to standard output, and a filter
//! chain captures standard output (with standard error, when merged) so the
//! chain can run over it once the core ends. Every write this sink makes on
//! a run's behalf goes through here, so the same redirections hold.
//!
//! A terminal gets at most `OUTPUT_LIMIT` bytes of a stream, as display text.
//! A filter chain reads the raw bytes instead, up to `CAPTURE_LIMIT`, so
//! `tail` finds the real end and `grep` sees what the command wrote; only
//! the chain's result is limited and made display text. A stream cut at
//! `CAPTURE_LIMIT` is noted after the chain's result, never inside the
//! chain's input, so no filter can drop the notice.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The most of a stream written to the terminal.
const OUTPUT_LIMIT: usize = 1024 * 1024;
/// The most of a stream held for a filter chain to read.
const CAPTURE_LIMIT: usize = 64 * 1024 * 1024;
const TRUNCATED: &str = "\n[HOL Guard truncated restricted pytest output]\n";

/// The redirections of the wrapper being run, when one is.
#[derive(Default)]
pub(super) struct Shaping(Mutex<Option<Frame>>);

struct Frame {
    merge: bool,
    captured: Option<Vec<u8>>,
    cut: bool,
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
            cut: false,
        });
        true
    }

    /// Stop shaping: the output held since `enter`, and whether a stream
    /// was cut at `CAPTURE_LIMIT` while held.
    pub(super) fn leave(&self) -> (Vec<u8>, bool) {
        self.frame()
            .take()
            .and_then(|frame| Some((frame.captured?, frame.cut)))
            .unwrap_or_default()
    }

    /// Whether standard error joins standard output.
    pub(super) fn merges(&self) -> bool {
        self.frame().as_ref().is_some_and(|frame| frame.merge)
    }

    /// Replay a run's standard output from `file`. The first `OUTPUT_LIMIT`
    /// raw bytes, for the denial check.
    pub(super) fn replay_out(&self, file: File) -> Vec<u8> {
        self.replay(file, self.captures(), |bytes| self.out(bytes))
    }

    /// Replay a run's standard error from `file`. The first `OUTPUT_LIMIT`
    /// raw bytes, for the denial check.
    pub(super) fn replay_err(&self, file: File) -> Vec<u8> {
        self.replay(file, self.captures() && self.merges(), |bytes| {
            self.err(bytes)
        })
    }

    /// Write a stream held for a filter chain raw, up to `CAPTURE_LIMIT`,
    /// and any other as display text.
    fn replay(&self, file: File, held: bool, sink: impl Fn(&[u8])) -> Vec<u8> {
        if !held {
            let (raw, truncated) = read(file, OUTPUT_LIMIT);
            sink(&shown(&raw, truncated));
            return raw;
        }
        let (mut raw, truncated) = read(file, CAPTURE_LIMIT);
        sink(&raw);
        if let Some(frame) = self.frame().as_mut() {
            frame.cut |= truncated;
        }
        raw.truncate(OUTPUT_LIMIT);
        raw
    }

    /// Write a filter chain's result to standard output as display text,
    /// with the truncation notice when it, or the input `cut`, was cut.
    pub(super) fn show(&self, bytes: &[u8], cut: bool) {
        let truncated = cut || bytes.len() > OUTPUT_LIMIT;
        self.out(&shown(&bytes[..bytes.len().min(OUTPUT_LIMIT)], truncated));
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
                ..
            }) => captured.extend_from_slice(bytes),
            Some(Frame { merge: true, .. }) => write(&mut std::io::stdout().lock(), bytes),
            _ => write(&mut std::io::stderr().lock(), bytes),
        }
    }

    fn captures(&self) -> bool {
        self.frame()
            .as_ref()
            .is_some_and(|frame| frame.captured.is_some())
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

/// Up to `limit` bytes of `file`, and whether it held more.
fn read(mut file: File, limit: usize) -> (Vec<u8>, bool) {
    let mut raw = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let bound = u64::try_from(limit).unwrap_or(u64::MAX);
        let _ = (&mut file)
            .take(bound.saturating_add(1))
            .read_to_end(&mut raw);
    }
    let truncated = raw.len() > limit;
    raw.truncate(limit);
    (raw, truncated)
}

fn shown(raw: &[u8], truncated: bool) -> Vec<u8> {
    let mut text = display_text(raw);
    if truncated {
        text.push_str(TRUNCATED);
    }
    text.into_bytes()
}

/// Output as text a terminal shows safely: CRLF folded, and control
/// characters other than newline and tab replaced.
fn display_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .replace("\r\n", "\n")
        .chars()
        .map(|character| {
            if character == '\n' || character == '\t' || u32::from(character) >= 32 {
                character
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "contained_workspace_sink_output_tests.rs"]
mod tests;
