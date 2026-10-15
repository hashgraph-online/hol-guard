//! Host (MCP client) side of the native relay.
//!
//! A reader thread frames the host's newline-delimited JSON-RPC stream with a
//! per-line byte cap and hands decoded objects to the relay over a bounded
//! channel; replies go back to the host one JSON document per line. A
//! malformed, oversized, or non-object line is fatal, as it is for the Python
//! proxy's `json.loads(line)` loop.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::Value;

/// Largest single host line the relay accepts.
pub(crate) const HOST_LINE_LIMIT: usize = 4 * 1024 * 1024;
/// Decoded host messages queued ahead of the relay (backpressure bound).
const HOST_QUEUE: usize = 16;

/// One read from the host.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HostRead {
    /// A decoded object, with the host's `params.arguments` key order when it
    /// is a `tools/call` whose arguments have more than one key.
    Message(Value, Option<Vec<String>>),
    /// No message arrived within the requested timeout.
    Timeout,
    /// The host closed its output stream.
    Eof,
    /// The host stream cannot be framed or decoded.
    Invalid(&'static str),
}

/// The relay's view of the MCP client.
pub(crate) trait HostLink {
    /// Next host message; `None` waits without a deadline.
    fn next(&mut self, timeout: Option<Duration>) -> HostRead;
    /// Write one message to the host and flush it.
    fn send(&mut self, message: &Value) -> Result<(), String>;
}

enum Line {
    Bytes(Vec<u8>),
    Eof,
    TooLong,
}

/// Read one `\n`-terminated line of at most `limit` bytes.
fn read_line(reader: &mut impl BufRead, limit: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(if line.is_empty() {
                Line::Eof
            } else {
                Line::Bytes(line)
            });
        }
        let (take, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if line.len() + take > limit {
            return Ok(Line::TooLong);
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if complete {
            return Ok(Line::Bytes(line));
        }
    }
}

/// `json.loads(line)` followed by the proxy's use of the result as a dict.
pub(crate) fn decode(line: &[u8]) -> HostRead {
    match serde_json::from_slice::<Value>(line) {
        Ok(message @ Value::Object(_)) => {
            let order = if needs_order(&message) {
                crate::mcp_relay_order::argument_order(line)
            } else {
                None
            };
            HostRead::Message(message, order)
        }
        Ok(_) => HostRead::Invalid("mcp_relay_host_message_not_object"),
        Err(_) => HostRead::Invalid("mcp_relay_host_message_invalid"),
    }
}

/// Whether the decoded map lost an argument order the decision depends on.
fn needs_order(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("tools/call")
        && message
            .get("params")
            .and_then(|params| params.get("arguments"))
            .and_then(Value::as_object)
            .is_some_and(|arguments| arguments.len() > 1)
}

fn pump(reader: impl Read, sender: &mpsc::SyncSender<HostRead>) {
    let mut reader = BufReader::new(reader);
    loop {
        let item = match read_line(&mut reader, HOST_LINE_LIMIT) {
            Ok(Line::Bytes(bytes)) => decode(&bytes),
            Ok(Line::Eof) => HostRead::Eof,
            Ok(Line::TooLong) => HostRead::Invalid("mcp_relay_host_message_too_large"),
            Err(_) => HostRead::Invalid("mcp_relay_host_read_failed"),
        };
        let last = !matches!(item, HostRead::Message(..));
        if sender.send(item).is_err() || last {
            return;
        }
    }
}

/// A host connected over a byte reader (stdin) and writer (stdout).
pub(crate) struct LineHost<W: Write> {
    inbox: mpsc::Receiver<HostRead>,
    output: W,
}

impl<W: Write> LineHost<W> {
    pub(crate) fn spawn(reader: impl Read + Send + 'static, output: W) -> Result<Self, String> {
        let (sender, inbox) = mpsc::sync_channel(HOST_QUEUE);
        thread::Builder::new()
            .name("guard-mcp-relay-host".to_owned())
            .spawn(move || pump(reader, &sender))
            .map_err(|_| "mcp_relay_host_reader_unavailable".to_owned())?;
        Ok(Self { inbox, output })
    }
}

impl<W: Write> HostLink for LineHost<W> {
    fn next(&mut self, timeout: Option<Duration>) -> HostRead {
        let received = match timeout {
            None => self.inbox.recv().ok(),
            Some(timeout) => match self.inbox.recv_timeout(timeout) {
                Ok(item) => Some(item),
                Err(mpsc::RecvTimeoutError::Timeout) => return HostRead::Timeout,
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            },
        };
        received.unwrap_or(HostRead::Eof)
    }

    fn send(&mut self, message: &Value) -> Result<(), String> {
        let mut bytes =
            serde_json::to_vec(message).map_err(|_| "mcp_relay_host_frame_invalid".to_owned())?;
        bytes.push(b'\n');
        self.output
            .write_all(&bytes)
            .and_then(|()| self.output.flush())
            .map_err(|_| "mcp_relay_host_write_failed".to_owned())
    }
}

#[cfg(test)]
#[path = "mcp_relay_host_tests.rs"]
mod tests;
