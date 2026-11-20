//! What the bounded bridge writes: a route's answer on stdout and stderr, or
//! the fixed fail-closed payload for the harness.

use std::io::{self, Write};

use super::Route;
use crate::bounded_hook_bridge_render::{failure_output, failure_output_for};

pub(crate) fn write_stdout(text: &str) {
    let mut stdout = io::stdout().lock();
    let _ = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush());
}

fn write_stderr_line(text: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr
        .write_all(text.as_bytes())
        .and_then(|()| stderr.write_all(b"\n"))
        .and_then(|()| stderr.flush());
}

pub(super) fn fail(harness: &str, event_name: &str, unmap: bool) -> i32 {
    let (payload, code) = failure_output(harness, event_name, unmap);
    write_stdout(&payload);
    code
}

fn refuse(harness: &str, event_name: &str, reason: &str, unmap: bool) -> i32 {
    let (payload, code) = failure_output_for(harness, event_name, reason, unmap);
    write_stdout(&payload);
    code
}

/// Write the answer for `route` and return its exit code.
pub(super) fn emit(harness: &str, route: Route) -> i32 {
    match route {
        Route::Respond {
            stdout,
            stderr,
            exit_code,
        } => {
            write_stdout(&stdout);
            if !stderr.is_empty() {
                write_stderr_line(&stderr);
            }
            exit_code
        }
        Route::Fail { event_name, unmap } => fail(harness, &event_name, unmap),
        Route::Refuse {
            event_name,
            reason,
            unmap,
        } => refuse(harness, &event_name, reason, unmap),
    }
}
