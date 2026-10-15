//! The bounded bridge's hook-input read on Windows, where pipes cannot be
//! polled: a reader thread takes at most one byte past the limit from an
//! unbuffered handle on stdin, and the bridge waits for it only until the
//! hook deadline. A read still blocked at the deadline is abandoned; the
//! bridge then answers with the failure payload and the process exits.

use std::fs::File;
use std::io::{self, Read};
use std::os::windows::io::AsHandle;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use super::{Input, MAX_HOOK_INPUT_BYTES, READ_CHUNK};
use crate::claude_hook_bridge_http::remaining;

/// `_read_hook_input`: at most one byte past the limit, the whole read
/// inside the hook deadline.
pub(crate) fn read_hook_input(deadline: Instant) -> Input {
    // A duplicate of the stdin handle, read without std's stdin buffer, so
    // nothing past the limit is taken from the pipe.
    let Ok(handle) = io::stdin().as_handle().try_clone_to_owned() else {
        return Input::Failed;
    };
    let mut stdin = File::from(handle);
    let (sender, receiver) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("hook-input".to_owned())
        .spawn(move || {
            let _ = sender.send(read_capped(&mut stdin));
        });
    if spawned.is_err() {
        return Input::Failed;
    }
    let left = remaining(deadline);
    if left.is_zero() {
        return Input::Failed;
    }
    match receiver.recv_timeout(left) {
        Ok(Some(raw)) if Instant::now() < deadline => Input::Read(raw),
        _ => Input::Failed,
    }
}

/// Read to end of input or one byte past the limit; `None` on a read error.
fn read_capped(stdin: &mut impl Read) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = vec![0_u8; READ_CHUNK];
    while raw.len() <= MAX_HOOK_INPUT_BYTES {
        let want = READ_CHUNK.min(MAX_HOOK_INPUT_BYTES + 1 - raw.len());
        match stdin.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(raw)
}
