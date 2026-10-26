//! The bounded bridge's hook-input read on unix: `poll` on stdin so every
//! read stays inside the hook deadline.

use std::io;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

use super::{Input, MAX_HOOK_INPUT_BYTES, READ_CHUNK};
use crate::claude_hook_bridge_http::remaining;

const MAX_POLL_WAIT: Duration = Duration::from_secs(60);

/// `_read_hook_input`: at most one byte past the limit, every read inside
/// the hook deadline.
pub(crate) fn read_hook_input(deadline: Instant) -> Input {
    let stdin = io::stdin();
    let mut raw = Vec::new();
    let mut chunk = vec![0_u8; READ_CHUNK];
    while raw.len() <= MAX_HOOK_INPUT_BYTES {
        let left = remaining(deadline);
        if left.is_zero() {
            return Input::Failed;
        }
        let Ok(timeout) = PollTimeout::try_from(left.min(MAX_POLL_WAIT)) else {
            return Input::Failed;
        };
        let mut descriptors = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
        match poll(&mut descriptors, timeout) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => {}
            Err(_) => return Input::Failed,
        }
        if Instant::now() >= deadline {
            return Input::Failed;
        }
        let want = READ_CHUNK.min(MAX_HOOK_INPUT_BYTES + 1 - raw.len());
        match nix::unistd::read(stdin.as_fd(), &mut chunk[..want]) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&chunk[..count]),
            Err(Errno::EINTR) => {}
            Err(_) => return Input::Failed,
        }
    }
    if Instant::now() >= deadline {
        return Input::Failed;
    }
    Input::Read(raw)
}
