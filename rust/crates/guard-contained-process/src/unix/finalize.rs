use crate::CapturedOutput;
use std::io;

pub(super) struct State {
    pub(super) initialized: bool,
    pub(super) protocol_limited: bool,
    #[cfg(not(target_os = "macos"))]
    pub(super) status: Option<i32>,
    #[cfg(target_os = "macos")]
    pub(super) foreign_report: [u8; 4],
    #[cfg(target_os = "macos")]
    pub(super) foreign_report_size: usize,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) timed_out: bool,
    pub(super) output_limited: bool,
    pub(super) cancelled: bool,
    pub(super) completion: Vec<u8>,
}

pub(super) fn finish(state: State) -> io::Result<CapturedOutput> {
    super::process_io::check_protocol_budget(state.protocol_limited)?;
    if !state.initialized && !state.cancelled && !state.timed_out {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native child did not confirm initialization",
        ));
    }
    #[cfg(target_os = "macos")]
    let status = if state.foreign_report_size == 4 {
        Some(i32::from_ne_bytes(state.foreign_report))
    } else if state.cancelled || state.timed_out || state.output_limited {
        None
    } else {
        return Err(io::Error::other(
            "native supervisor did not report foreign completion",
        ));
    };
    #[cfg(not(target_os = "macos"))]
    let status = state.status;
    let code = status.and_then(|status| {
        if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Some(-libc::WTERMSIG(status))
        } else {
            None
        }
    });
    Ok(CapturedOutput {
        exit_code: code.filter(|_| !state.cancelled && !state.timed_out && !state.output_limited),
        stdout: state.stdout,
        stderr: state.stderr,
        timed_out: state.timed_out,
        output_limited: state.output_limited,
        cancelled: state.cancelled,
        completion: state.completion,
    })
}
