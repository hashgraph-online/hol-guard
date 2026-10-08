use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use winapi::um::winbase::{
    FILE_FLAG_OVERLAPPED, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use winapi::um::winnt::GENERIC_READ;

#[path = "capture_io.rs"]
mod capture_io;
use capture_io::Operation;

pub struct CapturedOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub output_limited: bool,
    pub cancelled: bool,
}

/// Child handles are inheritable; only these three belong in HANDLE_LIST.
/// Parent handles use owned overlapped operations and cannot be inherited.
pub struct CapturePipes {
    pub child_stdin: OwnedHandle,
    pub child_stdout: OwnedHandle,
    pub child_stderr: OwnedHandle,
    parent_stdin: Operation,
    parent_stdout: Operation,
    parent_stderr: Operation,
}

fn pipe(write: bool, security: &mut SECURITY_ATTRIBUTES) -> io::Result<(OwnedHandle, Operation)> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| io::Error::other("capture pipe entropy unavailable"))?;
    use std::fmt::Write;
    let mut name = format!("\\\\.\\pipe\\hol-guard-capture-{}-", std::process::id());
    for byte in nonce {
        write!(&mut name, "{byte:02x}").expect("String writes are infallible");
    }
    let name = wide_path(Path::new(&name))?;
    let parent = unsafe {
        winapi::um::namedpipeapi::CreateNamedPipeW(
            name.as_ptr(),
            (if write {
                PIPE_ACCESS_OUTBOUND
            } else {
                PIPE_ACCESS_INBOUND
            }) | FILE_FLAG_OVERLAPPED
                | winapi::um::winbase::FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_WAIT | winapi::um::winbase::PIPE_REJECT_REMOTE_CLIENTS,
            1,
            8192,
            8192,
            0,
            null_mut(),
        )
    };
    if parent == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(parent as RawHandle) };
    let child = unsafe {
        CreateFileW(
            name.as_ptr(),
            if write { GENERIC_READ } else { GENERIC_WRITE },
            0,
            security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if child == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let child = unsafe { OwnedHandle::from_raw_handle(child as RawHandle) };
    Ok((child, Operation::new(parent)?.connect()?))
}

pub fn capture_pipes() -> io::Result<CapturePipes> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let (child_stdin, parent_stdin) = pipe(true, &mut security)?;
    let (child_stdout, parent_stdout) = pipe(false, &mut security)?;
    let (child_stderr, parent_stderr) = pipe(false, &mut security)?;
    Ok(CapturePipes {
        child_stdin,
        child_stdout,
        child_stderr,
        parent_stdin,
        parent_stdout,
        parent_stderr,
    })
}

fn cleanup(
    child: &mut ChildJobGuard,
    writer: &mut Option<Operation>,
    reader: &mut Option<Operation>,
    errors: &mut Option<Operation>,
    deadline: Instant,
) -> io::Result<()> {
    // Stop every pending operation before closing storage. Completion never
    // counts as additional captured output after the request stops.
    let mut failure = None;
    for operation in [&mut *writer, &mut *reader, &mut *errors]
        .into_iter()
        .flatten()
    {
        if let Err(error) = operation.request_cancel() {
            failure = Some(error);
        }
    }
    if let Err(error) = child.terminate_and_wait(deadline) {
        failure = Some(error);
    }
    for operation in [writer, reader, errors].into_iter().flatten() {
        if let Err(error) = operation.finish_cancel(deadline) {
            failure = Some(error);
        }
    }
    if failure.is_some() {
        return Err(io::Error::other("cleanup_incomplete"));
    }
    Ok(())
}

pub fn capture_owned_child(
    mut child: ChildJobGuard,
    pipes: CapturePipes,
    input: &[u8],
    limit: usize,
    per_stream: bool,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> io::Result<CapturedOutput> {
    let CapturePipes {
        child_stdin,
        child_stdout,
        child_stderr,
        parent_stdin,
        parent_stdout,
        parent_stderr,
    } = pipes;
    drop((child_stdin, child_stdout, child_stderr));
    let mut writer = if input.is_empty() {
        drop(parent_stdin);
        None
    } else {
        Some(parent_stdin)
    };
    let mut reader = Some(parent_stdout);
    let mut errors = Some(parent_stderr);
    let mut output = CapturedOutput {
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: false,
        output_limited: false,
        cancelled: false,
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    // The old bounded cleanup constant is reserved inside, never added to,
    // the inherited deadline. Short requests reserve at most one quarter.
    let reserve = Duration::from_millis(200).min(remaining / 4);
    let work_deadline = deadline.checked_sub(reserve).unwrap_or(deadline);
    let mut input_offset = 0;
    let mut root_exited = false;
    let work_result = (|| -> io::Result<()> {
        loop {
            if cancellation.load(Ordering::Acquire) {
                output.cancelled = true;
                break;
            }
            if Instant::now() >= work_deadline {
                output.timed_out = true;
                break;
            }
            let mut progress = false;
            if let Some(active) = writer.as_mut() {
                if let Some(count) = active.write(&input[input_offset..])? {
                    progress = true;
                    // Closing stdin early is an ordinary child outcome. Keep
                    // collecting its output and exit status, as on Unix.
                    if count == 0 {
                        writer = None;
                    } else {
                        input_offset += count;
                        if input_offset == input.len() {
                            writer = None;
                        }
                    }
                }
            }
            for (operation, is_stderr) in [(&mut reader, false), (&mut errors, true)] {
                if cancellation.load(Ordering::Acquire) || Instant::now() >= work_deadline {
                    break;
                }
                if let Some(active) = operation.as_mut() {
                    if let Some(count) = active.read()? {
                        progress = true;
                        if count == 0 {
                            *operation = None;
                            continue;
                        }
                        let retained = if per_stream {
                            if is_stderr {
                                output.stderr.len()
                            } else {
                                output.stdout.len()
                            }
                        } else {
                            output.stdout.len() + output.stderr.len()
                        };
                        let allowed = count.min(limit.saturating_sub(retained));
                        let bytes = active.buffer(allowed);
                        if is_stderr {
                            output.stderr.extend_from_slice(bytes);
                        } else {
                            output.stdout.extend_from_slice(bytes);
                        }
                        if allowed != count {
                            output.output_limited = true;
                            break;
                        }
                    }
                }
            }
            if output.output_limited {
                break;
            }
            if !root_exited {
                if let Some(code) = child.try_wait()? {
                    output.exit_code = Some(code as i32);
                    // A root can exit while descendants retain all three pipes.
                    // Kill and verify the entire Job before bounded final drain.
                    child.terminate_and_wait(deadline)?;
                    root_exited = true;
                }
            }
            if root_exited && reader.is_none() && errors.is_none() {
                break;
            }
            if !progress {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(work_deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
        Ok(())
    })();
    cleanup(&mut child, &mut writer, &mut reader, &mut errors, deadline)?;
    work_result?;
    if cancellation.load(Ordering::Acquire) {
        output.cancelled = true;
    }
    if Instant::now() >= deadline {
        output.timed_out = true;
    }
    if output.cancelled || output.timed_out || output.output_limited {
        output.exit_code = None;
    }
    Ok(output)
}

#[path = "capture_spawn.rs"]
mod capture_spawn;
pub use capture_spawn::capture;

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
