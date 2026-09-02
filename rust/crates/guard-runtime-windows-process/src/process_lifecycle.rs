use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::Duration;

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
use winapi::um::processthreadsapi::{GetProcessTimes, TerminateProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, SYNCHRONIZE};

const MAX_FINITE_WAIT_MILLIS: DWORD = u32::MAX - 1;

pub(super) fn duration_to_wait_millis(timeout: Duration) -> DWORD {
    timeout.as_millis().min(u128::from(MAX_FINITE_WAIT_MILLIS)) as DWORD
}

pub(super) fn process_is_running(process: &OwnedHandle) -> io::Result<bool> {
    // A process handle becomes signaled when the process exits.  This check is
    // deliberately independent of its exit code: 259 (STILL_ACTIVE) is a
    // valid application exit code and must not be mistaken for liveness.
    // SAFETY: `process` owns a valid process handle until this call returns.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 0) };
    match wait {
        WAIT_OBJECT_0 => Ok(false),
        WAIT_TIMEOUT => Ok(true),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected process state result")),
    }
}

pub(super) fn process_start_marker_for_handle(process: &OwnedHandle) -> io::Result<String> {
    let mut creation = winapi::shared::minwindef::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = winapi::shared::minwindef::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = winapi::shared::minwindef::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = winapi::shared::minwindef::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: all FILETIME pointers reference initialized writable storage and
    // `process` owns a valid process handle for the duration of this call.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle() as HANDLE,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Ok(format!("windows:{value:016x}"))
}

/// Return the exact creation-time marker associated with a process handle.
pub fn process_start_marker(process_id: u32) -> io::Result<String> {
    let process = super::open_process(process_id, PROCESS_QUERY_LIMITED_INFORMATION)?;
    process_start_marker_for_handle(&process)
}

/// Wait for a process to terminate, treating an already-gone PID as exited.
pub fn wait_for_process_exit(process_id: u32, timeout: std::time::Duration) -> io::Result<bool> {
    let process =
        match super::open_process(process_id, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(process) => process,
            Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => {
                return Ok(true)
            }
            Err(error) => return Err(error),
        };
    let millis = duration_to_wait_millis(timeout);
    // SAFETY: `process` owns a valid process handle until this call returns.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, millis) };
    match wait {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected process wait result")),
    }
}

/// Terminate a process with the bounded default used by legacy callers.
pub fn terminate_process(process_id: u32) -> io::Result<()> {
    terminate_process_verified(process_id, None, std::time::Duration::from_secs(2)).map(|_| ())
}

/// Terminate a process only if its already-open handle still has the expected identity.
pub fn terminate_process_verified(
    process_id: u32,
    expected_start_marker: Option<&str>,
    timeout: std::time::Duration,
) -> io::Result<bool> {
    let process = match super::open_process(
        process_id,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
    ) {
        Ok(process) => process,
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };
    if let Some(expected_start_marker) = expected_start_marker {
        if process_start_marker_for_handle(&process)?.as_str() != expected_start_marker {
            return Ok(false);
        }
    }
    if process_is_running(&process)? {
        // SAFETY: The process handle is owned and termination is followed by a wait.
        if unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) } == FALSE {
            return Err(io::Error::last_os_error());
        }
    }
    let millis = duration_to_wait_millis(timeout);
    // SAFETY: `process` owns a valid process handle until this call returns.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, millis) };
    match wait {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "process termination wait timed out",
        )),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected process wait result")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_to_wait_millis_never_uses_infinite_sentinel() {
        assert_eq!(duration_to_wait_millis(Duration::ZERO), 0);
        assert_eq!(
            duration_to_wait_millis(Duration::from_millis(u64::MAX)),
            u32::MAX - 1
        );
        assert_ne!(
            duration_to_wait_millis(Duration::from_millis(u64::MAX)),
            u32::MAX
        );
    }
}
