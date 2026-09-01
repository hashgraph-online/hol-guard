use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
use winapi::um::processthreadsapi::{GetExitCodeProcess, GetProcessTimes, TerminateProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, SYNCHRONIZE};

const STILL_ACTIVE: DWORD = 259;

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
    let millis = timeout.as_millis().min(u32::MAX as u128) as DWORD;
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
    let mut exit_code = 0;
    // SAFETY: The process handle is owned and `exit_code` is a valid output pointer.
    if unsafe { GetExitCodeProcess(process.as_raw_handle() as HANDLE, &mut exit_code) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    if exit_code == STILL_ACTIVE {
        // SAFETY: The process handle is owned and termination is followed by a wait.
        if unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) } == FALSE {
            return Err(io::Error::last_os_error());
        }
    }
    let millis = timeout.as_millis().min(u32::MAX as u128) as DWORD;
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
