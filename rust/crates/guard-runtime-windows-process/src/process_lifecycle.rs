use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
use winapi::um::jobapi2::{AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject};
use winapi::um::processthreadsapi::{GetProcessTimes, ResumeThread, TerminateProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{QueryFullProcessImageNameW, WAIT_FAILED, WAIT_OBJECT_0};
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

/// Like `process_start_marker`, but fails once the process has exited. An exited
/// process stays queryable while any handle to it (often its parent's) is open.
pub fn running_process_start_marker(process_id: u32) -> io::Result<String> {
    let process = super::open_process(process_id, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)?;
    if !process_is_running(&process)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "process has exited",
        ));
    }
    process_start_marker_for_handle(&process)
}

/// Image path of a process that has not exited.
///
/// One `OpenProcess` call answers this directly. A sysinfo refresh snapshots
/// every process on the machine first, which costs hundreds of milliseconds
/// per lookup on Windows and sits on every resident request.
pub fn running_process_image_path(process_id: u32) -> io::Result<PathBuf> {
    let process = super::open_process(process_id, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)?;
    if !process_is_running(&process)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "process has exited",
        ));
    }
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as DWORD;
    // SAFETY: `process` owns a valid process handle, `buffer` holds `size`
    // writable UTF-16 units and `size` is initialized writable storage.
    if unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            0,
            buffer.as_mut_ptr(),
            &mut size,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(size as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

/// Whether a process runs, as `windows_process_liveness` answers it:
/// `Some(false)` only when Windows proves it gone (an unknown id or an
/// exited process), `None` when that cannot be proven either way.
pub fn process_liveness(process_id: u32) -> Option<bool> {
    // Python answers "not running" for PID 0 without asking Windows, and
    // `open_process` refuses it before `OpenProcess` can set an error code.
    if process_id == 0 {
        return Some(false);
    }
    let process = match super::open_process(process_id, SYNCHRONIZE) {
        Ok(process) => process,
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => {
            return Some(false)
        }
        Err(_) => return None,
    };
    process_is_running(&process).ok()
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

pub(super) fn create_process_job() -> io::Result<OwnedHandle> {
    // SAFETY: A NULL name and security descriptor create an anonymous job
    // owned exactly once by the returned handle.
    let job = unsafe { CreateJobObjectW(null_mut(), std::ptr::null()) };
    if job.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: CreateJobObjectW returned this handle exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(job as RawHandle) })
    }
}

pub(super) fn assign_process_to_job(job: &OwnedHandle, process: &OwnedHandle) -> io::Result<()> {
    // SAFETY: Both handles remain owned and valid for the duration of the call.
    if unsafe {
        AssignProcessToJobObject(
            job.as_raw_handle() as HANDLE,
            process.as_raw_handle() as HANDLE,
        )
    } == FALSE
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn terminate_job(job: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `job` owns a live job handle until this call returns.
    if unsafe { TerminateJobObject(job.as_raw_handle() as HANDLE, 1) } == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn resume_thread(thread: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `thread` owns a live thread handle until this call returns.
    // ResumeThread returns the previous suspend count, or u32::MAX on failure.
    if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == DWORD::MAX {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
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
