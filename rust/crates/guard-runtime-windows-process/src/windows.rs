use std::ffi::OsStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::errhandlingapi::GetLastError;
#[cfg(test)]
use winapi::um::fileapi::GetFileType;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
#[cfg(test)]
use winapi::um::handleapi::GetHandleInformation;
use winapi::um::handleapi::{SetHandleInformation, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::processthreadsapi::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcess, TerminateProcess, UpdateProcThreadAttribute,
    PROCESS_INFORMATION,
};
#[cfg(test)]
use winapi::um::synchapi::CreateEventW;
use winapi::um::synchapi::WaitForSingleObject;
#[cfg(test)]
use winapi::um::winbase::FILE_TYPE_UNKNOWN;
use winapi::um::winbase::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    HANDLE_FLAG_INHERIT, STARTF_USESTDHANDLES, STARTUPINFOEXW, WAIT_FAILED, WAIT_OBJECT_0,
};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE};

#[path = "directory_binding.rs"]
mod directory_binding;
#[path = "private_files.rs"]
mod private_files;
#[path = "process_lifecycle.rs"]
mod process_lifecycle;
pub use directory_binding::{
    bind_directory, bind_private_directory, create_private_directory, PrivateDirectoryBinding,
};
pub use private_files::{
    create_private_file, delete_private_file_handle, open_private_directory, open_private_file,
    remove_file_if_same,
};
pub use process_lifecycle::{
    process_start_marker, terminate_process, terminate_process_verified, wait_for_process_exit,
};

// SAFETY: This module is the sole Win32 FFI boundary; borrowed handles remain valid
// for each call, and newly owned handles are wrapped exactly once before returning.

// PROC_THREAD_ATTRIBUTE_HANDLE_LIST is missing from winapi 0.3.9's constants.
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

fn open_process(process_id: u32, access: DWORD) -> io::Result<OwnedHandle> {
    if process_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process identifier must be non-zero",
        ));
    }
    // SAFETY: Access mask and process ID are plain values; the returned handle is wrapped exactly once.
    let process = unsafe { OpenProcess(access, FALSE, process_id) };
    if process.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: OpenProcess returned this handle exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(process as RawHandle) })
    }
}

/// A managed child process whose standard streams cannot leak to descendants.
pub struct ManagedChild {
    process: OwnedHandle,
    job: Option<OwnedHandle>,
    stdin: Option<std::fs::File>,
}

impl ManagedChild {
    /// Return the process identifier associated with this owned process handle.
    pub fn id(&self) -> u32 {
        // SAFETY: `process` owns a valid process handle until this method returns.
        unsafe {
            winapi::um::processthreadsapi::GetProcessId(self.process.as_raw_handle() as HANDLE)
        }
    }

    /// Take ownership of the parent's write side of the child's standard input.
    pub fn take_stdin(&mut self) -> Option<std::fs::File> {
        self.stdin.take()
    }

    /// Return the exact creation-time marker associated with this owned child.
    pub fn start_marker(&self) -> io::Result<String> {
        process_lifecycle::process_start_marker_for_handle(&self.process)
    }

    /// Wait for the child and report whether it exited successfully.
    pub fn wait_success(&self) -> io::Result<bool> {
        self.wait_success_with_timeout(std::time::Duration::from_secs(60 * 60 + 2))
    }

    /// Wait for the child with an explicit finite timeout.
    pub fn wait_success_with_timeout(&self, timeout: std::time::Duration) -> io::Result<bool> {
        // SAFETY: `process` owns a live process handle until this method returns.
        let millis = process_lifecycle::duration_to_wait_millis(timeout);
        let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, millis) };
        match wait {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "process wait timed out",
                ))
            }
            WAIT_FAILED => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("unexpected process wait result")),
        }
        let mut exit_code = 0;
        // SAFETY: The process handle is owned and `exit_code` is a valid output pointer.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as HANDLE, &mut exit_code) }
            == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(exit_code == 0)
    }

    /// Terminate the child if it is still running, then wait for it to exit.
    pub fn terminate(&self) -> io::Result<()> {
        self.terminate_with_timeout(std::time::Duration::from_secs(2))
    }

    /// Terminate the child with an explicit finite timeout.
    pub fn terminate_with_timeout(&self, timeout: std::time::Duration) -> io::Result<()> {
        if let Some(job) = &self.job {
            let _ = process_lifecycle::terminate_job(job);
        }
        if process_lifecycle::process_is_running(&self.process)? {
            // SAFETY: The process handle is owned and termination is followed by a wait.
            if unsafe { TerminateProcess(self.process.as_raw_handle() as HANDLE, 1) } == FALSE {
                return Err(io::Error::last_os_error());
            }
        }
        let millis = process_lifecycle::duration_to_wait_millis(timeout);
        // SAFETY: `process` owns a live process handle until this method returns.
        let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, millis) };
        match wait {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process termination wait timed out",
            )),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected process wait result")),
        }
    }
}

/// Spawn a child with only its three standard handles in the inherited list.
pub fn spawn_managed_child(executable: &Path, args: &[&OsStr]) -> io::Result<ManagedChild> {
    let executable_w = wide_path(executable)?;
    let command_line = command_line(executable.as_os_str(), args)?;
    let mut command_line_w = command_line;

    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let (child_stdin, parent_stdin) = create_stdin_pipe(&mut security)?;
    let child_stdout = create_null_handle(GENERIC_WRITE, &mut security)?;
    let child_stderr = create_null_handle(GENERIC_WRITE, &mut security)?;

    let handles = [
        child_stdin.as_raw_handle() as HANDLE,
        child_stdout.as_raw_handle() as HANDLE,
        child_stderr.as_raw_handle() as HANDLE,
    ];
    let mut attributes = AttributeList::new(1)?;
    attributes.set_handle_list(&handles)?;

    // SAFETY: STARTUPINFOEXW is a plain C struct where an all-zero value is valid.
    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as DWORD;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();

    // SAFETY: PROCESS_INFORMATION is a plain C struct where an all-zero value is valid.
    let mut process_info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    // SAFETY: All pointers reference live, nul-terminated or initialized storage;
    // the attribute list names only the three inheritable standard handles above.
    let created = unsafe {
        CreateProcessW(
            executable_w.as_ptr(),
            command_line_w.as_mut_ptr(),
            null_mut(),
            null_mut(),
            TRUE,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            null_mut(),
            null(),
            &mut startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == FALSE {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: CreateProcessW returned each handle exactly once on success.
    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess as RawHandle) };
    // SAFETY: CreateProcessW returned the thread handle exactly once on success.
    let thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread as RawHandle) };
    let job = process_lifecycle::create_process_job()
        .and_then(|job| {
            process_lifecycle::assign_process_to_job(&job, &process)?;
            Ok(job)
        })
        .ok();
    if let Err(error) = process_lifecycle::resume_thread(&thread) {
        if let Some(job) = &job {
            let _ = process_lifecycle::terminate_job(job);
        }
        // SAFETY: The process is still suspended; terminate the abandoned child.
        let _ = unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) };
        return Err(error);
    }
    drop(thread);
    // SAFETY: `parent_stdin` is transferred exactly once into the File owner.
    let stdin = unsafe { std::fs::File::from_raw_handle(parent_stdin.into_raw_handle()) };
    Ok(ManagedChild {
        process,
        job,
        stdin: Some(stdin),
    })
}

fn create_stdin_pipe(security: &mut SECURITY_ATTRIBUTES) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut child_read = null_mut();
    let mut parent_write = null_mut();
    // SAFETY: Output pointers and SECURITY_ATTRIBUTES remain valid for the call.
    if unsafe { CreatePipe(&mut child_read, &mut parent_write, security, 0) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreatePipe returned each handle exactly once; OwnedHandle now owns both.
    let child_read = unsafe { OwnedHandle::from_raw_handle(child_read as RawHandle) };
    let parent_write = unsafe { OwnedHandle::from_raw_handle(parent_write as RawHandle) };
    // SAFETY: `parent_write` remains owned and valid for this call.
    if unsafe {
        SetHandleInformation(
            parent_write.as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    Ok((child_read, parent_write))
}

fn create_null_handle(
    access: DWORD,
    security: &mut SECURITY_ATTRIBUTES,
) -> io::Result<OwnedHandle> {
    let path: Vec<u16> = OsStr::new(r"\\.\NUL").encode_wide().chain([0]).collect();
    // SAFETY: The path is nul-terminated and all pointer arguments remain valid for the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: CreateFileW returned this handle exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    Ok(path.as_os_str().encode_wide().chain([0]).collect())
}

fn command_line(executable: &OsStr, args: &[&OsStr]) -> io::Result<Vec<u16>> {
    let mut output = Vec::new();
    let all_args = std::iter::once(executable).chain(args.iter().copied());
    for (index, arg) in all_args.enumerate() {
        if index != 0 {
            output.push(' ' as u16);
        }
        output.extend(quote_arg(arg)?);
    }
    output.push(0);
    Ok(output)
}

fn quote_arg(arg: &OsStr) -> io::Result<Vec<u16>> {
    let value: Vec<u16> = arg.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in argument",
        ));
    }
    if !value.is_empty()
        && !value
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16)
    {
        return Ok(value);
    }
    let mut output = vec![b'"' as u16];
    let mut backslashes = 0;
    for unit in value {
        if unit == b'\\' as u16 {
            backslashes += 1;
        } else if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(output)
}

struct AttributeList {
    storage: Vec<usize>,
    list: *mut winapi::um::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(count: DWORD) -> io::Result<Self> {
        let mut size: SIZE_T = 0;
        // SAFETY: The sizing probe intentionally passes a null list and a valid size pointer.
        let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0
            // SAFETY: GetLastError reads the calling thread's Win32 error state.
            || unsafe { GetLastError() } != winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(io::Error::last_os_error());
        }
        let storage_units = size.div_ceil(size_of::<usize>() as SIZE_T);
        let mut storage = vec![0usize; storage_units];
        let list = storage.as_mut_ptr() as *mut _;
        // SAFETY: `list` points to aligned, exclusively owned storage of the requested size.
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage, list })
    }

    fn as_mut_ptr(&mut self) -> *mut winapi::um::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }

    fn set_handle_list(&mut self, handles: &[HANDLE]) -> io::Result<()> {
        // SAFETY: The initialized list and handle slice remain valid for this call.
        if unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr() as *mut _,
                std::mem::size_of_val(handles) as SIZE_T,
                null_mut(),
                null_mut(),
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: `self.list` was initialized successfully and is dropped exactly once.
        unsafe { DeleteProcThreadAttributeList(self.list) };
        let _ = &self.storage;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write;

    const SENTINEL_ENV: &str = "HOL_GUARD_TEST_UNLISTED_HANDLE";

    #[test]
    fn inherited_handle_is_not_leaked() {
        if let Ok(raw_handle) = env::var(SENTINEL_ENV) {
            let handle = raw_handle.parse::<usize>().expect("test handle is numeric") as HANDLE;
            let mut flags = 0;
            let inherited = unsafe {
                GetHandleInformation(handle, &mut flags) != FALSE
                    && GetFileType(handle) == FILE_TYPE_UNKNOWN
            };
            assert!(!inherited, "unlisted parent handle reached managed child");
            return;
        }

        let mut security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: TRUE,
        };
        let mut open_handles = Vec::new();
        for _ in 0..128 {
            open_handles.push(create_null_handle(GENERIC_WRITE, &mut security).unwrap());
        }
        let sentinel = unsafe { CreateEventW(&mut security, FALSE, FALSE, null()) };
        assert!(!sentinel.is_null());
        let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel as RawHandle) };
        env::set_var(
            SENTINEL_ENV,
            (sentinel.as_raw_handle() as usize).to_string(),
        );

        let executable = env::current_exe().unwrap();
        let arguments = [
            OsStr::new("--nocapture"),
            OsStr::new("inherited_handle_is_not_leaked"),
        ];
        let mut child = spawn_managed_child(&executable, &arguments).unwrap();
        let mut stdin = child.take_stdin().unwrap();
        stdin.flush().unwrap();
        drop(stdin);
        assert!(child
            .wait_success_with_timeout(std::time::Duration::from_secs(2))
            .unwrap());
        env::remove_var(SENTINEL_ENV);
        drop(open_handles);
    }
}
