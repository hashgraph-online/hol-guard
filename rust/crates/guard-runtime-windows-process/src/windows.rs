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
    InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
    PROCESS_INFORMATION,
};
#[cfg(test)]
use winapi::um::synchapi::CreateEventW;
use winapi::um::synchapi::WaitForSingleObject;
#[cfg(test)]
use winapi::um::winbase::FILE_TYPE_UNKNOWN;
use winapi::um::winbase::{
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, HANDLE_FLAG_INHERIT, INFINITE,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, WAIT_OBJECT_0,
};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE};

// PROC_THREAD_ATTRIBUTE_HANDLE_LIST is missing from winapi 0.3.9's constants.
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const STILL_ACTIVE: DWORD = 259;

/// A managed child process whose standard streams cannot leak to descendants.
pub struct ManagedChild {
    process: OwnedHandle,
    stdin: Option<std::fs::File>,
}

impl ManagedChild {
    /// Take ownership of the parent's write side of the child's standard input.
    pub fn take_stdin(&mut self) -> Option<std::fs::File> {
        self.stdin.take()
    }

    /// Wait for the child and report whether it exited successfully.
    pub fn wait_success(&self) -> io::Result<bool> {
        let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as HANDLE, &mut exit_code) }
            == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(exit_code == 0)
    }

    /// Terminate the child if it is still running, then wait for it to exit.
    pub fn terminate(&self) -> io::Result<()> {
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as HANDLE, &mut exit_code) }
            == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        if exit_code == STILL_ACTIVE
            && unsafe { TerminateProcess(self.process.as_raw_handle() as HANDLE, 1) } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, INFINITE) };
        if wait == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
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

    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as DWORD;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();

    let mut process_info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessW(
            executable_w.as_ptr(),
            command_line_w.as_mut_ptr(),
            null_mut(),
            null_mut(),
            TRUE,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            null(),
            &mut startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == FALSE {
        return Err(io::Error::last_os_error());
    }

    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess as RawHandle) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread as RawHandle) };
    let stdin = unsafe { std::fs::File::from_raw_handle(parent_stdin.into_raw_handle()) };
    Ok(ManagedChild {
        process,
        stdin: Some(stdin),
    })
}

fn create_stdin_pipe(security: &mut SECURITY_ATTRIBUTES) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut child_read = null_mut();
    let mut parent_write = null_mut();
    if unsafe { CreatePipe(&mut child_read, &mut parent_write, security, 0) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    if unsafe { SetHandleInformation(parent_write, HANDLE_FLAG_INHERIT, 0) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    let child_read = unsafe { OwnedHandle::from_raw_handle(child_read as RawHandle) };
    let parent_write = unsafe { OwnedHandle::from_raw_handle(parent_write as RawHandle) };
    Ok((child_read, parent_write))
}

fn create_null_handle(
    access: DWORD,
    security: &mut SECURITY_ATTRIBUTES,
) -> io::Result<OwnedHandle> {
    let path: Vec<u16> = OsStr::new(r"\\.\NUL").encode_wide().chain([0]).collect();
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
        let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0
            || unsafe { GetLastError() } != winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(io::Error::last_os_error());
        }
        let storage_units = size.div_ceil(size_of::<usize>() as SIZE_T);
        let mut storage = vec![0usize; storage_units];
        let list = storage.as_mut_ptr() as *mut _;
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage, list })
    }

    fn as_mut_ptr(&mut self) -> *mut winapi::um::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }

    fn set_handle_list(&mut self, handles: &[HANDLE]) -> io::Result<()> {
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
        assert!(child.wait_success().unwrap());
        env::remove_var(SENTINEL_ENV);
        drop(open_handles);
    }
}
