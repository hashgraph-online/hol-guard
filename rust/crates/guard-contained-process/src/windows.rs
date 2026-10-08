use crate::{CapturedOutput, Isolation, PinnedCommand};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use winapi::shared::ntdef::HANDLE;
use winapi::um::accctrl::{
    EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER,
};
use winapi::um::aclapi::{GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo};
use winapi::um::processthreadsapi::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, PROCESS_INFORMATION,
};
use winapi::um::securitybaseapi::FreeSid;
use winapi::um::userenv::{CreateAppContainerProfile, DeleteAppContainerProfile};
use winapi::um::winbase::{
    LocalFree, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use winapi::um::winnt::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PACL,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

const HANDLE_LIST: usize = 0x0002_0002;
const SECURITY_CAPABILITIES: usize = 0x0002_0009;
// LPAC excludes ALL_APPLICATION_PACKAGES. Only explicitly granted snapshot
// objects and the OS's ALL_RESTRICTED_APPLICATION_PACKAGES runtime remain readable.
const ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000f;
const ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;
const FILE_READ_EXECUTE: u32 = 0x0012_00a9;
const FILE_READ_WRITE_EXECUTE: u32 = 0x0013_01ff;

#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: PSID,
    capabilities: *mut winapi::um::winnt::SID_AND_ATTRIBUTES,
    capability_count: u32,
    reserved: u32,
}

mod app_container;
pub use app_container::AppContainer;

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in process value",
        ));
    }
    result.push(0);
    Ok(result)
}

fn quoted(value: &OsStr, output: &mut Vec<u16>) -> io::Result<()> {
    let value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in process argument",
        ));
    }
    output.push(b'"' as u16);
    let mut slashes = 0;
    for ch in value {
        if ch == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        if ch == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        }
        slashes = 0;
        output.push(ch);
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }
    fn add<T>(&mut self, attribute: usize, value: &mut T) -> io::Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.storage.as_mut_ptr().cast(),
                0,
                attribute,
                (value as *mut T).cast(),
                size_of::<T>(),
                null_mut(),
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast());
        }
    }
}

pub(crate) fn capture(
    command: PinnedCommand,
    input: &[u8],
    cap: usize,
    deadline: Instant,
    cancel: &AtomicBool,
    mut isolation: Isolation,
) -> io::Result<CapturedOutput> {
    if isolation.resources.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "legacy CPU/address-space/file/descriptor resource guarantees unavailable on Windows",
        ));
    }
    command.verify_bindings()?;
    let result = capture_native(
        &command,
        isolation.app_container.as_ref(),
        input,
        cap,
        isolation.output_per_stream,
        deadline,
        cancel,
    );
    let cleanup = isolation
        .app_container
        .as_mut()
        .map_or(Ok(()), AppContainer::close);
    cleanup?;
    result
}

fn convert(output: guard_runtime_windows_process::CapturedOutput) -> CapturedOutput {
    CapturedOutput {
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
        timed_out: output.timed_out,
        output_limited: output.output_limited,
        cancelled: output.cancelled,
        completion: Vec::new(),
    }
}

fn capture_native(
    command: &PinnedCommand,
    container: Option<&AppContainer>,
    input: &[u8],
    cap: usize,
    per_stream: bool,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<CapturedOutput> {
    if Instant::now() >= deadline || cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "AppContainer deadline before launch",
        ));
    }
    let pipes = guard_runtime_windows_process::capture_pipes()?;
    let mut handles = [
        pipes.child_stdin.as_raw_handle() as HANDLE,
        pipes.child_stdout.as_raw_handle() as HANDLE,
        pipes.child_stderr.as_raw_handle() as HANDLE,
    ];
    let mut capabilities = SecurityCapabilities {
        app_container_sid: container.map_or(null_mut(), |container| container.sid),
        capabilities: null_mut(),
        capability_count: 0,
        reserved: 0,
    };
    let mut lpac = ALL_APPLICATION_PACKAGES_OPT_OUT;
    let mut attributes = Attributes::new(if container.is_some() { 3 } else { 1 })?;
    attributes.add(HANDLE_LIST, &mut handles)?;
    if container.is_some() {
        attributes.add(SECURITY_CAPABILITIES, &mut capabilities)?;
        attributes.add(ALL_APPLICATION_PACKAGES_POLICY, &mut lpac)?;
    }
    let executable = wide(command.executable_path.as_os_str())?;
    let cwd = wide(command.cwd.path().as_os_str())?;
    let mut argv = Vec::new();
    quoted(command.executable_path.as_os_str(), &mut argv)?;
    for arg in &command.arguments {
        argv.push(b' ' as u16);
        quoted(arg, &mut argv)?;
    }
    argv.push(0);
    if argv.len() > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows argv byte budget exceeded",
        ));
    }
    let mut env = environment_block(&command.environment)?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.storage.as_mut_ptr().cast();
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    if Instant::now() >= deadline || cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "AppContainer request expired before process creation",
        ));
    }
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            argv.as_mut_ptr(),
            null_mut(),
            null_mut(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            env.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &mut startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    let thread_handle = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    let guard = guard_runtime_windows_process::attach_suspended_process(
        process_handle,
        thread_handle,
        None,
        deadline,
        cancel,
    )?;
    guard_runtime_windows_process::capture_owned_child(
        guard, pipes, input, cap, per_stream, deadline, cancel,
    )
    .map(convert)
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, length: u32) -> u32;
}
pub(crate) fn system_directory() -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(std::path::PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )))
}

mod files;
pub(crate) use files::{promote_transaction, remove_bound_directory, remove_bound_file};

pub(crate) fn job_containment_probe() -> io::Result<bool> {
    use winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn IsProcessInJob(process: HANDLE, job: HANDLE, result: *mut i32) -> i32;
        fn QueryInformationJobObject(
            job: HANDLE,
            class: i32,
            information: *mut std::ffi::c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut member = 0;
    if unsafe {
        IsProcessInJob(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            null_mut(),
            &mut member,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if member == 0 {
        return Ok(false);
    }
    let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            null_mut(),
            9,
            (&mut information as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let flags = information.BasicLimitInformation.LimitFlags;
    Ok(flags & 0x2000 != 0 && flags & (0x800 | 0x1000) == 0)
}

fn environment_block(entries: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    let mut environment = entries.to_vec();
    environment.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut env = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for (key, value) in environment {
        if !names.insert(key.to_string_lossy().to_uppercase()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate environment name",
            ));
        }
        if key.is_empty() || key.to_string_lossy().contains('=') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment key",
            ));
        }
        let key = wide(&key)?;
        let value = wide(&value)?;
        env.extend_from_slice(&key[..key.len() - 1]);
        env.push(b'=' as u16);
        env.extend_from_slice(&value);
    }
    env.push(0);
    if env.len() == 1 {
        env.push(0);
    }
    Ok(env)
}

#[cfg(test)]
#[path = "windows/environment_tests.rs"]
mod environment_tests;
