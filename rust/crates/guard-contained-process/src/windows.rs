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
use std::ptr::{null, null_mut};
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

pub struct AppContainer {
    name: Vec<u16>,
    sid: PSID,
    closed: bool,
}

impl AppContainer {
    /// Every run uses a new SID; no network capabilities or loopback exemption
    /// are requested. Creation and LPAC process attributes are probed by launch.
    pub fn create(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid AppContainer name",
            ));
        }
        let name = wide(OsStr::new(name))?;
        let mut sid = null_mut();
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null_mut(),
                0,
                &mut sid,
            )
        };
        if status < 0 || sid.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("AppContainer creation failed: {status:#x}"),
            ));
        }
        Ok(Self {
            name,
            sid,
            closed: false,
        })
    }

    /// Grants touch only newly-created private staging objects, never the live
    /// workspace, user profile, Guard state, executable installation or host ACLs.
    pub fn grant(&self, path: &Path, writable: bool, directory: bool) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .access_mode(0x0002_0000 | 0x0004_0000 | 0x0008_0000)
            .share_mode(1 | 2)
            .custom_flags(0x0020_0000 | if directory { 0x0200_0000 } else { 0 })
            .open(path)?;
        let metadata = file.metadata()?;
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 || metadata.is_dir() != directory {
            return Err(crate::bound_fs::changed());
        }
        let handle = file.as_raw_handle() as HANDLE;
        let mut owner: PSID = null_mut();
        let mut old_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut old_descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        struct Local(*mut std::ffi::c_void);
        impl Drop for Local {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _old = Local(old_descriptor);
        let mut entries: [EXPLICIT_ACCESS_W; 2] = unsafe { zeroed() };
        for (entry, (sid, rights)) in entries.iter_mut().zip([
            (owner, 0x001f_01ff),
            (
                self.sid,
                if writable {
                    FILE_READ_WRITE_EXECUTE
                } else {
                    FILE_READ_EXECUTE
                },
            ),
        ]) {
            entry.grfAccessPermissions = rights;
            entry.grfAccessMode = SET_ACCESS;
            entry.grfInheritance = if directory && writable { 3 } else { 0 };
            entry.Trustee.pMultipleTrustee = null_mut();
            entry.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
            entry.Trustee.ptstrName = sid.cast();
        }
        let mut acl: PACL = null_mut();
        let status = unsafe { SetEntriesInAclW(2, entries.as_mut_ptr(), null_mut(), &mut acl) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _acl = Local(acl.cast());
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // DACL grants alone do not permit a low-integrity AppContainer to write
        // medium-integrity user files. Only captured private objects are lowered.
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text: *const u16,
                revision: u32,
                descriptor: *mut PSECURITY_DESCRIPTOR,
                size: *mut u32,
            ) -> i32;
            fn GetSecurityDescriptorSacl(
                descriptor: PSECURITY_DESCRIPTOR,
                present: *mut i32,
                sacl: *mut PACL,
                defaulted: *mut i32,
            ) -> i32;
        }
        let label = wide(OsStr::new(if directory {
            "S:(ML;OICI;NW;;;LW)"
        } else {
            "S:(ML;;NW;;;LW)"
        }))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                label.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _label = Local(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut sacl = null_mut();
        if unsafe { GetSecurityDescriptorSacl(descriptor, &mut present, &mut sacl, &mut defaulted) }
            == 0
            || present == 0
            || sacl.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                0x10,
                null_mut(),
                null_mut(),
                null_mut(),
                sacl,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            let status = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            if status < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("AppContainer cleanup failed: {status:#x}"),
                ));
            }
            self.closed = true;
        }
        Ok(())
    }
}
impl Drop for AppContainer {
    fn drop(&mut self) {
        if !self.closed {
            unsafe {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
        }
        unsafe {
            FreeSid(self.sid);
        }
    }
}

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
    let mut environment: Vec<(OsString, OsString)> = command.environment.clone();
    environment.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut env = Vec::new();
    for (key, value) in environment {
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

#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[repr(C)]
struct RenameInfo {
    replace: u8,
    root: HANDLE,
    length: u32,
    name: [u16; 1],
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationFile(
        file: HANDLE,
        status: *mut IoStatus,
        information: *mut std::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
}
pub(crate) fn rename_bound(
    source: &File,
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    replace: bool,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let root = std::fs::OpenOptions::new()
        .access_mode(0x0010_0082)
        .share_mode(1 | 2 | 4)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent.path())?;
    if guard_runtime_windows_process::handle_file_id(&root)?
        != guard_runtime_windows_process::handle_file_id(parent.handle())?
    {
        return Err(crate::bound_fs::changed());
    }
    let name = wide(name)?;
    let name = &name[..name.len() - 1];
    let offset = std::mem::offset_of!(RenameInfo, name);
    let length = offset + name.len() * 2;
    let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
    let information = storage.as_mut_ptr().cast::<RenameInfo>();
    unsafe {
        (*information).replace = u8::from(replace);
        (*information).root = root.as_raw_handle() as HANDLE;
        (*information).length = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            information.cast::<u8>().add(offset).cast(),
            name.len(),
        );
    }
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let result = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut status,
            information.cast(),
            length as u32,
            10,
        )
    };
    if result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bound output rename failed: {result:#x}"),
        ));
    }
    parent.verify()
}

fn transaction_file(path: &Path, write: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let access = 0x8000_0000 | 0x0001_0000 | if write { 0x4000_0000 } else { 0 };
    // DELETE authority is on this opened object. With no WRITE/DELETE sharing,
    // third-party target mutation/rename cannot change the object we move.
    let file = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    if !file.metadata()?.is_file() || file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(crate::bound_fs::changed());
    }
    Ok(file)
}
fn delete_object(file: &File) -> io::Result<()> {
    let mut delete = 1u8;
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut status,
            (&mut delete as *mut u8).cast(),
            1,
            13,
        )
    };
    if result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bound output disposal failed: {result:#x}"),
        ));
    }
    Ok(())
}
fn published_object(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: &crate::bound_fs::Identity,
) -> io::Result<bool> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1 | 2 | 4)
        .custom_flags(0x0020_0000)
        .open(parent.path().join(name))?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Ok(false);
    }
    Ok(crate::bound_fs::identity(&file)?.same_object(expected))
}
pub(crate) fn promote_transaction(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    recovery: &crate::bound_fs::Directory,
    expected: Option<(&crate::bound_fs::Identity, &str)>,
    written: &crate::bound_fs::ReadFile,
) -> io::Result<()> {
    let mut new = transaction_file(&recovery.path().join("new"), true)?;
    let bytes = crate::bound_fs::read_file(&mut new, 256 * 1024 * 1024)?;
    if !bytes.identity.same_object(&written.identity) || bytes.digest != written.digest {
        return Err(crate::bound_fs::changed());
    }
    let old = if let Some((expected_id, expected_digest)) = expected {
        let mut old = transaction_file(&parent.path().join(name), false)?;
        let read = crate::bound_fs::read_file(&mut old, 256 * 1024 * 1024)?;
        if &read.identity != expected_id || read.digest != expected_digest {
            return Err(crate::bound_fs::changed());
        }
        parent.verify()?;
        if !published_object(parent, name, expected_id)? {
            return Err(crate::bound_fs::changed());
        }
        rename_bound(&old, recovery, OsStr::new("old"), false)?;
        Some(old)
    } else {
        None
    };
    if let Err(error) = rename_bound(&new, parent, name, false) {
        // A newly created user target wins. Restore only into an absent name;
        // never overwrite that target. The old bytes remain in recovery/old
        // when an intervening writer prevents restoration.
        if let Some(old) = old.as_ref() {
            let _ = rename_bound(old, parent, name, false);
        }
        delete_object(&new)?;
        return Err(error);
    }
    if !published_object(parent, name, &written.identity)? {
        return Err(crate::bound_fs::changed());
    }
    if let Some(old) = old.as_ref() {
        delete_object(old)?;
    }
    parent.verify()
}

pub(crate) fn remove_bound_file(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: (&crate::bound_fs::Identity, &str),
) -> io::Result<()> {
    let mut file = transaction_file(&parent.path().join(name), false)?;
    let read = crate::bound_fs::read_file(&mut file, 256 * 1024 * 1024)?;
    if read.identity != *expected.0
        || read.digest != expected.1
        || !published_object(parent, name, expected.0)?
    {
        return Err(crate::bound_fs::changed());
    }
    parent.verify()?;
    delete_object(&file)?;
    parent.verify()
}
pub(crate) fn remove_bound_directory(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: &crate::bound_fs::Identity,
) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let path = parent.path().join(name);
    let file = std::fs::OpenOptions::new()
        .access_mode(0x8000_0000 | 0x0001_0000)
        .share_mode(1)
        .custom_flags(0x0220_0000)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes() & 0x400 != 0
        || !crate::bound_fs::identity(&file)?.same_object(expected)
    {
        return Err(crate::bound_fs::changed());
    }
    if std::fs::read_dir(&path)?.next().transpose()?.is_some() {
        return Err(crate::bound_fs::changed());
    }
    parent.verify()?;
    // DELETE disposition belongs to this held, non-reparse object. Windows
    // itself refuses a nonempty directory; no recursive live path cleanup.
    delete_object(&file)?;
    parent.verify()
}

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
