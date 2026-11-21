use super::*;
use std::process::Child;
use winapi::um::jobapi2::{AssignProcessToJobObject, SetInformationJobObject};
use winapi::um::processenv::GetStdHandle;
use winapi::um::processthreadsapi::{OpenProcess, OpenThread, ResumeThread};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use winapi::um::winbase::{
    CREATE_NO_WINDOW, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use winapi::um::winnt::{
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    THREAD_SUSPEND_RESUME,
};

/// The `CreateProcess` flags a `std::process::Command` sets, through
/// `CommandExt::creation_flags`, before `ChildTree::adopt_suspended`:
/// suspended, and without a console window of its own, since the managed
/// runtime that launches it runs detached.
pub const CHILD_TREE_CREATION_FLAGS: u32 = CREATE_SUSPENDED | CREATE_NO_WINDOW;

/// A kill-on-close JobObject that holds a `std::process::Child` and every
/// process it starts, the Windows counterpart of a POSIX process group.
///
/// The child is spawned suspended and assigned before its only thread
/// resumes, so no descendant can start outside the job.
pub struct ChildTree {
    job: OwnedHandle,
}

/// What a job holds its tree to. The default is the strict arm: kill on close,
/// no breakaway, no resource limit.
#[derive(Clone, Copy, Debug)]
pub struct ChildTreeOptions {
    /// Kill every member when the last handle to the job closes.
    pub kill_on_close: bool,
    /// Let a member leave the job (a detached daemon the host must outlive).
    pub allow_breakaway: bool,
    /// Memory committed by the whole job, in bytes.
    pub job_memory_limit_bytes: Option<usize>,
    /// Processes the job may hold at once.
    pub active_process_limit: Option<u32>,
}

impl Default for ChildTreeOptions {
    fn default() -> Self {
        Self {
            kill_on_close: true,
            allow_breakaway: false,
            job_memory_limit_bytes: None,
            active_process_limit: None,
        }
    }
}

impl ChildTree {
    /// Assign a child spawned with `CHILD_TREE_CREATION_FLAGS` to a new
    /// job, then resume it. On error the caller still owns the suspended
    /// child and must kill and reap it.
    pub fn adopt_suspended(child: &Child) -> io::Result<Self> {
        Self::adopt_suspended_with(child, ChildTreeOptions::default())
    }

    /// `adopt_suspended` with the job's limits chosen by the caller.
    pub fn adopt_suspended_with(child: &Child, options: ChildTreeOptions) -> io::Result<Self> {
        let job = limited_job(options)?;
        // SAFETY: `child` owns its process handle for the duration of the call.
        if unsafe {
            AssignProcessToJobObject(
                job.as_raw_handle() as HANDLE,
                child.as_raw_handle() as HANDLE,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        resume_only_thread(child.id())?;
        Ok(Self { job })
    }

    /// Assign a running process, by id, to a new job. This is how a process
    /// that is already executing (a Python hook bootstrap) is contained by a
    /// holder that outlives it: the job dies with the holder or on `terminate`.
    pub fn adopt_process_id(process_id: u32, options: ChildTreeOptions) -> io::Result<Self> {
        let job = limited_job(options)?;
        // SAFETY: Plain access mask and process ID; the handle is wrapped exactly once.
        let process =
            unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, process_id) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcess returned this handle exactly once.
        let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
        // SAFETY: both handles are live for the duration of the call.
        if unsafe {
            AssignProcessToJobObject(
                job.as_raw_handle() as HANDLE,
                process.as_raw_handle() as HANDLE,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { job })
    }

    /// Terminate every process in the tree. Idempotent.
    pub fn terminate(&self) -> io::Result<()> {
        process_lifecycle::terminate_job(&self.job)
    }
}

/// A job holding `options`' limits and no member yet.
fn limited_job(options: ChildTreeOptions) -> io::Result<OwnedHandle> {
    let job = process_lifecycle::create_process_job()?;
    let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    let mut flags = 0;
    if options.kill_on_close {
        flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    if options.allow_breakaway {
        flags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    }
    if let Some(bytes) = options.job_memory_limit_bytes {
        limits.JobMemoryLimit = bytes;
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    }
    if let Some(processes) = options.active_process_limit {
        limits.BasicLimitInformation.ActiveProcessLimit = processes;
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    }
    limits.BasicLimitInformation.LimitFlags = flags;
    // SAFETY: `job` is a live job handle and `limits` outlives the call.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

/// Stop this process's standard handles from leaking into every child it
/// creates. `std::process::Command` always creates children with handle
/// inheritance on, so a long-lived child (a detached daemon launch) would
/// otherwise hold the host's stdio pipes open after this process exits.
/// `Stdio::inherit` still hands a child these handles: std duplicates them
/// as inheritable for that one launch.
pub fn disinherit_standard_handles() {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle takes a plain selector and returns a borrowed
        // handle that this process keeps open.
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // SAFETY: `handle` is a live standard handle. A console pseudo-handle
        // that rejects the call was never inheritable, so a failure is ignored.
        unsafe {
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

/// Resume the single suspended thread of a freshly created process. A
/// process with any other thread count was not created suspended by us.
fn resume_only_thread(process_id: u32) -> io::Result<()> {
    // SAFETY: Plain flag values; the returned handle is wrapped exactly once.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateToolhelp32Snapshot returned this handle exactly once.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as RawHandle) };
    let mut entry = unsafe { zeroed::<THREADENTRY32>() };
    entry.dwSize = size_of::<THREADENTRY32>() as DWORD;
    let mut threads = Vec::new();
    // SAFETY: `snapshot` is live and `entry` carries its own size.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    while more != FALSE {
        if entry.th32OwnerProcessID == process_id {
            threads.push(entry.th32ThreadID);
        }
        // SAFETY: As above.
        more = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    }
    let [thread_id] = threads.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child is not a singly threaded suspended process",
        ));
    };
    // SAFETY: Plain access mask and thread ID; the handle is wrapped exactly once.
    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, FALSE, *thread_id) };
    if thread.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenThread returned this handle exactly once.
    let thread = unsafe { OwnedHandle::from_raw_handle(thread as RawHandle) };
    // SAFETY: `thread` owns a live thread handle until this call returns.
    match unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } {
        1 => Ok(()),
        value if value == DWORD::MAX => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child was not singly suspended",
        )),
    }
}
