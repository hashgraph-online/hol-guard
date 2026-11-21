use super::*;
use std::time::{Duration, Instant};
use winapi::um::jobapi2::{QueryInformationJobObject, SetInformationJobObject};
use winapi::um::processthreadsapi::{GetProcessId, GetProcessIdOfThread, ResumeThread};
use winapi::um::winnt::{
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
};

/// Native JobObject guarantees, not aliases for POSIX RLIMIT_CPU/RLIMIT_AS.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResourceLimits {
    /// User-mode CPU time per process; does not count kernel-mode CPU time.
    pub cpu_user_seconds: Option<u64>,
    /// Committed memory per process; not a virtual-address-space limit.
    pub committed_memory_bytes: Option<usize>,
    pub active_processes: Option<u32>,
}

/// Owns the process and its non-breakaway, kill-on-close JobObject.
/// A process is assigned while suspended; no uncontained instruction can run.
pub struct ChildJobGuard {
    pub(super) process: OwnedHandle,
    job: Option<OwnedHandle>,
    process_id: u32,
}

pub fn attach_suspended_process(
    process: OwnedHandle,
    thread: OwnedHandle,
    resources: Option<ResourceLimits>,
    deadline: Instant,
    cancellation: &std::sync::atomic::AtomicBool,
) -> io::Result<ChildJobGuard> {
    // The guard owns the suspended process before any fallible job setup.
    let mut child = ChildJobGuard {
        process_id: unsafe { GetProcessId(process.as_raw_handle() as HANDLE) },
        process,
        job: None,
    };
    if child.process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { GetProcessIdOfThread(thread.as_raw_handle() as HANDLE) } != child.process_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "thread does not belong to child",
        ));
    }
    let job = process_lifecycle::create_process_job()?;
    let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if let Some(resources) = resources {
        if let Some(seconds) = resources.cpu_user_seconds {
            let ticks = seconds
                .checked_mul(10_000_000)
                .and_then(|ticks| i64::try_from(ticks).ok())
                .filter(|ticks| *ticks > 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "CPU user-time limit invalid")
                })?;
            unsafe {
                *limits
                    .BasicLimitInformation
                    .PerProcessUserTimeLimit
                    .QuadPart_mut() = ticks;
            }
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        }
        if let Some(bytes) = resources.committed_memory_bytes {
            if bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "committed memory limit invalid",
                ));
            }
            limits.ProcessMemoryLimit = bytes;
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }
        if let Some(processes) = resources.active_processes {
            if processes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "active process limit invalid",
                ));
            }
            limits.BasicLimitInformation.ActiveProcessLimit = processes;
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }
    }
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
    process_lifecycle::assign_process_to_job(&job, &child.process)?;
    child.job = Some(job);
    if cancellation.load(std::sync::atomic::Ordering::Acquire) || Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "child request expired before resume",
        ));
    }
    match unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } {
        1 => {}
        value if value == u32::MAX => return Err(io::Error::last_os_error()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child was not singly suspended",
            ))
        }
    }
    Ok(child)
}

impl ChildJobGuard {
    pub fn id(&self) -> u32 {
        self.process_id
    }

    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        match unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as HANDLE, &mut code) }
                    == FALSE
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(code))
            }
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected child wait result")),
        }
    }

    /// Terminate every member, then observe root and job quiescence by deadline.
    pub fn terminate_and_wait(&mut self, deadline: Instant) -> io::Result<()> {
        if let Some(job) = &self.job {
            process_lifecycle::terminate_job(job)?;
        } else if process_lifecycle::process_is_running(&self.process)?
            && unsafe { TerminateProcess(self.process.as_raw_handle() as HANDLE, 1) } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        let millis = process_lifecycle::duration_to_wait_millis(
            deadline.saturating_duration_since(Instant::now()),
        );
        match unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, millis) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child reap deadline",
                ))
            }
            WAIT_FAILED => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("unexpected child reap result")),
        }
        if let Some(job) = &self.job {
            loop {
                let mut accounting = unsafe { zeroed::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() };
                if unsafe {
                    QueryInformationJobObject(
                        job.as_raw_handle() as HANDLE,
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as DWORD,
                        null_mut(),
                    )
                } == FALSE
                {
                    return Err(io::Error::last_os_error());
                }
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "job reap deadline"));
                }
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cleanup_incomplete",
            ));
        }
        Ok(())
    }
}

impl Drop for ChildJobGuard {
    fn drop(&mut self) {
        // Errors are returned by terminate_and_wait on ordinary paths. During
        // unwinding, kill-on-close is the independent OS ownership backstop.
        if let Some(job) = &self.job {
            let _ = process_lifecycle::terminate_job(job);
        } else {
            unsafe {
                TerminateProcess(self.process.as_raw_handle() as HANDLE, 1);
            }
        }
    }
}
