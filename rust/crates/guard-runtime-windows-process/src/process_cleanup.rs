use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::Duration;

use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::processthreadsapi::TerminateProcess;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{WAIT_FAILED, WAIT_OBJECT_0};

use super::job_retirement::{self, CleanupBudget};
use super::process_lifecycle;

#[derive(Debug)]
struct CleanupFailure {
    original: io::Error,
    cleanup: io::Error,
}

impl fmt::Display for CleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; managed process cleanup failed: {}",
            self.original, self.cleanup
        )
    }
}

impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub(super) fn has_cleanup_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<CleanupFailure>())
}

pub(super) fn preserve_cleanup_error(original: io::Error, cleanup: io::Result<()>) -> io::Error {
    match cleanup {
        Ok(()) => original,
        Err(cleanup) => io::Error::new(original.kind(), CleanupFailure { original, cleanup }),
    }
}

pub(super) fn terminate_and_wait(
    process: &OwnedHandle,
    job: Option<&OwnedHandle>,
    timeout: Duration,
) -> io::Result<()> {
    terminate_and_wait_with_budget(process, job, &CleanupBudget::new(timeout))
}

fn terminate_and_wait_with_budget(
    process: &OwnedHandle,
    job: Option<&OwnedHandle>,
    budget: &CleanupBudget,
) -> io::Result<()> {
    // Restore the fallback guard before forced cleanup, including a startup
    // handoff that disarmed the outer Job just as the request deadline expired.
    let guard_result = job
        .map(|job| process_lifecycle::set_job_kill_on_close(job, true))
        .transpose()
        .map(|_| ());
    let job_result = job.map(process_lifecycle::terminate_job).transpose();
    let job_result = match guard_result {
        Ok(()) => job_result.map(|_| ()),
        Err(error) => Err(preserve_cleanup_error(error, job_result.map(|_| ()))),
    };
    // Always stop the directly owned child too: a failed assignment may leave it
    // outside the Job. A Job error still matters even if this process exits.
    // SAFETY: the process handle is owned throughout termination and the wait.
    let termination_result =
        if unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) } == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
    let before_wait = budget.remaining();
    let millis = process_lifecycle::duration_to_wait_millis(before_wait);
    // SAFETY: this is the same owned process handle used for termination above.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, millis) };
    let wait_result = match wait {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "process termination wait timed out",
        )),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected process wait result")),
    };
    let wait_result = require_timely_observation(before_wait, budget.remaining(), wait_result);
    let process_result = combine_cleanup_results(job_result, termination_result, wait_result);
    let job_result = job
        .map(|job| job_retirement::wait_for_empty_job(job, budget))
        .transpose()
        .map(|_| ());
    match process_result {
        Ok(()) => job_result,
        Err(error) => Err(preserve_cleanup_error(error, job_result)),
    }
}

fn require_timely_observation(
    before: Duration,
    after: Duration,
    result: io::Result<()>,
) -> io::Result<()> {
    if before.is_zero() || after.is_zero() {
        let timeout = io::Error::new(
            io::ErrorKind::TimedOut,
            "process exit observation timed out",
        );
        match result {
            Ok(()) => Err(timeout),
            Err(error) => Err(preserve_cleanup_error(error, Err(timeout))),
        }
    } else {
        result
    }
}

pub(super) fn retire_after_exit(
    process: &OwnedHandle,
    job: &OwnedHandle,
    timeout: Duration,
) -> io::Result<bool> {
    let budget = CleanupBudget::new(timeout);
    let grace = CleanupBudget::new(budget.remaining().min(job_retirement::NATURAL_EXIT_GRACE));
    match job_retirement::wait_for_empty_job_during_grace(job, &budget, &grace) {
        Ok(()) => Ok(true),
        Err(error) => {
            let cleanup = terminate_and_wait_with_budget(process, Some(job), &budget);
            if error.kind() == io::ErrorKind::TimedOut {
                // An emptied Job after forced termination is not a normal exit.
                match cleanup {
                    Ok(()) => Ok(false),
                    Err(cleanup) => Err(preserve_cleanup_error(error, Err(cleanup))),
                }
            } else {
                Err(preserve_cleanup_error(error, cleanup))
            }
        }
    }
}

fn combine_cleanup_results(
    job: io::Result<()>,
    termination: io::Result<()>,
    wait: io::Result<()>,
) -> io::Result<()> {
    // TerminateProcess may lose a race to an already exiting process. The owned
    // handle becoming signaled proves completion regardless of that call's result.
    let process_result = match (termination, wait) {
        (_, Ok(())) => Ok(()),
        (Ok(()), Err(wait)) => Err(wait),
        (Err(termination), Err(wait)) => Err(preserve_cleanup_error(termination, Err(wait))),
    };
    match job {
        Ok(()) => process_result,
        Err(job) => Err(preserve_cleanup_error(job, process_result)),
    }
}

#[cfg(test)]
#[path = "process_cleanup_tests.rs"]
mod tests;
