use super::*;
use std::time::Duration;

use super::spawn_setup::SpawnSetup;
use winapi::um::jobapi::IsProcessInJob;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureAt {
    Create,
    Assign,
    Resume,
    None,
}

struct ObservedSetup {
    failure: FailureAt,
    cleanup_error: bool,
    events: Vec<&'static str>,
    contained: bool,
    reaped: bool,
    job_empty: bool,
}

impl SpawnSetup for ObservedSetup {
    fn create_job(&mut self) -> io::Result<OwnedHandle> {
        self.events.push("create");
        if self.failure == FailureAt::Create {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "create denied",
            ))
        } else {
            process_lifecycle::create_process_job()
        }
    }

    fn assign_job(&mut self, job: &OwnedHandle, process: &OwnedHandle) -> io::Result<()> {
        self.events.push("assign");
        if self.failure == FailureAt::Assign {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "assign denied",
            ));
        }
        process_lifecycle::assign_process_to_job(job, process)?;
        let mut contained = FALSE;
        // SAFETY: both handles are owned and the output points to initialized storage.
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    process.as_raw_handle() as HANDLE,
                    job.as_raw_handle() as HANDLE,
                    &mut contained,
                )
            },
            FALSE
        );
        self.contained = contained != FALSE;
        Ok(())
    }

    fn resume(&mut self, thread: &OwnedHandle) -> io::Result<()> {
        self.events.push("resume");
        assert!(
            self.contained,
            "child resumed before observed Job membership"
        );
        if self.failure == FailureAt::Resume {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "resume denied",
            ))
        } else {
            process_lifecycle::resume_thread(thread)
        }
    }

    fn cleanup(&mut self, process: &OwnedHandle, job: Option<&OwnedHandle>) -> io::Result<()> {
        self.events.push("cleanup");
        process_cleanup::terminate_and_wait(process, job, Duration::from_secs(2))?;
        self.reaped = !process_lifecycle::process_is_running(process)?;
        self.job_empty = match job {
            Some(job) => process_lifecycle::job_active_processes(job)? == 0,
            None => true,
        };
        if self.cleanup_error {
            Err(io::Error::other("injected cleanup report failure"))
        } else {
            Ok(())
        }
    }
}

fn setup(failure: FailureAt) -> ObservedSetup {
    ObservedSetup {
        failure,
        cleanup_error: false,
        events: Vec::new(),
        contained: false,
        reaped: false,
        job_empty: false,
    }
}

#[test]
fn rejected_job_setup_never_resumes_and_reaps_the_actual_suspended_child() {
    for (failure, expected) in [
        (FailureAt::Create, vec!["create", "cleanup"]),
        (FailureAt::Assign, vec!["create", "assign", "cleanup"]),
        (
            FailureAt::Resume,
            vec!["create", "assign", "resume", "cleanup"],
        ),
    ] {
        let mut setup = setup(failure);
        let result = spawn_managed_child_with_setup(
            &std::env::current_exe().unwrap(),
            &[OsStr::new("--list")],
            &mut setup,
        );
        let error = match result {
            Ok(child) => {
                let _ = child.terminate();
                panic!("failed containment unexpectedly returned a child");
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!managed_cleanup_failed(&error));
        assert_eq!(setup.events, expected);
        assert!(
            setup.reaped,
            "suspended child did not exit during bounded cleanup"
        );
        assert!(
            setup.job_empty,
            "Job was not observed empty before closing it"
        );
    }
}

#[test]
fn failed_setup_retains_cleanup_failure_after_actual_child_reap() {
    let mut setup = setup(FailureAt::Assign);
    setup.cleanup_error = true;
    let result = spawn_managed_child_with_setup(
        &std::env::current_exe().unwrap(),
        &[OsStr::new("--list")],
        &mut setup,
    );
    let error = match result {
        Ok(child) => {
            let _ = child.terminate();
            panic!("failed containment unexpectedly returned a child");
        }
        Err(error) => error,
    };
    assert!(setup.reaped);
    assert!(setup.job_empty);
    assert!(managed_cleanup_failed(&error));
    assert!(error.to_string().contains("assign denied"));
    assert!(error
        .to_string()
        .contains("injected cleanup report failure"));
}

#[test]
fn actual_child_is_assigned_before_resume_and_exits_normally() {
    let mut setup = setup(FailureAt::None);
    let child = spawn_managed_child_with_setup(
        &std::env::current_exe().unwrap(),
        &[OsStr::new("--list")],
        &mut setup,
    )
    .unwrap();
    let result = child.wait_success_with_timeout(Duration::from_secs(5));
    let cleanup = child.terminate();
    assert_eq!(setup.events, ["create", "assign", "resume"]);
    assert!(setup.contained);
    assert!(result.unwrap());
    cleanup.unwrap();
    assert_eq!(
        process_lifecycle::job_active_processes(&child.job).unwrap(),
        0
    );
}

#[test]
fn kill_on_close_is_set_and_only_explicitly_released_by_handoff() {
    use winapi::um::jobapi2::QueryInformationJobObject;
    use winapi::um::winnt::{
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    let job = process_lifecycle::create_process_job().unwrap();
    let flags = || {
        // SAFETY: initialized, correctly sized output and a live owned Job handle.
        let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        assert_ne!(
            unsafe {
                QueryInformationJobObject(
                    job.as_raw_handle() as HANDLE,
                    JobObjectExtendedLimitInformation,
                    &mut limits as *mut _ as *mut _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
                    null_mut(),
                )
            },
            FALSE
        );
        limits.BasicLimitInformation.LimitFlags
    };
    let before = flags();
    assert_ne!(before & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    process_lifecycle::set_job_kill_on_close(&job, false).unwrap();
    assert_eq!(flags(), before & !JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
}

#[test]
fn valid_exit_code_259_is_a_completed_unsuccessful_exit() {
    let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join("cmd.exe");
    let child = spawn_managed_child(
        &executable,
        &[
            OsStr::new("/D"),
            OsStr::new("/C"),
            OsStr::new("exit /b 259"),
        ],
    )
    .unwrap();
    let result = child.wait_success_with_timeout(Duration::from_secs(5));
    let exited = process_lifecycle::process_is_running(&child.process);
    let cleanup = child.terminate();
    assert!(!result.unwrap());
    assert!(!exited.unwrap());
    cleanup.unwrap();
}
