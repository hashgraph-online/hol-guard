use std::io;
use std::os::windows::io::OwnedHandle;
use std::time::Duration;

use super::{process_cleanup, process_lifecycle};

const SPAWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) trait SpawnSetup {
    fn create_job(&mut self) -> io::Result<OwnedHandle> {
        process_lifecycle::create_process_job()
    }

    fn assign_job(&mut self, job: &OwnedHandle, process: &OwnedHandle) -> io::Result<()> {
        process_lifecycle::assign_process_to_job(job, process)
    }

    fn resume(&mut self, thread: &OwnedHandle) -> io::Result<()> {
        process_lifecycle::resume_thread(thread)
    }

    fn cleanup(&mut self, process: &OwnedHandle, job: Option<&OwnedHandle>) -> io::Result<()> {
        process_cleanup::terminate_and_wait(process, job, SPAWN_CLEANUP_TIMEOUT)
    }
}

pub(super) struct WindowsSpawnSetup;

impl SpawnSetup for WindowsSpawnSetup {}

pub(super) fn contain_and_resume(
    process: &OwnedHandle,
    thread: &OwnedHandle,
    setup: &mut impl SpawnSetup,
) -> io::Result<OwnedHandle> {
    let job = match setup.create_job() {
        Ok(job) => job,
        Err(error) => {
            return Err(process_cleanup::preserve_cleanup_error(
                error,
                setup.cleanup(process, None),
            ))
        }
    };
    let setup_result = setup
        .assign_job(&job, process)
        .and_then(|()| setup.resume(thread));
    match setup_result {
        Ok(()) => Ok(job),
        Err(error) => Err(process_cleanup::preserve_cleanup_error(
            error,
            setup.cleanup(process, Some(&job)),
        )),
    }
}
