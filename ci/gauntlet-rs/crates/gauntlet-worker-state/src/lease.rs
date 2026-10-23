//! Nonblocking exclusive lease for one live Linux worker invocation.
//! The descriptor owns the lock until it is dropped.

use crate::{
    io, ReservationError, RunReservationJournal, StartedMarker, TerminalOutcome, TerminalReceipt,
};
use gauntlet_contracts::WorkerRequest;
use rustix::fs::{
    flock, fstat, fsync, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags,
};
use rustix::io::Errno;
use std::os::fd::OwnedFd;

const LEASE_FILE: &str = "active.lock";

pub struct ActiveLease {
    descriptor: OwnedFd,
    root_dev: u64,
    root_ino: u64,
    lock_dev: u64,
    lock_ino: u64,
}

fn acquire(root: &OwnedFd, require_root: bool) -> Result<ActiveLease, ReservationError> {
    let descriptor = openat(
        root,
        LEASE_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(io)?;
    let opened = fstat(&descriptor).map_err(io)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_nlink != 1
        || opened.st_mode & 0o077 != 0
        || (require_root && opened.st_uid != 0)
    {
        return Err(ReservationError::UnsafeRoot);
    }
    match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::AGAIN) => return Err(ReservationError::LeaseBusy),
        Err(error) => return Err(io(error)),
    }
    let visible = statat(root, LEASE_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if visible.st_dev != opened.st_dev || visible.st_ino != opened.st_ino {
        return Err(ReservationError::UnsafeRoot);
    }
    fsync(&descriptor).map_err(io)?;
    fsync(root).map_err(io)?;
    let root_stat = fstat(root).map_err(io)?;
    Ok(ActiveLease {
        descriptor,
        root_dev: root_stat.st_dev as u64,
        root_ino: root_stat.st_ino,
        lock_dev: opened.st_dev as u64,
        lock_ino: opened.st_ino,
    })
}

impl ActiveLease {
    pub(crate) fn verify(&self, root: &OwnedFd) -> Result<(), ReservationError> {
        let current_root = fstat(root).map_err(io)?;
        let descriptor = fstat(&self.descriptor).map_err(io)?;
        let visible = statat(root, LEASE_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if current_root.st_dev as u64 != self.root_dev
            || current_root.st_ino != self.root_ino
            || descriptor.st_dev as u64 != self.lock_dev
            || descriptor.st_ino != self.lock_ino
            || visible.st_dev as u64 != self.lock_dev
            || visible.st_ino != self.lock_ino
        {
            return Err(ReservationError::UnsafeRoot);
        }
        Ok(())
    }
}

impl RunReservationJournal {
    /// Acquire the one active-worker lease without waiting. The caller must
    /// retain `ActiveLease` through process exit, cleanup and terminal receipt.
    pub fn acquire_active_lease(&self) -> Result<ActiveLease, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        acquire(&self.root, true)
    }

    /// The live worker path requires its lease before consuming a job ID.
    pub fn reserve_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        self.reserve_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            None,
        )
    }

    /// The Rust-owned deterministic path anchors its public signing key in
    /// the immutable started marker before any controller process exists.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(crate) fn reserve_keyed_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        controller_public_key_hex: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        self.reserve_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            Some(controller_public_key_hex),
        )
    }

    /// The same lease must cover durable terminal writing and cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: crate::ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
        expected_controller_key_pin_sha256: Option<&str>,
    ) -> Result<TerminalReceipt, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        #[cfg(target_os = "linux")]
        {
            let running = self
                .running_marker(
                    request.job_id(),
                    source_sha,
                    deployment_digest,
                    worker_generation,
                )?
                .ok_or(ReservationError::InvalidMarker)?;
            if running.process != process
                || running.started_marker_sha256 != expected_started_sha256
            {
                return Err(ReservationError::InvalidMarker);
            }
            crate::require_rust_job_slice_absent(request.job_id())?;
        }
        self.finish_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            expected_started_sha256,
            report_raw,
            process,
            exit_code,
            status,
            expected_controller_key_pin_sha256,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_canonical_directory, ProcessIdentity};
    use gauntlet_contracts::WorkerRequest;
    use serde_json::json;
    use std::fs;

    #[test]
    fn separate_open_descriptions_compete_for_one_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let first = RunReservationJournal::open(&root).unwrap();
        let second = RunReservationJournal::open(&root).unwrap();
        let held = acquire(&first.root, false).unwrap();
        assert!(matches!(
            acquire(&second.root, false),
            Err(ReservationError::LeaseBusy)
        ));
        assert!(matches!(
            first.acquire_active_lease(),
            Err(ReservationError::UnsafeRoot)
        ));
        drop(held);
        let recovered = acquire(&second.root, false).unwrap();
        recovered.verify(&second.root).unwrap();
    }

    #[test]
    fn replacing_the_visible_lock_file_invalidates_the_held_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let journal = RunReservationJournal::open(&root).unwrap();
        let held = acquire(&journal.root, false).unwrap();
        fs::rename(root.join(LEASE_FILE), root.join("old.lock")).unwrap();
        fs::write(root.join(LEASE_FILE), b"replacement").unwrap();
        assert!(matches!(
            held.verify(&journal.root),
            Err(ReservationError::UnsafeRoot)
        ));
    }

    #[test]
    fn live_journal_rejects_unleased_write_entrypoints() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let journal = RunReservationJournal {
            root: open_canonical_directory(&root, false).unwrap(),
            root_owned: true,
        };
        let source = "a".repeat(40);
        let deployment = "b".repeat(64);
        let generation = "c".repeat(64);
        let request = WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1",
                "action":"run",
                "source_sha":source,
                "job_id":"dddddddddddddddd",
                "deployment_digest":deployment,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            journal.reserve(&request, &source, &deployment, &generation),
            Err(ReservationError::UnsafeRoot)
        );
        assert_eq!(
            journal.finish(
                &request,
                &source,
                &deployment,
                &generation,
                &"e".repeat(64),
                br#"{}"#,
                ProcessIdentity {
                    pid: 1,
                    start_ticks: 1,
                },
                0,
                TerminalOutcome::Passed,
            ),
            Err(ReservationError::UnsafeRoot)
        );
    }
}
