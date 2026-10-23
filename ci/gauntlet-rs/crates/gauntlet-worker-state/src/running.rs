//! Durable, inert process identity after a one-time reservation. A marker is
//! never proof of liveness without a fresh pidfd/start-tick/cgroup sample.

use crate::linux_process::{observe_process, valid_cgroup};
use crate::{
    hex, io, marker_name, read_bounded_regular, ActiveLease, ProcessIdentity, ReservationError,
    RunReservationJournal,
};
use gauntlet_contracts::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use rustix::fs::{fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

const RUNNING_SCHEMA: &str = "hol-gauntlet-worker-running.v1";
const MAX_RUNNING_BYTES: u64 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningMarker {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub process: ProcessIdentity,
    pub cgroup: String,
    pub sha256: String,
}

fn running_name(job_id: &str) -> String {
    format!("{job_id}.running.json")
}

impl RunReservationJournal {
    /// A live Linux worker must retain the active lease and independently
    /// sample its launched process before and after persisting this record.
    /// A failed second sample leaves an irreversible unknown job, not a retry.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_running_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        process: ProcessIdentity,
        cgroup: &str,
    ) -> Result<RunningMarker, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        observe_process(process.pid, process.start_ticks, cgroup)
            .map_err(|_| ReservationError::InvalidMarker)?;
        let marker = self.mark_running_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            expected_started_sha256,
            process,
            cgroup,
        )?;
        observe_process(process.pid, process.start_ticks, cgroup)
            .map_err(|_| ReservationError::InvalidMarker)?;
        lease.verify(&self.root)?;
        Ok(marker)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mark_running_internal(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        process: ProcessIdentity,
        cgroup: &str,
    ) -> Result<RunningMarker, ReservationError> {
        if request.action() != WorkerAction::Run
            || !request.matches_deployment(source_sha, deployment_digest)
        {
            return Err(ReservationError::WrongRequest);
        }
        if !is_git_sha(source_sha)
            || !hex(deployment_digest, 64)
            || !hex(worker_generation, 64)
            || !hex(expected_started_sha256, 64)
            || process.pid == 0
            || process.start_ticks == 0
            || !valid_cgroup(cgroup)
        {
            return Err(ReservationError::InvalidPins);
        }
        let started = self
            .started(
                request.job_id(),
                source_sha,
                deployment_digest,
                worker_generation,
            )?
            .ok_or(ReservationError::InvalidMarker)?;
        if started.sha256 != expected_started_sha256 {
            return Err(ReservationError::InvalidMarker);
        }
        let terminal_name = format!("{}.terminal.json", request.job_id());
        match statat(&self.root, terminal_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(ReservationError::AlreadyStarted),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(io(error)),
        }
        let value = json!({
            "schema": RUNNING_SCHEMA,
            "source_sha": source_sha,
            "job_id": request.job_id(),
            "deployment_digest": deployment_digest,
            "worker_generation": worker_generation,
            "started_marker_sha256": expected_started_sha256,
            "pid": process.pid,
            "process_start_ticks": process.start_ticks,
            "cgroup": cgroup,
        });
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        if bytes.len() as u64 > MAX_RUNNING_BYTES {
            return Err(ReservationError::InvalidMarker);
        }
        let descriptor = openat(
            &self.root,
            running_name(request.job_id()),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                ReservationError::AlreadyStarted
            } else {
                io(error)
            }
        })?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fsync(&self.root).map_err(io)?;
        Ok(RunningMarker {
            source_sha: source_sha.to_owned(),
            job_id: request.job_id().to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: started.sha256,
            process,
            cgroup: cgroup.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    /// Read retained identity bytes against outside pins. This does not claim
    /// that the process remains alive; callers must perform a fresh pidfd check.
    pub fn running_marker(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Option<RunningMarker>, ReservationError> {
        marker_name(job_id)?;
        if !is_git_sha(source_sha) || !hex(deployment_digest, 64) || !hex(worker_generation, 64) {
            return Err(ReservationError::InvalidPins);
        }
        let Some(bytes) =
            read_bounded_regular(&self.root, &running_name(job_id), MAX_RUNNING_BYTES)?
        else {
            return Ok(None);
        };
        if canonicalize(&bytes).map_err(|_| ReservationError::InvalidMarker)? != bytes {
            return Err(ReservationError::InvalidMarker);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        let fields = value.as_object().ok_or(ReservationError::InvalidMarker)?;
        let started = self
            .started(job_id, source_sha, deployment_digest, worker_generation)?
            .ok_or(ReservationError::InvalidMarker)?;
        let process = ProcessIdentity {
            pid: value["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or(ReservationError::InvalidMarker)?,
            start_ticks: value["process_start_ticks"]
                .as_u64()
                .filter(|ticks| *ticks > 0)
                .ok_or(ReservationError::InvalidMarker)?,
        };
        let cgroup = value["cgroup"]
            .as_str()
            .filter(|group| valid_cgroup(group))
            .ok_or(ReservationError::InvalidMarker)?;
        if fields.len() != 9
            || value["schema"] != RUNNING_SCHEMA
            || value["source_sha"] != source_sha
            || value["job_id"] != job_id
            || value["deployment_digest"] != deployment_digest
            || value["worker_generation"] != worker_generation
            || value["started_marker_sha256"] != started.sha256
        {
            return Err(ReservationError::InvalidMarker);
        }
        Ok(Some(RunningMarker {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: started.sha256,
            process,
            cgroup: cgroup.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_contracts::{WorkerResponse, WorkerState};
    use std::fs;

    #[test]
    fn retained_running_state_requires_a_fresh_matching_kernel_process() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let journal = RunReservationJournal::open(&root).unwrap();
        let source = "a".repeat(40);
        let deployment = "b".repeat(64);
        let generation = "c".repeat(64);
        let job = "d".repeat(16);
        let run = WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1",
                "action":"run", "source_sha":source, "job_id":job,
                "deployment_digest":deployment,
            }))
            .unwrap(),
        )
        .unwrap();
        let progress = WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1",
                "action":"progress", "source_sha":source, "job_id":job,
            }))
            .unwrap(),
        )
        .unwrap();
        let started = journal
            .reserve(&run, &source, &deployment, &generation)
            .unwrap();
        let pid = std::process::id();
        let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
        let ticks = crate::linux_process::parse_proc_stat(&stat, pid)
            .unwrap()
            .start_ticks;
        let raw_cgroup = fs::read(format!("/proc/{pid}/cgroup")).unwrap();
        let cgroup = std::str::from_utf8(&raw_cgroup)
            .unwrap()
            .trim_end()
            .strip_prefix("0::")
            .unwrap();
        let process = ProcessIdentity {
            pid,
            start_ticks: ticks,
        };
        assert_eq!(
            journal.mark_running_internal(
                &run,
                &source,
                &deployment,
                &generation,
                &"e".repeat(64),
                process,
                cgroup,
            ),
            Err(ReservationError::InvalidMarker)
        );
        let running = journal
            .mark_running_internal(
                &run,
                &source,
                &deployment,
                &generation,
                &started.sha256,
                process,
                cgroup,
            )
            .unwrap();
        assert_eq!(
            journal
                .running_marker(&job, &source, &deployment, &generation)
                .unwrap(),
            Some(running)
        );
        let response = journal
            .project_read_only(&progress, &source, Some(&deployment), &generation)
            .unwrap();
        assert_eq!(
            WorkerResponse::parse(&response).unwrap().state(),
            WorkerState::Running
        );
        assert_eq!(
            journal.mark_running_internal(
                &run,
                &source,
                &deployment,
                &generation,
                &started.sha256,
                process,
                cgroup,
            ),
            Err(ReservationError::AlreadyStarted)
        );
        let path = root.join(running_name(&job));
        let mut forged: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        forged["cgroup"] = json!("/system.slice/not-this-process.service");
        fs::write(&path, canonicalize(forged.to_string().as_bytes()).unwrap()).unwrap();
        let response = journal
            .project_read_only(&progress, &source, Some(&deployment), &generation)
            .unwrap();
        assert_eq!(
            WorkerResponse::parse(&response).unwrap().state(),
            WorkerState::Unknown
        );
    }

    #[test]
    fn root_owned_terminal_reader_requires_the_retained_running_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let inert = RunReservationJournal::open(&root).unwrap();
        let source = "a".repeat(40);
        let deployment = "b".repeat(64);
        let generation = "c".repeat(64);
        let job = "d".repeat(16);
        let request = WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1", "action":"run",
                "source_sha":source, "job_id":job, "deployment_digest":deployment,
            }))
            .unwrap(),
        )
        .unwrap();
        let started = inert
            .reserve(&request, &source, &deployment, &generation)
            .unwrap();
        let process = ProcessIdentity {
            pid: 1234,
            start_ticks: 5678,
        };
        inert
            .mark_running_internal(
                &request,
                &source,
                &deployment,
                &generation,
                &started.sha256,
                process,
                "/system.slice/hol-product-cell-test.service",
            )
            .unwrap();
        let terminal = inert
            .finish(
                &request,
                &source,
                &deployment,
                &generation,
                &started.sha256,
                br#"{}"#,
                process,
                0,
                crate::TerminalOutcome::Passed,
            )
            .unwrap();
        let root_owned_reader = RunReservationJournal {
            root: crate::open_canonical_directory(&root, false).unwrap(),
            root_owned: true,
        };
        assert_eq!(
            root_owned_reader
                .terminal(&job, &source, &deployment, &generation)
                .unwrap(),
            Some(terminal)
        );
        let path = root.join(running_name(&job));
        let mut forged: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        forged["process_start_ticks"] = json!(5679);
        fs::write(&path, canonicalize(forged.to_string().as_bytes()).unwrap()).unwrap();
        assert_eq!(
            root_owned_reader.terminal(&job, &source, &deployment, &generation),
            Err(ReservationError::InvalidMarker)
        );
    }
}
