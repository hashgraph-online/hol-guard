//! Durable, data-only terminal custody for the future Linux worker.
//! The caller still owns process observation, report scoring and Root custody.

use crate::{hex, io, marker_name, read_bounded_regular, ReservationError, RunReservationJournal};
use gauntlet_contracts::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use rustix::fs::{fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

const TERMINAL_SCHEMA_V1: &str = "hol-gauntlet-worker-terminal.v1";
const TERMINAL_SCHEMA_V2: &str = "hol-gauntlet-worker-terminal.v2";
const MAX_TERMINAL_BYTES: u64 = 2048;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Passed,
    Failed,
    InvalidEvidence,
}

impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::InvalidEvidence => "invalid-evidence",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "passed" => Some(Self::Passed),
            "failed" => Some(Self::Failed),
            "invalid-evidence" => Some(Self::InvalidEvidence),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReceipt {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub controller_public_key_hex: Option<String>,
    pub controller_key_pin_sha256: Option<String>,
    pub report_sha256: String,
    pub process: ProcessIdentity,
    pub exit_code: i32,
    pub status: TerminalOutcome,
    pub sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn report_name(job_id: &str) -> String {
    format!("{job_id}.report.json")
}

fn terminal_name(job_id: &str) -> String {
    format!("{job_id}.terminal.json")
}

fn valid_process_outcome(
    process: ProcessIdentity,
    exit_code: i32,
    status: TerminalOutcome,
) -> bool {
    process.pid > 0
        && process.start_ticks > 0
        && (-128..=255).contains(&exit_code)
        && (status != TerminalOutcome::Passed || exit_code == 0)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn keyed_terminal_pin(
    journal: &RunReservationJournal,
    started: &crate::StartedMarker,
    expected_pin_sha256: &str,
) -> Result<(String, String), ReservationError> {
    if !hex(expected_pin_sha256, 64) {
        return Err(ReservationError::InvalidPins);
    }
    let pin = crate::controller_key::read_pin(journal, started, journal.root_owned)
        .map_err(|_| ReservationError::InvalidMarker)?;
    if pin.raw_sha256 != expected_pin_sha256
        || started.controller_public_key_hex.as_deref() != Some(&pin.public_key_hex)
    {
        return Err(ReservationError::InvalidMarker);
    }
    Ok((pin.public_key_hex, pin.raw_sha256))
}

fn terminal_key_fields(
    journal: &RunReservationJournal,
    started: &crate::StartedMarker,
    expected_pin_sha256: Option<&str>,
) -> Result<Option<(String, String)>, ReservationError> {
    if started.controller_public_key_hex.is_none() {
        if expected_pin_sha256.is_some() {
            return Err(ReservationError::InvalidPins);
        }
        let name = format!("{}.controller-key.json", started.job_id);
        match statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(ReservationError::InvalidMarker),
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(io(error)),
        }
    }
    let expected = expected_pin_sha256.ok_or(ReservationError::InvalidPins)?;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return keyed_terminal_pin(journal, started, expected).map(Some);
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = (journal, expected);
        Err(ReservationError::InvalidMarker)
    }
}

fn create_durable(
    root: &std::os::fd::OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReservationError> {
    let descriptor = openat(
        root,
        name,
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
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    fsync(root).map_err(io)?;
    Ok(())
}

impl RunReservationJournal {
    /// Inert test entrypoint. A Root-owned live journal must use
    /// `finish_under_lease` so no terminal can be written after losing its lease.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
    ) -> Result<TerminalReceipt, ReservationError> {
        if self.root_owned {
            return Err(ReservationError::UnsafeRoot);
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
            None,
        )
    }

    /// Write the exact bounded report bytes before a terminal marker. This is
    /// not a gate verdict: the caller must independently establish the kernel
    /// process identity and recompute the report outcome before using `Passed`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_internal(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
        expected_controller_key_pin_sha256: Option<&str>,
    ) -> Result<TerminalReceipt, ReservationError> {
        if request.action() != WorkerAction::Run
            || !request.matches_deployment(source_sha, deployment_digest)
        {
            return Err(ReservationError::WrongRequest);
        }
        if !is_git_sha(source_sha)
            || !hex(deployment_digest, 64)
            || !hex(worker_generation, 64)
            || !hex(expected_started_sha256, 64)
        {
            return Err(ReservationError::InvalidPins);
        }
        if !valid_process_outcome(process, exit_code, status)
            || report_raw.is_empty()
            || report_raw.len() as u64 > MAX_REPORT_BYTES
            || canonicalize(report_raw).map_err(|_| ReservationError::InvalidMarker)? != report_raw
        {
            return Err(ReservationError::InvalidMarker);
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
        let key_fields = terminal_key_fields(self, &started, expected_controller_key_pin_sha256)?;
        let job_id = request.job_id();
        match statat(
            &self.root,
            terminal_name(job_id).as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(ReservationError::AlreadyStarted),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(io(error)),
        }
        let report_sha256 = digest(report_raw);
        let mut value = json!({
            "schema": if key_fields.is_some() { TERMINAL_SCHEMA_V2 } else { TERMINAL_SCHEMA_V1 },
            "source_sha": source_sha,
            "job_id": job_id,
            "deployment_digest": deployment_digest,
            "worker_generation": worker_generation,
            "started_marker_sha256": expected_started_sha256,
            "report_sha256": report_sha256,
            "pid": process.pid,
            "process_start_ticks": process.start_ticks,
            "exit_code": exit_code,
            "status": status.as_str(),
        });
        if let Some((public, pin_sha256)) = &key_fields {
            value["controller_public_key_hex"] = json!(public);
            value["controller_key_pin_sha256"] = json!(pin_sha256);
        }
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        if bytes.len() as u64 > MAX_TERMINAL_BYTES {
            return Err(ReservationError::InvalidMarker);
        }
        create_durable(&self.root, &report_name(job_id), report_raw)?;
        create_durable(&self.root, &terminal_name(job_id), &bytes)?;
        if key_fields.is_some() {
            terminal_key_fields(self, &started, expected_controller_key_pin_sha256)?;
        }
        Ok(TerminalReceipt {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: expected_started_sha256.to_owned(),
            controller_public_key_hex: key_fields.as_ref().map(|fields| fields.0.clone()),
            controller_key_pin_sha256: key_fields.as_ref().map(|fields| fields.1.clone()),
            report_sha256,
            process,
            exit_code,
            status,
            sha256: digest(&bytes),
        })
    }

    /// Reconcile a retained report and terminal marker against independent
    /// pins. Missing terminal after a start is unresolved; report-only state
    /// is invalid and must never trigger a second run.
    pub fn terminal(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Option<TerminalReceipt>, ReservationError> {
        marker_name(job_id)?;
        let started = self.started(job_id, source_sha, deployment_digest, worker_generation)?;
        let terminal =
            read_bounded_regular(&self.root, &terminal_name(job_id), MAX_TERMINAL_BYTES)?;
        let Some(bytes) = terminal else {
            if read_bounded_regular(&self.root, &report_name(job_id), MAX_REPORT_BYTES)?.is_some() {
                return Err(ReservationError::InvalidMarker);
            }
            return Ok(None);
        };
        let started = started.ok_or(ReservationError::InvalidMarker)?;
        if canonicalize(&bytes).map_err(|_| ReservationError::InvalidMarker)? != bytes {
            return Err(ReservationError::InvalidMarker);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        let fields = value.as_object().ok_or(ReservationError::InvalidMarker)?;
        let process = ProcessIdentity {
            pid: value["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or(ReservationError::InvalidMarker)?,
            start_ticks: value["process_start_ticks"]
                .as_u64()
                .ok_or(ReservationError::InvalidMarker)?,
        };
        let exit_code = value["exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
            .ok_or(ReservationError::InvalidMarker)?;
        let status = value["status"]
            .as_str()
            .and_then(TerminalOutcome::parse)
            .ok_or(ReservationError::InvalidMarker)?;
        let report_sha256 = value["report_sha256"]
            .as_str()
            .filter(|sha| hex(sha, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        let key_fields = if let Some(public) = started.controller_public_key_hex.as_deref() {
            let pin_sha256 = value["controller_key_pin_sha256"]
                .as_str()
                .filter(|sha| hex(sha, 64))
                .ok_or(ReservationError::InvalidMarker)?;
            if fields.len() != 13
                || value["schema"] != TERMINAL_SCHEMA_V2
                || value["controller_public_key_hex"] != public
            {
                return Err(ReservationError::InvalidMarker);
            }
            terminal_key_fields(self, &started, Some(pin_sha256))?
        } else {
            if fields.len() != 11 || value["schema"] != TERMINAL_SCHEMA_V1 {
                return Err(ReservationError::InvalidMarker);
            }
            terminal_key_fields(self, &started, None)?
        };
        if value["source_sha"] != source_sha
            || value["job_id"] != job_id
            || value["deployment_digest"] != deployment_digest
            || value["worker_generation"] != worker_generation
            || value["started_marker_sha256"] != started.sha256
            || !valid_process_outcome(process, exit_code, status)
        {
            return Err(ReservationError::InvalidMarker);
        }
        #[cfg(target_os = "linux")]
        if self.root_owned {
            let running = self
                .running_marker(job_id, source_sha, deployment_digest, worker_generation)?
                .ok_or(ReservationError::InvalidMarker)?;
            if running.process != process || running.started_marker_sha256 != started.sha256 {
                return Err(ReservationError::InvalidMarker);
            }
        }
        let report = read_bounded_regular(&self.root, &report_name(job_id), MAX_REPORT_BYTES)?
            .ok_or(ReservationError::InvalidMarker)?;
        if report.is_empty()
            || canonicalize(&report).map_err(|_| ReservationError::InvalidMarker)? != report
            || digest(&report) != report_sha256
        {
            return Err(ReservationError::InvalidMarker);
        }
        Ok(Some(TerminalReceipt {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: started.sha256,
            controller_public_key_hex: key_fields.as_ref().map(|fields| fields.0.clone()),
            controller_key_pin_sha256: key_fields.as_ref().map(|fields| fields.1.clone()),
            report_sha256: report_sha256.to_owned(),
            process,
            exit_code,
            status,
            sha256: digest(&bytes),
        }))
    }

    /// Reopen an already completed Rust deterministic diagnostic for a host
    /// that retained the key before launch. This exports only the bounded
    /// invalid-evidence terminal and diagnostic summary, then independently
    /// reopens the fixed deterministic controller report to check its digest.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub fn read_deterministic_diagnostic_root_owned(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Value, ReservationError> {
        use gauntlet_evidence::observe_deterministic_report_root_owned_ineligible;

        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        let first = self
            .terminal(job_id, source_sha, deployment_digest, worker_generation)?
            .ok_or(ReservationError::InvalidMarker)?;
        if first.status != TerminalOutcome::InvalidEvidence
            || first.controller_key_pin_sha256.is_none()
        {
            return Err(ReservationError::InvalidMarker);
        }
        crate::require_rust_job_slice_absent(job_id)?;
        let terminal_raw =
            read_bounded_regular(&self.root, &terminal_name(job_id), MAX_TERMINAL_BYTES)?
                .ok_or(ReservationError::InvalidMarker)?;
        let report_raw = read_bounded_regular(&self.root, &report_name(job_id), 8192)?
            .ok_or(ReservationError::InvalidMarker)?;
        if digest(&terminal_raw) != first.sha256 || digest(&report_raw) != first.report_sha256 {
            return Err(ReservationError::InvalidMarker);
        }
        let terminal: Value =
            serde_json::from_slice(&terminal_raw).map_err(|_| ReservationError::InvalidMarker)?;
        let report: Value =
            serde_json::from_slice(&report_raw).map_err(|_| ReservationError::InvalidMarker)?;
        let config_digest = report["config_digest"]
            .as_str()
            .filter(|value| hex(value, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        let expected_deterministic_sha = report["deterministic_report_sha256"]
            .as_str()
            .filter(|value| hex(value, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        if report["schema"] != "hol-gauntlet-rust-deterministic-run-diagnostic.v1"
            || report["job_id"] != job_id
            || report["source_sha"] != source_sha
            || report["deployment_digest"] != deployment_digest
            || report["worker_generation"] != worker_generation
            || report["started_marker_sha256"] != first.started_marker_sha256
            || report["controller_key_pin_sha256"].as_str()
                != first.controller_key_pin_sha256.as_deref()
            || report["controller_public_key_hex"].as_str()
                != first.controller_public_key_hex.as_deref()
            || report["exit_code"] != first.exit_code
            || report["process"]["pid"] != first.process.pid
            || report["process"]["start_ticks"] != first.process.start_ticks
            || report["independent_control_verdict"] != false
            || report["execution_eligible"] != false
        {
            return Err(ReservationError::InvalidMarker);
        }
        let observed = observe_deterministic_report_root_owned_ineligible(
            job_id,
            source_sha,
            config_digest,
            first.exit_code,
        )
        .map_err(|_| ReservationError::InvalidMarker)?;
        if observed.raw_sha256 != expected_deterministic_sha
            || report["producer_status_claim"] != observed.producer_status
            || report["producer_cell_count"] != observed.cell_count
        {
            return Err(ReservationError::InvalidMarker);
        }
        if self.terminal(job_id, source_sha, deployment_digest, worker_generation)?
            != Some(first.clone())
        {
            return Err(ReservationError::InvalidMarker);
        }
        crate::require_rust_job_slice_absent(job_id)?;
        Ok(json!({
            "schema":"hol-gauntlet-rust-deterministic-readback.v1",
            "job_id":job_id,
            "source_sha":source_sha,
            "terminal":terminal,
            "diagnostic_report":report,
            "terminal_sha256":first.sha256,
            "diagnostic_report_sha256":first.report_sha256,
            "deterministic_report_sha256":observed.raw_sha256,
            "execution_eligible":false,
        }))
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "aarch64"))]
#[path = "terminal_keyed_tests.rs"]
mod keyed_tests;
