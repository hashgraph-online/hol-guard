//! Internal owner of one prepared controller's lease, deadline, process and
//! cleanup. This path does not read a benchmark report or issue a verdict.

use crate::contained_probe::{CgroupProbeError, OwnedJobCgroup};
use crate::controller_exec::{
    exchange_prelaunch_pipe, spawn_prepared_controller, ControllerExecError,
};
use crate::controller_key::{require_pinned_controller_key_under_lease, ControllerKeyError};
use crate::deadline::{BoottimeDeadline, DeadlineError};
use crate::linux_process::{observe_process, parse_proc_stat, ProcessObservationError};
use crate::prelaunch::{prepare_fixed_prelaunch, PrelaunchPins, PreparedLaunch};
use crate::process_reap::reap_probe_child_bounded;
use crate::{
    stop_rust_job_slice, ActiveLease, ProcessIdentity, ReservationError, RunReservationJournal,
};
use gauntlet_contracts::canonicalize;
use gauntlet_contracts::WorkerRequest;
use gauntlet_evidence::{
    observe_deterministic_report_root_owned_ineligible,
    observe_six_control_openings_root_owned_ineligible, read_six_deterministic_controls_root_owned,
    DeterministicReportObservation, EvidenceError, SixControlOpeningsShadow,
    SixDeterministicControlRecords,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

#[derive(Debug)]
pub(crate) enum ControllerRunError {
    Lease(ReservationError),
    Cgroup(CgroupProbeError),
    Launch(ControllerExecError),
    ControllerKey(ControllerKeyError),
    PostRunCustody(crate::prelaunch::PrelaunchError),
    Report(EvidenceError),
    Identity(ProcessObservationError),
    KernelObservation(String),
    Deadline(DeadlineError),
    Cancelled,
    Wait,
    CleanupUncertain,
}

impl std::fmt::Display for ControllerRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lease(error) => write!(f, "worker lease or running marker: {error}"),
            Self::Cgroup(error) => write!(f, "controller cgroup: {error}"),
            Self::Launch(error) => write!(f, "controller launch: {error}"),
            Self::ControllerKey(error) => write!(f, "controller public-key custody: {error}"),
            Self::PostRunCustody(error) => write!(f, "post-run input custody: {error}"),
            Self::Report(error) => write!(f, "controller report: {error}"),
            Self::Identity(error) => write!(f, "controller process identity: {error:?}"),
            Self::KernelObservation(error) => write!(f, "live kernel sample: {error}"),
            Self::Deadline(error) => write!(f, "controller deadline: {error}"),
            Self::Cancelled => f.write_str("controller cancellation requested"),
            Self::Wait => f.write_str("controller child wait failed"),
            Self::CleanupUncertain => f.write_str("controller or product-cell cleanup uncertain"),
        }
    }
}

impl std::error::Error for ControllerRunError {}

pub(crate) enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
}

/// This observation is deliberately insufficient for a terminal receipt.
/// A future dispatcher must authenticate report bytes and independently score
/// the six controls before writing even an invalid-evidence terminal record.
#[allow(dead_code)]
pub(crate) struct ControllerRunObservation {
    pub(crate) process: ProcessIdentity,
    pub(crate) started_marker_sha256: String,
    pub(crate) controller_public_key_hex: String,
    pub(crate) controller_key_pin_sha256: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) report: Option<DeterministicReportObservation>,
    pub(crate) controls: Option<SixDeterministicControlRecords>,
    pub(crate) control_openings: Option<SixControlOpeningsShadow>,
}

pub(crate) fn wait_for_child(
    child: &mut Child,
    deadline: &BoottimeDeadline,
    mut check_owner: impl FnMut() -> Result<(), ControllerRunError>,
    mut cancel_requested: impl FnMut() -> bool,
) -> Result<WaitOutcome, ControllerRunError> {
    loop {
        check_owner()?;
        if cancel_requested() {
            return Err(ControllerRunError::Cancelled);
        }
        if let Some(status) = child.try_wait().map_err(|_| ControllerRunError::Wait)? {
            return Ok(WaitOutcome::Exited(status));
        }
        let poll = deadline.next_poll().map_err(ControllerRunError::Deadline)?;
        if poll.is_zero() {
            return Ok(WaitOutcome::TimedOut);
        }
        thread::sleep(poll);
    }
}

pub(crate) fn observe_child(
    child: &Child,
    expected_cgroup: &str,
) -> Result<ProcessIdentity, ControllerRunError> {
    let pid = child.id();
    let stat = fs::read(format!("/proc/{pid}/stat"))
        .map_err(|_| ControllerRunError::Identity(ProcessObservationError::Unavailable))?;
    let start_ticks = parse_proc_stat(&stat, pid)
        .ok_or(ControllerRunError::Identity(
            ProcessObservationError::Unavailable,
        ))?
        .start_ticks;
    observe_process(pid, start_ticks, expected_cgroup).map_err(ControllerRunError::Identity)?;
    Ok(ProcessIdentity { pid, start_ticks })
}

/// Cleanup is attempted on every ordinary return after cgroup creation. A
/// failed step keeps the reserved job unresolved; no retry is inferred.
pub(crate) fn cleanup(
    group: &mut OwnedJobCgroup,
    child: Option<&mut Child>,
    job_id: &str,
    stop_product_slice: bool,
) -> Result<(), ControllerRunError> {
    let killed = group.kill();
    let reaped = child.map(reap_probe_child_bounded).transpose();
    let drained = group.drain_and_remove();
    // A pre-spawn refusal may refer to an older run with the same job ID.
    // Stop the product slice only if this invocation actually spawned a child.
    // Even on uncertain controller cleanup, attempt that exact slice stop;
    // its absence cannot turn an uncertain controller into success.
    let slice_ok = !stop_product_slice || stop_rust_job_slice(job_id).is_ok();
    if killed.is_err() || reaped.is_err() || drained.is_err() || !slice_ok {
        return Err(ControllerRunError::CleanupUncertain);
    }
    Ok(())
}

/// Own one actual fixed controller process until exit or CLOCK_BOOTTIME
/// expiry, then kill remaining descendants, reap and remove the controller
/// cgroup, and stop/observe the job's product-cell slice. No public caller is
/// wired to this until trusted pin delivery and report authentication exist.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn run_prepared_controller_ineligible(
    prepared: &PreparedLaunch,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    worker_generation: &str,
    active_seconds: u64,
    cancellation: &AtomicBool,
    acknowledge: impl FnOnce(
        &[u8],
        &BoottimeDeadline,
        &AtomicBool,
    ) -> Result<Vec<u8>, ControllerExecError>,
) -> Result<ControllerRunObservation, ControllerRunError> {
    if cancellation.load(Ordering::Acquire) {
        return Err(ControllerRunError::Cancelled);
    }
    let deadline = BoottimeDeadline::start(active_seconds).map_err(ControllerRunError::Deadline)?;
    lease
        .verify(&journal.root)
        .map_err(ControllerRunError::Lease)?;
    let mut group = OwnedJobCgroup::create(request.job_id()).map_err(ControllerRunError::Cgroup)?;
    if cancellation.load(Ordering::Acquire) {
        cleanup(&mut group, None, request.job_id(), false)?;
        return Err(ControllerRunError::Cancelled);
    }
    let launched = spawn_prepared_controller(
        prepared,
        &group,
        journal,
        lease,
        request,
        worker_generation,
        &deadline,
        cancellation,
        acknowledge,
    );
    let (mut child, started, key_pin) = match launched {
        Ok(value) => value,
        Err(error) => {
            let spawned = matches!(
                error,
                ControllerExecError::PostLaunch(_) | ControllerExecError::CleanupUncertain
            );
            cleanup(&mut group, None, request.job_id(), spawned)?;
            return Err(ControllerRunError::Launch(error));
        }
    };
    let observed = (|| {
        if cancellation.load(Ordering::Acquire) {
            return Err(ControllerRunError::Cancelled);
        }
        let process = observe_child(&child, group.path())?;
        journal
            .mark_running_under_lease(
                lease,
                request,
                request.source_sha(),
                request
                    .deployment_digest()
                    .ok_or(ControllerRunError::Lease(ReservationError::WrongRequest))?,
                worker_generation,
                &started.sha256,
                process,
                group.path(),
            )
            .map_err(ControllerRunError::Lease)?;
        let outcome = wait_for_child(
            &mut child,
            &deadline,
            || {
                lease
                    .verify(&journal.root)
                    .map_err(ControllerRunError::Lease)
            },
            || cancellation.load(Ordering::Acquire),
        )?;
        let (exit_code, timed_out) = match outcome {
            WaitOutcome::Exited(status) => (
                Some(
                    status
                        .code()
                        .or_else(|| status.signal().map(|signal| 128 + signal))
                        .ok_or(ControllerRunError::Wait)?,
                ),
                false,
            ),
            WaitOutcome::TimedOut => (None, true),
        };
        Ok(ControllerRunObservation {
            process,
            started_marker_sha256: started.sha256.clone(),
            controller_public_key_hex: key_pin.public_key_hex.clone(),
            controller_key_pin_sha256: key_pin.raw_sha256.clone(),
            exit_code,
            timed_out,
            report: None,
            controls: None,
            control_openings: None,
        })
    })();
    cleanup(&mut group, Some(&mut child), request.job_id(), true)?;
    lease
        .verify(&journal.root)
        .map_err(ControllerRunError::Lease)?;
    require_pinned_controller_key_under_lease(journal, lease, &started, &key_pin)
        .map_err(ControllerRunError::ControllerKey)?;
    let mut observation = observed?;
    prepared
        .recheck_all_assets_after_cleanup()
        .map_err(ControllerRunError::PostRunCustody)?;
    if !observation.timed_out {
        let exit_code = observation.exit_code.ok_or(ControllerRunError::Wait)?;
        let report = observe_deterministic_report_root_owned_ineligible(
            request.job_id(),
            request.source_sha(),
            prepared.config_digest(),
            exit_code,
        )
        .map_err(ControllerRunError::Report)?;
        if report.producer_status == "passed" {
            let controls = read_six_deterministic_controls_root_owned(
                request.job_id(),
                request.source_sha(),
                prepared.config_digest(),
                exit_code,
            )
            .map_err(ControllerRunError::Report)?;
            if controls.report.raw_sha256 != report.raw_sha256 {
                return Err(ControllerRunError::Report(EvidenceError::Invalid(
                    "deterministic report changed while reading controls",
                )));
            }
            // The job key came from this worker's one-use marker and the
            // prelaunch acknowledgement. Do not take role keys from records.
            let outside_keys = [
                "success",
                "input-binding",
                "injection",
                "boundary",
                "timeout",
                "cancel",
            ]
            .into_iter()
            .map(|role| (role.to_owned(), key_pin.public_key_hex.clone()))
            .collect::<BTreeMap<_, _>>();
            let config_path = format!(
                "/opt/hol-gauntlet/candidates/{}/config.json",
                request.source_sha()
            );
            let openings = observe_six_control_openings_root_owned_ineligible(
                request.job_id(),
                request.source_sha(),
                Path::new(&config_path),
                prepared.config_digest(),
                &report.raw_sha256,
                exit_code,
                &outside_keys,
            )
            .map_err(ControllerRunError::Report)?;
            observation.controls = Some(controls);
            observation.control_openings = Some(openings);
        }
        observation.report = Some(report);
    }
    Ok(observation)
}

/// Connect the fixed launch owner to caller-owned prelaunch pipes. A reviewed
/// dispatcher must attest both peers and retain the host record on uncertain
/// delivery before calling this internal path for a live job.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn run_prepared_controller_pipe_ineligible(
    prepared: &PreparedLaunch,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    worker_generation: &str,
    active_seconds: u64,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    ack_reader: &impl AsRawFd,
) -> Result<ControllerRunObservation, ControllerRunError> {
    run_prepared_controller_ineligible(
        prepared,
        journal,
        lease,
        request,
        worker_generation,
        active_seconds,
        cancellation,
        |frame, deadline, cancellation| {
            exchange_prelaunch_pipe(frame, prepared_writer, ack_reader, deadline, cancellation)
        },
    )
}

/// Execute one fixed deterministic controller under the Rust worker lease and
/// persist a keyed, explicitly invalid-evidence terminal. The host must pin
/// the prepared key before acknowledging the child. This is a diagnostic run:
/// producer status and signed openings are not an independent control verdict.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_deterministic_controller_pipe_ineligible(
    pins: &PrelaunchPins,
    request: &WorkerRequest,
    worker_generation: &str,
    active_seconds: u64,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    ack_reader: &impl AsRawFd,
) -> Result<Value, String> {
    const STATE_ROOT: &str = "/var/lib/hol-gauntlet-rust/worker-state";
    let journal = RunReservationJournal::open_root_owned(Path::new(STATE_ROOT))
        .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    let prepared = prepare_fixed_prelaunch(request, pins).map_err(|error| error.to_string())?;
    let observation = run_prepared_controller_pipe_ineligible(
        &prepared,
        &journal,
        &lease,
        request,
        worker_generation,
        active_seconds,
        cancellation,
        prepared_writer,
        ack_reader,
    )
    .map_err(|error| error.to_string())?;
    let report = observation
        .report
        .as_ref()
        .ok_or("controller did not produce a verified deterministic report")?;
    let exit_code = observation
        .exit_code
        .ok_or("controller exit is unknown; one-use job remains unresolved")?;
    if observation.timed_out
        || (report.producer_status == "passed"
            && (observation.controls.is_none() || observation.control_openings.is_none()))
    {
        return Err("controller outcome is incomplete; one-use job remains unresolved".to_owned());
    }
    let summary = json!({
        "schema":"hol-gauntlet-rust-deterministic-run-diagnostic.v1",
        "job_id":request.job_id(),
        "source_sha":request.source_sha(),
        "deployment_digest":pins.deployment_digest,
        "config_digest":report.config_digest,
        "worker_generation":worker_generation,
        "started_marker_sha256":observation.started_marker_sha256,
        "controller_public_key_hex":observation.controller_public_key_hex,
        "controller_key_pin_sha256":observation.controller_key_pin_sha256,
        "process":{"pid":observation.process.pid,"start_ticks":observation.process.start_ticks},
        "exit_code":exit_code,
        "deterministic_report_sha256":report.raw_sha256,
        "producer_status_claim":report.producer_status,
        "producer_cell_count":report.cell_count,
        "six_control_openings":observation.control_openings.as_ref().map(SixControlOpeningsShadow::to_json),
        "independent_control_verdict":false,
        "execution_eligible":false,
    });
    let raw = canonicalize(summary.to_string().as_bytes())
        .map_err(|error| format!("diagnostic report encoding: {error}"))?;
    let terminal = journal
        .finish_under_lease(
            &lease,
            request,
            request.source_sha(),
            &pins.deployment_digest,
            worker_generation,
            &observation.started_marker_sha256,
            &raw,
            observation.process,
            exit_code,
            crate::TerminalOutcome::InvalidEvidence,
            Some(&observation.controller_key_pin_sha256),
        )
        .map_err(|error| format!("diagnostic terminal unresolved: {error}"))?;
    Ok(json!({
        "schema":"hol-gauntlet-rust-deterministic-run-result.v1",
        "job_id":request.job_id(),
        "source_sha":request.source_sha(),
        "started_marker_sha256":observation.started_marker_sha256,
        "controller_key_pin_sha256":observation.controller_key_pin_sha256,
        "controller_public_key_hex":observation.controller_public_key_hex,
        "deterministic_report_sha256":report.raw_sha256,
        "diagnostic_report_sha256":terminal.report_sha256,
        "terminal_sha256":terminal.sha256,
        "exit_code":exit_code,
        "producer_status_claim":report.producer_status,
        "signed_openings_observed":observation.control_openings.is_some(),
        "independent_control_verdict":false,
        "execution_eligible":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn bounded_wait_distinguishes_exit_and_deadline_without_leaking_child() {
        let mut quick = Command::new("/usr/bin/true").spawn().unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        assert!(matches!(
            wait_for_child(&mut quick, &deadline, || Ok(()), || false),
            Ok(WaitOutcome::Exited(status)) if status.success()
        ));

        let mut slow = Command::new("/usr/bin/sleep").arg("3").spawn().unwrap();
        let deadline = BoottimeDeadline::start(1).unwrap();
        let outcome = wait_for_child(&mut slow, &deadline, || Ok(()), || false);
        slow.kill().unwrap();
        slow.wait().unwrap();
        assert!(matches!(outcome, Ok(WaitOutcome::TimedOut)));
    }

    #[test]
    fn owner_loss_aborts_wait_before_deadline() {
        let mut slow = Command::new("/usr/bin/sleep").arg("3").spawn().unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        let result = wait_for_child(
            &mut slow,
            &deadline,
            || Err(ControllerRunError::Wait),
            || false,
        );
        slow.kill().unwrap();
        slow.wait().unwrap();
        assert!(matches!(result, Err(ControllerRunError::Wait)));
    }

    #[test]
    fn cancellation_aborts_a_live_wait_without_claiming_exit() {
        let mut slow = Command::new("/usr/bin/sleep").arg("3").spawn().unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        let result = wait_for_child(&mut slow, &deadline, || Ok(()), || true);
        slow.kill().unwrap();
        slow.wait().unwrap();
        assert!(matches!(result, Err(ControllerRunError::Cancelled)));
    }
}
