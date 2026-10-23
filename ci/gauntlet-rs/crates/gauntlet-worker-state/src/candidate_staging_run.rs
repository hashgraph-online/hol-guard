//! First Rust-owned staging control execution. The host pins the signing key
//! before spawn, and Rust owns the one-use lease, deadline and both cleanup
//! domains. It deliberately writes only an invalid-evidence diagnostic; no
//! conformance package or benchmark admission can result from this path.

use crate::candidate_conformance_readiness::{
    inspect_candidate_staging_readiness_ineligible, CandidateConformanceReadinessPins,
};
use crate::candidate_staging_tap::{CandidateSdkTapPins, StagingTapV2, TapSessions};
use crate::contained_probe::OwnedJobCgroup;
use crate::controller_exec::{exchange_prelaunch_pipe, spawn_root_fd};
use crate::controller_key::{
    pin_controller_key_under_lease, require_pinned_controller_key_under_lease, SealedControllerKey,
};
use crate::controller_run::{cleanup, observe_child, wait_for_child, WaitOutcome};
use crate::staging_effect_events::{FinishedStagingEffectEvents, StagingEffectEvents};
use crate::staging_effect_journal::retain_staging_effect_journal_ineligible;
use crate::staging_kernel_observer::{LiveStagingKernelObservation, StagingKernelSampler};
use crate::{
    fixed_staging_control_plan, fixed_staging_control_plan_sdk_tap_v2,
    open_root_owned_public_directory, read_fixed_interpreter_path_held, ActiveLease,
    BoottimeDeadline, RunReservationJournal, SdkWirePeerPin, StagingControlPins, StagingRole,
    TerminalOutcome,
};
use gauntlet_contracts::{canonicalize, PrelaunchPrepared, WorkerRequest};
use gauntlet_evidence::verify_controller_tree;
use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const STAGING_STATE: &str = "/var/lib/hol-gauntlet-rust/staging-state";

struct EffectMonitorThread {
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<FinishedStagingEffectEvents, String>>>,
}

impl EffectMonitorThread {
    fn start(mut events: StagingEffectEvents) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_failed = Arc::clone(&failed);
        let handle = thread::Builder::new()
            .name("staging-effect-observer".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    if let Err(error) = events.drain() {
                        thread_failed.store(true, Ordering::Release);
                        return Err(error);
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                let finished = events.finish();
                if finished.is_err() {
                    thread_failed.store(true, Ordering::Release);
                }
                finished
            })
            .map_err(|error| format!("effect observer thread unavailable: {error}"))?;
        Ok(Self {
            stop,
            failed,
            handle: Some(handle),
        })
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn finish(mut self) -> Result<FinishedStagingEffectEvents, String> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .ok_or("effect observer thread already reaped")?
            .join()
            .map_err(|_| "effect observer thread panicked".to_owned())?
    }
}

impl Drop for EffectMonitorThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CandidateStagingRunPins<'a> {
    pub build_job_id: &'a str,
    pub run_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub controller_path: &'a str,
    pub controller_tree_sha256: &'a str,
    pub python_path: &'a str,
    pub interpreter_sha256: &'a str,
    pub worker_generation_sha256: &'a str,
    pub role: StagingRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateStagingRunProof {
    run_id: String,
    source_sha: String,
    role: String,
    controller_public_key_hex: String,
    controller_key_pin_sha256: String,
    started_marker_sha256: String,
    terminal_sha256: String,
    exit_code: i32,
    timed_out: bool,
    post_run_controller_custody: bool,
    live_kernel_activity: LiveStagingKernelObservation,
    sdk_tap_v2: Option<Value>,
    effect_events: Option<Value>,
}

impl CandidateStagingRunProof {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schema":"hol-gauntlet-candidate-staging-run-diagnostic.v1",
            "run_id":self.run_id,
            "source_sha":self.source_sha,
            "role":self.role,
            "controller_public_key_hex":self.controller_public_key_hex,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "started_marker_sha256":self.started_marker_sha256,
            "terminal_sha256":self.terminal_sha256,
            "exit_code":self.exit_code,
            "timed_out":self.timed_out,
            "post_run_controller_custody":self.post_run_controller_custody,
            "live_kernel_activity":self.live_kernel_activity.to_json(),
            "record_scored":false,
            "conformance_package_created":false,
            "execution_eligible":false,
        });
        if let Some(tap) = &self.sdk_tap_v2 {
            value["sdk_tap_v2"] = tap.clone();
        }
        if let Some(events) = &self.effect_events {
            value["effect_events"] = events.clone();
        }
        if let Some(product) = &self.live_kernel_activity.product {
            value["live_product_activity"] = product.to_json();
        }
        value
    }
}

fn staging_log(journal: &RunReservationJournal, run_id: &str) -> Result<File, String> {
    let name = format!("{run_id}.log");
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("one-use staging log unavailable: {error}"))?;
    let metadata = fstat(&descriptor).map_err(|error| error.to_string())?;
    if metadata.st_uid != 0 || metadata.st_nlink != 1 || metadata.st_mode & 0o7777 != 0o600 {
        return Err("staging log lacks Root-only custody".to_owned());
    }
    fsync(&descriptor).map_err(|error| error.to_string())?;
    fsync(&journal.root).map_err(|error| error.to_string())?;
    Ok(File::from(descriptor))
}

fn recheck_prelaunch(
    pins: &CandidateStagingRunPins<'_>,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
) -> Result<(), String> {
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    verify_controller_tree(Path::new(pins.controller_path), pins.controller_tree_sha256)
        .map_err(|error| error.to_string())?;
    interpreter
        .assert_unchanged()
        .map_err(|error| error.to_string())
}

/// The `deployment_digest` field of the versioned run frame is the outside
/// provisional config digest in this isolated staging journal. It cannot be
/// read as a final deployment: the namespace is distinct and this function
/// always writes an `invalid-evidence` terminal for later independent scoring.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_candidate_staging_control_ineligible(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    run_fixed_candidate_staging_control_impl(
        pins,
        None,
        false,
        false,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
    )
}

/// Separate explicit v2 entry. Existing v1 callers never mount the tap and
/// cannot silently change their controller transport or evidence semantics.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_candidate_staging_control_sdk_tap_v2_ineligible(
    pins: &CandidateStagingRunPins<'_>,
    tap_pins: &CandidateSdkTapPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    run_fixed_candidate_staging_control_impl(
        pins,
        Some(tap_pins),
        false,
        false,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
    )
}

/// Explicit PID-namespace variant of the ineligible v2 SDK tap. The Python
/// controller still receives the same `--sdk-tap-v2` mount and evidence stays
/// diagnostic; only the Rust-owned relay child changes isolation profile.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_candidate_staging_control_sdk_tap_pidns_ineligible(
    pins: &CandidateStagingRunPins<'_>,
    tap_pins: &CandidateSdkTapPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    run_fixed_candidate_staging_control_impl(
        pins,
        Some(tap_pins),
        true,
        false,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
    )
}

/// Explicit Root-forwarded PID-namespace SDK tap diagnostic. The Python
/// controller still runs with the passive `--sdk-tap-v2` mount; Rust records
/// a distinct v2 journal and v3 staging summary for the Root-owned wire.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_candidate_staging_control_sdk_tap_root_relay_ineligible(
    pins: &CandidateStagingRunPins<'_>,
    tap_pins: &CandidateSdkTapPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    run_fixed_candidate_staging_control_impl(
        pins,
        Some(tap_pins),
        true,
        true,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_fixed_candidate_staging_control_impl(
    pins: &CandidateStagingRunPins<'_>,
    tap_pins: Option<&CandidateSdkTapPins<'_>>,
    pidns: bool,
    root_relay: bool,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    if (pidns && tap_pins.is_none()) || (root_relay && !pidns) {
        return Err("PID-namespace SDK tap requires exact child pins".to_owned());
    }
    if !cfg!(all(target_os = "linux", target_arch = "aarch64")) || geteuid().as_raw() != 0 {
        return Err("Linux ARM64 Root staging owner required".to_owned());
    }
    if cancellation.load(Ordering::Acquire)
        || !request.matches_deployment(pins.source_sha, pins.config_digest)
        || request.job_id() != pins.run_id
        || pins.worker_generation_sha256.len() != 64
        || !pins
            .worker_generation_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "fixed staging request or worker generation differs from outside pins".to_owned(),
        );
    }
    let control_pins = StagingControlPins {
        build_job_id: pins.build_job_id,
        run_id: pins.run_id,
        source_sha: pins.source_sha,
        version: pins.version,
        config_digest: pins.config_digest,
        private_manifest_sha256: pins.private_manifest_sha256,
        controller_path: pins.controller_path,
        python_path: pins.python_path,
        interpreter_sha256: pins.interpreter_sha256,
    };
    let plan = if tap_pins.is_some() {
        fixed_staging_control_plan_sdk_tap_v2(&control_pins, pins.role)
    } else {
        fixed_staging_control_plan(&control_pins, pins.role)
    }
    .map_err(|error| error.to_string())?;
    let readiness =
        inspect_candidate_staging_readiness_ineligible(&CandidateConformanceReadinessPins {
            job_id: pins.build_job_id,
            source_sha: pins.source_sha,
            version: pins.version,
            config_digest: pins.config_digest,
            private_manifest_sha256: pins.private_manifest_sha256,
            prefix_tree_sha256: pins.prefix_tree_sha256,
            controller_path: pins.controller_path,
            controller_tree_sha256: pins.controller_tree_sha256,
        })
        .map_err(|error| error.to_string())?;
    if !readiness.contained_completion_present() {
        return Err("candidate lacks contained-output completion capability".to_owned());
    }
    let interpreter = read_fixed_interpreter_path_held(pins.python_path, pins.interpreter_sha256)
        .map_err(|error| error.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(STAGING_STATE))
        .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    recheck_prelaunch(pins, &interpreter, &journal, &lease)?;
    let effect_events = if root_relay {
        Some(EffectMonitorThread::start(
            StagingEffectEvents::start_for_run(Path::new("/home"), pins.run_id, pins.role)?,
        )?)
    } else {
        None
    };
    let mut group = OwnedJobCgroup::create(pins.run_id).map_err(|error| error.to_string())?;
    let mut tap = match tap_pins {
        Some(tap_pins) => match if root_relay {
            StagingTapV2::prepare_root_relay_pidns(
                tap_pins,
                readiness.verified_bun_sha256(),
                pins.run_id,
                &journal,
                &lease,
            )
        } else if pidns {
            StagingTapV2::prepare_pidns(
                tap_pins,
                readiness.verified_bun_sha256(),
                pins.run_id,
                &journal,
                &lease,
            )
        } else {
            StagingTapV2::prepare(
                tap_pins,
                readiness.verified_bun_sha256(),
                pins.run_id,
                &journal,
                &lease,
            )
        } {
            Ok(tap) => Some(tap),
            Err(error) => {
                cleanup(&mut group, None, pins.run_id, false)
                    .map_err(|cleanup| format!("SDK tap prelaunch cleanup uncertain: {cleanup}"))?;
                return Err(error);
            }
        },
        None => None,
    };
    run_with_group(
        pins,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
        &plan,
        &interpreter,
        &journal,
        &lease,
        &mut group,
        tap.as_mut(),
        effect_events,
    )
}

#[allow(clippy::too_many_arguments)]
fn wait_with_sdk_tap_v2(
    child: &mut std::process::Child,
    sampler: &mut StagingKernelSampler,
    group: &OwnedJobCgroup,
    tap: &StagingTapV2,
    pins: &CandidateStagingRunPins<'_>,
    process: crate::ProcessIdentity,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    effect_events: Option<&EffectMonitorThread>,
) -> Result<(WaitOutcome, Result<TapSessions, String>), String> {
    let controller = SdkWirePeerPin {
        pid: process.pid,
        start_ticks: process.start_ticks,
        cgroup: group.path().to_owned(),
    };
    let (sender, receiver) = sync_channel::<SdkWirePeerPin>(1);
    let tap_stopped = AtomicBool::new(false);
    thread::scope(|scope| {
        let stopped = &tap_stopped;
        let controller = &controller;
        let tap_handle = scope.spawn(move || {
            let ancestor = loop {
                if stopped.load(Ordering::Acquire)
                    || cancellation.load(Ordering::Acquire)
                    || deadline
                        .remaining()
                        .map_err(|error| error.to_string())?
                        .is_zero()
                {
                    return Err("SDK tap ended without an exact live Bun ancestor".to_owned());
                }
                match receiver.recv_timeout(Duration::from_millis(20)) {
                    Ok(pin) => break pin,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err("SDK tap ancestor handoff closed".to_owned());
                    }
                }
            };
            tap.run_sessions(
                journal,
                lease,
                pins.run_id,
                pins.role,
                controller,
                &ancestor,
                deadline,
                stopped,
            )
        });
        let mut sender = Some(sender);
        let waited = wait_for_child(
            child,
            deadline,
            || {
                lease
                    .verify(&journal.root)
                    .map_err(crate::controller_run::ControllerRunError::Lease)?;
                sampler
                    .sample(group)
                    .map_err(crate::controller_run::ControllerRunError::KernelObservation)?;
                if effect_events.is_some_and(EffectMonitorThread::failed) {
                    return Err(
                        crate::controller_run::ControllerRunError::KernelObservation(
                            "effect observer stopped before controller exit".to_owned(),
                        ),
                    );
                }
                if sender.is_some() {
                    if let Some(ancestor) = sampler
                        .unique_live_sdk_ancestor(tap.bun_sha256())
                        .map_err(crate::controller_run::ControllerRunError::KernelObservation)?
                    {
                        if let Some(sender) = sender.take() {
                            let _ = sender.send(ancestor);
                        }
                    }
                }
                Ok(())
            },
            || cancellation.load(Ordering::Acquire),
        );
        // The Python controller has stopped. Give already active relay
        // sessions a short bounded chance to finish their final frame/EOF.
        let settle_until = Instant::now() + Duration::from_secs(2);
        while waited.is_ok()
            && !tap_handle.is_finished()
            && !cancellation.load(Ordering::Acquire)
            && Instant::now() < settle_until
            && deadline.remaining().unwrap_or(Duration::ZERO) > Duration::ZERO
        {
            thread::sleep(Duration::from_millis(20));
        }
        tap_stopped.store(true, Ordering::Release);
        let tap_result = tap_handle
            .join()
            .map_err(|_| "SDK tap worker thread panicked".to_owned())?;
        Ok((waited.map_err(|error| error.to_string())?, tap_result))
    })
}

#[allow(clippy::too_many_arguments)]
fn run_with_group(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
    plan: &crate::FixedStagingControlPlan,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    group: &mut OwnedJobCgroup,
    mut tap: Option<&mut StagingTapV2>,
    effect_events: Option<EffectMonitorThread>,
) -> Result<CandidateStagingRunProof, String> {
    let launched = launch_control(
        pins,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
        plan,
        interpreter,
        journal,
        lease,
        group,
    );
    let (mut child, started, key_pin) = match launched {
        Ok(value) => value,
        Err(error) => {
            let control_cleanup = cleanup(group, None, pins.run_id, false);
            let tap_cleanup = tap
                .as_mut()
                .map(|tap| tap.cleanup(journal, lease))
                .transpose();
            control_cleanup
                .map_err(|cleanup| format!("staging prelaunch cleanup uncertain: {cleanup}"))?;
            tap_cleanup?;
            return Err(error);
        }
    };
    let observed = (|| {
        let process = observe_child(&child, group.path()).map_err(|error| error.to_string())?;
        journal
            .mark_running_under_lease(
                lease,
                request,
                pins.source_sha,
                pins.config_digest,
                pins.worker_generation_sha256,
                &started.sha256,
                process,
                group.path(),
            )
            .map_err(|error| error.to_string())?;
        let mut sampler = StagingKernelSampler::new(pins.run_id, pins.role)?;
        sampler.sample(group)?;
        let (outcome, tap_sessions) = if let Some(tap) = tap.as_ref() {
            let (outcome, sessions) = wait_with_sdk_tap_v2(
                &mut child,
                &mut sampler,
                group,
                tap,
                pins,
                process,
                journal,
                lease,
                deadline,
                cancellation,
                effect_events.as_ref(),
            )?;
            (outcome, Some(sessions))
        } else {
            let outcome = wait_for_child(
                &mut child,
                deadline,
                || {
                    lease
                        .verify(&journal.root)
                        .map_err(crate::controller_run::ControllerRunError::Lease)?;
                    sampler
                        .sample(group)
                        .map_err(crate::controller_run::ControllerRunError::KernelObservation)?;
                    if effect_events
                        .as_ref()
                        .is_some_and(EffectMonitorThread::failed)
                    {
                        return Err(
                            crate::controller_run::ControllerRunError::KernelObservation(
                                "effect observer stopped before controller exit".to_owned(),
                            ),
                        );
                    }
                    Ok(())
                },
                || cancellation.load(Ordering::Acquire),
            )
            .map_err(|error| error.to_string())?;
            (outcome, None)
        };
        Ok::<_, String>((process, outcome, sampler.finish(), tap_sessions))
    })();
    let control_cleanup = cleanup(group, Some(&mut child), pins.run_id, true);
    let tap_cleanup = tap
        .as_mut()
        .map(|tap| tap.cleanup(journal, lease))
        .transpose();
    control_cleanup.map_err(|error| format!("staging child cleanup uncertain: {error}"))?;
    tap_cleanup?;
    let (process, outcome, live_kernel_activity, tap_sessions) = observed?;
    let finished_effect_events = effect_events.map(EffectMonitorThread::finish).transpose()?;
    let (exit_code, timed_out) = match outcome {
        WaitOutcome::Exited(status) => (
            status
                .code()
                .or_else(|| status.signal().map(|signal| 128 + signal))
                .ok_or("staging child exit status unavailable")?,
            false,
        ),
        WaitOutcome::TimedOut => (124, true),
    };
    let post_run_controller_custody = recheck_prelaunch(pins, interpreter, journal, lease).is_ok();
    require_pinned_controller_key_under_lease(journal, lease, &started, &key_pin)
        .map_err(|error| error.to_string())?;
    let sdk_tap_v2 = match (tap.as_ref(), tap_sessions) {
        (Some(tap), Some(Ok(sessions))) => Some(
            match tap.retain_sessions(journal, lease, &started, &sessions) {
                Ok(receipt) => sessions.summary(&receipt),
                Err(error) => {
                    json!({"schema":"hol-gauntlet-staging-sdk-tap-summary.v1","status":"invalid-evidence","error":error,"execution_eligible":false})
                }
            },
        ),
        (Some(_), Some(Err(error))) => Some(json!({
            "schema":"hol-gauntlet-staging-sdk-tap-summary.v1",
            "status":"invalid-evidence",
            "error":error,
            "execution_eligible":false,
        })),
        (Some(_), None) => return Err("SDK tap outcome missing".to_owned()),
        (None, _) => None,
    };
    let effect_events = finished_effect_events
        .as_ref()
        .map(|finished| {
            retain_staging_effect_journal_ineligible(journal, lease, &started, finished)
                .map(|receipt| receipt.to_json())
        })
        .transpose()?;
    let mut report = json!({
        "schema":"hol-gauntlet-staging-control-run-report.v1",
        "source_sha":pins.source_sha,
        "build_job_id":pins.build_job_id,
        "run_id":pins.run_id,
        "role":pins.role.as_str(),
        "provisional_config_digest":pins.config_digest,
        "controller_public_key_hex":key_pin.public_key_hex,
        "process":{"pid":process.pid,"start_ticks":process.start_ticks},
        "exit_code":exit_code,
        "timed_out":timed_out,
        "controller_and_product_slice_cleanup_verified":true,
        "post_run_controller_custody":post_run_controller_custody,
        "live_kernel_activity":live_kernel_activity.to_json(),
        "record_scored":false,
        "execution_eligible":false,
    });
    if let Some(tap) = &sdk_tap_v2 {
        report["sdk_tap_v2"] = tap.clone();
    }
    if let Some(events) = &effect_events {
        report["effect_events"] = events.clone();
    }
    if let Some(product) = &live_kernel_activity.product {
        report["live_product_activity"] = product.to_json();
    }
    let raw = canonicalize(report.to_string().as_bytes()).map_err(|error| error.to_string())?;
    let terminal = journal
        .finish_under_lease(
            lease,
            request,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
            &started.sha256,
            &raw,
            process,
            exit_code,
            TerminalOutcome::InvalidEvidence,
            Some(&key_pin.raw_sha256),
        )
        .map_err(|error| error.to_string())?;
    Ok(CandidateStagingRunProof {
        run_id: pins.run_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        role: pins.role.as_str().to_owned(),
        controller_public_key_hex: key_pin.public_key_hex.clone(),
        controller_key_pin_sha256: key_pin.raw_sha256.clone(),
        started_marker_sha256: started.sha256.clone(),
        terminal_sha256: terminal.sha256,
        exit_code,
        timed_out,
        post_run_controller_custody,
        live_kernel_activity,
        sdk_tap_v2,
        effect_events,
    })
}

#[allow(clippy::too_many_arguments)]
fn launch_control(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
    plan: &crate::FixedStagingControlPlan,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    group: &OwnedJobCgroup,
) -> Result<
    (
        std::process::Child,
        crate::StartedMarker,
        crate::controller_key::ControllerKeyPin,
    ),
    String,
> {
    let key = SealedControllerKey::generate().map_err(|error| error.to_string())?;
    let started = journal
        .reserve_keyed_under_lease(
            lease,
            request,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
            key.public_key_hex(),
        )
        .map_err(|error| error.to_string())?;
    let key_pin = pin_controller_key_under_lease(journal, lease, &started, &key)
        .map_err(|error| error.to_string())?;
    let prepared = PrelaunchPrepared {
        job_id: started.job_id.clone(),
        source_sha: started.source_sha.clone(),
        deployment_digest: started.deployment_digest.clone(),
        worker_generation: started.worker_generation.clone(),
        started_marker_sha256: started.sha256.clone(),
        controller_key_pin_sha256: key_pin.raw_sha256.clone(),
        controller_public_key_hex: key_pin.public_key_hex.clone(),
    };
    let frame = prepared.to_bytes().map_err(|error| error.to_string())?;
    exchange_prelaunch_pipe(
        &frame,
        prepared_writer,
        acknowledgement_reader,
        deadline,
        cancellation,
    )
    .map_err(|error| error.to_string())?;
    if cancellation.load(Ordering::Acquire)
        || deadline
            .remaining()
            .map_err(|error| error.to_string())?
            .is_zero()
    {
        return Err("staging cancelled or expired before spawn".to_owned());
    }
    recheck_prelaunch(pins, interpreter, journal, lease)?;
    require_pinned_controller_key_under_lease(journal, lease, &started, &key_pin)
        .map_err(|error| error.to_string())?;
    let log = staging_log(journal, pins.run_id)?;
    let cwd = open_root_owned_public_directory(Path::new(plan.cwd()))
        .map_err(|error| error.to_string())?;
    let writer = group.writer().map_err(|error| error.to_string())?;
    let mut environment = plan.environment();
    environment.insert(
        "HOL_GAUNTLET_RUST_SIGNING_KEY_FD",
        key.fd().as_raw_fd().to_string(),
    );
    let child = spawn_root_fd(
        interpreter,
        plan.argv(),
        &environment,
        cwd,
        writer,
        Some(key.fd()),
        Stdio::from(log.try_clone().map_err(|error| error.to_string())?),
        Stdio::from(log),
    )
    .map_err(|error| error.to_string())?;
    Ok((child, started, key_pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires dedicated Linux ARM64 Root VM fanotify"]
    fn effect_thread_retains_a_live_writer_after_cleanup_boundary() {
        let directory = tempfile::tempdir_in("/home").unwrap();
        let path = directory.path().join("effect.txt");
        let monitor =
            EffectMonitorThread::start(StagingEffectEvents::start(Path::new("/home")).unwrap())
                .unwrap();
        std::fs::write(&path, b"synthetic-effect").unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(!monitor.failed());
        let finished = monitor.finish().unwrap();
        let held = std::fs::File::open(&path).unwrap();
        let target = held.metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        let event = finished
            .events()
            .iter()
            .find(|event| event.device == target.dev() && event.inode == target.ino())
            .unwrap();
        assert_eq!(event.reported_pid, std::process::id());
        assert!(event.pidfd_available);
        let writer = event.writer.as_ref().unwrap();
        let correlated = finished.correlate_file(&held, &writer.cgroup).unwrap();
        assert_eq!(correlated.close_writes, 1);
    }
}
