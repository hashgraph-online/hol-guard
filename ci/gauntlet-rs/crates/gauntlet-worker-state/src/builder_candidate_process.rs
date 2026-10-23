//! Bounded Podman client ownership for one local candidate container. The
//! caller owns AppArmor and source custody before and after this process.

use crate::builder_cgroup::OwnedCandidateCgroup;
use crate::builder_image_build::free_bytes;
use crate::builder_run_plan::BuilderRunPlan;
use crate::linux_process::{observe_process, parse_proc_stat};
use crate::process_reap::reap_probe_child_bounded;
use rustix::fs::{fsync, openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const MIN_REMAIN_FREE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const RUN_WAIT: Duration = Duration::from_secs(2100);
const INSPECT_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateProcessError {
    ExistingContainer,
    ContainerUnknown,
    LogUnavailable,
    CgroupUnavailable,
    SpawnFailed,
    ProcessMismatch,
    LeaseUnavailable,
    LowDisk,
    TimedOut,
    CleanupUncertain,
}

impl fmt::Display for CandidateProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ExistingContainer => "candidate container name already exists",
            Self::ContainerUnknown => "candidate container absence could not be established",
            Self::LogUnavailable => "bounded candidate output log unavailable",
            Self::CgroupUnavailable => "fixed candidate cgroup unavailable",
            Self::SpawnFailed => "fixed Podman candidate client could not start",
            Self::ProcessMismatch => "Podman client process differs from owned cgroup",
            Self::LeaseUnavailable => "worker lease changed during candidate execution",
            Self::LowDisk => "candidate execution crossed the VM disk reserve",
            Self::TimedOut => "candidate execution exceeded its fixed deadline",
            Self::CleanupUncertain => "candidate process or cgroup cleanup is uncertain",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateProcessObservation {
    pub(crate) client_pid: u32,
    pub(crate) client_start_ticks: u64,
    pub(crate) exit_code: i32,
    pub(crate) stdout_sha256: String,
    pub(crate) stderr_sha256: String,
}

fn podman_command() -> Command {
    let mut command = Command::new("/usr/bin/podman");
    command.env_clear();
    command.env("HOME", "/root");
    command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command.env("TMPDIR", "/var/tmp");
    command
}

pub(crate) fn container_absent(job_id: &str) -> Result<bool, CandidateProcessError> {
    let mut command = podman_command();
    command.args([
        "container",
        "exists",
        &format!("hol-gauntlet-build-{job_id}"),
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| CandidateProcessError::ContainerUnknown)?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < INSPECT_WAIT => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CandidateProcessError::ContainerUnknown);
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| CandidateProcessError::ContainerUnknown)?;
    if output.stdout.len() > 4096 || output.stderr.len() > 4096 {
        return Err(CandidateProcessError::ContainerUnknown);
    }
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(CandidateProcessError::ContainerUnknown),
    }
}

fn create_log(job: &OwnedFd, name: &str) -> Result<File, CandidateProcessError> {
    let descriptor = openat(
        job,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| CandidateProcessError::LogUnavailable)?;
    Ok(File::from(descriptor))
}

fn record_stream(
    stream_id: u8,
    mut stream: impl Read + Send + 'static,
    mut file: File,
    exceeded: Arc<AtomicBool>,
    channel: mpsc::Sender<(u8, Result<String, CandidateProcessError>)>,
) {
    thread::spawn(move || {
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        let result = (|| {
            loop {
                let count = stream
                    .read(&mut buffer)
                    .map_err(|_| CandidateProcessError::LogUnavailable)?;
                if count == 0 {
                    break;
                }
                let available = MAX_LOG_BYTES.saturating_sub(total) as usize;
                let kept = count.min(available);
                if kept > 0 {
                    file.write_all(&buffer[..kept])
                        .map_err(|_| CandidateProcessError::LogUnavailable)?;
                    hash.update(&buffer[..kept]);
                    total += kept as u64;
                }
                if kept < count {
                    exceeded.store(true, Ordering::Release);
                }
            }
            file.sync_all()
                .map_err(|_| CandidateProcessError::LogUnavailable)?;
            Ok(format!("{:x}", hash.finalize()))
        })();
        let _ = channel.send((stream_id, result));
    });
}

fn cleanup(
    group: &mut OwnedCandidateCgroup,
    child: &mut std::process::Child,
) -> Result<(), CandidateProcessError> {
    let killed = group.kill();
    let reaped = reap_probe_child_bounded(child);
    let drained = group.drain_and_remove();
    if killed.is_err() || reaped.is_err() || drained.is_err() {
        return Err(CandidateProcessError::CleanupUncertain);
    }
    Ok(())
}

pub(crate) fn run_candidate_process(
    plan: &BuilderRunPlan,
    job: &OwnedFd,
    still_owned: &impl Fn() -> Result<(), CandidateProcessError>,
) -> Result<CandidateProcessObservation, CandidateProcessError> {
    if !container_absent(&plan.job_id)? {
        return Err(CandidateProcessError::ExistingContainer);
    }
    let stdout = create_log(job, "candidate-run.stdout.log")?;
    let stderr = create_log(job, "candidate-run.stderr.log")?;
    fsync(job).map_err(|_| CandidateProcessError::LogUnavailable)?;
    let mut group = OwnedCandidateCgroup::create(&plan.job_id)
        .map_err(|_| CandidateProcessError::CgroupUnavailable)?;
    let mut command = podman_command();
    command.args(&plan.argv[1..]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if group.attach_child(&mut command).is_err() {
        let killed = group.kill();
        let drained = group.drain_and_remove();
        return if killed.is_ok() && drained.is_ok() {
            Err(CandidateProcessError::CgroupUnavailable)
        } else {
            Err(CandidateProcessError::CleanupUncertain)
        };
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let killed = group.kill();
            let drained = group.drain_and_remove();
            return if killed.is_ok() && drained.is_ok() {
                Err(CandidateProcessError::SpawnFailed)
            } else {
                Err(CandidateProcessError::CleanupUncertain)
            };
        }
    };
    let observed = std::fs::read(format!("/proc/{}/stat", child.id()))
        .ok()
        .and_then(|raw| parse_proc_stat(&raw, child.id()))
        .and_then(|stat| {
            observe_process(child.id(), stat.start_ticks, group.path())
                .ok()
                .map(|_| stat.start_ticks)
        });
    let Some(client_start_ticks) = observed else {
        cleanup(&mut group, &mut child)?;
        return Err(CandidateProcessError::ProcessMismatch);
    };
    let (child_stdout, child_stderr) = match (child.stdout.take(), child.stderr.take()) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        _ => {
            cleanup(&mut group, &mut child)?;
            return Err(CandidateProcessError::SpawnFailed);
        }
    };
    let (sender, receiver) = mpsc::channel();
    let exceeded = Arc::new(AtomicBool::new(false));
    record_stream(0, child_stdout, stdout, exceeded.clone(), sender.clone());
    record_stream(1, child_stderr, stderr, exceeded.clone(), sender);
    let started = Instant::now();
    let mut last_disk = Instant::now();
    let outcome = loop {
        if exceeded.load(Ordering::Acquire) {
            break Err(CandidateProcessError::LogUnavailable);
        }
        if still_owned().is_err() {
            break Err(CandidateProcessError::LeaseUnavailable);
        }
        if last_disk.elapsed() >= Duration::from_secs(5) {
            if !free_bytes().is_ok_and(|bytes| bytes >= MIN_REMAIN_FREE) {
                break Err(CandidateProcessError::LowDisk);
            }
            last_disk = Instant::now();
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break status
                    .code()
                    .or_else(|| status.signal().map(|signal| 128 + signal))
                    .ok_or(CandidateProcessError::ProcessMismatch)
            }
            Ok(None) if started.elapsed() < RUN_WAIT => thread::sleep(POLL),
            Ok(None) => break Err(CandidateProcessError::TimedOut),
            Err(_) => break Err(CandidateProcessError::CleanupUncertain),
        }
    };
    cleanup(&mut group, &mut child)?;
    let (first_id, first) = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| CandidateProcessError::CleanupUncertain)?;
    let (second_id, second) = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| CandidateProcessError::CleanupUncertain)?;
    if first_id == second_id {
        return Err(CandidateProcessError::CleanupUncertain);
    }
    let first = first?;
    let second = second?;
    let exit_code = outcome?;
    if exceeded.load(Ordering::Acquire) {
        return Err(CandidateProcessError::LogUnavailable);
    }
    if !container_absent(&plan.job_id)? {
        return Err(CandidateProcessError::ContainerUnknown);
    }
    let (stdout_sha256, stderr_sha256) = if first_id == 0 {
        (first, second)
    } else {
        (second, first)
    };
    Ok(CandidateProcessObservation {
        client_pid: child.id(),
        client_start_ticks,
        exit_code,
        stdout_sha256,
        stderr_sha256,
    })
}
