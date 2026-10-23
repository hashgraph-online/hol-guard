//! Descriptor-bound Root controller launch primitive. It accepts only a
//! `PreparedLaunch` produced by the fixed prelaunch reader and the matching
//! job-owned cgroup. The caller still owns lease, deadline, report, product
//! slice and terminal reconciliation; spawning is not a benchmark verdict.

use crate::contained_probe::{CgroupProbeError, OwnedJobCgroup};
use crate::controller_key::{
    pin_controller_key_under_lease, require_pinned_controller_key_under_lease, ControllerKeyError,
    ControllerKeyPin, SealedControllerKey,
};
use crate::deadline::DeadlineError;
use crate::interpreter_exec::InterpreterExecError;
use crate::launch_plan::{rust_controller_cgroup_path, rust_job_slice_name};
use crate::linux_process::ProcessObservationError;
use crate::prelaunch::{PrelaunchError, PreparedLaunch};
use crate::process_reap::reap_probe_child_bounded;
use crate::{
    open_canonical_directory, open_root_owned_public_directory, ActiveLease, BoottimeDeadline,
    HeldInterpreter, ReservationError, RunReservationJournal, StartedMarker,
};
use gauntlet_contracts::{PrelaunchHandoffError, PrelaunchPrepared, WorkerRequest};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_ARGV: usize = 22;
const ENV_KEYS: [&str; 4] = ["HOL_GAUNTLET_RUST_JOB_SLICE", "HOME", "LANG", "PATH"];
const SIGNED_ENV_KEYS: [&str; 5] = [
    "HOL_GAUNTLET_RUST_JOB_SLICE",
    "HOL_GAUNTLET_RUST_SIGNING_KEY_FD",
    "HOME",
    "LANG",
    "PATH",
];
const OUTPUT_DIRECTORY: &str = "/var/lib/hol-gauntlet/outputs";

#[derive(Debug)]
pub enum ControllerExecError {
    RootRequired,
    InvalidPlan,
    UnsafeLog,
    OutputExists,
    Prelaunch(PrelaunchError),
    Reservation(ReservationError),
    ControllerKey(ControllerKeyError),
    HostHandoff(PrelaunchHandoffError),
    HostPipeUnavailable,
    HostPipeTooLarge,
    Deadline(DeadlineError),
    PrelaunchExpired,
    Cancelled,
    Interpreter(InterpreterExecError),
    Cgroup(CgroupProbeError),
    Process(ProcessObservationError),
    Spawn,
    ChildIdentityUnknown,
    PostLaunch(Box<ControllerExecError>),
    CleanupUncertain,
}

impl fmt::Display for ControllerExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootRequired => f.write_str("Linux Root required for controller launch"),
            Self::InvalidPlan => {
                f.write_str("fixed controller launch plan differs from held inputs")
            }
            Self::UnsafeLog => f.write_str("Root-owned private controller log required"),
            Self::OutputExists => f.write_str("fixed benchmark output path already exists"),
            Self::Prelaunch(error) => write!(f, "prelaunch custody changed: {error}"),
            Self::Reservation(error) => write!(f, "worker reservation: {error}"),
            Self::ControllerKey(error) => write!(f, "worker controller key: {error}"),
            Self::HostHandoff(error) => write!(f, "host prelaunch handoff: {error}"),
            Self::HostPipeUnavailable => f.write_str("host prelaunch pipe unavailable"),
            Self::HostPipeTooLarge => f.write_str("host prelaunch frame exceeds 1024 bytes"),
            Self::Deadline(error) => write!(f, "host prelaunch deadline: {error}"),
            Self::PrelaunchExpired => f.write_str("host prelaunch deadline expired before spawn"),
            Self::Cancelled => {
                f.write_str("controller launch cancelled before host acknowledgement")
            }
            Self::Interpreter(error) => write!(f, "interpreter execution: {error}"),
            Self::Cgroup(error) => write!(f, "controller cgroup: {error}"),
            Self::Process(error) => write!(f, "controller process identity: {error:?}"),
            Self::Spawn => f.write_str("descriptor-bound Root child could not start or be reaped"),
            Self::ChildIdentityUnknown => f.write_str("Root child credentials are unavailable"),
            Self::PostLaunch(error) => {
                write!(f, "controller spawned but post-check failed: {error}")
            }
            Self::CleanupUncertain => f.write_str("Root child cleanup could not be proven"),
        }
    }
}

impl std::error::Error for ControllerExecError {}

fn cstring(value: &str) -> Result<CString, ControllerExecError> {
    CString::new(value).map_err(|_| ControllerExecError::InvalidPlan)
}

fn fixed_environment(
    environment: &BTreeMap<&'static str, String>,
    signing_fd: Option<RawFd>,
) -> Result<Vec<CString>, ControllerExecError> {
    let keys = environment.keys().copied().collect::<Vec<_>>();
    if (signing_fd.is_some() && keys != SIGNED_ENV_KEYS)
        || (signing_fd.is_none() && keys != ENV_KEYS)
        || signing_fd.is_some_and(|fd| {
            !(3..=4096).contains(&fd)
                || environment["HOL_GAUNTLET_RUST_SIGNING_KEY_FD"] != fd.to_string()
        })
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    environment
        .iter()
        .map(|(name, value)| cstring(&format!("{name}={value}")))
        .collect()
}

#[cfg(test)]
#[path = "controller_exec_tests.rs"]
mod tests;

#[path = "controller_exec_pipe.rs"]
mod pipe;
pub use pipe::{exchange_prelaunch_pipe, read_run_request_pipe};

#[path = "controller_exec_probe.rs"]
mod probe;
pub use probe::{run_fixed_root_controller_exec_probe, RootControllerProbeProof};

/// Replace `/usr/bin/false` before it can execute. All strings, pointers,
/// descriptors and output handles are prepared in the parent. The child
/// performs only fixed syscalls before `execveat(AT_EMPTY_PATH)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_root_fd(
    interpreter: &HeldInterpreter,
    argv: &[String],
    environment: &BTreeMap<&'static str, String>,
    cwd: OwnedFd,
    cgroup_writer: OwnedFd,
    signing_key: Option<&File>,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, ControllerExecError> {
    if argv.is_empty() || argv.len() > MAX_ARGV || argv[0] != interpreter.declaration().python_path
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    let args: Vec<CString> = argv
        .iter()
        .map(|value| cstring(value))
        .collect::<Result<_, _>>()?;
    let signing_fd = signing_key.map(AsRawFd::as_raw_fd);
    let env = fixed_environment(environment, signing_fd)?;
    let argument_ptrs: Vec<usize> = args.iter().map(|value| value.as_ptr() as usize).collect();
    let environment_ptrs: Vec<usize> = env.iter().map(|value| value.as_ptr() as usize).collect();
    let executable = interpreter
        .checked_fd()
        .map_err(|_| ControllerExecError::Interpreter(InterpreterExecError::InvalidInterpreter))?;
    let executable_fd = executable.as_raw_fd();
    let mut command = Command::new("/usr/bin/false");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: no allocation or lock is taken after fork. The fixed cgroup
    // writer and already-opened cwd/executable descriptors remain alive until
    // the syscall replaces the child or `Command::spawn` returns an error.
    unsafe {
        command.pre_exec(move || {
            let _keep_args = &args;
            let _keep_env = &env;
            let mut pid = libc::getpid() as u32;
            let mut digits = [0u8; 10];
            let mut start = digits.len();
            loop {
                start -= 1;
                digits[start] = b'0' + (pid % 10) as u8;
                pid /= 10;
                if pid == 0 {
                    break;
                }
            }
            let bytes = &digits[start..];
            let written = libc::write(
                cgroup_writer.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            );
            if written != bytes.len() as isize {
                return Err(if written < 0 {
                    io::Error::last_os_error()
                } else {
                    io::Error::from_raw_os_error(libc::EIO)
                });
            }
            if libc::fchdir(cwd.as_raw_fd()) != 0
                || libc::setsid() < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            if let Some(fd) = signing_fd {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0
                    || flags & libc::FD_CLOEXEC == 0
                    || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut argv_ptrs = [std::ptr::null(); MAX_ARGV + 1];
            for (slot, pointer) in argv_ptrs.iter_mut().zip(&argument_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            let mut env_ptrs = [std::ptr::null(); SIGNED_ENV_KEYS.len() + 1];
            for (slot, pointer) in env_ptrs.iter_mut().zip(&environment_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    command.spawn().map_err(|_| ControllerExecError::Spawn)
}

/// Internal launch step for a future worker dispatcher. A verified one-time
/// marker and matching lease are mandatory; the caller must still retain the
/// lease, child and cgroup through deadline, report, product-slice cleanup and
/// terminal reconciliation. The host must durably record the prepared frame
/// and return its exact ack before the child may spawn. This remains internal.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn spawn_prepared_controller(
    prepared: &PreparedLaunch,
    group: &OwnedJobCgroup,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    worker_generation: &str,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    acknowledge: impl FnOnce(
        &[u8],
        &BoottimeDeadline,
        &AtomicBool,
    ) -> Result<Vec<u8>, ControllerExecError>,
) -> Result<(Child, StartedMarker, ControllerKeyPin), ControllerExecError> {
    if geteuid().as_raw() != 0 {
        return Err(ControllerExecError::RootRequired);
    }
    if !journal.root_owned {
        return Err(ControllerExecError::Reservation(
            ReservationError::UnsafeRoot,
        ));
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerExecError::Reservation)?;
    let plan = prepared.launch_plan();
    if !prepared.matches_run_request(request)
        || rust_controller_cgroup_path(request.job_id())
            .ok()
            .as_deref()
            != Some(plan.controller_cgroup())
        || rust_job_slice_name(request.job_id()).ok().as_deref() != Some(plan.job_slice())
        || group.path() != plan.controller_cgroup()
        || plan.fixed().argv.len() != MAX_ARGV
        || plan.fixed().argv[0] != prepared.interpreter().declaration().python_path
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    prepared
        .recheck_controller_and_interpreter()
        .map_err(ControllerExecError::Prelaunch)?;
    // A stale output is an admission refusal, not a reason to consume a
    // one-use key pin. Recheck again after the host acknowledgement below.
    require_fresh_output(request.job_id())?;
    let deployment_digest = request
        .deployment_digest()
        .ok_or(ControllerExecError::InvalidPlan)?;
    let signing_key =
        SealedControllerKey::generate().map_err(ControllerExecError::ControllerKey)?;
    let started = journal
        .reserve_keyed_under_lease(
            lease,
            request,
            request.source_sha(),
            deployment_digest,
            worker_generation,
            signing_key.public_key_hex(),
        )
        .map_err(ControllerExecError::Reservation)?;
    let pin = pin_controller_key_under_lease(journal, lease, &started, &signing_key)
        .map_err(ControllerExecError::ControllerKey)?;
    let prepared_frame = PrelaunchPrepared {
        job_id: started.job_id.clone(),
        source_sha: started.source_sha.clone(),
        deployment_digest: started.deployment_digest.clone(),
        worker_generation: started.worker_generation.clone(),
        started_marker_sha256: started.sha256.clone(),
        controller_key_pin_sha256: pin.raw_sha256.clone(),
        controller_public_key_hex: pin.public_key_hex.clone(),
    };
    let frame = prepared_frame
        .to_bytes()
        .map_err(ControllerExecError::HostHandoff)?;
    let acknowledgement = acknowledge(&frame, deadline, cancellation)?;
    prepared_frame
        .verify_acknowledgement(&acknowledgement)
        .map_err(ControllerExecError::HostHandoff)?;
    if cancellation.load(Ordering::Acquire) {
        return Err(ControllerExecError::Cancelled);
    }
    if deadline
        .remaining()
        .map_err(ControllerExecError::Deadline)?
        .is_zero()
    {
        return Err(ControllerExecError::PrelaunchExpired);
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerExecError::Reservation)?;
    require_pinned_controller_key_under_lease(journal, lease, &started, &pin)
        .map_err(ControllerExecError::ControllerKey)?;
    prepared
        .recheck_controller_and_interpreter()
        .map_err(ControllerExecError::Prelaunch)?;
    require_fresh_output(request.job_id())?;
    let log = open_fixed_log(request.job_id(), &plan.fixed().log_path)?;
    let cwd = open_root_owned_public_directory(Path::new(&plan.fixed().cwd))
        .map_err(|_| ControllerExecError::InvalidPlan)?;
    let writer = group.writer().map_err(ControllerExecError::Cgroup)?;
    let mut environment = plan.environment();
    environment.insert(
        "HOL_GAUNTLET_RUST_SIGNING_KEY_FD",
        signing_key.fd().as_raw_fd().to_string(),
    );
    let mut child = spawn_root_fd(
        prepared.interpreter(),
        &plan.fixed().argv,
        &environment,
        cwd,
        writer,
        Some(signing_key.fd()),
        Stdio::from(
            log.try_clone()
                .map_err(|_| ControllerExecError::UnsafeLog)?,
        ),
        Stdio::from(
            log.try_clone()
                .map_err(|_| ControllerExecError::UnsafeLog)?,
        ),
    )?;
    let post_check = prepared
        .recheck_controller_and_interpreter()
        .map_err(ControllerExecError::Prelaunch)
        .and_then(|()| {
            lease
                .verify(&journal.root)
                .map_err(ControllerExecError::Reservation)
        })
        .and_then(|()| {
            require_pinned_controller_key_under_lease(journal, lease, &started, &pin)
                .map_err(ControllerExecError::ControllerKey)
        })
        .and_then(|()| {
            let retained = journal
                .started(
                    request.job_id(),
                    request.source_sha(),
                    deployment_digest,
                    worker_generation,
                )
                .map_err(ControllerExecError::Reservation)?;
            if retained.as_ref() == Some(&started) {
                Ok(())
            } else {
                Err(ControllerExecError::Reservation(
                    ReservationError::InvalidMarker,
                ))
            }
        });
    if let Err(error) = post_check {
        let killed = group.kill();
        let reaped = reap_probe_child_bounded(&mut child);
        if killed.is_err() || reaped.is_err() {
            return Err(ControllerExecError::CleanupUncertain);
        }
        return Err(ControllerExecError::PostLaunch(Box::new(error)));
    }
    Ok((child, started, pin))
}

fn require_absent_child(output: &OwnedFd, name: &str) -> Result<(), ControllerExecError> {
    match statat(output, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Ok(_) => Err(ControllerExecError::OutputExists),
        Err(_) => Err(ControllerExecError::UnsafeLog),
    }
}

fn require_fresh_output(job_id: &str) -> Result<(), ControllerExecError> {
    let output = open_canonical_directory(Path::new(OUTPUT_DIRECTORY), true)
        .map_err(|_| ControllerExecError::UnsafeLog)?;
    require_absent_child(&output, job_id)
}

fn open_fixed_log(job_id: &str, declared_path: &str) -> Result<File, ControllerExecError> {
    if declared_path != format!("{OUTPUT_DIRECTORY}/{job_id}.log") {
        return Err(ControllerExecError::UnsafeLog);
    }
    let output = open_canonical_directory(Path::new(OUTPUT_DIRECTORY), true)
        .map_err(|_| ControllerExecError::UnsafeLog)?;
    let filename = format!("{job_id}.log");
    let descriptor = openat(
        &output,
        filename.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| ControllerExecError::UnsafeLog)?;
    let metadata = fstat(&descriptor).map_err(|_| ControllerExecError::UnsafeLog)?;
    if metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o077 != 0
        || metadata.st_size != 0
    {
        return Err(ControllerExecError::UnsafeLog);
    }
    fsync(&descriptor).map_err(|_| ControllerExecError::UnsafeLog)?;
    fsync(&output).map_err(|_| ControllerExecError::UnsafeLog)?;
    Ok(File::from(descriptor))
}
