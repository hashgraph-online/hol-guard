//! Bounded one-use construction of the trusted, source-bound builder image.
//! Candidate source is not mounted or executed. A success is an image-custody
//! observation only; it cannot admit a candidate archive or benchmark result.

use crate::builder_cgroup::OwnedBuilderCgroup;
use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{
    fixed_builder_image_plan, inspect_fixed_builder_base_images, BuilderImagePlan,
};
use crate::builder_image_context::{
    python_worker_lock, verify_existing_context, verify_python_lock, RUST_STATE,
};
use crate::linux_process::{observe_process, parse_proc_stat};
use crate::process_reap::reap_probe_child_bounded;
use crate::{hex, open_root_owned_public_directory, RunReservationJournal};
use rustix::fs::{fstat, fsync, openat, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const BUILDS: &str = "/var/lib/hol-gauntlet/builds";
const MIN_START_FREE: u64 = 12 * 1024 * 1024 * 1024;
const MIN_REMAIN_FREE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const BUILD_WAIT: Duration = Duration::from_secs(1200);
const INSPECT_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderImageBuildError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ContextMismatch,
    BaseMismatch,
    ExistingImage,
    LowDisk,
    LogUnavailable,
    CgroupUnavailable,
    SpawnFailed,
    BuildFailed,
    TimedOut,
    CleanupUncertain,
    ImageMismatch,
}

impl fmt::Display for BuilderImageBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for trusted builder image build",
            Self::InvalidPins => "fixed controller, job and base image pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable or changed",
            Self::ContextMismatch => "one-use builder image context differs from pinned controller",
            Self::BaseMismatch => "local base image IDs changed or are unavailable",
            Self::ExistingImage => "Rust builder image tag already exists; inspect before retry",
            Self::LowDisk => "builder image build lacks the fixed disk reserve",
            Self::LogUnavailable => "one-use bounded builder log unavailable",
            Self::CgroupUnavailable => "fixed builder cgroup unavailable",
            Self::SpawnFailed => "fixed Podman image build could not start",
            Self::BuildFailed => "fixed Podman image build failed; inspect retained logs",
            Self::TimedOut => "fixed Podman image build exceeded its deadline",
            Self::CleanupUncertain => "builder process or cgroup cleanup is uncertain",
            Self::ImageMismatch => "resulting image identity or labels differ from the build pins",
        })
    }
}

impl std::error::Error for BuilderImageBuildError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderImageBuildProof {
    plan: BuilderImagePlan,
    image_id: String,
    stdout_sha256: String,
    stderr_sha256: String,
}

impl BuilderImageBuildProof {
    pub fn to_json(&self) -> Value {
        let mut value = self.plan.to_json();
        value["schema"] = json!("hol-gauntlet-builder-image-build-shadow.v1");
        value["base_images_verified"] = json!(true);
        value["image_built"] = json!(true);
        value["image_verified"] = json!(true);
        value["image_id"] = json!(self.image_id);
        value["stdout_sha256"] = json!(self.stdout_sha256);
        value["stderr_sha256"] = json!(self.stderr_sha256);
        value["cgroup_drained"] = json!(true);
        value["execution_eligible"] = json!(false);
        value
    }
}

pub(crate) fn free_bytes() -> Result<u64, BuilderImageBuildError> {
    let path = CString::new(BUILDS).map_err(|_| BuilderImageBuildError::LowDisk)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the fixed NUL-terminated path and writable statvfs buffer are valid.
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(BuilderImageBuildError::LowDisk);
    }
    // SAFETY: statvfs returned success and initialized the buffer.
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or(BuilderImageBuildError::LowDisk)
}

fn fixed_podman() -> Command {
    let mut command = Command::new("/usr/bin/podman");
    command.env_clear();
    command.env("HOME", "/root");
    command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command.env("TMPDIR", "/var/tmp");
    command
}

fn wait_short(mut command: Command) -> Result<std::process::Output, BuilderImageBuildError> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| BuilderImageBuildError::ImageMismatch)?;
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
                return Err(BuilderImageBuildError::ImageMismatch);
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| BuilderImageBuildError::ImageMismatch)?;
    if output.stdout.len() > 8192 || output.stderr.len() > 8192 {
        return Err(BuilderImageBuildError::ImageMismatch);
    }
    Ok(output)
}

fn tag_absent(plan: &BuilderImagePlan) -> Result<bool, BuilderImageBuildError> {
    let mut command = fixed_podman();
    command.args(["image", "exists", plan.image_tag.as_str()]);
    let output = wait_short(command)?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(BuilderImageBuildError::ImageMismatch),
    }
}

pub(crate) fn inspect_result(plan: &BuilderImagePlan) -> Result<String, BuilderImageBuildError> {
    let mut command = fixed_podman();
    command.args([
        "image",
        "inspect",
        "--format",
        "{{.Id}}|{{.Os}}|{{.Architecture}}|{{.User}}|{{json .Labels}}",
        plan.image_tag.as_str(),
    ]);
    let output = wait_short(command)?;
    if !output.status.success() {
        return Err(BuilderImageBuildError::ImageMismatch);
    }
    let raw =
        std::str::from_utf8(&output.stdout).map_err(|_| BuilderImageBuildError::ImageMismatch)?;
    let fields: Vec<_> = raw.trim_end_matches('\n').splitn(5, '|').collect();
    if fields.len() != 5
        || !hex(fields[0], 64)
        || fields[1] != "linux"
        || fields[2] != "arm64"
        || fields[3] != "65532:65532"
    {
        return Err(BuilderImageBuildError::ImageMismatch);
    }
    let labels: Value =
        serde_json::from_str(fields[4]).map_err(|_| BuilderImageBuildError::ImageMismatch)?;
    for (name, expected) in [
        (
            "hol.gauntlet.source_context",
            plan.source_context_sha256.as_str(),
        ),
        (
            "hol.gauntlet.dockerfile",
            plan.effective_dockerfile_sha256.as_str(),
        ),
        ("hol.gauntlet.uv_id", plan.uv_image_id.as_str()),
        ("hol.gauntlet.rust_id", plan.rust_image_id.as_str()),
    ] {
        if labels.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(BuilderImageBuildError::ImageMismatch);
        }
    }
    let image_id = format!("sha256:{}", fields[0]);
    let mut by_id = fixed_podman();
    by_id.args(["image", "inspect", "--format", "{{.Id}}", image_id.as_str()]);
    let by_id = wait_short(by_id)?;
    if !by_id.status.success() || by_id.stdout != format!("{}\n", fields[0]).as_bytes() {
        return Err(BuilderImageBuildError::ImageMismatch);
    }
    Ok(image_id)
}

fn create_log(job: &OwnedFd, name: &str) -> Result<File, BuilderImageBuildError> {
    let descriptor = openat(
        job,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| BuilderImageBuildError::LogUnavailable)?;
    Ok(File::from(descriptor))
}

fn record_stream(
    stream_id: u8,
    mut stream: impl Read + Send + 'static,
    mut file: File,
    exceeded: Arc<AtomicBool>,
    channel: mpsc::Sender<(u8, Result<String, BuilderImageBuildError>)>,
) {
    thread::spawn(move || {
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        let result = (|| {
            loop {
                let count = stream
                    .read(&mut buffer)
                    .map_err(|_| BuilderImageBuildError::LogUnavailable)?;
                if count == 0 {
                    break;
                }
                let available = MAX_LOG_BYTES.saturating_sub(total) as usize;
                let kept = count.min(available);
                if kept > 0 {
                    file.write_all(&buffer[..kept])
                        .map_err(|_| BuilderImageBuildError::LogUnavailable)?;
                    hash.update(&buffer[..kept]);
                    total += kept as u64;
                }
                if kept < count {
                    exceeded.store(true, Ordering::Release);
                }
            }
            file.sync_all()
                .map_err(|_| BuilderImageBuildError::LogUnavailable)?;
            Ok(format!("{:x}", hash.finalize()))
        })();
        let _ = channel.send((stream_id, result));
    });
}

fn build_argv(plan: &BuilderImagePlan) -> Vec<String> {
    let context = format!("{BUILDS}/{}/builder-image-context", plan.job_id);
    vec![
        "build".to_owned(),
        "--pull=never".to_owned(),
        "--no-cache".to_owned(),
        "--quiet".to_owned(),
        "--tag".to_owned(),
        plan.image_tag.clone(),
        "--label".to_owned(),
        format!("hol.gauntlet.source_context={}", plan.source_context_sha256),
        "--label".to_owned(),
        format!(
            "hol.gauntlet.dockerfile={}",
            plan.effective_dockerfile_sha256
        ),
        "--label".to_owned(),
        format!("hol.gauntlet.uv_id={}", plan.uv_image_id),
        "--label".to_owned(),
        format!("hol.gauntlet.rust_id={}", plan.rust_image_id),
        "--file".to_owned(),
        format!("{context}/Builder.Dockerfile"),
        context,
    ]
}

fn run_bounded_build(
    plan: &BuilderImagePlan,
    job: &OwnedFd,
    still_owned: &impl Fn() -> Result<(), BuilderImageBuildError>,
) -> Result<(String, String), BuilderImageBuildError> {
    let stdout = create_log(job, "builder-image.stdout.log")?;
    let stderr = create_log(job, "builder-image.stderr.log")?;
    fsync(job).map_err(|_| BuilderImageBuildError::LogUnavailable)?;
    let mut group = OwnedBuilderCgroup::create(&plan.job_id)
        .map_err(|_| BuilderImageBuildError::CgroupUnavailable)?;
    let mut command = fixed_podman();
    command.args(build_argv(plan));
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    group
        .attach_child(&mut command)
        .map_err(|_| BuilderImageBuildError::CgroupUnavailable)?;
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let killed = group.kill();
            let drained = group.drain_and_remove();
            return if killed.is_ok() && drained.is_ok() {
                Err(BuilderImageBuildError::SpawnFailed)
            } else {
                Err(BuilderImageBuildError::CleanupUncertain)
            };
        }
    };
    let observed = std::fs::read(format!("/proc/{}/stat", child.id()))
        .ok()
        .and_then(|raw| parse_proc_stat(&raw, child.id()))
        .is_some_and(|stat| observe_process(child.id(), stat.start_ticks, group.path()).is_ok());
    if !observed {
        let killed = group.kill();
        let reaped = reap_probe_child_bounded(&mut child);
        let drained = group.drain_and_remove();
        return if killed.is_ok() && reaped.is_ok() && drained.is_ok() {
            Err(BuilderImageBuildError::SpawnFailed)
        } else {
            Err(BuilderImageBuildError::CleanupUncertain)
        };
    }
    let (sender, receiver) = mpsc::channel();
    let exceeded = Arc::new(AtomicBool::new(false));
    let (child_stdout, child_stderr) = match (child.stdout.take(), child.stderr.take()) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        _ => {
            let killed = group.kill();
            let reaped = reap_probe_child_bounded(&mut child);
            let drained = group.drain_and_remove();
            return if killed.is_ok() && reaped.is_ok() && drained.is_ok() {
                Err(BuilderImageBuildError::SpawnFailed)
            } else {
                Err(BuilderImageBuildError::CleanupUncertain)
            };
        }
    };
    record_stream(0, child_stdout, stdout, exceeded.clone(), sender.clone());
    record_stream(1, child_stderr, stderr, exceeded.clone(), sender);
    let started = Instant::now();
    let mut last_disk = Instant::now();
    let outcome = loop {
        if exceeded.load(Ordering::Acquire) {
            break Err(BuilderImageBuildError::LogUnavailable);
        }
        if still_owned().is_err() {
            break Err(BuilderImageBuildError::LeaseUnavailable);
        }
        if last_disk.elapsed() >= Duration::from_secs(5) {
            if !free_bytes().is_ok_and(|bytes| bytes >= MIN_REMAIN_FREE) {
                break Err(BuilderImageBuildError::LowDisk);
            }
            last_disk = Instant::now();
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(BuilderImageBuildError::BuildFailed),
            Ok(None) if started.elapsed() < BUILD_WAIT => thread::sleep(POLL),
            Ok(None) => break Err(BuilderImageBuildError::TimedOut),
            Err(_) => break Err(BuilderImageBuildError::CleanupUncertain),
        }
    };
    let killed = group.kill();
    let reaped = reap_probe_child_bounded(&mut child);
    let drained = group.drain_and_remove();
    if killed.is_err() || reaped.is_err() || drained.is_err() {
        return Err(BuilderImageBuildError::CleanupUncertain);
    }
    let (first_id, first) = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| BuilderImageBuildError::CleanupUncertain)?;
    let (second_id, second) = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| BuilderImageBuildError::CleanupUncertain)?;
    if first_id == second_id {
        return Err(BuilderImageBuildError::CleanupUncertain);
    }
    let first = first?;
    let second = second?;
    outcome?;
    if exceeded.load(Ordering::Acquire) {
        return Err(BuilderImageBuildError::LogUnavailable);
    }
    if first_id == 0 {
        Ok((first, second))
    } else {
        Ok((second, first))
    }
}

/// Build only the trusted builder image from a previously materialized,
/// one-use Root context. Both worker locks remain held through cgroup cleanup
/// and image inspection. A failed or interrupted job cannot be retried here.
pub fn build_fixed_builder_image_ineligible(
    controller_root: &Path,
    tree_digest: &str,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
) -> Result<BuilderImageBuildProof, BuilderImageBuildError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderImageBuildError::RootRequired);
    }
    if !hex(tree_digest, 64) || !hex(job_id, 16) || !hex(uv_id, 64) || !hex(rust_id, 64) {
        return Err(BuilderImageBuildError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| BuilderImageBuildError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| BuilderImageBuildError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| BuilderImageBuildError::LeaseUnavailable)?;
    let context = inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    let plan = fixed_builder_image_plan(&context, job_id, uv_id, rust_id)
        .map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&plan).map_err(|_| BuilderImageBuildError::BaseMismatch)?;
    verify_existing_context(&plan).map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    if !tag_absent(&plan)? {
        return Err(BuilderImageBuildError::ExistingImage);
    }
    if free_bytes()? < MIN_START_FREE {
        return Err(BuilderImageBuildError::LowDisk);
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    let job = openat(
        &builds,
        job_id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    let stat = fstat(&job).map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o077 != 0
    {
        return Err(BuilderImageBuildError::ContextMismatch);
    }
    let still_owned = || {
        lease
            .verify(&journal.root)
            .map_err(|_| BuilderImageBuildError::LeaseUnavailable)?;
        verify_python_lock(&python_lock).map_err(|_| BuilderImageBuildError::LeaseUnavailable)
    };
    let (stdout_sha256, stderr_sha256) = run_bounded_build(&plan, &job, &still_owned)?;
    still_owned()?;
    verify_existing_context(&plan).map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderImageBuildError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&plan).map_err(|_| BuilderImageBuildError::BaseMismatch)?;
    let image_id = inspect_result(&plan)?;
    if free_bytes()? < MIN_REMAIN_FREE {
        return Err(BuilderImageBuildError::LowDisk);
    }
    Ok(BuilderImageBuildProof {
        plan,
        image_id,
        stdout_sha256,
        stderr_sha256,
    })
}

#[cfg(test)]
#[path = "builder_image_build_tests.rs"]
mod tests;
