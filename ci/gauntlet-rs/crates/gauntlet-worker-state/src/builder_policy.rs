//! One-use preparation and load/remove proof for the exact job AppArmor
//! policy. It does not start a candidate container or leave a profile loaded.

use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{fixed_builder_image_plan, inspect_fixed_builder_base_images};
use crate::builder_image_build::inspect_result;
use crate::builder_image_context::{
    python_worker_lock, verify_existing_context, verify_python_lock, RUST_STATE,
};
use crate::{hex, open_root_owned_public_directory, RunReservationJournal};
use rustix::fs::{fstat, fsync, open, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BUILDS: &str = "/var/lib/hol-gauntlet/builds";
const PARSER: &str = "/usr/sbin/apparmor_parser";
const PROFILES: &str = "/sys/kernel/security/apparmor/profiles";
const POLICY: &str = "Builder.apparmor";
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_PROFILES_BYTES: u64 = 64 * 1024;
const PARSER_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderPolicyError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ContextMismatch,
    BaseMismatch,
    ImageMismatch,
    ExistingPolicy,
    PolicyUncertain,
    ProfileAlreadyLoaded,
    ParserFailed(String),
    CleanupUncertain,
}

impl fmt::Display for BuilderPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootRequired => f.write_str("Linux ARM Root required for AppArmor policy proof"),
            Self::InvalidPins => f.write_str("fixed controller, image and job pins required"),
            Self::LeaseUnavailable => f.write_str("Rust or Python worker lease unavailable"),
            Self::ContextMismatch => {
                f.write_str("builder policy or context differs from pinned controller")
            }
            Self::BaseMismatch => f.write_str("local builder base image IDs changed"),
            Self::ImageMismatch => {
                f.write_str("source-bound builder image differs from outside ID")
            }
            Self::ExistingPolicy => f.write_str("one-use job AppArmor policy file already exists"),
            Self::PolicyUncertain => {
                f.write_str("job AppArmor policy write or readback is uncertain")
            }
            Self::ProfileAlreadyLoaded => f.write_str("job AppArmor profile was already loaded"),
            Self::ParserFailed(message) => write!(f, "fixed AppArmor parser failed: {message}"),
            Self::CleanupUncertain => f.write_str("job AppArmor profile removal is uncertain"),
        }
    }
}

impl std::error::Error for BuilderPolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderPolicyProof {
    job_id: String,
    profile_name: String,
    policy_sha256: String,
    image_id: String,
    policy_path: String,
}

impl BuilderPolicyProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-builder-policy-shadow.v1",
            "job_id":self.job_id,
            "profile_name":self.profile_name,
            "policy_sha256":self.policy_sha256,
            "policy_path":self.policy_path,
            "image_id":self.image_id,
            "profile_loaded_observed":true,
            "profile_removed_observed":true,
            "candidate_container_started":false,
            "execution_eligible":false,
        })
    }
}

fn parser_available() -> Result<(), BuilderPolicyError> {
    let descriptor = open(
        PARSER,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderPolicyError::ParserFailed("fixed executable unavailable".to_owned()))?;
    let stat = fstat(&descriptor)
        .map_err(|_| BuilderPolicyError::ParserFailed("fixed executable unavailable".to_owned()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o111 == 0
    {
        return Err(BuilderPolicyError::ParserFailed(
            "unsafe fixed executable".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn profile_is_loaded(name: &str) -> Result<bool, BuilderPolicyError> {
    let descriptor = open(
        PROFILES,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderPolicyError::CleanupUncertain)?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(MAX_PROFILES_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BuilderPolicyError::CleanupUncertain)?;
    if bytes.len() as u64 > MAX_PROFILES_BYTES {
        return Err(BuilderPolicyError::CleanupUncertain);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| BuilderPolicyError::CleanupUncertain)?;
    Ok(text.lines().any(|line| line == format!("{name} (enforce)")))
}

pub(crate) fn run_parser(action: &str, policy_path: &str) -> Result<(), BuilderPolicyError> {
    let mut command = Command::new(PARSER);
    command.args([action, policy_path]);
    command.env_clear();
    command.env("HOME", "/root");
    command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| BuilderPolicyError::ParserFailed("spawn failed".to_owned()))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < PARSER_WAIT => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BuilderPolicyError::ParserFailed(
                    "timeout or wait failure".to_owned(),
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| BuilderPolicyError::ParserFailed("wait failed".to_owned()))?;
    if output.stdout.len() > 4096 || output.stderr.len() > 4096 {
        return Err(BuilderPolicyError::ParserFailed(
            "output exceeded limit".to_owned(),
        ));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(BuilderPolicyError::ParserFailed(if message.is_empty() {
            format!("exit {:?}", output.status.code())
        } else {
            message
        }));
    }
    Ok(())
}

fn write_policy(job_id: &str, bytes: &[u8], expected: &str) -> Result<String, BuilderPolicyError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(BuilderPolicyError::PolicyUncertain);
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderPolicyError::ContextMismatch)?;
    let job = openat(
        &builds,
        job_id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderPolicyError::ContextMismatch)?;
    let stat = fstat(&job).map_err(|_| BuilderPolicyError::ContextMismatch)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o077 != 0
    {
        return Err(BuilderPolicyError::ContextMismatch);
    }
    let descriptor = match openat(
        &job,
        POLICY,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::EXIST) => return Err(BuilderPolicyError::ExistingPolicy),
        Err(_) => return Err(BuilderPolicyError::PolicyUncertain),
    };
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    file.sync_all()
        .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    fsync(&job).map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    let digest = read_policy_at(&job, expected)?;
    if digest != expected {
        return Err(BuilderPolicyError::PolicyUncertain);
    }
    Ok(format!("{BUILDS}/{job_id}/{POLICY}"))
}

fn read_policy_at(
    job: &std::os::fd::OwnedFd,
    expected: &str,
) -> Result<String, BuilderPolicyError> {
    let descriptor = openat(
        job,
        POLICY,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    let before = fstat(&descriptor).map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as usize > MAX_POLICY_BYTES
    {
        return Err(BuilderPolicyError::PolicyUncertain);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    let after = fstat(&file).map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    let visible = statat(job, POLICY, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    if bytes.len() as i64 != before.st_size
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_ctime != after.st_ctime
        || before.st_dev != visible.st_dev
        || before.st_ino != visible.st_ino
        || before.st_mode != visible.st_mode
    {
        return Err(BuilderPolicyError::PolicyUncertain);
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != expected {
        return Err(BuilderPolicyError::PolicyUncertain);
    }
    Ok(digest)
}

pub(crate) fn read_policy(job_id: &str, expected: &str) -> Result<String, BuilderPolicyError> {
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    let job = openat(
        &builds,
        job_id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderPolicyError::PolicyUncertain)?;
    read_policy_at(&job, expected)
}

/// Prove that the exact rendered policy loads and removes under both worker
/// locks. An uncertain parser outcome is never promoted to a usable profile.
pub fn prove_fixed_builder_policy_ineligible(
    controller_root: &Path,
    tree_digest: &str,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
    image_id: &str,
) -> Result<BuilderPolicyProof, BuilderPolicyError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderPolicyError::RootRequired);
    }
    if !hex(tree_digest, 64)
        || !hex(job_id, 16)
        || !hex(uv_id, 64)
        || !hex(rust_id, 64)
        || image_id
            .strip_prefix("sha256:")
            .is_none_or(|digest| !hex(digest, 64))
    {
        return Err(BuilderPolicyError::InvalidPins);
    }
    parser_available()?;
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| BuilderPolicyError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| BuilderPolicyError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| BuilderPolicyError::LeaseUnavailable)?;
    let context = inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderPolicyError::ContextMismatch)?;
    let plan = fixed_builder_image_plan(&context, job_id, uv_id, rust_id)
        .map_err(|_| BuilderPolicyError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&plan).map_err(|_| BuilderPolicyError::BaseMismatch)?;
    verify_existing_context(&plan).map_err(|_| BuilderPolicyError::ContextMismatch)?;
    if inspect_result(&plan).map_err(|_| BuilderPolicyError::ImageMismatch)? != image_id {
        return Err(BuilderPolicyError::ImageMismatch);
    }
    if profile_is_loaded(context.profile_name())? {
        return Err(BuilderPolicyError::ProfileAlreadyLoaded);
    }
    let policy_path = write_policy(job_id, context.policy_bytes(), context.policy_sha256())?;
    let loaded = run_parser("--replace", &policy_path);
    let present = profile_is_loaded(context.profile_name());
    // Even a failed parser may have loaded the exact profile before exiting.
    let remove = if present.as_ref().is_ok_and(|present| *present) {
        run_parser("--remove", &policy_path)
    } else {
        Ok(())
    };
    let absent = profile_is_loaded(context.profile_name());
    if present.is_err() || remove.is_err() || absent != Ok(false) {
        return Err(BuilderPolicyError::CleanupUncertain);
    }
    loaded?;
    if present != Ok(true) {
        return Err(BuilderPolicyError::ParserFailed(
            "profile not observed after load".to_owned(),
        ));
    }
    lease
        .verify(&journal.root)
        .map_err(|_| BuilderPolicyError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| BuilderPolicyError::LeaseUnavailable)?;
    read_policy(job_id, context.policy_sha256())?;
    inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderPolicyError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&plan).map_err(|_| BuilderPolicyError::BaseMismatch)?;
    if inspect_result(&plan).map_err(|_| BuilderPolicyError::ImageMismatch)? != image_id {
        return Err(BuilderPolicyError::ImageMismatch);
    }
    Ok(BuilderPolicyProof {
        job_id: job_id.to_owned(),
        profile_name: context.profile_name().to_owned(),
        policy_sha256: context.policy_sha256().to_owned(),
        image_id: image_id.to_owned(),
        policy_path,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_profile_line_does_not_accept_namespaced_or_complain_variants() {
        let name = "hol-gauntlet-build-0123456789abcdef";
        let sample = format!("{name}//&crun (enforce)\n{name} (complain)\n");
        assert!(!sample
            .lines()
            .any(|line| line == format!("{name} (enforce)")));
        let sample = format!("{name} (enforce)\n");
        assert!(sample
            .lines()
            .any(|line| line == format!("{name} (enforce)")));
    }
}
