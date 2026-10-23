//! One-use Root-owned materialization of a base-ID-pinned builder context.
//! It holds both worker leases, but does not launch Podman or candidate code.

use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{
    fixed_builder_image_plan, inspect_fixed_builder_base_images, BuilderImagePlan,
};
use crate::{hex, open_root_owned_public_directory, RunReservationJournal};
use rustix::fs::{
    fchmod, flock, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, FlockOperation, Mode,
    OFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) const RUST_STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";
const PYTHON_ROOT: &str = "/opt/hol-gauntlet";
const PYTHON_LOCK: &str = "worker.lock";
const BUILDS: &str = "/var/lib/hol-gauntlet/builds";
const CONTEXT: &str = "builder-image-context";
const FILES: [&str; 3] = [
    "Builder.Dockerfile",
    "builder_entry.py",
    "build_artifact.py",
];
const MAX_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderImageContextError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ContextUnavailable,
    ExistingContext,
    WriteUncertain,
    PostWriteMismatch,
}

impl fmt::Display for BuilderImageContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for one-use builder image context",
            Self::InvalidPins => "outside controller, job and base image pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable or unsafe",
            Self::ContextUnavailable => {
                "Root-owned build slot, controller or base image unavailable"
            }
            Self::ExistingContext => "one-use builder image context already exists",
            Self::WriteUncertain => {
                "builder image context write is uncertain; inspect before retry"
            }
            Self::PostWriteMismatch => "builder context, base images or leases changed after write",
        })
    }
}

impl std::error::Error for BuilderImageContextError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderImageContextProof {
    plan: BuilderImagePlan,
    path: String,
    file_sha256: Vec<String>,
}

impl BuilderImageContextProof {
    pub fn to_json(&self) -> Value {
        let mut value = self.plan.to_json();
        value["schema"] = json!("hol-gauntlet-builder-image-context-shadow.v1");
        value["base_images_verified"] = json!(true);
        value["context_path"] = json!(self.path);
        value["context_file_sha256"] = json!({
            FILES[0]:self.file_sha256[0],
            FILES[1]:self.file_sha256[1],
            FILES[2]:self.file_sha256[2],
        });
        value["one_use_context_written"] = json!(true);
        value
    }
}

fn same_inode(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_mode == second.st_mode
        && first.st_nlink == second.st_nlink
        && first.st_size == second.st_size
        && first.st_mtime == second.st_mtime
        && first.st_mtime_nsec == second.st_mtime_nsec
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn root_private_dir(descriptor: &OwnedFd) -> bool {
    fstat(descriptor).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == 0
            && stat.st_mode & 0o077 == 0
    })
}

pub(crate) struct PythonWorkerLease {
    parent: OwnedFd,
    descriptor: OwnedFd,
}

pub(crate) fn python_worker_lock() -> Result<PythonWorkerLease, BuilderImageContextError> {
    let parent = open_root_owned_public_directory(Path::new(PYTHON_ROOT))
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let descriptor = openat(
        &parent,
        PYTHON_LOCK,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let before = fstat(&descriptor).map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
    {
        return Err(BuilderImageContextError::LeaseUnavailable);
    }
    flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let visible = statat(&parent, PYTHON_LOCK, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    if !same_inode(&before, &visible) {
        return Err(BuilderImageContextError::LeaseUnavailable);
    }
    Ok(PythonWorkerLease { parent, descriptor })
}

pub(crate) fn verify_python_lock(
    lease: &PythonWorkerLease,
) -> Result<(), BuilderImageContextError> {
    let held = fstat(&lease.descriptor).map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let visible = statat(&lease.parent, PYTHON_LOCK, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    if !same_inode(&held, &visible) {
        return Err(BuilderImageContextError::LeaseUnavailable);
    }
    Ok(())
}

fn write_one(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<String, BuilderImageContextError> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(BuilderImageContextError::WriteUncertain);
    }
    let descriptor = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    let mut output = File::from(descriptor);
    output
        .write_all(bytes)
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    output
        .sync_all()
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    fchmod(&output, Mode::from_bits_truncate(0o444))
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    output
        .sync_all()
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    read_one(directory, name, bytes)
}

fn read_one(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<String, BuilderImageContextError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    let before = fstat(&descriptor).map_err(|_| BuilderImageContextError::WriteUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o777 != 0o444
        || before.st_nlink != 1
        || before.st_size != bytes.len() as i64
    {
        return Err(BuilderImageContextError::WriteUncertain);
    }
    let mut readback = Vec::with_capacity(bytes.len());
    let mut reader = File::from(descriptor);
    Read::by_ref(&mut reader)
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    let after = fstat(&reader).map_err(|_| BuilderImageContextError::WriteUncertain)?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    if !same_inode(&before, &after) || !same_inode(&before, &visible) || readback != bytes {
        return Err(BuilderImageContextError::WriteUncertain);
    }
    Ok(format!("{:x}", Sha256::digest(&readback)))
}

pub(crate) fn verify_existing_context(
    plan: &BuilderImagePlan,
) -> Result<(), BuilderImageContextError> {
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    if !root_private_dir(&builds) {
        return Err(BuilderImageContextError::ContextUnavailable);
    }
    let job = openat(
        &builds,
        plan.job_id.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    if !root_private_dir(&job) {
        return Err(BuilderImageContextError::ContextUnavailable);
    }
    let directory = openat(
        &job,
        CONTEXT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    if !root_private_dir(&directory) {
        return Err(BuilderImageContextError::ContextUnavailable);
    }
    read_one(&directory, FILES[0], plan.dockerfile_bytes())?;
    read_one(&directory, FILES[1], plan.entry_bytes())?;
    read_one(&directory, FILES[2], plan.artifact_bytes())?;
    Ok(())
}

fn materialize_at(
    builds: &OwnedFd,
    plan: BuilderImagePlan,
) -> Result<BuilderImageContextProof, BuilderImageContextError> {
    if !root_private_dir(builds) {
        return Err(BuilderImageContextError::ContextUnavailable);
    }
    let job = openat(
        builds,
        plan.job_id.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    if !root_private_dir(&job) {
        return Err(BuilderImageContextError::ContextUnavailable);
    }
    match mkdirat(&job, CONTEXT, Mode::from_bits_truncate(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(BuilderImageContextError::ExistingContext),
        Err(_) => return Err(BuilderImageContextError::WriteUncertain),
    }
    fsync(&job).map_err(|_| BuilderImageContextError::WriteUncertain)?;
    let directory = openat(
        &job,
        CONTEXT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderImageContextError::WriteUncertain)?;
    if !root_private_dir(&directory) {
        return Err(BuilderImageContextError::WriteUncertain);
    }
    let digests = vec![
        write_one(&directory, FILES[0], plan.dockerfile_bytes())?,
        write_one(&directory, FILES[1], plan.entry_bytes())?,
        write_one(&directory, FILES[2], plan.artifact_bytes())?,
    ];
    fsync(&directory).map_err(|_| BuilderImageContextError::WriteUncertain)?;
    fsync(&job).map_err(|_| BuilderImageContextError::WriteUncertain)?;
    Ok(BuilderImageContextProof {
        path: format!("{BUILDS}/{}/{CONTEXT}", plan.job_id),
        plan,
        file_sha256: digests,
    })
}

/// One-use diagnostic. A failure after `mkdirat` leaves the directory in
/// place for inspection; neither this function nor the caller may replay it.
pub fn materialize_fixed_builder_image_context(
    controller_root: &Path,
    tree_digest: &str,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
) -> Result<BuilderImageContextProof, BuilderImageContextError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderImageContextError::RootRequired);
    }
    if !hex(tree_digest, 64) || !hex(job_id, 16) || !hex(uv_id, 64) || !hex(rust_id, 64) {
        return Err(BuilderImageContextError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| BuilderImageContextError::LeaseUnavailable)?;
    let python_lock = python_worker_lock()?;
    let context = inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    let plan = fixed_builder_image_plan(&context, job_id, uv_id, rust_id)
        .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    inspect_fixed_builder_base_images(&plan)
        .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderImageContextError::ContextUnavailable)?;
    let proof = materialize_at(&builds, plan)?;
    lease
        .verify(&journal.root)
        .map_err(|_| BuilderImageContextError::PostWriteMismatch)?;
    verify_python_lock(&python_lock).map_err(|_| BuilderImageContextError::PostWriteMismatch)?;
    inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| BuilderImageContextError::PostWriteMismatch)?;
    inspect_fixed_builder_base_images(&proof.plan)
        .map_err(|_| BuilderImageContextError::PostWriteMismatch)?;
    Ok(proof)
}
