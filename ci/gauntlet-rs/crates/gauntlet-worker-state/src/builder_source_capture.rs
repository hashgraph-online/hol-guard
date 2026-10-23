//! Inert one-use capture of a guest inbox archive into a private build slot.
//! This never launches Podman or admits the captured bytes as a candidate.

use crate::{hex, open_root_owned_public_directory};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat,
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

const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const HOME: &str = "/home";
const GUEST: &str = "construct.guest";
const BUILDS: &str = "/var/lib/hol-gauntlet/builds";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderSourceCaptureError {
    RootRequired,
    InvalidPins,
    UnsafeParent,
    UnsafeSource,
    SourceChanged,
    DigestMismatch,
    ExistingBuild,
    CaptureUncertain,
}

impl fmt::Display for BuilderSourceCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for fixed build source capture",
            Self::InvalidPins => "fixed job and archive SHA-256 required",
            Self::UnsafeParent => "fixed guest inbox or Root build directory is unsafe",
            Self::UnsafeSource => "guest source is not a bounded, single-link owner-only file",
            Self::SourceChanged => "guest source changed during capture",
            Self::DigestMismatch => "guest source differs from outside SHA-256 pin",
            Self::ExistingBuild => "one-use build directory already exists",
            Self::CaptureUncertain => {
                "build source write is uncertain; inspect exact slot before retry"
            }
        })
    }
}

impl std::error::Error for BuilderSourceCaptureError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderSourceCaptureProof {
    job_id: String,
    archive_sha256: String,
    build_path: String,
    bytes: u64,
}

impl BuilderSourceCaptureProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-builder-source-capture-shadow.v1",
            "job_id":self.job_id,
            "source_archive_sha256":self.archive_sha256,
            "build_path":self.build_path,
            "bytes":self.bytes,
            "one_use_build_slot":true,
            "builder_executed":false,
            "execution_eligible":false,
        })
    }
}

fn same_inode(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_nlink == second.st_nlink
        && first.st_size == second.st_size
        && first.st_mtime == second.st_mtime
        && first.st_mtime_nsec == second.st_mtime_nsec
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn source_bytes(
    inbox: &OwnedFd,
    name: &str,
    owner: u32,
    expected: &str,
) -> Result<Vec<u8>, BuilderSourceCaptureError> {
    let descriptor = openat(
        inbox,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderSourceCaptureError::UnsafeSource)?;
    let before = fstat(&descriptor).map_err(|_| BuilderSourceCaptureError::UnsafeSource)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_SOURCE_BYTES
    {
        return Err(BuilderSourceCaptureError::UnsafeSource);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    Read::by_ref(&mut file)
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BuilderSourceCaptureError::SourceChanged)?;
    let after = fstat(&file).map_err(|_| BuilderSourceCaptureError::SourceChanged)?;
    let visible = statat(inbox, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderSourceCaptureError::SourceChanged)?;
    if bytes.len() as i64 != before.st_size
        || !same_inode(&before, &after)
        || !same_inode(&before, &visible)
    {
        return Err(BuilderSourceCaptureError::SourceChanged);
    }
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err(BuilderSourceCaptureError::DigestMismatch);
    }
    Ok(bytes)
}

fn capture_at(
    inbox: &OwnedFd,
    builds: &OwnedFd,
    job_id: &str,
    expected_sha256: &str,
    source_owner: u32,
    build_owner: u32,
    build_base: &str,
) -> Result<BuilderSourceCaptureProof, BuilderSourceCaptureError> {
    if !hex(job_id, 16) || !hex(expected_sha256, 64) {
        return Err(BuilderSourceCaptureError::InvalidPins);
    }
    let inbox_stat = fstat(inbox).map_err(|_| BuilderSourceCaptureError::UnsafeParent)?;
    let builds_stat = fstat(builds).map_err(|_| BuilderSourceCaptureError::UnsafeParent)?;
    if FileType::from_raw_mode(inbox_stat.st_mode) != FileType::Directory
        || inbox_stat.st_uid != source_owner
        || inbox_stat.st_mode & 0o022 != 0
        || FileType::from_raw_mode(builds_stat.st_mode) != FileType::Directory
        || builds_stat.st_uid != build_owner
        || builds_stat.st_mode & 0o077 != 0
    {
        return Err(BuilderSourceCaptureError::UnsafeParent);
    }
    let name = format!("hol-gauntlet-source-{job_id}.tar.gz");
    let bytes = source_bytes(inbox, &name, source_owner, expected_sha256)?;
    match mkdirat(builds, job_id, Mode::from_bits_truncate(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(BuilderSourceCaptureError::ExistingBuild),
        Err(_) => return Err(BuilderSourceCaptureError::CaptureUncertain),
    }
    let result = (|| {
        fsync(builds).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        let slot = openat(
            builds,
            job_id,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        let slot_stat = fstat(&slot).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        if slot_stat.st_uid != build_owner || slot_stat.st_mode & 0o777 != 0o700 {
            return Err(BuilderSourceCaptureError::CaptureUncertain);
        }
        let descriptor = openat(
            &slot,
            "source.tar.gz",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        let mut output = File::from(descriptor);
        output
            .write_all(&bytes)
            .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        output
            .sync_all()
            .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        fchmod(&output, Mode::from_bits_truncate(0o444))
            .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        output
            .sync_all()
            .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        let observed = source_bytes_readback(&slot, expected_sha256, build_owner, bytes.len())?;
        if observed != bytes.len() as u64 {
            return Err(BuilderSourceCaptureError::CaptureUncertain);
        }
        fsync(&slot).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        fsync(builds).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        Ok(BuilderSourceCaptureProof {
            job_id: job_id.to_owned(),
            archive_sha256: expected_sha256.to_owned(),
            build_path: format!("{build_base}/{job_id}/source.tar.gz"),
            bytes: observed,
        })
    })();
    // An error after exclusive mkdir is never rolled back or retried here.
    result
}

fn source_bytes_readback(
    slot: &OwnedFd,
    expected_sha256: &str,
    owner: u32,
    expected_len: usize,
) -> Result<u64, BuilderSourceCaptureError> {
    let descriptor = openat(
        slot,
        "source.tar.gz",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
    let before = fstat(&descriptor).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_mode & 0o777 != 0o444
        || before.st_nlink != 1
        || before.st_size != expected_len as i64
    {
        return Err(BuilderSourceCaptureError::CaptureUncertain);
    }
    let mut file = File::from(descriptor);
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_SOURCE_BYTES {
            return Err(BuilderSourceCaptureError::CaptureUncertain);
        }
        hasher.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
    let visible = statat(slot, "source.tar.gz", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderSourceCaptureError::CaptureUncertain)?;
    if count != expected_len as u64
        || !same_inode(&before, &after)
        || !same_inode(&before, &visible)
        || format!("{:x}", hasher.finalize()) != expected_sha256
    {
        return Err(BuilderSourceCaptureError::CaptureUncertain);
    }
    Ok(count)
}

/// Capture a previously transferred archive in the fixed Root build tree.
/// The caller must independently authenticate the outside digest and hold the
/// appropriate worker lease before this can become an execution path.
pub fn capture_fixed_guest_source_archive(
    job_id: &str,
    expected_sha256: &str,
) -> Result<BuilderSourceCaptureProof, BuilderSourceCaptureError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderSourceCaptureError::RootRequired);
    }
    if !hex(job_id, 16) || !hex(expected_sha256, 64) {
        return Err(BuilderSourceCaptureError::InvalidPins);
    }
    let home = open_root_owned_public_directory(Path::new(HOME))
        .map_err(|_| BuilderSourceCaptureError::UnsafeParent)?;
    let inbox = openat(
        &home,
        GUEST,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderSourceCaptureError::UnsafeParent)?;
    let owner = fstat(&inbox)
        .map_err(|_| BuilderSourceCaptureError::UnsafeParent)?
        .st_uid;
    if owner == 0 {
        return Err(BuilderSourceCaptureError::UnsafeParent);
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| BuilderSourceCaptureError::UnsafeParent)?;
    capture_at(&inbox, &builds, job_id, expected_sha256, owner, 0, BUILDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::open;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_capture_is_read_back_and_replay_refuses() {
        let temp = tempfile::tempdir().unwrap();
        let inbox_path = temp.path().join("inbox");
        let builds_path = temp.path().join("builds");
        fs::create_dir(&inbox_path).unwrap();
        fs::create_dir(&builds_path).unwrap();
        fs::set_permissions(&inbox_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&builds_path, fs::Permissions::from_mode(0o700)).unwrap();
        let job = "0123456789abcdef";
        let bytes = vec![0x5a; 2 * 1024 * 1024];
        let digest = format!("{:x}", Sha256::digest(&bytes));
        fs::write(
            inbox_path.join(format!("hol-gauntlet-source-{job}.tar.gz")),
            &bytes,
        )
        .unwrap();
        let inbox_file = inbox_path.join(format!("hol-gauntlet-source-{job}.tar.gz"));
        fs::set_permissions(&inbox_file, fs::Permissions::from_mode(0o600)).unwrap();
        let inbox = open(
            &inbox_path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let builds = open(
            &builds_path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let owner = geteuid().as_raw();
        let base = builds_path.to_str().unwrap();
        let proof = capture_at(&inbox, &builds, job, &digest, owner, owner, base).unwrap();
        assert_eq!(proof.to_json()["bytes"], bytes.len() as u64);
        let target = builds_path.join(job).join("source.tar.gz");
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            capture_at(&inbox, &builds, job, &digest, owner, owner, base),
            Err(BuilderSourceCaptureError::ExistingBuild)
        );
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }

    #[test]
    fn wrong_digest_and_symlink_refuse_before_build_slot() {
        let temp = tempfile::tempdir().unwrap();
        let inbox_path = temp.path().join("inbox");
        let builds_path = temp.path().join("builds");
        fs::create_dir(&inbox_path).unwrap();
        fs::create_dir(&builds_path).unwrap();
        fs::set_permissions(&inbox_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&builds_path, fs::Permissions::from_mode(0o700)).unwrap();
        let job = "fedcba9876543210";
        let file = inbox_path.join(format!("hol-gauntlet-source-{job}.tar.gz"));
        fs::write(&file, b"source").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let inbox = open(
            &inbox_path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let builds = open(
            &builds_path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let owner = geteuid().as_raw();
        let base = builds_path.to_str().unwrap();
        assert_eq!(
            capture_at(&inbox, &builds, job, &"0".repeat(64), owner, owner, base),
            Err(BuilderSourceCaptureError::DigestMismatch)
        );
        assert!(!builds_path.join(job).exists());
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/dev/null", &file).unwrap();
        assert_eq!(
            capture_at(&inbox, &builds, job, &"0".repeat(64), owner, owner, base),
            Err(BuilderSourceCaptureError::UnsafeSource)
        );
        assert!(!builds_path.join(job).exists());
    }
}
