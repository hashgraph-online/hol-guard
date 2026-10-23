//! Necessary cleanup check for a Rust job's systemd product-cell slice.
//! Absence alone is not a full terminal proof: the controller must already be
//! stopped and reaped so it cannot create another product cell after this read.

use crate::{launch_plan::rust_job_slice_name, ReservationError};
#[cfg(target_os = "linux")]
use rustix::fs::openat;
use rustix::fs::{fstat, open, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const SYSTEMCTL: &str = "/usr/bin/systemctl";
#[cfg(target_os = "linux")]
const STOP_WAIT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const ABSENCE_WAIT: Duration = Duration::from_secs(3);
#[cfg(target_os = "linux")]
const POLL: Duration = Duration::from_millis(20);

/// Only the fixed systemd slice stop and its observed cgroup absence.
/// Controller reaping, worker lease, report custody and verdict remain separate.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSliceStopObservation {
    pub slice_name: String,
    pub stop_invoked: bool,
    pub slice_absent: bool,
}

fn safe_parent(stat: &Stat, expected_uid: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == expected_uid
        && stat.st_mode & 0o022 == 0
}

fn same_directory(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn check_absent_at(
    parent: &OwnedFd,
    name: &str,
    expected_uid: u32,
) -> Result<(), ReservationError> {
    let before = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !safe_parent(&before, expected_uid) {
        return Err(ReservationError::CleanupUncertain);
    }
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => {}
        _ => return Err(ReservationError::CleanupUncertain),
    }
    let after = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&before, &after) {
        return Err(ReservationError::CleanupUncertain);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_present_at(
    parent: &OwnedFd,
    name: &str,
    expected_uid: u32,
) -> Result<(), ReservationError> {
    let before = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !safe_parent(&before, expected_uid) {
        return Err(ReservationError::CleanupUncertain);
    }
    let visible = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ReservationError::CleanupUncertain)?;
    if !safe_parent(&visible, expected_uid) {
        return Err(ReservationError::CleanupUncertain);
    }
    let held = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    let opened = fstat(&held).map_err(|_| ReservationError::CleanupUncertain)?;
    let after = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&visible, &opened) || !same_directory(&before, &after) {
        return Err(ReservationError::CleanupUncertain);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_safe_present_slice(name: &str) -> Result<(), ReservationError> {
    let parent = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    check_present_at(&parent, name, 0)?;
    let reopened = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    let held = fstat(&parent).map_err(|_| ReservationError::CleanupUncertain)?;
    let visible = fstat(&reopened).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&held, &visible) {
        return Err(ReservationError::CleanupUncertain);
    }
    check_present_at(&reopened, name, 0)
}

#[cfg(target_os = "linux")]
fn require_fixed_systemctl() -> Result<(), ReservationError> {
    let metadata =
        std::fs::symlink_metadata(SYSTEMCTL).map_err(|_| ReservationError::CleanupUncertain)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(ReservationError::CleanupUncertain);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stop_fixed_slice(name: &str) -> Result<(), ReservationError> {
    require_fixed_systemctl()?;
    let mut child = Command::new(SYSTEMCTL)
        .args(["--system", "stop", name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ReservationError::CleanupUncertain)?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) | Err(_) => return Err(ReservationError::CleanupUncertain),
            Ok(None) if started.elapsed() < STOP_WAIT => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let kill_started = Instant::now();
                while kill_started.elapsed() < ABSENCE_WAIT {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    thread::sleep(POLL);
                }
                return Err(ReservationError::CleanupUncertain);
            }
        }
    }
}

/// A terminal writer may call this only after the owned controller is stopped
/// and reaped. Any existing slice, including an empty one, blocks cleanup.
#[cfg(target_os = "linux")]
pub fn require_rust_job_slice_absent(job_id: &str) -> Result<(), ReservationError> {
    let name = rust_job_slice_name(job_id)?;
    if geteuid().as_raw() != 0 {
        return Err(ReservationError::RootRequired);
    }
    let parent = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    check_absent_at(&parent, &name, 0)?;
    let reopened = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    let held = fstat(&parent).map_err(|_| ReservationError::CleanupUncertain)?;
    let visible = fstat(&reopened).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&held, &visible) {
        return Err(ReservationError::CleanupUncertain);
    }
    check_absent_at(&reopened, &name, 0)
}

/// Stop only the exact, Root-observed systemd slice for this parsed job ID.
/// Callers must stop and reap the owned controller first; this primitive does
/// not prove that ordering or authorize a terminal cleanup receipt by itself.
#[cfg(target_os = "linux")]
pub fn stop_rust_job_slice(job_id: &str) -> Result<JobSliceStopObservation, ReservationError> {
    let name = rust_job_slice_name(job_id)?;
    if geteuid().as_raw() != 0 {
        return Err(ReservationError::RootRequired);
    }
    if require_rust_job_slice_absent(job_id).is_ok() {
        return Ok(JobSliceStopObservation {
            slice_name: name,
            stop_invoked: false,
            slice_absent: true,
        });
    }
    require_safe_present_slice(&name)?;
    stop_fixed_slice(&name)?;
    let started = Instant::now();
    loop {
        if require_rust_job_slice_absent(job_id).is_ok() {
            return Ok(JobSliceStopObservation {
                slice_name: name,
                stop_invoked: true,
                slice_absent: true,
            });
        }
        if started.elapsed() >= ABSENCE_WAIT {
            return Err(ReservationError::CleanupUncertain);
        }
        thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn existing_or_replaced_slice_blocks_terminal_cleanup() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let name = rust_job_slice_name("0123456789abcdef").unwrap();
        let uid = geteuid().as_raw();
        assert_eq!(check_absent_at(&descriptor, &name, uid), Ok(()));
        fs::create_dir(root.path().join(&name)).unwrap();
        assert_eq!(
            check_absent_at(&descriptor, &name, uid),
            Err(ReservationError::CleanupUncertain)
        );
        fs::remove_dir(root.path().join(&name)).unwrap();
        symlink(root.path(), root.path().join(&name)).unwrap();
        assert_eq!(
            check_absent_at(&descriptor, &name, uid),
            Err(ReservationError::CleanupUncertain)
        );
    }

    #[test]
    fn unsafe_parent_and_invalid_job_id_refuse() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            check_absent_at(
                &descriptor,
                "holgauntletrust0123456789abcdef.slice",
                geteuid().as_raw()
            ),
            Err(ReservationError::CleanupUncertain)
        );
        assert_eq!(
            rust_job_slice_name("../system"),
            Err(ReservationError::InvalidPins)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_present_slice_requires_a_directory_with_stable_identity() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let name = "holgauntletrust0123456789abcdef.slice";
        assert_eq!(
            check_present_at(&descriptor, name, geteuid().as_raw()),
            Err(ReservationError::CleanupUncertain)
        );
        fs::create_dir(root.path().join(name)).unwrap();
        fs::set_permissions(root.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            check_present_at(&descriptor, name, geteuid().as_raw()),
            Ok(())
        );
        fs::remove_dir(root.path().join(name)).unwrap();
        symlink(root.path(), root.path().join(name)).unwrap();
        assert_eq!(
            check_present_at(&descriptor, name, geteuid().as_raw()),
            Err(ReservationError::CleanupUncertain)
        );
    }
}
