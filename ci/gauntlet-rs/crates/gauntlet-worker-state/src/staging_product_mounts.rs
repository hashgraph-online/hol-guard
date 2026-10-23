//! Outside-kernel observations of the three fixed deterministic task mounts.
//! The process root is held by the caller while its pidfd and namespaces are
//! checked. No process is entered and no candidate-supplied path is followed.

use crate::open_root_owned_public_directory;
use rustix::fs::{fstat, openat2, FileType, Mode, OFlags, ResolveFlags, Stat};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::Path;

fn same_directory(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
}

fn mapped_directory(physical: &Stat, view: &Stat, mode: u32) -> bool {
    FileType::from_raw_mode(physical.st_mode) == FileType::Directory
        && FileType::from_raw_mode(view.st_mode) == FileType::Directory
        && physical.st_uid == 10001
        && physical.st_gid == 10001
        && physical.st_mode & 0o7777 == mode
        && view.st_uid == 10004
        && view.st_gid == 10004
        && physical.st_dev == view.st_dev
        && physical.st_ino == view.st_ino
        && physical.st_mode == view.st_mode
}

fn open_directory(root: &OwnedFd, path: &str) -> Result<OwnedFd, String> {
    openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("fixed task directory unavailable: {error}"))
}

fn mount_id(mountinfo: &str, destination: &str) -> Result<u64, String> {
    let mut matched = None;
    for line in mountinfo.lines() {
        let (left, _) = line.split_once(" - ").ok_or("invalid kernel mountinfo")?;
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        if fields.len() < 6 {
            return Err("invalid kernel mountinfo fields".to_owned());
        }
        if fields[4] != destination {
            continue;
        }
        let options: Vec<_> = fields[5].split(',').collect();
        let id = fields[0]
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .ok_or("invalid task mount ID")?;
        if matched.is_some()
            || !["rw", "nosuid", "nodev"]
                .iter()
                .all(|o| options.contains(o))
            || options.contains(&"ro")
        {
            return Err("task mount lacks a unique writable nosuid/nodev view".to_owned());
        }
        matched = Some(id);
    }
    matched.ok_or_else(|| "fixed task mount absent from product namespace".to_owned())
}

pub(crate) fn observe_task_mounts(
    role_path: &str,
    product_root: &OwnedFd,
    mountinfo: &str,
) -> Result<Value, String> {
    let tasks_path = format!("{role_path}/tasks");
    let tasks = open_root_owned_public_directory(Path::new(&tasks_path))
        .map_err(|error| error.to_string())?;
    let tasks_before = fstat(&tasks).map_err(|error| error.to_string())?;
    if tasks_before.st_mode & 0o7777 != 0o700 {
        return Err("task parent is not Root-private".to_owned());
    }
    let mut rows = Vec::new();
    for name in ["checkout", "remote", "home"] {
        let source = format!("{tasks_path}/{name}");
        let destination = if name == "checkout" {
            "/runtime/home/project".to_owned()
        } else {
            source.clone()
        };
        let physical_fd = open_directory(&tasks, name)?;
        let physical = fstat(&physical_fd).map_err(|error| error.to_string())?;
        let view_fd = open_directory(product_root, &destination[1..])?;
        let view = fstat(&view_fd).map_err(|error| error.to_string())?;
        let expected_mode = if name == "checkout" { 0o755 } else { 0o700 };
        if !mapped_directory(&physical, &view, expected_mode) {
            return Err("kernel task mapping differs from physical UID/GID/inode/mode".to_owned());
        }
        let id = mount_id(mountinfo, &destination)?;
        let reopened = fstat(open_directory(&tasks, name)?).map_err(|e| e.to_string())?;
        let remapped =
            fstat(open_directory(product_root, &destination[1..])?).map_err(|e| e.to_string())?;
        if !same_directory(&physical, &reopened) || !same_directory(&view, &remapped) {
            return Err("task mount changed during kernel observation".to_owned());
        }
        rows.push(json!({
            "source":source,"destination":destination,"mount_id":id,
            "device":physical.st_dev,"inode":physical.st_ino,"mode":physical.st_mode & 0o7777,
            "physical_uid":physical.st_uid,"physical_gid":physical.st_gid,
            "product_uid":view.st_uid,"product_gid":view.st_gid,
        }));
    }
    let reopened = open_root_owned_public_directory(Path::new(&tasks_path))
        .map_err(|error| error.to_string())?;
    if !same_directory(&tasks_before, &fstat(&reopened).map_err(|e| e.to_string())?) {
        return Err("task parent changed during kernel observation".to_owned());
    }
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_mount_requires_exact_destination_and_floor_without_stacked_mounts() {
        let row = "41 1 8:1 /task /runtime/home/project rw,nosuid,nodev - ext4 /dev/vda rw\n";
        assert_eq!(mount_id(row, "/runtime/home/project"), Ok(41));
        assert!(mount_id(row, "/runtime/home/other").is_err());
        assert!(mount_id(&row.repeat(2), "/runtime/home/project").is_err());
        for replacement in [
            "ro,nosuid,nodev",
            "rw,nodev",
            "rw,nosuid",
            "rw,ro,nosuid,nodev",
        ] {
            assert!(mount_id(
                &row.replace("rw,nosuid,nodev", replacement),
                "/runtime/home/project"
            )
            .is_err());
        }
    }

    #[test]
    fn mapping_rejects_changed_inode_mode_or_either_owner() {
        let root = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let mut physical = fstat(fd).unwrap();
        physical.st_uid = 10001;
        physical.st_gid = 10001;
        physical.st_mode = (physical.st_mode & !0o7777) | 0o700;
        let mut view = physical;
        view.st_uid = 10004;
        view.st_gid = 10004;
        assert!(mapped_directory(&physical, &view, 0o700));
        assert!(!mapped_directory(&physical, &view, 0o755));
        let mut changed = view;
        changed.st_ino += 1;
        assert!(!mapped_directory(&physical, &changed, 0o700));
        changed = view;
        changed.st_gid = 10001;
        assert!(!mapped_directory(&physical, &changed, 0o700));
        changed = view;
        changed.st_mode |= 0o020;
        assert!(!mapped_directory(&physical, &changed, 0o700));
        physical.st_mode |= 0o055;
        view.st_mode |= 0o055;
        assert!(mapped_directory(&physical, &view, 0o755));
        physical.st_uid = 0;
        assert!(!mapped_directory(&physical, &view, 0o755));
    }
}
