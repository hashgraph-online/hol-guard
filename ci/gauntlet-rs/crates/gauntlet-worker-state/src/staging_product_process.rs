//! A pidfd-held, outside-kernel sample of the fixed product namespace init.
//! Neither a producer JSON identity nor an effect-event cgroup is an input.

use crate::linux_process::parse_proc_stat;
use crate::staging_product_mounts::observe_task_mounts;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, open, openat, Mode, OFlags, Stat};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const PROC_LIMIT: u64 = 16 * 1024;
const MOUNT_LIMIT: u64 = 1024 * 1024;
const EXE_LIMIT: u64 = 64 * 1024 * 1024;

pub(crate) fn read_at(directory: &OwnedFd, name: &str, limit: u64) -> Result<Vec<u8>, String> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("product {name} unavailable: {e}"))?;
    let mut raw = Vec::new();
    File::from(fd)
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > limit {
        return Err(format!("product {name} exceeds fixed bound"));
    }
    Ok(raw)
}

pub(crate) fn alive(pidfd: &OwnedFd) -> Result<(), String> {
    let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
    if poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|e| e.to_string())?
        != 0
    {
        return Err("product pidfd is no longer live".to_owned());
    }
    Ok(())
}

fn selected_status(raw: &[u8], pid: u32) -> Result<BTreeMap<&str, Vec<u64>>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid product status UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(key, "Uid" | "Gid" | "NSpid" | "NoNewPrivs" | "Seccomp") {
            continue;
        }
        let values: Vec<u64> = value
            .split_ascii_whitespace()
            .map(|part| {
                part.parse::<u64>()
                    .map_err(|_| "invalid product status number")
            })
            .collect::<Result<_, _>>()?;
        if fields.insert(key, values).is_some() {
            return Err("duplicate product status field".to_owned());
        }
    }
    let ids = fields.get("NSpid").ok_or("missing namespace PID")?;
    if fields.get("Uid").map(Vec::as_slice) != Some(&[10004; 4])
        || fields.get("Gid").map(Vec::as_slice) != Some(&[10004; 4])
        || fields.get("NoNewPrivs").map(Vec::as_slice) != Some(&[1])
        || fields.get("Seccomp").map(Vec::as_slice) != Some(&[2])
        || !(2..=8).contains(&ids.len())
        || ids[0] != u64::from(pid)
        || ids.last() != Some(&1)
        || ids.contains(&0)
    {
        return Err("process is not the filtered UID/GID 10004 namespace init".to_owned());
    }
    Ok(fields)
}

pub(crate) fn same_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
}

pub(crate) fn same_executable(a: &Stat, b: &Stat) -> bool {
    same_inode(a, b)
        && a.st_size == b.st_size
        && a.st_nlink == b.st_nlink
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

pub(crate) fn executable(proc: &OwnedFd) -> Result<(OwnedFd, Stat, String), String> {
    // This is the kernel's exe magic link under our held /proc/PID directory.
    let fd = openat(proc, "exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_size <= 0
        || before.st_size as u64 > EXE_LIMIT
    {
        return Err("product executable outside fixed byte bound".to_owned());
    }
    let mut file = File::from(fd);
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length += count as u64;
        if length > EXE_LIMIT {
            return Err("product executable grew beyond bound".to_owned());
        }
        hasher.update(&chunk[..count]);
    }
    if length != before.st_size as u64
        || !same_executable(&before, &fstat(&file).map_err(|e| e.to_string())?)
    {
        return Err("product executable changed while hashing".to_owned());
    }
    Ok((file.into(), before, format!("{:x}", hasher.finalize())))
}

pub(crate) fn observe_product_init(
    pid: u32,
    cgroup: &str,
    role_path: &str,
) -> Result<Value, String> {
    let raw_pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or("invalid product PID")?;
    let pidfd = pidfd_open(raw_pid, PidfdFlags::empty()).map_err(|e| e.to_string())?;
    alive(&pidfd)?;
    let proc = open(
        format!("/proc/{pid}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before =
        parse_proc_stat(&read_at(&proc, "stat", 4096)?, pid).ok_or("invalid product proc stat")?;
    if !matches!(before.state, 'R' | 'S' | 'D') {
        return Err("product process is not live".to_owned());
    }
    let expected_cgroup = format!("0::{cgroup}\n");
    if read_at(&proc, "cgroup", 4096)? != expected_cgroup.as_bytes() {
        return Err("product cgroup differs from independently scanned service".to_owned());
    }
    let status_raw = read_at(&proc, "status", PROC_LIMIT)?;
    let status = selected_status(&status_raw, pid)?;
    let mut namespaces = Vec::new();
    let mut namespace_values = BTreeMap::new();
    for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup", "user"] {
        let relative = format!("ns/{name}");
        let fd = openat(
            &proc,
            &relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let stat = fstat(&fd).map_err(|e| e.to_string())?;
        let own = open(
            format!("/proc/self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let same = same_inode(&stat, &fstat(&own).map_err(|e| e.to_string())?);
        if same != (name == "user") {
            return Err(
                "product namespaces lack fixed isolation or initial user namespace".to_owned(),
            );
        }
        namespace_values.insert(name, json!({"device":stat.st_dev,"inode":stat.st_ino}));
        namespaces.push((relative, fd, stat));
    }
    // Follow exactly the kernel root link once, then refuse symlinks beneath it.
    let root = openat(
        &proc,
        "root",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let root_stat = fstat(&root).map_err(|e| e.to_string())?;
    let mounts = read_at(&proc, "mountinfo", MOUNT_LIMIT)?;
    let mounts_text = std::str::from_utf8(&mounts).map_err(|_| "invalid mountinfo UTF-8")?;
    let tasks = observe_task_mounts(role_path, &root, mounts_text)?;
    let argv = read_at(&proc, "cmdline", PROC_LIMIT)?;
    let (exe, exe_stat, executable_sha256) = executable(&proc)?;
    let final_exe = openat(
        &proc,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let final_root = openat(
        &proc,
        "root",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    for (name, held, stat) in namespaces {
        let visible = openat(&proc, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| e.to_string())?;
        if !same_inode(&stat, &fstat(&held).map_err(|e| e.to_string())?)
            || !same_inode(&stat, &fstat(&visible).map_err(|e| e.to_string())?)
        {
            return Err("product namespace changed during sample".to_owned());
        }
    }
    let final_status = read_at(&proc, "status", PROC_LIMIT)?;
    let after = parse_proc_stat(&read_at(&proc, "stat", 4096)?, pid)
        .ok_or("invalid final product proc stat")?;
    if after.start_ticks != before.start_ticks
        || !matches!(after.state, 'R' | 'S' | 'D')
        || read_at(&proc, "cgroup", 4096)? != expected_cgroup.as_bytes()
        || selected_status(&final_status, pid)? != status
        || read_at(&proc, "mountinfo", MOUNT_LIMIT)? != mounts
        || read_at(&proc, "cmdline", PROC_LIMIT)? != argv
        || !same_inode(&root_stat, &fstat(&final_root).map_err(|e| e.to_string())?)
        || !same_executable(&exe_stat, &fstat(&exe).map_err(|e| e.to_string())?)
        || !same_executable(&exe_stat, &fstat(&final_exe).map_err(|e| e.to_string())?)
    {
        return Err("product process or mount identity changed during sample".to_owned());
    }
    alive(&pidfd)?;
    Ok(json!({
        "pid":pid,"start_ticks":before.start_ticks,"cgroup":cgroup,
        "uid":10004,"gid":10004,"namespace_pid":1,"no_new_privileges":true,"seccomp_mode":2,
        "namespaces":namespace_values,"executable_sha256":executable_sha256,
        "argv_sha256":format!("{:x}", Sha256::digest(&argv)),
        "mountinfo_sha256":format!("{:x}", Sha256::digest(&mounts)),
        "task_mounts":tasks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_filtered_private_namespace_init_matches() {
        let status = b"Name:\tinit\nUid:\t10004 10004 10004 10004\nGid:\t10004 10004 10004 10004\nNSpid:\t42 1\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        assert!(selected_status(status, 42).is_ok());
        assert!(selected_status(status, 43).is_err());
        let text = std::str::from_utf8(status).unwrap();
        for changed in [
            text.replace("42 1", "42 2"),
            text.replace("42 1", "42"),
            text.replace("10004", "0"),
            text.replace("Seccomp:\t2", "Seccomp:\t0"),
            text.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            format!("{text}NSpid:\t42 1\n"),
        ] {
            assert!(selected_status(changed.as_bytes(), 42).is_err());
        }
    }
}
