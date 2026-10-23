//! Observe a product child while the fanotify-supplied pidfd remains held.
//! A sample is after close-write, not an atomic observation of the writing
//! instruction; executable identity and an argv hash cannot prove causality.

use crate::linux_process::parse_proc_stat;
use crate::staging_effect_events::EffectWriter;
use crate::staging_product_process::{alive, executable, read_at, same_executable, same_inode};
use rustix::fs::{fstat, open, openat, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

const PROC_LIMIT: u64 = 16 * 1024;

fn selected_status(raw: &[u8], pid: u32) -> Result<BTreeMap<&str, Vec<u64>>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid writer status UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(key, "Uid" | "Gid" | "NSpid" | "NoNewPrivs" | "Seccomp") {
            continue;
        }
        let values = value
            .split_ascii_whitespace()
            .map(|part| {
                part.parse::<u64>()
                    .map_err(|_| "invalid writer status number")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if fields.insert(key, values).is_some() {
            return Err("duplicate writer status field".to_owned());
        }
    }
    let ids = fields.get("NSpid").ok_or("missing writer namespace PID")?;
    if fields.get("Uid").map(Vec::as_slice) != Some(&[10004; 4])
        || fields.get("Gid").map(Vec::as_slice) != Some(&[10004; 4])
        || fields.get("NoNewPrivs").map(Vec::as_slice) != Some(&[1])
        || fields.get("Seccomp").map(Vec::as_slice) != Some(&[2])
        || !(2..=8).contains(&ids.len())
        || ids[0] != u64::from(pid)
        || ids.iter().any(|n| *n == 0 || *n > i32::MAX as u64)
    {
        return Err("writer is not a filtered UID/GID 10004 namespace process".to_owned());
    }
    Ok(fields)
}

fn observed_action(argv: &[u8]) -> Result<&'static str, String> {
    if argv.len() < 2 || argv.last() != Some(&0) || argv[0] == 0 {
        return Err("writer command identity unavailable".to_owned());
    }
    Ok(match argv.split(|byte| *byte == 0).nth(1) {
        Some(b"serve-managed") => "serve-managed",
        Some(b"supervise-managed") => "supervise-managed",
        Some(b"resident-client-stream") => "resident-client-stream",
        Some(b"resident-client") => "resident-client",
        _ => "other",
    })
}

pub(crate) fn observe_writer_image(
    writer: &EffectWriter,
    pidfd: &OwnedFd,
) -> Result<Value, String> {
    alive(pidfd)?;
    let pid = writer.pid;
    let proc = open(
        format!("/proc/{pid}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before =
        parse_proc_stat(&read_at(&proc, "stat", 4096)?, pid).ok_or("invalid writer stat")?;
    let expected_cgroup = format!("0::{}\n", writer.cgroup);
    if before.start_ticks != writer.start_ticks
        || !matches!(before.state, 'R' | 'S' | 'D')
        || before.parent_pid == 0
        || read_at(&proc, "cgroup", 4096)? != expected_cgroup.as_bytes()
    {
        return Err("writer differs from captured PID/start/cgroup".to_owned());
    }
    let status_raw = read_at(&proc, "status", PROC_LIMIT)?;
    let status = selected_status(&status_raw, pid)?;
    let mut namespaces = Vec::new();
    let mut namespace_values = BTreeMap::new();
    for name in ["mnt", "pid", "user"] {
        let relative = format!("ns/{name}");
        let fd = openat(
            &proc,
            &relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let stat = fstat(&fd).map_err(|e| e.to_string())?;
        namespace_values.insert(name, json!({"device":stat.st_dev,"inode":stat.st_ino}));
        namespaces.push((relative, fd, stat));
    }
    let argv = read_at(&proc, "cmdline", PROC_LIMIT)?;
    let action = observed_action(&argv)?;
    let (exe, exe_stat, executable_sha256) = executable(&proc)?;
    let final_exe = openat(
        &proc,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    for (name, held, stat) in namespaces {
        let visible = openat(&proc, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| e.to_string())?;
        if !same_inode(&stat, &fstat(&held).map_err(|e| e.to_string())?)
            || !same_inode(&stat, &fstat(&visible).map_err(|e| e.to_string())?)
        {
            return Err("writer namespace changed during sample".to_owned());
        }
    }
    let final_status = read_at(&proc, "status", PROC_LIMIT)?;
    let after =
        parse_proc_stat(&read_at(&proc, "stat", 4096)?, pid).ok_or("invalid final writer stat")?;
    if after.start_ticks != before.start_ticks
        || after.parent_pid != before.parent_pid
        || !matches!(after.state, 'R' | 'S' | 'D')
        || read_at(&proc, "cgroup", 4096)? != expected_cgroup.as_bytes()
        || selected_status(&final_status, pid)? != status
        || read_at(&proc, "cmdline", PROC_LIMIT)? != argv
        || !same_executable(&exe_stat, &fstat(&exe).map_err(|e| e.to_string())?)
        || !same_executable(&exe_stat, &fstat(&final_exe).map_err(|e| e.to_string())?)
    {
        return Err("writer process or image changed during sample".to_owned());
    }
    alive(pidfd)?;
    Ok(
        json!({"executable_sha256":executable_sha256,"argv_sha256":format!("{:x}", Sha256::digest(&argv)),
        "observed_action":action,"uid":10004,"gid":10004,
        "namespace_pid":status["NSpid"].last(),"parent_pid":before.parent_pid,
        "no_new_privileges":true,"seccomp_mode":2,"namespaces":namespace_values}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_status_requires_filtered_fixed_ids_and_retains_namespace_pid() {
        let status = "Uid:\t10004 10004 10004 10004\nGid:\t10004 10004 10004 10004\nNSpid:\t42 7\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        assert_eq!(
            selected_status(status.as_bytes(), 42).unwrap()["NSpid"],
            vec![42, 7]
        );
        for bad in [
            status.replace("42 7", "42"),
            status.replace("42 7", "42 0"),
            status.replace("10004", "10001"),
            status.replace("Seccomp:\t2", "Seccomp:\t0"),
            status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            format!("{status}NSpid:\t42 7\n"),
        ] {
            assert!(selected_status(bad.as_bytes(), 42).is_err());
        }
        assert!(selected_status(status.as_bytes(), 43).is_err());
    }

    #[test]
    fn command_classification_emits_only_fixed_actions() {
        assert_eq!(
            observed_action(b"/native\0serve-managed\0--private-argument\0").unwrap(),
            "serve-managed"
        );
        assert_eq!(
            observed_action(b"/native\0resident-client-stream\0--stdin\0").unwrap(),
            "resident-client-stream"
        );
        assert_eq!(observed_action(b"/bin/sh\0-c\0opaque\0").unwrap(), "other");
        assert!(observed_action(b"").is_err());
        assert!(observed_action(b"/native").is_err());
        assert!(observed_action(b"\0serve-managed\0").is_err());
    }
}
