//! Kernel-only, read-only samples of Podman container scopes while a staging
//! control runs. These tuples can later be compared with a signed record's
//! container claim; scope presence alone cannot prove SDK or Guard behavior.

use crate::linux_process::{observe_process, parse_proc_stat};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

const MACHINE_SLICE: &str = "/sys/fs/cgroup/machine.slice";
const MAX_ENTRIES: usize = 512;
const MAX_SCOPES: usize = 32;
const MAX_PIDS_PER_SCOPE: usize = 256;
const MAX_CONTROL_BYTES: u64 = 4096;
const MAX_PROC_BYTES: usize = 4096;
const MAX_BUN_BYTES: u64 = 256 * 1024 * 1024;
const SDK_ARGV: &[u8] =
    b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContainerProcessIdentity {
    pub(crate) container_id: String,
    pub(crate) pid: u32,
    pub(crate) start_ticks: u64,
    pub(crate) cgroup: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SdkExecutableIdentity {
    pub(crate) container_id: String,
    pub(crate) pid: u32,
    pub(crate) start_ticks: u64,
    pub(crate) cgroup: String,
    pub(crate) argv_sha256: String,
    pub(crate) executable_sha256: String,
}

fn exact_sdk_argv(raw: &[u8]) -> bool {
    raw.len() <= 512
        && raw
            .iter()
            .rposition(|byte| *byte != 0)
            .is_some_and(|last| &raw[..=last] == SDK_ARGV)
}

fn read_cmdline(path: &str) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(path)
        .ok()?
        .take(513)
        .read_to_end(&mut raw)
        .ok()?;
    (raw.len() <= 512).then_some(raw)
}

/// Reopen one already pidfd-checked container PID. The kernel's exe link is
/// followed deliberately; descriptor bytes are hashed between two process,
/// command and executable identity observations. A disappearing process is
/// absent evidence, never a successful executable sample.
pub(crate) fn observe_sdk_executable(
    process: &ContainerProcessIdentity,
) -> Option<SdkExecutableIdentity> {
    observe_process(process.pid, process.start_ticks, &process.cgroup).ok()?;
    let cmdline_path = format!("/proc/{}/cmdline", process.pid);
    let first_argv = read_cmdline(&cmdline_path)?;
    if !exact_sdk_argv(&first_argv) {
        return None;
    }
    let executable_path = format!("/proc/{}/exe", process.pid);
    let mut executable = File::open(&executable_path).ok()?;
    let before = executable.metadata().ok()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_BUN_BYTES {
        return None;
    }
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = executable.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        count = count.checked_add(read as u64)?;
        if count > MAX_BUN_BYTES {
            return None;
        }
        digest.update(&chunk[..read]);
    }
    if count != before.len() {
        return None;
    }
    let after = executable.metadata().ok()?;
    let visible = std::fs::metadata(&executable_path).ok()?;
    let final_argv = read_cmdline(&cmdline_path)?;
    observe_process(process.pid, process.start_ticks, &process.cgroup).ok()?;
    if first_argv != final_argv
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.dev() != visible.dev()
        || before.ino() != visible.ino()
        || before.len() != visible.len()
    {
        return None;
    }
    Some(SdkExecutableIdentity {
        container_id: process.container_id.clone(),
        pid: process.pid,
        start_ticks: process.start_ticks,
        cgroup: process.cgroup.clone(),
        argv_sha256: format!("{:x}", Sha256::digest(SDK_ARGV)),
        executable_sha256: format!("{:x}", digest.finalize()),
    })
}

pub(crate) struct MachineSliceSampler {
    machine: OwnedFd,
    original: Stat,
}

fn same_root_directory(first: &Stat, second: &Stat) -> bool {
    FileType::from_raw_mode(first.st_mode) == FileType::Directory
        && first.st_uid == 0
        && first.st_mode & 0o022 == 0
        && first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn scope_id(name: &[u8]) -> Option<&[u8]> {
    let id = name.strip_prefix(b"libpod-")?.strip_suffix(b".scope")?;
    (id.len() == 64
        && id
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)))
    .then_some(id)
}

pub(crate) fn parse_pids(raw: &[u8]) -> Result<Vec<u32>, String> {
    if raw.len() as u64 > MAX_CONTROL_BYTES || !raw.is_empty() && !raw.ends_with(b"\n") {
        return Err("invalid container cgroup.procs framing".to_owned());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "invalid container cgroup.procs UTF-8")?;
    let mut pids = BTreeSet::new();
    for line in text.lines() {
        if pids.len() == MAX_PIDS_PER_SCOPE
            || line.is_empty()
            || line.len() > 10
            || !line.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("invalid or unbounded container cgroup.procs".to_owned());
        }
        let pid = line
            .parse::<u32>()
            .map_err(|_| "container PID overflows u32")?;
        if pid == 0 || !pids.insert(pid) {
            return Err("invalid or duplicate container PID".to_owned());
        }
    }
    Ok(pids.into_iter().collect())
}

fn open_root_directory(parent: &OwnedFd, name: &str) -> Result<Option<OwnedFd>, String> {
    let directory = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("unsafe container scope: {error}")),
    };
    let opened = fstat(&directory).map_err(|error| error.to_string())?;
    let visible = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(visible) => visible,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("container scope changed: {error}")),
    };
    if !same_root_directory(&opened, &visible) {
        return Err("unsafe container scope identity".to_owned());
    }
    Ok(Some(directory))
}

fn read_pids(directory: &OwnedFd) -> Result<Option<Vec<u32>>, String> {
    let descriptor = match openat(
        directory,
        "cgroup.procs",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("container cgroup.procs unavailable: {error}")),
    };
    let mut raw = Vec::new();
    File::from(descriptor)
        .take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("container cgroup.procs read failed: {error}"))?;
    parse_pids(&raw).map(Some)
}

impl MachineSliceSampler {
    pub(crate) fn new() -> Result<Self, String> {
        let machine = open(
            MACHINE_SLICE,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("machine slice unavailable: {error}"))?;
        let original = fstat(&machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&original, &original) {
            return Err("unsafe machine slice".to_owned());
        }
        Ok(Self { machine, original })
    }

    pub(crate) fn sample(&self) -> Result<Vec<ContainerProcessIdentity>, String> {
        let before = fstat(&self.machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&self.original, &before) {
            return Err("machine slice changed before scan".to_owned());
        }
        let mut entries = Dir::read_from(&self.machine).map_err(|error| error.to_string())?;
        let mut entry_count = 0;
        let mut scope_count = 0;
        let mut result = Vec::new();
        for entry in &mut entries {
            let entry = entry.map_err(|error| error.to_string())?;
            entry_count += 1;
            if entry_count > MAX_ENTRIES {
                return Err("machine slice entry bound exceeded".to_owned());
            }
            let name = entry.file_name().to_bytes();
            let Some(id) = scope_id(name) else {
                continue;
            };
            scope_count += 1;
            if scope_count > MAX_SCOPES {
                return Err("Podman scope bound exceeded".to_owned());
            }
            let name = std::str::from_utf8(name).map_err(|_| "invalid Podman scope name")?;
            let Some(scope) = open_root_directory(&self.machine, name)? else {
                continue;
            };
            let Some(container) = open_root_directory(&scope, "container")? else {
                continue;
            };
            let Some(pids) = read_pids(&container)? else {
                continue;
            };
            let container_id = std::str::from_utf8(id)
                .map_err(|_| "invalid Podman container ID")?
                .to_owned();
            let expected_cgroup = format!("/machine.slice/{name}/container");
            for pid in pids {
                let path = format!("/proc/{pid}/stat");
                let Ok(raw) = std::fs::read(path) else {
                    continue;
                };
                if raw.len() > MAX_PROC_BYTES {
                    continue;
                }
                let Some(stat) = parse_proc_stat(&raw, pid) else {
                    continue;
                };
                if observe_process(pid, stat.start_ticks, &expected_cgroup).is_err() {
                    continue;
                }
                result.push(ContainerProcessIdentity {
                    container_id: container_id.clone(),
                    pid,
                    start_ticks: stat.start_ticks,
                    cgroup: expected_cgroup.clone(),
                });
            }
        }
        let after = fstat(&self.machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&self.original, &after) {
            return Err("machine slice changed during scan".to_owned());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_podman_scope_and_pid_parser_refuse_ambiguous_names() {
        let id = "a".repeat(64);
        assert_eq!(
            scope_id(format!("libpod-{id}.scope").as_bytes()),
            Some(id.as_bytes())
        );
        assert!(scope_id(format!("libpod-{id}.scope/child").as_bytes()).is_none());
        assert!(scope_id(b"libpod-short.scope").is_none());
        assert_eq!(parse_pids(b"12\n7\n"), Ok(vec![7, 12]));
        for value in [b"1\n1\n".as_slice(), b"0\n", b"-1\n", b"1", b"4294967296\n"] {
            assert!(parse_pids(value).is_err());
        }
    }

    #[test]
    fn sdk_command_requires_the_fixed_complete_argv() {
        assert!(exact_sdk_argv(b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json\0"));
        assert!(!exact_sdk_argv(
            b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/other.json\0"
        ));
        assert!(!exact_sdk_argv(b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json\0--unsafe"));
    }
}
