//! Outside-pinned helper and Podman security preflight for an ARM candidate
//! build. Observed VM hashes do not by themselves approve a production pin.

use crate::hex;
use rustix::fs::{fstat, open, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PODMAN: &str = "/usr/bin/podman";
const SLIRP: &str = "/usr/bin/slirp4netns";
const APPARMOR: &str = "/usr/sbin/apparmor_parser";
const SECCOMP: &str = "/usr/share/containers/seccomp.json";
const MAX_BINARY: u64 = 64 * 1024 * 1024;
const MAX_SECCOMP: u64 = 1024 * 1024;
const INFO_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePreflightError {
    InvalidPins,
    HelperMismatch,
    PodmanUnavailable,
    SecurityDisabled,
}

impl fmt::Display for CandidatePreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPins => "four outside helper SHA-256 pins required",
            Self::HelperMismatch => "fixed Podman, slirp, AppArmor or seccomp file differs",
            Self::PodmanUnavailable => "bounded local Podman security inspection failed",
            Self::SecurityDisabled => "ARM Podman AppArmor, seccomp or slirp requirement absent",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRuntimePins {
    pub(crate) podman_sha256: String,
    pub(crate) slirp_sha256: String,
    pub(crate) apparmor_sha256: String,
    pub(crate) seccomp_sha256: String,
}

impl CandidateRuntimePins {
    pub fn parse(
        podman: &str,
        slirp: &str,
        apparmor: &str,
        seccomp: &str,
    ) -> Result<Self, CandidatePreflightError> {
        if ![podman, slirp, apparmor, seccomp]
            .iter()
            .all(|digest| hex(digest, 64))
        {
            return Err(CandidatePreflightError::InvalidPins);
        }
        Ok(Self {
            podman_sha256: podman.to_owned(),
            slirp_sha256: slirp.to_owned(),
            apparmor_sha256: apparmor.to_owned(),
            seccomp_sha256: seccomp.to_owned(),
        })
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "podman_sha256":self.podman_sha256,
            "slirp4netns_sha256":self.slirp_sha256,
            "apparmor_parser_sha256":self.apparmor_sha256,
            "seccomp_sha256":self.seccomp_sha256,
        })
    }
}

fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn verify_file(
    path: &str,
    expected: &str,
    execute: bool,
    limit: u64,
) -> Result<(), CandidatePreflightError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePreflightError::HelperMismatch)?;
    let before = fstat(&descriptor).map_err(|_| CandidatePreflightError::HelperMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
        || (execute && before.st_mode & 0o111 == 0)
        || before.st_size <= 0
        || before.st_size as u64 > limit
    {
        return Err(CandidatePreflightError::HelperMismatch);
    }
    let mut file = File::from(descriptor);
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidatePreflightError::HelperMismatch)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > limit {
            return Err(CandidatePreflightError::HelperMismatch);
        }
        hash.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidatePreflightError::HelperMismatch)?;
    let visible = statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePreflightError::HelperMismatch)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || format!("{:x}", hash.finalize()) != expected
    {
        return Err(CandidatePreflightError::HelperMismatch);
    }
    Ok(())
}

fn podman_info() -> Result<Value, CandidatePreflightError> {
    let mut command = Command::new(PODMAN);
    command.args(["info", "--format", "json"]);
    command
        .env_clear()
        .env("HOME", "/root")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| CandidatePreflightError::PodmanUnavailable)?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < INFO_WAIT => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CandidatePreflightError::PodmanUnavailable);
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| CandidatePreflightError::PodmanUnavailable)?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 || output.stderr.len() > 4096 {
        return Err(CandidatePreflightError::PodmanUnavailable);
    }
    serde_json::from_slice(&output.stdout).map_err(|_| CandidatePreflightError::PodmanUnavailable)
}

pub(crate) fn verify_candidate_runtime(
    pins: &CandidateRuntimePins,
) -> Result<(), CandidatePreflightError> {
    verify_file(PODMAN, &pins.podman_sha256, true, MAX_BINARY)?;
    verify_file(SLIRP, &pins.slirp_sha256, true, MAX_BINARY)?;
    verify_file(APPARMOR, &pins.apparmor_sha256, true, MAX_BINARY)?;
    verify_file(SECCOMP, &pins.seccomp_sha256, false, MAX_SECCOMP)?;
    let info = podman_info()?;
    if info["host"]["arch"] != "arm64"
        || info["host"]["os"] != "linux"
        || info["host"]["security"]["rootless"] != false
        || info["host"]["security"]["apparmorEnabled"] != true
        || info["host"]["security"]["seccompEnabled"] != true
        || info["host"]["security"]["seccompProfilePath"] != SECCOMP
        || info["host"]["slirp4netns"]["executable"] != SLIRP
        || info["host"]["cpus"].as_u64().is_none_or(|value| value < 2)
        || info["host"]["memTotal"]
            .as_u64()
            .is_none_or(|value| value < 15 * 1024 * 1024 * 1024)
    {
        return Err(CandidatePreflightError::SecurityDisabled);
    }
    Ok(())
}
