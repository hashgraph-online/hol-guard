//! Host-owned, one-use intent record for a future candidate builder handoff.
//! This journal does not execute a build or authenticate a VM result.

use crate::private_jobs::{same_file, state_root};
use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const SCHEMA_V2: &str = "hol-gauntlet-host-candidate-build-pin.v2";
const SCHEMA_V3: &str = "hol-gauntlet-host-candidate-build-pin.v3";
const MAX_PIN_BYTES: u64 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidateBuildPins {
    pub job_id: String,
    pub source_sha: String,
    pub source_archive_sha256: String,
    pub version: String,
    pub tag: String,
    pub controller_root: String,
    pub controller_tree_sha256: String,
    pub uv_base_image_id: String,
    pub rust_base_image_id: String,
    pub builder_image_id: String,
    pub policy_sha256: String,
    pub podman_sha256: String,
    pub slirp4netns_sha256: String,
    pub apparmor_parser_sha256: String,
    pub seccomp_sha256: String,
    pub runner_binary_sha256: String,
    pub result_reader_binary_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidateBuildPinRecord {
    pub pins: HostCandidateBuildPins,
    pub host_nonce_hex: String,
    pub raw_sha256: String,
    pub schema: &'static str,
}

impl HostCandidateBuildPinRecord {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schema":self.schema,
            "job_id":self.pins.job_id,
            "source_sha":self.pins.source_sha,
            "source_archive_sha256":self.pins.source_archive_sha256,
            "version":self.pins.version,
            "controller_root":self.pins.controller_root,
            "controller_tree_sha256":self.pins.controller_tree_sha256,
            "uv_base_image_id":self.pins.uv_base_image_id,
            "rust_base_image_id":self.pins.rust_base_image_id,
            "builder_image_id":self.pins.builder_image_id,
            "policy_sha256":self.pins.policy_sha256,
            "podman_sha256":self.pins.podman_sha256,
            "slirp4netns_sha256":self.pins.slirp4netns_sha256,
            "apparmor_parser_sha256":self.pins.apparmor_parser_sha256,
            "seccomp_sha256":self.pins.seccomp_sha256,
            "runner_binary_sha256":self.pins.runner_binary_sha256,
            "result_reader_binary_sha256":self.pins.result_reader_binary_sha256,
            "host_nonce_hex":self.host_nonce_hex,
            "raw_sha256":self.raw_sha256,
            "prelaunch_host_pin_only":true,
            "execution_eligible":false,
        });
        if self.schema == SCHEMA_V3 {
            value["tag"] = json!(self.pins.tag);
        }
        value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCandidateBuildPinError {
    UnsafeDirectory,
    InvalidPins,
    AlreadyRecorded,
    Missing,
    UnsafeRecord,
    Changed,
    RandomUnavailable,
    Io,
}

impl fmt::Display for HostCandidateBuildPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafeDirectory => "isolated private host build-pin directory required",
            Self::InvalidPins => "invalid outside candidate build identity",
            Self::AlreadyRecorded => "host already recorded this candidate build job ID",
            Self::Missing => "host has no prelaunch candidate build pin for this job",
            Self::UnsafeRecord => "host candidate build pin is malformed or unsafe",
            Self::Changed => "host candidate build pin changed while reading",
            Self::RandomUnavailable => "host CSPRNG unavailable for build nonce",
            Self::Io => "host candidate build pin I/O failed",
        })
    }
}

impl std::error::Error for HostCandidateBuildPinError {}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl HostCandidateBuildPins {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.job_id, 16)
            && is_git_sha(&self.source_sha)
            && hex(&self.source_archive_sha256, 64)
            && valid_package_version(&self.version)
            && (self.tag == format!("local-{}", self.source_sha)
                || matches!(self.tag.as_str(), "v3.48.0" | "v3.49.0")
                    && self.version.as_str() == &self.tag[1..])
            && self
                .controller_root
                .strip_prefix("/opt/hol-gauntlet/controller-")
                .is_some_and(|generation| hex(generation, 16))
            && hex(&self.controller_tree_sha256, 64)
            && hex(&self.uv_base_image_id, 64)
            && hex(&self.rust_base_image_id, 64)
            && self
                .builder_image_id
                .strip_prefix("sha256:")
                .is_some_and(|digest| hex(digest, 64))
            && hex(&self.policy_sha256, 64)
            && hex(&self.podman_sha256, 64)
            && hex(&self.slirp4netns_sha256, 64)
            && hex(&self.apparmor_parser_sha256, 64)
            && hex(&self.seccomp_sha256, 64)
            && hex(&self.runner_binary_sha256, 64)
            && hex(&self.result_reader_binary_sha256, 64)
    }

    fn canonical_bytes(&self, host_nonce_hex: &str) -> Result<Vec<u8>, HostCandidateBuildPinError> {
        if !self.valid() || !hex(host_nonce_hex, 64) {
            return Err(HostCandidateBuildPinError::InvalidPins);
        }
        let value = json!({
            "schema":SCHEMA_V3,
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "source_archive_sha256":self.source_archive_sha256,
            "version":self.version,
            "tag":self.tag,
            "controller_root":self.controller_root,
            "controller_tree_sha256":self.controller_tree_sha256,
            "uv_base_image_id":self.uv_base_image_id,
            "rust_base_image_id":self.rust_base_image_id,
            "builder_image_id":self.builder_image_id,
            "policy_sha256":self.policy_sha256,
            "podman_sha256":self.podman_sha256,
            "slirp4netns_sha256":self.slirp4netns_sha256,
            "apparmor_parser_sha256":self.apparmor_parser_sha256,
            "seccomp_sha256":self.seccomp_sha256,
            "runner_binary_sha256":self.runner_binary_sha256,
            "result_reader_binary_sha256":self.result_reader_binary_sha256,
            "host_nonce_hex":host_nonce_hex,
        });
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| HostCandidateBuildPinError::InvalidPins)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_PIN_BYTES {
            return Err(HostCandidateBuildPinError::InvalidPins);
        }
        Ok(bytes)
    }

    fn parse(
        bytes: &[u8],
        job_id: &str,
    ) -> Result<(Self, String, &'static str), HostCandidateBuildPinError> {
        if canonicalize(bytes).map_err(|_| HostCandidateBuildPinError::UnsafeRecord)? != bytes {
            return Err(HostCandidateBuildPinError::UnsafeRecord);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| HostCandidateBuildPinError::UnsafeRecord)?;
        let object = value
            .as_object()
            .ok_or(HostCandidateBuildPinError::UnsafeRecord)?;
        let string = |name| {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(HostCandidateBuildPinError::UnsafeRecord)
        };
        let schema = match value["schema"].as_str() {
            Some(SCHEMA_V2) if object.len() == 18 => SCHEMA_V2,
            Some(SCHEMA_V3) if object.len() == 19 => SCHEMA_V3,
            _ => return Err(HostCandidateBuildPinError::UnsafeRecord),
        };
        let source_sha = string("source_sha")?;
        let pins = Self {
            job_id: string("job_id")?,
            source_sha: source_sha.clone(),
            source_archive_sha256: string("source_archive_sha256")?,
            version: string("version")?,
            tag: if schema == SCHEMA_V3 {
                string("tag")?
            } else {
                format!("local-{source_sha}")
            },
            controller_root: string("controller_root")?,
            controller_tree_sha256: string("controller_tree_sha256")?,
            uv_base_image_id: string("uv_base_image_id")?,
            rust_base_image_id: string("rust_base_image_id")?,
            builder_image_id: string("builder_image_id")?,
            policy_sha256: string("policy_sha256")?,
            podman_sha256: string("podman_sha256")?,
            slirp4netns_sha256: string("slirp4netns_sha256")?,
            apparmor_parser_sha256: string("apparmor_parser_sha256")?,
            seccomp_sha256: string("seccomp_sha256")?,
            runner_binary_sha256: string("runner_binary_sha256")?,
            result_reader_binary_sha256: string("result_reader_binary_sha256")?,
        };
        let host_nonce_hex = string("host_nonce_hex")?;
        if !pins.valid() || pins.job_id != job_id || !hex(&host_nonce_hex, 64) {
            return Err(HostCandidateBuildPinError::UnsafeRecord);
        }
        Ok((pins, host_nonce_hex, schema))
    }
}

pub struct HostCandidateBuildPinJournal {
    directory: OwnedFd,
    path: PathBuf,
    owner: u32,
}

fn same_directory(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_mode == right.st_mode
}

impl HostCandidateBuildPinJournal {
    /// Open a caller-created 0700 directory outside the Python observer's
    /// state. A journal here cannot itself prove a launch happened afterward.
    pub fn open(path: &Path) -> Result<Self, HostCandidateBuildPinError> {
        let owner = geteuid().as_raw();
        let directory =
            state_root(path, owner).map_err(|_| HostCandidateBuildPinError::UnsafeDirectory)?;
        Ok(Self {
            directory,
            path: path.to_owned(),
            owner,
        })
    }

    fn stable_directory(&self) -> Result<(), HostCandidateBuildPinError> {
        let reopened =
            state_root(&self.path, self.owner).map_err(|_| HostCandidateBuildPinError::Changed)?;
        let held = fstat(&self.directory).map_err(|_| HostCandidateBuildPinError::Io)?;
        let visible = fstat(&reopened).map_err(|_| HostCandidateBuildPinError::Io)?;
        if !same_directory(&held, &visible) {
            return Err(HostCandidateBuildPinError::Changed);
        }
        Ok(())
    }

    fn name(job_id: &str) -> Result<String, HostCandidateBuildPinError> {
        if !hex(job_id, 16) {
            return Err(HostCandidateBuildPinError::InvalidPins);
        }
        Ok(format!("{job_id}.candidate-build-pin.json"))
    }

    /// Persist a one-use host intent before any future VM build invocation.
    /// A partial record consumes the job ID; it may not be repaired in place.
    pub fn record(
        &self,
        pins: &HostCandidateBuildPins,
    ) -> Result<HostCandidateBuildPinRecord, HostCandidateBuildPinError> {
        if !pins.valid() {
            return Err(HostCandidateBuildPinError::InvalidPins);
        }
        self.stable_directory()?;
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| HostCandidateBuildPinError::RandomUnavailable)?;
        let host_nonce_hex = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let bytes = pins.canonical_bytes(&host_nonce_hex)?;
        let name = Self::name(&pins.job_id)?;
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                HostCandidateBuildPinError::AlreadyRecorded
            } else {
                HostCandidateBuildPinError::Io
            }
        })?;
        let stat = fstat(&descriptor).map_err(|_| HostCandidateBuildPinError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != self.owner
            || stat.st_nlink != 1
            || stat.st_mode & 0o777 != 0o600
        {
            return Err(HostCandidateBuildPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        file.write_all(&bytes)
            .map_err(|_| HostCandidateBuildPinError::Io)?;
        file.sync_all()
            .map_err(|_| HostCandidateBuildPinError::Io)?;
        fsync(&self.directory).map_err(|_| HostCandidateBuildPinError::Io)?;
        self.stable_directory()?;
        let readback = self.read(&pins.job_id)?;
        if readback.pins != *pins || readback.host_nonce_hex != host_nonce_hex {
            return Err(HostCandidateBuildPinError::Changed);
        }
        Ok(readback)
    }

    pub fn read(
        &self,
        job_id: &str,
    ) -> Result<HostCandidateBuildPinRecord, HostCandidateBuildPinError> {
        let name = Self::name(job_id)?;
        self.stable_directory()?;
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == Errno::NOENT {
                HostCandidateBuildPinError::Missing
            } else {
                HostCandidateBuildPinError::UnsafeRecord
            }
        })?;
        let before = fstat(&descriptor).map_err(|_| HostCandidateBuildPinError::UnsafeRecord)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner
            || before.st_nlink != 1
            || before.st_mode & 0o777 != 0o600
            || before.st_size <= 0
            || before.st_size as u64 > MAX_PIN_BYTES
        {
            return Err(HostCandidateBuildPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        let mut bytes = Vec::with_capacity(before.st_size as usize);
        (&mut file)
            .take(MAX_PIN_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HostCandidateBuildPinError::UnsafeRecord)?;
        let after = fstat(&file).map_err(|_| HostCandidateBuildPinError::Changed)?;
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostCandidateBuildPinError::Changed)?;
        if bytes.len() as i64 != before.st_size
            || !same_file(&before, &after)
            || !same_file(&before, &visible)
        {
            return Err(HostCandidateBuildPinError::Changed);
        }
        let (pins, host_nonce_hex, schema) = HostCandidateBuildPins::parse(&bytes, job_id)?;
        self.stable_directory()?;
        Ok(HostCandidateBuildPinRecord {
            pins,
            host_nonce_hex,
            raw_sha256: format!("{:x}", Sha256::digest(&bytes)),
            schema,
        })
    }
}
