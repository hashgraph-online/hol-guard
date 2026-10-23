//! Isolated host custody for a worker-owned public signing key. A caller must
//! persist this record before acknowledging controller launch over a reviewed
//! transport; this library cannot prove the caller's ordering or VM identity.

use crate::private_jobs::{same_file, state_root};
use gauntlet_contracts::{canonicalize, is_git_sha, PrelaunchPrepared};
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

const SCHEMA: &str = "hol-gauntlet-host-controller-key-pin.v1";
const MAX_PIN_BYTES: u64 = 1024;
const MAX_SUITE_BYTES: u64 = 8192;

#[path = "controller_key_terminal.rs"]
mod terminal;
pub use terminal::HostKeyedTerminalObservation;
#[path = "controller_key_readback.rs"]
mod readback;
pub use readback::HostDeterministicReadbackObservation;
#[path = "controller_key_sdk_tap.rs"]
mod sdk_tap;
pub use sdk_tap::HostSdkTapJournalPin;
#[path = "controller_key_effect_events.rs"]
mod effect_events;
pub use effect_events::HostEffectEventsPin;
#[path = "controller_key_product_effect.rs"]
mod product_effect;
#[path = "controller_key_staging_readback.rs"]
mod staging_readback;
pub use staging_readback::HostStagingRestartReadbackObservation;

#[path = "controller_key_pipe.rs"]
mod pipe;
#[path = "controller_key_process.rs"]
mod process;
pub use process::{HostPreparedProcess, HostProcessFailure};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostControllerKeyPins {
    pub job_id: String,
    pub source_sha: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub controller_key_pin_sha256: String,
    pub controller_public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPrelaunchIdentity {
    pub job_id: String,
    pub source_sha: String,
    pub deployment_digest: String,
    pub worker_generation: String,
}

impl HostPrelaunchIdentity {
    fn valid(&self) -> bool {
        hex(&self.job_id, 16)
            && is_git_sha(&self.source_sha)
            && hex(&self.deployment_digest, 64)
            && hex(&self.worker_generation, 64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyPinRecord {
    pub pins: HostControllerKeyPins,
    pub raw_sha256: String,
}

impl HostKeyPinRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":SCHEMA,
            "job_id":self.pins.job_id,
            "source_sha":self.pins.source_sha,
            "deployment_digest":self.pins.deployment_digest,
            "worker_generation":self.pins.worker_generation,
            "started_marker_sha256":self.pins.started_marker_sha256,
            "controller_key_pin_sha256":self.pins.controller_key_pin_sha256,
            "controller_public_key_hex":self.pins.controller_public_key_hex,
            "raw_sha256":self.raw_sha256,
            "execution_eligible":false,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPinError {
    UnsafeDirectory,
    InvalidPins,
    WrongRequest,
    WrongPreparedIdentity,
    AlreadyRecorded,
    Missing,
    UnsafeRecord,
    InvalidTerminal,
    InvalidTapJournal,
    InvalidEffectJournal,
    TransportTimedOut,
    TransportFailed,
    FrameTooLarge,
    Changed,
    Io,
}

impl fmt::Display for HostKeyPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafeDirectory => "isolated private host pin directory required",
            Self::InvalidPins => "invalid outside controller key identity",
            Self::WrongRequest => "VM run request differs from the planned host job",
            Self::WrongPreparedIdentity => "VM prepared frame differs from the planned host job",
            Self::AlreadyRecorded => "host already recorded this one-use job ID",
            Self::Missing => "host has no prelaunch controller key pin for this job",
            Self::UnsafeRecord => "host controller key pin is malformed or unsafe",
            Self::InvalidTerminal => "keyed VM terminal differs from the host prelaunch pin",
            Self::InvalidTapJournal => "SDK tap journal differs from the keyed VM run",
            Self::InvalidEffectJournal => "effect event journal differs from the keyed VM run",
            Self::TransportTimedOut => "VM prelaunch frame or acknowledgement timed out",
            Self::TransportFailed => "VM prelaunch transport failed",
            Self::FrameTooLarge => "VM prelaunch frame exceeds its byte limit",
            Self::Changed => "host controller key pin changed while reading",
            Self::Io => "host controller key pin I/O failed",
        })
    }
}

impl std::error::Error for HostKeyPinError {}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl HostControllerKeyPins {
    fn valid(&self) -> bool {
        hex(&self.job_id, 16)
            && is_git_sha(&self.source_sha)
            && hex(&self.deployment_digest, 64)
            && hex(&self.worker_generation, 64)
            && hex(&self.started_marker_sha256, 64)
            && hex(&self.controller_key_pin_sha256, 64)
            && hex(&self.controller_public_key_hex, 64)
    }

    fn bytes(&self) -> Result<Vec<u8>, HostKeyPinError> {
        if !self.valid() {
            return Err(HostKeyPinError::InvalidPins);
        }
        let value = json!({
            "schema":SCHEMA,
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "deployment_digest":self.deployment_digest,
            "worker_generation":self.worker_generation,
            "started_marker_sha256":self.started_marker_sha256,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "controller_public_key_hex":self.controller_public_key_hex,
        });
        let bytes =
            canonicalize(value.to_string().as_bytes()).map_err(|_| HostKeyPinError::InvalidPins)?;
        if bytes.len() as u64 > MAX_PIN_BYTES {
            return Err(HostKeyPinError::InvalidPins);
        }
        Ok(bytes)
    }

    fn parse(bytes: &[u8], job_id: &str) -> Result<Self, HostKeyPinError> {
        if canonicalize(bytes).map_err(|_| HostKeyPinError::UnsafeRecord)? != bytes {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| HostKeyPinError::UnsafeRecord)?;
        let object = value.as_object().ok_or(HostKeyPinError::UnsafeRecord)?;
        let string = |name| {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(HostKeyPinError::UnsafeRecord)
        };
        if object.len() != 8 || value["schema"] != SCHEMA {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let pins = Self {
            job_id: string("job_id")?,
            source_sha: string("source_sha")?,
            deployment_digest: string("deployment_digest")?,
            worker_generation: string("worker_generation")?,
            started_marker_sha256: string("started_marker_sha256")?,
            controller_key_pin_sha256: string("controller_key_pin_sha256")?,
            controller_public_key_hex: string("controller_public_key_hex")?,
        };
        if !pins.valid() || pins.job_id != job_id {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        Ok(pins)
    }
}

pub struct HostControllerKeyPinJournal {
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

impl HostControllerKeyPinJournal {
    /// Open a caller-created 0700 host directory separate from Python's live
    /// observer state. This never creates or changes that observer's files.
    pub fn open(path: &Path) -> Result<Self, HostKeyPinError> {
        let owner = geteuid().as_raw();
        let directory = state_root(path, owner).map_err(|_| HostKeyPinError::UnsafeDirectory)?;
        Ok(Self {
            directory,
            path: path.to_owned(),
            owner,
        })
    }

    fn stable_directory(&self) -> Result<(), HostKeyPinError> {
        let reopened = state_root(&self.path, self.owner).map_err(|_| HostKeyPinError::Changed)?;
        let held = fstat(&self.directory).map_err(|_| HostKeyPinError::Io)?;
        let visible = fstat(&reopened).map_err(|_| HostKeyPinError::Io)?;
        if !same_directory(&held, &visible) {
            return Err(HostKeyPinError::Changed);
        }
        Ok(())
    }

    /// Exclusive, fsynced one-use host record. The caller must finish this
    /// before sending the worker an execute acknowledgement. A partial write
    /// consumes the job ID and requires investigation, never an overwrite.
    pub fn record(
        &self,
        pins: &HostControllerKeyPins,
    ) -> Result<HostKeyPinRecord, HostKeyPinError> {
        let bytes = pins.bytes()?;
        self.stable_directory()?;
        let name = format!("{}.controller-key-pin.json", pins.job_id);
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                HostKeyPinError::AlreadyRecorded
            } else {
                HostKeyPinError::Io
            }
        })?;
        let stat = fstat(&descriptor).map_err(|_| HostKeyPinError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != self.owner
            || stat.st_nlink != 1
            || stat.st_mode & 0o777 != 0o600
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        file.write_all(&bytes).map_err(|_| HostKeyPinError::Io)?;
        file.sync_all().map_err(|_| HostKeyPinError::Io)?;
        fsync(&self.directory).map_err(|_| HostKeyPinError::Io)?;
        self.stable_directory()?;
        let observed = self.read(&pins.job_id)?;
        if observed.pins != *pins {
            return Err(HostKeyPinError::Changed);
        }
        Ok(observed)
    }

    /// Persist a diagnostic six-role suite anchor only after the caller has
    /// reopened every prelaunch key pin. The manifest is one-use host data,
    /// not a guest conformance package or benchmark admission.
    pub fn record_staging_suite_manifest(
        &self,
        build_job_id: &str,
        suite_id: &str,
        bytes: &[u8],
    ) -> Result<String, HostKeyPinError> {
        if !hex(build_job_id, 16)
            || !hex(suite_id, 16)
            || bytes.is_empty()
            || bytes.len() as u64 > MAX_SUITE_BYTES
            || canonicalize(bytes).ok().as_deref() != Some(bytes)
        {
            return Err(HostKeyPinError::InvalidPins);
        }
        let manifest: Value =
            serde_json::from_slice(bytes).map_err(|_| HostKeyPinError::InvalidPins)?;
        if manifest["build_job_id"] != build_job_id
            || manifest["roles"]["success"]["run_id"] != suite_id
        {
            return Err(HostKeyPinError::InvalidPins);
        }
        self.stable_directory()?;
        let name = format!("{build_job_id}.{suite_id}.staging-suite-pins.json");
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                HostKeyPinError::AlreadyRecorded
            } else {
                HostKeyPinError::Io
            }
        })?;
        let stat = fstat(&descriptor).map_err(|_| HostKeyPinError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != self.owner
            || stat.st_nlink != 1
            || stat.st_mode & 0o7777 != 0o600
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        file.write_all(bytes).map_err(|_| HostKeyPinError::Io)?;
        file.sync_all().map_err(|_| HostKeyPinError::Io)?;
        fsync(&self.directory).map_err(|_| HostKeyPinError::Io)?;
        self.stable_directory()?;
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| HostKeyPinError::Changed)?;
        let before = fstat(&descriptor).map_err(|_| HostKeyPinError::Io)?;
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner
            || before.st_nlink != 1
            || before.st_mode & 0o7777 != 0o600
            || before.st_size as u64 != bytes.len() as u64
            || !same_file(&before, &visible)
        {
            return Err(HostKeyPinError::Changed);
        }
        let mut observed = Vec::with_capacity(bytes.len());
        File::from(descriptor)
            .take(MAX_SUITE_BYTES + 1)
            .read_to_end(&mut observed)
            .map_err(|_| HostKeyPinError::Io)?;
        self.stable_directory()?;
        if observed != bytes {
            return Err(HostKeyPinError::Changed);
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Accept a bounded worker prepared frame, persist its exact identity,
    /// then emit the only acknowledgement that may precede controller launch.
    /// The caller still has to deliver that ack over a reviewed live channel.
    pub fn accept_prepared(
        &self,
        prepared_raw: &[u8],
        expected: &HostPrelaunchIdentity,
    ) -> Result<(HostKeyPinRecord, Vec<u8>), HostKeyPinError> {
        let prepared =
            PrelaunchPrepared::parse(prepared_raw).map_err(|_| HostKeyPinError::InvalidPins)?;
        if !expected.valid()
            || prepared.job_id != expected.job_id
            || prepared.source_sha != expected.source_sha
            || prepared.deployment_digest != expected.deployment_digest
            || prepared.worker_generation != expected.worker_generation
        {
            return Err(HostKeyPinError::WrongPreparedIdentity);
        }
        let pins = HostControllerKeyPins {
            job_id: prepared.job_id.clone(),
            source_sha: prepared.source_sha.clone(),
            deployment_digest: prepared.deployment_digest.clone(),
            worker_generation: prepared.worker_generation.clone(),
            started_marker_sha256: prepared.started_marker_sha256.clone(),
            controller_key_pin_sha256: prepared.controller_key_pin_sha256.clone(),
            controller_public_key_hex: prepared.controller_public_key_hex.clone(),
        };
        let record = self.record(&pins)?;
        if prepared.host_record_sha256().ok().as_deref() != Some(&record.raw_sha256) {
            return Err(HostKeyPinError::Changed);
        }
        let acknowledgement = prepared
            .acknowledgement(&record.raw_sha256)
            .map_err(|_| HostKeyPinError::Changed)?;
        Ok((record, acknowledgement))
    }

    /// Reopen the host's prelaunch anchor after restart. It is a host record,
    /// not an authenticated VM execution or Guard verdict by itself.
    pub fn read(&self, job_id: &str) -> Result<HostKeyPinRecord, HostKeyPinError> {
        if !hex(job_id, 16) {
            return Err(HostKeyPinError::InvalidPins);
        }
        self.stable_directory()?;
        let name = format!("{job_id}.controller-key-pin.json");
        let descriptor = openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == Errno::NOENT {
                HostKeyPinError::Missing
            } else {
                HostKeyPinError::UnsafeRecord
            }
        })?;
        let before = fstat(&descriptor).map_err(|_| HostKeyPinError::Io)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner
            || before.st_nlink != 1
            || before.st_mode & 0o777 != 0o600
            || before.st_size <= 0
            || before.st_size as u64 > MAX_PIN_BYTES
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if !same_file(&before, &visible) {
            return Err(HostKeyPinError::Changed);
        }
        let mut file = File::from(descriptor);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_PIN_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HostKeyPinError::Io)?;
        let after = fstat(&file).map_err(|_| HostKeyPinError::Io)?;
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if bytes.len() as i64 != before.st_size
            || !same_file(&before, &after)
            || !same_file(&before, &visible)
        {
            return Err(HostKeyPinError::Changed);
        }
        let pins = HostControllerKeyPins::parse(&bytes, job_id)?;
        self.stable_directory()?;
        Ok(HostKeyPinRecord {
            pins,
            raw_sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }
}
