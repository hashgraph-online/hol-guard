//! One-use host digest for a Root producer's staging close-write journal.
//! The Lima transport and guest artifact are diagnostic, not VM attestation.

use super::{
    hex, sdk_tap::fixed_guest_readout_argv, HostControllerKeyPinJournal, HostKeyPinError,
    HostKeyPinRecord, HostSdkTapJournalPin,
};
use crate::private_jobs::same_file;
use crate::stream_process::run_streamed;
use gauntlet_contracts::{
    canonicalize, validate_effect_writer_images, EffectFileHandle, EFFECT_IMAGE_JOURNAL_SCHEMA,
    EFFECT_IMAGE_RECEIPT_SCHEMA, MAX_RECORD_BYTES,
};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;

const SCHEMA: &str = "hol-gauntlet-host-effect-events-pin.v1";
const JOURNAL_SCHEMA: &str = "hol-gauntlet-staging-effect-events.v1";
const RECEIPT_SCHEMA: &str = "hol-gauntlet-staging-effect-events-receipt.v1";
const HANDLE_JOURNAL_SCHEMA: &str = "hol-gauntlet-staging-effect-events.v2";
const HANDLE_RECEIPT_SCHEMA: &str = "hol-gauntlet-staging-effect-events-receipt.v2";
const MAX_JOURNAL_BYTES: usize = MAX_RECORD_BYTES;
const MAX_EVENTS: usize = 32_768;
const MAX_PIN_BYTES: u64 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEffectEventsPin {
    pub run_id: String,
    pub host_key_record_sha256: String,
    pub terminal_sha256: String,
    pub report_sha256: String,
    pub journal_sha256: String,
    pub journal_bytes: usize,
    pub events: usize,
    pub unknown_writers: usize,
    pub raw_sha256: String,
}

impl HostEffectEventsPin {
    fn record_value(&self) -> Value {
        json!({
            "schema":SCHEMA,
            "run_id":self.run_id,
            "host_key_record_sha256":self.host_key_record_sha256,
            "terminal_sha256":self.terminal_sha256,
            "report_sha256":self.report_sha256,
            "journal_sha256":self.journal_sha256,
            "journal_bytes":self.journal_bytes,
            "events":self.events,
            "unknown_writers":self.unknown_writers,
            "execution_eligible":false,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut value = self.record_value();
        value["raw_sha256"] = json!(self.raw_sha256);
        value
    }
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn count(value: &Value, maximum: usize) -> Option<usize> {
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n <= maximum)
}

fn valid_cgroup(path: &str) -> bool {
    path.len() <= 256
        && path.starts_with('/')
        && path != "/"
        && path[1..].split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

impl HostKeyPinRecord {
    /// A completed effect pin must name the same outside key, terminal and
    /// report as the independently retained Root-forwarded SDK tap pin.
    pub fn match_effect_events_tap_ineligible(
        &self,
        tap: &HostSdkTapJournalPin,
        effect: &HostEffectEventsPin,
    ) -> Result<(), HostKeyPinError> {
        if tap.run_id != self.pins.job_id
            || effect.run_id != self.pins.job_id
            || tap.host_key_record_sha256 != self.raw_sha256
            || effect.host_key_record_sha256 != self.raw_sha256
            || tap.terminal_sha256 != effect.terminal_sha256
            || tap.report_sha256 != effect.report_sha256
        {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        Ok(())
    }

    pub fn observe_effect_events_ineligible(
        &self,
        terminal_raw: &[u8],
        report_raw: &[u8],
        journal_raw: &[u8],
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        let terminal = self.observe_keyed_terminal(terminal_raw, report_raw)?;
        if terminal.producer_status != "invalid-evidence"
            || journal_raw.is_empty()
            || journal_raw.len() > MAX_JOURNAL_BYTES
            || canonicalize(journal_raw).map_err(|_| HostKeyPinError::InvalidEffectJournal)?
                != journal_raw
        {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        let report: Value = serde_json::from_slice(report_raw)
            .map_err(|_| HostKeyPinError::InvalidEffectJournal)?;
        let journal: Value = serde_json::from_slice(journal_raw)
            .map_err(|_| HostKeyPinError::InvalidEffectJournal)?;
        let receipt = &report["effect_events"];
        let images = journal["schema"] == EFFECT_IMAGE_JOURNAL_SCHEMA;
        let handles = journal["schema"] == HANDLE_JOURNAL_SCHEMA || images;
        if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
            || report["run_id"] != self.pins.job_id
            || report["source_sha"] != self.pins.source_sha
            || report["execution_eligible"] != false
            || !exact_keys(
                receipt,
                &[
                    "schema",
                    "run_id",
                    "sha256",
                    "bytes",
                    "events",
                    "unknown_writers",
                    "host_pin_retained",
                    "guard_causality_verified",
                    "execution_eligible",
                ],
            )
            || receipt["schema"]
                != if images {
                    EFFECT_IMAGE_RECEIPT_SCHEMA
                } else if handles {
                    HANDLE_RECEIPT_SCHEMA
                } else {
                    RECEIPT_SCHEMA
                }
            || receipt["run_id"] != self.pins.job_id
            || receipt["host_pin_retained"] != false
            || receipt["guard_causality_verified"] != false
            || receipt["execution_eligible"] != false
        {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        let journal_sha256 = digest(journal_raw);
        let mut journal_fields = vec![
            "schema",
            "run_id",
            "source_sha",
            "started_marker_sha256",
            "controller_public_key_hex",
            "scope",
            "events",
            "event_count",
            "unknown_writer_count",
            "host_pin_retained",
            "guard_causality_verified",
            "execution_eligible",
        ];
        if images {
            journal_fields.push("writer_images");
        }
        if receipt["sha256"] != journal_sha256
            || count(&receipt["bytes"], MAX_JOURNAL_BYTES) != Some(journal_raw.len())
            || journal_raw.is_empty()
            || !exact_keys(&journal, &journal_fields)
            || (journal["schema"] != JOURNAL_SCHEMA && !handles)
            || journal["run_id"] != self.pins.job_id
            || journal["source_sha"] != self.pins.source_sha
            || journal["started_marker_sha256"] != self.pins.started_marker_sha256
            || journal["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || journal["scope"] != "watched-filesystem-close-write"
            || journal["host_pin_retained"] != false
            || journal["guard_causality_verified"] != false
            || journal["execution_eligible"] != false
        {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        let rows = journal["events"]
            .as_array()
            .filter(|rows| rows.len() <= MAX_EVENTS)
            .ok_or(HostKeyPinError::InvalidEffectJournal)?;
        let mut unknown = 0;
        for (index, row) in rows.iter().enumerate() {
            let mut fields = vec![
                "sequence",
                "device",
                "inode",
                "owner",
                "reported_pid",
                "pidfd_available",
                "writer",
            ];
            if handles {
                fields.push("file_handle");
                if !row["file_handle"].is_null()
                    && EffectFileHandle::from_json(&row["file_handle"]).is_none()
                {
                    return Err(HostKeyPinError::InvalidEffectJournal);
                }
            }
            if !exact_keys(row, &fields)
                || row["sequence"].as_u64() != Some(index as u64 + 1)
                || row["device"].as_u64().is_none_or(|n| n == 0)
                || row["inode"].as_u64().is_none_or(|n| n == 0)
                || row["owner"].as_u64().is_none_or(|n| n > u32::MAX as u64)
                || row["reported_pid"]
                    .as_u64()
                    .is_none_or(|n| n == 0 || n > u32::MAX as u64)
                || !row["pidfd_available"].is_boolean()
            {
                return Err(HostKeyPinError::InvalidEffectJournal);
            }
            if row["writer"].is_null() {
                unknown += 1;
            } else if !exact_keys(&row["writer"], &["pid", "start_ticks", "cgroup"])
                || row["pidfd_available"] != true
                || row["writer"]["pid"] != row["reported_pid"]
                || row["writer"]["start_ticks"].as_u64().is_none_or(|n| n == 0)
                || !row["writer"]["cgroup"].as_str().is_some_and(valid_cgroup)
            {
                return Err(HostKeyPinError::InvalidEffectJournal);
            }
        }
        if count(&journal["event_count"], MAX_EVENTS) != Some(rows.len())
            || count(&journal["unknown_writer_count"], MAX_EVENTS) != Some(unknown)
            || receipt["events"] != journal["event_count"]
            || receipt["unknown_writers"] != journal["unknown_writer_count"]
            || images && !validate_effect_writer_images(&journal["writer_images"], rows)
        {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        Ok(HostEffectEventsPin {
            run_id: self.pins.job_id.clone(),
            host_key_record_sha256: self.raw_sha256.clone(),
            terminal_sha256: terminal.terminal_sha256,
            report_sha256: terminal.report_sha256,
            journal_sha256,
            journal_bytes: journal_raw.len(),
            events: rows.len(),
            unknown_writers: unknown,
            raw_sha256: String::new(),
        })
    }
}

impl HostControllerKeyPinJournal {
    pub fn record_effect_events_from_lima_ineligible(
        &self,
        run_id: &str,
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        if !hex(run_id, 16) {
            return Err(HostKeyPinError::InvalidPins);
        }
        match self.read_effect_events_pin(run_id) {
            Ok(_) => return Err(HostKeyPinError::AlreadyRecorded),
            Err(HostKeyPinError::Missing) => (),
            Err(error) => return Err(error),
        }
        self.read(run_id)?;
        let read = |suffix, maximum| {
            let argv = fixed_guest_readout_argv(run_id, suffix)?;
            run_streamed(&argv, b"\n", Duration::from_secs(30), maximum)
                .map_err(|_| HostKeyPinError::TransportFailed)
        };
        let terminal = read("terminal.json", 2048)?;
        let report = read("report.json", 16 * 1024 * 1024)?;
        let events = read("effect-events.json", MAX_JOURNAL_BYTES)?;
        self.record_effect_events_ineligible(run_id, &terminal, &report, &events)
    }

    /// Reopen the same fixed guest files after restart and compare them with
    /// the already durable host digest. This does not attest the VM identity.
    pub fn verify_effect_events_from_lima_ineligible(
        &self,
        run_id: &str,
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        let retained = self.read_effect_events_pin(run_id)?;
        let read = |suffix, maximum| {
            let argv = fixed_guest_readout_argv(run_id, suffix)?;
            run_streamed(&argv, b"\n", Duration::from_secs(30), maximum)
                .map_err(|_| HostKeyPinError::TransportFailed)
        };
        let terminal = read("terminal.json", 2048)?;
        let report = read("report.json", 16 * 1024 * 1024)?;
        let events = read("effect-events.json", MAX_JOURNAL_BYTES)?;
        self.verify_effect_events_ineligible(run_id, &terminal, &report, &events)?;
        Ok(retained)
    }

    pub fn verify_effect_events_ineligible(
        &self,
        run_id: &str,
        terminal: &[u8],
        report: &[u8],
        events: &[u8],
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        let retained = self.read_effect_events_pin(run_id)?;
        let observed = self
            .read(run_id)?
            .observe_effect_events_ineligible(terminal, report, events)?;
        if retained.record_value() != observed.record_value()
            || self.read_effect_events_pin(run_id)? != retained
        {
            return Err(HostKeyPinError::Changed);
        }
        Ok(retained)
    }

    pub fn record_effect_events_ineligible(
        &self,
        run_id: &str,
        terminal: &[u8],
        report: &[u8],
        events: &[u8],
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        let key = self.read(run_id)?;
        let observed = key.observe_effect_events_ineligible(terminal, report, events)?;
        let bytes = canonicalize(observed.record_value().to_string().as_bytes())
            .map_err(|_| HostKeyPinError::InvalidEffectJournal)?;
        if bytes.len() as u64 > MAX_PIN_BYTES {
            return Err(HostKeyPinError::InvalidEffectJournal);
        }
        self.stable_directory()?;
        let name = format!("{run_id}.effect-events-pin.json");
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
        file.write_all(&bytes).map_err(|_| HostKeyPinError::Io)?;
        file.sync_all().map_err(|_| HostKeyPinError::Io)?;
        fsync(&self.directory).map_err(|_| HostKeyPinError::Io)?;
        let retained = self.read_effect_events_pin(run_id)?;
        if retained.record_value() != observed.record_value()
            || self.read(run_id)?.raw_sha256 != key.raw_sha256
        {
            return Err(HostKeyPinError::Changed);
        }
        Ok(retained)
    }

    pub fn read_effect_events_pin(
        &self,
        run_id: &str,
    ) -> Result<HostEffectEventsPin, HostKeyPinError> {
        if !hex(run_id, 16) {
            return Err(HostKeyPinError::InvalidPins);
        }
        self.stable_directory()?;
        let name = format!("{run_id}.effect-events-pin.json");
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
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner
            || before.st_nlink != 1
            || before.st_mode & 0o7777 != 0o600
            || before.st_size <= 0
            || before.st_size as u64 > MAX_PIN_BYTES
            || !same_file(&before, &visible)
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_PIN_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|_| HostKeyPinError::Io)?;
        let after = fstat(&file).map_err(|_| HostKeyPinError::Io)?;
        let visible = statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if raw.len() as i64 != before.st_size
            || !same_file(&before, &after)
            || !same_file(&before, &visible)
            || canonicalize(&raw).map_err(|_| HostKeyPinError::UnsafeRecord)? != raw
        {
            return Err(HostKeyPinError::Changed);
        }
        let value: Value =
            serde_json::from_slice(&raw).map_err(|_| HostKeyPinError::UnsafeRecord)?;
        let parse_hash = |field: &str| {
            value[field]
                .as_str()
                .filter(|raw| hex(raw, 64))
                .map(str::to_owned)
                .ok_or(HostKeyPinError::UnsafeRecord)
        };
        let record = HostEffectEventsPin {
            run_id: run_id.to_owned(),
            host_key_record_sha256: parse_hash("host_key_record_sha256")?,
            terminal_sha256: parse_hash("terminal_sha256")?,
            report_sha256: parse_hash("report_sha256")?,
            journal_sha256: parse_hash("journal_sha256")?,
            journal_bytes: count(&value["journal_bytes"], MAX_JOURNAL_BYTES)
                .filter(|n| *n > 0)
                .ok_or(HostKeyPinError::UnsafeRecord)?,
            events: count(&value["events"], MAX_EVENTS).ok_or(HostKeyPinError::UnsafeRecord)?,
            unknown_writers: count(&value["unknown_writers"], MAX_EVENTS)
                .ok_or(HostKeyPinError::UnsafeRecord)?,
            raw_sha256: digest(&raw),
        };
        if value != record.record_value()
            || record.unknown_writers > record.events
            || self.read(run_id)?.raw_sha256 != record.host_key_record_sha256
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        self.stable_directory()?;
        Ok(record)
    }
}

#[cfg(test)]
#[path = "controller_key_effect_events_tests.rs"]
mod tests;
