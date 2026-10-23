//! Host-side, one-use custody for a completed SDK tap diagnostic. The guest
//! journal is still producer evidence: this binds bytes to the prelaunch host
//! key, but does not authenticate Native effects or grant execution eligibility.

use super::{hex, HostControllerKeyPinJournal, HostKeyPinError, HostKeyPinRecord};
use crate::private_jobs::same_file;
use crate::stream_process::run_streamed;
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;

const SCHEMA: &str = "hol-gauntlet-host-sdk-tap-pin.v1";
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_PIN_BYTES: u64 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSdkTapJournalPin {
    pub run_id: String,
    pub host_key_record_sha256: String,
    pub terminal_sha256: String,
    pub report_sha256: String,
    pub journal_sha256: String,
    pub journal_bytes: usize,
    pub sessions: usize,
    pub events: usize,
    pub observed_bytes: usize,
    pub raw_sha256: String,
}

impl HostSdkTapJournalPin {
    fn record_value(&self) -> Value {
        json!({
            "schema":SCHEMA,
            "run_id":self.run_id,
            "host_key_record_sha256":self.host_key_record_sha256,
            "terminal_sha256":self.terminal_sha256,
            "report_sha256":self.report_sha256,
            "journal_sha256":self.journal_sha256,
            "journal_bytes":self.journal_bytes,
            "sessions":self.sessions,
            "events":self.events,
            "observed_bytes":self.observed_bytes,
            "execution_eligible":false,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut value = self.record_value();
        value["raw_sha256"] = json!(self.raw_sha256);
        value
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn count(value: &Value, maximum: usize) -> Option<usize> {
    value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= maximum)
}

pub(super) fn fixed_guest_readout_argv(
    run_id: &str,
    suffix: &str,
) -> Result<Vec<String>, HostKeyPinError> {
    if !hex(run_id, 16)
        || !matches!(
            suffix,
            "terminal.json" | "report.json" | "sdk-tap.json" | "effect-events.json"
        )
    {
        return Err(HostKeyPinError::InvalidPins);
    }
    let defaults: Value = serde_json::from_str(include_str!("../operations-defaults-v1.json"))
        .map_err(|_| HostKeyPinError::InvalidPins)?;
    let limactl = defaults["limactl"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or(HostKeyPinError::InvalidPins)?;
    let vm = defaults["vm"]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or(HostKeyPinError::InvalidPins)?;
    Ok([
        limactl.to_owned(),
        "shell".to_owned(),
        vm.to_owned(),
        "--".to_owned(),
        "sudo".to_owned(),
        "-n".to_owned(),
        "cat".to_owned(),
        format!("/var/lib/hol-gauntlet-rust/staging-state/{run_id}.{suffix}"),
    ]
    .to_vec())
}

impl HostKeyPinRecord {
    /// Check a completed guest terminal, report and journal against the key
    /// pinned on this host before launch. This is a consistency check only.
    pub fn observe_sdk_tap_journal(
        &self,
        terminal_raw: &[u8],
        report_raw: &[u8],
        journal_raw: &[u8],
    ) -> Result<HostSdkTapJournalPin, HostKeyPinError> {
        let terminal = self.observe_keyed_terminal(terminal_raw, report_raw)?;
        if terminal.producer_status != "invalid-evidence"
            || journal_raw.is_empty()
            || journal_raw.len() > MAX_JOURNAL_BYTES
            || canonicalize(journal_raw).map_err(|_| HostKeyPinError::InvalidTapJournal)?
                != journal_raw
        {
            return Err(HostKeyPinError::InvalidTapJournal);
        }
        let report: Value =
            serde_json::from_slice(report_raw).map_err(|_| HostKeyPinError::InvalidTapJournal)?;
        let journal: Value =
            serde_json::from_slice(journal_raw).map_err(|_| HostKeyPinError::InvalidTapJournal)?;
        let receipt = &report["sdk_tap_v2"]["journal"];
        let root_forwarded =
            report["sdk_tap_v2"]["schema"] == "hol-gauntlet-staging-sdk-tap-summary.v3";
        if root_forwarded {
            if report["sdk_tap_v2"]["native_peer_independently_observed_by_root"] != true
                || report["sdk_tap_v2"]["root_forwarded"] != true
                || receipt["schema"] != "hol-gauntlet-sdk-tap-journal-receipt.v2"
                || receipt["root_forwarded"] != true
                || journal["schema"] != "hol-gauntlet-sdk-tap-journal.v2"
                || journal["root_forwarded"] != true
                || journal["wire_owner"] != "root-forwarded"
            {
                return Err(HostKeyPinError::InvalidTapJournal);
            }
        } else if report["sdk_tap_v2"].get("root_forwarded").is_some()
            || receipt.get("root_forwarded").is_some()
            || journal.get("root_forwarded").is_some()
            || journal.get("wire_owner").is_some()
        {
            return Err(HostKeyPinError::InvalidTapJournal);
        }
        let sessions = journal["sessions"]
            .as_array()
            .ok_or(HostKeyPinError::InvalidTapJournal)?;
        let session_count =
            count(&journal["session_count"], 16).ok_or(HostKeyPinError::InvalidTapJournal)?;
        let event_count =
            count(&journal["event_count"], 1000).ok_or(HostKeyPinError::InvalidTapJournal)?;
        let observed_bytes = count(&journal["observed_bytes"], 12 * 1024 * 1024)
            .ok_or(HostKeyPinError::InvalidTapJournal)?;
        let mut families = BTreeSet::new();
        let mut events = 0_usize;
        let mut bytes = 0_usize;
        for (index, session) in sessions.iter().enumerate() {
            let family = session["family"]
                .as_str()
                .filter(|value| matches!(*value, "docs" | "mail"))
                .ok_or(HostKeyPinError::InvalidTapJournal)?;
            let wire = &session["wire"];
            let wire_events = wire["events"]
                .as_array()
                .ok_or(HostKeyPinError::InvalidTapJournal)?;
            let wire_bytes = count(&wire["total_bytes"], 12 * 1024 * 1024)
                .ok_or(HostKeyPinError::InvalidTapJournal)?;
            let frame_bytes = wire_events.iter().try_fold(0_usize, |sum, event| {
                let size = count(&event["frame_bytes"], 1024 * 1024 + 1)?;
                sum.checked_add(size)
            });
            if session["sequence"].as_u64() != Some(index as u64 + 1)
                || if root_forwarded {
                    session["wire_owner"] != "root-forwarded"
                } else {
                    session.get("wire_owner").is_some()
                }
                || wire_events.is_empty()
                || wire["schema"] != "hol-gauntlet-sdk-wire-tap.v1"
                || wire["peer_identity_verified"] != false
                || wire["journal_durable"] != false
                || wire["execution_eligible"] != false
                || wire["completed_tool_calls"]
                    .as_u64()
                    .is_none_or(|n| n as usize > wire_events.len() / 2)
                || frame_bytes != Some(wire_bytes)
                || wire_events.iter().enumerate().any(|(i, event)| {
                    event["sequence"].as_u64() != Some(i as u64 + 1)
                        || event["family"] != family
                        || !matches!(
                            event["direction"].as_str(),
                            Some("client-to-service" | "service-to-client")
                        )
                        || event["frame_sha256"]
                            .as_str()
                            .is_none_or(|hash| !hex(hash, 64))
                        || event["canonical_message_sha256"]
                            .as_str()
                            .is_none_or(|hash| !hex(hash, 64))
                })
            {
                return Err(HostKeyPinError::InvalidTapJournal);
            }
            families.insert(family);
            events = events
                .checked_add(wire_events.len())
                .ok_or(HostKeyPinError::InvalidTapJournal)?;
            bytes = bytes
                .checked_add(wire_bytes)
                .ok_or(HostKeyPinError::InvalidTapJournal)?;
        }
        let journal_sha256 = digest(journal_raw);
        if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
            || report["run_id"] != self.pins.job_id
            || report["source_sha"] != self.pins.source_sha
            || report["provisional_config_digest"] != self.pins.deployment_digest
            || report["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || report["execution_eligible"] != false
            || report["record_scored"] != false
            || !matches!(
                (
                    report["sdk_tap_v2"]["schema"].as_str(),
                    report["sdk_tap_v2"]["native_peer_independently_observed_by_root"].as_bool()
                ),
                (Some("hol-gauntlet-staging-sdk-tap-summary.v1"), Some(false))
                    | (Some("hol-gauntlet-staging-sdk-tap-summary.v2"), Some(true))
                    | (Some("hol-gauntlet-staging-sdk-tap-summary.v3"), Some(true))
            )
            || report["sdk_tap_v2"]["execution_eligible"] != false
            || (!root_forwarded && receipt["schema"] != "hol-gauntlet-sdk-tap-journal-receipt.v1")
            || receipt["run_id"] != self.pins.job_id
            || receipt["sha256"] != journal_sha256
            || receipt["bytes"].as_u64() != Some(journal_raw.len() as u64)
            || receipt["sessions"].as_u64() != Some(session_count as u64)
            || receipt["events"].as_u64() != Some(event_count as u64)
            || receipt["child_report_authenticated"] != false
            || receipt["host_pin_retained"] != false
            || receipt["execution_eligible"] != false
            || (!root_forwarded && journal["schema"] != "hol-gauntlet-sdk-tap-journal.v1")
            || journal["run_id"] != self.pins.job_id
            || journal["source_sha"] != self.pins.source_sha
            || journal["started_marker_sha256"] != self.pins.started_marker_sha256
            || journal["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || journal["child_report_authenticated"] != false
            || journal["host_pin_retained"] != false
            || journal["execution_eligible"] != false
            || session_count != sessions.len()
            || families.len() != 2
            || events != event_count
            || bytes != observed_bytes
        {
            return Err(HostKeyPinError::InvalidTapJournal);
        }
        Ok(HostSdkTapJournalPin {
            run_id: self.pins.job_id.clone(),
            host_key_record_sha256: self.raw_sha256.clone(),
            terminal_sha256: terminal.terminal_sha256,
            report_sha256: terminal.report_sha256,
            journal_sha256,
            journal_bytes: journal_raw.len(),
            sessions: session_count,
            events: event_count,
            observed_bytes,
            raw_sha256: String::new(),
        })
    }
}

impl HostControllerKeyPinJournal {
    /// Read only three fixed guest files through a bounded Lima transport,
    /// then pin their hashes outside the VM. The guest `cat` path and Lima VM
    /// are fixed here, but executable/VM identity and guest file metadata are
    /// not independently attested by this diagnostic.
    pub fn record_sdk_tap_from_lima_ineligible(
        &self,
        run_id: &str,
    ) -> Result<HostSdkTapJournalPin, HostKeyPinError> {
        match self.read_sdk_tap_journal_pin(run_id) {
            Ok(_) => return Err(HostKeyPinError::AlreadyRecorded),
            Err(HostKeyPinError::Missing) => {}
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
        let journal = read("sdk-tap.json", MAX_JOURNAL_BYTES)?;
        self.record_sdk_tap_journal_diagnostic(run_id, &terminal, &report, &journal)
    }

    fn staged_input(&self, name: &str, maximum: u64) -> Result<Vec<u8>, HostKeyPinError> {
        self.stable_directory()?;
        let descriptor = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| HostKeyPinError::UnsafeRecord)?;
        let before = fstat(&descriptor).map_err(|_| HostKeyPinError::Io)?;
        let visible = statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner
            || before.st_nlink != 1
            || before.st_mode & 0o7777 != 0o600
            || before.st_size <= 0
            || before.st_size as u64 > maximum
            || !same_file(&before, &visible)
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        let mut file = File::from(descriptor);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HostKeyPinError::Io)?;
        let after = fstat(&file).map_err(|_| HostKeyPinError::Io)?;
        let visible = statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| HostKeyPinError::Changed)?;
        if bytes.len() as i64 != before.st_size
            || !same_file(&before, &after)
            || !same_file(&before, &visible)
        {
            return Err(HostKeyPinError::Changed);
        }
        self.stable_directory()?;
        Ok(bytes)
    }

    /// Consume three previously staged, owner-only transfer files. Their
    /// transport provenance is not established by this method; a reviewed
    /// guest readout and Lima channel must bind them for a final verdict.
    pub fn record_sdk_tap_from_staged_files(
        &self,
        run_id: &str,
    ) -> Result<HostSdkTapJournalPin, HostKeyPinError> {
        if !hex(run_id, 16) {
            return Err(HostKeyPinError::InvalidPins);
        }
        let terminal = self.staged_input(&format!("{run_id}.terminal.json"), 2048)?;
        let report = self.staged_input(&format!("{run_id}.report.json"), 16 * 1024 * 1024)?;
        let journal =
            self.staged_input(&format!("{run_id}.sdk-tap.json"), MAX_JOURNAL_BYTES as u64)?;
        self.record_sdk_tap_journal_diagnostic(run_id, &terminal, &report, &journal)
    }

    /// Fsync an immutable host digest after rereading the prelaunch key pin.
    /// A partial write consumes the run ID; callers must reconcile, not retry.
    pub fn record_sdk_tap_journal_diagnostic(
        &self,
        run_id: &str,
        terminal_raw: &[u8],
        report_raw: &[u8],
        journal_raw: &[u8],
    ) -> Result<HostSdkTapJournalPin, HostKeyPinError> {
        let key = self.read(run_id)?;
        let observed = key.observe_sdk_tap_journal(terminal_raw, report_raw, journal_raw)?;
        let bytes = canonicalize(observed.record_value().to_string().as_bytes())
            .map_err(|_| HostKeyPinError::InvalidTapJournal)?;
        if bytes.len() as u64 > MAX_PIN_BYTES {
            return Err(HostKeyPinError::InvalidTapJournal);
        }
        self.stable_directory()?;
        let name = format!("{run_id}.sdk-tap-pin.json");
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
        self.stable_directory()?;
        let retained = self.read_sdk_tap_journal_pin(run_id)?;
        if retained.run_id != observed.run_id
            || retained.host_key_record_sha256 != observed.host_key_record_sha256
            || retained.terminal_sha256 != observed.terminal_sha256
            || retained.report_sha256 != observed.report_sha256
            || retained.journal_sha256 != observed.journal_sha256
            || retained.journal_bytes != observed.journal_bytes
            || retained.sessions != observed.sessions
            || retained.events != observed.events
            || retained.observed_bytes != observed.observed_bytes
            || self.read(run_id)?.raw_sha256 != key.raw_sha256
        {
            return Err(HostKeyPinError::Changed);
        }
        Ok(retained)
    }

    /// Reopen a retained digest after interruption. The guest bytes must be
    /// supplied again to `observe_sdk_tap_journal` before interpretation.
    pub fn read_sdk_tap_journal_pin(
        &self,
        run_id: &str,
    ) -> Result<HostSdkTapJournalPin, HostKeyPinError> {
        if !hex(run_id, 16) {
            return Err(HostKeyPinError::InvalidPins);
        }
        self.stable_directory()?;
        let name = format!("{run_id}.sdk-tap-pin.json");
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
            || canonicalize(&bytes).map_err(|_| HostKeyPinError::UnsafeRecord)? != bytes
        {
            return Err(HostKeyPinError::Changed);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| HostKeyPinError::UnsafeRecord)?;
        let parse_hash = |field: &str| {
            value[field]
                .as_str()
                .filter(|raw| hex(raw, 64))
                .map(str::to_owned)
                .ok_or(HostKeyPinError::UnsafeRecord)
        };
        let record = HostSdkTapJournalPin {
            run_id: run_id.to_owned(),
            host_key_record_sha256: parse_hash("host_key_record_sha256")?,
            terminal_sha256: parse_hash("terminal_sha256")?,
            report_sha256: parse_hash("report_sha256")?,
            journal_sha256: parse_hash("journal_sha256")?,
            journal_bytes: count(&value["journal_bytes"], MAX_JOURNAL_BYTES)
                .ok_or(HostKeyPinError::UnsafeRecord)?,
            sessions: count(&value["sessions"], 16).ok_or(HostKeyPinError::UnsafeRecord)?,
            events: count(&value["events"], 1000).ok_or(HostKeyPinError::UnsafeRecord)?,
            observed_bytes: count(&value["observed_bytes"], 12 * 1024 * 1024)
                .ok_or(HostKeyPinError::UnsafeRecord)?,
            raw_sha256: digest(&bytes),
        };
        if value != record.record_value()
            || self.read(run_id)?.raw_sha256 != record.host_key_record_sha256
        {
            return Err(HostKeyPinError::UnsafeRecord);
        }
        self.stable_directory()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostControllerKeyPins;
    use std::os::unix::fs::PermissionsExt;

    fn canonical(value: Value) -> Vec<u8> {
        canonicalize(value.to_string().as_bytes()).unwrap()
    }

    fn sample() -> (
        tempfile::TempDir,
        HostControllerKeyPinJournal,
        HostKeyPinRecord,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = temp.path().canonicalize().unwrap();
        let host = HostControllerKeyPinJournal::open(&directory).unwrap();
        let pins = HostControllerKeyPins {
            job_id: "0123456789abcdef".to_owned(),
            source_sha: "a".repeat(40),
            deployment_digest: "b".repeat(64),
            worker_generation: "c".repeat(64),
            started_marker_sha256: "d".repeat(64),
            controller_key_pin_sha256: "e".repeat(64),
            controller_public_key_hex: "f".repeat(64),
        };
        let key = host.record(&pins).unwrap();
        let sessions = ["docs", "mail"]
            .into_iter()
            .enumerate()
            .map(|(index, family)| {
                json!({
                    "sequence":index + 1,
                    "family":family,
                    "sdk_peer":{"pid":100 + index,"start_ticks":10,"cgroup":"/agent","uid":10001,"gid":10001},
                    "native_peer":{"pid":200,"start_ticks":20,"cgroup":"/controller","uid":0,"gid":0},
                    "sdk_ancestry":{"relay_pid":100 + index,"ancestor_pid":90,"ancestor_start_ticks":9,"cgroup":"/agent","hops":1},
                    "wire":{
                        "schema":"hol-gauntlet-sdk-wire-tap.v1",
                        "events":[{"sequence":1,"family":family,"direction":"client-to-service","frame_sha256":"1".repeat(64),"canonical_message_sha256":"2".repeat(64),"frame_bytes":35,"method":"notifications/initialized","id_json":null}],
                        "completed_tool_calls":0,"total_bytes":35,
                        "peer_identity_verified":false,"journal_durable":false,"execution_eligible":false
                    }
                })
            })
            .collect::<Vec<_>>();
        let journal = canonical(json!({
            "schema":"hol-gauntlet-sdk-tap-journal.v1",
            "run_id":pins.job_id,"source_sha":pins.source_sha,
            "started_marker_sha256":pins.started_marker_sha256,
            "controller_public_key_hex":pins.controller_public_key_hex,
            "sessions":sessions,"session_count":2,"event_count":2,"observed_bytes":70,
            "child_report_authenticated":false,"host_pin_retained":false,"execution_eligible":false
        }));
        let report = canonical(json!({
            "schema":"hol-gauntlet-staging-control-run-report.v1",
            "run_id":pins.job_id,"source_sha":pins.source_sha,
            "provisional_config_digest":pins.deployment_digest,
            "controller_public_key_hex":pins.controller_public_key_hex,
            "record_scored":false,"execution_eligible":false,
            "sdk_tap_v2":{
                "schema":"hol-gauntlet-staging-sdk-tap-summary.v1",
                "native_peer_independently_observed_by_root":false,"execution_eligible":false,
                "journal":{
                    "schema":"hol-gauntlet-sdk-tap-journal-receipt.v1",
                    "run_id":pins.job_id,"sha256":digest(&journal),"bytes":journal.len(),
                    "sessions":2,"events":2,"child_report_authenticated":false,
                    "host_pin_retained":false,"execution_eligible":false
                }
            }
        }));
        let terminal = canonical(json!({
            "schema":"hol-gauntlet-worker-terminal.v2",
            "job_id":pins.job_id,"source_sha":pins.source_sha,
            "deployment_digest":pins.deployment_digest,
            "worker_generation":pins.worker_generation,
            "started_marker_sha256":pins.started_marker_sha256,
            "controller_key_pin_sha256":pins.controller_key_pin_sha256,
            "controller_public_key_hex":pins.controller_public_key_hex,
            "report_sha256":digest(&report),
            "pid":321,"process_start_ticks":1234,"exit_code":0,"status":"invalid-evidence"
        }));
        (temp, host, key, terminal, report, journal)
    }

    #[test]
    fn host_pins_completed_tap_once_and_refuses_changed_or_missing_evidence() {
        let (temp, host, key, terminal, report, journal) = sample();
        let run_id = &key.pins.job_id;
        assert_eq!(
            host.read_sdk_tap_journal_pin(run_id),
            Err(HostKeyPinError::Missing)
        );
        let pin = host
            .record_sdk_tap_journal_diagnostic(run_id, &terminal, &report, &journal)
            .unwrap();
        assert_eq!(pin.journal_sha256, digest(&journal));
        assert_eq!((pin.sessions, pin.events, pin.observed_bytes), (2, 2, 70));
        assert_eq!(host.read_sdk_tap_journal_pin(run_id).unwrap(), pin);
        assert_eq!(
            host.record_sdk_tap_journal_diagnostic(run_id, &terminal, &report, &journal),
            Err(HostKeyPinError::AlreadyRecorded)
        );
        let mut changed = journal.clone();
        changed[0] = b' ';
        assert!(key
            .observe_sdk_tap_journal(&terminal, &report, &changed)
            .is_err());
        let mut value: Value = serde_json::from_slice(&journal).unwrap();
        value["started_marker_sha256"] = json!("0".repeat(64));
        assert_eq!(
            key.observe_sdk_tap_journal(&terminal, &report, &canonical(value)),
            Err(HostKeyPinError::InvalidTapJournal)
        );
        let mut value: Value = serde_json::from_slice(&journal).unwrap();
        value["sessions"].as_array_mut().unwrap().pop();
        assert!(key
            .observe_sdk_tap_journal(&terminal, &report, &canonical(value))
            .is_err());
        let mut value: Value = serde_json::from_slice(&report).unwrap();
        value["sdk_tap_v2"]["journal"]["sha256"] = json!("0".repeat(64));
        assert!(key
            .observe_sdk_tap_journal(&terminal, &canonical(value), &journal)
            .is_err());
        let path = temp.path().join(format!("{run_id}.sdk-tap-pin.json"));
        std::fs::write(&path, b"{}").unwrap();
        assert!(host.read_sdk_tap_journal_pin(run_id).is_err());
    }

    #[test]
    fn host_accepts_only_matching_summary_version_and_root_socket_claim() {
        let (_temp, _host, key, terminal, report, journal) = sample();
        let mut value: Value = serde_json::from_slice(&report).unwrap();
        value["sdk_tap_v2"]["native_peer_independently_observed_by_root"] = json!(true);
        let forged = canonical(value.clone());
        let mut terminal_value: Value = serde_json::from_slice(&terminal).unwrap();
        terminal_value["report_sha256"] = json!(digest(&forged));
        assert_eq!(
            key.observe_sdk_tap_journal(&canonical(terminal_value.clone()), &forged, &journal),
            Err(HostKeyPinError::InvalidTapJournal)
        );
        value["sdk_tap_v2"]["schema"] = json!("hol-gauntlet-staging-sdk-tap-summary.v2");
        let v2 = canonical(value);
        terminal_value["report_sha256"] = json!(digest(&v2));
        assert!(key
            .observe_sdk_tap_journal(&canonical(terminal_value), &v2, &journal)
            .is_ok());
    }

    #[test]
    fn host_distinguishes_root_forwarded_wire_from_child_report() {
        let (_temp, _host, key, terminal, report, journal) = sample();
        let mut journal_value: Value = serde_json::from_slice(&journal).unwrap();
        journal_value["schema"] = json!("hol-gauntlet-sdk-tap-journal.v2");
        journal_value["root_forwarded"] = json!(true);
        journal_value["wire_owner"] = json!("root-forwarded");
        for session in journal_value["sessions"].as_array_mut().unwrap() {
            session["wire_owner"] = json!("root-forwarded");
        }
        let root_journal = canonical(journal_value.clone());
        let mut report_value: Value = serde_json::from_slice(&report).unwrap();
        report_value["sdk_tap_v2"]["schema"] = json!("hol-gauntlet-staging-sdk-tap-summary.v3");
        report_value["sdk_tap_v2"]["native_peer_independently_observed_by_root"] = json!(true);
        report_value["sdk_tap_v2"]["root_forwarded"] = json!(true);
        report_value["sdk_tap_v2"]["journal"]["schema"] =
            json!("hol-gauntlet-sdk-tap-journal-receipt.v2");
        report_value["sdk_tap_v2"]["journal"]["root_forwarded"] = json!(true);
        report_value["sdk_tap_v2"]["journal"]["sha256"] = json!(digest(&root_journal));
        report_value["sdk_tap_v2"]["journal"]["bytes"] = json!(root_journal.len());
        let root_report = canonical(report_value.clone());
        let mut terminal_value: Value = serde_json::from_slice(&terminal).unwrap();
        terminal_value["report_sha256"] = json!(digest(&root_report));
        let root_terminal = canonical(terminal_value.clone());
        assert!(key
            .observe_sdk_tap_journal(&root_terminal, &root_report, &root_journal)
            .is_ok());
        journal_value["sessions"][0]
            .as_object_mut()
            .unwrap()
            .remove("wire_owner");
        assert!(key
            .observe_sdk_tap_journal(&root_terminal, &root_report, &canonical(journal_value))
            .is_err());
        report_value["sdk_tap_v2"]["journal"]["root_forwarded"] = json!(false);
        let false_report = canonical(report_value);
        terminal_value["report_sha256"] = json!(digest(&false_report));
        assert!(key
            .observe_sdk_tap_journal(&canonical(terminal_value), &false_report, &root_journal)
            .is_err());
    }

    #[test]
    fn staged_transfer_files_require_private_stable_custody() {
        let (temp, host, key, terminal, report, journal) = sample();
        let run_id = &key.pins.job_id;
        for (suffix, bytes) in [
            ("terminal.json", terminal.as_slice()),
            ("report.json", report.as_slice()),
            ("sdk-tap.json", journal.as_slice()),
        ] {
            let path = temp.path().join(format!("{run_id}.{suffix}"));
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let report_path = temp.path().join(format!("{run_id}.report.json"));
        std::fs::set_permissions(&report_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            host.record_sdk_tap_from_staged_files(run_id),
            Err(HostKeyPinError::UnsafeRecord)
        );
        std::fs::set_permissions(&report_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let pinned = host.record_sdk_tap_from_staged_files(run_id).unwrap();
        assert_eq!(pinned.journal_sha256, digest(&journal));
        assert_eq!(
            host.record_sdk_tap_from_staged_files(run_id),
            Err(HostKeyPinError::AlreadyRecorded)
        );
    }

    #[test]
    fn vm_readout_uses_only_fixed_guest_paths() {
        let argv = fixed_guest_readout_argv("0123456789abcdef", "sdk-tap.json").unwrap();
        assert_eq!(
            argv[1..7],
            [
                "shell",
                "hol-beta-bootstrap-20261016-004",
                "--",
                "sudo",
                "-n",
                "cat"
            ]
        );
        assert_eq!(
            argv[7],
            "/var/lib/hol-gauntlet-rust/staging-state/0123456789abcdef.sdk-tap.json"
        );
        assert!(fixed_guest_readout_argv("../bad", "sdk-tap.json").is_err());
        assert!(fixed_guest_readout_argv("0123456789abcdef", "started.json").is_err());
    }
}
