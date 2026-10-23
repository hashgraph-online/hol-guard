//! One-use Root journal for kernel-observed staging close-write events.
//! This records evidence for later outside scoring and never admits a run.

use crate::linux_process::valid_cgroup;
use crate::staging_effect_events::{FinishedStagingEffectEvents, MAX_EFFECT_EVENTS};
use crate::{hex, ActiveLease, RunReservationJournal, StartedMarker};
use gauntlet_contracts::{
    canonicalize, validate_effect_writer_images, EffectFileHandle, EFFECT_IMAGE_JOURNAL_SCHEMA,
    EFFECT_IMAGE_RECEIPT_SCHEMA, MAX_RECORD_BYTES,
};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};

const MAX_JOURNAL_BYTES: usize = MAX_RECORD_BYTES;
const SCHEMA: &str = "hol-gauntlet-staging-effect-events.v2";
const LEGACY_SCHEMA: &str = "hol-gauntlet-staging-effect-events.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectJournalReceipt {
    pub run_id: String,
    pub sha256: String,
    pub bytes: usize,
    pub events: usize,
    pub unknown_writers: usize,
    pub writer_images_captured: bool,
}

impl EffectJournalReceipt {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":if self.writer_images_captured { EFFECT_IMAGE_RECEIPT_SCHEMA } else { "hol-gauntlet-staging-effect-events-receipt.v2" },
            "run_id":self.run_id,
            "sha256":self.sha256,
            "bytes":self.bytes,
            "events":self.events,
            "unknown_writers":self.unknown_writers,
            "host_pin_retained":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
        })
    }
}

fn name(run_id: &str) -> Result<String, String> {
    if !hex(run_id, 16) {
        return Err("exact staging effect run ID required".to_owned());
    }
    Ok(format!("{run_id}.effect-events.json"))
}

fn require_started(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
) -> Result<(), String> {
    if !journal.root_owned || started.controller_public_key_hex.is_none() {
        return Err("Root-owned keyed staging effect journal required".to_owned());
    }
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    if journal
        .started(
            &started.job_id,
            &started.source_sha,
            &started.deployment_digest,
            &started.worker_generation,
        )
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(started)
    {
        return Err("effect journal differs from keyed started marker".to_owned());
    }
    Ok(())
}

fn exact_file(stat: &rustix::fs::Stat, size: usize) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_size == size as i64
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn journal_bytes(
    started: &StartedMarker,
    finished: &FinishedStagingEffectEvents,
) -> Result<(Vec<u8>, usize, usize), String> {
    let events = finished.events();
    if events.len() > MAX_EFFECT_EVENTS {
        return Err("staging effect event bound exceeded".to_owned());
    }
    let mut rows = Vec::with_capacity(events.len());
    let mut unknown = 0;
    for (index, event) in events.iter().enumerate() {
        if event.device == 0 || event.inode == 0 || event.reported_pid == 0 {
            return Err("staging effect event lacks inode identity".to_owned());
        }
        let writer = if let Some(writer) = &event.writer {
            if writer.pid != event.reported_pid
                || !event.pidfd_available
                || writer.start_ticks == 0
                || !valid_cgroup(&writer.cgroup)
            {
                return Err("staging effect writer identity malformed".to_owned());
            }
            json!({
                "pid":writer.pid,
                "start_ticks":writer.start_ticks,
                "cgroup":writer.cgroup,
            })
        } else {
            unknown += 1;
            Value::Null
        };
        rows.push(json!({
            "sequence":index + 1,
            "device":event.device,
            "inode":event.inode,
            "owner":event.owner,
            "file_handle":event.file_handle.as_ref().map(EffectFileHandle::to_json),
            "reported_pid":event.reported_pid,
            "pidfd_available":event.pidfd_available,
            "writer":writer,
        }));
    }
    let mut document = json!({
        "schema":SCHEMA,
        "run_id":started.job_id,
        "source_sha":started.source_sha,
        "started_marker_sha256":started.sha256,
        "controller_public_key_hex":started.controller_public_key_hex,
        "scope":"watched-filesystem-close-write",
        "events":rows,
        "event_count":events.len(),
        "unknown_writer_count":unknown,
        "host_pin_retained":false,
        "guard_causality_verified":false,
        "execution_eligible":false,
    });
    if let Some(images) = finished.writer_images() {
        let images = json!(images);
        if !validate_effect_writer_images(&images, document["events"].as_array().unwrap()) {
            return Err("staging effect writer images malformed".to_owned());
        }
        document["schema"] = json!(EFFECT_IMAGE_JOURNAL_SCHEMA);
        document["writer_images"] = images;
    }
    let raw = canonicalize(document.to_string().as_bytes()).map_err(|error| error.to_string())?;
    if raw.len() > MAX_JOURNAL_BYTES {
        return Err("staging effect journal byte bound exceeded".to_owned());
    }
    Ok((raw, events.len(), unknown))
}

pub fn retain_staging_effect_journal_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    finished: &FinishedStagingEffectEvents,
) -> Result<EffectJournalReceipt, String> {
    require_started(journal, lease, started)?;
    let (raw, events, unknown_writers) = journal_bytes(started, finished)?;
    let name = name(&started.job_id)?;
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("one-use effect journal unavailable: {error}"))?;
    if !exact_file(&fstat(&descriptor).map_err(|error| error.to_string())?, 0) {
        return Err("effect journal lacks Root-only custody".to_owned());
    }
    let mut file = File::from(descriptor);
    file.write_all(&raw).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fsync(&journal.root).map_err(|error| error.to_string())?;
    let held = fstat(&file).map_err(|error| error.to_string())?;
    let visible = statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    if !exact_file(&held, raw.len())
        || !exact_file(&visible, raw.len())
        || held.st_dev != visible.st_dev
        || held.st_ino != visible.st_ino
    {
        return Err("effect journal changed during write".to_owned());
    }
    require_started(journal, lease, started)?;
    Ok(EffectJournalReceipt {
        run_id: started.job_id.clone(),
        sha256: format!("{:x}", Sha256::digest(&raw)),
        bytes: raw.len(),
        events,
        unknown_writers,
        writer_images_captured: finished.writer_images().is_some(),
    })
}

pub fn read_staging_effect_journal_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    outside_sha256: &str,
) -> Result<Vec<u8>, String> {
    require_started(journal, lease, started)?;
    if !hex(outside_sha256, 64) {
        return Err("outside effect journal digest required".to_owned());
    }
    let name = name(&started.job_id)?;
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("effect journal unavailable: {error}"))?;
    let before = fstat(&descriptor).map_err(|error| error.to_string())?;
    if before.st_size <= 0
        || before.st_size > MAX_JOURNAL_BYTES as i64
        || !exact_file(&before, before.st_size as usize)
    {
        return Err("effect journal has unsafe metadata".to_owned());
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    let after = fstat(&file).map_err(|error| error.to_string())?;
    let visible = statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    if raw.len() != before.st_size as usize
        || !exact_file(&after, raw.len())
        || !exact_file(&visible, raw.len())
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_dev != visible.st_dev
        || before.st_ino != visible.st_ino
        || format!("{:x}", Sha256::digest(&raw)) != outside_sha256
        || canonicalize(&raw).map_err(|error| error.to_string())? != raw
    {
        return Err("effect journal differs from outside pin".to_owned());
    }
    let document: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    let images = document["schema"] == EFFECT_IMAGE_JOURNAL_SCHEMA;
    let mut fields = vec![
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
        fields.push("writer_images");
    }
    if !exact_keys(&document, &fields)
        || (document["schema"] != SCHEMA && document["schema"] != LEGACY_SCHEMA && !images)
        || document["run_id"] != started.job_id
        || document["source_sha"] != started.source_sha
        || document["started_marker_sha256"] != started.sha256
        || document["controller_public_key_hex"].as_str()
            != started.controller_public_key_hex.as_deref()
        || document["scope"] != "watched-filesystem-close-write"
        || document["host_pin_retained"] != false
        || document["guard_causality_verified"] != false
        || document["execution_eligible"] != false
    {
        return Err("effect journal identity differs from keyed run".to_owned());
    }
    let rows = document["events"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_EFFECT_EVENTS)
        .ok_or("effect journal events are malformed")?;
    let mut unknown = 0;
    let handles = document["schema"] == SCHEMA || images;
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
                return Err("effect journal file handle is invalid".to_owned());
            }
        }
        if !exact_keys(row, &fields)
            || row["sequence"].as_u64() != Some(index as u64 + 1)
            || row["device"].as_u64().is_none_or(|value| value == 0)
            || row["inode"].as_u64().is_none_or(|value| value == 0)
            || row["owner"]
                .as_u64()
                .is_none_or(|value| value > u32::MAX as u64)
            || row["reported_pid"]
                .as_u64()
                .is_none_or(|value| value == 0 || value > u32::MAX as u64)
            || !row["pidfd_available"].is_boolean()
        {
            return Err("effect journal event shape is invalid".to_owned());
        }
        let writer = &row["writer"];
        if writer.is_null() {
            unknown += 1;
        } else if !exact_keys(writer, &["pid", "start_ticks", "cgroup"])
            || row["pidfd_available"] != true
            || writer["pid"] != row["reported_pid"]
            || writer["start_ticks"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || !writer["cgroup"].as_str().is_some_and(valid_cgroup)
        {
            return Err("effect journal writer shape is invalid".to_owned());
        }
    }
    if document["event_count"].as_u64() != Some(rows.len() as u64)
        || document["unknown_writer_count"].as_u64() != Some(unknown as u64)
        || images && !validate_effect_writer_images(&document["writer_images"], rows)
    {
        return Err("effect journal event totals differ".to_owned());
    }
    require_started(journal, lease, started)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staging_effect_events::StagingEffectEvents;
    use gauntlet_contracts::WorkerRequest;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    #[ignore = "requires dedicated Linux ARM64 Root VM fanotify and private journal"]
    fn keyed_journal_is_one_use_and_reader_requires_outside_digest() {
        check_keyed_journal(false);
        check_keyed_journal(true);
    }

    fn check_keyed_journal(images: bool) {
        let state = tempfile::tempdir_in("/root").unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(state.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let request = WorkerRequest::parse(br#"{"action":"run","deployment_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","job_id":"a1b2c3d4e5f60718","schema":"hol-gauntlet-worker-request.v1","source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).unwrap();
        let started = journal
            .reserve_keyed_under_lease(
                &lease,
                &request,
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
                &"d".repeat(64),
            )
            .unwrap();
        let mut monitor = if images {
            StagingEffectEvents::start_for_run(
                Path::new("/home"),
                &started.job_id,
                crate::StagingRole::Success,
            )
        } else {
            StagingEffectEvents::start(Path::new("/home"))
        }
        .unwrap();
        let effect_dir = tempfile::tempdir_in("/home").unwrap();
        std::fs::write(effect_dir.path().join("effect.txt"), b"synthetic-effect").unwrap();
        monitor.drain().unwrap();
        let finished = monitor.finish().unwrap();
        let receipt =
            retain_staging_effect_journal_ineligible(&journal, &lease, &started, &finished)
                .unwrap();
        assert!(receipt.events >= 1);
        assert_eq!(receipt.to_json()["execution_eligible"], false);
        let raw =
            read_staging_effect_journal_ineligible(&journal, &lease, &started, &receipt.sha256)
                .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&raw)), receipt.sha256);
        let document: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            document["schema"],
            if images {
                EFFECT_IMAGE_JOURNAL_SCHEMA
            } else {
                SCHEMA
            }
        );
        if images {
            assert_eq!(document["writer_images"], json!([]));
        }
        assert!(
            retain_staging_effect_journal_ineligible(&journal, &lease, &started, &finished)
                .is_err()
        );
        assert!(read_staging_effect_journal_ineligible(
            &journal,
            &lease,
            &started,
            &"e".repeat(64),
        )
        .is_err());
    }
}
