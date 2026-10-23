//! One-use Root journal for completed SDK tap diagnostics. Child reports and
//! their frame bytes still need independent authentication before eligibility.

use crate::{
    hex,
    linux_process::valid_cgroup,
    sdk_wire_peer::{SdkWireAncestryObservation, SdkWirePeerObservation},
    sdk_wire_tap::SdkWireObservation,
    ActiveLease, RunReservationJournal, StartedMarker,
};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};

const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_SESSIONS: usize = 16;
const MAX_EVENTS: usize = 1_000;
const MAX_OBSERVED_BYTES: usize = 12 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkTapWireOwner {
    ChildReport,
    RootForwarded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkTapRetainedSession {
    pub wire_owner: SdkTapWireOwner,
    pub family: String,
    pub sdk_peer: SdkWirePeerObservation,
    pub native_peer: SdkWirePeerObservation,
    pub sdk_ancestry: SdkWireAncestryObservation,
    pub wire: SdkWireObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkTapJournalReceipt {
    pub wire_owner: SdkTapWireOwner,
    pub run_id: String,
    pub sha256: String,
    pub bytes: usize,
    pub sessions: usize,
    pub events: usize,
}

impl SdkTapJournalReceipt {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schema":"hol-gauntlet-sdk-tap-journal-receipt.v1",
            "run_id":self.run_id,
            "sha256":self.sha256,
            "bytes":self.bytes,
            "sessions":self.sessions,
            "events":self.events,
            "child_report_authenticated":false,
            "host_pin_retained":false,
            "execution_eligible":false,
        });
        if self.wire_owner == SdkTapWireOwner::RootForwarded {
            value["schema"] = json!("hol-gauntlet-sdk-tap-journal-receipt.v2");
            value["root_forwarded"] = json!(true);
        }
        value
    }
}

fn journal_name(run_id: &str) -> Result<String, String> {
    if !hex(run_id, 16) {
        return Err("fixed SDK tap run ID required".to_owned());
    }
    Ok(format!("{run_id}.sdk-tap.json"))
}

fn require_started(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
) -> Result<(), String> {
    if !journal.root_owned {
        return Err("Root-owned SDK tap journal required".to_owned());
    }
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    let retained = journal
        .started(
            &started.job_id,
            &started.source_sha,
            &started.deployment_digest,
            &started.worker_generation,
        )
        .map_err(|error| error.to_string())?;
    if retained.as_ref() != Some(started) || started.controller_public_key_hex.is_none() {
        return Err("SDK tap journal differs from keyed started marker".to_owned());
    }
    Ok(())
}

fn valid_id_json(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    let Ok(raw) = canonicalize(id.as_bytes()) else {
        return false;
    };
    if raw != id.as_bytes() {
        return false;
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::String(value)) => !value.is_empty() && value.len() <= 128,
        Ok(Value::Number(value)) => value.is_i64() || value.is_u64(),
        _ => false,
    }
}

fn validate_session(session: &SdkTapRetainedSession) -> Result<(usize, usize), String> {
    if !matches!(session.family.as_str(), "docs" | "mail")
        || (session.sdk_peer.uid, session.sdk_peer.gid) != (10001, 10001)
        || (session.native_peer.uid, session.native_peer.gid) != (0, 0)
        || session.sdk_peer.pid == session.native_peer.pid
        || session.sdk_peer.pid == 0
        || session.sdk_peer.start_ticks == 0
        || session.native_peer.pid == 0
        || session.native_peer.start_ticks == 0
        || !valid_cgroup(&session.sdk_peer.cgroup)
        || !valid_cgroup(&session.native_peer.cgroup)
        || session.sdk_ancestry.relay_pid != session.sdk_peer.pid
        || session.sdk_ancestry.cgroup != session.sdk_peer.cgroup
        || !(1..=8).contains(&session.sdk_ancestry.hops)
        || session.sdk_ancestry.ancestor_pid == session.sdk_peer.pid
        || session.sdk_ancestry.ancestor_start_ticks == 0
        || session.wire.events.is_empty()
    {
        return Err("SDK tap session identity or shape is invalid".to_owned());
    }
    let mut total = 0_usize;
    for (index, event) in session.wire.events.iter().enumerate() {
        if event.sequence != index + 1
            || event.family != session.family
            || !matches!(event.direction, "client-to-service" | "service-to-client")
            || !hex(&event.frame_sha256, 64)
            || !hex(&event.canonical_message_sha256, 64)
            || !(2..=1024 * 1024 + 1).contains(&event.frame_bytes)
            || event
                .method
                .as_ref()
                .is_some_and(|method| method.is_empty() || method.len() > 256)
            || event
                .id_json
                .as_deref()
                .is_some_and(|id| !valid_id_json(id))
        {
            return Err("SDK tap event metadata is invalid".to_owned());
        }
        total = total
            .checked_add(event.frame_bytes)
            .ok_or("SDK tap byte count overflow")?;
    }
    if total != session.wire.total_bytes
        || total > MAX_OBSERVED_BYTES
        || session.wire.completed_tool_calls > session.wire.events.len() / 2
    {
        return Err("SDK tap session totals differ from events".to_owned());
    }
    Ok((session.wire.events.len(), total))
}

fn journal_bytes(
    started: &StartedMarker,
    sessions: &[SdkTapRetainedSession],
) -> Result<(Vec<u8>, usize, SdkTapWireOwner), String> {
    if sessions.is_empty() || sessions.len() > MAX_SESSIONS {
        return Err("SDK tap session count outside fixed bound".to_owned());
    }
    let mut events = 0_usize;
    let mut bytes = 0_usize;
    let mut docs = false;
    let mut mail = false;
    let mut records = Vec::new();
    let owner = sessions[0].wire_owner;
    for (index, session) in sessions.iter().enumerate() {
        if session.wire_owner != owner {
            return Err("mixed SDK tap wire owners are invalid".to_owned());
        }
        let (count, size) = validate_session(session)?;
        events = events
            .checked_add(count)
            .ok_or("SDK tap event count overflow")?;
        bytes = bytes
            .checked_add(size)
            .ok_or("SDK tap aggregate overflow")?;
        if events > MAX_EVENTS || bytes > MAX_OBSERVED_BYTES {
            return Err("SDK tap aggregate bound exceeded".to_owned());
        }
        docs |= session.family == "docs";
        mail |= session.family == "mail";
        let mut record = json!({
            "sequence":index + 1,
            "family":session.family,
            "sdk_peer":session.sdk_peer.to_json(),
            "native_peer":session.native_peer.to_json(),
            "sdk_ancestry":session.sdk_ancestry.to_json(),
            "wire":session.wire.to_json(),
        });
        if owner == SdkTapWireOwner::RootForwarded {
            record["wire_owner"] = json!("root-forwarded");
        }
        records.push(record);
    }
    if !docs || !mail {
        return Err("both fixed SDK tap families required".to_owned());
    }
    let mut value = json!({
        "schema":"hol-gauntlet-sdk-tap-journal.v1",
        "run_id":started.job_id,
        "source_sha":started.source_sha,
        "started_marker_sha256":started.sha256,
        "controller_public_key_hex":started.controller_public_key_hex,
        "sessions":records,
        "session_count":sessions.len(),
        "event_count":events,
        "observed_bytes":bytes,
        "child_report_authenticated":false,
        "host_pin_retained":false,
        "execution_eligible":false,
    });
    if owner == SdkTapWireOwner::RootForwarded {
        value["schema"] = json!("hol-gauntlet-sdk-tap-journal.v2");
        value["wire_owner"] = json!("root-forwarded");
        value["root_forwarded"] = json!(true);
    }
    let raw = canonicalize(value.to_string().as_bytes()).map_err(|error| error.to_string())?;
    if raw.len() > MAX_JOURNAL_BYTES {
        return Err("SDK tap journal exceeds fixed byte bound".to_owned());
    }
    Ok((raw, events, owner))
}

fn exact_file(stat: &rustix::fs::Stat, size: usize) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_size == size as i64
}

/// Persist a complete, still-ineligible diagnostic under the keyed run.
pub fn retain_sdk_tap_journal_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    sessions: &[SdkTapRetainedSession],
) -> Result<SdkTapJournalReceipt, String> {
    require_started(journal, lease, started)?;
    let (raw, events, wire_owner) = journal_bytes(started, sessions)?;
    let name = journal_name(&started.job_id)?;
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("one-use SDK tap journal unavailable: {error}"))?;
    if !exact_file(&fstat(&descriptor).map_err(|error| error.to_string())?, 0) {
        return Err("SDK tap journal lacks Root-only custody".to_owned());
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
        return Err("SDK tap journal changed during write".to_owned());
    }
    require_started(journal, lease, started)?;
    Ok(SdkTapJournalReceipt {
        wire_owner,
        run_id: started.job_id.clone(),
        sha256: format!("{:x}", Sha256::digest(&raw)),
        bytes: raw.len(),
        sessions: sessions.len(),
        events,
    })
}

/// Read private journal bytes only under an outside digest pin.
pub fn read_sdk_tap_journal_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    outside_sha256: &str,
) -> Result<Vec<u8>, String> {
    require_started(journal, lease, started)?;
    if !hex(outside_sha256, 64) {
        return Err("outside SDK tap journal digest required".to_owned());
    }
    let name = journal_name(&started.job_id)?;
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("SDK tap journal unavailable: {error}"))?;
    let before = fstat(&descriptor).map_err(|error| error.to_string())?;
    if before.st_size <= 0
        || before.st_size > MAX_JOURNAL_BYTES as i64
        || !exact_file(&before, before.st_size as usize)
    {
        return Err("SDK tap journal has unsafe metadata".to_owned());
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
        || !exact_file(&visible, raw.len())
        || !exact_file(&after, raw.len())
        || before.st_dev != visible.st_dev
        || before.st_ino != visible.st_ino
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || format!("{:x}", Sha256::digest(&raw)) != outside_sha256
        || canonicalize(&raw).map_err(|error| error.to_string())? != raw
    {
        return Err("SDK tap journal differs from outside pin".to_owned());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    let root_forwarded = value["schema"] == "hol-gauntlet-sdk-tap-journal.v2";
    let valid_owner = if root_forwarded {
        value["wire_owner"] == "root-forwarded" && value["root_forwarded"] == true
    } else {
        value["schema"] == "hol-gauntlet-sdk-tap-journal.v1"
            && value.get("wire_owner").is_none()
            && value.get("root_forwarded").is_none()
    };
    if !valid_owner
        || value["sessions"].as_array().is_none_or(|sessions| {
            sessions.iter().any(|session| {
                if root_forwarded {
                    session["wire_owner"] != "root-forwarded"
                } else {
                    session.get("wire_owner").is_some()
                }
            })
        })
        || value["run_id"] != started.job_id
        || value["source_sha"] != started.source_sha
        || value["started_marker_sha256"] != started.sha256
        || value["controller_public_key_hex"].as_str()
            != started.controller_public_key_hex.as_deref()
        || value["child_report_authenticated"] != false
        || value["host_pin_retained"] != false
        || value["execution_eligible"] != false
    {
        return Err("SDK tap journal identity differs from keyed run".to_owned());
    }
    require_started(journal, lease, started)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_wire_tap::SdkWireEvent;
    use gauntlet_contracts::WorkerRequest;
    use std::os::unix::fs::PermissionsExt;

    fn session(family: &str) -> SdkTapRetainedSession {
        SdkTapRetainedSession {
            wire_owner: SdkTapWireOwner::ChildReport,
            family: family.to_owned(),
            sdk_peer: SdkWirePeerObservation {
                pid: 100,
                start_ticks: 10,
                cgroup: "/machine.slice/libpod-demo.scope".to_owned(),
                uid: 10001,
                gid: 10001,
            },
            native_peer: SdkWirePeerObservation {
                pid: 200,
                start_ticks: 20,
                cgroup: "/system.slice/worker.service".to_owned(),
                uid: 0,
                gid: 0,
            },
            sdk_ancestry: SdkWireAncestryObservation {
                relay_pid: 100,
                ancestor_pid: 99,
                ancestor_start_ticks: 9,
                cgroup: "/machine.slice/libpod-demo.scope".to_owned(),
                hops: 1,
            },
            wire: SdkWireObservation {
                events: vec![SdkWireEvent {
                    sequence: 1,
                    family: family.to_owned(),
                    direction: "client-to-service",
                    frame_sha256: "a".repeat(64),
                    canonical_message_sha256: "b".repeat(64),
                    frame_bytes: 35,
                    method: Some("notifications/initialized".to_owned()),
                    id_json: None,
                }],
                completed_tool_calls: 0,
                total_bytes: 35,
            },
        }
    }

    #[test]
    fn metadata_refuses_changed_totals_and_invalid_ids() {
        let mut bad = session("mail");
        bad.wire.total_bytes += 1;
        assert!(validate_session(&bad).is_err());
        bad = session("mail");
        bad.wire.events[0].id_json = Some("1.5".to_owned());
        assert!(validate_session(&bad).is_err());
    }

    #[test]
    #[ignore = "requires Linux Root for one-use private staging journal"]
    fn root_journal_is_one_use_and_outside_digest_catches_changed_bytes() {
        let temp = tempfile::tempdir_in("/root").unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(temp.path()).unwrap();
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
        let sessions = [session("docs"), session("mail")];
        let receipt =
            retain_sdk_tap_journal_ineligible(&journal, &lease, &started, &sessions).unwrap();
        assert_eq!((receipt.sessions, receipt.events), (2, 2));
        assert_eq!(receipt.to_json()["execution_eligible"], false);
        let raw =
            read_sdk_tap_journal_ineligible(&journal, &lease, &started, &receipt.sha256).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&raw)), receipt.sha256);
        assert!(retain_sdk_tap_journal_ineligible(&journal, &lease, &started, &sessions).is_err());
        assert!(
            read_sdk_tap_journal_ineligible(&journal, &lease, &started, &"e".repeat(64)).is_err()
        );
        std::fs::write(temp.path().join("a1b2c3d4e5f60718.sdk-tap.json"), b"{}").unwrap();
        assert!(
            read_sdk_tap_journal_ineligible(&journal, &lease, &started, &receipt.sha256).is_err()
        );
    }

    #[test]
    #[ignore = "requires Linux Root for a versioned one-use private SDK tap journal"]
    fn root_forwarded_journal_is_distinct_from_child_report() {
        let temp = tempfile::tempdir_in("/root").unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(temp.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let request = WorkerRequest::parse(br#"{"action":"run","deployment_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","job_id":"a1b2c3d4e5f60719","schema":"hol-gauntlet-worker-request.v1","source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).unwrap();
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
        let mut sessions = [session("docs"), session("mail")];
        sessions[0].wire_owner = SdkTapWireOwner::RootForwarded;
        assert!(retain_sdk_tap_journal_ineligible(&journal, &lease, &started, &sessions).is_err());
        sessions[1].wire_owner = SdkTapWireOwner::RootForwarded;
        let receipt =
            retain_sdk_tap_journal_ineligible(&journal, &lease, &started, &sessions).unwrap();
        assert_eq!(
            receipt.to_json()["schema"],
            "hol-gauntlet-sdk-tap-journal-receipt.v2"
        );
        assert_eq!(receipt.to_json()["root_forwarded"], true);
        let raw =
            read_sdk_tap_journal_ineligible(&journal, &lease, &started, &receipt.sha256).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["schema"], "hol-gauntlet-sdk-tap-journal.v2");
        assert_eq!(value["root_forwarded"], true);
        assert_eq!(value["sessions"][0]["wire_owner"], "root-forwarded");
        assert_eq!(value["sessions"][1]["wire_owner"], "root-forwarded");
        assert!(retain_sdk_tap_journal_ineligible(&journal, &lease, &started, &sessions).is_err());
    }
}
