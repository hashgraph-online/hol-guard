//! Root readback of a fixed contained output, signed control and Native writer
//! image. All inputs share outside run/config/report/journal pins. The result
//! remains diagnostic until the request-to-writer causal boundary is observed.

use crate::staging_effect_file::{correlate_rows, open_fixed_effect_file, same_file};
use crate::staging_effect_journal::read_staging_effect_journal_ineligible;
use crate::staging_file_handle::sample_file_handle;
use crate::staging_product_effect::{matching_sample, read_report};
use crate::{open_root_owned_public_directory, ActiveLease, RunReservationJournal, StartedMarker};
use gauntlet_contracts::EFFECT_IMAGE_JOURNAL_SCHEMA;
use gauntlet_evidence::{
    observe_staging_contained_relation_root_owned_ineligible, ContainedFileIdentity,
    StagingEvidencePins,
};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const CONTENTS: &[u8] = b"private plane effect";

pub fn observe_staging_contained_effect_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    pins: &StagingEvidencePins<'_>,
    outside_journal_sha256: &str,
    outside_report_sha256: &str,
) -> Result<Value, String> {
    if !journal.root_owned
        || pins.run_id != started.job_id
        || pins.source_sha != started.source_sha
        || pins.config_digest != started.deployment_digest
        || Some(pins.controller_public_key_hex) != started.controller_public_key_hex.as_deref()
        || !matches!(
            pins.role,
            "success" | "input-binding" | "injection" | "boundary"
        )
    {
        return Err("contained effect requires one keyed positive control run".to_owned());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    let report = read_report(journal, started, outside_report_sha256, pins.role)?;
    if report["build_job_id"] != pins.build_job_id
        || report["effect_events"]["sha256"] != outside_journal_sha256
    {
        return Err("contained control and event journal differ from the pinned report".to_owned());
    }
    let product = matching_sample(&report, pins.run_id, pins.role)?;
    let raw =
        read_staging_effect_journal_ineligible(journal, lease, started, outside_journal_sha256)?;
    let events: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if events["schema"] != EFFECT_IMAGE_JOURNAL_SCHEMA {
        return Err("contained effect requires a v3 process-image journal".to_owned());
    }
    let parent_path = format!("/home/hx-{}/{}/tasks", pins.run_id, pins.role);
    let parent =
        open_root_owned_public_directory(Path::new(&parent_path)).map_err(|e| e.to_string())?;
    let parent_stat = fstat(&parent).map_err(|e| e.to_string())?;
    let open_task = || {
        openat(
            &parent,
            "checkout",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())
    };
    let task = open_task()?;
    let task_stat = fstat(&task).map_err(|e| e.to_string())?;
    let task_row = product["task_mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["source"] == format!("{parent_path}/checkout"))
        .ok_or("contained checkout kernel map missing")?;
    if FileType::from_raw_mode(task_stat.st_mode) != FileType::Directory
        || task_stat.st_uid != 10001
        || task_stat.st_gid != 10001
        || task_stat.st_mode & 0o7777 != 0o755
        || task_row["device"].as_u64() != Some(task_stat.st_dev)
        || task_row["inode"].as_u64() != Some(task_stat.st_ino)
    {
        return Err("contained checkout differs from the observed idmapped task".to_owned());
    }
    let (file, stat) = open_fixed_effect_file(&task, "native-contained.txt", 10001, CONTENTS)?;
    if stat.st_gid != 10001 {
        return Err("contained file group differs from physical task owner".to_owned());
    }
    let handle = sample_file_handle(&file)?;
    let (close_writes, _) = correlate_rows(
        &raw,
        &stat,
        10004,
        product["cgroup"].as_str().unwrap(),
        Some(&handle),
    )?;
    let relation = observe_staging_contained_relation_root_owned_ineligible(
        pins,
        product,
        &events,
        &ContainedFileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            handle: handle.clone(),
        },
    )
    .map_err(|e| e.to_string())?;
    let visible_parent =
        open_root_owned_public_directory(Path::new(&parent_path)).map_err(|e| e.to_string())?;
    let visible_task = openat(
        &visible_parent,
        "checkout",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let (visible_file, visible_stat) =
        open_fixed_effect_file(&visible_task, "native-contained.txt", 10001, CONTENTS)?;
    if !same_file(
        &parent_stat,
        &fstat(&visible_parent).map_err(|e| e.to_string())?,
    ) || !same_file(&task_stat, &fstat(&task).map_err(|e| e.to_string())?)
        || !same_file(
            &task_stat,
            &fstat(&visible_task).map_err(|e| e.to_string())?,
        )
        || !same_file(&stat, &fstat(&file).map_err(|e| e.to_string())?)
        || !same_file(&stat, &visible_stat)
        || sample_file_handle(&file)? != handle
        || sample_file_handle(&visible_file)? != handle
        || report != read_report(journal, started, outside_report_sha256, pins.role)?
        || raw
            != read_staging_effect_journal_ineligible(
                journal,
                lease,
                started,
                outside_journal_sha256,
            )?
    {
        return Err("contained evidence changed during composed readback".to_owned());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"hol-gauntlet-staging-contained-effect-shadow.v1",
        "run_id":pins.run_id,"build_job_id":pins.build_job_id,"role":pins.role,"source_sha":pins.source_sha,
        "config_sha256":pins.config_digest,"worker_generation_sha256":started.worker_generation,
        "outside_report_sha256":outside_report_sha256,"outside_journal_sha256":outside_journal_sha256,
        "final_bytes":CONTENTS.len(),"final_sha256":format!("{:x}",Sha256::digest(CONTENTS)),
        "device":stat.st_dev,"inode":stat.st_ino,"file_handle":handle.to_json(),"close_writes":close_writes,
        "physical_owner_uid":10001,"event_view_owner_uid":10004,"held_final_file_checked":true,
        "file_generation_verified":true,"idmap_kernel_verified":true,"native_asset_rechecked":true,
        "signed_reported_relations_verified":true,"contained_relation":relation,
        "request_to_writer_causality_verified":false,"guard_causality_verified":false,"execution_eligible":false}),
    )
}
