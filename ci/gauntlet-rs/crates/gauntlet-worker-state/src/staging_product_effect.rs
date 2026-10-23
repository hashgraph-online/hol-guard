//! Correlate retained effects with a separately collected live product sample.
//! The outside report hash must come from the host's retained terminal pin.

use crate::staging_effect_file::observe_staging_fixed_provider_effect_ineligible;
use crate::{
    hex, open_root_owned_public_directory, read_bounded_regular, ActiveLease,
    RunReservationJournal, StartedMarker, TerminalOutcome,
};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

fn exact(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)))
}

fn positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n > 0)
}

pub(crate) fn matching_sample<'a>(
    report: &'a Value,
    run: &str,
    role: &str,
) -> Result<&'a Value, String> {
    let activity = &report["live_product_activity"];
    let sample = &activity["observation"];
    let slice = crate::launch_plan::rust_job_slice_name(run).map_err(|e| e.to_string())?;
    let unit = sample["service"]
        .as_str()
        .ok_or("kernel product service missing")?;
    let unit_id = unit
        .strip_prefix("hol-product-cell-")
        .and_then(|s| s.strip_suffix(".service"))
        .filter(|id| hex(id, 32))
        .ok_or("invalid kernel product service name")?;
    let cgroup = format!("/{slice}/hol-product-cell-{unit_id}.service");
    if !exact(
        activity,
        &[
            "schema",
            "run_id",
            "role",
            "slice_samples",
            "process_attempts",
            "observation",
            "last_unavailable_reason",
            "continuously_observed",
            "guard_causality_verified",
            "execution_eligible",
        ],
    ) || activity["schema"] != "hol-gauntlet-staging-product-kernel.v1"
        || activity["run_id"] != run
        || activity["role"] != role
        || !positive(&activity["slice_samples"])
        || !positive(&activity["process_attempts"])
        || !activity["last_unavailable_reason"].is_null()
        || activity["continuously_observed"] != false
        || activity["guard_causality_verified"] != false
        || activity["execution_eligible"] != false
        || !exact(
            sample,
            &[
                "pid",
                "start_ticks",
                "cgroup",
                "uid",
                "gid",
                "namespace_pid",
                "no_new_privileges",
                "seccomp_mode",
                "namespaces",
                "executable_sha256",
                "argv_sha256",
                "mountinfo_sha256",
                "task_mounts",
                "service",
                "cgroup_device",
                "cgroup_inode",
            ],
        )
        || sample["pid"]
            .as_u64()
            .is_none_or(|p| p == 0 || p > i32::MAX as u64)
        || !positive(&sample["start_ticks"])
        || sample["cgroup"] != cgroup
        || sample["uid"] != 10004
        || sample["gid"] != 10004
        || sample["namespace_pid"] != 1
        || sample["no_new_privileges"] != true
        || sample["seccomp_mode"] != 2
        || !positive(&sample["cgroup_device"])
        || !positive(&sample["cgroup_inode"])
        || !["executable_sha256", "argv_sha256", "mountinfo_sha256"]
            .iter()
            .all(|f| sample[*f].as_str().is_some_and(|s| hex(s, 64)))
        || !exact(
            &sample["namespaces"],
            &["mnt", "pid", "net", "ipc", "uts", "cgroup", "user"],
        )
    {
        return Err("invalid independent product kernel sample".to_owned());
    }
    for namespace in sample["namespaces"].as_object().unwrap().values() {
        if !exact(namespace, &["device", "inode"])
            || !positive(&namespace["device"])
            || !positive(&namespace["inode"])
        {
            return Err("invalid product kernel namespace identity".to_owned());
        }
    }
    let rows = sample["task_mounts"]
        .as_array()
        .filter(|a| a.len() == 3)
        .ok_or("three independent kernel task maps required")?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let source = row["source"].as_str().ok_or("missing kernel task source")?;
        let name = source
            .strip_prefix(&format!("/home/hx-{run}/{role}/tasks/"))
            .filter(|s| matches!(*s, "checkout" | "remote" | "home"))
            .ok_or("kernel task source outside fixed run")?;
        let destination = if name == "checkout" {
            "/runtime/home/project"
        } else {
            source
        };
        let expected_mode = if name == "checkout" { 0o755 } else { 0o700 };
        if !seen.insert(name)
            || !exact(
                row,
                &[
                    "source",
                    "destination",
                    "mount_id",
                    "device",
                    "inode",
                    "mode",
                    "physical_uid",
                    "physical_gid",
                    "product_uid",
                    "product_gid",
                ],
            )
            || row["destination"] != destination
            || !positive(&row["mount_id"])
            || !positive(&row["device"])
            || !positive(&row["inode"])
            || row["mode"] != expected_mode
            || row["physical_uid"] != 10001
            || row["physical_gid"] != 10001
            || row["product_uid"] != 10004
            || row["product_gid"] != 10004
        {
            return Err("invalid kernel task idmap relation".to_owned());
        }
    }
    Ok(sample)
}

pub(crate) fn read_report(
    journal: &RunReservationJournal,
    started: &StartedMarker,
    outside_sha: &str,
    role: &str,
) -> Result<Value, String> {
    let terminal = journal
        .terminal(
            &started.job_id,
            &started.source_sha,
            &started.deployment_digest,
            &started.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("terminal is missing")?;
    if !hex(outside_sha, 64)
        || terminal.report_sha256 != outside_sha
        || terminal.status != TerminalOutcome::InvalidEvidence
        || terminal.exit_code != 0
        || terminal.started_marker_sha256 != started.sha256
        || started.controller_public_key_hex.is_none()
    {
        return Err("kernel report does not match outside completed-run pin".to_owned());
    }
    let raw = read_bounded_regular(
        &journal.root,
        &format!("{}.report.json", started.job_id),
        16 * 1024,
    )
    .map_err(|e| e.to_string())?
    .ok_or("kernel report missing")?;
    if format!("{:x}", Sha256::digest(&raw)) != outside_sha
        || canonicalize(&raw).map_err(|e| e.to_string())? != raw
    {
        return Err("kernel report bytes differ from outside pin".to_owned());
    }
    let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || report["run_id"] != started.job_id
        || report["source_sha"] != started.source_sha
        || report["role"] != role
        || report["provisional_config_digest"] != started.deployment_digest
        || report["controller_public_key_hex"].as_str()
            != started.controller_public_key_hex.as_deref()
        || report["exit_code"] != 0
        || report["timed_out"] != false
        || report["controller_and_product_slice_cleanup_verified"] != true
        || report["post_run_controller_custody"] != true
        || report["record_scored"] != false
        || report["execution_eligible"] != false
    {
        return Err("outside-pinned product report has wrong run identity or lifecycle".to_owned());
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub fn observe_kernel_bound_provider_effect_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    outside_journal_sha: &str,
    outside_report_sha: &str,
    role: &str,
    surface: &str,
) -> Result<Value, String> {
    if !journal.root_owned {
        return Err("Root kernel effect reader required".to_owned());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    let report = read_report(journal, started, outside_report_sha, role)?;
    if report["effect_events"]["sha256"] != outside_journal_sha {
        return Err(
            "effect journal and kernel sample do not share the outside report pin".to_owned(),
        );
    }
    let sample = matching_sample(&report, &started.job_id, role)?;
    let name = match surface {
        "provider-remote" => "remote",
        "provider-home" => "home",
        _ => return Err("fixed provider surface required".to_owned()),
    };
    let source = format!("/home/hx-{}/{role}/tasks/{name}", started.job_id);
    let row = sample["task_mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["source"] == source)
        .ok_or("provider task map missing")?;
    let parent_path = format!("/home/hx-{}/{role}/tasks", started.job_id);
    let parent =
        open_root_owned_public_directory(Path::new(&parent_path)).map_err(|e| e.to_string())?;
    let open_task = || {
        openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())
    };
    let task = open_task()?;
    let before = fstat(&task).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory
        || before.st_uid != 10001
        || before.st_gid != 10001
        || before.st_mode & 0o7777 != 0o700
        || row["device"].as_u64() != Some(before.st_dev)
        || row["inode"].as_u64() != Some(before.st_ino)
    {
        return Err("retained provider parent differs from live idmapped task".to_owned());
    }
    let effect = observe_staging_fixed_provider_effect_ineligible(
        journal,
        lease,
        started,
        outside_journal_sha,
        role,
        surface,
        sample["cgroup"].as_str().unwrap(),
    )?;
    let after = fstat(open_task()?).map_err(|e| e.to_string())?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || read_report(journal, started, outside_report_sha, role)? != report
    {
        return Err("provider task or pinned kernel report changed during readback".to_owned());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    let mut value = effect.to_json();
    value["schema"] = json!(if effect.file_handle.is_some() {
        "hol-gauntlet-staging-kernel-bound-effect.v2"
    } else {
        "hol-gauntlet-staging-kernel-bound-effect.v1"
    });
    value
        .as_object_mut()
        .unwrap()
        .remove("caller_expected_cgroup");
    value["kernel_observed_cgroup"] = sample["cgroup"].clone();
    value["kernel_product_pid"] = sample["pid"].clone();
    value["kernel_product_start_ticks"] = sample["start_ticks"].clone();
    value["outside_report_sha256"] = json!(outside_report_sha);
    value["idmap_kernel_verified"] = json!(true);
    value["continuously_observed"] = json!(false);
    Ok(value)
}

/// Compose the held-file attribution with the signed product process and
/// mount relation under the host-pinned one-use controller key. The two
/// provider writes are diagnostic probes, not Guard-mediated tool effects.
#[allow(clippy::too_many_arguments)]
pub fn observe_signed_kernel_bound_provider_effect_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    outside_journal_sha: &str,
    outside_report_sha: &str,
    role: &str,
    surface: &str,
) -> Result<Value, String> {
    use gauntlet_evidence::{
        observe_staging_product_relation_root_owned_ineligible, StagingProductRelationPins,
    };
    let mut effect = observe_kernel_bound_provider_effect_ineligible(
        journal,
        lease,
        started,
        outside_journal_sha,
        outside_report_sha,
        role,
        surface,
    )?;
    if effect["file_generation_verified"] != true {
        return Err("signed effect relation requires observed file generation".to_owned());
    }
    let report = read_report(journal, started, outside_report_sha, role)?;
    let sample = matching_sample(&report, &started.job_id, role)?;
    let relation = observe_staging_product_relation_root_owned_ineligible(
        &StagingProductRelationPins {
            run_id: &started.job_id,
            role,
            source_sha: &started.source_sha,
            controller_public_key_hex: started
                .controller_public_key_hex
                .as_deref()
                .ok_or("signed effect relation lacks outside controller key")?,
        },
        sample,
    )
    .map_err(|e| e.to_string())?;
    if report != read_report(journal, started, outside_report_sha, role)? {
        return Err("kernel report changed during signed product comparison".to_owned());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    effect["schema"] = json!("hol-gauntlet-staging-signed-kernel-bound-effect.v1");
    effect["signed_control_relation"] = relation;
    Ok(effect)
}

#[cfg(test)]
#[path = "staging_product_effect_tests.rs"]
mod tests;
