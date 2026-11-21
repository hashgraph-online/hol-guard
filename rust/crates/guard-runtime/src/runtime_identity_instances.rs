//! Running instances of probed runtimes, for probe requests that set
//! `instances`.
//!
//! An instance is one process, named by boot, PID and start identity, bound to
//! the artifact it actually started from. A process launched from a probed path
//! is bound to the file there now only when the file provably has not changed
//! since the process started: it started in a later second than the file's
//! last change, and on Linux it still maps the same inode. Otherwise the
//! process keeps the artifact an earlier probe bound it to, carried in
//! `known_instances`, or gets an unidentified artifact whose version is
//! unknown, which never clears an advisory. Replacing a runtime on disk
//! therefore never rewrites what an old process is running.
//!
//! A known instance at a probed location that is no longer running is
//! reported `exited`, the evidence a fix needs that the old build stopped. On
//! Windows an exited process keeps its start marker while any handle to it is
//! open, so only a process that has not exited counts as still running.
//! Known instances elsewhere belong to another probe and are left out. Only
//! processes whose executable path this user can read are seen, so the scan
//! never makes the scope complete.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::resident_process_identity::{process_start_marker, running_process_start_marker};

pub(crate) const FEATURE: &str = "runtime-identity-instances-v1";
pub(super) const MAX_INSTANCES: usize = 4_096;
const DELETED_SUFFIX: &str = " (deleted)";

/// An instance an earlier probe reported, with the artifact it was bound to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KnownInstance {
    boot_identity: String,
    pid: u32,
    start_identity: String,
    #[serde(default)]
    location_id: Option<String>,
    artifact: Value,
}

/// A probed location whose file was identified.
pub(super) struct Probed<'a> {
    pub(super) location_id: &'a str,
    pub(super) resolved: &'a str,
    pub(super) artifact: &'a Value,
}

pub(super) struct Instances {
    pub(super) instances: Vec<Value>,
    /// Every artifact an instance names; the probe merges them by id.
    pub(super) artifacts: Vec<Value>,
    /// Running processes launched from a probed path whose start identity
    /// could not be read, so no instance could be formed for them.
    pub(super) unbound_processes: usize,
    pub(super) limit_reached: bool,
}

pub(super) fn validate_known(known: &[KnownInstance]) -> Result<(), String> {
    let invalid = || "runtime_identity_probe_known_instance_invalid".to_owned();
    if known.len() > MAX_INSTANCES {
        return Err(invalid());
    }
    for item in known {
        let text_ok =
            |value: &str| !value.is_empty() && value.len() <= 512 && !value.contains('\0');
        if item.pid == 0
            || !text_ok(&item.boot_identity)
            || !text_ok(&item.start_identity)
            || !item.location_id.as_deref().is_none_or(text_ok)
            || !artifact_ok(&item.artifact)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// A stored artifact may never claim more than the probe itself can: the
/// store is a local file, and a raised assurance would clear advisories. It
/// must also be one the assessment accepts, or carrying it would cost the
/// reply every process it names.
fn artifact_ok(artifact: &Value) -> bool {
    artifact["artifact_id"]
        .as_str()
        .is_some_and(|id| id.starts_with("artifact:"))
        && crate::runtime_identity::carried_artifact_ok(artifact)
}

/// `location_ids` names every location the probe covered, identified or not;
/// a known instance elsewhere belongs to another probe's scope and is left out.
pub(super) fn enumerate(
    probed: &[Probed<'_>],
    location_ids: &BTreeSet<&str>,
    known: &[KnownInstance],
) -> Instances {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let boot = boot_identity();
    let by_path: BTreeMap<&str, &Probed<'_>> = probed
        .iter()
        .rev()
        .map(|location| (location.resolved, location))
        .collect();
    let known_by_process: BTreeMap<(&str, u32, &str), &KnownInstance> = known
        .iter()
        .map(|item| {
            (
                (
                    item.boot_identity.as_str(),
                    item.pid,
                    item.start_identity.as_str(),
                ),
                item,
            )
        })
        .collect();
    let mut found = Instances {
        instances: Vec::new(),
        artifacts: Vec::new(),
        unbound_processes: 0,
        limit_reached: false,
    };
    let mut seen: BTreeSet<(String, u32, String)> = BTreeSet::new();
    let mut processes: Vec<(&Pid, &sysinfo::Process)> = system.processes().iter().collect();
    processes.sort_by_key(|(pid, _)| pid.as_u32());
    for (pid, process) in processes {
        let Some((launched, deleted)) = process.exe().map(launched_path) else {
            continue;
        };
        let Some(location) = by_path.get(launched.to_string_lossy().as_ref()) else {
            continue;
        };
        let pid = pid.as_u32();
        let Ok(start) = process_start_marker(pid) else {
            found.unbound_processes += 1;
            continue;
        };
        let key = (boot.as_str(), pid, start.as_str());
        let artifact =
            if !deleted && runs_current_file(pid, process.start_time(), location.resolved) {
                location.artifact.clone()
            } else if let Some(item) = known_by_process.get(&key) {
                item.artifact.clone()
            } else {
                unidentified(location.artifact, &instance_id(&boot, pid, &start))
            };
        seen.insert((boot.clone(), pid, start.clone()));
        push(
            &mut found,
            instance(
                &boot,
                pid,
                &start,
                Some(location.location_id),
                &artifact,
                "running",
            ),
            artifact,
        );
    }
    // A known instance this scan did not see is either running where no probed
    // file points any more, or gone.
    for item in known {
        let Some(location) = item
            .location_id
            .as_deref()
            .filter(|id| location_ids.contains(id))
        else {
            continue;
        };
        let key = (
            item.boot_identity.clone(),
            item.pid,
            item.start_identity.clone(),
        );
        if !seen.insert(key) {
            continue;
        }
        let state = if item.boot_identity == boot
            && running_process_start_marker(item.pid)
                .is_ok_and(|start| start == item.start_identity)
        {
            "running"
        } else {
            "exited"
        };
        let row = instance(
            &item.boot_identity,
            item.pid,
            &item.start_identity,
            Some(location),
            &item.artifact,
            state,
        );
        push(&mut found, row, item.artifact.clone());
    }
    found
}

fn push(found: &mut Instances, row: Value, artifact: Value) {
    if found.instances.len() >= MAX_INSTANCES {
        found.limit_reached = true;
        return;
    }
    found.instances.push(row);
    found.artifacts.push(artifact);
}

fn instance(
    boot: &str,
    pid: u32,
    start: &str,
    location_id: Option<&str>,
    artifact: &Value,
    state: &str,
) -> Value {
    json!({
        "instance_id": instance_id(boot, pid, start),
        "boot_identity": boot,
        "pid": pid,
        "start_identity": start,
        "artifact_id": artifact["artifact_id"],
        "location_id": location_id,
        "state": state,
        "coverage": "observed_only",
    })
}

fn instance_id(boot: &str, pid: u32, start: &str) -> String {
    let fields = format!("guard.runtime-probe-instance.v1\0{boot}\0{pid}\0{start}");
    format!(
        "instance:{}",
        hex::encode(Sha256::digest(fields.as_bytes()))
    )
}

/// A process whose file was replaced runs bytes nobody hashed. It keeps the
/// location's family and platform, but no version, so it can never clear.
fn unidentified(location_artifact: &Value, instance_id: &str) -> Value {
    let fields = format!("guard.runtime-probe-unidentified.v1\0{instance_id}");
    json!({
        "artifact_id": format!("artifact:{}", hex::encode(Sha256::digest(fields.as_bytes()))),
        "family": location_artifact["family"], "vendor": null, "version": null,
        "build_id": null, "os": location_artifact["os"], "arch": location_artifact["arch"],
        "executable_sha256": null, "component_identity_sha256": null,
        "identity_assurance": "unknown",
    })
}

/// The path a process was launched from, and whether Linux reports that file
/// as deleted since.
fn launched_path(exe: &Path) -> (PathBuf, bool) {
    let text = exe.to_string_lossy();
    if let Some(stripped) = text.strip_suffix(DELETED_SUFFIX) {
        return (PathBuf::from(stripped), true);
    }
    let resolved = fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    (resolved, false)
}

/// Whether the file at `resolved` is the one the process started from: it has
/// not changed since a second before the process started, and on Linux the
/// process maps that same inode. Whole seconds only, so a launch in the same
/// second as an install stays unproven.
fn runs_current_file(pid: u32, started: u64, resolved: &str) -> bool {
    let Ok(meta) = fs::metadata(resolved) else {
        return false;
    };
    if changed_secs(&meta).is_none_or(|changed| started <= changed) {
        return false;
    }
    same_inode(pid, &meta)
}

fn changed_secs(meta: &fs::Metadata) -> Option<u64> {
    let modified = secs(meta.modified().ok()?)?;
    Some(modified.max(status_changed_secs(meta)?))
}

fn secs(time: std::time::SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// When the file was last put in place. A rename into place moves the Unix
/// change time.
#[cfg(unix)]
fn status_changed_secs(meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    u64::try_from(meta.ctime()).ok()
}

/// Windows keeps a file's creation time across a rename, so a build staged
/// before the process started and renamed into place after it can still bind
/// the process to the new file. Instances are `observed_only` and never clear
/// an advisory, so the cost is a missed restart finding, never a false fix.
#[cfg(windows)]
fn status_changed_secs(meta: &fs::Metadata) -> Option<u64> {
    secs(meta.created().ok()?)
}

/// No change time to read, so no process is ever bound to the current file.
#[cfg(not(any(unix, windows)))]
fn status_changed_secs(_meta: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn same_inode(pid: u32, meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(format!("/proc/{pid}/exe"))
        .is_ok_and(|mapped| mapped.dev() == meta.dev() && mapped.ino() == meta.ino())
}

#[cfg(not(target_os = "linux"))]
fn same_inode(_pid: u32, _meta: &fs::Metadata) -> bool {
    true
}

fn boot_identity() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(id) = fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let id = id.trim();
        if !id.is_empty() {
            return format!("linux:{id}");
        }
    }
    format!("boot:{}", System::boot_time())
}

#[cfg(test)]
#[path = "runtime_identity_instances_tests.rs"]
mod tests;
