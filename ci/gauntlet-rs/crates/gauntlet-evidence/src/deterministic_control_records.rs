//! Fixed-path, Root-owned custody of the six retained deterministic records.
//! A matching report hash does not authenticate a controller observation.

use crate::crypto::{is_sha256, sha256};
use crate::deterministic_report::{verify_deterministic_report, DeterministicReportObservation};
use crate::python_worker_files::{
    open_private_directory, private_directory, read_private_file, read_root_owned_report_bytes,
    unchanged,
};
use crate::worker_receipt::bounded_json;
use crate::{EvidenceError, Result};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Mode, OFlags};
use rustix::process::geteuid;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;

const ROLES: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];
const MAX_CONTROL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

pub struct SixDeterministicControlRecords {
    pub report: DeterministicReportObservation,
    pub digests: BTreeMap<String, String>,
    records: BTreeMap<String, Vec<u8>>,
    pub execution_eligible: bool,
}

impl SixDeterministicControlRecords {
    pub fn record_bytes(&self, role: &str) -> Option<&[u8]> {
        self.records.get(role).map(Vec::as_slice)
    }
}

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn lowercase_job_id(job_id: &str) -> bool {
    job_id.len() == 16
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Compare six raw `control.json` blobs with the report's role/hash claims.
/// The records remain opaque here; independent signature and effect scoring
/// must consume the returned bytes before a result can be eligible.
pub fn verify_six_deterministic_control_records(
    report_raw: &[u8],
    records: BTreeMap<String, Vec<u8>>,
    expected_source_sha: &str,
    expected_config_digest: &str,
    expected_exit_code: i32,
) -> Result<SixDeterministicControlRecords> {
    let report = verify_deterministic_report(
        report_raw,
        expected_source_sha,
        expected_config_digest,
        expected_exit_code,
    )?;
    let value = bounded_json(report_raw, MAX_REPORT_BYTES)?;
    let cells = value["cells"]
        .as_array()
        .filter(|cells| cells.len() == ROLES.len())
        .ok_or(invalid("deterministic report lacks six control rows"))?;
    if value["selected_cases"].as_u64() != Some(ROLES.len() as u64)
        || value["model_requests"].as_u64() != Some(0)
        || records.len() != ROLES.len()
    {
        return Err(invalid(
            "deterministic control inventory differs from six roles",
        ));
    }
    let mut digests = BTreeMap::new();
    for role in ROLES {
        let raw = records
            .get(role)
            .ok_or(invalid("deterministic control role is missing"))?;
        if raw.is_empty() || raw.len() as u64 > MAX_CONTROL_BYTES {
            return Err(invalid("deterministic control record exceeds byte limit"));
        }
        bounded_json(raw, MAX_CONTROL_BYTES as usize)?;
        digests.insert(role.to_owned(), sha256(raw));
    }
    let mut seen = BTreeSet::new();
    for row in cells {
        let role = row["episode_id"]
            .as_str()
            .ok_or(invalid("deterministic control row lacks a role"))?;
        let claimed = row["record_sha256"]
            .as_str()
            .filter(|digest| is_sha256(digest))
            .ok_or(invalid("deterministic control row lacks a record digest"))?;
        if !seen.insert(role) || digests.get(role).map(String::as_str) != Some(claimed) {
            return Err(invalid("deterministic control record differs from report"));
        }
    }
    if seen.len() != ROLES.len() {
        return Err(invalid("deterministic control roles are incomplete"));
    }
    Ok(SixDeterministicControlRecords {
        report,
        digests,
        records,
        execution_eligible: false,
    })
}

fn open_root_state(job_id: &str) -> Result<OwnedFd> {
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let root_stat = fstat(&root).map_err(io)?;
    if root_stat.st_uid != 0 || root_stat.st_mode & 0o022 != 0 {
        return Err(invalid("deterministic state ancestry is mutable"));
    }
    let home_dir = openat(
        &root,
        "home",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let home = fstat(&home_dir).map_err(io)?;
    if home.st_uid != 0 || home.st_mode & 0o022 != 0 {
        return Err(invalid("deterministic state ancestry is mutable"));
    }
    let name = format!("hg-{job_id}");
    open_private_directory(&home_dir, &name, 0)?
        .map(|(directory, _)| directory)
        .ok_or(invalid("deterministic state directory is missing"))
}

fn unchanged_named(parent: &OwnedFd, name: &str, child: &OwnedFd) -> Result<()> {
    let held = fstat(child).map_err(io)?;
    let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if !unchanged(&held, &named) {
        return Err(invalid("deterministic state directory changed"));
    }
    Ok(())
}

fn read_role_records(state: &OwnedFd) -> Result<BTreeMap<String, Vec<u8>>> {
    private_directory(state, 0)?;
    let (deterministic, _) = open_private_directory(state, "d", 0)?
        .ok_or(invalid("deterministic state directory is missing"))?;
    let mut records = BTreeMap::new();
    for role in ROLES {
        let (directory, _) = open_private_directory(&deterministic, role, 0)?
            .ok_or(invalid("deterministic control directory is missing"))?;
        let raw = read_private_file(&directory, "control.json", 0, MAX_CONTROL_BYTES)?
            .ok_or(invalid("deterministic control record is missing"))?;
        unchanged_named(&deterministic, role, &directory)?;
        records.insert(role.to_owned(), raw);
    }
    unchanged_named(state, "d", &deterministic)?;
    Ok(records)
}

/// Read only the fixed six Root-owned state records and fixed output report.
/// Reopen both trees and compare the snapshots before exposing record bytes
/// to a future independent scorer. Running or incomplete jobs refuse.
pub fn read_six_deterministic_controls_root_owned(
    job_id: &str,
    expected_source_sha: &str,
    expected_config_digest: &str,
    expected_exit_code: i32,
) -> Result<SixDeterministicControlRecords> {
    if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
        return Err(invalid("Linux Root deterministic control custody required"));
    }
    if !lowercase_job_id(job_id) {
        return Err(invalid("invalid independent deterministic job ID"));
    }
    let report =
        read_root_owned_report_bytes(job_id)?.ok_or(invalid("deterministic report is missing"))?;
    let state = open_root_state(job_id)?;
    let before = fstat(&state).map_err(io)?;
    let records = read_role_records(&state)?;
    let reopened = open_root_state(job_id)?;
    if !unchanged(&before, &fstat(&reopened).map_err(io)?)
        || records != read_role_records(&reopened)?
        || Some(report.as_slice()) != read_root_owned_report_bytes(job_id)?.as_deref()
    {
        return Err(invalid("deterministic control snapshot changed"));
    }
    verify_six_deterministic_control_records(
        &report,
        records,
        expected_source_sha,
        expected_config_digest,
        expected_exit_code,
    )
}

#[cfg(test)]
#[path = "deterministic_control_records_tests.rs"]
mod tests;
