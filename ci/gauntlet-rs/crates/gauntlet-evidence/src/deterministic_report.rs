//! Bounded deterministic controller-report consistency against outside pins.
//! A controller claim is never an independently recomputed Guard verdict.

use crate::crypto::{is_sha256, sha256};
use crate::python_worker_files::read_root_owned_report_bytes;
use crate::worker_receipt::bounded_json;
use crate::{EvidenceError, Result};
use gauntlet_contracts::is_git_sha;

const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicReportObservation {
    pub source_sha: String,
    pub config_digest: String,
    pub raw_sha256: String,
    pub exit_code: i32,
    pub producer_status: String,
    pub cell_count: usize,
    pub execution_eligible: bool,
}

/// Check report identity and zero-model profile without trusting the report's
/// `status`, `passed` fields or any producer-supplied control outcome.
pub fn verify_deterministic_report(
    raw: &[u8],
    expected_source_sha: &str,
    expected_config_digest: &str,
    expected_exit_code: i32,
) -> Result<DeterministicReportObservation> {
    if !is_git_sha(expected_source_sha)
        || !is_sha256(expected_config_digest)
        || !(-128..=255).contains(&expected_exit_code)
        || raw.is_empty()
        || raw.len() > MAX_REPORT_BYTES
    {
        return Err(EvidenceError::Invalid(
            "invalid deterministic report pins or size",
        ));
    }
    let report = bounded_json(raw, MAX_REPORT_BYTES)?;
    let fields = report.as_object().ok_or(EvidenceError::Invalid(
        "deterministic report must be an object",
    ))?;
    let status = report["status"]
        .as_str()
        .filter(|status| matches!(*status, "passed" | "failed" | "invalid-evidence"))
        .ok_or(EvidenceError::Invalid(
            "invalid deterministic producer status",
        ))?;
    let cells = report["cells"].as_array().ok_or(EvidenceError::Invalid(
        "deterministic report cells are missing",
    ))?;
    if !fields.contains_key("schema")
        || report["schema"] != "gauntlet-ci-check.v1"
        || report["expected_guard_source_sha"] != expected_source_sha
        || report["guard_source_sha"] != expected_source_sha
        || report["runner_config_digest"] != expected_config_digest
        || report["profile"] != "deterministic"
        || report["exit_code"].as_i64() != Some(i64::from(expected_exit_code))
        || report["model_tokens"].as_u64() != Some(0)
        || report["model_usage_known"] != true
        || (status == "passed" && expected_exit_code != 0)
        || cells.len() > 6
    {
        return Err(EvidenceError::Invalid(
            "deterministic report identity, usage or exit differs from pins",
        ));
    }
    Ok(DeterministicReportObservation {
        source_sha: expected_source_sha.to_owned(),
        config_digest: expected_config_digest.to_owned(),
        raw_sha256: sha256(raw),
        exit_code: expected_exit_code,
        producer_status: status.to_owned(),
        cell_count: cells.len(),
        execution_eligible: false,
    })
}

/// Read the fixed Root-owned output for one parsed job ID, then compare its
/// exact raw digest and identity with outside arguments. No path selector or
/// controller-provided trust anchor is accepted.
pub fn read_deterministic_report_root_owned(
    job_id: &str,
    expected_source_sha: &str,
    expected_config_digest: &str,
    expected_raw_sha256: &str,
    expected_exit_code: i32,
) -> Result<DeterministicReportObservation> {
    if !is_sha256(expected_raw_sha256) {
        return Err(EvidenceError::Invalid("invalid outside report digest"));
    }
    let raw = read_root_owned_report_bytes(job_id)?
        .ok_or(EvidenceError::Invalid("deterministic report is missing"))?;
    if sha256(&raw) != expected_raw_sha256 {
        return Err(EvidenceError::Invalid(
            "deterministic report differs from outside digest",
        ));
    }
    verify_deterministic_report(
        &raw,
        expected_source_sha,
        expected_config_digest,
        expected_exit_code,
    )
}

/// Read a freshly produced, fixed-path Root-owned report after the launched
/// controller and its product cells have stopped. Its raw digest is an
/// observation, not an outside pin, and its status remains a producer claim.
pub fn observe_deterministic_report_root_owned_ineligible(
    job_id: &str,
    expected_source_sha: &str,
    expected_config_digest: &str,
    expected_exit_code: i32,
) -> Result<DeterministicReportObservation> {
    let raw = read_root_owned_report_bytes(job_id)?
        .ok_or(EvidenceError::Invalid("deterministic report is missing"))?;
    verify_deterministic_report(
        &raw,
        expected_source_sha,
        expected_config_digest,
        expected_exit_code,
    )
}

#[cfg(test)]
#[path = "deterministic_report_tests.rs"]
mod tests;
